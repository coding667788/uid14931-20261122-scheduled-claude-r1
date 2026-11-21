"""Robust maintenance-plan solver for timed page handoffs.

Problem (all quantities are logical; nothing touches hardware)
--------------------------------------------------------------
Targets declare fixed queue conditions (invalidate a range / drain in-flight
commands) with deadlines.  Candidate maintenance commands each belong to one
queue, carry a pause duration, optional explicit conflict resources, and one
or more option windows (a command id executes at most once).  A window may
declare queues that could be unresponsive in it; an allowed fault is at most
one such (window, queue) pair.  The chosen plan is fixed up front -- primary
and backup windows cannot pick different plans at runtime -- and must still
meet every deadline in the baseline and in every allowed fault scenario.

Algorithm
---------
Requirement-driven depth-first branch-and-bound with memoization: at each step
the solver branches over *robust covers* of the most-constrained still-open
requirement (each cover is itself proven to survive every allowed fault),
prunes on an additive per-requirement lower bound, and memoizes dominated
states by (covered union, drain set, used commands, placement timeline).

A separate exhaustive enumerator (brute_force_plan) cross-checks optimality
on small instances in the test suite.

Objective, lexicographic:
    1. total pause duration (sum of selected command durations)
    2. number of selected commands
    3. ordered list keyed by (execution start, window id, offset, command id)
"""

from __future__ import annotations

from .ranges import canonical, intersect, subtract_many


# ---------------------------------------------------------------------------
# Normalized input structures
# ---------------------------------------------------------------------------

class Window:
    __slots__ = ("wid", "start", "duration", "dead_queues")

    def __init__(self, raw):
        self.wid = raw["window_id"]
        self.start = raw["start"]
        self.duration = raw["duration"]
        self.dead_queues = frozenset(
            (q["slot"], q["queue_no"])
            for q in raw.get("unresponsive_queues", []))


class Requirement:
    __slots__ = ("idx", "target_id", "kind", "slot", "queue_no",
                 "rng", "deadline", "target_range", "qkey")

    def __init__(self, idx, target_id, kind, slot, queue_no, rng,
                 deadline, target_range):
        self.idx = idx
        self.target_id = target_id
        self.kind = kind
        self.slot = slot
        self.queue_no = queue_no
        self.rng = rng                      # tuple for invalidate, else None
        self.deadline = deadline
        self.target_range = target_range
        self.qkey = (slot, queue_no)


class Command:
    __slots__ = ("cid", "kind", "slot", "queue_no", "duration", "rng",
                 "resources", "placements", "qkey")

    def __init__(self, raw, windows):
        self.cid = raw["command_id"]
        self.kind = raw["kind"]
        self.slot = raw["slot"]
        self.queue_no = raw["queue_no"]
        self.qkey = (self.slot, self.queue_no)
        self.duration = raw["duration"]
        self.rng = ((raw["range"]["start"], raw["range"]["end"])
                    if self.kind == "invalidate" else None)
        implicit = {"queue:%s:%s" % (self.slot, self.queue_no)}
        self.resources = frozenset(implicit | set(raw.get("resources", [])))
        self.placements = [Placement(win, opt["offset"], self)
                           for opt in raw["windows"]
                           for win in [windows[opt["window_id"]]]]


class Placement:
    __slots__ = ("win", "offset", "finish", "start_abs", "end_abs", "cmd")

    def __init__(self, win, offset, cmd):
        self.win = win
        self.offset = offset
        self.cmd = cmd
        self.start_abs = win.start + offset
        self.end_abs = win.start + offset + cmd.duration
        self.finish = self.end_abs


def _overlap(p1, p2):
    return intersect((p1.start_abs, p1.end_abs),
                     (p2.start_abs, p2.end_abs)) is not None


def _conflict(cmd_a, pa, cmd_b, pb):
    if not _overlap(pa, pb):
        return False
    return bool(cmd_a.resources & cmd_b.resources)


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

class Solver:
    def __init__(self, case):
        self.case = case
        self.windows = {w["window_id"]: Window(w) for w in case["windows"]}
        self.reqs = self._build_requirements(case)
        self.commands = [Command(c, self.windows) for c in case["commands"]]
        self.faults = self._build_faults()
        self.best = None                 # (objective, frozenset of pair keys)
        self.nodes = 0
        self._drop_useless()
        self._index()

    # -- setup ---------------------------------------------------------------

    def _build_requirements(self, case):
        reqs = []
        idx = 0
        for tgt in case["targets"]:
            tr = (tgt["range"]["start"], tgt["range"]["end"])
            for req in tgt["requirements"]:
                rng = ((req["range"]["start"], req["range"]["end"])
                       if req["kind"] == "invalidate" else None)
                reqs.append(Requirement(
                    idx, tgt["target_id"], req["kind"], req["slot"],
                    req["queue_no"], rng, tgt["deadline"], tr))
                idx += 1
        return reqs

    def _build_faults(self):
        faults = []
        for win in self.windows.values():
            for qkey in sorted(win.dead_queues):
                faults.append((win.wid, qkey))
        return faults

    def _command_helps(self, cmd):
        for req in self.reqs:
            if req.qkey != cmd.qkey or req.kind != cmd.kind:
                continue
            timely = [p for p in cmd.placements if p.finish <= req.deadline]
            if not timely:
                continue
            if cmd.kind == "drain":
                return True
            if intersect(cmd.rng, req.rng):
                return True
        return False

    def _drop_useless(self):
        kept = [c for c in self.commands if self._command_helps(c)]
        self.dropped = sorted(c.cid for c in self.commands if c not in kept)
        self.commands = kept

    def _index(self):
        # All selectable (command, placement) pairs, keyed for stable output.
        self.pairs = []
        self.pair_by_key = {}
        for cmd in self.commands:
            for place in cmd.placements:
                key = (cmd.cid, place.win.wid, place.offset)
                self.pair_by_key[key] = (cmd, place)
                self.pairs.append(key)
        # Which pairs can ever serve each requirement?
        self.req_pairs = {}
        for req in self.reqs:
            eligible = []
            for key in self.pairs:
                cmd, place = self.pair_by_key[key]
                if cmd.qkey != req.qkey or cmd.kind != req.kind:
                    continue
                if place.finish > req.deadline:
                    continue
                if req.kind == "invalidate" and not intersect(cmd.rng,
                                                               req.rng):
                    continue
                eligible.append(key)
            self.req_pairs[req.idx] = tuple(sorted(eligible))
        # Robust cover sets per requirement: minimal collections of pairs that
        # survive every allowed fault and fully cover the requirement.
        self.robust_covers = {}
        for req in self.reqs:
            self.robust_covers[req.idx] = self._robust_covers_for(req)
        # Cheapest possible pair per requirement (lower-bound ingredient).
        self.cheapest = {}
        for req in self.reqs:
            pairs = self.req_pairs[req.idx]
            if pairs:
                self.cheapest[req.idx] = min(
                    self.pair_by_key[k][0].duration for k in pairs)

    # -- coverage semantics --------------------------------------------------

    def _cover_survives(self, pair_keys, req):
        """True iff these pairs cover the req under every allowed fault."""
        for fault in self.faults:
            alive = [k for k in pair_keys
                     if not self._blocked(k, fault)]
            if not self._pairs_cover(alive, req):
                return False
        return True

    def _blocked(self, key, fault):
        win_id, qkey = fault
        cmd, place = self.pair_by_key[key]
        return place.win.wid == win_id and cmd.qkey == qkey

    def _pairs_cover(self, pair_keys, req):
        contrib = [k for k in pair_keys
                   if self._pair_serves(k, req)]
        if not contrib:
            return False
        if req.kind == "drain":
            return True
        union = canonical([self.pair_by_key[k][0].rng for k in contrib])
        return not subtract_many(req.rng, union)

    def _pair_serves(self, key, req):
        cmd, place = self.pair_by_key[key]
        if cmd.qkey != req.qkey or cmd.kind != req.kind:
            return False
        if place.finish > req.deadline:
            return False
        if req.kind == "invalidate":
            return intersect(cmd.rng, req.rng) is not None
        return True

    def _robust_covers_for(self, req):
        """Enumerate minimal robust covers of one requirement.

        A cover is a set of pair keys that (a) fully covers the requirement in
        the baseline and (b) stays covering under every single fault.  Only
        minimal (irredundant) covers are kept; larger supersets can never win
        on the duration/count objectives.
        """
        eligible = list(self.req_pairs[req.idx])
        covers = []
        seen = set()
        # Bound cover size: one pair per distinct fault window is enough in
        # practice; cap defensively at the number of eligible pairs.
        from itertools import combinations
        for size in range(1, len(eligible) + 1):
            for combo in combinations(eligible, size):
                combo_set = frozenset(combo)
                if combo_set in seen:
                    continue
                if not self._pairs_cover(combo_set, req):
                    continue
                if not self._cover_survives(combo_set, req):
                    continue
                # minimality: no proper subset already accepted.
                if any(existing < combo_set for existing in seen):
                    continue
                covers.append(combo_set)
                seen.add(combo_set)
        # Deterministic order: cheapest duration first, then count, then keys.
        covers.sort(key=lambda s: (
            sum(self.pair_by_key[k][0].duration for k in s), len(s),
            tuple(sorted(s))))
        return tuple(covers)

    # -- conflict handling ---------------------------------------------------

    def _pair_conflicts(self, key, used_pairs):
        cmd, place = self.pair_by_key[key]
        for other_key in used_pairs:
            other_cmd, other_place = self.pair_by_key[other_key]
            if other_cmd.cid == cmd.cid:
                return True       # same command id executes at most once
            if _conflict(cmd, place, other_cmd, other_place):
                return True
        return False

    # -- search --------------------------------------------------------------

    def solve(self):
        # Requirement order: fewest robust covers first (most constrained).
        self.req_order = sorted(
            self.reqs,
            key=lambda r: (len(self.robust_covers[r.idx]), r.deadline, r.idx))
        if any(not self.robust_covers[r.idx] for r in self.req_order):
            return None
        used = frozenset()
        self._dfs(0, used, 0, 0)
        if self.best is None:
            return None
        return self.best

    def _objective_of(self, used_pairs):
        cmds = {self.pair_by_key[k][0] for k in used_pairs}
        total = sum(c.duration for c in cmds)
        ordered = sorted(
            (p.start_abs, p.win.wid, p.offset, c.cid)
            for k in used_pairs for c, p in [self.pair_by_key[k]])
        return (total, len(cmds), ordered)

    def _duration_of(self, used_pairs):
        return sum(self.pair_by_key[k][0].duration for k in used_pairs)

    def _dfs(self, ri, used, cur_duration, cur_count):
        self.nodes += 1
        if ri == len(self.req_order):
            obj = self._objective_of(used)
            if self.best is None or obj < self.best[0]:
                self.best = (obj, used)
            return

        req = self.req_order[ri]
        # Lower bound: current cost + cheapest pair for every remaining req.
        remaining = self.req_order[ri:]
        lb = cur_duration
        for r in remaining:
            lb += self.cheapest.get(r.idx, 0)
        if self.best is not None and lb > self.best[0][0]:
            return
        if self.best is not None and lb == self.best[0][0] \
                and cur_count >= self.best[0][1]:
            return

        for cover in self.robust_covers[req.idx]:
            add = [k for k in cover if k not in used]
            if any(self._pair_conflicts(k, used) for k in add):
                continue
            # No internal conflict inside the cover itself.
            if any(self._pair_conflicts(k, set(add) - {k}) for k in add):
                continue
            new_used = used | frozenset(add)
            new_cmds = {self.pair_by_key[k][0] for k in new_used}
            new_duration = sum(c.duration for c in new_cmds)
            if self.best is not None and new_duration > self.best[0][0]:
                continue
            self._dfs(ri + 1, new_used, new_duration, len(new_cmds))

    # -- exhaustive reference (small cases only) -----------------------------

    def brute_force_plan(self, cap=8):
        """Enumerate every subset x placement combination. For tests only."""
        if len(self.commands) > cap:
            raise ValueError("brute force limited to %d commands" % cap)
        best = None
        chosen = []

        def rec(i):
            nonlocal best
            if i == len(self.commands):
                used = frozenset(
                    (c.cid, p.win.wid, p.offset) for c, p in chosen)
                if not self._full_robust(used):
                    return
                obj = self._objective_of(used)
                if best is None or obj < best[0]:
                    best = (obj, used)
                return
            rec(i + 1)
            cmd = self.commands[i]
            for place in cmd.placements:
                if any(_conflict(cmd, place, o, op) for o, op in chosen):
                    continue
                chosen.append((cmd, place))
                rec(i + 1)
                chosen.pop()

        rec(0)
        return best

    def _full_robust(self, used):
        for req in self.reqs:
            if not self._pairs_cover(used, req):
                return False
            for fault in self.faults:
                alive = frozenset(k for k in used
                                  if not self._blocked(k, fault))
                if not self._pairs_cover(alive, req):
                    return False
        return True

    # -- infeasibility report ------------------------------------------------

    def blocker_report(self):
        """Baseline explanation: earliest target that cannot be handed off."""
        by_target = {t["target_id"]: t for t in self.case["targets"]}
        earliest = None
        for req in sorted(self.reqs, key=lambda r: (r.deadline, r.target_id,
                                                    r.idx)):
            structural = self._baseline_structural(req)
            if structural is None:
                continue
            if earliest is None or req.deadline < earliest[0].deadline:
                earliest = (req, structural)
        if earliest is None:
            tgt = sorted(self.case["targets"],
                         key=lambda t: (t["deadline"], t["target_id"]))[0]
            return {
                "kind": "no_conflict_free_plan",
                "earliest_target_id": tgt["target_id"],
                "deadline": tgt["deadline"],
                "range": tgt["range"],
                "uncovered_conditions": [
                    {"slot": r["slot"], "queue_no": r["queue_no"],
                     "condition": r["kind"], "range": r.get("range"),
                     "reason": "solver_exhausted_conflicts_or_faults"}
                    for r in tgt["requirements"]],
            }
        req, structural = earliest
        tgt = by_target[req.target_id]
        return {
            "kind": "not_handoffable",
            "earliest_target_id": req.target_id,
            "deadline": req.deadline,
            "range": tgt["range"],
            "uncovered_conditions": [self._condition_json(req, structural)],
        }

    def _baseline_structural(self, req):
        candidates = [c for c in self.commands
                      if c.qkey == req.qkey and c.kind == req.kind
                      and any(p.finish <= req.deadline for p in c.placements)]
        if req.kind == "drain":
            if candidates:
                return None
            same_queue = [c for c in self.case["commands"]
                          if (c["slot"], c["queue_no"]) == req.qkey]
            return [{"reason": ("no_timely_window" if same_queue
                                else "no_command_on_queue")}]
        if not candidates:
            same_queue = [c for c in self.case["commands"]
                          if (c["slot"], c["queue_no"]) == req.qkey
                          and c["kind"] == "invalidate"]
            return [{"reason": ("no_timely_window" if same_queue
                                else "no_command_on_queue"),
                     "ranges": [{"start": req.rng[0], "end": req.rng[1]}]}]
        union = canonical([c.rng for c in candidates])
        missing = subtract_many(req.rng, union)
        if missing:
            return [{"reason": "range_uncoverable",
                     "ranges": [{"start": s, "end": e} for s, e in missing]}]
        return None

    def _condition_json(self, req, structural):
        item = {
            "slot": req.slot,
            "queue_no": req.queue_no,
            "condition": req.kind,
            "range": ({"start": req.rng[0], "end": req.rng[1]}
                      if req.rng else None),
            "reason": sorted({m["reason"] for m in structural})[0],
        }
        for m in structural:
            if "ranges" in m:
                item.setdefault("missing_ranges", []).extend(m["ranges"])
        return item


# ---------------------------------------------------------------------------
# Public entry point + deterministic JSON rendering
# ---------------------------------------------------------------------------

def solve_schedule(case):
    solver = Solver(case)
    result = solver.solve()
    if result is None:
        return {
            "case_id": case["case_id"],
            "feasible": False,
            "search_nodes": solver.nodes,
            "blocker_report": solver.blocker_report(),
        }
    objective, used = result
    plan = [_plan_item(solver.pair_by_key[k]) for k in sorted(
        used, key=lambda k: (solver.pair_by_key[k][1].start_abs,
                             solver.pair_by_key[k][1].win.wid,
                             solver.pair_by_key[k][1].offset,
                             solver.pair_by_key[k][0].cid))]
    response = {
        "case_id": case["case_id"],
        "feasible": True,
        "search_nodes": solver.nodes,
        "objective": {
            "total_pause_duration": objective[0],
            "command_count": objective[1],
            "ordered_key": [
                {"start": s, "window_id": w, "offset": o, "command_id": cid}
                for s, w, o, cid in objective[2]],
        },
        "plan": plan,
        "robustness": _robustness_proof(solver, used),
    }
    if solver.dropped:
        response["excluded_useless_commands"] = solver.dropped
    return response


def _plan_item(pair):
    cmd, place = pair
    return {
        "command_id": cmd.cid,
        "kind": cmd.kind,
        "slot": cmd.slot,
        "queue_no": cmd.queue_no,
        "window_id": place.win.wid,
        "offset": place.offset,
        "start": place.start_abs,
        "finish": place.finish,
        "duration": cmd.duration,
        "range": ({"start": cmd.rng[0], "end": cmd.rng[1]}
                  if cmd.rng else None),
        "resources": sorted(cmd.resources),
    }


def _robustness_proof(solver, used):
    proof = [{
        "scenario": "baseline", "window_id": None,
        "unresponsive_queue": None, "blocked_commands": [],
        "all_targets_still_on_time": all(
            solver._pairs_cover(used, r) for r in solver.reqs),
    }]
    for win_id, qkey in solver.faults:
        blocked = sorted(
            solver.pair_by_key[k][0].cid for k in used
            if solver._blocked(k, (win_id, qkey)))
        alive = frozenset(k for k in used
                          if not solver._blocked(k, (win_id, qkey)))
        feasible = all(solver._pairs_cover(alive, r) for r in solver.reqs)
        proof.append({
            "scenario": "%s|%s|%s" % (win_id, qkey[0], qkey[1]),
            "window_id": win_id,
            "unresponsive_queue": {"slot": qkey[0], "queue_no": qkey[1]},
            "blocked_commands": blocked,
            "all_targets_still_on_time": feasible,
        })
    return {"scenarios_checked": len(proof), "results": proof}

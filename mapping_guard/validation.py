"""Field-level input validation for every CLI case envelope.

Validation is deliberately strict: unknown fields, wrong types, reused ids,
unknown enum values and out-of-range addresses all fail with a dotted field
path.  Structural failures (wrong JSON shape) use StructureError; everything
semantic that cannot be known until replay (unknown instance, post-revoke
registration, version conflicts ...) is enforced later in model/storage.
"""

from __future__ import annotations

from . import ADDRESS_MAX
from .errors import require, reject_unknown, RuleError, StructureError
from .ranges import validate_range

EVENT_TYPES = frozenset({
    "bind", "unbind", "map", "revoke", "register_command",
    "command_receipt", "cache_publish", "invalidate_ack", "handoff_request",
})

_QUEUE_FIELDS = ("device", "slot", "queue_no", "instance")


def _queue_part(ev, path):
    for name in _QUEUE_FIELDS:
        if name == "instance":
            require(ev, name, int, path)
        else:
            require(ev, name, str, path)


def _validate_event(ev, idx):
    path = "events[%d]" % idx
    if not isinstance(ev, dict):
        raise StructureError(path, "object", type(ev).__name__)
    require(ev, "id", str, path)
    etype = require(ev, "type", str, path, enum=EVENT_TYPES)
    per_event = {
        "bind": ("device", "slot", "queue_no", "instance", "gen", "range"),
        "unbind": ("device", "slot", "queue_no", "instance"),
        "map": ("device", "slot", "queue_no", "instance", "gen", "owner",
                "range"),
        "revoke": ("device", "gen", "range"),
        "register_command": ("device", "slot", "queue_no", "instance", "gen",
                             "cmd_id", "range"),
        "command_receipt": ("cmd_id", "status"),
        "cache_publish": ("device", "slot", "queue_no", "instance", "gen",
                          "entry_id", "range"),
        "invalidate_ack": ("device", "slot", "queue_no", "instance", "gen",
                           "range"),
        "handoff_request": ("request_id", "device", "from_owner", "to_owner",
                            "expected_source_version", "new_gen", "range"),
    }
    allowed = {"id", "type", "perms"} | set(per_event[etype])
    reject_unknown(ev, allowed, path)
    for name in per_event[etype]:
        if name in ("device", "slot", "owner", "from_owner", "to_owner",
                    "cmd_id", "entry_id", "request_id"):
            require(ev, name, str, path)
        elif name in ("instance", "gen", "queue_no",
                      "expected_source_version", "new_gen"):
            val = require(ev, name, int, path)
            if name == "queue_no" and val < 0:
                raise RuleError(path + ".queue_no", "range",
                                "queue_no must be >= 0")
            if name in ("gen", "new_gen") and val < 0:
                raise RuleError(path + "." + name, "range",
                                "mapping generation must be >= 0")
            if name == "expected_source_version" and val < 0:
                raise RuleError(path + ".expected_source_version", "range",
                                "source version must be >= 0")
        elif name == "range":
            validate_range(ev["range"], path + ".range")
        elif name == "status":
            require(ev, name, str, path,
                    enum=frozenset({"completed", "cancelled"}))
    if "perms" in ev:
        perms = ev["perms"]
        if not isinstance(perms, list) or not perms or \
                any(p not in ("r", "w") for p in perms):
            raise RuleError(path + ".perms", "bad_perms",
                            "perms must be a non-empty list from {r, w}")
    return etype


def validate_apply_case(case):
    path = "$"
    if not isinstance(case, dict):
        raise StructureError(path, "object", type(case).__name__)
    reject_unknown(case, {"case_id", "events"}, path)
    require(case, "case_id", str, path)
    events = require(case, "events", list, path)
    if not events:
        raise RuleError("events", "empty_batch", "an apply batch needs >= 1 "
                                                 "event")
    seen = set()
    types_seen = []
    for idx, ev in enumerate(events):
        etype = _validate_event(ev, idx)
        eid = ev["id"]
        if eid in seen:
            raise RuleError("events[%d].id" % idx, "duplicate_event",
                            "event id %r reused inside the batch" % eid)
        seen.add(eid)
        types_seen.append(etype)
    # A request_id may only be carried by one handoff request in a batch.
    req_ids = [ev["request_id"] for ev in events
               if ev["type"] == "handoff_request"]
    if len(set(req_ids)) != len(req_ids):
        raise RuleError("events.request_id", "duplicate_request",
                        "the same handoff request_id appears twice in a batch")
    return {"case_id": case["case_id"], "events": events}


def validate_inspect_query(query):
    path = "$"
    if not isinstance(query, dict):
        raise StructureError(path, "object", type(query).__name__)
    reject_unknown(query, {"case_id", "commit", "range"}, path)
    require(query, "case_id", str, path)
    if "commit" in query:
        commit = require(query, "commit", int, path)
        if commit < 0:
            raise RuleError("commit", "range", "commit must be >= 0")
    if "range" in query:
        validate_range(query["range"], "range")
    return query


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------

def validate_schedule_case(case):
    path = "$"
    if not isinstance(case, dict):
        raise StructureError(path, "object", type(case).__name__)
    reject_unknown(case, {"case_id", "windows", "targets", "commands"}, path)
    require(case, "case_id", str, path)
    windows = require(case, "windows", list, path)
    if not windows:
        raise RuleError("windows", "empty", "at least one maintenance window "
                                            "is required")
    win_ids = set()
    for i, win in enumerate(windows):
        wp = "windows[%d]" % i
        reject_unknown(win, {"window_id", "start", "duration",
                             "unresponsive_queues"}, wp)
        wid = require(win, "window_id", str, wp)
        if wid in win_ids:
            raise RuleError(wp + ".window_id", "duplicate_window",
                            "window id %r reused" % wid)
        win_ids.add(wid)
        start = require(win, "start", int, wp)
        duration = require(win, "duration", int, wp)
        if start < 0 or duration <= 0:
            raise RuleError(wp, "range", "start >= 0 and duration > 0 required")
        if "unresponsive_queues" in win:
            uq = require(win, "unresponsive_queues", list, wp)
            for j, item in enumerate(uq):
                reject_unknown(item, {"slot", "queue_no"},
                               wp + ".unresponsive_queues[%d]" % j)
                require(item, "slot", str,
                        wp + ".unresponsive_queues[%d]" % j)
                qn = require(item, "queue_no", int,
                             wp + ".unresponsive_queues[%d]" % j)
                if qn < 0:
                    raise RuleError(
                        wp + ".unresponsive_queues[%d].queue_no" % j,
                        "range", "queue_no must be >= 0")

    targets = require(case, "targets", list, path)
    if not targets:
        raise RuleError("targets", "empty", "at least one handoff target is "
                                            "required")
    target_ids = set()
    req_index = []
    for i, tgt in enumerate(targets):
        tp = "targets[%d]" % i
        reject_unknown(tgt, {"target_id", "device", "range", "deadline",
                             "from_owner", "to_owner", "requirements"}, tp)
        tid = require(tgt, "target_id", str, tp)
        if tid in target_ids:
            raise RuleError(tp + ".target_id", "duplicate_target",
                            "target id %r reused" % tid)
        target_ids.add(tid)
        require(tgt, "device", str, tp)
        validate_range(tgt["range"], tp + ".range")
        deadline = require(tgt, "deadline", int, tp)
        if deadline <= 0:
            raise RuleError(tp + ".deadline", "range", "deadline must be > 0")
        require(tgt, "from_owner", str, tp)
        require(tgt, "to_owner", str, tp)
        reqs = require(tgt, "requirements", list, tp)
        if not reqs:
            raise RuleError(tp + ".requirements", "empty",
                            "each target declares its queue conditions")
        for j, req in enumerate(reqs):
            rp = tp + ".requirements[%d]" % j
            reject_unknown(req, {"kind", "slot", "queue_no", "range"}, rp)
            kind = require(req, "kind", str, rp,
                           enum=frozenset({"invalidate", "drain"}))
            require(req, "slot", str, rp)
            qn = require(req, "queue_no", int, rp)
            if qn < 0:
                raise RuleError(rp + ".queue_no", "range",
                                "queue_no must be >= 0")
            if kind == "invalidate":
                validate_range(req["range"], rp + ".range")
            elif "range" in req:
                reject_unknown(req, {"kind", "slot", "queue_no", "range"}, rp)
            req_index.append((tid, kind, req["slot"], qn,
                              (req["range"]["start"], req["range"]["end"])
                              if kind == "invalidate" else None,
                              deadline))

    commands = require(case, "commands", list, path)
    if not commands:
        raise RuleError("commands", "empty", "at least one candidate command "
                                             "is required")
    cmd_ids = set()
    for i, cmd in enumerate(commands):
        cp = "commands[%d]" % i
        reject_unknown(cmd, {"command_id", "kind", "slot", "queue_no",
                             "duration", "range", "resources", "windows"}, cp)
        cid = require(cmd, "command_id", str, cp)
        if cid in cmd_ids:
            raise RuleError(cp + ".command_id", "duplicate_command",
                            "command id %r reused" % cid)
        cmd_ids.add(cid)
        kind = require(cmd, "kind", str, cp,
                       enum=frozenset({"invalidate", "drain"}))
        require(cmd, "slot", str, cp)
        qn = require(cmd, "queue_no", int, cp)
        if qn < 0:
            raise RuleError(cp + ".queue_no", "range", "queue_no >= 0")
        dur = require(cmd, "duration", int, cp)
        if dur <= 0:
            raise RuleError(cp + ".duration", "range", "duration must be > 0")
        if kind == "invalidate":
            validate_range(cmd["range"], cp + ".range")
        elif "range" in cmd:
            raise StructureError(cp + ".range", "absent for drain command",
                                 "present")
        if "resources" in cmd:
            res = require(cmd, "resources", list, cp)
            if any(not isinstance(r, str) or not r for r in res):
                raise StructureError(cp + ".resources",
                                     "array of non-empty strings", "bad item")
        opts = require(cmd, "windows", list, cp)
        if not opts:
            raise RuleError(cp + ".windows", "empty",
                            "each candidate needs at least one option window")
        for j, opt in enumerate(opts):
            op = cp + ".windows[%d]" % j
            reject_unknown(opt, {"window_id", "offset"}, op)
            wid = require(opt, "window_id", str, op)
            if wid not in win_ids:
                raise RuleError(op + ".window_id", "unknown_window",
                                "window %r not declared in windows" % wid)
            offset = require(opt, "offset", int, op)
            if offset < 0:
                raise RuleError(op + ".offset", "range",
                                "offset must be >= 0")
            win = next(w for w in windows if w["window_id"] == wid)
            if offset + dur > win["duration"]:
                raise RuleError(op, "out_of_window",
                                "command %s does not fit inside window %r"
                                % (cid, wid))
    _cross_check_target_windows(case)
    return case


def _cross_check_target_windows(case):
    """Every deadline must be reachable by at least one declared window."""
    for i, tgt in enumerate(case["targets"]):
        reachable = [w for w in case["windows"]
                     if w["start"] + w["duration"] <= tgt["deadline"]]
        if not reachable:
            raise RuleError("targets[%d].deadline" % i, "unreachable_deadline",
                            "no window ends before target %r deadline"
                            % tgt["target_id"])


def validate_address_bounds(value, field):
    if not (0 <= value <= ADDRESS_MAX):
        raise RuleError(field, "range", "address outside [0, 2^52]")

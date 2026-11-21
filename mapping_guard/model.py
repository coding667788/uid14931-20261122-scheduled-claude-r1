"""In-memory state machine and safety rules for the remapping auditor.

The model is rebuilt deterministically by replaying the durable event log,
so every rule lives here exactly once and ``inspect`` sees the same truth the
handoff transaction checked.

Identity model
--------------
* qi          -- (device, slot, queue_no): a reusable hot-plug queue slot.
* instance    -- monotonically increasing, never reused generation of a qi.
* mapping gen -- generation of a device's source mapping table entry.
* segment     -- a half-open [start, end) piece of a device mapping, kept at
                 segment granularity forever (never expanded per page).

A cache entry is residual on exactly the addresses where no *valid* segment of
its own device and mapping generation still covers it.  The same test decides
whether a pre-revoke command is still outstanding against a revoked mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import ranges
from .errors import RuleError


@dataclass
class Segment:
    device: str
    start: int
    end: int
    owner: str
    gen: int
    perms: tuple
    valid: bool = True
    removed_by: str = None       # event id that revoked/superseded this piece
    removed_seq: int = None


@dataclass
class CacheEntry:
    entry_id: str
    qi: tuple
    instance: int
    device: str
    gen: int
    start: int
    end: int
    acked: list = field(default_factory=list)   # canonical covered pieces
    publish_seq: int = 0
    publish_event: str = ""


@dataclass
class Command:
    cmd_id: str
    qi: tuple
    instance: int
    device: str
    gen: int
    start: int
    end: int
    status: str = "open"         # open | completed | cancelled
    register_seq: int = 0
    register_event: str = ""
    receipt_event: str = None


@dataclass
class Ack:
    ack_id: str
    qi: tuple
    instance: int
    device: str
    gen: int
    start: int
    end: int
    effective: bool
    reason: str
    seq: int


class State:
    def __init__(self):
        self.authz = {}                       # authz id -> binding dict
        self.qi = {}                          # qi -> {"instance": int|None}
        self.known_instances = {}             # qi -> set(instance)
        self.segments = {}                    # device -> list[Segment]
        self.source_version = {}              # device -> int
        self.caches = {}                      # qi -> list[CacheEntry]
        self.commands = {}                    # cmd_id -> Command
        self.acks = []                        # list[Ack]
        self.events = []                      # list of stored event dicts
        self.seen_ids = set()
        self.ack_ids = set()
        self.seq = 0
        self.handoffs = {}                    # request_id -> receipt dict

    # -- queue helpers -------------------------------------------------------

    def require_qi(self, device, slot, queue_no, path):
        qi = (device, slot, queue_no)
        if qi not in self.qi:
            raise RuleError(path, "unknown_queue",
                            "queue %r was never bound on device %r"
                            % ((slot, queue_no), device))
        return qi

    def require_instance(self, qi, instance, path):
        known = self.known_instances.get(qi, set())
        if instance not in known:
            raise RuleError(path, "unknown_instance",
                            "instance %s was never bound to queue %r"
                            % (instance, qi))
        return qi

    # -- mapping helpers -----------------------------------------------------

    def _device_segments(self, device):
        return self.segments.setdefault(device, [])

    def valid_segments(self, device):
        return [s for s in self.segments.get(device, []) if s.valid]

    def uncovered(self, device, gen, window):
        """Return residual pieces of window lacking valid same-gen coverage."""
        covered = [(s.start, s.end) for s in self.valid_segments(device)
                   if s.gen == gen]
        return ranges.subtract_many(window, covered)

    def _install(self, device, window, owner, gen, perms, event_id, revoke):
        """Replace valid coverage of window on device.

        Revoke (``revoke=True``) leaves no replacement; map/handoff install a
        fresh segment.  Superseded/revoked pieces keep their history with
        ``removed_by`` pointing at the causing event -- this is the trigger
        evidence reported by ``inspect``.  Sides outside the window survive.
        """
        segs = self._device_segments(device)
        new_history = []
        for seg in segs:
            if not seg.valid or not ranges.intersect((seg.start, seg.end), window):
                new_history.append(seg)
                continue
            for piece in ranges.subtract((seg.start, seg.end), window):
                new_history.append(Segment(
                    device, piece[0], piece[1], seg.owner, seg.gen, seg.perms,
                    valid=True))
            hit = ranges.intersect((seg.start, seg.end), window)
            new_history.append(Segment(
                device, hit[0], hit[1], seg.owner, seg.gen, seg.perms,
                valid=False, removed_by=event_id, removed_seq=self.seq + 1))
        if not revoke:
            new_history.append(Segment(
                device, window[0], window[1], owner, gen, tuple(perms),
                valid=True))
        self.segments[device] = new_history

    def bump(self, device):
        self.source_version[device] = self.source_version.get(device, 0) + 1
        return self.source_version[device]

    # -- trigger attribution -------------------------------------------------

    def trigger_for(self, device, gen, piece):
        """The event that ended same-gen coverage of `piece` (or None)."""
        best = None
        for seg in self.segments.get(device, []):
            if seg.gen != gen or seg.valid or not seg.removed_by:
                continue
            if ranges.intersect((seg.start, seg.end), piece):
                if best is None or seg.removed_seq > best.removed_seq:
                    best = seg
        return best

    # -- residual evidence ---------------------------------------------------

    def cache_residual_pieces(self, entry):
        """Residual (uncovered, not yet acked) pieces for one cache entry."""
        outstanding = ranges.subtract_many(
            (entry.start, entry.end), entry.acked)
        residual = []
        for piece in outstanding:
            residual.extend(self.uncovered(entry.device, entry.gen, piece))
        return ranges.canonical(residual)

    def stale_command_pieces(self, cmd):
        """Outstanding pieces of a pre-revoke command lacking a receipt.

        A command stays registered against the mapping generation it named.
        Once any address of that generation's mapping is revoked or
        superseded (remap/handoff), the command becomes a potential in-flight
        reference until it carries an explicit completed/cancelled receipt --
        a later mapping over the same pages must not let an old-generation
        command finish against current ownership.
        """
        if cmd.status != "open":
            return []
        # Was the generation this command targeted ever invalidated on any
        # part of its range? Invalidated (non-valid) segments carry removed_by.
        invalidated = [s for s in self.segments.get(cmd.device, [])
                       if s.gen == cmd.gen and not s.valid
                       and ranges.intersect((s.start, s.end),
                                            (cmd.start, cmd.end))]
        if not invalidated:
            return []
        # The command is outstanding across exactly the pieces whose named
        # generation no longer validly covers them.
        return self.uncovered(cmd.device, cmd.gen,
                              (cmd.start, cmd.end))

    def all_blockers(self, window=None):
        """Every outstanding invalidation blocker, optionally clipped to window."""
        out = []
        for qi, entries in self.caches.items():
            for entry in entries:
                for piece in self.cache_residual_pieces(entry):
                    if window is not None:
                        hit = ranges.intersect(piece, window)
                        if not hit:
                            continue
                        piece = hit
                    seg = self.trigger_for(entry.device, entry.gen, piece)
                    trigger = (seg.removed_by if seg else entry.publish_event)
                    out.append({
                        "kind": "cache",
                        "device": entry.device,
                        "queue": {"slot": qi[1], "queue_no": qi[2]},
                        "instance": entry.instance,
                        "gen": entry.gen,
                        "entry_id": entry.entry_id,
                        "range": {"start": piece[0], "end": piece[1]},
                        "trigger_event": trigger,
                    })
        for cmd in self.commands.values():
            for piece in self.stale_command_pieces(cmd):
                if window is not None:
                    hit = ranges.intersect(piece, window)
                    if not hit:
                        continue
                    piece = hit
                seg = self.trigger_for(cmd.device, cmd.gen, piece)
                trigger = (seg.removed_by if seg else cmd.register_event)
                out.append({
                    "kind": "command",
                    "device": cmd.device,
                    "queue": {"slot": cmd.qi[1], "queue_no": cmd.qi[2]},
                    "instance": cmd.instance,
                    "gen": cmd.gen,
                    "command_id": cmd.cmd_id,
                    "range": {"start": piece[0], "end": piece[1]},
                    "trigger_event": trigger,
                })
        out.sort(key=lambda b: (b["device"], b["kind"], b["entry_id"]
                                if b["kind"] == "cache" else b["command_id"],
                                b["range"]["start"], b["range"]["end"]))
        return out


# ----------------------------------------------------------------------------
# Event application
# ----------------------------------------------------------------------------

def apply_event(state, ev):
    """Apply one validated event. Returns a small per-event result dict."""
    etype = ev["type"]
    eid = ev["id"]
    if etype == "invalidate_ack":
        if eid in state.ack_ids:
            return {"event_id": eid, "effect": "duplicate_ack", "effective": True}
    elif eid in state.seen_ids:
        raise RuleError("events.id", "duplicate_event",
                        "event id %r already used" % eid)

    handler = _HANDLERS.get(etype)
    if handler is None:
        raise RuleError("events.type", "unknown_event_type",
                        "unknown event type %r" % etype)
    result = handler(state, ev)
    state.seq += 1
    state.seen_ids.add(eid)
    if etype == "invalidate_ack":
        state.ack_ids.add(eid)
    stored = dict(ev)
    stored["seq"] = state.seq
    state.events.append(stored)
    if result is None:
        result = {}
    result.setdefault("event_id", eid)
    result.setdefault("seq", state.seq)
    return result


def _h_bind(state, ev):
    path = "events.bind"
    qi = (ev["device"], ev["slot"], ev["queue_no"])
    instance = ev["instance"]
    # Instance generations are never reused: a known instance number may only
    # reappear to add another authorization (different gen/range) for the same
    # still-active binding, never to re-bind a removed/replaced instance.
    if instance in state.known_instances.get(qi, set()):
        if state.qi.get(qi, {}).get("instance") != instance:
            raise RuleError(path + ".instance", "instance_reuse",
                            "instance %s previously bound and removed; "
                            "instance generations can never be reused"
                            % instance)
    else:
        if qi in state.qi and state.qi[qi]["instance"] is not None \
                and instance <= state.qi[qi]["instance"]:
            raise RuleError(path + ".instance", "instance_not_advanced",
                            "new instance must exceed current instance %s"
                            % state.qi[qi]["instance"])
    rng = ranges.validate_range(ev["range"], path + ".range")
    perms = _validate_perms(ev.get("perms", ["r", "w"]), path)
    state.qi.setdefault(qi, {"instance": None})
    state.known_instances.setdefault(qi, set()).add(instance)
    if state.qi[qi]["instance"] is None:
        state.qi[qi]["instance"] = instance
    state.caches.setdefault(qi, [])
    state.authz[ev["id"]] = {
        "authz_id": ev["id"], "device": ev["device"], "qi": qi,
        "instance": instance, "gen": ev["gen"], "range": rng, "perms": perms,
    }
    state.segments.setdefault(ev["device"], [])
    state.source_version.setdefault(ev["device"], 0)
    return {"effect": "bound", "queue": _qi_json(qi), "instance": instance}


def _h_unbind(state, ev):
    path = "events.unbind"
    qi = state.require_qi(ev["device"], ev["slot"], ev["queue_no"], path)
    state.require_instance(qi, ev["instance"], path)
    if state.qi[qi]["instance"] != ev["instance"]:
        raise RuleError(path + ".instance", "not_current_instance",
                        "instance %s is not the active instance of %r"
                        % (ev["instance"], qi))
    state.qi[qi]["instance"] = None
    return {"effect": "unbound", "queue": _qi_json(qi),
            "instance": ev["instance"]}


def _find_authz(state, device, qi, instance, gen, window, path):
    for auth in state.authz.values():
        if (auth["device"] == device and auth["qi"] == qi
                and auth["instance"] == instance and auth["gen"] == gen
                and ranges.covered_by([auth["range"]], window)):
            return auth
    raise RuleError(path, "unauthorized",
                    "no authorization binds device=%r queue=%r instance=%s "
                    "gen=%s over %s" % (device, qi, instance, gen, window))


def _validate_perms(perms, path):
    if not isinstance(perms, list) or not perms or \
            any(p not in ("r", "w") for p in perms):
        raise RuleError(path, "bad_perms", "perms must be a non-empty list "
                                           "drawn from {r, w}")
    if len(set(perms)) != len(perms):
        raise RuleError(path, "bad_perms", "duplicate permissions")
    return tuple(sorted(perms))


def _h_map(state, ev):
    path = "events.map"
    window = ranges.validate_range(ev["range"], path + ".range")
    perms = _validate_perms(ev.get("perms", ["r", "w"]), path + ".perms")
    qi = state.require_qi(ev["device"], ev["slot"], ev["queue_no"], path)
    state.require_instance(qi, ev["instance"], path)
    _find_authz(state, ev["device"], qi, ev["instance"], ev["gen"], window, path)
    # A large range may cover existing mappings; sub-range remap preserves the
    # two valid side mappings (_install keeps pieces outside the window).
    state._install(ev["device"], window, ev["owner"], ev["gen"], perms,
                   ev["id"], revoke=False)
    version = state.bump(ev["device"])
    return {"effect": "mapped", "device": ev["device"],
            "range": {"start": window[0], "end": window[1]},
            "source_version": version}


def _h_revoke(state, ev):
    path = "events.revoke"
    window = ranges.validate_range(ev["range"], path + ".range")
    device = ev["device"]
    gen = ev["gen"]
    if not any(s.valid and s.gen == gen and ranges.intersect(
            (s.start, s.end), window) for s in state.segments.get(device, [])):
        raise RuleError(path, "revoke_without_mapping",
                        "no valid gen=%s mapping intersects %s on device %r"
                        % (gen, window, device))
    state._install(device, window, None, gen, (), ev["id"], revoke=True)
    version = state.bump(device)
    return {"effect": "revoked", "device": device,
            "range": {"start": window[0], "end": window[1]},
            "source_version": version}


def _h_register(state, ev):
    path = "events.register_command"
    window = ranges.validate_range(ev["range"], path + ".range")
    qi = state.require_qi(ev["device"], ev["slot"], ev["queue_no"], path)
    state.require_instance(qi, ev["instance"], path)
    if ev["cmd_id"] in state.commands:
        raise RuleError(path + ".cmd_id", "duplicate_command",
                        "command id %r already registered" % ev["cmd_id"])
    _find_authz(state, ev["device"], qi, ev["instance"], ev["gen"], window, path)
    # References cannot be inserted after the mapping they target is gone.
    missing = state.uncovered(ev["device"], ev["gen"], window)
    if missing:
        raise RuleError(path + ".range", "registration_after_revoke",
                        "addresses %s have no valid gen=%s mapping; "
                        "unregistered references may not be added after revoke"
                        % (ranges.to_json(missing), ev["gen"]))
    cmd = Command(ev["cmd_id"], qi, ev["instance"], ev["device"], ev["gen"],
                  window[0], window[1], register_seq=state.seq + 1,
                  register_event=ev["id"])
    state.commands[ev["cmd_id"]] = cmd
    return {"effect": "registered", "command_id": cmd.cmd_id}


def _h_receipt(state, ev):
    path = "events.command_receipt"
    cmd = state.commands.get(ev["cmd_id"])
    if cmd is None:
        raise RuleError(path + ".cmd_id", "unknown_command",
                        "no registered command %r" % ev["cmd_id"])
    if ev["status"] not in ("completed", "cancelled"):
        raise RuleError(path + ".status", "enum",
                        "receipt status must be completed or cancelled")
    if cmd.status != "open":
        if cmd.status == ev["status"]:
            return {"effect": "duplicate_receipt", "command_id": cmd.cmd_id,
                    "status": cmd.status}
        raise RuleError(path + ".status", "conflicting_receipt",
                        "command %r already %s" % (cmd.cmd_id, cmd.status))
    # An old-generation command may not complete against current page
    # ownership: completion is bookkeeping only and never clears cache state.
    cmd.status = ev["status"]
    cmd.receipt_event = ev["id"]
    return {"effect": "receipt", "command_id": cmd.cmd_id,
            "status": cmd.status}


def _h_publish(state, ev):
    path = "events.cache_publish"
    window = ranges.validate_range(ev["range"], path + ".range")
    qi = state.require_qi(ev["device"], ev["slot"], ev["queue_no"], path)
    state.require_instance(qi, ev["instance"], path)
    if state.qi[qi]["instance"] != ev["instance"]:
        raise RuleError(path + ".instance", "not_current_instance",
                        "cache entries may only be published by the active "
                        "instance of %r" % (qi,))
    _find_authz(state, ev["device"], qi, ev["instance"], ev["gen"], window, path)
    missing = state.uncovered(ev["device"], ev["gen"], window)
    if missing:
        raise RuleError(path + ".range", "publish_without_mapping",
                        "cache entry over %s has no valid gen=%s source mapping"
                        % (ranges.to_json(missing), ev["gen"]))
    if any(e.entry_id == ev["entry_id"] for e in state.caches.get(qi, [])):
        raise RuleError(path + ".entry_id", "duplicate_entry",
                        "cache entry %r already published" % ev["entry_id"])
    entry = CacheEntry(ev["entry_id"], qi, ev["instance"], ev["device"],
                       ev["gen"], window[0], window[1],
                       publish_seq=state.seq + 1, publish_event=ev["id"])
    state.caches[qi].append(entry)
    return {"effect": "published", "entry_id": entry.entry_id}


def _h_ack(state, ev):
    path = "events.invalidate_ack"
    window = ranges.validate_range(ev["range"], path + ".range")
    qi = state.require_qi(ev["device"], ev["slot"], ev["queue_no"], path)
    state.require_instance(qi, ev["instance"], path)
    entries = [e for e in state.caches.get(qi, [])
               if e.instance == ev["instance"] and e.gen == ev["gen"]]
    if not entries:
        state.acks.append(Ack(ev["id"], qi, ev["instance"], ev["device"],
                              ev["gen"], window[0], window[1], False,
                              "no_matching_instance_or_generation",
                              state.seq + 1))
        return {"effect": "ack_ignored", "effective": False,
                "reason": "no_matching_instance_or_generation"}
    hits = []
    for entry in entries:
        hit = ranges.intersect((entry.start, entry.end), window)
        if hit:
            entry.acked = ranges.canonical(entry.acked + [hit])
            hits.append(hit)
    if not hits:
        state.acks.append(Ack(ev["id"], qi, ev["instance"], ev["device"],
                              ev["gen"], window[0], window[1], False,
                              "range_without_entry", state.seq + 1))
        return {"effect": "ack_ignored", "effective": False,
                "reason": "range_without_entry"}
    state.acks.append(Ack(ev["id"], qi, ev["instance"], ev["device"],
                          ev["gen"], window[0], window[1], True, "applied",
                          state.seq + 1))
    return {"effect": "ack_applied", "effective": True,
            "covered": ranges.to_json(hits)}


def _h_handoff(state, ev):
    """The guarded page-ownership transfer (see storage.py for the durable
    transaction wrapper; this is the in-transaction verification + effect)."""
    path = "events.handoff_request"
    window = ranges.validate_range(ev["range"], path + ".range")
    device = ev["device"]

    # 1. expected source mapping version must match exactly.
    current_version = state.source_version.get(device, 0)
    if ev["expected_source_version"] != current_version:
        raise RuleError(path + ".expected_source_version", "version_conflict",
                        "expected source version %s but device %r is at %s"
                        % (ev["expected_source_version"], device,
                           current_version))

    # 2. the window must be explainable by this device's most recent mapping
    #    generation: every segment intersecting it -- valid or freshly revoked
    #    -- must belong to from_owner.  A window with no segment history at all
    #    (never mapped) cannot be handed off.
    window_segments = [s for s in state.segments.get(device, [])
                       if ranges.intersect((s.start, s.end), window)]
    if not window_segments:
        raise RuleError(path + ".range", "window_never_mapped",
                        "device %r never mapped the requested window" % device)
    covered = [(s.start, s.end) for s in window_segments]
    if not ranges.covered_by(covered, window):
        raise RuleError(path + ".range", "window_not_fully_mapped",
                        "handoff window is not fully explained by mapping "
                        "history of device %r" % device)
    bad_owner = [s for s in window_segments if s.owner != ev["from_owner"]]
    if bad_owner:
        raise RuleError(path + ".from_owner", "owner_conflict",
                        "window contains mappings not owned by %r"
                        % ev["from_owner"])
    # An active (unrevoked) mapping in the window is fine: handoff itself
    # supersedes it atomically.

    # 3. requesting device must be the sole holder: no other device may hold a
    #    valid mapping intersecting the window.
    for other_device, segs in state.segments.items():
        if other_device == device:
            continue
        for seg in segs:
            if seg.valid and ranges.intersect((seg.start, seg.end), window):
                raise RuleError(path + ".range", "other_device_holds_page",
                                "device %r still validly maps part of the "
                                "window" % other_device)

    # 4. every related device/queue must have zero outstanding references in
    #    the window: stale cache pieces and stale pre-revoke commands, on this
    #    device *and* any residual evidence left by other devices.
    blockers = state.all_blockers(window=window)
    if blockers:
        raise RuleError(path + ".range", "outstanding_references",
                        "%d blocker(s) remain in window, e.g. %r"
                        % (len(blockers), blockers[0]))

    perms = _validate_perms(ev.get("perms", ["r", "w"]), path + ".perms")
    new_gen = ev["new_gen"]
    used_gens = {s.gen for s in state.segments.get(device, [])}
    if new_gen in used_gens:
        raise RuleError(path + ".new_gen", "gen_reuse",
                        "new_gen %s already used on device %r"
                        % (new_gen, device))
    replaced_gens = sorted({s.gen for s in window_segments})
    state._install(device, window, ev["to_owner"], new_gen, perms,
                   ev["id"], revoke=False)
    version = state.bump(device)
    receipt = {
        "receipt_id": "rcpt-%s" % ev["request_id"],
        "request_id": ev["request_id"],
        "device": device,
        "range": {"start": window[0], "end": window[1]},
        "from_owner": ev["from_owner"],
        "to_owner": ev["to_owner"],
        "new_gen": new_gen,
        "replaced_gens": replaced_gens,
        "source_version": version,
        "commit": state.seq + 1,
    }
    state.handoffs[ev["request_id"]] = receipt
    return {"effect": "handoff_committed", **receipt}


_HANDLERS = {
    "bind": _h_bind,
    "unbind": _h_unbind,
    "map": _h_map,
    "revoke": _h_revoke,
    "register_command": _h_register,
    "command_receipt": _h_receipt,
    "cache_publish": _h_publish,
    "invalidate_ack": _h_ack,
    "handoff_request": _h_handoff,
}


def _qi_json(qi):
    return {"device": qi[0], "slot": qi[1], "queue_no": qi[2]}


def rebuild(events):
    """Replay durable events into a fresh State."""
    state = State()
    for ev in events:
        ev = dict(ev)
        ev.pop("seq", None)
        apply_event(state, ev)
    return state

"""Deterministic synthetic case generator for mapping_guard.

Running this module writes every scenario the README references into the
cases/ directory.  All data is invented from fixed integer patterns -- no
randomness, no hardware, no timestamps -- so output is byte-stable across
machines and reruns.

Scenarios produced
------------------
apply_full_lifecycle.json     -- bind/map/publish/revoke/ack/handoff happy path
apply_safety_rejections.json  -- deliberately unsafe events for negative tests
schedule_*.json               -- the five required schedule verifications plus
                                 the 24-command / 64-range / 8-queue scale case
"""

from __future__ import annotations

import json
import os

PAGE = 4096
HERE = os.path.dirname(os.path.abspath(__file__))


def write(name, obj):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    return path


# ---------------------------------------------------------------------------
# apply cases
# ---------------------------------------------------------------------------

def apply_lifecycle():
    events = [
        {"id": "bind-d0-q0-i1-g1", "type": "bind", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 0, "end": 16 * PAGE}},
        {"id": "map-d0-g1-wide", "type": "map", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "owner": "tenant-alpha",
         "range": {"start": 0, "end": 16 * PAGE}},
        {"id": "pub-ce-wide", "type": "cache_publish", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "entry_id": "cache-wide",
         "range": {"start": 0, "end": 16 * PAGE}},
        {"id": "bind-d0-q0-i1-g2", "type": "bind", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 2,
         "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
        # Sub-range remap: the two flanking gen-1 mappings must survive.
        {"id": "map-d0-g2-middle", "type": "map", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 2,
         "owner": "tenant-alpha",
         "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
        # Two partial acks merge to cover the short hole left in the old cache.
        {"id": "ack-hole-left", "type": "invalidate_ack", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 4 * PAGE, "end": 6 * PAGE}},
        {"id": "ack-hole-right", "type": "invalidate_ack", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 6 * PAGE, "end": 8 * PAGE}},
        # A command registered while the mapping is valid; revoke then drains.
        {"id": "reg-cmd-1", "type": "register_command", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 2,
         "cmd_id": "cmd-1", "range": {"start": 4 * PAGE, "end": 5 * PAGE}},
        {"id": "revoke-g2-middle", "type": "revoke", "device": "dev0",
         "gen": 2, "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
        {"id": "receipt-cmd-1", "type": "command_receipt",
         "cmd_id": "cmd-1", "status": "completed"},
        {"id": "ack-g2-full", "type": "invalidate_ack", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 2,
         "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
        {"id": "handoff-middle", "type": "handoff_request",
         "request_id": "req-handoff-middle", "device": "dev0",
         "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
         "expected_source_version": 3, "new_gen": 3,
         "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
    ]
    return {"case_id": "apply-full-lifecycle", "events": events}


def apply_safety():
    # Each event is individually well-formed; rejection comes from a safety
    # rule during replay.  Tests run them in small batches and assert codes.
    return {"case_id": "apply-safety-rejections", "events": [
        {"id": "b", "type": "bind", "device": "dev0", "slot": "slot0",
         "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 0, "end": PAGE}},
        {"id": "m", "type": "map", "device": "dev0", "slot": "slot0",
         "queue_no": 0, "instance": 1, "gen": 1, "owner": "tenant-alpha",
         "range": {"start": 0, "end": PAGE}},
        {"id": "pub", "type": "cache_publish", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "entry_id": "ce", "range": {"start": 0, "end": PAGE}},
        {"id": "rev", "type": "revoke", "device": "dev0", "gen": 1,
         "range": {"start": 0, "end": PAGE}},
        # 1) unregistered reference inserted after revoke.
        {"id": "late-reg", "type": "register_command", "device": "dev0",
         "slot": "slot0", "queue_no": 0, "instance": 1, "gen": 1,
         "cmd_id": "late-cmd", "range": {"start": 0, "end": 100}},
        # 2) handoff while cache evidence is still outstanding.
        {"id": "early-handoff", "type": "handoff_request",
         "request_id": "req-early", "device": "dev0",
         "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
         "expected_source_version": 2, "new_gen": 2,
         "range": {"start": 0, "end": PAGE}},
        # 3) stale source version expectation.
        {"id": "stale-version", "type": "handoff_request",
         "request_id": "req-stale", "device": "dev0",
         "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
         "expected_source_version": 1, "new_gen": 2,
         "range": {"start": 0, "end": PAGE}},
    ]}


# ---------------------------------------------------------------------------
# schedule cases
# ---------------------------------------------------------------------------

def _window(wid, start, duration, dead_queues=None):
    w = {"window_id": wid, "start": start, "duration": duration}
    if dead_queues:
        w["unresponsive_queues"] = [
            {"slot": "slot%d" % q, "queue_no": q} for q in dead_queues]
    return w


def schedule_short_hole():
    # Local large-range invalidation must leave only the short hole [4k,8k).
    return {
        "case_id": "sched-short-hole",
        "windows": [_window("w1", 0, 30), _window("w2", 40, 30)],
        "targets": [{
            "target_id": "tg1", "device": "dev0",
            "range": {"start": 0, "end": 16 * PAGE}, "deadline": 100,
            "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
            "requirements": [
                {"kind": "invalidate", "slot": "slot0", "queue_no": 0,
                 "range": {"start": 4 * PAGE, "end": 8 * PAGE}},
            ]}],
        "commands": [
            {"command_id": "hole-a", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 4,
             "range": {"start": 4 * PAGE, "end": 6 * PAGE},
             "windows": [{"window_id": "w1", "offset": 0},
                         {"window_id": "w2", "offset": 0}]},
            {"command_id": "hole-b", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 4,
             "range": {"start": 6 * PAGE, "end": 8 * PAGE},
             "windows": [{"window_id": "w1", "offset": 4},
                         {"window_id": "w2", "offset": 4}]},
        ],
    }


def schedule_replay_after_handoff():
    # A queue declared potentially dead in both windows needs independent
    # redundancy; the post-handoff replay of old acks cannot count (modeled in
    # apply tests). Here the solver must double-cover the condition.
    return {
        "case_id": "sched-replay-after-handoff",
        "windows": [
            _window("w1", 0, 20, dead_queues=[0]),
            _window("w2", 30, 20, dead_queues=[0])],
        "targets": [{
            "target_id": "tg1", "device": "dev0",
            "range": {"start": 0, "end": PAGE}, "deadline": 80,
            "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
            "requirements": [
                {"kind": "invalidate", "slot": "slot0", "queue_no": 0,
                 "range": {"start": 0, "end": PAGE}},
                {"kind": "drain", "slot": "slot0", "queue_no": 0},
            ]}],
        "commands": [
            {"command_id": "inv-1", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 5,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w1", "offset": 0}]},
            {"command_id": "inv-2", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 5,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w2", "offset": 0}]},
            {"command_id": "drain-1", "kind": "drain", "slot": "slot0",
             "queue_no": 0, "duration": 3,
             "windows": [{"window_id": "w1", "offset": 8}]},
            {"command_id": "drain-2", "kind": "drain", "slot": "slot0",
             "queue_no": 0, "duration": 3,
             "windows": [{"window_id": "w2", "offset": 8}]},
        ],
    }


def schedule_two_devices_same_page():
    # Two devices with residual caches on the same page: each queue condition
    # must be covered independently before the page may change owner.  Every
    # queue can be unresponsive in one of the two windows, so the fixed plan
    # has to place work for each queue in both windows.
    return {
        "case_id": "sched-two-devices-same-page",
        "windows": [
            _window("w1", 0, 40, dead_queues=[0]),
            _window("w2", 50, 40, dead_queues=[1])],
        "targets": [{
            "target_id": "tg1", "device": "dev0",
            "range": {"start": 0, "end": PAGE}, "deadline": 120,
            "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
            "requirements": [
                {"kind": "invalidate", "slot": "slot0", "queue_no": 0,
                 "range": {"start": 0, "end": PAGE}},
                {"kind": "invalidate", "slot": "slot1", "queue_no": 1,
                 "range": {"start": 0, "end": PAGE}},
            ]}],
        "commands": [
            {"command_id": "dev0-inv-a", "kind": "invalidate",
             "slot": "slot0", "queue_no": 0, "duration": 6,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w1", "offset": 0}]},
            {"command_id": "dev0-inv-b", "kind": "invalidate",
             "slot": "slot0", "queue_no": 0, "duration": 6,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w2", "offset": 0}]},
            {"command_id": "dev1-inv-a", "kind": "invalidate",
             "slot": "slot1", "queue_no": 1, "duration": 6,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w1", "offset": 0}]},
            {"command_id": "dev1-inv-b", "kind": "invalidate",
             "slot": "slot1", "queue_no": 1, "duration": 6,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w2", "offset": 0}]},
        ],
    }


def schedule_primary_backup_fixed():
    # Primary/backup windows cannot pick plans at runtime: one static plan must
    # survive a fault in either window.  The two windows declare *different*
    # potentially-unresponsive queues, which makes a fixed plan achievable
    # while still proving runtime window switching is not allowed.
    return {
        "case_id": "sched-primary-backup-fixed",
        "windows": [
            _window("primary", 0, 25, dead_queues=[0]),
            _window("backup", 40, 25, dead_queues=[1])],
        "targets": [{
            "target_id": "tg1", "device": "dev0",
            "range": {"start": 0, "end": 2 * PAGE}, "deadline": 120,
            "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
            "requirements": [
                {"kind": "invalidate", "slot": "slot0", "queue_no": 0,
                 "range": {"start": 0, "end": PAGE}},
                {"kind": "invalidate", "slot": "slot1", "queue_no": 1,
                 "range": {"start": PAGE, "end": 2 * PAGE}},
            ]}],
        "commands": [
            # Queue 0: two distinct commands, one per window, so the plan
            # survives queue-0 being unresponsive in the primary window.
            {"command_id": "q0-in-primary", "kind": "invalidate",
             "slot": "slot0", "queue_no": 0, "duration": 5,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "primary", "offset": 0}]},
            {"command_id": "q0-in-backup", "kind": "invalidate",
             "slot": "slot0", "queue_no": 0, "duration": 5,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "backup", "offset": 0}]},
            # Queue 1: the symmetric pair for the backup-window fault.
            {"command_id": "q1-in-primary", "kind": "invalidate",
             "slot": "slot1", "queue_no": 1, "duration": 5,
             "range": {"start": PAGE, "end": 2 * PAGE},
             "windows": [{"window_id": "primary", "offset": 0}]},
            {"command_id": "q1-in-backup", "kind": "invalidate",
             "slot": "slot1", "queue_no": 1, "duration": 5,
             "range": {"start": PAGE, "end": 2 * PAGE},
             "windows": [{"window_id": "backup", "offset": 0}]},
        ],
    }


def schedule_bruteforce_crosscheck():
    # Tiny (<=8 commands) instance whose optimum the tests cross-check with
    # independent exhaustive enumeration.
    return {
        "case_id": "sched-brute-crosscheck",
        "windows": [
            _window("w1", 0, 20, dead_queues=[0]),
            _window("w2", 30, 20, dead_queues=[1])],
        "targets": [
            {"target_id": "tg1", "device": "dev0",
             "range": {"start": 0, "end": PAGE}, "deadline": 100,
             "from_owner": "a", "to_owner": "b",
             "requirements": [
                 {"kind": "invalidate", "slot": "slot0", "queue_no": 0,
                  "range": {"start": 0, "end": PAGE}},
                 {"kind": "drain", "slot": "slot1", "queue_no": 1},
             ]}],
        "commands": [
            {"command_id": "i-w1", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 4,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w1", "offset": 0}]},
            {"command_id": "i-w2", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 4,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w2", "offset": 0}]},
            {"command_id": "d-w1", "kind": "drain", "slot": "slot1",
             "queue_no": 1, "duration": 3,
             "windows": [{"window_id": "w1", "offset": 0}]},
            {"command_id": "d-w2", "kind": "drain", "slot": "slot1",
             "queue_no": 1, "duration": 3,
             "windows": [{"window_id": "w2", "offset": 0}]},
            # Decoy: same coverage as i-w2 but longer -- must never be chosen.
            {"command_id": "i-w2-slow", "kind": "invalidate", "slot": "slot0",
             "queue_no": 0, "duration": 9,
             "range": {"start": 0, "end": PAGE},
             "windows": [{"window_id": "w2", "offset": 0}]},
        ],
    }


def schedule_scale():
    """Required scale: 24 candidate commands, 64 ranges, 8 queues.

    Layout: 8 queues x 3 commands = 24 commands.  The 64 target ranges are
    distributed round-robin over the 8 queues (8 single-page ranges each).
    Each queue's three commands split its eight ranges into groups of
    3 + 3 + 2.  Four windows, each declaring a different pair of potentially
    unresponsive queues: every command carries option windows in two windows
    whose fault pairs never contain this queue together, so a fixed plan can
    place each command twice across independent windows and survive every
    allowed single-queue fault.
    """
    n_queues = 8
    n_ranges = 64
    windows = [
        _window("w1", 0, 40, dead_queues=[0, 1]),
        _window("w2", 60, 40, dead_queues=[2, 3]),
        _window("w3", 120, 40, dead_queues=[4, 5]),
        _window("w4", 180, 40, dead_queues=[6, 7]),
    ]
    # Two windows per queue such that no single fault pair blocks both:
    # queue q is dead in window (q//2), and alive in the opposite half.
    safe_window_pairs = {
        0: ("w1", "w3"), 1: ("w1", "w3"),
        2: ("w2", "w4"), 3: ("w2", "w4"),
        4: ("w3", "w1"), 5: ("w3", "w1"),
        6: ("w4", "w2"), 7: ("w4", "w2"),
    }
    targets = []
    commands = []
    for q in range(n_queues):
        queue_ranges = list(range(q, n_ranges, n_queues))  # 8 range indices
        requirements = []
        for idx in queue_ranges:
            start = idx * PAGE
            requirements.append({
                "kind": "invalidate", "slot": "slot%d" % q, "queue_no": q,
                "range": {"start": start, "end": start + PAGE},
            })
        targets.append({
            "target_id": "tg-q%d" % q, "device": "dev0",
            "range": {"start": queue_ranges[0] * PAGE,
                      "end": queue_ranges[-1] * PAGE + PAGE},
            "deadline": 260, "from_owner": "tenant-alpha",
            "to_owner": "tenant-beta", "requirements": requirements,
        })
        win_a, win_b = safe_window_pairs[q]
        # Three distinct commands per queue (24 total).  Each command covers
        # the queue's full span (union of its 8 ranges); they differ in
        # duration and in the pair of windows they can run in, so a fixed plan
        # can select two of them in fault-independent windows.
        full_start = queue_ranges[0] * PAGE
        full_end = queue_ranges[-1] * PAGE + PAGE
        placements = [
            (win_a, win_b),
            (win_b, win_a),
            (win_a, win_b),
        ]
        for g in range(3):
            wa, wb = placements[g]
            commands.append({
                "command_id": "q%d-g%d" % (q, g),
                "kind": "invalidate", "slot": "slot%d" % q, "queue_no": q,
                "duration": 3 + g,
                "range": {"start": full_start, "end": full_end},
                "resources": ["link%d" % (q % 2)],
                "windows": [
                    {"window_id": wa, "offset": 0},
                    {"window_id": wb, "offset": 0},
                ],
            })
    return {"case_id": "sched-scale-24-64-8", "windows": windows,
            "targets": targets, "commands": commands}


ALL = {
    "apply_full_lifecycle.json": apply_lifecycle,
    "apply_safety_rejections.json": apply_safety,
    "schedule_short_hole.json": schedule_short_hole,
    "schedule_replay_after_handoff.json": schedule_replay_after_handoff,
    "schedule_two_devices_same_page.json": schedule_two_devices_same_page,
    "schedule_primary_backup_fixed.json": schedule_primary_backup_fixed,
    "schedule_bruteforce_crosscheck.json": schedule_bruteforce_crosscheck,
    "schedule_scale_24_64_8.json": schedule_scale,
}


def main():
    written = []
    for name, builder in ALL.items():
        written.append(write(name, builder()))
    for path in written:
        print(os.path.relpath(path, HERE))


if __name__ == "__main__":
    main()

"""Tests for the state-machine safety rules and SQLite transaction protocol."""

import json
import os
import tempfile
import unittest

from mapping_guard.errors import RuleError
from mapping_guard.model import rebuild
from mapping_guard.storage import (apply_batch, canonical_json,
                                   handoff_content_hash, inspect, open_db)
from mapping_guard.validation import validate_apply_case

PAGE = 4096


def bind(eid, instance, gen, start, end, device="dev0", slot="s0", q=0):
    return {"id": eid, "type": "bind", "device": device, "slot": slot,
            "queue_no": q, "instance": instance, "gen": gen,
            "range": {"start": start, "end": end}}


def map_ev(eid, instance, gen, owner, start, end, device="dev0",
           slot="s0", q=0):
    return {"id": eid, "type": "map", "device": device, "slot": slot,
            "queue_no": q, "instance": instance, "gen": gen, "owner": owner,
            "range": {"start": start, "end": end}}


def publish(eid, entry, instance, gen, start, end, device="dev0",
            slot="s0", q=0):
    return {"id": eid, "type": "cache_publish", "device": device, "slot": slot,
            "queue_no": q, "instance": instance, "gen": gen, "entry_id": entry,
            "range": {"start": start, "end": end}}


def revoke(eid, gen, start, end, device="dev0"):
    return {"id": eid, "type": "revoke", "device": device, "gen": gen,
            "range": {"start": start, "end": end}}


def ack(eid, instance, gen, start, end, device="dev0", slot="s0", q=0):
    return {"id": eid, "type": "invalidate_ack", "device": device,
            "slot": slot, "queue_no": q, "instance": instance, "gen": gen,
            "range": {"start": start, "end": end}}


def handoff(eid, request_id, sv, new_gen, start, end, frm="tenantA",
            to="tenantB", device="dev0"):
    return {"id": eid, "type": "handoff_request", "request_id": request_id,
            "device": device, "from_owner": frm, "to_owner": to,
            "expected_source_version": sv, "new_gen": new_gen,
            "range": {"start": start, "end": end}}


class TempDB(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mg-test-")
        self.db = os.path.join(self.dir, "log.sqlite")

    def open(self):
        return open_db(self.db)

    def apply(self, events, case_id="case"):
        conn = self.open()
        try:
            return apply_batch(
                conn, validate_apply_case(
                    {"case_id": case_id, "events": events}))
        finally:
            conn.close()

    def inspect(self, **query):
        conn = self.open()
        try:
            query.setdefault("case_id", "case")
            return inspect(conn, query)
        finally:
            conn.close()


class TestSubRangeRemap(TempDB):

    def test_sides_survive_and_short_hole(self):
        events = [
            bind("b", 1, 1, 0, 3 * PAGE),
            map_ev("m", 1, 1, "tenantA", 0, 3 * PAGE),
            publish("p", "ce", 1, 1, 0, 3 * PAGE),
            bind("b2", 1, 2, PAGE, 2 * PAGE),
            map_ev("m2", 1, 2, "tenantA", PAGE, 2 * PAGE),
        ]
        self.apply(events)
        view = self.inspect(commit=5)["legal_ownership_at_commit"]
        segs = sorted((s["range"]["start"], s["range"]["end"], s["gen"])
                      for s in view)
        self.assertEqual(segs, [(0, PAGE, 1), (PAGE, 2 * PAGE, 2),
                                (2 * PAGE, 3 * PAGE, 1)])
        # Old cache only retains a residual on the replaced short hole.
        blockers = self.inspect()["blocking_queues"]
        self.assertEqual(blockers[0]["minimal_blocking_range"],
                         [{"start": PAGE, "end": 2 * PAGE}])

    def test_partial_acks_merge(self):
        events = [
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
            ack("a1", 1, 1, 0, PAGE // 2),
            ack("a2", 1, 1, PAGE // 2, PAGE),
        ]
        self.apply(events)
        self.assertTrue(self.inspect()["fully_drained"])

    def test_overlapping_delayed_replayed_acks(self):
        events = [
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
            ack("a1", 1, 1, 0, 3 * PAGE // 4),
            ack("a2", 1, 1, PAGE // 2, PAGE),   # overlaps a1
        ]
        self.apply(events)
        self.assertTrue(self.inspect()["fully_drained"])
        # Replaying an already stored event is an explicit no-op, not a crash.
        again = self.apply([events[-1]])
        self.assertIn("replayed", again["event_results"][0]["effect"])


class TestInstanceGenerations(TempDB):

    def test_instance_number_never_reused(self):
        self.apply([bind("b1", 1, 1, 0, PAGE),
                    {"id": "u", "type": "unbind", "device": "dev0",
                     "slot": "s0", "queue_no": 0, "instance": 1}])
        with self.assertRaises(RuleError) as ctx:
            self.apply([bind("b2", 1, 1, 0, PAGE)])
        self.assertEqual(ctx.exception.code, "instance_reuse")

    def test_new_instance_ack_cannot_clear_old_cache(self):
        events = [
            bind("b1", 1, 1, 0, PAGE),
            map_ev("m1", 1, 1, "tenantA", 0, PAGE),
            publish("p1", "ce1", 1, 1, 0, PAGE),
            revoke("r1", 1, 0, PAGE),
            {"id": "u1", "type": "unbind", "device": "dev0", "slot": "s0",
             "queue_no": 0, "instance": 1},
            bind("b2", 2, 2, 0, PAGE),
            map_ev("m2", 2, 2, "tenantB", 0, PAGE),
            publish("p2", "ce2", 2, 2, 0, PAGE),
            revoke("r2", 2, 0, PAGE),
            # Old instance (1) speaking about gen2 must be ignored.
            ack("a-old", 1, 2, 0, PAGE),
        ]
        self.apply(events)
        out = self.inspect()
        self.assertFalse(out["fully_drained"])
        # The old-instance ack must not have cleared the instance-2 cache:
        # a blocker attributed to instance 2 with entry ce2 remains.
        missing = [m for group in out["blocking_queues"]
                   for m in group["missing_evidence"]]
        new_cache_blockers = [m for m in missing
                              if m["kind"] == "cache"
                              and m["instance"] == 2
                              and m["entry_id"] == "ce2"]
        self.assertTrue(new_cache_blockers)
        # And the stale ack itself is recorded as ineffective.
        conn = self.open()
        try:
            acks = conn.execute(
                "SELECT payload FROM events WHERE type='invalidate_ack'")
            payloads = [json.loads(r["payload"]) for r in acks]
            self.assertEqual(payloads[0]["instance"], 1)
        finally:
            conn.close()


class TestHandoffProtocol(TempDB):

    def _drained_setup(self):
        return [
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
            ack("a", 1, 1, 0, PAGE),
        ]

    def test_handoff_writes_receipt_and_switches_owner(self):
        self.apply(self._drained_setup())
        res = self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])
        receipt = res["handoff_receipts"][0]
        self.assertEqual(receipt["from_owner"], "tenantA")
        self.assertEqual(receipt["to_owner"], "tenantB")
        self.assertEqual(receipt["replaced_gens"], [1])
        view = self.inspect()["legal_ownership_at_commit"]
        self.assertEqual(view[0]["owner"], "tenantB")
        self.assertEqual(view[0]["gen"], 2)

    def test_handoff_blocked_while_references_outstanding(self):
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
        ])
        with self.assertRaises(RuleError) as ctx:
            self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])
        self.assertEqual(ctx.exception.code, "outstanding_references")

    def test_stale_source_version_rejected(self):
        self.apply(self._drained_setup())
        bad = handoff("h", "req1", 1, 2, 0, PAGE)  # version is now 2
        with self.assertRaises(RuleError) as ctx:
            self.apply([bad])
        self.assertEqual(ctx.exception.code, "version_conflict")

    def test_other_device_holding_page_blocks_handoff(self):
        # Two devices validly map the same host page.
        events = [
            bind("b0", 1, 1, 0, PAGE, device="dev0"),
            map_ev("m0", 1, 1, "tenantA", 0, PAGE, device="dev0"),
            bind("b1", 1, 1, 0, PAGE, device="dev1", slot="s1", q=1),
            map_ev("m1", 1, 1, "tenantA", 0, PAGE, device="dev1",
                   slot="s1", q=1),
            publish("p0", "ce0", 1, 1, 0, PAGE, device="dev0"),
            revoke("r0", 1, 0, PAGE, device="dev0"),
            ack("a0", 1, 1, 0, PAGE, device="dev0"),
        ]
        self.apply(events)
        with self.assertRaises(RuleError) as ctx:
            self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])
        self.assertEqual(ctx.exception.code, "other_device_holds_page")

    def test_idempotent_same_content_returns_original_receipt(self):
        self.apply(self._drained_setup())
        h = handoff("h", "req1", 2, 2, 0, PAGE)
        first = self.apply([h])["handoff_receipts"][0]
        second = self.apply([h])
        self.assertEqual(second["event_results"][0]["effect"],
                         "idempotent_replay")
        self.assertEqual(second["handoff_receipts"][0], first)
        conn = self.open()
        try:
            n = conn.execute("SELECT COUNT(*) AS n FROM handoffs").fetchone()
            self.assertEqual(n["n"], 1)
        finally:
            conn.close()

    def test_different_content_same_request_rejects_batch(self):
        self.apply(self._drained_setup())
        self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])
        bad = handoff("h2", "req1", 3, 99, 0, PAGE)
        with self.assertRaises(RuleError) as ctx:
            self.apply([bad])
        self.assertEqual(ctx.exception.code, "handoff_conflict")

    def test_batch_atomicity_on_failure(self):
        self.apply(self._drained_setup())
        head_before = self.inspect()["commit_head"]
        # First event valid, second invalid: nothing durable may land.
        with self.assertRaises(RuleError):
            self.apply([
                {"id": "noop-ack", "type": "invalidate_ack",
                 "device": "dev0", "slot": "s0", "queue_no": 0,
                 "instance": 1, "gen": 1, "range": {"start": 0, "end": 1}},
                handoff("h-bad", "reqX", 99, 2, 0, PAGE),
            ])
        self.assertEqual(self.inspect()["commit_head"], head_before)

    def test_content_hash_stable(self):
        h = handoff("h", "req1", 2, 2, 0, PAGE)
        h2 = dict(h)
        h2["id"] = "different-event-id"
        self.assertEqual(handoff_content_hash(h), handoff_content_hash(h2))


class TestCommands(TempDB):

    def test_registration_after_revoke_forbidden(self):
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            revoke("r", 1, 0, PAGE),
        ])
        with self.assertRaises(RuleError) as ctx:
            self.apply([{
                "id": "late", "type": "register_command", "device": "dev0",
                "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
                "cmd_id": "c1", "range": {"start": 0, "end": 100}}])
        self.assertEqual(ctx.exception.code, "registration_after_revoke")

    def test_prerevoke_command_needs_receipt_before_handoff(self):
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            {"id": "reg", "type": "register_command", "device": "dev0",
             "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
             "cmd_id": "c1", "range": {"start": 0, "end": 100}},
            revoke("r", 1, 0, PAGE),
        ])
        with self.assertRaises(RuleError) as ctx:
            self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])
        self.assertEqual(ctx.exception.code, "outstanding_references")
        self.apply([{"id": "rc", "type": "command_receipt",
                     "cmd_id": "c1", "status": "cancelled"}])
        self.apply([handoff("h", "req1", 2, 2, 0, PAGE)])

    def test_old_generation_command_completion_is_bookkeeping_only(self):
        # A completed receipt must not erase outstanding cache evidence.
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            {"id": "reg", "type": "register_command", "device": "dev0",
             "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
             "cmd_id": "c1", "range": {"start": 0, "end": 100}},
            revoke("r", 1, 0, PAGE),
            {"id": "rc", "type": "command_receipt", "cmd_id": "c1",
             "status": "completed"},
        ])
        self.assertFalse(self.inspect()["fully_drained"])

    def test_open_old_command_blocks_handoff_even_after_remap(self):
        # Revoke then remap the same pages under a new generation: the open
        # pre-revoke gen-1 command must still block until it gets a receipt.
        self.apply([
            bind("b1", 1, 1, 0, PAGE),
            map_ev("m1", 1, 1, "tenantA", 0, PAGE),
            {"id": "reg", "type": "register_command", "device": "dev0",
             "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
             "cmd_id": "c1", "range": {"start": 0, "end": 100}},
            revoke("r1", 1, 0, PAGE),
            bind("b2", 1, 2, 0, PAGE),
            map_ev("m2", 1, 2, "tenantA", 0, PAGE),
        ])
        with self.assertRaises(RuleError) as ctx:
            self.apply([handoff("h", "req1", 3, 3, 0, PAGE)])
        self.assertEqual(ctx.exception.code, "outstanding_references")
        blockers = self.inspect()["blocking_queues"]
        cmd_blockers = [m for g in blockers for m in g["missing_evidence"]
                        if m["kind"] == "command"]
        self.assertTrue(cmd_blockers)
        self.apply([{"id": "rc", "type": "command_receipt",
                     "cmd_id": "c1", "status": "cancelled"}])

    def test_old_command_receipt_after_handoff_still_cannot_finish(self):
        # Even after ownership moves, a receipt for a pre-revoke old-gen
        # command is bookkeeping and cannot satisfy new-owner evidence.
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            {"id": "reg", "type": "register_command", "device": "dev0",
             "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
             "cmd_id": "c1", "range": {"start": 0, "end": 100}},
            revoke("r", 1, 0, PAGE),
            ack("a", 1, 1, 0, PAGE),
            {"id": "rc", "type": "command_receipt", "cmd_id": "c1",
             "status": "completed"},
            handoff("h", "req1", 2, 2, 0, PAGE),
        ])
        view = self.inspect()
        # New owner owns the page; the old command's receipt never created a
        # mapping or cache entry under the new generation.
        new_segments = [s for s in view["legal_ownership_at_commit"]
                        if s["gen"] == 2]
        self.assertEqual(len(new_segments), 1)
        self.assertEqual(new_segments[0]["owner"], "tenantB")

    def test_permissions_are_bound_and_audited(self):
        events = [
            {**bind("b", 1, 1, 0, PAGE), "perms": ["r"]},
            {**map_ev("m", 1, 1, "tenantA", 0, PAGE), "perms": ["r"]},
        ]
        self.apply(events)
        seg = self.inspect()["legal_ownership_at_commit"][0]
        self.assertEqual(seg["perms"], ["r"])

    def test_address_cap_end_to_end(self):
        cap = 1 << 52
        events = [
            bind("b", 1, 1, cap - PAGE, cap),
            map_ev("m", 1, 1, "tenantA", cap - PAGE, cap),
            publish("p", "ce", 1, 1, cap - PAGE, cap),
            revoke("r", 1, cap - PAGE, cap),
            ack("a", 1, 1, cap - PAGE, cap),
            handoff("h", "req1", 2, 2, cap - PAGE, cap),
        ]
        self.apply(events)
        seg = self.inspect()["legal_ownership_at_commit"][0]
        self.assertEqual(seg["range"], {"start": cap - PAGE, "end": cap})


class TestHistoricalView(TempDB):

    def test_inspect_only_reads_legal_ownership_at_commit(self):
        self.apply([
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
            ack("a", 1, 1, 0, PAGE),
            handoff("h", "req1", 2, 2, 0, PAGE),
        ])
        at5 = self.inspect(commit=5)
        self.assertEqual(at5["legal_ownership_at_commit"], [])
        self.assertEqual(at5["handoffs_visible_at_commit"], [])
        at6 = self.inspect(commit=6)
        self.assertEqual(at6["legal_ownership_at_commit"][0]["owner"],
                         "tenantB")
        self.assertEqual(len(at6["handoffs_visible_at_commit"]), 1)

    def test_inspect_commit_ahead_of_head_rejected(self):
        self.apply([bind("b", 1, 1, 0, PAGE)])
        with self.assertRaises(RuleError):
            self.inspect(commit=99)

    def test_event_rebuild_is_deterministic(self):
        events = [
            bind("b", 1, 1, 0, PAGE),
            map_ev("m", 1, 1, "tenantA", 0, PAGE),
            publish("p", "ce", 1, 1, 0, PAGE),
            revoke("r", 1, 0, PAGE),
        ]
        s1 = rebuild(events)
        s2 = rebuild(events)
        self.assertEqual(canonical_json([
            {"gen": x.gen, "valid": x.valid, "start": x.start, "end": x.end}
            for x in s1.segments["dev0"]]),
            canonical_json([
                {"gen": x.gen, "valid": x.valid, "start": x.start,
                 "end": x.end} for x in s2.segments["dev0"]]))


if __name__ == "__main__":
    unittest.main()

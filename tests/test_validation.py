"""Unit tests for interval algebra and field-level validation."""

import json
import unittest

from mapping_guard import ranges
from mapping_guard.errors import RuleError, StructureError
from mapping_guard.validation import (validate_apply_case,
                                      validate_schedule_case)


class TestRanges(unittest.TestCase):

    def test_intersect(self):
        self.assertEqual(ranges.intersect((0, 10), (5, 15)), (5, 10))
        self.assertIsNone(ranges.intersect((0, 5), (5, 10)))  # half-open

    def test_subtract_keeps_both_sides(self):
        self.assertEqual(ranges.subtract((0, 100), (40, 60)),
                         [(0, 40), (60, 100)])
        self.assertEqual(ranges.subtract((0, 10), (20, 30)), [(0, 10)])
        self.assertEqual(ranges.subtract((0, 10), (0, 10)), [])

    def test_subtract_many_merges(self):
        pieces = ranges.subtract_many((0, 100), [(10, 20), (80, 90)])
        self.assertEqual(pieces, [(0, 10), (20, 80), (90, 100)])

    def test_covered_by(self):
        self.assertTrue(ranges.covered_by([(0, 50), (50, 100)], (0, 100)))
        self.assertFalse(ranges.covered_by([(0, 49)], (0, 100)))

    def test_address_cap_is_2_pow_52(self):
        ok = {"start": 0, "end": 1 << 52}
        self.assertEqual(ranges.validate_range(ok, "$"), (0, 1 << 52))
        with self.assertRaises(RuleError):
            ranges.validate_range({"start": 0, "end": (1 << 52) + 1}, "$")
        with self.assertRaises(RuleError):
            ranges.validate_range({"start": 10, "end": 10}, "$")

    def test_no_per_page_representation(self):
        # A 2^52 span stays one segment; ranges never enumerate pages.
        big = (0, 1 << 52)
        self.assertEqual(ranges.subtract_many(big, [(1 << 20, 1 << 21)]),
                         [(0, 1 << 20), (1 << 21, 1 << 52)])


class TestStructureErrors(unittest.TestCase):

    def test_wrong_top_level_type(self):
        with self.assertRaises(StructureError) as ctx:
            validate_apply_case(["not", "an", "object"])
        self.assertEqual(ctx.exception.field, "$")
        self.assertEqual(ctx.exception.code, "structure")

    def test_missing_field_path(self):
        with self.assertRaises(StructureError) as ctx:
            validate_apply_case({"case_id": "x"})
        self.assertEqual(ctx.exception.field, "$.events")

    def test_wrong_field_type_path(self):
        case = {"case_id": "x", "events": [
            {"id": "e1", "type": "map", "device": 7}]}
        with self.assertRaises(StructureError) as ctx:
            validate_apply_case(case)
        self.assertEqual(ctx.exception.field, "events[0].device")

    def test_unknown_event_type(self):
        case = {"case_id": "x", "events": [
            {"id": "e1", "type": "teleport", "device": "d"}]}
        with self.assertRaises(RuleError) as ctx:
            validate_apply_case(case)
        self.assertEqual(ctx.exception.code, "enum")

    def test_unknown_field_rejected(self):
        case = {"case_id": "x", "surprise": 1, "events": []}
        with self.assertRaises(StructureError) as ctx:
            validate_apply_case(case)
        self.assertEqual(ctx.exception.field, "$.surprise")

    def test_duplicate_event_id_in_batch(self):
        case = {"case_id": "x", "events": [
            {"id": "e", "type": "revoke", "device": "d", "gen": 1,
             "range": {"start": 0, "end": 1}},
            {"id": "e", "type": "revoke", "device": "d", "gen": 1,
             "range": {"start": 0, "end": 1}}]}
        with self.assertRaises(RuleError) as ctx:
            validate_apply_case(case)
        self.assertEqual(ctx.exception.code, "duplicate_event")

    def test_boolean_is_not_integer(self):
        case = {"case_id": "x", "events": [
            {"id": "e", "type": "revoke", "device": "d", "gen": True,
             "range": {"start": 0, "end": 1}}]}
        with self.assertRaises(StructureError):
            validate_apply_case(case)

    def test_schedule_bad_window_fit(self):
        case = {
            "case_id": "s",
            "windows": [{"window_id": "w", "start": 0, "duration": 5}],
            "targets": [{
                "target_id": "t", "device": "d",
                "range": {"start": 0, "end": 4096}, "deadline": 100,
                "from_owner": "a", "to_owner": "b",
                "requirements": [{"kind": "drain", "slot": "s0",
                                  "queue_no": 0}]}],
            "commands": [{
                "command_id": "c", "kind": "drain", "slot": "s0",
                "queue_no": 0, "duration": 9,
                "windows": [{"window_id": "w", "offset": 0}]}],
        }
        with self.assertRaises(RuleError) as ctx:
            validate_schedule_case(case)
        self.assertEqual(ctx.exception.code, "out_of_window")

    def test_schedule_unknown_window_reference(self):
        case = {
            "case_id": "s",
            "windows": [{"window_id": "w", "start": 0, "duration": 10}],
            "targets": [{
                "target_id": "t", "device": "d",
                "range": {"start": 0, "end": 4096}, "deadline": 100,
                "from_owner": "a", "to_owner": "b",
                "requirements": [{"kind": "drain", "slot": "s0",
                                  "queue_no": 0}]}],
            "commands": [{
                "command_id": "c", "kind": "drain", "slot": "s0",
                "queue_no": 0, "duration": 2,
                "windows": [{"window_id": "ghost", "offset": 0}]}],
        }
        with self.assertRaises(RuleError) as ctx:
            validate_schedule_case(case)
        self.assertEqual(ctx.exception.code, "unknown_window")


if __name__ == "__main__":
    unittest.main()

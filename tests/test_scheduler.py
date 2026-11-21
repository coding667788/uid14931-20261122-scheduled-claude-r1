"""Tests for the robust maintenance scheduler."""

import json
import os
import unittest

from mapping_guard.scheduler import Solver, solve_schedule
from mapping_guard.validation import validate_schedule_case

CASES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "cases")


def load(name):
    with open(os.path.join(CASES, name), "r", encoding="utf-8") as fh:
        return validate_schedule_case(json.load(fh))


class TestSmallOptimumVsBruteForce(unittest.TestCase):
    """Independent exhaustive enumeration must agree on every small case."""

    SMALL = [
        "schedule_short_hole.json",
        "schedule_replay_after_handoff.json",
        "schedule_two_devices_same_page.json",
        "schedule_primary_backup_fixed.json",
        "schedule_bruteforce_crosscheck.json",
    ]

    def test_branch_and_bound_matches_brute_force(self):
        for name in self.SMALL:
            with self.subTest(case=name):
                solver = Solver(load(name))
                dfs = solver.solve()
                brute = solver.brute_force_plan()
                self.assertIsNotNone(dfs)
                self.assertIsNotNone(brute)
                self.assertEqual(dfs[0], brute[0],
                                 "objective mismatch on %s" % name)
                # And every plan the solver emits truly survives each fault.
                response = solve_schedule(load(name))
                self.assertTrue(response["feasible"])
                for scenario in response["robustness"]["results"]:
                    self.assertTrue(
                        scenario["all_targets_still_on_time"],
                        "%s fails scenario %s" % (name, scenario["scenario"]))


class TestObjectiveOrdering(unittest.TestCase):

    def test_duration_then_count_then_ordered_key(self):
        case = load("schedule_bruteforce_crosscheck.json")
        response = solve_schedule(case)
        # The slow decoy command i-w2-slow must never be chosen.
        self.assertNotIn("i-w2-slow",
                         [p["command_id"] for p in response["plan"]])
        obj = response["objective"]
        # Explicitly verify lexicographic structure types.
        self.assertIsInstance(obj["total_pause_duration"], int)
        self.assertIsInstance(obj["command_count"], int)
        starts = [k["start"] for k in obj["ordered_key"]]
        self.assertEqual(starts, sorted(starts))

    def test_command_id_executes_at_most_once(self):
        for name in TestSmallOptimumVsBruteForce.SMALL:
            response = solve_schedule(load(name))
            ids = [p["command_id"] for p in response["plan"]]
            self.assertEqual(len(ids), len(set(ids)), name)

    def test_no_resource_conflicts_in_plan(self):
        for name in TestSmallOptimumVsBruteForce.SMALL:
            response = solve_schedule(load(name))
            plan = response["plan"]
            for a in plan:
                for b in plan:
                    if a is b:
                        continue
                    overlap = not (a["start"] >= b["finish"]
                                   or b["start"] >= a["finish"])
                    if overlap and a["window_id"] == b["window_id"]:
                        self.assertFalse(
                            set(a["resources"]) & set(b["resources"]),
                            "%s: %s conflicts %s" % (name, a["command_id"],
                                                     b["command_id"]))


class TestInfeasibleReports(unittest.TestCase):

    def test_single_faulty_window_no_redundancy(self):
        case = {
            "case_id": "infeasible",
            "windows": [{"window_id": "w", "start": 0, "duration": 20,
                         "unresponsive_queues": [
                             {"slot": "s0", "queue_no": 0}]}],
            "targets": [{
                "target_id": "t", "device": "d",
                "range": {"start": 0, "end": 4096}, "deadline": 100,
                "from_owner": "a", "to_owner": "b",
                "requirements": [{"kind": "drain", "slot": "s0",
                                  "queue_no": 0}]}],
            "commands": [{
                "command_id": "c", "kind": "drain", "slot": "s0",
                "queue_no": 0, "duration": 3,
                "windows": [{"window_id": "w", "offset": 0}]}],
        }
        response = solve_schedule(validate_schedule_case(case))
        self.assertFalse(response["feasible"])
        report = response["blocker_report"]
        self.assertIn(report["kind"],
                      {"not_handoffable", "no_conflict_free_plan"})
        self.assertTrue(report["uncovered_conditions"])

    def test_structurally_uncoverable_range(self):
        case = {
            "case_id": "hole",
            "windows": [{"window_id": "w", "start": 0, "duration": 20}],
            "targets": [{
                "target_id": "t", "device": "d",
                "range": {"start": 0, "end": 8192}, "deadline": 100,
                "from_owner": "a", "to_owner": "b",
                "requirements": [{"kind": "invalidate", "slot": "s0",
                                  "queue_no": 0,
                                  "range": {"start": 0, "end": 8192}}]}],
            "commands": [{
                "command_id": "c", "kind": "invalidate", "slot": "s0",
                "queue_no": 0, "duration": 3,
                "range": {"start": 0, "end": 4096},
                "windows": [{"window_id": "w", "offset": 0}]}],
        }
        response = solve_schedule(validate_schedule_case(case))
        self.assertFalse(response["feasible"])
        cond = response["blocker_report"]["uncovered_conditions"][0]
        self.assertEqual(cond["reason"], "range_uncoverable")
        self.assertEqual(cond["missing_ranges"],
                         [{"start": 4096, "end": 8192}])

    def test_earliest_deadline_reported_first(self):
        case = {
            "case_id": "earliest",
            "windows": [{"window_id": "w", "start": 0, "duration": 20,
                         "unresponsive_queues": [
                             {"slot": "s0", "queue_no": 0},
                             {"slot": "s1", "queue_no": 1}]}],
            "targets": [
                {"target_id": "late", "device": "d",
                 "range": {"start": 0, "end": 4096}, "deadline": 200,
                 "from_owner": "a", "to_owner": "b",
                 "requirements": [{"kind": "drain", "slot": "s1",
                                   "queue_no": 1}]},
                {"target_id": "early", "device": "d",
                 "range": {"start": 0, "end": 4096}, "deadline": 100,
                 "from_owner": "a", "to_owner": "b",
                 "requirements": [{"kind": "drain", "slot": "s0",
                                   "queue_no": 0}]},
            ],
            "commands": [
                {"command_id": "c0", "kind": "drain", "slot": "s0",
                 "queue_no": 0, "duration": 2,
                 "windows": [{"window_id": "w", "offset": 0}]},
                {"command_id": "c1", "kind": "drain", "slot": "s1",
                 "queue_no": 1, "duration": 2,
                 "windows": [{"window_id": "w", "offset": 0}]},
            ],
        }
        response = solve_schedule(validate_schedule_case(case))
        self.assertFalse(response["feasible"])
        self.assertEqual(
            response["blocker_report"]["earliest_target_id"], "early")


class TestScaleCase(unittest.TestCase):

    def test_required_dimensions(self):
        case = load("schedule_scale_24_64_8.json")
        self.assertEqual(len(case["commands"]), 24)
        self.assertEqual(
            sum(len(t["requirements"]) for t in case["targets"]), 64)
        self.assertEqual(len({c["slot"] for c in case["commands"]}), 8)

    def test_scale_plan_feasible_and_fast(self):
        import time
        case = load("schedule_scale_24_64_8.json")
        t0 = time.perf_counter()
        response = solve_schedule(case)
        elapsed = time.perf_counter() - t0
        self.assertTrue(response["feasible"])
        self.assertLess(elapsed, 5.0, "solver too slow on scale case")
        # Robustness: baseline plus one scenario per declared fault pair.
        n_faults = sum(len(w.get("unresponsive_queues", []))
                       for w in case["windows"])
        self.assertEqual(response["robustness"]["scenarios_checked"],
                         1 + n_faults)
        self.assertTrue(all(r["all_targets_still_on_time"]
                            for r in response["robustness"]["results"]))

    def test_deterministic_output(self):
        case = load("schedule_scale_24_64_8.json")
        first = json.dumps(solve_schedule(case), sort_keys=True,
                           ensure_ascii=False)
        second = json.dumps(solve_schedule(case), sort_keys=True,
                            ensure_ascii=False)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

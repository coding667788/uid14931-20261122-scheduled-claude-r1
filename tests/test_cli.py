"""End-to-end tests through the exact acceptance CLI entry point.

These invoke ``python -m mapping_guard ...`` as a subprocess so they exercise
argument parsing, exit codes, UTF-8 JSON on stdout and file handling exactly
as the acceptance harness will.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = os.path.join(ROOT, "cases")


class CliTestCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mg-cli-")
        self.db = os.path.join(self.dir, "db.sqlite")

    def run_cli(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "mapping_guard", *args],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
        return proc.returncode, proc.stdout, proc.stderr

    def test_apply_inspect_schedule_happy_path(self):
        code, out, err = self.run_cli(
            "apply", os.path.join(CASES, "apply_full_lifecycle.json"),
            "--db", self.db)
        self.assertEqual(code, 0, err)
        applied = json.loads(out)
        self.assertTrue(applied["ok"])
        self.assertEqual(len(applied["handoff_receipts"]), 1)

        query = {"case_id": "apply-full-lifecycle",
                 "commit": applied["commit_head"]}
        qpath = os.path.join(self.dir, "query.json")
        with open(qpath, "w", encoding="utf-8") as fh:
            json.dump(query, fh)
        code, out, err = self.run_cli("inspect", qpath, "--db", self.db)
        self.assertEqual(code, 0, err)
        view = json.loads(out)
        self.assertTrue(view["ok"])
        self.assertTrue(view["fully_drained"])
        owners = {(s["range"]["start"], s["owner"])
                  for s in view["legal_ownership_at_commit"]}
        self.assertIn((4 * 4096, "tenant-beta"), owners)

        code, out, err = self.run_cli(
            "schedule", os.path.join(CASES, "schedule_short_hole.json"))
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["feasible"])

    def test_structure_error_exit_code_2(self):
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"case_id": 1, "events": []}, fh)
        code, out, _ = self.run_cli("apply", bad, "--db", self.db)
        self.assertEqual(code, 2)
        envelope = json.loads(out)
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["error"]["code"], "structure")
        self.assertIn("case_id", envelope["error"]["field"])

    def test_rule_error_exit_code_3(self):
        code, out, _ = self.run_cli(
            "apply", os.path.join(CASES, "apply_safety_rejections.json"),
            "--db", self.db)
        self.assertEqual(code, 3)
        envelope = json.loads(out)
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["error"]["code"],
                         "registration_after_revoke")

    def test_apply_without_db_is_rejected(self):
        code, out, _ = self.run_cli(
            "apply", os.path.join(CASES, "apply_full_lifecycle.json"))
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["error"]["code"], "db_required")

    def test_missing_file(self):
        code, out, _ = self.run_cli(
            "schedule", os.path.join(self.dir, "nope.json"))
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["error"]["code"], "file_not_found")

    def test_inspect_range_filter(self):
        self.run_cli(
            "apply", os.path.join(CASES, "apply_full_lifecycle.json"),
            "--db", self.db)
        query = {"case_id": "apply-full-lifecycle",
                 "range": {"start": 100 * 4096, "end": 101 * 4096}}
        qpath = os.path.join(self.dir, "query.json")
        with open(qpath, "w", encoding="utf-8") as fh:
            json.dump(query, fh)
        code, out, err = self.run_cli("inspect", qpath, "--db", self.db)
        self.assertEqual(code, 0, err)
        view = json.loads(out)
        # Nothing relevant lives in that distant window.
        self.assertEqual(view["blocking_queues"], [])

    def test_repeated_apply_is_byte_stable(self):
        # schedule output is pure and byte-stable across runs.
        outs = []
        for _ in range(2):
            code, out, err = self.run_cli(
                "schedule", os.path.join(CASES, "schedule_short_hole.json"))
            self.assertEqual(code, 0, err)
            outs.append(out)
        self.assertEqual(outs[0], outs[1])

        # Re-applying the same events to one database returns the stored
        # receipt through the idempotent path (single durable handoff row).
        db = self.db
        self.run_cli("apply",
                     os.path.join(CASES, "apply_full_lifecycle.json"),
                     "--db", db)
        code, out, err = self.run_cli(
            "apply", os.path.join(CASES, "apply_full_lifecycle.json"),
            "--db", db)
        self.assertEqual(code, 0, err)
        replay = json.loads(out)
        self.assertTrue(all(
            r["effect"] in ("replayed", "idempotent_replay")
            for r in replay["event_results"]))
        self.assertEqual(len(replay["handoff_receipts"]), 1)


if __name__ == "__main__":
    unittest.main()

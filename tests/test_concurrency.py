"""Two-process concurrency tests using the barrier server in concurrency.py.

Every scenario spawns real OS processes against one shared SQLite file; no
thread ever touches the database in these tests.
"""

import json
import os
import tempfile
import unittest

from mapping_guard.concurrency import (scenario_first_handoff_race,
                                       scenario_historical_view,
                                       scenario_post_commit_loss,
                                       scenario_pre_commit_abort)
from mapping_guard.storage import inspect, open_db


class ConcurrencyTestCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mg-conc-")

    def test_first_handoff_race_single_winner(self):
        report = scenario_first_handoff_race(self.dir)
        statuses = sorted(w["status"] for w in report["workers"])
        self.assertEqual(statuses, ["committed", "rejected"])
        loser = next(w for w in report["workers"]
                     if w["status"] == "rejected")
        # The loser re-verified inside its own transaction and lost on a
        # version/content/unique conflict rather than crashing.
        self.assertIn(loser["code"],
                      {"version_conflict", "handoff_conflict",
                       "concurrent_commit_conflict", "outstanding_references"})
        self.assertEqual(report["handoff_rows"], 1)

    def test_pre_commit_abort_leaves_no_trace(self):
        report = scenario_pre_commit_abort(self.dir)
        self.assertEqual(report["abort"]["status"], "aborted")
        # The five evidence events survive; only the handoff rolled back.
        self.assertEqual(report["head_after_abort"], 5)
        self.assertEqual(report["handoffs_after_abort"], 0)
        self.assertEqual(report["retry"]["status"], "committed")
        self.assertEqual(report["retry"]["receipts"], 1)

    def test_post_commit_response_loss_returns_original_receipt(self):
        report = scenario_post_commit_loss(self.dir)
        self.assertTrue(report["killed_winner"])
        # The retry must be an idempotent replay of the original receipt,
        # leaving exactly one durable handoff row and six event rows.
        self.assertEqual(report["retry"]["status"], "replayed")
        self.assertEqual(report["retry"]["effect"], "idempotent_replay")
        self.assertEqual(report["handoff_rows"], 1)
        self.assertEqual(report["event_rows"], 6)
        self.assertEqual(report["stored_receipt"]["to_owner"], "tenantB")
        self.assertEqual(report["retry"]["receipt"],
                         report["stored_receipt"])

    def test_historical_view_reads_only_then_legal_ownership(self):
        report = scenario_historical_view(self.dir)
        self.assertEqual(report["writer"]["status"], "written")
        reader = report["reader"]
        self.assertEqual(reader["status"], "read")
        # At commit 5 the mapping had been revoked: no valid ownership.
        self.assertIsNone(reader["owner_at_5"])
        self.assertEqual(reader["handoffs_visible_at_5"], 0)
        # At commit 6 the handoff is visible with the new tenant.
        self.assertEqual(reader["owner_at_6"], "tenantB")
        self.assertEqual(reader["handoffs_visible_at_6"], 1)

    def test_database_file_has_no_per_page_rows(self):
        # The scale of persisted rows must stay independent of page count.
        scenario_pre_commit_abort(self.dir)
        db = os.path.join(self.dir, "abort.sqlite")
        conn = open_db(db)
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            for table in ("events", "handoffs", "meta"):
                self.assertIn(table, tables)
            n_events = conn.execute(
                "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            # Six events for a 4096-page-scale window would explode under
            # per-page storage; here it is the event count only.
            self.assertLessEqual(n_events, 8)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

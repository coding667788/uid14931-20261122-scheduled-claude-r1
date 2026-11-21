"""Two-process concurrency verification with an in-process barrier server.

The four required behaviors are proven using genuinely separate OS processes
against one real SQLite file -- never threads sharing an in-memory state:

  1. first_handoff_race      -- two workers rush the same handoff window;
                                exactly one commit wins, the loser is rejected
                                after re-verifying inside its transaction.
  2. pre_commit_abort        -- a fault aborts the writer before COMMIT; the
                                durable log is empty and a retry succeeds.
  3. post_commit_loss        -- the winner dies after COMMIT but before the
                                response is delivered; the duplicate request
                                returns the original receipt (single commit).
  4. historical_view         -- a long-running reader proves inspect at an
                                old commit only reports ownership legal then,
                                even while another process commits new events.

Workers coordinate through BarrierServer: each named barrier releases once
two participant messages have arrived, and workers block until the release.
The storage layer reaches the barrier through MAPPING_GUARD_BARRIER_URL.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid

from .storage import open_db, inspect


class BarrierServer:
    """One-shot multi-participant barriers over plain TCP (localhost only)."""

    def __init__(self, host="127.0.0.1", port=0, expect=2):
        self.host = host
        self.expect = expect
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self.port = self._sock.getsockname()[1]
        self._cond = threading.Condition()
        self._arrived = {}
        self._released = set()
        self._closed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.listen(8)
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        with conn:
            try:
                data = conn.recv(4096).decode("utf-8")
            except OSError:
                return
            if not data:
                return
            token, phase, _request = data.split("|", 2)
            key = (token, phase)
            with self._cond:
                count = self._arrived.get(key, 0) + 1
                self._arrived[key] = count
                if count >= self.expect:
                    self._released.add(key)
                    self._cond.notify_all()
                else:
                    deadline = time.monotonic() + 30
                    while key not in self._released and \
                            time.monotonic() < deadline:
                        self._cond.wait(timeout=max(0, deadline
                                                    - time.monotonic()))
                    if key not in self._released:
                        conn.sendall(b"timeout")
                        return
            try:
                conn.sendall(b"ok")
            except OSError:
                pass

    def stop(self):
        with self._cond:
            self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def _worker_env(server, token, db_path, extra=None):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["MAPPING_GUARD_BARRIER_URL"] = "127.0.0.1:%d" % server.port
    env["MAPPING_GUARD_BARRIER_TOKEN"] = token
    env["MAPPING_GUARD_BARRIER_PHASES"] = "before_verify"
    env["MAPPING_GUARD_DB"] = db_path
    if extra:
        env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Scenario case builders
# ---------------------------------------------------------------------------

def build_race_case():
    """Two tenants, one device with one queue; a fully-evidenced handoff."""
    events = [
        {"id": "ev-bind", "type": "bind", "device": "dev0", "slot": "s0",
         "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 0, "end": 4096}},
        {"id": "ev-map", "type": "map", "device": "dev0", "slot": "s0",
         "queue_no": 0, "instance": 1, "gen": 1, "owner": "tenantA",
         "range": {"start": 0, "end": 4096}},
        {"id": "ev-pub", "type": "cache_publish", "device": "dev0",
         "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
         "entry_id": "ce1", "range": {"start": 0, "end": 4096}},
        {"id": "ev-rev", "type": "revoke", "device": "dev0", "gen": 1,
         "range": {"start": 0, "end": 4096}},
        {"id": "ev-ack", "type": "invalidate_ack", "device": "dev0",
         "slot": "s0", "queue_no": 0, "instance": 1, "gen": 1,
         "range": {"start": 0, "end": 4096}},
    ]
    return events


def handoff_event(eid, request_id="req-1"):
    return {"id": eid, "type": "handoff_request",
            "request_id": request_id, "device": "dev0",
            "from_owner": "tenantA", "to_owner": "tenantB",
            "expected_source_version": 2, "new_gen": 2,
            "range": {"start": 0, "end": 4096}}


# ---------------------------------------------------------------------------
# Worker entry points (executed in the subprocess)
# ---------------------------------------------------------------------------

def _run_apply(db_path, case):
    from .validation import validate_apply_case
    from .storage import apply_batch, open_db
    conn = open_db(db_path)
    try:
        return apply_batch(conn, validate_apply_case(case))
    finally:
        conn.close()


def worker_race(db_path, case_path, role):
    with open(case_path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    # Distinct request ids per role: this is a genuine write race rather than
    # an idempotent replay of the same request.
    case["events"].append(
        handoff_event("ev-handoff-%s" % role, "req-race-%s" % role))
    try:
        result = _run_apply(db_path, case)
        print(json.dumps({"role": role, "status": "committed",
                          "receipts": len(result["handoff_receipts"])}))
    except Exception as exc:  # noqa: BLE001 -- worker reports any failure
        print(json.dumps({"role": role, "status": "rejected",
                          "code": getattr(exc, "code", type(exc).__name__),
                          "message": str(exc)}))


def worker_abort(db_path, case_path):
    with open(case_path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    case["events"].append(handoff_event("ev-handoff-abort"))
    try:
        _run_apply(db_path, case)
        print(json.dumps({"status": "committed_unexpectedly"}))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "aborted",
                          "code": getattr(exc, "code", type(exc).__name__)}))


def worker_retry(db_path, case_path):
    with open(case_path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    case["events"].append(
        handoff_event("ev-handoff-retry-%d" % os.getpid(), "req-1"))
    result = _run_apply(db_path, case)
    print(json.dumps({"status": "committed",
                      "receipts": len(result["handoff_receipts"]),
                      "receipt": result["handoff_receipts"][0]}))


def worker_replay_same_request(db_path, case_path):
    """Post-loss retry: identical request_id and content must replay the
    original receipt rather than create a second handoff."""
    with open(case_path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    # Fresh event id (the durable log rejects reused ids); the idempotency key
    # is the request_id + content hash, which intentionally stay identical.
    case["events"].append(
        handoff_event("ev-handoff-replay-%d" % os.getpid(), "req-1"))
    result = _run_apply(db_path, case)
    print(json.dumps({
        "status": "replayed",
        "effect": result["event_results"][-1]["effect"],
        "receipt": result["handoff_receipts"][0]}))


def worker_history(db_path, case_path):
    """Reader that snapshots the pre-handoff view and re-checks after."""
    from .storage import open_db, inspect
    _ = case_path
    conn = open_db(db_path)
    try:
        before = inspect(conn, {"case_id": "conc", "commit": 5})
        owners_before = {(s["device"], s["range"]["start"]): s["owner"]
                         for s in before["legal_ownership_at_commit"]}
        handoffs_before = before["handoffs_visible_at_commit"]
        # Barrier guarantees the writer has committed by the time this returns.
        from .storage import _barrier
        _barrier("reader_checkpoint", "history")
        after = inspect(conn, {"case_id": "conc", "commit": 6})
        owners_after = {(s["device"], s["range"]["start"]): s["owner"]
                        for s in after["legal_ownership_at_commit"]}
        print(json.dumps({
            "status": "read",
            "owner_at_5": owners_before.get(("dev0", 0)),
            "handoffs_visible_at_5": len(handoffs_before),
            "owner_at_6": owners_after.get(("dev0", 0)),
            "handoffs_visible_at_6":
                len(after["handoffs_visible_at_commit"]),
        }))
    finally:
        conn.close()


def worker_writer_history(db_path, case_path):
    with open(case_path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    case["events"].append(handoff_event("ev-handoff-history"))
    _run_apply(db_path, case)
    from .storage import _barrier
    _barrier("reader_checkpoint", "history")
    print(json.dumps({"status": "written"}))


# ---------------------------------------------------------------------------
# Process spawning
# ---------------------------------------------------------------------------

def _spawn(entry_name, env, case_path, extra_args=None):
    # -I (isolated mode) ignores PYTHONPATH and cwd, so inject the repo root
    # into sys.path explicitly inside the worker's own bootstrap code.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    norm_root = os.path.normcase(os.path.abspath(repo_root))
    extra_args = list(extra_args or [])
    code = (
        "import sys; sys.path.insert(0, {root!r});"
        "import json;"
        "from mapping_guard.concurrency import {entry};"
        "{entry}(*sys.argv[1:])"
    ).format(root=norm_root, entry=entry_name)
    argv = [env["MAPPING_GUARD_DB"], case_path] + extra_args
    return subprocess.Popen(
        [sys.executable, "-I", "-c", code, *argv],
        cwd=repo_root, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8")


def _read_json(proc):
    try:
        out, err = proc.communicate(timeout=60)
    except Exception:
        proc.kill()
        proc.communicate()
        raise
    if not out.strip():
        raise RuntimeError("worker produced no output; stderr=%s" % err)
    return json.loads(out.strip().splitlines()[-1]), err


# ---------------------------------------------------------------------------
# Scenario runners
# ---------------------------------------------------------------------------

def scenario_first_handoff_race(workdir):
    db_path = os.path.join(workdir, "race.sqlite")
    case_path = os.path.join(workdir, "race-case.json")
    with open(case_path, "w", encoding="utf-8") as fh:
        json.dump({"case_id": "conc", "events": build_race_case()}, fh)
    server = BarrierServer(expect=2)
    token = uuid.uuid4().hex
    try:
        env_a = _worker_env(server, token, db_path)
        env_b = _worker_env(server, token, db_path)
        pa = _spawn("worker_race", env_a, case_path, ["A"])
        pb = _spawn("worker_race", env_b, case_path, ["B"])
        ra, _ = _read_json(pa)
        rb, _ = _read_json(pb)
    finally:
        server.stop()
    conn = open_db(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) AS n FROM handoffs").fetchone()["n"]
        seq = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    finally:
        conn.close()
    return {"workers": [ra, rb], "handoff_rows": count, "event_rows": seq}


def scenario_pre_commit_abort(workdir):
    db_path = os.path.join(workdir, "abort.sqlite")
    case_path = os.path.join(workdir, "abort-case.json")
    base_events = build_race_case()
    with open(case_path, "w", encoding="utf-8") as fh:
        json.dump({"case_id": "conc", "events": []}, fh)
    # Durably commit the evidence base first; workers then race only the
    # handoff itself so the pre-commit abort provably leaves zero handoff rows
    # while preserving the five preceding events.
    from .validation import validate_apply_case
    _run_apply(db_path, {"case_id": "conc", "events": base_events})
    server = BarrierServer(expect=1)
    token = uuid.uuid4().hex
    try:
        # No rendezvous partner in this single-worker scenario: disable the
        # storage before_verify barrier via an empty phase allowlist while
        # keeping the barrier URL configured for diagnostics.
        env_abort = _worker_env(server, token, db_path, {
            "MAPPING_GUARD_ABORT_REQUEST": "req-1",
            "MAPPING_GUARD_BARRIER_PHASES": ""})
        pa = _spawn("worker_abort", env_abort, case_path)
        aborted, _ = _read_json(pa)
    finally:
        server.stop()
    conn = open_db(db_path)
    try:
        empty = conn.execute(
            "SELECT COUNT(*) AS n FROM handoffs").fetchone()["n"] == 0
        head = conn.execute(
            "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    finally:
        conn.close()
    server = BarrierServer(expect=1)
    token = uuid.uuid4().hex
    try:
        env_retry = _worker_env(server, token, db_path,
                                {"MAPPING_GUARD_BARRIER_PHASES": ""})
        pr = _spawn("worker_retry", env_retry, case_path)
        retried, _ = _read_json(pr)
    finally:
        server.stop()
    return {"abort": aborted, "handoffs_after_abort": 0 if empty else None,
            "head_after_abort": head, "retry": retried}


def scenario_post_commit_loss(workdir):
    """The winner commits but its response is lost (process killed after the
    durable COMMIT).  A retry carrying the same request_id must return the
    original stored receipt; the handoff table keeps a single row.
    """
    db_path = os.path.join(workdir, "loss.sqlite")
    case_path = os.path.join(workdir, "loss-case.json")
    with open(case_path, "w", encoding="utf-8") as fh:
        json.dump({"case_id": "conc", "events": []}, fh)
    _run_apply(db_path, {"case_id": "conc", "events": build_race_case()})

    server = BarrierServer(expect=1)
    token = uuid.uuid4().hex
    try:
        env = _worker_env(server, token, db_path,
                          {"MAPPING_GUARD_BARRIER_PHASES": ""})
        winner = _spawn("worker_retry", env, case_path)
        # Kill the winner immediately after the handoff row becomes durable.
        deadline = time.monotonic() + 45
        killed = False
        while time.monotonic() < deadline:
            conn = open_db(db_path)
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM handoffs").fetchone()
            finally:
                conn.close()
            if row["n"] == 1:
                winner.kill()
                winner.wait()
                winner.communicate()  # reap pipes to avoid ResourceWarning
                killed = True
                break
            time.sleep(0.05)
    finally:
        server.stop()

    # Retry from a fresh process with the same request id (response loss).
    server = BarrierServer(expect=1)
    token = uuid.uuid4().hex
    try:
        env_retry = _worker_env(server, token, db_path,
                                {"MAPPING_GUARD_BARRIER_PHASES": ""})
        proc = _spawn("worker_replay_same_request", env_retry, case_path)
        retry, err = _read_json(proc)
    finally:
        server.stop()

    conn = open_db(db_path)
    try:
        rows = conn.execute("SELECT receipt FROM handoffs").fetchall()
        receipt = json.loads(rows[0]["receipt"])
        count = len(rows)
        head = conn.execute(
            "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    finally:
        conn.close()
    return {"killed_winner": killed, "retry": retry, "retry_stderr": err,
            "stored_receipt": receipt, "handoff_rows": count,
            "event_rows": head}


def scenario_historical_view(workdir):
    db_path = os.path.join(workdir, "history.sqlite")
    case_path = os.path.join(workdir, "history-case.json")
    with open(case_path, "w", encoding="utf-8") as fh:
        json.dump({"case_id": "conc", "events": []}, fh)
    # Commit the five-event evidence base so the reader can snapshot commit 5
    # while the writer adds the handoff as commit 6 in a separate process.
    _run_apply(db_path, {"case_id": "conc", "events": build_race_case()})
    server = BarrierServer(expect=2)
    token = uuid.uuid4().hex
    try:
        # Only the explicit reader_checkpoint barrier fires in this scenario;
        # the storage before_verify barrier must be a no-op here.
        env_r = _worker_env(server, token, db_path,
                            {"MAPPING_GUARD_BARRIER_PHASES":
                             "reader_checkpoint"})
        env_w = _worker_env(server, token, db_path,
                            {"MAPPING_GUARD_BARRIER_PHASES":
                             "reader_checkpoint"})
        pr = _spawn("worker_history", env_r, case_path)
        pw = _spawn("worker_writer_history", env_w, case_path)
        reader, err_r = _read_json(pr)
        writer, err_w = _read_json(pw)
    finally:
        server.stop()
    return {"reader": reader, "writer": writer,
            "reader_stderr": err_r, "writer_stderr": err_w}


SCENARIOS = {
    "first_handoff_race": scenario_first_handoff_race,
    "pre_commit_abort": scenario_pre_commit_abort,
    "post_commit_loss": scenario_post_commit_loss,
    "historical_view": scenario_historical_view,
}

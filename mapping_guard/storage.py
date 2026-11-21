"""Durable event log in SQLite and the single-transaction handoff protocol.

Durability model
----------------
Only interval-scale rows are persisted (never per-page expansion):

* meta     -- one-row bookkeeping (case id, schema version)
* events   -- append-only logical events, ordered by ``seq``
* handoffs -- idempotency table keyed by the client's request_id; stores the
              canonical content hash and the receipt returned on first commit

A batch is all-or-nothing: every event is verified against the state rebuilt
inside one ``BEGIN IMMEDIATE`` transaction and the full page-range switch plus
its receipt are written inside that same transaction.  Any rule failure rolls
the whole batch back.  Repeated requests with identical content return the
stored receipt; the same request_id carrying different content rejects the
whole batch.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from .errors import RuleError
from .model import State, apply_event
from .ranges import canonical, intersect

SCHEMA_VERSION = "1"

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    type     TEXT NOT NULL,
    payload  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handoffs (
    request_id   TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    commit_seq   INTEGER NOT NULL,
    receipt      TEXT NOT NULL
);
"""

HANDOFF_CONTENT_FIELDS = ("request_id", "device", "from_owner", "to_owner",
                          "expected_source_version", "new_gen", "range",
                          "perms")


def canonical_json(obj):
    """Deterministic JSON text used for hashing and replay comparison."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def handoff_content_hash(ev):
    content = {k: ev.get(k) for k in HANDOFF_CONTENT_FIELDS}
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def open_db(path):
    # isolation_level=None puts the driver in autocommit mode so *we* own
    # every transaction boundary explicitly (DDL included); otherwise the
    # implicit transaction opened by the DDL script collides with our
    # BEGIN IMMEDIATE.
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # A bounded busy timeout makes a racing writer wait for the lock and then
    # re-verify against the winner's committed state (instead of crashing).
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_DDL)
    _meta_set(conn, "schema_version", SCHEMA_VERSION, insert=True)
    return conn


def _meta_set(conn, key, value, insert=False):
    if insert:
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
                     (key, value))
    else:
        conn.execute("UPDATE meta SET value = ? WHERE key = ?", (value, key))


def _meta_get(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def load_events(conn):
    return [json.loads(r["payload"]) for r in conn.execute(
        "SELECT payload FROM events ORDER BY seq")]


def load_state(conn):
    return rebuild_from_events(load_events(conn))


def rebuild_from_events(events):
    state = State()
    for ev in events:
        apply_event(state, ev)
    return state


def _barrier(phase, request_id, bypass_phases=False):
    """Optional test-only synchronization hook.

    Enabled by MAPPING_GUARD_BARRIER_URL (host:port of the barrier server in
    concurrency.py).  MAPPING_GUARD_BARRIER_PHASES optionally restricts which
    phases block in this process so unrelated storage barriers are no-ops;
    explicit test checkpoints pass bypass_phases=True.  Never active in normal
    runs.  Failures raise so a broken test cannot pass silently.
    """
    url = os.environ.get("MAPPING_GUARD_BARRIER_URL")
    if not url:
        return
    allowed = os.environ.get("MAPPING_GUARD_BARRIER_PHASES")
    if not bypass_phases and allowed is not None and phase not in allowed.split(","):
        return
    import socket
    host, port = url.split(":")
    token = os.environ.get("MAPPING_GUARD_BARRIER_TOKEN", "run")
    msg = "%s|%s|%s" % (token, phase, request_id)
    with socket.create_connection((host, int(port)), timeout=15) as sock:
        sock.sendall(msg.encode("utf-8"))
        answer = sock.recv(1024).decode("utf-8")
    if answer != "ok":
        raise RuleError("$", "barrier_failed",
                        "barrier at phase %s answered %r" % (phase, answer))


def apply_batch(conn, case):
    """Process one validated apply case inside a single SQLite transaction."""
    case_id = case["case_id"]
    events = case["events"]

    # Test-only rendezvous: two racing writers synchronize *before* either
    # takes the write lock, then both open BEGIN IMMEDIATE.  This exercises a
    # genuine OS-level SQLite lock race rather than a serialized queue.
    first_handoff = next((e for e in events
                          if e["type"] == "handoff_request"), None)
    if first_handoff is not None:
        _barrier("before_verify", first_handoff["request_id"])

    conn.execute("BEGIN IMMEDIATE")
    try:
        known_case = _meta_get(conn, "case_id")
        if known_case is None:
            _meta_set(conn, "case_id", case_id, insert=True)
        elif known_case != case_id:
            raise RuleError("$.case_id", "case_mismatch",
                            "database already holds case %r" % known_case)

        state = load_state(conn)
        head_before = state.seq

        stored_ids = {r["event_id"]: r["payload"]
                      for r in conn.execute(
                          "SELECT event_id, payload FROM events")}
        stored_handoffs = {r["request_id"]: r
                           for r in conn.execute(
                               "SELECT * FROM handoffs")}

        results = []
        replayed = []
        new_receipts = []

        for idx, ev in enumerate(events):
            path = "events[%d]" % idx

            # Replayed event id: payload must be byte-identical canonically.
            if ev["id"] in stored_ids:
                if canonical_json(ev) != stored_ids[ev["id"]]:
                    raise RuleError(path, "conflicting_replay",
                                    "event id %r reused with different content"
                                    % ev["id"])
                replayed.append(ev["id"])
                if ev["type"] == "handoff_request":
                    row = stored_handoffs.get(ev["request_id"])
                    if row is not None:
                        results.append({
                            "event_id": ev["id"],
                            "effect": "idempotent_replay",
                            "receipt": json.loads(row["receipt"]),
                        })
                else:
                    results.append({"event_id": ev["id"],
                                    "effect": "replayed"})
                continue

            # Handoff idempotency is keyed by request_id, independent of the
            # event id: identical content returns the original receipt;
            # different content rejects the entire batch.
            if ev["type"] == "handoff_request":
                digest = handoff_content_hash(ev)
                row = stored_handoffs.get(ev["request_id"])
                if row is not None:
                    if row["content_hash"] != digest:
                        raise RuleError(
                            path + ".request_id", "handoff_conflict",
                            "request_id %r previously committed with different "
                            "content; batch rejected wholesale"
                            % ev["request_id"])
                    receipt = json.loads(row["receipt"])
                    results.append({"event_id": ev["id"],
                                    "effect": "idempotent_replay",
                                    "receipt": receipt})
                    replayed.append(ev["id"])
                    continue

            result = apply_event(state, ev)
            conn.execute(
                "INSERT INTO events(event_id, type, payload) VALUES(?, ?, ?)",
                (ev["id"], ev["type"], canonical_json(ev)))

            if ev["type"] == "handoff_request":
                # Test-only abort hook: rollback immediately before commit so
                # the durable log shows nothing (pre-commit abort scenario).
                abort_target = os.environ.get("MAPPING_GUARD_ABORT_REQUEST")
                if abort_target == ev["request_id"]:
                    conn.execute("ROLLBACK")
                    raise RuleError(path, "forced_abort",
                                    "commit aborted by test fault injection "
                                    "for request %r" % ev["request_id"])

                receipt = state.handoffs[ev["request_id"]]
                conn.execute(
                    "INSERT INTO handoffs(request_id, content_hash, "
                    "commit_seq, receipt) VALUES(?, ?, ?, ?)",
                    (ev["request_id"], handoff_content_hash(ev),
                     receipt["commit"], canonical_json(receipt)))
                new_receipts.append(receipt)
                result = dict(result)
                result["receipt"] = receipt
            results.append(result)

        conn.execute("COMMIT")
    except RuleError:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    except sqlite3.IntegrityError as exc:
        # A racing transaction committed the same event/request first.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise RuleError("events", "concurrent_commit_conflict",
                        "lost the write race: %s" % str(exc))
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    all_receipts = [json.loads(r["receipt"])
                    for r in conn.execute(
                        "SELECT receipt FROM handoffs ORDER BY commit_seq")]
    return {
        "case_id": case_id,
        "accepted": True,
        "head_before": head_before,
        "commit_head": state.seq,
        "replayed_event_ids": replayed,
        "event_results": results,
        "handoff_receipts": all_receipts,
        "new_receipts": new_receipts,
    }


def inspect(conn, query):
    """Rebuild the view at a requested commit and list missing evidence."""
    events = load_events(conn)
    head = len(events)
    commit = query.get("commit", head)
    if commit > head:
        raise RuleError("commit", "commit_ahead_of_head",
                        "requested commit %s but head is %s" % (commit, head))
    state = rebuild_from_events(events[:commit])

    window = None
    if "range" in query:
        window = (query["range"]["start"], query["range"]["end"])

    blockers = state.all_blockers(window=window)
    # Minimal blocking range per (device, queue, instance) and the trigger.
    groups = {}
    for b in blockers:
        key = (b["device"], b["queue"]["slot"], b["queue"]["queue_no"],
               b["instance"])
        groups.setdefault(key, []).append(b)
    blocking = []
    for key in sorted(groups):
        items = groups[key]
        pieces = [(b["range"]["start"], b["range"]["end"]) for b in items]
        merged = canonical(pieces)
        triggers = sorted({b["trigger_event"] for b in items})
        blocking.append({
            "device": key[0],
            "queue": {"slot": key[1], "queue_no": key[2]},
            "instance": key[3],
            "minimal_blocking_range": [
                {"start": s, "end": e} for s, e in merged
            ],
            "trigger_events": triggers,
            "missing_evidence": items,
        })

    mapping_view = []
    for device in sorted(state.segments):
        for seg in sorted((s for s in state.segments[device] if s.valid),
                          key=lambda s: (s.start, s.end)):
            mapping_view.append({
                "device": device,
                "range": {"start": seg.start, "end": seg.end},
                "owner": seg.owner,
                "gen": seg.gen,
                "perms": list(seg.perms),
            })

    handoff_view = [
        {
            "request_id": r["request_id"],
            "receipt_id": r["receipt_id"],
            "device": r["device"],
            "range": r["range"],
            "from_owner": r["from_owner"],
            "to_owner": r["to_owner"],
            "new_gen": r["new_gen"],
            "replaced_gens": r["replaced_gens"],
            "source_version": r["source_version"],
            "commit": r["commit"],
        }
        for r in sorted(state.handoffs.values(), key=lambda r: r["commit"])
        if r["commit"] <= commit and (
                window is None or intersect(
                    (r["range"]["start"], r["range"]["end"]), window))
    ]

    return {
        "case_id": _meta_get(conn, "case_id"),
        "commit": commit,
        "commit_head": head,
        "query_range": query.get("range"),
        "legal_ownership_at_commit": mapping_view,
        "handoffs_visible_at_commit": handoff_view,
        "blocking_queues": blocking,
        "fully_drained": not blockers,
    }

"""Command line entry point: python -m mapping_guard <command> CASE.json [--db DB.sqlite]

Output is deterministic UTF-8 JSON on stdout.  Every failure uses the
structured error envelope {"ok": false, "error": {...}} and a documented exit
code; nothing other than JSON is ever written to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .errors import AuditorError, EXIT_USAGE
from .storage import apply_batch, inspect, open_db
from .validation import (validate_apply_case, validate_inspect_query,
                         validate_schedule_case)
from .scheduler import solve_schedule


def _load_case(path):
    if not os.path.isfile(path):
        raise AuditorError("$", "file_not_found",
                           "input file %r does not exist" % path)
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise AuditorError("$", "invalid_json",
                               "cannot parse JSON: %s" % exc)


def _emit(obj, code):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2,
                                sort_keys=False))
    sys.stdout.write("\n")
    return code


def _error_envelope(exc):
    return {"ok": False, "error": exc.to_json()}


def cmd_apply(args):
    raw = _load_case(args.case)
    case = validate_apply_case(raw)
    if not args.db:
        raise AuditorError("--db", "db_required",
                           "apply needs a durable database: pass --db DB.sqlite")
    conn = open_db(args.db)
    try:
        result = apply_batch(conn, case)
    finally:
        conn.close()
    result = dict(result)
    result["ok"] = True
    return _emit(result, 0)


def cmd_inspect(args):
    raw = _load_case(args.case)
    query = validate_inspect_query(raw)
    if not args.db:
        raise AuditorError("--db", "db_required",
                           "inspect needs the durable database: pass --db "
                           "DB.sqlite")
    conn = open_db(args.db)
    try:
        result = inspect(conn, query)
    finally:
        conn.close()
    result = dict(result)
    result["ok"] = True
    return _emit(result, 0)


def cmd_schedule(args):
    raw = _load_case(args.case)
    case = validate_schedule_case(raw)
    result = solve_schedule(case)
    result["ok"] = True
    return _emit(result, 0)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mapping_guard",
        description="Virtual device remapping safety auditor (pure logic).")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("apply", "inspect"):
        p = sub.add_parser(name)
        p.add_argument("case")
        p.add_argument("--db", required=False)
        p.set_defaults(func=globals()["cmd_" + name])

    p = sub.add_parser("schedule")
    p.add_argument("case")
    p.set_defaults(func=cmd_schedule)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AuditorError as exc:
        return _emit(_error_envelope(exc), exc.exit_code)
    except argparse.ArgumentError as exc:
        err = {"field": "argv", "code": "usage", "message": str(exc)}
        return _emit({"ok": False, "error": err}, EXIT_USAGE)


if __name__ == "__main__":
    sys.exit(main())

"""Structured, field-level error types shared by every subcommand.

Two failure classes are kept distinct on purpose:

* StructureError -- the JSON envelope or a field has the wrong type/shape.
  Exit code 2.
* RuleError      -- well-formed input that violates an auditor safety rule
  (unknown generation, post-revoke registration, conflicting handoff ...).
  Exit code 3.

Every error carries a dotted field path so callers can pinpoint the exact
offending member of a batch.
"""

from __future__ import annotations

# Exit codes are part of the documented CLI contract.
EXIT_OK = 0
EXIT_STRUCTURE = 2
EXIT_RULE = 3
EXIT_USAGE = 4


class AuditorError(Exception):
    exit_code = EXIT_RULE

    def __init__(self, field, code, message):
        super().__init__(message)
        self.field = field
        self.code = code
        self.message = message

    def to_json(self):
        return {"field": self.field, "code": self.code, "message": self.message}


class StructureError(AuditorError):
    exit_code = EXIT_STRUCTURE

    def __init__(self, field, expected, actual):
        super().__init__(
            field,
            "structure",
            "expected %s at %s, got %s" % (expected, field, actual),
        )
        self.expected = expected
        self.actual = actual


class RuleError(AuditorError):
    exit_code = EXIT_RULE

    def __init__(self, field, code, message):
        super().__init__(field, code, message)


# -- small validation helpers -------------------------------------------------

def require(obj, key, typ, path, *, enum=None):
    """Fetch obj[key] with type/enum checks; raise StructureError/RuleError."""
    if not isinstance(obj, dict):
        raise StructureError(path, "object", type(obj).__name__)
    if key not in obj:
        raise StructureError("%s.%s" % (path, key), "present field", "missing")
    value = obj[key]
    if typ is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise StructureError("%s.%s" % (path, key), "integer", _tn(value))
    elif typ is str:
        if not isinstance(value, str):
            raise StructureError("%s.%s" % (path, key), "string", _tn(value))
    elif typ is bool:
        if not isinstance(value, bool):
            raise StructureError("%s.%s" % (path, key), "boolean", _tn(value))
    elif typ is list:
        if not isinstance(value, list):
            raise StructureError("%s.%s" % (path, key), "array", _tn(value))
    elif typ is dict:
        if not isinstance(value, dict):
            raise StructureError("%s.%s" % (path, key), "object", _tn(value))
    if enum is not None and value not in enum:
        raise RuleError("%s.%s" % (path, key), "enum",
                        "value %r not one of %s" % (value, sorted(enum)))
    return value


def reject_unknown(obj, allowed, path):
    extra = sorted(set(obj) - set(allowed))
    if extra:
        raise StructureError(
            "%s.%s" % (path, extra[0]), "known field", "unexpected field"
        )


def _tn(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__

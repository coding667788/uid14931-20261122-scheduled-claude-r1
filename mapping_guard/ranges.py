"""Half-open interval algebra over [start, end) ranges.

The address space is capped at 2**52 and every representation stays at
segment granularity: nothing in this module (or the package) expands a range
into individual pages.
"""

from __future__ import annotations

from . import ADDRESS_MAX


def validate_range(rng, path):
    """Validate one {"start": int, "end": int} object; raise RuleError on bad data."""
    from .errors import RuleError, StructureError

    if not isinstance(rng, dict):
        raise StructureError(path, "object", type(rng).__name__)
    start = rng.get("start")
    end = rng.get("end")
    if not isinstance(start, int) or isinstance(start, bool):
        raise StructureError(path + ".start", "integer", _type_name(start))
    if not isinstance(end, int) or isinstance(end, bool):
        raise StructureError(path + ".end", "integer", _type_name(end))
    if not (0 <= start < ADDRESS_MAX):
        raise RuleError(path + ".start", "range", "must satisfy 0 <= start < 2^52")
    if not (start < end <= ADDRESS_MAX):
        raise RuleError(path + ".end", "range", "must satisfy start < end <= 2^52")
    return start, end


def _type_name(value):
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


def intersect(a, b):
    """Return overlap of (a_start, a_end) and (b_start, b_end) or None."""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    return (lo, hi) if lo < hi else None


def subtract(whole, hole):
    """Return the parts of `whole` not covered by `hole` (zero to two pieces)."""
    overlap = intersect(whole, hole)
    if overlap is None:
        return [whole]
    lo, hi = overlap
    out = []
    if whole[0] < lo:
        out.append((whole[0], lo))
    if hi < whole[1]:
        out.append((hi, whole[1]))
    return out


def merge(segments):
    """Merge overlapping or adjacent segments; input/output lists of (start, end)."""
    if not segments:
        return []
    ordered = sorted(segments)
    out = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = out[-1]
        if start <= last_end:
            if end > last_end:
                out[-1] = (last_start, end)
        else:
            out.append((start, end))
    return out


def subtract_many(whole, holes):
    """Subtract all holes from whole, returning canonical disjoint segments."""
    pieces = [whole]
    for hole in holes:
        nxt = []
        for piece in pieces:
            nxt.extend(subtract(piece, hole))
        pieces = nxt
    return merge(pieces)


def covered_by(segments, window):
    """True iff every point of window is covered by the union of segments."""
    remaining = [window]
    for seg in merge(segments):
        nxt = []
        for piece in remaining:
            nxt.extend(subtract(piece, seg))
        remaining = nxt
        if not remaining:
            return True
    return not remaining


def canonical(segments):
    """Merge and sort, dropping empty pieces."""
    return merge([(s, e) for s, e in segments if s < e])


def to_json(segments):
    return [{"start": s, "end": e} for s, e in canonical(segments)]

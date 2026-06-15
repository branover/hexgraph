"""JSON column types that stay robust against legacy/malformed stored values.

A `JSON` column round-trips through `json.dumps`/`json.loads`, so a well-formed row
deserializes to the expected container. But a legacy / hand-edited / double-encoded row
can come back as a JSON *string* (or some other scalar): the column was once handed a
Python `str`, which the JSON impl stored double-encoded (`'"..."'`), so it reads back as
that inner string. Every `(value or {}).get(...)` read site then raises
`AttributeError: 'str' object has no attribute 'get'`, and every `dict(value or {})`
raises `ValueError` — a single bad row 500s an entire listing.

`JSONDict` coerces ONCE at the column-read boundary so no caller can ever observe a
non-dict for a dict-typed column. Writes are untouched (upstream Pydantic validation is
the write guard); only reads are normalized, and only for the malformed values that would
otherwise crash — `None` and well-formed dicts pass through byte-for-byte.
"""

from __future__ import annotations

import json

from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator


def coerce_evidence(evidence: object) -> dict:
    """Normalize a stored JSON value to a dict for reading.

    Pass dicts through unchanged, best-effort parse a JSON string when it decodes to an
    object (recovering a double-encoded dict, including its data), and treat anything else
    (a non-object JSON value, a non-JSON string, a scalar, `None`) as empty. This is the
    single coercion used both by `JSONDict` and by the pure read helpers (e.g. is_verified)
    that may receive evidence NOT sourced from the column (tests, in-memory, imports)."""
    if isinstance(evidence, dict):
        return evidence
    if isinstance(evidence, str):
        try:
            parsed = json.loads(evidence)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def dig_dict(obj: object, *keys: str):
    """Safely walk nested dicts: return ``obj[k0][k1]…`` but yield ``None`` the moment any
    level isn't a dict.

    The pervasive ``(d.get(k) or {}).get(k2)`` idiom only guards a *falsy* intermediate — it
    still crashes when a level is a *truthy non-dict*, e.g. an agent that wrote
    ``evidence.extra.verification`` as free-text prose instead of the expected object
    (``'str' object has no attribute 'get'``). The frozen Finding schema's ``extra`` is
    intentionally free-form, so its children can be any JSON type; read sites must navigate
    defensively. Use this for any nested read into agent-authored evidence."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


class JSONDict(TypeDecorator):
    """A `JSON` column whose Python value is ALWAYS a dict (or `None`) on read.

    The DDL is plain `JSON` (impl), so this is a transparent, migration-free swap. A SQL
    NULL is preserved as `None` (every read site already guards `value or {}`); any other
    non-dict value is coerced via `coerce_evidence`, so a single malformed row can never
    crash a read regardless of which of the many read sites touches it."""

    impl = JSON
    cache_ok = True

    def process_result_value(self, value, dialect):  # noqa: D102 (impl detail)
        if value is None:
            return None
        return coerce_evidence(value)

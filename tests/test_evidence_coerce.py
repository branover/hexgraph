"""`coerce_evidence` / `is_verified` must tolerate a non-dict `evidence_json`.

`Finding.evidence_json` is a JSON column, so a healthy row reads back as a dict. But a
legacy/hand-edited/double-encoded row can deserialize to a *string* (or other scalar), and
the many `(evidence or {}).get(...)` read sites would then raise `AttributeError: 'str'
object has no attribute 'get'` — one bad row 500ing a whole findings listing. These guard
that the read path coerces defensively (and recovers a double-encoded dict where it can).
"""

import json

from hexgraph.engine.findings.findings import coerce_evidence, is_verified

_VERIFIED = {"extra": {"verification": {"verified": True}}}


def test_coerce_passes_dicts_through_unchanged():
    ev = {"extra": {"assurance": {"standard": "static"}}}
    assert coerce_evidence(ev) is ev


def test_coerce_recovers_double_encoded_dict():
    # A JSON column handed a string stores it double-encoded; it reads back as that string.
    assert coerce_evidence(json.dumps(_VERIFIED)) == _VERIFIED


def test_coerce_degrades_non_object_to_empty_dict():
    assert coerce_evidence("not json at all") == {}   # unparseable string
    assert coerce_evidence("[1, 2, 3]") == {}         # valid JSON but not an object
    assert coerce_evidence(None) == {}
    assert coerce_evidence(42) == {}


def test_is_verified_handles_string_evidence_without_raising():
    # The exact crash: a string evidence used to blow up the project endpoint.
    assert is_verified("not json at all") is False
    assert is_verified(json.dumps(_VERIFIED)) is True
    assert is_verified(json.dumps({"extra": {"verification": {"verified": False}}})) is False
    assert is_verified(None) is False
    assert is_verified(_VERIFIED) is True

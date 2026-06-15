"""`coerce_evidence` / `is_verified` must tolerate a non-dict `evidence_json`.

`Finding.evidence_json` is a JSON column, so a healthy row reads back as a dict. But a
legacy/hand-edited/double-encoded row can deserialize to a *string* (or other scalar), and
the many `(evidence or {}).get(...)` read sites would then raise `AttributeError: 'str'
object has no attribute 'get'` — one bad row 500ing a whole findings listing. These guard
that the read path coerces defensively (and recovers a double-encoded dict where it can).
"""

import json

from hexgraph.db.jsontypes import dig_dict
from hexgraph.engine.findings.assurance import assurance_of
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


# --- nested non-dict: extra / verification / assurance can themselves be the wrong type ---
# (e.g. an agent wrote evidence.extra.verification as free-text prose). The `(x or {}).get`
# idiom only guards a falsy intermediate; a truthy non-dict still crashed. dig_dict guards it.

def test_dig_dict_walks_nested_dicts():
    assert dig_dict({"a": {"b": {"c": 1}}}, "a", "b", "c") == 1
    assert dig_dict({"a": {"b": {}}}, "a", "b", "c") is None  # missing leaf
    assert dig_dict({}, "a") is None


def test_dig_dict_yields_none_on_a_truthy_non_dict_level():
    # the real shape that crashed: extra.verification is a string, not a {verified:…} object
    assert dig_dict({"extra": {"verification": "prose"}}, "extra", "verification", "verified") is None
    assert dig_dict({"extra": "a string"}, "extra", "verification") is None  # extra itself non-dict
    assert dig_dict("not even a dict", "extra") is None
    assert dig_dict(None, "extra") is None


def test_is_verified_handles_nondict_extra_and_verification():
    assert is_verified({"extra": {"verification": "PowerPC disasm prose…"}}) is False  # the field report
    assert is_verified({"extra": "a string instead of a dict"}) is False
    assert is_verified({"extra": {"verification": {"verified": True}}}) is True  # still works


def test_assurance_of_handles_nondict_nesting():
    # verification is a string but a valid extra.assurance is still recovered (not crashed/lost)
    ev = {"extra": {"verification": "prose", "assurance": {"standard": "input_reachable"}}}
    assert assurance_of(ev) == {"standard": "input_reachable"}
    # fully malformed nesting → None, no raise
    assert assurance_of({"extra": "a string"}) is None
    assert assurance_of({"extra": {"assurance": "not a dict"}}) is None
    assert assurance_of(None) is None
    # falls back to verification.assurance when extra.assurance is absent
    assert assurance_of({"extra": {"verification": {"assurance": {"standard": "code_present"}}}}) \
        == {"standard": "code_present"}

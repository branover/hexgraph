"""The `evidence_json` column guarantees a dict on read (JSONDict TypeDecorator).

PR #250 routed the highest-exposure read sites through `coerce_evidence`, but ~15 other
sites read `f.evidence_json` directly (`(f.evidence_json or {}).get(...)` →
`AttributeError`, `dict(f.evidence_json or {})` → `ValueError`) and would still crash on a
legacy/double-encoded row whose evidence deserializes to a *string*. Coercing once at the
column-read boundary makes every reader safe by construction. These tests pin that: the
column itself, plus a few representative sites that were previously unguarded.
"""

import json

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.dedup import dedupe_findings
from hexgraph.engine.findings.report import build_report_md
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _add_finding(s, *, project_id, target_id, title, evidence_json, status="new",
                 finding_type="vulnerability"):
    """Insert a finding with an arbitrary `evidence_json`. Assigning a Python str to the
    JSON column double-encodes it, so on a fresh read it comes back as a *string* — exactly
    the legacy shape this fix has to tolerate."""
    s.add(Finding(project_id=project_id, target_id=target_id, task_id="t", title=title,
                  severity="high", confidence="high", category="auth", summary="s",
                  reasoning="r", evidence_json=evidence_json, finding_type=finding_type,
                  status=status))


def test_column_coerces_non_dict_evidence_to_dict_on_read(hg_home):
    """Round-trip through the DB: a double-encoded dict is recovered, a garbage string and a
    non-object JSON value degrade to {}, and a well-formed dict passes through unchanged."""
    with session_scope() as s:
        p = create_project(s, name="col")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id
        _add_finding(s, project_id=pid, target_id=tid, title="dbl",
                     evidence_json=json.dumps({"extra": {"verification": {"verified": True}}}))
        _add_finding(s, project_id=pid, target_id=tid, title="garbage", evidence_json="not json")
        _add_finding(s, project_id=pid, target_id=tid, title="listish", evidence_json="[1, 2, 3]")
        _add_finding(s, project_id=pid, target_id=tid, title="normal", evidence_json={"a": 1})

    with session_scope() as s:  # fresh session → values come back through the column processor
        rows = {f.title: f.evidence_json for f in s.query(Finding).filter_by(project_id=pid).all()}
    assert all(isinstance(v, dict) for v in rows.values())          # nothing is a str anymore
    assert rows["dbl"] == {"extra": {"verification": {"verified": True}}}  # recovered, data intact
    assert rows["garbage"] == {}                                    # unparseable → empty
    assert rows["listish"] == {}                                    # valid JSON but not an object
    assert rows["normal"] == {"a": 1}                               # untouched


def test_report_build_tolerates_string_evidence(hg_home):
    """build_report_md reads `f.evidence_json or {}` then `.get(...)` — would crash on a
    string before; the finding's section renders now."""
    with session_scope() as s:
        p = create_project(s, name="rep")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid = p.id
        _add_finding(s, project_id=pid, target_id=t.id, title="str-ev-finding",
                     evidence_json="legacy string evidence", status="confirmed")

    with session_scope() as s:
        md = build_report_md(s, pid)  # was: AttributeError 500
    assert "str-ev-finding" in md


def test_dedupe_tolerates_string_evidence(hg_home):
    """dedupe_findings builds a signature from `ev.get("function"/"sink")` — would crash on
    a string before. Two identical string-evidence findings now dedupe to one."""
    with session_scope() as s:
        p = create_project(s, name="ded")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid = p.id
        _add_finding(s, project_id=pid, target_id=t.id, title="dupe", evidence_json="legacy")
        _add_finding(s, project_id=pid, target_id=t.id, title="dupe", evidence_json="legacy")

    with session_scope() as s:
        removed = dedupe_findings(s, pid)  # was: AttributeError
    assert removed == 1


def test_verify_endpoint_tolerates_string_evidence(hg_home):
    """POST /api/findings/{id}/verify reads `(f.evidence_json or {}).get("extra")` first —
    a string used to 500 there; now it reaches the normal 'no PoC spec' 400."""
    with session_scope() as s:
        p = create_project(s, name="vfy")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid = p.id
        _add_finding(s, project_id=pid, target_id=t.id, title="str-ev", evidence_json="legacy", finding_type="poc")
        fid = s.query(Finding).filter_by(project_id=pid).one().id

    resp = TestClient(create_app()).post(f"/api/findings/{fid}/verify")
    assert resp.status_code == 400  # "no stored PoC spec", NOT 500
    assert "PoC spec" in resp.json()["detail"]

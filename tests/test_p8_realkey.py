"""P8: cheap real-key validation harness.

- No-key checks (CI, $0): the planted bugs are statically present; scoring logic works.
- Live check: skipped unless ANTHROPIC_API_KEY is set; runs the real backend against the
  tiny multi-vuln set with a cassette (so reruns are $0) and asserts a detection rate.
"""

import os

import pytest

from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync
from hexgraph.eval import load_expectations, run_scored_eval, score_detection

from conftest import fixture_path

VULN_FW = os.path.join(os.path.dirname(__file__), "fixtures", "vuln_fw")


def test_scoring_logic():
    exp = [{"binary": "cgi", "categories": ["memory-safety"]},
           {"binary": "cmd", "categories": ["command-injection"]},
           {"binary": "creds", "categories": ["hardcoded-secret", "auth"]}]
    detected = {"cgi": ["memory-safety"], "cmd": ["other"], "creds": ["auth"]}
    score = score_detection(exp, detected)
    assert score["total"] == 3 and score["hits"] == 2
    assert abs(score["rate"] - 2 / 3) < 1e-6
    assert score["per_binary"]["cmd"]["detected"] is False


def test_planted_bugs_are_statically_present(hg_home, sandbox):
    """Recon (no LLM) confirms each binary's characteristic sink — the bugs are real."""
    spec = load_expectations(os.path.join(VULN_FW, "expectations.json"))
    want = {"cgi": "strcpy", "cmd": "system", "creds": "S3cr3t-Backdoor-2024"}
    with session_scope() as s:
        p = create_project(s, name="present")
        pid = p.id
        ids = {}
        for exp in spec["targets"]:
            t = ingest_file(s, p, os.path.join(VULN_FW, exp["binary"]), name=exp["binary"])
            ids[exp["binary"]] = (t.id, create_task(s, project=p, target_id=t.id, type="recon", backend="none").id)
    for binary, (tid, recon_id) in ids.items():
        run_task_sync(recon_id)
    with session_scope() as s:
        from hexgraph.db.models import Target
        for binary, (tid, _r) in ids.items():
            meta = s.get(Target, tid).metadata_json
            blob = " ".join(meta.get("imports", []) + meta.get("strings", []))
            assert want[binary] in blob, f"{binary} missing its planted sink"


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="real-key live test; set ANTHROPIC_API_KEY")
def test_real_key_detection_rate(hg_home, sandbox, monkeypatch):
    # Cassette-backed: record on first run, replay ($0) thereafter.
    monkeypatch.setenv("HEXGRAPH_CASSETTE", "auto")
    score = run_scored_eval(fixtures_dir=VULN_FW, backend="anthropic")
    assert score["rate"] >= score["min_detection_rate"], score["per_binary"]

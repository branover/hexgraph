"""Scored detection harness (P8).

Runs the analysis tasks over a target set with known planted bugs and scores how
many the agent detected. Used by `make test-live` (real backend, cassette-backed
so reruns are $0) and the no-key fixture checks. Detection = a static_analysis
finding whose category matches the binary's expected category set.
"""

from __future__ import annotations

import json
from pathlib import Path

from hexgraph.db.models import Finding, Project
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync


def load_expectations(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def score_detection(expectations: list[dict], detected: dict[str, list[str]]) -> dict:
    """expectations: [{binary, categories}]; detected: {binary: [categories]}.
    Returns {total, hits, rate, per_binary}."""
    per = {}
    hits = 0
    for exp in expectations:
        b = exp["binary"]
        want = set(exp["categories"])
        got = set(detected.get(b, []))
        ok = bool(want & got)
        per[b] = {"expected": sorted(want), "got": sorted(got), "detected": ok}
        hits += int(ok)
    total = len(expectations)
    return {"total": total, "hits": hits, "rate": (hits / total if total else 0.0), "per_binary": per}


def run_scored_eval(*, fixtures_dir: str | Path, backend: str, project_name: str = "vuln-eval") -> dict:
    """Ingest each expected binary, run recon then static_analysis (focused), and
    score. Manages its own DB sessions (each task is committed before
    `run_task_sync`, which opens its own session)."""
    fixtures_dir = Path(fixtures_dir)
    spec = load_expectations(fixtures_dir / "expectations.json")

    with session_scope() as s:
        project = create_project(s, name=project_name, llm_backend=backend)
        pid = project.id

    detected: dict[str, list[str]] = {}
    for exp in spec["targets"]:
        with session_scope() as s:
            project = s.get(Project, pid)
            target = ingest_file(s, project, fixtures_dir / exp["binary"], name=exp["binary"])
            tid = target.id
            recon_id = create_task(s, project=project, target_id=tid, type="recon", backend="none").id
        run_task_sync(recon_id)  # fills imports/metadata the context builder uses
        with session_scope() as s:
            project = s.get(Project, pid)
            sa_id = create_task(
                s, project=project, target_id=tid, type="static_analysis",
                backend=backend, params={"function": exp.get("function")},
            ).id
        run_task_sync(sa_id)
        with session_scope() as s:
            detected[exp["binary"]] = [f.category for f in s.query(Finding).filter(Finding.task_id == sa_id).all()]

    score = score_detection(spec["targets"], detected)
    score["project_id"] = pid
    score["min_detection_rate"] = spec.get("min_detection_rate", 0.5)
    return score

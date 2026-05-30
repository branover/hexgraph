"""Ingest-and-analyze orchestration (the M2 core loop, zero model calls).

  ingest file → recon → (if firmware) unpack into children → recon each child
              → links_against edges

Used by the CLI `ingest` command and by the demo. Recon auto-runs on ingest for
every target (SPEC §5).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.engine.ingest import ingest_file
from hexgraph.engine.recon import run_recon
from hexgraph.engine.unpack import build_links_against, unpack_firmware
from hexgraph.sandbox.runner import SandboxRunner

_FIRMWARE_FORMATS = {"squashfs", "cpio"}


def analyze_target(
    session: Session,
    project: Project,
    target: Target,
    runner: SandboxRunner,
) -> dict:
    """Recon a target; if it's firmware, unpack and recon each child."""
    _finding, facts = run_recon(session, project, target, runner)
    summary = {"target_id": target.id, "name": target.name, "children": []}

    is_firmware = facts.get("kind") == "firmware_image" or facts.get("format") in _FIRMWARE_FORMATS
    if is_firmware:
        for child in unpack_firmware(session, project, target, runner):
            run_recon(session, project, child, runner)
            summary["children"].append({"target_id": child.id, "name": child.name})
    return summary


def ingest_and_analyze(
    session: Session,
    project: Project,
    src_path: str | Path,
    *,
    name: str | None = None,
    runner: SandboxRunner | None = None,
) -> dict:
    runner = runner or SandboxRunner()
    root = ingest_file(session, project, src_path, name=name)
    summary = analyze_target(session, project, root, runner)
    links = build_links_against(session, project)
    summary["links_against_edges"] = links
    summary["root_target_id"] = root.id
    return summary

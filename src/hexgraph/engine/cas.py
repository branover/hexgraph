"""Content-addressed store (P2 ruling #5).

One store per project at `<data_dir>/cas/<sha256>`. Holds tool outputs, serialized
context bundles, and LLM response traces. Content-addressing gives free dedup and
a stable provenance anchor (identical decompilation across functions → one blob).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hexgraph.db.models import Project


def cas_dir(project: Project) -> Path:
    d = Path(project.data_dir) / "cas"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put(project: Project, data: str | bytes) -> str:
    """Store bytes/text; return the sha256. Idempotent."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    sha = _sha(raw)
    path = cas_dir(project) / sha
    if not path.exists():
        path.write_bytes(raw)
    return sha


def put_json(project: Project, obj: Any) -> str:
    return put(project, json.dumps(obj, sort_keys=True, default=str))


def get(project: Project, sha: str) -> bytes | None:
    path = cas_dir(project) / sha
    return path.read_bytes() if path.exists() else None


def get_text(project: Project, sha: str) -> str | None:
    raw = get(project, sha)
    return raw.decode("utf-8") if raw is not None else None


def size_report(project: Project) -> dict:
    d = cas_dir(project)
    files = list(d.glob("*"))
    return {"objects": len(files), "bytes": sum(f.stat().st_size for f in files), "dir": str(d)}

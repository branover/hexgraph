"""Layer 3 — record/replay cassettes (P2; the real implementation of the M0 hook).

A `CassetteBackend` wraps any backend and caches its response keyed by the
request's `cache_key` (the context `bundle_sha`). Recorded once with a real key,
a run replays offline at $0 — this is what makes the P8 real-key validation cheap
and CI-safe. Selected by `HEXGRAPH_CASSETTE`: off (default) | record | replay | auto.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from hexgraph.db.models import Project
from hexgraph.llm.base import LLMBackend, LLMError, LLMRequest, LLMResponse, Usage


def _dir(project: Project) -> Path:
    d = Path(project.data_dir) / "cassettes"
    d.mkdir(parents=True, exist_ok=True)
    return d


class CassetteBackend:
    def __init__(self, inner: LLMBackend, project: Project, mode: str) -> None:
        self.inner = inner
        self.project = project
        self.mode = mode
        self.name = inner.name

    def _path(self, key: str) -> Path:
        return _dir(self.project) / f"{key}.json"

    def complete(self, req: LLMRequest) -> LLMResponse:
        key = req.cache_key
        path = self._path(key) if key else None

        if path and self.mode in ("replay", "auto") and path.exists():
            data = json.loads(path.read_text())
            u = data.get("usage", {})
            return LLMResponse(text=data["text"], usage=Usage(**u) if u else Usage())

        if path and self.mode == "replay":
            raise LLMError(f"cassette miss for {key} in replay mode (record it first)")

        resp = self.inner.complete(req)
        if path and self.mode in ("record", "auto"):
            path.write_text(json.dumps({
                "text": resp.text,
                "usage": {
                    "input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens,
                    "cost_source": resp.usage.cost_source, "cost_usd": resp.usage.cost_usd,
                },
            }, indent=2))
        return resp

    def stream(self, req: LLMRequest):
        yield self.complete(req).text


def maybe_wrap_cassette(backend: LLMBackend, project: Project) -> LLMBackend:
    """Wrap `backend` with cassette record/replay if HEXGRAPH_CASSETTE is set."""
    mode = (os.environ.get("HEXGRAPH_CASSETTE") or "off").lower()
    if mode in ("record", "replay", "auto"):
        return CassetteBackend(backend, project, mode)
    return backend

"""Layer 3 — record/replay cassettes (seam only; M0-T9).

The hook exists so a future milestone can: when a real key is available, run in
`record` mode (wrap a real backend, capture request/response keyed by a hash of
`(task_type, model, normalized_prompt)`); on later runs in `replay` mode, serve
from the cassette with no network. Recorded cassettes are validated by the same
contract test as the fixtures.

Not implemented yet — intentionally a thin placeholder so the boundary is clear.
"""

from __future__ import annotations

import hashlib

from hexgraph.llm.base import LLMRequest


def cassette_key(req: LLMRequest) -> str:
    """Stable key for a request, used as the cassette filename stem."""
    basis = f"{req.task_type}\x00{req.model or ''}\x00{req.prompt.strip()}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


# TODO(M-later): RecordingBackend(wraps=real_backend, dir=...) and
# ReplayBackend(dir=...) implementing the LLMBackend protocol.

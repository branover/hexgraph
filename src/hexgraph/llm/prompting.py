"""System prompt for real backends.

The mock ignores prompts (it replays fixtures), but real backends need to be told
to emit the exact Finding schema. We embed the canonical JSON Schema so the
instruction can never drift from `finding.schema.json`.
"""

from __future__ import annotations

from functools import lru_cache

from hexgraph.paths import finding_schema_path


@lru_cache(maxsize=1)
def _schema_text() -> str:
    return finding_schema_path().read_text()


def system_prompt(task_type: str) -> str:
    return (
        "You are HexGraph, an expert vulnerability-research agent performing a "
        f"'{task_type}' task. You are given STATIC analysis tool output only "
        "(decompilation, strings, imports, recon facts) — you cannot and must not "
        "assume the target can be executed. Reason carefully and report only "
        "credible findings.\n\n"
        "Respond with ONLY a JSON object of the form {\"findings\": [ ... ]} — no "
        "prose, no markdown fences. Each element MUST validate against this JSON "
        "Schema:\n"
        f"{_schema_text()}\n"
        "If you find no issues, return {\"findings\": []}."
    )

"""The record-keeping guidance scaffolding — Phase 0 of the working-memory layer.

These pin the single-source-of-truth constants and the two delivery paths that render
them: the generated VR skill (via `write_skill`) and the in-process system prompt (via
`prompting.system_prompt`). Offline/mock; no backend, no network.
"""

from __future__ import annotations

import os
import tempfile

from hexgraph.record_keeping import RECORD_KEEPING, RECORD_KEEPING_COMPACT


def test_constants_import_and_are_nonempty():
    assert isinstance(RECORD_KEEPING, str) and RECORD_KEEPING.strip()
    assert isinstance(RECORD_KEEPING_COMPACT, str) and RECORD_KEEPING_COMPACT.strip()
    # The compact form is a distillation, not the whole rubric.
    assert len(RECORD_KEEPING_COMPACT) < len(RECORD_KEEPING)


def test_full_rubric_covers_the_taxonomy_hypotheses_and_journal():
    """RECORD_KEEPING must carry the §3 taxonomy, the two overlaps, both rubrics, and
    worked examples — it is the only place hypotheses/journal recording is taught."""
    text = RECORD_KEEPING
    # five-store taxonomy + the two dangerous overlaps
    for token in ("Findings", "Observation store", "Hypotheses", "Journal",
                  "Journal vs. Observations", "Hypotheses vs. Findings"):
        assert token in text, token
    # hypothesis rubric: falsifiable question, lifecycle, close-with-verdict, pinning
    for token in ("falsifiable", "investigating", "parked", "done", "evidence",
                  "verdict", "pin"):
        assert token.lower() in text.lower(), token
    # journal rubric: the four prompts, the authorship rule, skimmable
    for token in ("Idea", "Tried", "Learned", "authorship", "skimmable"):
        assert token.lower() in text.lower(), token
    # the anti-example: raw tool output belongs in the Observation store, not the journal
    assert "anti-example" in text.lower()
    assert "Observation" in text


def test_compact_states_the_core_rule_and_authorship():
    c = RECORD_KEEPING_COMPACT.lower()
    assert "hypotheses" in c and "journal" in c
    assert "worklist" in c
    # the authorship invariant must survive into the compact form
    assert "own" in c
    # the journal-vs-observation line: narrative, not raw tool output
    assert "observation" in c


def test_write_skill_emits_both_files_and_subfile_is_the_rubric():
    from hexgraph.agent_setup import write_skill

    with tempfile.TemporaryDirectory() as d:
        skill_path = write_skill(d)
        skill_dir = os.path.dirname(skill_path)
        sub = os.path.join(skill_dir, "record-keeping.md")
        assert os.path.isfile(skill_path) and skill_path.endswith("hexgraph-vr/SKILL.md")
        assert os.path.isfile(sub)
        # the sub-file IS the rubric — no drift, no second copy
        assert open(sub).read() == RECORD_KEEPING


def test_skill_body_points_to_the_subfile():
    """No duplication: the SKILL body references record-keeping.md instead of restating
    the hypothesis/journal rubric inline."""
    from hexgraph.agent_setup import SKILL

    assert "record-keeping.md" in SKILL


def test_system_prompt_carries_the_compact_guidance():
    from hexgraph.llm.prompting import system_prompt

    out = system_prompt("static_analysis")
    assert RECORD_KEEPING_COMPACT in out

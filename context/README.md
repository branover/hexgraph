# HexGraph MVP — Claude Code context bundle

This directory is the **starting context** for building the HexGraph MVP. Read it top to bottom before writing code.

## What HexGraph is
A self-hosted, agentic vulnerability-research workbench. You point it at a binary or firmware image; it ingests the target, breaks it into sub-targets, runs AI-driven analysis tasks using the **user's own model access** (Anthropic API key *or* local Claude Code connection), and records every result as a structured **finding** in a local **graph** linking targets and findings. A local (loopback-only) web UI lets the user browse the graph, launch tasks, and triage findings. No cloud, no accounts, no paid features, no internet-facing service.

## Read these in order
1. **`SPEC.md`** — the complete build specification (constraints, data model, task types, interfaces, milestones, acceptance criteria). This is the source of truth.
2. **`docs/mock-llm-provider.md`** — how to build the **mock LLM backend** so the whole system can be developed, tested, and demoed **with no real API key and zero token spend**. Build this *first* (milestone M0) — everything else is developed against it.
3. **`schemas/finding.schema.json`** — the canonical Finding JSON schema every task must emit. The mock and the real backends both conform to it.
4. **`fixtures/`** — ready-made mock responses and a description of the test targets. These let the loop run end-to-end offline on day one.

## The golden rule for this MVP
**Build mock-first.** The default model backend in development and CI is the mock (`HEXGRAPH_LLM_BACKEND=mock`). A new developer — or you, Claude Code — must be able to clone, run `make demo`, and watch the full *ingest → task → finding → graph → spawn* loop execute against the bundled fixtures **without any credentials**. Real backends (Anthropic API, Claude Code) are wired in behind the same interface but are never required to develop or test.

## Directory map
```
hexgraph-mvp-context/
├── README.md                     # you are here
├── SPEC.md                       # full build spec (source of truth)
├── docs/
│   └── mock-llm-provider.md      # mock/sandbox LLM design (build this first)
├── schemas/
│   └── finding.schema.json       # canonical structured-finding schema
└── fixtures/
    ├── mock_llm/
    │   ├── _manifest.yaml         # task_type -> default scenario + scenario list
    │   ├── recon/happy_path.json
    │   ├── static_analysis/critical_overflow.json
    │   ├── static_analysis/no_findings.json
    │   ├── static_analysis/malformed_then_valid.json
    │   ├── reverse_engineering/annotate.json
    │   ├── harness_generation/compiles.json
    │   └── pattern_sweep/match_found.json
    └── targets/
        └── README.md             # the test binary + synthetic firmware to commit under tests/fixtures/
```

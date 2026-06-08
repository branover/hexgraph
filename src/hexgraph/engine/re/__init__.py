"""Static reverse engineering — read a target without touching its bytes.

Everything here is the always-on static tier (no execution). Modules:
- **binutils** — authoritative low-level ELF facts (nm/objdump/readelf) + mitigations.
- **recon** — ingest-time recon that computes a target's cached facts.
- **floss** — recover obfuscated/stack/decoded strings a plain strings pass misses.
- **yara** — pattern / n-day scan against the bundled + user rules.
- **taint** + **static_core** — the grounded P-Code source→sink taint pass.
- **enrichment** — materialize functions / call-graph / structs (Ghidra enrich-recon).
- **solver** + **solving** — angr symbolic execution (reaching-input / constraint solving).
- **emulation** — P-Code emulation for runtime constant/key recovery.
- **ghidra** + **ghidra_project** + **ghidra_bridge** — the Ghidra decompiler backends.

NB: the package is `hexgraph.engine.re`; a bare `import re` inside these modules still
resolves to Python's stdlib `re` (absolute imports), not this package.
"""

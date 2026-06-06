# Phase 5 tooling evaluation — fixtures

This directory holds the **Phase 5 external-tool evaluation**: the plan, the blind briefs, and four purpose-built challenge targets (source + build script + committed binaries), each constructed so it **forces** one of the new reverse-engineering tools.

- **`EVAL_PLAN.md`** — the master plan: the VR-agent RE steps, the simulated-user UI walkthrough, the deterministic auto-population contract, success criteria, the two required agent reports, and how to run it. **Contains answer-key spoilers — this is the orchestrator's copy. Never hand it (or the `*.c` sources) to the VR agent.**
- **`BRIEFS.md`** — the blind, no-spoiler briefs. **This is the only thing the VR agent sees**, alongside the one compiled binary it is working.

## Challenges

Rebuild with `./build.sh` (needs `cc`, `mksquashfs`, and `docker` for the mingw PE). Sources are committed; the binaries are committed build outputs, like `tests/fixtures/challenges/`.

| Binary | Forces | Source | Why the tool is required |
|---|---|---|---|
| `mitis_relayd` | `binutils_facts` | `mitis_relayd.c` | executable stack (NX off) + `system` import buried past recon's cap |
| `stringcrypt.exe` | `floss_strings` | `stringcrypt.c` | C2 URL / key hidden as a stack string + XOR-decoded blob (not plain `strings`) |
| `vantage_iot_fw.bin` | `yara_scan` / `yara_sweep` | `logsvc.c` + `kvstore.c` | default-cred / weak-crypto / old-dropbear strings spread across two binaries |
| `licensegate` | angr (run after Phase 5C-B) | `licensegate.c` | a constraint-gated check whose only-valid input is *solved*, never stored |

The targets are fictional and version strings are scrubbed, so nothing is solvable by recognizing a public CVE — only by reverse-engineering the binary with the intended tool.

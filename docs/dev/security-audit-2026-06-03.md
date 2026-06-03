# Pre-release security audit — 2026-06-03

An adversarial, read-only audit of HexGraph's load-bearing security invariants, run as
independent passes ahead of the `v0.1.0` tag. Each invariant was reviewed against the actual
code by a separate reviewer trying to break it, not just confirm it. Scope was `main` at the
time of the `build/release-packaging` branch.

**Bottom line: all three invariants hold.** No high- or medium-severity issues. One
low-severity hardening gap and a handful of informational notes, tracked below.

## Loopback-only — PASS (one LOW)

The bind assertion (`assert_loopback`) sits on the single, unavoidable serve path
(`cli serve` → `run_server` → `assert_loopback` immediately before the only `uvicorn.run`).
A non-loopback bind raises unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`, which warns loudly. The
`HEXGRAPH_IN_CONTAINER=1` compose bypass is correctly the narrow "accept `0.0.0.0` only"
case and does **not** widen the Host-header allowlist. DNS-rebinding is defended by an
in-house, IPv6-aware Host-header guard plus a same-origin guard on every state-changing
endpoint; adversarial Host values (`evil.com`, `127.0.0.1.evil.com`, decimal/octal IPs,
`127.0.0.1@evil.com`) are all rejected. Neither the bind host nor the container flag is
reachable through the API.

- **F1 (LOW, hardening):** `HEXGRAPH_IN_CONTAINER=1` set *outside* a real container is a
  silent, un-warned non-loopback bypass (`api/loopback.py`). Not API-reachable and requires
  environment control equivalent to the documented override, so it is not an escalation —
  but unlike the operator override it emits no warning. Fix: warn loudly when the container
  bind is honored (and/or sanity-check for an actual container, e.g. `/.dockerenv`).

## Policy seam + sandbox — PASS

Every code path that executes the target, opens egress from a sandbox container, or boots a
rehost passes through the matching `assert_allows_*` / `current_policy()` gate before acting
and fails closed (`current_policy()` returns the static-only default on any settings error).
The exec paths are double-gated (engine assert + a runner-side `requires_execution`
re-check). Egress paths build a deny-all-but-this scope that refuses non-local and
SSRF-encoded hosts, assert the gate, and audit allow/deny to `EgressEvent` before the probe
runs. No feature code branches on backend/tier/executor identity; the only `== "mock"`
checks select the fuzzer/builder engine via the registry seam, never a security gate.

`_hardening_args` (`--network none` unless the policy-checked egress tier, `--read-only`,
`--cap-drop ALL`, `--no-new-privileges`, `--user`, stricter-than-default tmpfs) is applied to
every container that handles target bytes, locally and on the remote executor; a
`ResourceSpec` only ever touches mem/cpu/pids. `--privileged`/`--device` appear only in the
rehost emulator containers, behind `assert_allows_rehost()`. The LLM receives only derived,
length-bounded tool output; the raw artifact is only ever passed as a filesystem path into a
sandbox probe.

- Informational: the remote-executor staging helpers (`docker cp` of trusted probe scripts +
  a fixed `chmod`) intentionally don't use `_hardening_args` because they run no hostile
  bytes — worth a one-line code comment for posterity. `current_policy()`'s blanket
  `except: pass` fails closed but could mask a misconfigured `features.*` as a silent
  "static-only". Rehost containers are `--privileged` by necessity and rely on the
  bounded-egress probe boundary, matching the design docs.

## Secrets never logged / stored / returned — PASS

Every in-scope secret (`ANTHROPIC_API_KEY`, `HEXGRAPH_API_KEY`, SSH creds, remote-Docker
creds, `HG_CHANNEL_SECRET`) was traced from its read point to every sink. `settings.json`
and `/api/settings` are presence-only via a strict allowlist (a crafted PATCH can't write a
secret), with a second defensive gate in the setup wizard. Credentials reach a probe via an
env var, never argv (not visible in `/proc/<pid>/cmdline`); the remote executor scrubs the
`DOCKER_HOST`/TLS material from every error and health path. No secret column exists in the
DB; `EgressEvent` records only host:port + a non-secret descriptor. No secrets are hardcoded
in the tree.

- Informational: a `remote`/`fuzz_environment` `host_descriptor` is operator-typed free text
  the API echoes back; an operator who embedded a credential in the descriptor itself
  (`ssh://user:pass@host`) would see it echoed. The real connection string is always read
  separately from env/`config.toml`, so this is an operator-responsibility boundary, not a
  code leak — worth a one-line note in the remote/fuzz-remote docs.

## Follow-ups

- **F1** → a small hardening PR (warn on the container bind bypass).
- The informational notes → one-line code comments / doc notes; no behavior change needed.

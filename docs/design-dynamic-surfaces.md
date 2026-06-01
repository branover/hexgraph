# Design — Dynamic & networked attack surfaces

> **Status: IMPLEMENTED.** This design has shipped. HexGraph extends from *static
> binary/firmware analysis* to **web/service surfaces, live remote devices, and rehosted
> firmware** without breaking the hostile-isolation invariants. The graduated policy
> tiers, the Target-as-surface model, firmware rehosting (`features.rehost`), bounded
> network egress (`features.network`), and live-remote SSH/telnet collection
> (`features.remote`) are all live — see `CLAUDE.md`/`README.md` for the current,
> authoritative behaviour. This document is retained for the design rationale; where it
> describes a future "phase," read that as already delivered.

## Why

HexGraph today is excellent at *bytes at rest*: ingest a binary/firmware → sandboxed
recon/decompile/xrefs → typed graph → verified PoC (incl. opt-in dynamic PoC/fuzzing
via qemu). But a huge fraction of real router/IoT VR is **dynamic and networked**:

- an **auth bypass** in a router login page, or a **post-auth RCE** in a management web app;
- the way in is a live **SSH/telnet** session to a running device, not a firmware image;
- a vuln that only manifests when the firmware is **running with its real service/hardware
  dependencies** — which a single extracted binary can't model.

These need analysis to start from a *channel* (HTTP, a shell, an emulated machine), not a
file. This document defines the one abstraction that carries all three, the security model
that keeps it bounded, and the order we build it in.

## The core abstraction: a Target *is* a reachable attack surface

Keep **one** entity — `Target` — and generalise what it *means*. Do **not** fork a parallel
"surface" table: the target tree, polymorphic `edge`, `finding.target_id`, `task.target_id`,
archive/restore-by-sha, and `AnalysisRun` all key off `Target` and must keep working.

> A **byte target** is reached by mounting its file into the sandbox (today).
> A **dynamic target** is reached by opening a **Channel** — an HTTP base URL, an
> SSH/serial session, or an emulated-firmware instance — *from inside* the sandbox.

The only structurally new concept is the **Channel**: the connection descriptor + liveness
for a dynamic surface. It lives in `Target.metadata_json["channel"]` (a JSON sub-document —
zero migration, exactly like firmware's `metadata_json["filesystem"]`). So findings, edges,
tasks, and archive all keep pointing at `target_id` unchanged.

**The differentiator** is a single edge type, `serves` / `routes_to`: a discovered web route
or live service links to the **decompiled handler `function` node in the same firmware
binary**. That fuses static binary analysis with the live surface in one graph — something a
standalone web scanner or a standalone emulator cannot do. A confirmed web finding can point
straight at the CGI handler's `strcpy`; an n-day in one binary can be checked against the
live endpoint that reaches it.

### New vocabulary (mostly zero-migration)

`NodeType`/`EdgeType` are plain `String` columns (`db/models.py`), so new members are
zero-migration. `TargetKind` is an enum → adding members is one `alembic --autogenerate`
(stored as a string, so DDL is a no-op + a contract bump). The minimal set:

- **`TargetKind`**: `web_app` (HTTP/API surface — rehosted or live), `live_device` (a remote
  host reached by a credentialed channel), `rehosted_instance` (firmware booted under
  emulation), `service` (a non-HTTP listener).
- **`NodeType`** (zero-migration): `endpoint`/`route` (a web route/RPC method — the dynamic
  analogue of `function`), `param` (a request field — analogue of the existing `input`),
  `session` (an authenticated context — the *handle*, never the credential), `observation`
  (a recorded request/response, content-addressed in CAS so dynamic evidence is replayable).
- **`EdgeType`** (zero-migration): `serves`/`routes_to` (route → handler `function`),
  `reachable_via` (dynamic target → `session`/`endpoint`), `observed_at` (finding/node →
  `observation` provenance), `exposes` (`rehosted_instance` → `endpoint`/`service`). Reuse
  existing `taints`, `bypasses`, `listens_on`, `connects_to`, `derived_from`, `about`.

### Seam changes (the backbone)

- **Executor seam** (`sandbox/executor.py`, which already reserves `RemoteExecutor`/
  `DynamicExecutor`): widen the `Executor` Protocol with one dynamic verb —
  `run_channel_probe(probe, *, channel, …)` — and add concrete impls behind `get_executor()`:
  a **`NetworkExecutor`** (same disposable, capped, `--cap-drop ALL` container as today, but
  with a *bounded* network instead of `--network none` — the **only** place that flag is
  conditionally relaxed, and only after the policy allows egress) and a **`RehostExecutor`**
  (boots an image under emulation, exposes its services on a sandbox-internal address). Task
  code never branches on executor identity — it calls `get_executor()` and the new verb.
- **Collector** (a thin sibling of ingest for live devices): connects over the channel, pulls
  back accessible artifacts, and materialises them as targets/nodes so the **existing static
  VR runs on them unchanged**.

## Security model: graduated, opt-in policy tiers

Each new surface relaxes an invariant (network egress, executing a service, touching a live
host). We extend the **policy seam** (`policy.py`) into graduated tiers, each derived *only*
from a `features.*` toggle — there is no settable "tier" knob an agent could call, so
**enabling a capability is the sole way to raise the tier**, and a settings error
**fails closed** (deny), never open.

The tiers, constants, and flags below are **as shipped** in `policy.py`/`settings.py`:

| Tier | Constant | Enabled by | Permits |
|---|---|---|---|
| **0 — static-only** (default) | `TIER_STATIC_ONLY` | — | no exec, no network |
| **1 — sandboxed-exec** | `TIER_SANDBOXED_EXEC` | `features.poc.enabled` / `features.fuzzing.enabled` | exec; still `--network none` |
| **2 — local-network** | `TIER_LOCAL_NETWORK` | `features.network.enabled` | bounded egress to a **computed** per-target scope of loopback/private hosts only (`assert_allows_egress` + `NetworkScope` refuse any non-loopback/private host); every outbound action audited to `EgressEvent` |
| **3 — live-remote** | `TIER_LIVE_REMOTE` | `features.remote.enabled` | egress pinned to **one** operator-authorized remote `host:port` (`remote_scope`, `assert_allows_remote`); mandatory egress **audit log**; read-only tool allowlist on the device |

(`features.rehost.enabled` is a **separate, orthogonal gate** — `assert_allows_rehost()` — that
permits full-system emulation of a firmware image inside the sandbox; assessing the booted
device's web surface then needs `features.network`. It is not itself a network tier.)

**Invariants that never relax, at any tier** (enforced *below* the policy so no tier can opt
out):

- The **loopback product promise** — the API/UI bind `127.0.0.1`. "Networked" refers to the
  **sandbox↔target** path only; HexGraph itself is never exposed. (Distinguish "binds
  loopback" from "may make one bounded, declared outbound connection when you opt in.")
- **The LLM never sees raw target bytes** — new dynamic tools still return *bounded text*
  (HTTP responses, captures, device dumps are summarised, never streamed raw to the model).
- **The model never touches the environment** — it *requests* a probe; HexGraph decides if
  the destination is in scope and runs it.
- **Isolation floor**: `--cap-drop ALL`, `no-new-privileges`, `--user 1000:1000`, mem/cpu/pids
  caps, read-only rootfs, hard timeout, disposable. Network changes *only* the `--network`
  flag + an egress allowlist sidecar; it never grants capabilities, root, or `--network host`.
- **Secrets never logged/stored/returned** — extended from the API key to all target
  credentials: env/`config.toml` only, never the DB, never `settings.json`, never logs.
- **Fail closed** — an unparseable/empty scope denies all egress.

New primitives alongside `assert_allows_execution`: `assert_allows_egress(dest)` /
`egress_scope()`, a default-deny allowlisting egress proxy, and an `EgressEvent` audit record
for every outbound action at Tiers 2–3. The seam rule holds: feature code says
`assert_allows_egress(dest)` + `get_executor()`, never `if tier == 3`.

### Centralized app-layer egress guard (shipped — review #7 middle ground)

With `features.network` on, the egress container runs with `--network bridge` (full LAN+
internet L3 reach). What confines a probe to its loopback/private target is an
**application-level** allowlist check. Originally each egress probe re-implemented its own
ad-hoc `dest in allow` string compare; a new probe that forgot it — or an unsuppressed
redirect / DNS-resolution mismatch — would get unconfined egress. (Note: this container runs
**HexGraph's own network-client probe code**, *not* the hostile target's bytes, so this is
defense-in-depth for our code, not an open hole.)

The interim hardening (shipped) centralizes that check into one shared chokepoint,
`sandbox/probes/_egress.py` (stdlib-only, since the sandbox image has no `hexgraph`):

- `dest(host, port)` — the canonical `"host:port"` normalization (mirrors how the policy
  scopes build entries; unbrackets IPv6) used for matching.
- `ensure_allowed(host, port, allow)` — the explicit pre-connect check, raising
  `EgressBlocked` off-list (probes translate it into their existing
  `{"error": "destination not in allowlist"}` shape).
- `install_socket_guard(allow)` — the **can't-forget backstop**: monkeypatches
  `socket.create_connection` / `socket.socket.connect{,_ex}` so *every* outbound
  **TCP (AF_INET/AF_INET6, SOCK_STREAM)** connect is checked against `allow`, even one a
  probe forgot to gate. It deliberately leaves **DNS resolution, UDP, and AF_UNIX**
  untouched (guarding `getaddrinfo`/UDP would break name resolution), and lets the
  legitimate on-allowlist target connect through (incl. the rehost device's private IP).

All five egress probes (`http_probe`, `tcp_probe`, `surface_probe`, `web_discover_probe`,
`remote_probe`) call `install_socket_guard(allow)` once at startup and route their explicit
check through the shared helper. A contract test statically asserts every egress probe
adopts the guard, so a *new* egress probe that forgets it fails CI.

### Future hardening — kernel-level egress confinement (Option B, deferred)

The robust end-state is **kernel-enforced** egress containment, not probe code: each
ephemeral egress container gets a per-container **nftables/iptables OUTPUT chain that is
DROP-default and ALLOWs only the run's allowlisted `host:port`** (plus the DNS resolver, if
needed). The kernel — not a Python monkeypatch — then drops any packet to an off-allowlist
destination, so a buggy/forgetful probe, a followed redirect, or a DNS-resolution mismatch
*cannot* reach a host outside the computed scope.

It is **deferred** because it is large and erodes the isolation floor:

- Installing per-container firewall rules needs **`NET_ADMIN`** inside the container (which
  contradicts `--cap-drop ALL`), or host-side veth/`nftables` rules keyed to each ephemeral
  container's network namespace — a non-trivial sidecar that must be torn down with the
  disposable container and must never widen capabilities/root.
- The **rehost** path joins the emulator's network namespace
  (`--network container:<emulator>`), so per-probe rules can't simply live on the probe's own
  netns — the shared-netns case needs separate handling.
- It must remain **fail-closed** and never relax outside the policy seam.

Until that lands, the **centralized app-layer guard above is the shipped interim**: a single
robust-by-construction chokepoint instead of N copy-pasted checks. (Referenced from the
`sandbox/probes/_egress.py` module docstring.)

The unforgeable **`{{NONCE}}` oracle** (`engine/poc.py`) generalises directly to network
PoCs: an injected command echoes the nonce in an HTTP response, or an auth bypass reaches a
nonce-gated page — proving the exploit really crossed the boundary instead of trusting the
model.

## The three entry points (they compose)

A **rehosted instance is a live device** with HTTP + SSH, so these reuse one another:

- **Web/service surface** *(first live capability — see phasing)*. Model a web app as
  `endpoint`/`param`/`session` nodes; tasks for crawl, auth-state modelling, and
  request/param fuzzing; an HTTP-request PoC reusing the `{{NONCE}}` oracle. Wrap real tools
  (httpx, nuclei, ffuf/katana, a headless Chromium/Playwright, sqlmap) rather than rebuild.
  The `serves` edge links each route to its handler `function` in the firmware binary.
- **Live device via SSH/telnet**. A `Collector` (paramiko/asyncssh; telnet/serial/adb) opens
  a credentialed channel, inventories listening services/processes/packages, then fetches
  prioritised artifacts (network-facing binaries → their libs → web root → config/nvram) and
  ingests them so the existing recon/decompile/xrefs/LLM analysis lights up — with a
  provenance stamp ("pulled from device X at time T"; static-from-bytes findings are more
  trustworthy than live command output, which a compromised device can fake).
- **Firmware rehosting**. Wrap FirmAE/Firmadyne/qemu-system (Renode for MCU/bare-metal) behind
  a `Rehoster`/`RehostExecutor` seam to boot an image into a live system, exposing its services
  for dynamic PoC/fuzzing with real dependency context. Rehosting is famously unreliable
  (NVRAM, peripherals, watchdogs) — treat it as **best-effort, env-gated**, degrading cleanly
  to static analysis when boot fails.

## Phasing (delivered)

The build followed the smallest-useful-slice-first order the design panel converged on; all
phases have shipped:

1. **Backbone** — the Target-as-surface vocabulary + the `policy.py` graduated-tier refactor +
   mock-backed surface recon materialising route/endpoint/param nodes and the `serves`→handler
   cross-link. Done.
2. **Network relaxation** — bounded egress + allowlist/audit behind `features.network`
   (Tier 2), live web recon bounded to the target. Done.
3. **Dynamic PoC** — web findings verified via the generalised `{{NONCE}}` channel oracle,
   `serves`-linked to the handler binary. Done.
4. **Other entry points** — firmware **rehosting** (`features.rehost`) and **live-device
   SSH/telnet collection** (`features.remote`, Tier 3), composing with the web track via the
   shared dynamic-target model. Done.

## Risks & open questions

- **Egress containment is the crux** — a bounded-network sandbox is materially harder than
  `--network none`. Default-deny allowlist, no `--network host` ever, computed (not
  user-supplied) scope at Tier 2; the egress proxy + audit is the highest-risk surface.
- **Rehosting reliability** — best-effort, env-gated, degrade to static on boot failure.
- **Liveness vs. the content-addressed model** — `ContextBundle`/CAS assume reproducible
  inputs; a live endpoint isn't. The `observation` node (CAS-stored request/response) is the
  bridge: context references the recorded observation, not the live channel. Staleness
  semantics need care.
- **Route identity/dedup** — parameterised paths (`/users/123` vs `/users/{id}`) need a
  normalisation rule analogous to `normalize_symbol_name` so `merge_duplicates` doesn't
  explode the graph.
- **Legal / rules-of-engagement** — hitting a live external host is the one place HexGraph can
  cause real-world harm; the authorization gate must be unskippable for non-loopback targets,
  and live collection on fragile production devices is read-mostly + capped by default.
- **`Executor` Protocol widening** is a small but real `@runtime_checkable` contract change —
  land it with the contract test and a `supports()`/`NotImplementedError` default.

## Grounding

Seams this builds on: `sandbox/executor.py` (Executor seam, reserved Remote/Dynamic impls),
`sandbox/runner.py` (the container boundary + isolation floor), `policy.py` (the analysis
policy seam), `db/models.py` (TargetKind/NodeType/EdgeType, the polymorphic edge),
`engine/ingest.py` + `engine/pipeline.py` (ingest/orchestration), `engine/poc.py` (the
`{{NONCE}}` oracle), `engine/agent_tools.py` + `engine/mcp_tools.py` (the two drive paths),
`settings.py` (`features.*`). See [`design-vision.md`](design-vision.md) and
[`implementation-plan.md`](implementation-plan.md) for the v2 foundation this extends.

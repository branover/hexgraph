# Fuzzing

`features.fuzzing` adds coverage-guided, surface-aware, campaign-driven fuzzing. Enable it
(`hexgraph config set features.fuzzing.enabled true`, then `just fuzz-build`) and a **Campaigns** tab
plus a per-target **Fuzz** button appear. The design rationale and internals live in
[design-fuzzing-and-source.md](design-fuzzing-and-source.md).

![A finished campaign's crash inbox — triage view](images/artifacts-triage.png)

## Engine by attack surface (the Fuzzer seam)

The `Fuzzer` seam picks the engine by **attack surface** (never branched on in task code):

- **`source_lib`** (an instrumented derived target, *with* source) → **AFL++** (`afl-clang-lto` +
  CmpLog + persistent mode) — real coverage.
- **`binary_only`** (a stripped ELF, *no* source) → **AFL++ qemu-mode** (`-Q`, full edge coverage via
  QEMU TCG; frida-mode the opt-in alt). A foreign-arch MIPS/ARM firmware binary runs under qemu-user
  with the parent firmware rootfs as the `-L` sysroot — the proven PoC path.
- **`network`** (a live / rehosted service) → **boofuzz** (generational, over a real socket) — or
  **desock + AFL++** to coverage-fuzz a *local* server binary with `--network none` (LD_PRELOAD turns
  its socket into stdin).
- **`file_format`** → AFL++ / libFuzzer + an auto-derived dictionary.

The UI never hardcodes the engine list — the Fuzz modal shows the engines the **server advertises**
for the target's surface (`GET /api/fuzz/engines`).

![The Fuzz modal — source/binary surface](images/fuzz-modal.png)

## Launching a campaign

The Fuzz modal is surface-aware: pick the target to fuzz (a launch from the Campaigns tab defaults to
the best surface — an instrumented or live target, not the raw ingested root) and the surface-relevant
inputs appear: **network** host/port/protocol + an optional binary-protocol `proto_spec`, optional
**seeds** (corpus paths) and a **dictionary** (auto-derived when omitted), a **focus function**, and
the per-campaign **`ResourceSpec`** (mem/cpus/pids + an *unconstrained* toggle), defaulting from
Settings.

![The Fuzz modal — network surface (boofuzz)](images/fuzz-modal-network.png)

Campaigns are **detached + crash-safe**: each launches a hardened `docker run -d` container owned by a
durable `fuzz_campaign` row; a periodic reaper streams crashes → `fuzz_crash` findings as they happen,
dedups by a normalized stack-hash, minimizes the reproducer, classifies exploitability, and **survives
a `serve` restart**. Start/stop/resume preserves the corpus in CAS.

![The Campaigns tab — live/finished campaign list](images/campaigns.png)

The Campaigns tab shows a **live row** per campaign (status, execs/s, edges covered, crash count,
coverage %) over a Server-Sent Events stream with polling fallback, plus Stop/Resume. A campaign that
did **0 work** (service unreachable / 0 executions) or hit **engine instability** finalizes in a
distinct **`degraded`** state with an amber warning badge explaining why — never a silent zero-crash
"completed".

## Crash triage

Selecting a campaign opens the **Artifacts / triage** view: crashes **grouped by dedup bucket** (one
representative + a dupe count), each with an **assurance chip** (the ladder — see
[verification-assurance.md](verification-assurance.md)), the deterministic exploitability rating, and a
**source-mapped stack** (symbolized frames → jump to the IDE line; ASan frames are symbolized at
runtime via `llvm-symbolizer`, a binary-only `abort` is addr2line'd to its sink). Per crash:

- **Reproduce** / **Minimize** re-run the stored reproducer **byte-faithfully** against the
  instrumented harness binary (LLM-free, the unforgeable `crash` oracle — the MCP verb is
  `verify_fuzz_artifact`).
- **Promote** confirms it as a tracked finding; **Promote → PoC** seeds a reproducer-backed PoC the
  one-click **Re-verify** path re-proves.

A binary-only crash climbs to `code_present/dynamic` (lab-confirmed in isolation); a network
service-death reaches `input_reachable/dynamic` (reached + triggered end-to-end through the live input
boundary; its crashing message replays over the socket). Every entity is deep-linkable by URL
(`?tab=campaigns&campaign=…`), so a triage view is shareable and restored on reload.

## Fuzzing a local network service — launch-and-join

A fuzz container runs on `--network bridge`, whose loopback is the *container's own* — so it cannot
reach a service bound to the host's bare `127.0.0.1`. For a service HexGraph can **start itself** (a
launchable server binary), it uses **launch-and-join**: it boots the service in its own hardened
sandbox container and joins the fuzzer to that container's network namespace, so `127.0.0.1:port` is
reachable **without `--network host`** — the isolation is preserved (both containers keep
`--cap-drop ALL` / `--no-new-privileges` / `--read-only` / non-root; the service runs `--network
none`, the fuzzer reaches it over the shared netns, every send audited).

The service launch rides the **PoC/fuzzing** exec tier; the fuzz egress rides **`features.network`** +
the bounded local-network tier. To fuzz a service **already running** on your host, bind it to a
reachable private address (`192.168.x.x` / `10.x.x.x`, or a container HexGraph can bridge to) and point
the campaign at that host. (`--network host` is deliberately not offered — it would dissolve the
isolation.)

## Network fuzzing rides the existing tier

Binary/source/desock fuzzing rides the **exec** tier (`features.fuzzing`). **Network** fuzzing rides
the **existing** local-network tier (`features.network` — bounded to loopback/private, every send
audited to an `EgressEvent`, joining a rehosted device's emulator netns) — **not a new gate**.
Composes with **rehost** (fuzz a rehosted device's service via its netns) and **remote**
(`features.remote` — blind network-fuzz of a physical device is off by default + loud-warned,
destructive; prefer replay/PoC).

## Remote fuzz environments (`features.fuzz_remote`)

Fuzzing is the one genuinely resource-hungry workload, so a campaign can run on a **Docker host you
own** instead of your laptop. A **fuzz environment** is a registered place a campaign's container runs:
`local` (the default) plus N remote Docker endpoints. Because the Builder and Fuzzer call HexGraph's
**Executor seam**, building and fuzzing run on the remote with **no analysis change** — the
`RemoteDockerExecutor` stages the build context + seed corpus to the remote over `DOCKER_HOST`
(CAS-content-addressed, via a named volume) and streams crashes/coverage/stats back into your **local
graph**.

**Trust model — the control plane stays loopback.** The API/UI never leave `127.0.0.1`; the remote is
purely a compute backend you own and explicitly authorize. The **same sandbox boundary applies on the
remote** — every container there still runs `--network none` (except the gated net-fuzz tier),
`--cap-drop ALL`, `--no-new-privileges`, `--read-only`, `--user 1000`, and the resource caps. Each
remote launch is **audited**. Running on a remote is gated *only* by `features.fuzz_remote` (off by
default, fail-closed).

**Register one** in Settings → *Remote fuzz environments* (or `POST /api/fuzz/environments`): give it a
name, a transport (`ssh`/`tcp`), and a non-secret descriptor. The **connection details are a secret** —
read at connect time from env or `config.toml`, never stored in the DB or logged, shown presence-only:

```bash
# env (preferred) — keyed by the environment id (e.g. id "fuzzbox"):
export HEXGRAPH_FUZZ_REMOTE_FUZZBOX_DOCKER_HOST="ssh://you@beefybox"     # SSH control socket
# or tcp:// + TLS client certs:
#   HEXGRAPH_FUZZ_REMOTE_FUZZBOX_DOCKER_HOST="tcp://10.0.0.5:2376"
#   HEXGRAPH_FUZZ_REMOTE_FUZZBOX_TLS_VERIFY=1   HEXGRAPH_FUZZ_REMOTE_FUZZBOX_CERT_PATH=~/.docker/fuzzbox
hexgraph config set features.fuzz_remote.enabled true
```
```toml
# …or config.toml
[fuzz_remote.fuzzbox]
docker_host = "ssh://you@beefybox"
```

A one-click **Health-check** verifies the endpoint is reachable + authorized and has the
`hexgraph-fuzz` image present. Then pick the environment in the Fuzz modal (defaults to `local`), or
pass `environment` to `start_fuzz_campaign` (MCP) / the campaign API. Each environment carries a
per-environment `ResourceSpec` ceiling the campaign inherits.

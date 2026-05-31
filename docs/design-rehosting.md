# Firmware rehosting → live web surface (design)

## Goal
Boot a **real firmware image** (its kernel + userland + web server) under full-system
emulation so HexGraph can assess the *running* device — the router login, the post-auth
admin console, the CGI handlers — not just the static binaries. The booted device's web
server becomes a `web_app` **surface** (a Channel), and everything HexGraph already does to
a live surface (`surface_recon` → endpoint/param/`routes_to` graph, `web_recon`,
`http_request`, web `verify_poc`) applies — now fused to the firmware's static binary graph
via the existing `routes_to` edge (the dynamic↔static bridge).

First target: **OWASP IoTGoat** (OpenWrt-based, deliberately-vulnerable web UI). Rehoster:
**FirmAE** (full-system `qemu-system` emulation with NVRAM faking + network bring-up).

## The seam (`engine/rehost.py`)
Mirrors the Decompiler/Executor seams — feature code asks `get_rehoster()`, never names a
tool:

```
class Rehoster(ABC):
    def rehost(self, firmware_path, *, brand=None, timeout=...) -> RehostResult: ...
    def stop(self, handle) -> None: ...

@dataclass RehostResult: ip: str; base_url: str; handle: str; detail: str

class FirmAERehoster(Rehoster):   # default
    # drives FirmAE inside its own privileged Docker container (FirmAE bundles
    # qemu-system + kernels). run.sh -r <brand> <firmware> boots it; we read the
    # assigned IP, confirm the web port answers, and return base_url=http://<ip>.
```

`get_rehoster()` returns `FirmAERehoster` unless `HEXGRAPH_REHOSTER` overrides. Degrades
gracefully: if Docker or the FirmAE image is absent it raises `RehostUnavailable` (caught
by callers, like `BridgeUnavailable`/decompile fallbacks) — analysis never hard-crashes.

## Policy gating (the seam, not a scattered check)
Rehosting **boots the whole firmware** (the strongest form of execution) and **brings up a
network the device serves on**. It therefore gets its own explicit, opt-in gate:
- `features.rehost` (default off) → `policy.assert_allows_rehost()`.
- Booting is the only new privilege rehosting adds. **Assessing** the booted device is
  unchanged: it's a private-IP `web_app` surface, so `http_request`/`web_recon`/web
  `verify_poc` still require **`features.network`** and the per-target `local_network_scope`
  (FirmAE assigns a loopback/private IP, e.g. `192.168.0.1`/`10.0.0.1`, which the existing
  scope guard permits; a non-private IP would be refused — structural containment holds).
- So a full live assessment needs BOTH `features.rehost` (to boot) and `features.network`
  (to talk to it). Static-only stays the default; a settings error fails closed.

The emulator runs in a **privileged, `--network`-isolated-from-the-host** container with its
own tap network; the firmware is hostile but contained to that emulation sandbox, and
HexGraph only reaches it over the bounded, audited egress path.

## Graph wiring
`rehost_firmware(session, project, firmware_target)`:
1. `assert_allows_rehost()`.
2. `get_rehoster().rehost(firmware.path)` → `base_url`.
3. `register_web_surface(..., parent=firmware_target, base_url=base_url)` — a `web_app`
   child of the firmware (so the surface hangs under the image it came from).
4. Return the surface target; the operator/agent then runs `surface_recon` (with a route
   spec or crawl) + assesses it. `routes_to` links each discovered route to the handler
   function already materialized in the firmware's static graph.

Every outbound request is audited to `EgressEvent`; the boot itself is recorded as an
`EgressEvent`/run note so there's a durable log that the device was emulated.

## Surfaces
- CLI: `hexgraph rehost <firmware-target>` (+ `make iotgoat` to fetch IoTGoat, ingest it,
  rehost, and register the surface — the "hand it to Claude" harness for a real image).
- MCP: a `rehost` run-tool (gated by `features.rehost`) so a driver agent can boot + assess.

## Honest limits
Full-system rehosting is best-effort: many vendor images don't boot cleanly (missing NVRAM
defaults, watchdogs, custom init). FirmAE's heuristics get a large fraction up; when a boot
fails or no web port answers, `rehost_firmware` reports that clearly rather than pretending.
IoTGoat is a known-good FirmAE target, used as the reference. Heavy deps (FirmAE image,
qemu-system, privileged Docker + `/dev/net/tun`) are env-gated exactly like the Ghidra and
sandbox toolchains — offline tests use a fake rehoster; live boot is gated + documented.

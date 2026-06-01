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

class FirmAERehoster(Rehoster):   # vendor firmware blobs (squashfs/cramfs/trx/uImage)
    # drives FirmAE in a privileged Docker container: extracts the rootfs, supplies a
    # kernel + libnvram, boots it, infers the network. run.sh -r <brand> <firmware>.

class QemuDiskRehoster(Rehoster): # full-OS disk images (.vmdk/.qcow2/.vdi, partitioned .img)
    # boots the image's OWN kernel + init under qemu-system-x86_64 + KVM, as-is, in a
    # container (--device /dev/kvm). user-net hostfwd exposes the guest web port at
    # 127.0.0.1:<port> inside the container netns; the probe joins that netns to reach it.
```

**Two rehosters, auto-selected by image type** (`select_rehoster`): a *full-OS disk image*
(a bootable VM disk, or a partitioned MBR/GPT image — detected by magic/extension) boots
as-is under **qemu+KVM**; a *vendor firmware blob* (no kernel/partition table) goes to
**FirmAE** to extract + supply a kernel. `HEXGRAPH_REHOSTER=qemu|firmae` forces a choice;
`get_rehoster(firmware_path=…)` does the auto-selection. Both degrade gracefully: if Docker
or the image is absent they raise `RehostUnavailable` (caught by callers, like
`BridgeUnavailable`/decompile fallbacks) — analysis never hard-crashes.

This split is why **IoTGoat works via qemu but not FirmAE**: it's a full OpenWrt disk image,
so qemu boots the real OS (procd→ubus→uhttpd come up normally), whereas FirmAE's
extract-and-reboot harness can't bring OpenWrt's service stack up. Validated end-to-end:
HexGraph auto-selected qemu for the IoTGoat x86 image, booted it, registered the live
`web_app` surface, and `http_request` reached its `uhttpd` (HTTP 307→HTTPS LuCI) through the
container netns.

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
Full-system rehosting is best-effort: many images don't boot cleanly (missing NVRAM
defaults, watchdogs, custom init). FirmAE's heuristics get a large fraction up; when a boot
fails or no web port answers, `rehost_firmware` reports that clearly rather than pretending.
Heavy deps (FirmAE image, qemu-system, privileged Docker + `/dev/net/tun`) are env-gated
exactly like the Ghidra and sandbox toolchains — offline tests use a fake rehoster; live
boot is gated + documented.

**What "best-effort" means, concretely** (validated end-to-end on this build):
- FirmAE runs as designed for **traditional vendor firmware** (sysvinit / `/etc/init.d/rcS`
  boot, squashfs/cramfs/jffs2 rootfs). For those, the seam takes you from a firmware blob to
  a live `web_app` surface.
- **OpenWrt-based images (incl. OWASP IoTGoat) don't come up under FirmAE** — OpenWrt's
  `procd`→`ubus`→`netifd`→`uhttpd` service chain fails to initialize under FirmAE's
  extract-and-reboot harness (the boot console loops "Failed to connect to ubus"); FirmAE
  infers the interface + web service but the guest never serves. **This is why auto-selection
  routes full-OS disk images to the qemu rehoster instead** — qemu boots the image's own
  kernel + init as-is, so OpenWrt comes up normally. (FirmAE remains the right tool for a
  vendor squashfs blob, which has no bootable kernel of its own.)
- **Loop devices are a global kernel resource.** A hard-killed emulator leaks a loop attached
  to FirmAE's fixed path (`/FirmAE/scratch/<iid>/image.raw`), which then shadows the next
  run's fresh loop and corrupts `makeImage` ("Bad magic number"). The entry script (root in
  the privileged container) detaches stale FirmAE loops at **startup and on exit (trap)**, and
  `FirmAERehoster.stop()` uses `docker stop` (SIGTERM → trap) before `rm`, so teardown is
  clean and runs self-heal across attempts.

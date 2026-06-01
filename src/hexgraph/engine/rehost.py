"""Firmware rehosting seam (docs/design-rehosting.md).

Boot a whole firmware image (kernel + userland + web server) under full-system emulation
so its LIVE web surface can be assessed, then register that surface as a `web_app` child of
the firmware target — fusing the running device to its static binary graph (the `routes_to`
bridge). Mirrors the Decompiler/Executor seams: feature code asks `get_rehoster()` and never
names a tool; `FirmAERehoster` (FirmAE in a privileged Docker container) is the default.

The emulated device lives on a tap network INSIDE the FirmAE container's namespace, so
HexGraph's probe joins that namespace (`--network container:<handle>`) to reach the device's
private IP directly — no host port-forwarding hacks, and the egress scope (loopback/private)
still contains it. Booting is gated by `features.rehost`; assessing the device by
`features.network` (it's a private-IP surface), exactly like any other web surface.

Degrades gracefully: if Docker or the FirmAE image is absent, `rehost()` raises
`RehostUnavailable` (callers handle it) — analysis never hard-crashes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target


class RehostError(RuntimeError):
    """Rehosting was attempted but failed (boot failed, no web port answered, …)."""


class RehostUnavailable(RehostError):
    """The rehoster can't run here (no Docker / FirmAE image) — handle gracefully."""


@dataclass(frozen=True)
class RehostResult:
    ip: str                 # the emulated device's IP on the FirmAE tap (private)
    base_url: str           # http://<ip>[:port] — the device's web surface
    handle: str             # the FirmAE container name (probe joins its netns)
    detail: str = ""


# Our FirmAE image's entrypoint prints this line once the device is up, carrying the
# device IP + whether a web port answered. Defining the contract OURSELVES (a thin wrapper
# over FirmAE) keeps it stable instead of parsing FirmAE's free-form output.
_MARKER = "HEXGRAPH_REHOST"


class Rehoster:
    name: str

    def rehost(self, firmware_path: str, *, brand: str | None = None,
               timeout: int | None = None) -> RehostResult: ...

    def stop(self, handle: str) -> None: ...


def _docker_available() -> bool:
    from hexgraph.sandbox.runner import docker_available

    return docker_available()


def _image_present(image: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
    return r.returncode == 0


class FirmAERehoster(Rehoster):
    """Drive FirmAE inside a privileged Docker container (it bundles qemu-system + kernels).
    Our `hexgraph-firmae` image's entrypoint runs FirmAE's analyze+run on the mounted
    firmware and, once the device serves, prints `HEXGRAPH_REHOST {json}` and keeps the
    emulation alive. We read that line, then hand back the container as the rehost handle."""

    name = "firmae"

    def __init__(self) -> None:
        from hexgraph import settings

        self.image = settings.get("features.rehost.image", "hexgraph-firmae:latest")
        self.timeout = int(settings.get("features.rehost.timeout", 600) or 600)

    def rehost(self, firmware_path: str, *, brand: str | None = None,
               timeout: int | None = None) -> RehostResult:
        if not _docker_available():
            raise RehostUnavailable("Docker is not running — rehosting needs it.")
        if not _image_present(self.image):
            raise RehostUnavailable(
                f"FirmAE image {self.image!r} not found — build it (make firmae-build) "
                "or set features.rehost.image.")
        if not os.path.isfile(firmware_path):
            raise RehostError(f"firmware not found: {firmware_path}")

        name = f"hexgraph-firmae-{uuid.uuid4().hex[:10]}"
        budget = int(timeout or self.timeout)
        # Privileged + /dev/net/tun: FirmAE creates a tap and runs qemu-system. The
        # firmware is hostile but contained to this emulation container; HexGraph reaches
        # the device only over the bounded, audited egress path (a probe joining this netns).
        cmd = [
            "docker", "run", "-d", "--name", name, "--privileged",
            "--device", "/dev/net/tun",
            "-v", f"{os.path.abspath(firmware_path)}:/firmware/image.bin:ro",
            self.image,
        ]
        if brand:
            cmd.append(brand)
        run = subprocess.run(cmd, capture_output=True, text=True)
        if run.returncode != 0:
            raise RehostError(f"failed to start FirmAE container: {run.stderr.strip()[:400]}")
        try:
            info = self._await_marker(name, budget)
        except Exception:
            self.stop(name)
            raise
        ip = info.get("ip")
        if not ip:
            self.stop(name)
            raise RehostError("FirmAE booted but reported no device IP")
        if not info.get("web"):
            # leave the container up for diagnosis is unhelpful; tear down + report
            self.stop(name)
            raise RehostError(f"firmware emulated at {ip} but no web port answered")
        port = info.get("port") or 80
        base = f"http://{ip}" if port == 80 else f"http://{ip}:{port}"
        return RehostResult(ip=ip, base_url=base, handle=name,
                            detail=info.get("detail", f"FirmAE emulated the firmware at {ip}"))

    def _await_marker(self, name: str, budget: int) -> dict:
        """Follow the container logs until the entrypoint prints the HEXGRAPH_REHOST line
        (bounded by `budget`)."""
        proc = subprocess.Popen(["docker", "logs", "-f", name], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        import time
        deadline = time.monotonic() + budget
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                if _MARKER in line:
                    m = re.search(_MARKER + r"\s+(\{.*\})", line)
                    if m:
                        return json.loads(m.group(1))
                if time.monotonic() > deadline:
                    raise RehostError(f"firmware did not boot within {budget}s")
            raise RehostError("FirmAE exited before the device came up (boot failed)")
        finally:
            proc.kill()

    def stop(self, handle: str) -> None:
        # `docker stop` sends SIGTERM first, so the entry script's trap detaches the loop
        # devices it created (they're a global kernel resource — a hard `rm -f`/SIGKILL
        # would leak them and poison the next run). Then remove the container.
        subprocess.run(["docker", "stop", "-t", "15", handle], capture_output=True)
        subprocess.run(["docker", "rm", "-f", handle], capture_output=True)


def get_rehoster() -> Rehoster:
    """The rehosting seam. `HEXGRAPH_REHOSTER` overrides (e.g. 'firmae')."""
    name = os.environ.get("HEXGRAPH_REHOSTER", "firmae").lower()
    if name == "firmae":
        return FirmAERehoster()
    raise ValueError(f"unknown rehoster {name!r}")


def rehost_firmware(session: Session, project: Project, firmware: Target,
                    *, brand: str | None = None, rehoster: Rehoster | None = None) -> Target:
    """Boot `firmware` under full-system emulation and register its live web server as a
    `web_app` surface child of the firmware. Gated by features.rehost. Returns the surface
    target; assess it with surface_recon/web_recon/http_request (needs features.network)."""
    from hexgraph.engine.audit import record_egress
    from hexgraph.engine.surfaces import register_web_surface
    from hexgraph.policy import assert_allows_rehost

    assert_allows_rehost()  # opt-in gate: raises unless features.rehost is enabled
    if not firmware.path or not os.path.isfile(firmware.path):
        raise RehostError("firmware target has no byte image on disk to emulate")

    rehoster = rehoster or get_rehoster()
    result = rehoster.rehost(firmware.path, brand=brand)

    surface = register_web_surface(
        session, project, result.base_url, name=f"{firmware.name} (rehosted)", parent=firmware)
    # Record the rehost handle on the surface's channel so the probe joins the emulator's
    # network namespace to reach the device IP.
    meta = dict(surface.metadata_json or {})
    channel = dict(meta.get("channel") or {})
    channel["rehost"] = {"container": result.handle, "ip": result.ip, "rehoster": rehoster.name}
    meta["channel"] = channel
    surface.metadata_json = meta
    session.flush()

    # Durable, auditable record that the firmware was emulated and is being reached.
    # Use the same host:port form the egress allowlist uses (urlparse, default port 80)
    # so the boot event lines up with the later probe events for this surface.
    u = urlparse(result.base_url)
    dest = f"{u.hostname or result.ip}:{u.port or (443 if u.scheme == 'https' else 80)}"
    record_egress(session, project_id=project.id, target_id=surface.id, task_id=None,
                  dest=dest, allowed=True, tool="rehost", detail=result.detail)
    return surface


def rehost_container(target: Target) -> str | None:
    """The FirmAE container backing a rehosted surface, if any — the probe joins its netns."""
    return ((target.metadata_json or {}).get("channel", {}).get("rehost") or {}).get("container")

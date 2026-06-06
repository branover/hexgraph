#!/usr/bin/env python3
"""Stand up a REAL firmware as a live web target: ingest the image, boot it under
full-system emulation (FirmAE), register its web server as a surface, and print how to
hand the engagement to a Claude Code agent.

    .venv/bin/python scripts/rehost_engagement.py /path/to/firmware.img [--brand auto]
or: just iotgoat fw=/path/to/IoTGoat-rpi.img   (downloads IoTGoat if fw is unset)

Prereqs: the FirmAE image built (`just firmae-build`) and Docker with /dev/net/tun +
--privileged available. Enables features.rehost + features.network for you.
Tear down the emulator with:  docker rm -f <the container name printed below>
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware", help="path to the firmware image to rehost")
    ap.add_argument("--brand", default="auto", help="FirmAE brand hint (default: auto)")
    ap.add_argument("--name", default=None, help="target name")
    args = ap.parse_args()

    import os
    if not os.path.isfile(args.firmware):
        print(f"error: firmware image not found: {args.firmware}\n"
              "(download IoTGoat with `just iotgoat`, or pass an existing image path.)",
              file=sys.stderr)
        return 2

    from hexgraph import settings
    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import session_scope
    from hexgraph.engine.ingest import create_project, ingest_file
    from hexgraph.engine.rehost import RehostError, rehost_firmware
    from hexgraph.policy import PolicyViolation
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    prepare_database()
    # Booting needs features.rehost; talking to the device needs features.network.
    settings.update_settings({"features": {"rehost": {"enabled": True},
                                           "network": {"enabled": True}}})
    with session_scope() as s:
        project = create_project(s, name=args.name or "rehosted firmware")
        # Ingest the image (sandboxed recon + unpack populate the static graph) so the
        # rehosted surface's routes_to edges can bind to real handler functions.
        fw = ingest_file(s, project, args.firmware, name=args.name)
        if docker_available():
            from hexgraph.engine.pipeline import analyze_target
            try:
                analyze_target(s, project, fw, get_executor())
            except Exception as exc:  # noqa: BLE001 — recon is best-effort here
                print(f"(recon skipped: {exc})", file=sys.stderr)
        pid, fwid = project.id, fw.id

    print(f"• ingested firmware target {fwid}; booting under FirmAE (this can take minutes)…")
    with session_scope() as s:
        from hexgraph.db.models import Project, Target
        project, fw = s.get(Project, pid), s.get(Target, fwid)
        try:
            surface = rehost_firmware(s, project, fw, brand=args.brand)
        except PolicyViolation as exc:
            print(f"error: {exc}", file=sys.stderr); return 1
        except RehostError as exc:
            print(f"rehost failed: {exc}", file=sys.stderr)
            print("(IoTGoat is the known-good reference image; many vendor images don't boot "
                  "cleanly under emulation.)", file=sys.stderr)
            return 1
        ch = (surface.metadata_json or {}).get("channel", {})
        sid, base, container = surface.id, ch.get("base_url"), ch.get("rehost", {}).get("container")

    print("\n" + "=" * 72)
    print("Rehosted firmware engagement is ready.")
    print("=" * 72)
    print(f"  project_id : {pid}")
    print(f"  firmware   : {fwid}")
    print(f"  surface    : {sid}  →  {base}")
    print(f"  emulator   : container {container}")
    print("\nHand it to Claude Code (scripts/engagement-rehosted.md), giving it the project_id")
    print("and surface id. Then task_run(surface, 'surface_recon'/'web_recon'), net_http_request,")
    print("finding_verify_poc — the same web workflow, now against the real firmware's live UI.")
    print(f"\nTear down the emulator when done:  docker rm -f {container}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

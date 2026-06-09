"""Network / protocol fuzzing — boofuzz (live, default) + desock+AFL++ (local, tier 1).
Design §2.3 / §5.6.

Two tiers, picked by the surface's engine (the seam, never branched on in task code):

  • **boofuzz (tier 2, live socket — the DEFAULT, `engine="boofuzz"`).** A GENERATIONAL
    protocol fuzzer: HexGraph hands the probe a small request/state spec (blocks, a
    length/checksum field, a tiny state graph) and boofuzz mutates each field, driving a
    LIVE service over a real socket. The campaign joins the rehosted device's emulator
    netns (`net_container`) or talks to a local service; egress is bounded by
    `local_tcp_scope(host,port)` + `features.network` and EVERY connection is audited to
    `EgressEvent` — refusing any non-loopback/non-private host (the EXISTING local-network
    tier, no new gate). A crash = the service DIED (the liveness oracle re-probes it
    DOWN) → `input_reachable/dynamic` (the strongest assurance — reached through the live
    input boundary). Why boofuzz over AFLNet: it is pure-Python (no kernel modules / no
    rebuilding the target as a forkserver), it drives an ARBITRARY live/rehosted service
    we don't have source for, and it carries a re-runnable crashing message sequence the
    existing verify path replays — exactly the blind-network-fuzz case the battle test
    needs. AFLNet (mutational-replay over a recorded corpus) is the natural future
    alternate when a recorded corpus + a local forkserver binary exist; desock covers the
    coverage-guided local-binary case today.

  • **desock+AFL++ (tier 1, `engine="desock"`, `--network none`).** When we HAVE the
    server binary, LD_PRELOAD libdesock turns its accept()/recv() socket into stdin,
    so AFL++ coverage-fuzzes it with no real networking — keeping the static-by-default
    posture. A desock crash (ASan/signal) is `code_present/dynamic`.

The engine resolves inputs + returns the launch description; the campaign engine runs the
detached container (boofuzz on the bounded-egress path, desock on `--network none`) and
the reaper ingests crashes through the SAME Phase-3 pipeline.
"""

from __future__ import annotations

import json
import os
import tempfile

from hexgraph.engine.fuzzers.base import FuzzCampaignSpec, Fuzzer, PreparedFuzz
from hexgraph.engine.fuzzers.shared import fuzz_image


class BoofuzzFuzzer(Fuzzer):
    """Generational live-socket protocol fuzzer (the default network engine)."""

    name = "boofuzz"
    surfaces = ("network",)

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        host, port = spec.host, spec.port
        # The launch-and-join path (§5.8b): HexGraph LAUNCHES the service itself in a
        # detached container, so the fuzzer reaches it on the SHARED netns loopback —
        # the host is `127.0.0.1` by construction. A bare port + a launchable server
        # binary is enough; the live host is that service container's loopback.
        launch_on = bool(spec.launch) and bool(spec.launch_binary)
        if not port:
            raise ValueError(
                "network fuzzing needs the service port (a rehosted device IP / local "
                "service); none resolved from the target")
        if not host and not launch_on:
            raise ValueError(
                "network fuzzing needs the live service host (a rehosted device IP / local "
                "service); none resolved from the target — for a service HexGraph can start "
                "itself, use the launch-and-join path (a launchable server binary)")
        if launch_on and not host:
            host = "127.0.0.1"  # the launched service listens on the shared-netns loopback

        # The protocol spec (blocks/checksum/state). Default: a single mutable request
        # block seeded from the dictionary/seed (so even a bare port is fuzzed). The
        # operator/LLM can pass a richer proto_spec (multi-block, checksum, state graph).
        # The connection descriptor (host/port/allow/outdir) is built + appended by the
        # campaign engine at launch (it owns the egress scope + audit); prepare carries
        # only the proto-spec (no bytes at rest).
        proto = spec.proto_spec or _default_proto_spec(spec)
        extra_args = ["--proto-spec", json.dumps(proto)]
        return PreparedFuzz(
            probe="boofuzz_probe.py", image=fuzz_image(), artifact=None,
            extra_args=extra_args, extra_ro_mounts=[],
            coverage_instrumented=False, engine="boofuzz",
            # The ONLY place a campaign relaxes --network none: bounded, scoped, audited.
            requires_egress=True, egress_host=host, egress_port=int(port),
            net_container=spec.net_container,
            # When launch-and-join is on, the campaign engine starts this server ELF in
            # its OWN service container FIRST and joins the fuzzer to its netns.
            launch_binary=spec.launch_binary if launch_on else None,
            launch_command=spec.launch_command if launch_on else None,
            launch_sysroot=spec.sysroot if launch_on else None,
        )


class DesockAflFuzzer(Fuzzer):
    """desock + AFL++ — coverage-fuzz a LOCAL server binary with --network none (tier 1)."""

    name = "desock"
    surfaces = ("network",)

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        binary = spec.target_binary or (target.path or None)
        if not binary:
            raise ValueError(
                "desock+AFL++ network fuzzing needs the LOCAL server binary "
                "(spec.target_binary or target.path); for a live service with no binary "
                "use the boofuzz engine")
        extra_args = [
            f"--max-total-time={spec.max_total_time}",
            f"--max-crashes={spec.max_crashes}",
            f"--instances={max(1, int(spec.instances))}",
            f"--port={int(spec.port)}" if spec.port else "--port=0",
        ]
        mounts: list[tuple[str, str]] = []
        if spec.sysroot:
            mounts.append((spec.sysroot, "/sysroot"))
            extra_args.append("--sysroot=/sysroot")
        for i, s in enumerate(spec.seeds):
            if s and os.path.isfile(s):
                mounts.append((s, f"/seeds/seed_{i}"))
                extra_args.append(f"--seed=/seeds/seed_{i}")
        if spec.dictionary:
            extra_args.append("--dict=" + json.dumps(spec.dictionary[:256]))
        return PreparedFuzz(
            probe="desock_probe.py", image=fuzz_image(), artifact=binary,
            extra_args=extra_args, extra_ro_mounts=mounts,
            coverage_instrumented=True, engine="desock",
            requires_egress=False,  # desock feeds the socket from stdin → --network none
        )


def _default_proto_spec(spec: FuzzCampaignSpec) -> dict:
    """A minimal one-request boofuzz spec when the caller gave none: a single mutable
    string block seeded from a dictionary token / seed, terminated by CRLF. Enough to
    blindly fuzz a line/length-prefixed text protocol (the common firmware-daemon case)."""
    seed = ""
    if spec.dictionary:
        seed = str(spec.dictionary[0])[:64]
    return {
        "messages": [
            {"name": "request",
             "fields": [
                 {"type": "string", "name": "cmd", "default": seed or "FUZZ", "fuzzable": True},
                 {"type": "delim", "name": "crlf", "default": "\r\n", "fuzzable": False},
             ]},
        ],
        "receive_after_send": True,
    }

"""Binary-only fuzzing — AFL++ qemu-mode (default) / frida-mode (alt), design §2.3/§5.4.

The firmware case: a stripped ELF with NO source. AFL++ qemu-mode (`-Q`) gets full edge
coverage from QEMU's TCG without instrumenting the target — and it REUSES HexGraph's
proven qemu-user foreign-arch path: a MIPS/ARM/… firmware binary runs under
`qemu-<arch>` (AFL++ ships its own `afl-qemu-trace` per-arch), and the parent firmware's
extracted rootfs is mounted as the `-L` sysroot so a dynamically-linked binary finds its
libs — exactly the mechanism `poc_probe`/`verify_poc` already use.

frida-mode (`-O`) is the opt-in alternative (faster on some native x86, weaker cross-arch,
adds a runtime-injection dependency). The seam picks qemu-mode by default; an explicit
`engine="frida"` override switches the probe flag.

The engine resolves the target ELF + sysroot and returns the `afl_qemu_probe.py` launch
description; the campaign engine runs it DETACHED (`--network none`) and the reaper
ingests crashes through the SAME Phase-3 artifact/dedup/exploitability/minimize/verify
pipeline — a binary-only crash is `code_present/dynamic` (§5.6).
"""

from __future__ import annotations

import json

from hexgraph.engine.fuzzers.base import FuzzCampaignSpec, Fuzzer, PreparedFuzz
from hexgraph.engine.fuzzers.shared import fuzz_image


class BinaryOnlyFuzzer(Fuzzer):
    """AFL++ qemu-mode / frida-mode — no source, coverage from the emulator."""

    name = "qemu"
    surfaces = ("binary_only", "file_format")

    def __init__(self, mode: str = "qemu") -> None:
        # mode ∈ {"qemu","frida"} — the probe flag; default qemu (the firmware fit).
        self.mode = "frida" if mode == "frida" else "qemu"
        self.name = self.mode

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        binary = spec.target_binary or (target.path or None)
        if not binary:
            raise ValueError(
                "binary-only fuzzing needs the target ELF (spec.target_binary or target.path)")

        extra_args = [
            f"--mode={self.mode}",
            f"--max-total-time={spec.max_total_time}",
            f"--max-crashes={spec.max_crashes}",
            f"--instances={max(1, int(spec.instances))}",
        ]
        mounts: list[tuple[str, str]] = []
        # The target ELF is mounted at /artifact (ro) by the runner; afl-fuzz needs to run
        # it (copied to the writable /out by the probe). A foreign-arch ELF runs under
        # afl-qemu-trace's bundled qemu; the parent firmware rootfs is the `-L` sysroot.
        if spec.sysroot:
            mounts.append((spec.sysroot, "/sysroot"))
            extra_args.append("--sysroot=/sysroot")

        for i, s in enumerate(spec.seeds):
            import os
            if s and os.path.isfile(s):
                mounts.append((s, f"/seeds/seed_{i}"))
                extra_args.append(f"--seed=/seeds/seed_{i}")
        if spec.dictionary:
            extra_args.append("--dict=" + json.dumps(spec.dictionary[:256]))

        # qemu-mode gives real edge coverage (via TCG) of the *target* — honestly
        # coverage-instrumented even with no source. frida-mode likewise.
        return PreparedFuzz(
            probe="afl_qemu_probe.py", image=fuzz_image(), artifact=binary,
            extra_args=extra_args, extra_ro_mounts=mounts,
            coverage_instrumented=True, engine=self.mode,
        )


class FridaFuzzer(BinaryOnlyFuzzer):
    """frida-mode — the opt-in binary-only alternative (engine='frida')."""

    name = "frida"

    def __init__(self) -> None:
        super().__init__(mode="frida")

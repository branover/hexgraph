#!/usr/bin/env python3
"""FLOSS string deobfuscation over a single target, run INSIDE the sandbox.

Recovers the strings a plain `strings` pass misses — STACK strings (built one byte
at a time on the stack at run time), TIGHT strings (a packed form decoded on the
stack), and DECODED strings (produced by a decode routine FLOSS lightly EMULATES) —
in addition to a clean STATIC `strings` pass. On firmware/malware targets these
hidden strings (URLs, command templates, keys, format strings) are often the lead.

It shells out to the real FLARE `floss` CLI with `-j` and parses its JSON, so the
results are exactly what FLOSS reports. FLOSS emulates the constructing functions
IN-PROCESS inside this container's Python (vivisect) — it NEVER executes the target
natively, opens no socket, and stays on the same static surface as every other probe
(--network none, the target is only inspected).

**Arch / format reality.** FLOSS's stack/tight/decoded recovery is driven by vivisect,
which supports the **PE** format (x86/amd64) for string DECODING + stackstrings. On a
non-PE artifact (an ELF firmware binary, a foreign-arch MIPS/ARM blob, shellcode we
won't guess), FLOSS can still do a STATIC pass but its emulation legs error out. So the
probe DEGRADES GRACEFULLY: a PE gets the full pass; anything else gets a static-only
pass plus an explicit `note`, never a crash. A wholly unreadable/unanalyzable artifact
is reported as an error JSON on stdout with a non-zero exit (the runner surfaces it).

Caps mirror recon/binutils discipline: every recovered list is bounded so a hostile blob
saturated with strings can't make the payload grow without bound — this probe records a
curated Observation, it does not re-flood the graph (the agent promotes what matters).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

# Bounds (mirror recon/binutils caps so a huge/hostile binary yields a bounded payload).
# These are the FULL recovered lists in the Observation payload; promotion into the graph
# is a deliberate, separate act (the probe feeds the substrate, it does not mint nodes).
_MAX_STACK = 2000        # stack strings kept
_MAX_TIGHT = 2000        # tight strings kept
_MAX_DECODED = 2000      # decoded strings kept
_MAX_STATIC = 2000       # FLOSS static strings kept (recon/binutils promote far fewer)

_DEFAULT_MIN_LEN = 4     # FLOSS's own default minimum string length
_MIN_LEN_FLOOR = 4       # never go below FLOSS's floor (shorter = noise)
_MIN_LEN_CEIL = 64       # an obvious upper guard on an agent-supplied value

# FLOSS itself can be slow (it emulates decode routines). The sandbox ALSO hard-caps the
# run; this is a defence-in-depth inner wall-clock guard so one pathological sample can't
# wedge the container for the whole outer budget.
_TIMEOUT = 600


def _read_magic(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(2)


def _is_pe(magic: bytes) -> bool:
    """A PE/COFF image starts with the DOS stub magic 'MZ'. FLOSS's decode/stackstring
    emulation supports PE; this gate decides full-vs-degraded."""
    return magic[:2] == b"MZ"


def _floss_argv(path: str, *, min_length: int, only: list[str] | None) -> list[str]:
    """The FIXED command this probe assembles (never agent argv). Always ends in the
    read-only artifact path, with `--` so a path that looks like a flag can't be one.
    `only` restricts to a string-type subset (the degraded static-only path); the FLOSS
    flags themselves stay fixed here — the agent only ever influences `min_length`."""
    argv = ["floss", "-j", "-q", "-n", str(min_length)]
    if only:
        argv += ["--only", *only]
    argv += ["--", path]
    return argv


def _run_floss(path: str, *, min_length: int, only: list[str] | None) -> tuple[int, str, str]:
    argv = _floss_argv(path, min_length=min_length, only=only)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, "", f"floss timed out after {_TIMEOUT}s"
    except OSError as exc:
        return 127, "", f"failed to run floss: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def _bounded(items: list, cap: int) -> tuple[list, bool]:
    """Cap a list, reporting whether it was truncated (no silent caps — the discipline)."""
    if len(items) <= cap:
        return items, False
    return items[:cap], True


def _stack_entries(rows: list) -> list[dict]:
    """Normalize FLOSS stack/tight-string rows to a compact, stable shape: the string +
    its source function and offset where available (FLOSS gives them as integers)."""
    out: list[dict] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        out.append({
            "string": r.get("string"),
            "encoding": r.get("encoding"),
            "function": r.get("function"),
            "offset": r.get("offset"),
            "program_counter": r.get("program_counter"),
        })
    return out


def _decoded_entries(rows: list) -> list[dict]:
    """Normalize FLOSS decoded-string rows: the string + the decode routine that built it
    and where it was decoded (the lead material — a decode routine is worth pivoting to)."""
    out: list[dict] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        out.append({
            "string": r.get("string"),
            "encoding": r.get("encoding"),
            "decoding_routine": r.get("decoding_routine"),
            "decoded_at": r.get("decoded_at"),
            "address": r.get("address"),
            "address_type": r.get("address_type"),
        })
    return out


def _static_entries(rows: list) -> list[dict]:
    out: list[dict] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        out.append({"string": r.get("string"), "encoding": r.get("encoding"),
                    "offset": r.get("offset")})
    return out


def _assemble(raw: dict, *, degraded: bool, note: str | None,
              min_length: int) -> dict:
    """Build the probe's curated, bounded payload from FLOSS's JSON."""
    strings = raw.get("strings") if isinstance(raw, dict) else {}
    strings = strings if isinstance(strings, dict) else {}
    meta = raw.get("metadata") if isinstance(raw, dict) else {}
    meta = meta if isinstance(meta, dict) else {}

    stack, st_trunc = _bounded(_stack_entries(strings.get("stack_strings")), _MAX_STACK)
    tight, ti_trunc = _bounded(_stack_entries(strings.get("tight_strings")), _MAX_TIGHT)
    decoded, de_trunc = _bounded(_decoded_entries(strings.get("decoded_strings")), _MAX_DECODED)
    static, st2_trunc = _bounded(_static_entries(strings.get("static_strings")), _MAX_STATIC)

    truncated = {k: v for k, v in {
        "stack_strings": st_trunc, "tight_strings": ti_trunc,
        "decoded_strings": de_trunc, "static_strings": st2_trunc,
    }.items() if v}

    facts: dict = {
        "tool": "floss_probe",
        "floss_version": meta.get("version"),
        "language": meta.get("language"),
        "min_length": min_length,
        "degraded": degraded,           # True ⇒ static-only (non-PE / unsupported emulation)
        "stack_strings": stack,
        "tight_strings": tight,
        "decoded_strings": decoded,
        "static_strings": static,
        "counts": {
            "stack_strings": len(stack),
            "tight_strings": len(tight),
            "decoded_strings": len(decoded),
            "static_strings": len(static),
        },
    }
    if truncated:
        facts["truncated"] = truncated  # never a silent cap
    if note:
        facts["note"] = note
    return facts


def collect(path: str, *, min_length: int) -> dict:
    """Run FLOSS over an artifact and assemble the bounded facts payload.

    PE images get the full pass (stack/tight/decoded + static). A non-PE artifact gets a
    DEGRADED static-only pass with an explicit note — FLOSS's emulation legs only support
    PE, so attempting them on an ELF/foreign-arch blob would error; we deliberately don't.
    Raises RuntimeError on an unanalyzable artifact (the caller turns it into error JSON)."""
    try:
        magic = _read_magic(path)
    except OSError as exc:
        raise RuntimeError(f"cannot read artifact: {exc}") from exc

    if _is_pe(magic):
        rc, out, err = _run_floss(path, min_length=min_length, only=None)
        if rc == 0 and out.strip():
            return _assemble(json.loads(out), degraded=False, note=None, min_length=min_length)
        # A PE that FLOSS still couldn't fully analyze (a corrupt/foreign-machine PE):
        # fall back to a static-only pass rather than failing outright.
        _err_lines = (err or "").strip().splitlines()
        _detail = _err_lines[-1][:200] if _err_lines else "unknown error"
        note = f"FLOSS full analysis failed; recovered static strings only ({_detail})"
        rc2, out2, err2 = _run_floss(path, min_length=min_length, only=["static"])
        if rc2 == 0 and out2.strip():
            return _assemble(json.loads(out2), degraded=True, note=note, min_length=min_length)
        raise RuntimeError(f"floss failed: {(err2 or err or 'unknown error').strip()[:300]}")

    # Non-PE (ELF firmware binary, foreign-arch MIPS/ARM, raw blob): FLOSS's stack/decode
    # EMULATION supports PE only, so run a static-only pass and say so. This is the
    # graceful-degradation path the design calls for — a partial result with a clear note.
    note = ("non-PE artifact: FLOSS stack/tight/decoded-string EMULATION supports the PE "
            "format only, so only STATIC strings were recovered here (the obfuscated-string "
            "recovery applies to x86/amd64 PE targets).")
    rc, out, err = _run_floss(path, min_length=min_length, only=["static"])
    if rc == 0 and out.strip():
        return _assemble(json.loads(out), degraded=True, note=note, min_length=min_length)
    raise RuntimeError(f"floss could not analyze this artifact: {(err or 'unknown error').strip()[:300]}")


def _parse_min_length(raw) -> int:
    """Clamp the one agent knob into FLOSS's sane range (never raw argv)."""
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MIN_LEN
    return max(_MIN_LEN_FLOOR, min(_MIN_LEN_CEIL, v))


def main() -> int:
    parser = argparse.ArgumentParser(description="FLOSS string deobfuscation probe")
    parser.add_argument("artifact")
    # The ONLY agent-influenced parameter (design §2.8): a validated minimum string length.
    parser.add_argument("--min-length", default=_DEFAULT_MIN_LEN)
    try:
        args = parser.parse_args()
    except SystemExit:
        print(json.dumps({"error": "usage: floss_probe.py <artifact> [--min-length N]"}))
        return 2

    min_length = _parse_min_length(args.min_length)
    try:
        facts = collect(args.artifact, min_length=min_length)
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except Exception as exc:  # noqa: BLE001 — keep the probe resilient; report the reason
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(facts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

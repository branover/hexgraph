"""The Decompiler seam (SPEC §3).

radare2 (`R2Decompiler`) is the always-available default. Ghidra is an optional
upgrade, selected when enabled in Settings — `GhidraDecompiler` (headless, in the
sandbox image) and `GhidraBridgeDecompiler` (a Ghidra you have open). Task code
asks for `get_decompiler()` and never names a tool, so swapping is transparent.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod

from hexgraph.sandbox.executor import Executor, get_executor

log = logging.getLogger(__name__)


def focus_only_payload(out: dict) -> dict:
    """Trim a decompiler result dict to a FOCUS-ONLY payload for a per-function `decompilation`
    Observation.

    A focused decompile is about THIS one function, but the decompiler dict also carries the
    whole-program `calls` (≤2000) and `structs` (≤200) used by enriched recon — ~33 KB of
    unrelated noise on every `obs_get` of a per-function decompile. The decompilation extractor
    (`_extract_functions`) and `search_decompiled` read only `focus` (whole-program calls/structs
    are enriched from SEPARATE call_graph/structs Observations recorded by enrich_recon), so
    dropping them here loses nothing — the focus's own callees stay inside `focus`. The single
    source of truth so the agent-tool path and the single-pass static_analysis path stay in sync."""
    return {"functions": (out or {}).get("functions", []), "focus": (out or {}).get("focus")}


class Decompiler(ABC):
    name: str

    @abstractmethod
    def decompile(self, artifact: str, function: str | None = None, *,
                  address: str | None = None, reanalyze: bool = False, project=None) -> dict:
        """Return {functions: [...], focus: {name, address, pseudocode, disasm}|null}.

        A focus is given EITHER as a `function` name OR an `address` (hex, e.g. "0x401200");
        an address resolves to the function CONTAINING it (analyze-at-address). `reanalyze`
        raises the analysis depth / busts any cached analysis so a missed function or edge
        gets a second chance.

        `project` (a `Project`, optional) lets a decompiler that supports it cache its analysis
        on that project's data dir (the persistent Ghidra project — analyze once, reuse). It is
        ignored by decompilers without a persistent project (radare2)."""
        ...


def _focus_args(function: str | None, address: str | None, reanalyze: bool) -> list[str] | None:
    """The probe's positional focus (name or address) + the --reanalyze flag. Address
    wins if both are given (callers pass one or the other)."""
    args: list[str] = []
    if address:
        args.append(address)
    elif function:
        args.append(function)
    if reanalyze:
        args.append("--reanalyze")
    return args or None


def _range_args(address: str, length: int | None, count: int | None) -> list[str]:
    """The probe's `--range <addr>` argv for RAW-byte-range disassembly (no function).
    `count` (instructions) wins over `length` (bytes) when both are supplied, mirroring
    the probe; either is omitted entirely when None so the probe applies its default."""
    args = ["--range", address]
    if count is not None:
        args += ["--count", str(int(count))]
    elif length is not None:
        args += ["--length", str(int(length))]
    return args


class R2Decompiler(Decompiler):
    name = "radare2"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None, *,
                  address: str | None = None, reanalyze: bool = False, project=None) -> dict:
        # radare2 has no persistent project; `project` is accepted for seam parity, ignored.
        return self.runner.run_json_probe(
            "decompile_probe.py", artifact,
            extra_args=_focus_args(function, address, reanalyze))

    def disassemble_range(self, artifact: str, address: str, *,
                          length: int | None = None, count: int | None = None) -> dict:
        """Disassemble a RAW byte range at `address` (no function required) — the fallback
        for a CFG blind spot both decompilers miss. Returns the probe's
        {tool, range: {address, length|count, disasm} | {..., error}} payload. Always
        radare2: `pD`/`pd` read+disassemble raw bytes (Ghidra's path returns empty disasm)."""
        return self.runner.run_json_probe(
            "decompile_probe.py", artifact,
            extra_args=_range_args(address, length, count))


class GhidraDecompiler(Decompiler):
    """Headless Ghidra (`analyzeHeadless`) running in the sandbox image. Emits the
    same {functions, focus} contract (plus calls/structs used by enriched recon).

    When a `project` is supplied, the imported+analyzed Ghidra project is PERSISTED on that
    project's data dir and reused across calls (engine.re.ghidra_project) — the first decompile
    of an artifact pays the full analysis cost; later decompiles of OTHER functions reuse it.
    Without a `project` it runs the old throwaway-project path (correct, just slower)."""

    name = "ghidra"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None, *,
                  address: str | None = None, reanalyze: bool = False, project=None) -> dict:
        out = self._decompile_ghidra(artifact, function, address=address,
                                     reanalyze=reanalyze, project=project)
        # Function-inventory mismatch fallback: Ghidra and the r2 probes do NOT share a
        # function inventory, so an EXPLICIT focus (a function name or address) that r2/recon
        # surfaced can be absent from Ghidra's defined set → Ghidra returns focus=null and the
        # focus is silently rejected. radare2 ALWAYS runs in the sandbox image and resolves a
        # bare hex address / `fcn.ADDR` / a containing function, so fall back to it ONCE for the
        # focus while keeping Ghidra's richer whole-program inventory (functions/calls/structs).
        # Only for an explicit focus Ghidra missed — never on a plain list_functions, on an
        # error, or on a focus Ghidra already resolved.
        if (function or address) and isinstance(out, dict) and not out.get("error") \
                and out.get("focus") is None:
            r2 = R2Decompiler(self.runner).decompile(
                artifact, function, address=address, reanalyze=reanalyze, project=project)
            if isinstance(r2, dict) and r2.get("focus"):
                out["focus"] = r2["focus"]
                # F16: the focus pseudocode came from radare2 (r2dec/r2ghidra), NOT Ghidra —
                # Ghidra didn't define this function. TAG it: r2dec is heuristic and can
                # mis-resolve PLT/args or even fabricate a call (a dogfood agent chased a bogus
                # strncpy() lead), so a caller must NOT read fallback output as Ghidra-quality.
                # The whole-program inventory on `out` is still Ghidra's.
                out["focus_engine"] = R2Decompiler.name
                out["focus_fallback"] = True
        # Symmetry: a focus Ghidra DID resolve is tagged too, so provenance is explicit on every
        # focused result (the caller never has to infer the engine from the absence of a flag).
        if out.get("focus") and not out.get("focus_fallback"):
            out["focus_engine"] = self.name
        return out

    def _decompile_ghidra(self, artifact: str, function: str | None = None, *,
                          address: str | None = None, reanalyze: bool = False, project=None) -> dict:
        args = _focus_args(function, address, reanalyze=False)  # the probe focus only; see below
        slot = self._resolve_slot(artifact, project)
        if slot is None:
            # No cache (no project / radare path / resolve failure) → throwaway /scratch project.
            return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)

        # CROSS-PROCESS lock for the WHOLE use of the slot: the web app and an agent's MCP server
        # are separate OS processes sharing this data dir, and a Ghidra project is NOT
        # concurrency-safe — two analyzeHeadless opening one project corrupts it permanently. The
        # lock is lock-and-wait with a timeout; a concurrent same-target decompile blocks until
        # the in-flight one finishes (then proceeds warm). On timeout we DON'T touch the cached
        # slot at all — fall back to a throwaway ephemeral project (correct, just uncached) rather
        # than block forever or risk corruption. DIFFERENT targets → different slots → still
        # concurrent. The lock is host-side; no container flag changes.
        with slot.lock() as locked:
            if not locked:
                return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
            # reanalyze drops the warm slot INSIDE this same lock (force_cold) so the clear +
            # re-import is atomic — otherwise a concurrent same-target decompile could re-warm
            # the slot in the gap and silently no-op the reanalyze.
            return self._run_locked(slot, artifact, args, force_cold=reanalyze)

    def run_taint(self, artifact: str, *, project=None) -> dict:
        """Run the grounded P-Code data-flow taint pass (`--taint`) over the analyzed program,
        reusing the SAME persistent project as `decompile()` (warm ⇒ NO re-analysis — taint after
        a prior decompile is fast). Returns the probe's `{taint: {flows, analyzed}}` payload (plus
        tool/cached). Held under the slot lock like every other use of the project; falls back to a
        throwaway project when there's no cache or the lock times out (correct, just uncached)."""
        args = ["--taint"]
        slot = self._resolve_slot(artifact, project)
        if slot is None:
            return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
        with slot.lock() as locked:
            if not locked:
                return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
            return self._run_locked(slot, artifact, args)

    def run_emulate(self, artifact: str, function: str, *, project=None) -> dict:
        """Emulate `function` in Ghidra's P-Code emulator and recover the constant it returns
        (`--emulate`), reusing the SAME persistent project as `decompile()` (warm ⇒ no
        re-analysis). Returns the probe's `{emulation: {...}}` payload. No native execution of the
        target — the routine runs inside the JVM interpreter. Held under the slot lock; falls back
        to a throwaway project without a cache or on lock timeout (correct, just uncached)."""
        args = ["--emulate", function]
        slot = self._resolve_slot(artifact, project)
        if slot is None:
            return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
        with slot.lock() as locked:
            if not locked:
                return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
            return self._run_locked(slot, artifact, args)

    def rename_function(self, artifact: str, *, address: str, new_name: str, project=None) -> dict:
        """Rename the function at `address` to `new_name` IN the persistent Ghidra project and
        re-decompile it (the rename round-trip, design §7). analyzeHeadless runs without
        -readOnly, so the -process/-import run SAVES the rename back into the project — every
        future decompile sees it (analyze-once). Held under the slot lock for the whole write,
        since a Ghidra project is not concurrency-safe. Returns the re-decompiled focus dict.

        Without a persistent project (no project / resolve failure) this still renames in a
        throwaway project and returns the focus, but the rename does not persist (nothing to
        persist to) — callers gate on Ghidra being the active, project-backed backend."""
        args = ["--rename", address, new_name]
        slot = self._resolve_slot(artifact, project)
        if slot is None:
            return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
        with slot.lock() as locked:
            if not locked:
                # Couldn't take the lock — refuse rather than risk a concurrent corrupt write.
                return {"error": "ghidra project busy (could not lock for rename); try again"}
            return self._run_locked(slot, artifact, args)

    def xrefs(self, artifact: str, *, mode: str, subject: str | None = None, project=None) -> dict:
        """Serve a cross-reference query from the SAME persistent project as `decompile()` — the
        program's already-built reference index (`ReferenceManager`) answers warm, so NO
        re-analysis (an xref on a large target is as fast as a warm decompile, not the cold r2
        whole-binary `aaa` sweep that times out per call). `mode` is one of callers | function |
        data | callgraph | sinks; `subject` is the symbol name / hex address it's about (None for
        callgraph/sinks). The probe emits the SAME JSON shape as the r2 xrefs_probe so the caller
        formats either backend identically; a symbol the index doesn't know returns an empty result
        with `not_found` (NOT `error`) so the caller can fast-fail instead of retrying cold on r2.

        Held under the slot lock like every other use of the project (a Ghidra project is not
        concurrency-safe); falls back to a throwaway project without a persistent cache or on lock
        timeout (correct, just uncached — that path pays a one-time cold import)."""
        args = ["--xrefs", mode] + ([subject] if subject else [])
        slot = self._resolve_slot(artifact, project)
        if slot is None:
            return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
        with slot.lock() as locked:
            if not locked:
                return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)
            return self._run_locked(slot, artifact, args)

    def _run_locked(self, slot, artifact: str, args, *, force_cold: bool = False):
        """Run the probe with the slot held exclusively. Decides cold vs warm on the AUTHORITATIVE
        committed marker (`slot.exists()`); cleans a partially-written slot before a cold run; and
        passes the warm/cold verdict to the probe explicitly (the probe re-affirms via the same
        marker). The probe COMMITS the marker as the last step of a successful cold import, so the
        host no longer races a separate write_meta.

        `force_cold` (reanalyze) drops any committed warm project so the run re-imports cold —
        a persisted Ghidra project is not re-analyzed in place. Done here, under the run's own
        lock, so no concurrent decompile can re-warm the slot between the clear and the run."""
        if force_cold and slot.exists():
            log.info(
                "ghidra project cache: reanalyze — clearing slot %s to re-import cold",
                slot.root.name)
            try:
                slot.clear_project()
            except Exception:  # noqa: BLE001 — never break a decompile over a cache clear
                pass
        warm = slot.exists()
        if not warm and slot.project_dir.is_dir() and any(slot.project_dir.iterdir()):
            # Non-empty project dir with NO committed marker ⇒ a prior cold run died mid-import.
            # Don't open it warm (a never-fully-imported program → permanent -process failure);
            # wipe it and re-import cold.
            log.info(
                "ghidra project cache: clearing a half-written slot %s and re-importing cold",
                slot.root.name)
            slot.clear_project()
        out = self.runner.run_json_probe(
            "ghidra_probe.py", artifact, extra_args=args, project_mount=str(slot.root))
        # The probe committed meta.json on a successful cold import; on the warm path it's already
        # there. Either way, mark the slot most-recently-used so LRU eviction spares it.
        try:
            slot.touch()
        except Exception:  # noqa: BLE001 — bookkeeping must not fail a good decompile
            pass
        return out

    def _resolve_slot(self, artifact: str, project):
        """Resolve, prepare, and make room for the persistent-project slot for this artifact —
        or None if caching isn't possible (no project / no data dir / any error). Best-effort:
        a failure falls back to the throwaway path rather than breaking decompilation."""
        if project is None or not getattr(project, "data_dir", None):
            return None
        try:
            from hexgraph.engine.re import ghidra_project as gp
            from hexgraph.sandbox.runner import sandbox_image

            sha = gp.content_hash(artifact)
            version = gp.ghidra_version_for_image(sandbox_image(), runner=self.runner)
            slot = gp.resolve(project.data_dir, sha, version)
            slot.prepare()
            # Evict BEFORE the run so a cold analysis lands within the cap; never evict the
            # slot we're about to (re)use.
            gp.evict_to_cap(project.data_dir, gp.project_cache_mb(), keep=slot.root.name)
            return slot
        except Exception:  # noqa: BLE001 — caching is an optimization, never load-bearing
            return None


def _resolve_name(explicit: str | None) -> str:
    """Pick the decompiler: explicit arg → env override → Settings → radare2.
    Never raises on config — an unavailable Ghidra is handled by the caller's
    best-effort fallback, so analysis always proceeds."""
    if explicit:
        return explicit.lower()
    env = os.environ.get("HEXGRAPH_DECOMPILER")
    if env:
        return env.lower()
    try:
        from hexgraph.engine.re.ghidra import ghidra_config

        g = ghidra_config()
        if g.get("enabled"):
            return "ghidra_bridge" if g.get("mode") == "bridge" else "ghidra"
    except Exception:  # noqa: BLE001 — config problems must not break decompilation
        pass
    return "radare2"


def get_decompiler(name: str | None = None) -> Decompiler:
    resolved = _resolve_name(name)
    if resolved in ("radare2", "r2"):
        return R2Decompiler()
    if resolved == "ghidra":
        return GhidraDecompiler()
    if resolved in ("ghidra_bridge", "bridge"):
        from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler

        return GhidraBridgeDecompiler()
    raise ValueError(f"unknown decompiler {resolved!r}")

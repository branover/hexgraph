#!/usr/bin/env python3
"""Symbolic execution over a target with angr, run INSIDE the dedicated angr sandbox image.

This is the flagship Phase-5C probe behind the `get_solver()` seam. It NEVER executes the
target — angr loads the artifact's bytes, symbolically explores its real code, and asks z3
for a model — so it stays on the same static surface as every other probe (`--network none`,
read-only `/artifact`, dropped caps, non-root, resource-capped, a hard timeout). Two modes,
mirroring the Solver ABC:

  * reaching-input — given a SINK (a function/address execution should reach, e.g. `system`),
    solve for the concrete INPUT BYTES that drive execution to it. The strongest static claim
    HexGraph can make short of a live PoC: a concrete reaching input.
  * constraint    — given a CHECK (a function and, optionally, the address that represents the
    check PASSING), recover a value/input that SATISFIES it (the angr analogue of P-Code
    emulation's constant recovery).

**Bounded hard** (symbolic execution is the one tool here that can genuinely explode):
  * a wall-clock deadline (`--timeout`, an INNER guard below the container's own timeout, so
    we emit a clean "unsolved" result instead of being SIGKILLed),
  * a step cap (`--max-steps`) and an active-state cap (`--max-active`),
  * DFS exploration so memory stays bounded (one active state at a time) AND the search order
    is DETERMINISTIC — the same artifact + selector solves to the same answer every run.
On no solution / timeout / step or state cap we return a clean `{"solved": false, ...}` JSON
(never a crash). The model never supplies an angr script — only the validated sink/check
selector HexGraph maps into the fixed exploration below (design §2.8).

Emits a single JSON object on stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

# angr is chatty (and its sub-loggers log warnings about missing libs / unsupported syscalls
# that are normal for our bounded solve). Quiet them so they never corrupt the JSON on stdout.
logging.disable(logging.WARNING)
for _n in ("angr", "cle", "pyvex", "claripy", "archinfo", "ailment", "angr.storage",
           "angr.state_plugins.unicorn_engine", "angr.engines"):
    logging.getLogger(_n).setLevel(logging.CRITICAL)

# Defaults for the bounding knobs (HexGraph-set; the agent only ever picks a coarse budget
# tier that maps onto these, never a raw value — design §2.8).
_DEFAULT_TIMEOUT = 120        # inner wall-clock seconds (the container caps harder on top)
_DEFAULT_MAX_STEPS = 4000     # symbolic steps before we give up (a runaway guard)
_DEFAULT_MAX_ACTIVE = 64      # deferred-state ceiling (memory guard; DFS keeps 1 active)
_DEFAULT_MAX_INPUT = 64       # symbolic input length in bytes (argv/stdin)
_MIN_INPUT = 1
_MAX_INPUT_CEIL = 4096        # an obvious upper guard on an agent-supplied length
_LOOP_BOUND = 50              # max iterations of any single loop (LoopSeer) — a runaway guard
_PATH_ADDR_CAP = 64           # how many grounded basic-block addresses we report on the path


def _hx(n: int) -> str:
    return hex(int(n))


def _parse_addr(raw) -> int | None:
    """Parse a hex/dec address string into an int, or None."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except ValueError:
        return None


def _safe_repr(data: bytes) -> str:
    """A human-readable, bounded repr of the recovered bytes (printables shown, the rest as
    \\xNN). The bytes are often non-ASCII — that is exactly why a solver was needed — so the
    authoritative form is the hex in `concrete_input`; this is just a readability aid."""
    out = []
    for b in data[:256]:
        if 0x20 <= b < 0x7f and b not in (0x5c,):  # printable, excluding backslash
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _sink_addrs(proj, *, func: str | None, explicit_addr: int | None) -> list[int]:
    """Resolve the address(es) execution must reach to be 'at the sink'. Tries, in order:
    an explicit address; the PLT stub for `func` (the call site of a dynamically-linked
    libc sink like system — reaching it means we are about to call it); the function's own
    address in the knowledge base / a resolved symbol. Returns a deduped list (explore finds
    on ANY of them)."""
    addrs: list[int] = []
    if explicit_addr is not None:
        addrs.append(explicit_addr)
    if func:
        # The PLT stub: for a dynamically-linked libc sink, the `call func@plt` target. When
        # PC reaches it we are about to enter the sink — the cleanest 'reached the sink' marker.
        try:
            plt = getattr(proj.loader.main_object, "plt", {}) or {}
            if func in plt:
                addrs.append(int(plt[func]))
        except Exception:  # noqa: BLE001 — loader differences must not crash resolution
            pass
        # A resolved symbol (static binary, or the extern/SimProcedure address angr hooks).
        try:
            sym = proj.loader.find_symbol(func)
            if sym is not None and sym.rebased_addr:
                addrs.append(int(sym.rebased_addr))
        except Exception:  # noqa: BLE001
            pass
    # Dedup, preserve order.
    seen: set[int] = set()
    out: list[int] = []
    for a in addrs:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def _make_input(claripy, proj, *, model: str, length: int, binpath: str):
    """Build the symbolic input + an initial state for it. Returns (state, sym_input).

    `model="argv"`: the input is argv[1] (the classic CLI license/serial gate). `model="stdin"`:
    the input arrives on stdin. The state is the program ENTRY state (not full libc init) so the
    bounded solve stays fast and deterministic; angr's libc SimProcedures (strlen/strcmp/…) make
    the gate logic tractable without auto-loading real libc."""
    import angr  # local import: this file only ever runs inside the angr image

    sym = claripy.BVS("hexgraph_input", 8 * length)
    # Zero-fill unconstrained memory/registers so the solve is deterministic and doesn't fork on
    # uninitialized reads (the standard CTF-solve hygiene). `entry_state` (not full_init_state):
    # it builds the initial argv/envp stack the kernel hands the program but skips the dynamic-
    # loader init, so we reach main fast and with far fewer steps — and angr's libc SimProcedures
    # (strlen/strcmp/…) still make the gate logic tractable with auto_load_libs off.
    opts = {
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }
    if model == "stdin":
        state = proj.factory.entry_state(args=[binpath], add_options=opts, stdin=sym)
    else:  # argv (default)
        state = proj.factory.entry_state(args=[binpath, sym], add_options=opts)
    return state, sym


def _bounded_explore(simgr, find_addrs, *, timeout: int, max_steps: int, max_active: int):
    """Run a DETERMINISTIC, hard-bounded DFS exploration toward `find_addrs`. Returns a dict
    of telemetry {steps, active_peak, elapsed, reason}. `reason` is one of solved / no-solution
    / timeout / step-cap / state-cap. DFS keeps a single active state (bounded memory + a stable
    search order); the deferred stash is capped so a fan-out can't blow memory either."""
    start = time.monotonic()
    tele = {"steps": 0, "active_peak": 0, "deferred_peak": 0, "reason": "no-solution"}

    finds = set(find_addrs)

    def _found(state) -> bool:
        return state.addr in finds

    def _found_states() -> list:
        # Read the `found` stash via .stashes — `simgr.found` raises AttributeError until the
        # stash has been created (the first move populates it).
        return simgr.stashes.get("found") or []

    # A state could already be sitting at a find address (entry == sink is unlikely, but be safe).
    simgr.move(from_stash="active", to_stash="found", filter_func=_found)

    while (simgr.active or simgr.stashes.get("deferred")) and not _found_states():
        if time.monotonic() - start > timeout:
            tele["reason"] = "timeout"
            break
        if tele["steps"] >= max_steps:
            tele["reason"] = "step-cap"
            break
        # Memory guard: DFS keeps ≤1 active state, the rest wait in `deferred`. If the deferred
        # frontier itself blows past the cap, stop rather than risk OOM (a clean unsolved).
        deferred = simgr.stashes.get("deferred") or []
        tele["deferred_peak"] = max(tele["deferred_peak"], len(deferred))
        if len(deferred) > max_active:
            tele["reason"] = "state-cap"
            break
        simgr.step()  # DFS repopulates `active` from `deferred` when the one active state ends
        tele["steps"] += 1
        tele["active_peak"] = max(tele["active_peak"], len(simgr.active))
        # Move any active state that reached a find target into `found` (DFS doesn't auto-check).
        simgr.move(from_stash="active", to_stash="found", filter_func=_found)

    if _found_states():
        tele["reason"] = "solved"
    tele["elapsed"] = round(time.monotonic() - start, 2)
    return tele


def _path_addrs(state) -> list[str]:
    """The few grounded basic-block addresses on the satisfying path (for promoting the
    grounded nodes/edges, never the whole program). Bounded to the head + tail of the trace."""
    try:
        bbl = [int(a) for a in state.history.bbl_addrs.hardcopy]
    except Exception:  # noqa: BLE001
        return []
    if len(bbl) <= _PATH_ADDR_CAP:
        chosen = bbl
    else:
        half = _PATH_ADDR_CAP // 2
        chosen = bbl[:half] + bbl[-half:]
    return [_hx(a) for a in chosen]


def _solve(args) -> dict:
    """Run the requested solve and return the result dict (pure-ish; never raises)."""
    try:
        import angr  # noqa: F401
        import claripy
    except Exception as exc:  # noqa: BLE001 — only happens off the angr image
        return {"solved": False, "reason": "error",
                "error": f"angr is not available in this image: {exc}"}

    binpath = args.artifact
    if not os.path.isfile(binpath):
        return {"solved": False, "reason": "error", "error": f"artifact not found: {binpath}"}

    length = max(_MIN_INPUT, min(_MAX_INPUT_CEIL, int(args.max_input_len)))
    model = args.input_model if args.input_model in ("argv", "stdin") else "argv"

    try:
        proj = angr.Project(binpath, auto_load_libs=False,
                            load_options={"auto_load_libs": False})
    except Exception as exc:  # noqa: BLE001 — an unanalyzable/unsupported artifact
        return {"solved": False, "reason": "error",
                "error": f"angr could not load the artifact: {type(exc).__name__}: {exc}"}

    base = {
        "tool": "angr_probe",
        "mode": args.mode,
        "angr_version": getattr(angr, "__version__", None),
        "input_model": model,
        "input_len": length,
        "arch": str(getattr(proj.arch, "name", None)),
    }

    explicit = _parse_addr(args.sink_addr) if args.mode == "reaching-input" else _parse_addr(args.check_addr)
    sink_func = args.sink_func if args.mode == "reaching-input" else None
    find_addrs = _sink_addrs(proj, func=sink_func, explicit_addr=explicit)
    # In constraint mode, an explicit --check-addr is required to know where the check passes;
    # if absent, fall back to a sink-func selector the same way reaching-input does (so a check
    # gated behind a sink still works), else there's nothing to aim at.
    if args.mode == "constraint" and not find_addrs and args.sink_func:
        find_addrs = _sink_addrs(proj, func=args.sink_func, explicit_addr=None)
    if not find_addrs:
        return {**base, "solved": False, "reason": "no-target",
                "error": "could not resolve a target address to explore toward "
                         f"(sink_func={args.sink_func!r}, sink_addr={args.sink_addr!r}, "
                         f"check_addr={args.check_addr!r}); pass a concrete address or a "
                         "resolvable sink function name"}
    base["targets"] = [_hx(a) for a in find_addrs]

    try:
        state, sym = _make_input(claripy, proj, model=model, length=length, binpath=binpath)
        simgr = proj.factory.simulation_manager(state)
        # DFS = deterministic order + bounded memory (one active state); LoopSeer caps any single
        # loop's iterations so a runaway loop trips the bound rather than spinning forever.
        simgr.use_technique(angr.exploration_techniques.DFS())
        try:
            simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=_LOOP_BOUND))
        except Exception:  # noqa: BLE001 — LoopSeer needs a CFG; optional, never fatal
            pass
        tele = _bounded_explore(
            simgr, find_addrs,
            timeout=int(args.timeout), max_steps=int(args.max_steps),
            max_active=int(args.max_active),
        )
    except Exception as exc:  # noqa: BLE001 — any angr/z3 failure → a clean unsolved
        return {**base, "solved": False, "reason": "error",
                "error": f"symbolic exploration failed: {type(exc).__name__}: {exc}"}

    result = {**base, **{k: tele[k] for k in ("steps", "active_peak", "deferred_peak",
                                              "elapsed", "reason")}}

    found_states = simgr.stashes.get("found") or []
    if not found_states:
        result["solved"] = False
        return result

    found = found_states[0]
    try:
        data = found.solver.eval(sym, cast_to=bytes)
    except Exception as exc:  # noqa: BLE001 — model extraction failed
        return {**result, "solved": False, "reason": "no-model",
                "error": f"reached the target but could not extract a concrete model: {exc}"}

    result["solved"] = True
    result["concrete_input"] = data.hex()
    result["concrete_input_repr"] = _safe_repr(data)
    result["path_addrs"] = _path_addrs(found)
    result["reached_addr"] = _hx(found.addr)

    if args.mode == "constraint":
        # The angr analogue of emulation's constant recovery: surface a best-effort scalar
        # reading of the recovered input (the first 1/2/4/8 little-endian bytes), so it can feed
        # the same function-node annotation path. The full byte sequence stays authoritative.
        result["function"] = args.function
        n = len(data)
        width = next((w for w in (8, 4, 2, 1) if n >= w), None)
        if width is not None:
            val = int.from_bytes(data[:width], "little")
            result["recovered_value"] = val
            result["recovered_value_hex"] = hex(val)
            result["recovered_value_width"] = width
        result["recovered_input"] = data.hex()
    return result


def main() -> int:
    p = argparse.ArgumentParser(description="angr symbolic-execution solver probe")
    p.add_argument("artifact")
    p.add_argument("--mode", choices=["reaching-input", "constraint"], default="reaching-input")
    p.add_argument("--sink-func", default=None)
    p.add_argument("--sink-addr", default=None)
    p.add_argument("--function", default=None)
    p.add_argument("--function-addr", default=None)
    p.add_argument("--check-addr", default=None)
    p.add_argument("--arg-index", default=None)
    p.add_argument("--input-model", default="argv", choices=["argv", "stdin"])
    p.add_argument("--max-input-len", default=_DEFAULT_MAX_INPUT)
    p.add_argument("--timeout", default=_DEFAULT_TIMEOUT)
    p.add_argument("--max-steps", default=_DEFAULT_MAX_STEPS)
    p.add_argument("--max-active", default=_DEFAULT_MAX_ACTIVE)
    try:
        args = p.parse_args()
    except SystemExit:
        print(json.dumps({"solved": False, "reason": "error",
                          "error": "usage: angr_probe.py <artifact> --mode reaching-input|constraint [...]"}))
        return 2

    try:
        out = _solve(args)
    except Exception as exc:  # noqa: BLE001 — keep the probe resilient; report the reason
        out = {"tool": "angr_probe", "solved": False, "reason": "error",
               "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))
    # Always exit 0: an unsolved/timeout is a VALID result the engine reads from stdout, not a
    # probe failure. The runner reserves non-zero for a real crash.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

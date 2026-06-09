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
  * a PER-QUERY z3 timeout so a single hard SMT query can't hang past that deadline (the
    wall-clock guard is only checked BETWEEN steps, so on its own a runaway query could overrun
    both it and the container cap → SIGKILL; the per-query cap degrades it to a clean unsolved),
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
_PER_QUERY_TIMEOUT = 30       # max wall-clock seconds for ANY SINGLE z3 query (per-query cap)
# A byte "matters" iff, with every OTHER input byte pinned to the solved model, it still has at
# most this many distinct feasible values (i.e. it is genuinely RESTRICTED by the gate). The
# separation is wide and clean: on the licensegate calibration the 8 semantic serial bytes have
# exactly 1 feasible value each (fully forced), while every filler byte has 256 (entirely free) —
# this threshold sits in the empty gap between those clusters, so it also catches a legitimately
# small-but-not-singleton byte (a fixed nibble = 16 values, a 2-of-256 choice, …) while excluding
# an incidental `byte != 0` (255 values) or a fully-free byte (256). See _constrained_byte_len.
_BYTE_SIGNIFICANT_MAX_VALUES = 16


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


def _set_query_timeout(state, *, seconds: int) -> None:
    """Bound a SINGLE z3 query to `seconds` (claripy/z3 `timeout`, set in ms). The wall-clock
    deadline in `_bounded_explore` is COOPERATIVE — it is only checked between `step()`s — so on
    its own a single pathological SMT query could overrun it AND the container cap (→ SIGKILL).
    Capping each query makes z3 return "unknown" (a clean unsolved) instead of hanging. Best
    effort: a claripy/angr build without the attribute simply falls back to the cooperative
    guard alone (still correct, just less graceful)."""
    ms = max(1, int(seconds)) * 1000
    try:
        state.solver._solver.timeout = ms
    except Exception:  # noqa: BLE001 — a missing/renamed attribute must never break the solve
        pass


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
        # argv[1] is a C string: an interior NUL would TRUNCATE it, so a solved byte sequence
        # containing one wouldn't survive as a real argv[1] — the reported reproducer would
        # mislead. Constrain every symbolic byte to be non-NUL so the recovered input is faithful
        # (and the solve stays deterministic — strlen no longer forks on where a NUL lands). NUL
        # bytes are legitimate on stdin, so this constraint is argv-mode only.
        # (argv caveat) We deliberately do NOT force every symbolic byte non-NUL. A blanket
        # non-NUL constraint breaks legitimate solves for programs that rely on a NUL TERMINATOR
        # inside the buffer (e.g. a fixed-length strlen(argv[1])==N check) — it forbids the very
        # terminator the program needs. _solve truncates the reported argv reproducer at the
        # first NUL instead (that IS the real argv[1]), so it stays honest without over-
        # constraining the solve. (NUL is always legitimate on stdin.)
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


def _constrained_byte_len(state, sym, *, length: int) -> int | None:
    """How many LEADING bytes of the symbolic input the satisfying path actually constrains. The
    full `concrete_input` is the whole `length`-byte buffer (e.g. 8 real serial bytes + filler z3
    happened to assign), which OVER-STATES the reproducer — a human can't tell which bytes matter.
    We derive the honest count here, SEMANTICALLY, from the satisfying state's solver.

    Method (semantic, not syntactic). A byte "matters" iff it is genuinely RESTRICTED, not iff it
    merely appears in some accumulated path constraint — angr's incidental constraints (strlen /
    length checks, argv buffer + NUL-terminator modeling, libc internals) reference input bytes far
    past the semantic serial without forcing them, so "appears in a constraint" badly over-counts
    (the earlier syntactic max-Extract-bit heuristic returned 52 on licensegate, not 8). Instead,
    per byte `i`, we PIN every OTHER byte to its solved value and ask the solver how free byte `i`
    still is — `eval_upto(byte_i, K+1, extra_constraints=[others == solved])` counts its feasible
    values up to K+1. Byte `i` is SIGNIFICANT iff it has at most ``_BYTE_SIGNIFICANT_MAX_VALUES``
    feasible values (genuinely forced/near-forced); an incidental `byte != 0` (≈255 values) or a
    free byte (256) is not. `constrained_len` = highest significant index + 1.

    Bounded cost: at most `length` solver queries (length is the budget-capped input size), each a
    cheap eval over simple equality assumptions. Defensive throughout: ANY introspection / eval
    failure degrades to None (the caller keeps the full buffer as the only reproducer) — never a
    crash, and never a misleadingly-small claim. Returns 0 when no byte is significant.

    LIMITATION (always UNDER-counts, never over-counts): a byte under a loose constraint (more than
    _BYTE_SIGNIFICANT_MAX_VALUES feasible values, e.g. a range check) or a cross-byte disjunction
    (e.g. `b0==1 OR b1==1`, where pinning one operand can mask the other's role) reads as filler.
    That is safe by design — the full `concrete_input` is always retained as the authoritative
    reproducer, so a short constrained_len never loses data; it only reports a possibly-shorter
    \"bytes that clearly matter\" prefix."""
    try:
        solver = state.solver
        get_byte = sym.get_byte            # per-byte BV view; byte 0 == the first program-read byte
        eval_upto = solver.eval_upto       # SimSolver: model enumeration (raises if not present)
    except Exception:  # noqa: BLE001 — a build that doesn't expose the API we rely on → caller keeps full buffer
        return None

    # The solved value of every input byte: we pin all-but-one to these and probe the remaining one.
    try:
        solved = [int(solver.eval(get_byte(i))) for i in range(length)]
    except Exception:  # noqa: BLE001 — model extraction failed; don't guess
        return None

    last_significant = -1
    for i in range(length):
        # Pin every OTHER byte to its solved value, then count how many values byte i can still
        # take. Few feasible values ⇒ the gate genuinely restricts this byte ⇒ it matters.
        extra = [get_byte(j) == solved[j] for j in range(length) if j != i]
        try:
            feasible = eval_upto(get_byte(i), _BYTE_SIGNIFICANT_MAX_VALUES + 1,
                                 extra_constraints=extra)
        except Exception:  # noqa: BLE001 — a single byte's query failed (e.g. per-query z3 timeout)
            # Don't fabricate a smaller claim from a partial scan, and don't crash: bail to None so
            # the caller keeps the full buffer rather than an under-reported prefix.
            return None
        if len(feasible) <= _BYTE_SIGNIFICANT_MAX_VALUES:
            last_significant = i

    return last_significant + 1  # 0 when no byte is significant


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
    # Echo the enclosing-function address back so the engine can carry it onto the promoted
    # function node's provenance (the node's `address` is otherwise lost). A free locator the
    # caller already resolved — we report it, we don't re-derive it.
    if args.function_addr:
        base["function_addr"] = args.function_addr

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

    # Cap any single z3 query at the per-query ceiling, never above the run's own deadline, so a
    # late query still returns well inside the container cap (see _set_query_timeout).
    query_timeout = min(int(args.timeout), _PER_QUERY_TIMEOUT)
    try:
        state, sym = _make_input(claripy, proj, model=model, length=length, binpath=binpath)
        _set_query_timeout(state, seconds=query_timeout)
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
    # Re-apply the per-query cap on the satisfying state: a forked child may not inherit the
    # parent's solver timeout, and this final model-extraction `eval` is the query most likely to
    # be expensive — it must not hang past the deadline either.
    _set_query_timeout(found, seconds=query_timeout)
    try:
        data = found.solver.eval(sym, cast_to=bytes)
    except Exception as exc:  # noqa: BLE001 — model extraction failed
        return {**result, "solved": False, "reason": "no-model",
                "error": f"reached the target but could not extract a concrete model: {exc}"}

    # argv reproducer faithfulness (reaching-input): argv[1] is a C string, so the real input is
    # the bytes up to the FIRST NUL — report THAT (the full solved buffer's trailing/interior NULs
    # cannot be passed as argv[1] and would mislead). The serial the check reads lives in the
    # leading non-NUL bytes, so it is preserved. Constraint mode keeps the full bytes (a recovered
    # VALUE may legitimately contain NUL); stdin keeps the full bytes too.
    if args.mode == "reaching-input" and model == "argv":
        data = data.split(bytes([0]), 1)[0]
    result["solved"] = True
    result["concrete_input"] = data.hex()
    result["concrete_input_repr"] = _safe_repr(data)
    result["path_addrs"] = _path_addrs(found)
    result["reached_addr"] = _hx(found.addr)

    # Which bytes actually MATTER: `concrete_input` is the whole symbolic buffer (the few real
    # bytes the gate checks + unconstrained filler), so it over-states the reproducer. Derive how
    # many LEADING bytes the satisfying path constrains and surface that prefix as `minimal_input`
    # — "the part that matters" — so a human copies the real serial, not the padding. Additive:
    # `concrete_input` stays the full buffer for back-compat. Best-effort: on any introspection
    # failure `_constrained_byte_len` returns None and we omit both fields rather than mislead.
    clen = _constrained_byte_len(found, sym, length=length)
    if clen is not None:
        # `_constrained_byte_len` measures the FULL symbolic buffer, BEFORE the argv NUL-truncation
        # above — so its raw value is the faithful "does the path depend on the input" signal even
        # when the reportable reproducer is shorter. Record that signal explicitly so the engine's
        # integrity gate (`SolverResult.is_input_constrained`) can't be fooled by a NUL-prefix corner.
        result["input_constrained"] = clen > 0
        # Never report more constrained_len bytes than the reproducer actually has (argv `data` was
        # NUL-truncated above; the constrained PREFIX can't extend past the real reproducer bytes).
        # NUL-prefix-argv corner: a path that genuinely constrains argv[1] to BEGIN with a NUL
        # truncates `data` to empty, so this clamps constrained_len to 0 even though the path IS
        # input-dependent — hence the explicit `input_constrained` flag above, which is NOT clamped.
        clen = min(clen, len(data))
        result["constrained_len"] = clen
        result["minimal_input"] = data[:clen].hex()

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

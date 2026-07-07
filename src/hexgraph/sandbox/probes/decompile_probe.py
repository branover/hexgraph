#!/usr/bin/env python3
"""Decompile a target INSIDE the sandbox using radare2 (r2pipe).

argv[1] = /artifact (read-only); the remaining args are an optional focus
(a function NAME or a hex ADDRESS like 0x401200) plus an optional --reanalyze
flag. A focus given as an address resolves to the function CONTAINING it
(analyze-at-address), so a bare address from xrefs/strings is decompilable
without first knowing the function name.

Emits JSON: { functions: [...], focus: {name, address, pseudocode, disasm,
callees} | null }.

A separate RANGE mode (`--range <addr> [--length N] [--count N]`) disassembles
a RAW byte range starting at `addr` with NO function required — the fallback for
a CFG blind spot where neither r2 nor Ghidra defined a function, so the focus
paths above return "not found". It runs `pD <length> @ <addr>` (disassemble N
bytes) or `pd <count> @ <addr>` (N instructions) and emits
{ range: {address, length|count, disasm} | {error} }.

radare2 is the v1 decompiler (the Decompiler seam lets Ghidra drop in later).
We use built-in `pdc` (pseudo-C) with a `pdf` (disassembly) fallback — no
r2ghidra plugin required. No network; the target is analyzed, never executed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time

# Persistent radare2 project (analyze-once / reuse). When a writable slot is bind-mounted at
# PROJECT_MOUNT (engine.re.r2_project → runner.CONTAINER_PROJECT_DIR), the whole-binary decompile
# path saves the analyzed program as a NAMED project under `dir.projects` and reloads it with NO
# `aaa` on later calls, exactly like the Ghidra probe. Absent the mount, it runs the old throwaway
# `aaa`-per-call path. (The mount point name is Ghidra-flavored; it's just a generic writable dir.)
PROJECT_MOUNT = "/ghidra-project"
# radare2's `dir.projects` points here (under the mount); the named project lands at <this>/hexgraph.
PROJECT_SUBDIR = "project"
# The bare project NAME saved with `Ps` / reloaded with `-p`. MUST be a name, never a path — an
# absolute-path project (`Ps /abs`) SEGFAULTS r2 on reload (verified across r2 versions).
PROJECT_NAME = "hexgraph"
# The COMMITTED warm marker (engine.re.r2_project.META_NAME) under PROJECT_MOUNT, written as the
# LAST step of a successful cold save — its presence (NOT raw dir non-emptiness) is the
# authoritative "valid warm project" signal, so a crashed/timed-out cold save re-analyzes cold.
META_NAME = "meta.json"

# Returned when a plain focus/list decompile hits a COLD slot: the whole-binary decompile path is
# warm-only (THE analysis invariant) — it must NEVER run a cold `aaa` itself (that per-call cold sweep
# on a large target is the ~2547s timeout). Only the two EXPLICIT analysis entry points cold-analyze:
# `--analyze` (re_analyze, detached, generous budget) and `--reanalyze` (re_reanalyze, the deliberate
# deeper re-analysis). Everything else points here on a cold miss. (Targeted --disasm/--range need no
# analysis and are unaffected.)
_RE_ANALYZE_LEAD = (
    "No warm radare2 analysis for this target yet. Run re_analyze(target) FIRST — it builds the warm "
    "project ONCE with a generous budget (detached; poll until state='analyzed'), then re-run this — "
    "it's warm-only and never runs a cold analysis itself (re_analyze is the only place a full "
    "analysis pass happens).")


def _valid_marker(path: str) -> bool:
    """True iff `path` is a committed, parseable warm marker. Anything else (absent, empty,
    truncated/corrupt JSON from a crash) ⇒ treat the slot as cold. Mirrors ghidra_probe."""
    try:
        with open(path) as fh:
            json.load(fh)
        return True
    except (OSError, ValueError):
        return False


def _clear_partial(proj_dir: str, marker: str) -> None:
    """Wipe a partially-written slot before a cold re-analysis: drop the stale marker and the
    incomplete project dir, then recreate an empty project dir. Best-effort."""
    try:
        os.remove(marker)
    except OSError:
        pass
    try:
        if os.path.isdir(proj_dir):
            shutil.rmtree(proj_dir)
    except OSError:
        pass
    os.makedirs(proj_dir, exist_ok=True)


def _commit_marker(marker: str) -> None:
    """COMMIT the warm marker — the LAST step of a successful cold save, written atomically
    (tmp + os.replace) so a crash never leaves a half-written marker that reads as warm. Mirrors
    engine.re.r2_project.R2Project.write_meta; its presence makes the slot warm next call."""
    payload = json.dumps({"program_name": PROJECT_NAME, "created_at": time.time()})
    tmp = marker + ".tmp"
    try:
        with open(tmp, "w") as fh:
            fh.write(payload)
        os.replace(tmp, marker)
    except OSError:
        pass  # best-effort; without a marker the next call simply re-analyzes cold (correct)


def _project_flags() -> tuple[bool, str, str, list[str]]:
    """Decide the persistent-project state for a whole-binary decompile. Returns
    (use_project, proj_dir, marker, extra_open_flags): `use_project` is True only when the writable
    mount is present; `extra_open_flags` sets `dir.projects` (always) plus `-p <name>` when a valid
    warm project exists, so the r2 open reloads the analysis instead of re-running `aaa`. On a cold
    or half-written slot it wipes any partial state so the save starts clean."""
    if not os.path.isdir(PROJECT_MOUNT):
        return False, "", "", []
    proj_dir = os.path.join(PROJECT_MOUNT, PROJECT_SUBDIR)
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    named = os.path.join(proj_dir, PROJECT_NAME)
    warm = bool(_valid_marker(marker) and os.path.isdir(named) and os.listdir(named))
    if not warm:
        _clear_partial(proj_dir, marker)  # fresh OR half-written → start the cold save clean
    os.makedirs(proj_dir, exist_ok=True)
    flags = ["-e", f"dir.projects={proj_dir}"]
    if warm:
        flags += ["-p", PROJECT_NAME]
    return True, proj_dir, marker, flags


def _set_git_env() -> None:
    """Set a deterministic git identity BEFORE r2 opens/saves a project (r2 spawns any git child
    with the env it was launched with). r2 6.1.4 projects are plain dirs (no git), so this is
    normally an unused no-op — but a version whose projects are git-backed would otherwise stall on
    a missing identity. `setdefault` never clobbers a real identity."""
    for k, v in (("GIT_AUTHOR_NAME", "hexgraph"), ("GIT_AUTHOR_EMAIL", "hexgraph@localhost"),
                 ("GIT_COMMITTER_NAME", "hexgraph"), ("GIT_COMMITTER_EMAIL", "hexgraph@localhost")):
        os.environ.setdefault(k, v)


def _emit_r2_version() -> int:
    """Print `{r2_version}` — the toolchain half of the project cache key (engine.re.r2_project.
    r2_version_for_image runs this with NO target). Reads `radare2 -v`'s first line
    ('radare2 6.1.4 …' → '6.1.4'); r2_version stays null if radare2 can't be run."""
    import subprocess

    ver = None
    for exe in ("radare2", "r2"):
        try:
            out = subprocess.run([exe, "-v"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        lines = (out.stdout or "").strip().splitlines()
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                ver = parts[1]
        break
    print(json.dumps({"tool": "decompile_probe", "r2_version": ver}))
    return 0


# `call <target>` in r2 disassembly. Capture the callee symbol/function name,
# skipping register-indirect calls (call rax / call qword [..]).
_CALL_RE = re.compile(r"\bcall\b\s+(?:dword |qword |word |byte )?(?:sym\.imp\.|sym\.|fcn\.|loc\.)?([A-Za-z_][\w]*)")
_REGISTERS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
}


def _callees(disasm: str) -> list[str]:
    out: list[str] = []
    for m in _CALL_RE.finditer(disasm or ""):
        name = m.group(1)
        if name in _REGISTERS or name in out:
            continue
        out.append(name)
    return out


# A function/symbol name is interpolated into an r2 command (`pdc @ <name>`), where
# `;` chains commands and `!`/backticks reach the shell. Only allow characters that
# occur in real symbol names, so an unresolved name can never inject a command.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@$:]+$")

# A focus given as a hex address (e.g. from xrefs/strings). Validated separately and
# strictly so it, too, can never inject a command when interpolated into an r2 seek.
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")

# Range-mode defaults + ceilings. The probe disassembles at most this many bytes /
# instructions in one call so a pathological request can't run unbounded; the host clips
# the returned text separately (the no-silent-caps marker). Generous enough to read a whole
# blind-spot region in one pass.
_RANGE_DEFAULT_LENGTH = 256
_RANGE_MAX_LENGTH = 8192
_RANGE_MAX_COUNT = 1024


def _name_candidates(fn: str) -> list[str]:
    fn = fn.lstrip(".")
    return [f"sym.{fn}", f"sym.imp.{fn}", f"fcn.{fn}", fn]


def _containing_function(addr: int, funcs: list[dict]) -> dict | None:
    """The aflj function record whose [offset, offset+size) contains `addr`, or None.
    Pure-Python over r2's own function table — no command interpolation, so resolving
    an attacker-influenced address is injection-safe."""
    for f in funcs:
        off = f.get("offset")
        size = f.get("size") or f.get("realsz") or 0
        if isinstance(off, int) and off <= addr < off + (size or 1):
            return f
    return None


def _function_facts(r2, seek: str, info=None) -> dict:
    """Rich, always-welcome function facts for the focus — recovered prototype/signature,
    calling convention, and arg/local variables — from r2's function info (`afij`: the
    signature, calling convention, arg/local counts) and variables (`afvj`). `seek` is the
    same already-validated flag/address used for the `pdc`/`pdf` seek, so this adds no new
    injection surface. `info` is an optional pre-fetched `afij` result (the targeted-disasm path
    already has it) reused to avoid a second identical `afij` call; fetched here when None.
    Best-effort: every field is guarded, so a missing/odd shape just omits that fact."""
    facts: dict = {}
    if info is None:
        try:
            info = json.loads(r2.cmd(f"afij @ {seek}") or "[]")
        except (json.JSONDecodeError, TypeError):
            info = []
    if isinstance(info, list) and info and isinstance(info[0], dict):
        fi = info[0]
        sig = fi.get("signature")
        if sig:
            # r2's signature IS the recovered C prototype; expose it under both keys the
            # enrichment whitelist accepts (prototype is the primary, signature the synonym).
            facts["prototype"] = sig
            facts["signature"] = sig
        if fi.get("calltype"):
            facts["calling_convention"] = fi["calltype"]
        if isinstance(fi.get("nargs"), int):
            facts["param_count"] = fi["nargs"]
        if isinstance(fi.get("nlocals"), int):
            facts["local_count"] = fi["nlocals"]
    # afvj's shape varies across r2 versions: either a {storage_class: [vars]} map
    # ("reg"/"sp"/"bp"/"stack") OR a flat [vars] list — handle both. A variable's `kind`
    # is its STORAGE class, NOT an arg/local marker, so don't key on kind=="arg"; r2 marks
    # a parameter with an `isarg`/`arg` boolean (newer) or kind=="arg" (older), so take the
    # union of those signals and default to local. Misclassifying is worse than omitting,
    # so unmarked variables are locals (the prototype + param_count still convey the args).
    try:
        vars_ = json.loads(r2.cmd(f"afvj @ {seek}") or "[]")
    except (json.JSONDecodeError, TypeError):
        vars_ = []
    if isinstance(vars_, dict):
        entries = [v for group in vars_.values() for v in (group or []) if isinstance(v, dict)]
    elif isinstance(vars_, list):
        entries = [v for v in vars_ if isinstance(v, dict)]
    else:
        entries = []

    def _is_arg(v: dict) -> bool:
        return bool(v.get("isarg") or v.get("arg") or v.get("kind") == "arg")

    params: list = []
    locals_: list = []
    for v in entries:
        if not v.get("name"):
            continue
        entry = {"name": v.get("name"), "type": v.get("type")}
        (params if _is_arg(v) else locals_).append(entry)
    if params:
        facts["params"] = params
        facts.setdefault("param_count", len(params))
    if locals_:
        facts["locals"] = locals_
        facts.setdefault("local_count", len(locals_))
    return facts


def _disassemble_range(r2, address: str, *, length: int | None, count: int | None) -> dict:
    """Disassemble a RAW byte range at `address` — NO function required.

    `address` is the already-validated hex string (`_ADDR`), interpolated into an r2 seek
    only after that check, so it can never inject. `count` (instruction count) takes
    precedence over `length` (byte count) when both are given; otherwise `length` bytes
    are disassembled, defaulting to _RANGE_DEFAULT_LENGTH. Bounds are clamped to the
    ceilings so a pathological N can't run unbounded. Returns the range payload with the
    resolved mode echoed back, or an {error} if r2 produced nothing."""
    if count is not None:
        n = max(1, min(count, _RANGE_MAX_COUNT))
        # `pd N @ addr` — disassemble N instructions from addr (no function needed).
        disasm = (r2.cmd(f"pd {n} @ {address}") or "").strip()
        meta = {"count": n}
    else:
        n = length if length is not None else _RANGE_DEFAULT_LENGTH
        n = max(1, min(n, _RANGE_MAX_LENGTH))
        # `pD N @ addr` — disassemble N BYTES from addr (capital D = byte length, not insn
        # count), the raw-range read for a CFG blind spot with no defined function.
        disasm = (r2.cmd(f"pD {n} @ {address}") or "").strip()
        meta = {"length": n}
    if not disasm:
        return {"address": address, **meta,
                "error": "no disassembly at this address (out of range, or not mapped)"}
    return {"address": address, **meta, "disasm": disasm}


def _flag_value(rest: list[str], flag: str) -> str | None:
    """The value following `flag` in argv (`--length 256`), or None if absent/dangling."""
    if flag in rest:
        i = rest.index(flag)
        if i + 1 < len(rest):
            return rest[i + 1]
    return None


def _parse_int(val: str | None) -> int | None:
    """A non-negative int from a flag value, or None if absent/unparseable (clamped in
    _disassemble_range). Accepts decimal or 0x-hex so the host can pass either form."""
    if val is None:
        return None
    try:
        return int(val, 0)
    except (TypeError, ValueError):
        return None


_DISASM_FALLBACK_COUNT = 64  # raw linear instructions when an address defines no function


def _resolve_disasm_seek(r2, subject: str) -> tuple[str | None, bool]:
    """A seekable, injection-safe target for TARGETED disassembly (no whole-program aaa). A hex
    address is used as-is; a name is resolved against r2's already-loaded flag table (symbols /
    imports are known on open, no analysis needed). Returns (seek, is_addr), or (None, False) when
    a name can't be resolved without analysis (the caller then points at re_analyze)."""
    if _ADDR.match(subject):
        return subject, True
    if not _SAFE_NAME.match(subject):
        return None, False
    try:
        flags = {f["name"] for f in json.loads(r2.cmd("fj") or "[]")
                 if isinstance(f, dict) and f.get("name")}
    except (json.JSONDecodeError, TypeError):
        flags = set()
    for cand in _name_candidates(subject):
        if cand in flags:
            return cand, False
    return None, False


def _targeted_disasm(r2, seek: str, is_addr: bool) -> dict | None:
    """Disassemble the function at `seek` with ONE-function analysis (`af`) — never a whole-binary
    `aaa`, never `pdc`. `af` is bounded by the single function's own CFG, so this is cheap on any
    target size. Falls back to a raw linear disassembly (`pd`) from an address when no function is
    defined there. `seek` is already validated/resolved, so it can't inject. Returns the focus
    dict, or None when there's nothing to disassemble."""
    r2.cmd(f"af @ {seek}")  # analyze JUST this one function (no whole-binary pass)
    disasm = (r2.cmd(f"pdf @ {seek}") or "").strip()
    mode = "function"
    if not disasm and is_addr:
        disasm = (r2.cmd(f"pd {_DISASM_FALLBACK_COUNT} @ {seek}") or "").strip()
        mode = "linear"
    if not disasm:
        return None
    info = []
    try:
        info = json.loads(r2.cmd(f"afij @ {seek}") or "[]")
    except (json.JSONDecodeError, TypeError):
        info = []
    name = None
    addr = None
    if isinstance(info, list) and info and isinstance(info[0], dict):
        name = info[0].get("name")
        off = info[0].get("offset")
        addr = hex(off) if isinstance(off, int) else None
    focus = {"name": name or seek, "address": addr or (seek if is_addr else None),
             "disasm": disasm, "disasm_mode": mode, "callees": _callees(disasm)}
    if mode == "function":
        # Reuse the afij we already fetched — no second identical call on the function path.
        focus.update(_function_facts(r2, seek, info=info))
    return focus


def main() -> int:
    if "--r2-version" in sys.argv:
        return _emit_r2_version()  # no-target run: report the toolchain version for the cache key
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: decompile_probe.py <artifact> [function|0xADDR] "
                                   "[--reanalyze] | --range <0xADDR> [--length N | --count N]"}))
        return 2
    path = sys.argv[1]
    # Remaining args: an optional positional focus (name or 0xADDR) + a --reanalyze flag.
    rest = sys.argv[2:]
    reanalyze = "--reanalyze" in rest
    # RANGE mode: `--range <0xADDR>` disassembles a raw byte range with NO function needed.
    # The address comes as the value AFTER --range (kept off the positionals so it isn't
    # mistaken for a focus). --length / --count bound it (count wins if both given).
    range_addr = _flag_value(rest, "--range")
    # TARGETED disassemble mode: `--disasm <name|0xADDR>` disassembles ONE function (via `af`) with
    # NO whole-binary `aaa` and NO `pdc` — the cheap path for re_disassemble on any target size.
    disasm_subject = _flag_value(rest, "--disasm")
    _value_flags = {"--range", "--length", "--count", "--disasm"}  # consume their following value too
    positionals = []
    skip = False
    for tok in rest:
        if skip:
            skip = False
            continue
        if tok in _value_flags:
            skip = True
            continue
        if tok.startswith("--"):
            continue
        positionals.append(tok)
    # --analyze: the DETACHED whole-binary analysis run (re_analyze's r2 path) — a full `aaa` + `Ps`
    # + commit-the-warm-marker, with NO focus. start_detached appends a /out positional the probe
    # would otherwise treat as a focus function name, so force it off (mirrors ghidra_probe --analyze).
    analyze_mode = "--analyze" in rest
    focus_arg = None if analyze_mode else (positionals[0] if positionals else None)

    try:
        import r2pipe
    except ImportError as exc:
        print(json.dumps({"error": f"radare2/r2pipe not available in the sandbox image: {exc}"}))
        return 3

    # Persistent project (analyze-once) applies to the WHOLE-BINARY decompile path only — the
    # targeted disasm/range modes are already cheap (`af`/`pD`) and open plain. When the writable
    # slot is mounted, `_project_flags` reloads a warm project via `-p` (skipping `aaa`) or wipes
    # any partial state for a clean cold save.
    use_project = disasm_subject is None and range_addr is None
    proj_dir = marker = ""
    open_flags = ["-2"]  # -2 silences stderr
    warm = False
    if use_project:
        use_project, proj_dir, marker, pflags = _project_flags()
        if use_project:
            warm = "-p" in pflags
            open_flags += pflags
            _set_git_env()  # before open: r2 spawns any git child with the inherited env

    try:
        r2 = r2pipe.open(path, flags=open_flags)
    except Exception as exc:  # noqa: BLE001 — surface a structured reason, not a bare traceback
        print(json.dumps({"error": f"radare2 failed to open the target: {exc}"}))
        return 4
    try:
        if disasm_subject is not None:
            # TARGETED disassembly: NO whole-binary aaa, NO pdc. Analyze just the one function at
            # the subject (`af`) and `pdf` it, falling back to a raw linear read at an address.
            seek, is_addr = _resolve_disasm_seek(r2, disasm_subject)
            if seek is None:
                print(json.dumps({"tool": "decompile_probe", "mode": "disasm",
                                  "subject": disasm_subject, "focus": None,
                                  "error": "not resolvable without analysis "
                                           "(pass a hex address, or run re_analyze first)"}))
                return 0
            focus = _targeted_disasm(r2, seek, is_addr)
            print(json.dumps({"tool": "decompile_probe", "mode": "disasm",
                              "subject": disasm_subject, "focus": focus}))
            return 0
        if range_addr is not None:
            # RANGE mode: no analysis pass needed — `pD`/`pd` read+disassemble raw bytes,
            # which is the whole point (the function-based paths already failed). Validate
            # the address with the SAME strict regex as a focus so it can never inject.
            if not _ADDR.match(range_addr):
                print(json.dumps({"tool": "decompile_probe",
                                  "range": {"error": f"invalid address {range_addr!r} "
                                                     "(expected hex like 0x401200)"}}))
                return 0
            length = _parse_int(_flag_value(rest, "--length"))
            count = _parse_int(_flag_value(rest, "--count"))
            rng = _disassemble_range(r2, range_addr, length=length, count=count)
            print(json.dumps({"tool": "decompile_probe", "range": rng}))
            return 0
        # WARM-ONLY enforcement (THE analysis invariant): the whole-binary decompile/list path must
        # NEVER run a cold `aaa` off its own bat — only the two EXPLICIT analysis entry points do:
        # `--analyze` (re_analyze) and `--reanalyze` (re_reanalyze). A plain focus/list decompile on a
        # COLD slot returns the re_analyze lead instead of analyzing, so no per-call tool (nor the LLM
        # decompile task / enrich) ever triggers a full analysis. (Targeted --disasm/--range returned
        # above; they need no analysis.)
        # rc=0 with a STRUCTURED payload (not a non-zero exit run_probe would raise on) so the host
        # surfaces the lead gracefully — same convention as ghidra_probe / xrefs_probe warm-misses.
        if not warm and not (analyze_mode or reanalyze):
            print(json.dumps({"tool": "decompile_probe", "focus": None, "functions": [],
                              "needs_analysis": True, "error": _RE_ANALYZE_LEAD}))
            return 0
        # Whole-binary analysis. A WARM persistent project already carries it (reloaded at open via
        # `-p`), so skip `aaa` entirely — the whole point of the cache. Otherwise analyze (`aaaa` =
        # the deeper --reanalyze pass; `aaa` the fast default) and, when persisting, SAVE the
        # analyzed program as a named project + commit the warm marker LAST so the next call reloads.
        if not warm:
            r2.cmd("aaaa" if reanalyze else "aaa")
            if use_project:
                r2.cmd(f"Ps {PROJECT_NAME}")  # save by NAME under dir.projects (never a path)
                # Commit the warm marker ONLY if `Ps` actually wrote the named project — a failed
                # save (disk/permission) leaves nothing, so committing would falsely mark the slot
                # warm. (It self-heals next call via the same named-dir check, but this avoids the
                # wasted cold redo and keeps the marker honest.)
                named = os.path.join(proj_dir, PROJECT_NAME)
                if os.path.isdir(named) and os.listdir(named):
                    _commit_marker(marker)
        records = []
        offsets = {}
        try:
            for f in (json.loads(r2.cmd("aflj") or "[]")):
                if f.get("name"):
                    records.append(f)
                    offsets[f["name"]] = f.get("offset")
        except json.JSONDecodeError:
            pass
        functions = list(offsets.keys())

        focus = None
        if focus_arg and _ADDR.match(focus_arg):
            # ADDRESS focus (analyze-at-address): resolve the function CONTAINING it.
            addr = int(focus_arg, 16)
            hit = _containing_function(addr, records)
            # Seek to the containing function by its r2-known name, else to the raw
            # (validated) address — `pdc @ 0xADDR` decompiles from there regardless.
            seek = hit["name"] if hit else focus_arg
            pseudo = r2.cmd(f"pdc @ {seek}").strip()
            disasm = r2.cmd(f"pdf @ {seek}").strip()
            off = hit.get("offset") if hit else addr
            focus = {
                "name": hit["name"] if hit else focus_arg,
                "resolved": hit["name"] if hit else None,
                "address": hex(off) if isinstance(off, int) else focus_arg,
                "pseudocode": pseudo,
                "disasm": disasm,
                "callees": _callees(disasm),
                **_function_facts(r2, seek),
            }
        elif focus_arg:
            # NAME focus. Resolve the function symbol r2 actually knows.
            resolved = next(
                (c for c in _name_candidates(focus_arg) if c in functions),
                focus_arg if focus_arg in functions else None,
            )
            # Never interpolate an unvalidated name into an r2 command. Use the
            # resolved flag, or the sym.<name> fallback ONLY if the name is safe;
            # otherwise refuse to seek (treated as "function not found").
            if resolved:
                seek = resolved
            elif _SAFE_NAME.match(focus_arg):
                seek = f"sym.{focus_arg.lstrip('.')}"
            else:
                seek = None
            pseudo = r2.cmd(f"pdc @ {seek}").strip() if seek else ""
            disasm = r2.cmd(f"pdf @ {seek}").strip() if seek else ""
            off = offsets.get(resolved) if resolved else None
            focus = {
                "name": focus_arg,
                "resolved": resolved,
                "address": hex(off) if isinstance(off, int) else None,
                "pseudocode": pseudo,
                "disasm": disasm,
                "callees": _callees(disasm),
                **(_function_facts(r2, seek) if seek else {}),
            }

        # `cached` mirrors ghidra_probe: True ⇒ served from a WARM persistent project (no `aaa`
        # this call), False ⇒ a cold analysis (or the uncached throwaway path).
        print(json.dumps({"tool": "decompile_probe", "functions": functions[:200],
                          "focus": focus, "cached": warm}))
        return 0
    finally:
        r2.quit()


if __name__ == "__main__":
    raise SystemExit(main())

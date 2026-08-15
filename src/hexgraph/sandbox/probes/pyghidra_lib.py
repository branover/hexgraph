#!/usr/bin/env python3
"""Shared PyGhidra runtime + analysis cores (Python 3), used by the headless probe
(`pyghidra_probe.py`) AND the resident bridge. Replaces the Jython `ghidra_probe.py` scripts:
the Ghidra Java API is identical via jpype, so each core ports ~1:1 from its Jython original,
now in real Python 3 — no encoding cookie, f-strings, shared between headless + bridge.

Sandbox hardening recipe (proven under --user 1000:1000 --read-only --network none --cap-drop ALL):
pin every writable Ghidra/Java path at the /scratch tmpfs. Beyond HOME/TMPDIR/XDG (which the runner
sets), pyghidra ALSO needs (a) Python's tempfile via $TMPDIR (its plugin lock) and (b) the JVM's
`-Duser.home=/scratch` — under --user 1000 Java reads user.home from /etc/passwd (=/home/analyst,
read-only), IGNORING $HOME. Set these BEFORE pyghidra.start() (before the JVM launches). NOTE: never
run a pyghidra script from a writable dir on sys.path (e.g. /scratch) — its namespace-path finder
recurses; probes run from /opt/hexgraph (read-only), which is fine.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import struct
import time

SCRATCH = os.environ.get("TMPDIR", "/scratch")
PROJECT_MOUNT = "/ghidra-project"
PROJECT_NAME = "hexgraph"          # the Ghidra project name (matches ghidra_probe)
META_NAME = "meta.json"            # the committed warm marker (matches ghidra_probe)
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")

# Versioned contract for the ELF PT_LOAD <-> Ghidra address-space check recorded in meta.json and
# returned by every headless result. Bump when the validation semantics change so old markers are
# informational only; every warm open re-validates against the live Program before it is yielded.
ADDRESS_MAPPING_SCHEMA = 1


class AddressMappingMismatch(RuntimeError):
    """A newly imported Ghidra Program does not map the ELF at its declared virtual addresses.

    Warm projects are deliberately accepted at their existing base with a warning; this error is
    reserved for a cold import that cannot satisfy the new coordinate contract.
    """

    def __init__(self, report):
        self.report = report
        details = []
        if report.get("unexpected_image_base"):
            details.append(
                f"image base {report.get('image_base')} instead of "
                f"{report.get('preferred_image_base')}"
            )
        missing = ", ".join(report.get("unmapped_addresses") or [])
        if missing:
            details.append(f"unmapped {missing}")
        if report.get("reason"):
            details.append(f"unverified ELF mapping: {report['reason']}")
        super().__init__(
            "Ghidra project address mapping does not match the ELF PT_LOAD virtual-address map "
            f"({'; '.join(details) or 'unknown mismatch'}). The new analysis cannot be committed; "
            "check the ELF loader result before retrying."
        )

# Above this size a COLD import runs the "fast profile": disable the auto-analysis passes proven
# pathological on a 100 MB+ monolith (see _slow) so recon still gets functions/call-graph/strings
# but the O(n^2) / decompile-every-function passes don't grind for tens of minutes. Smaller binaries
# keep FULL analysis. (Ported from ghidra_probe.GHIDRA_FAST_PROFILE_BYTES.)
_FAST_PROFILE_BYTES = int(float(os.environ.get("HEXGRAPH_GHIDRA_FAST_PROFILE_MB", "100")) * 1024 * 1024)


def _setup_env() -> None:
    """Pin every writable Ghidra/Java/Python-temp path at /scratch BEFORE the JVM starts."""
    for var in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                "XDG_STATE_HOME"):
        os.environ.setdefault(var, SCRATCH)
    heap = os.environ.get("HEXGRAPH_GHIDRA_HEAP_PCT", "45.0")
    existing = os.environ.get("_JAVA_OPTIONS", "")
    os.environ["_JAVA_OPTIONS"] = (
        f"-Djava.io.tmpdir={SCRATCH} -Duser.home={SCRATCH} -XX:MaxRAMPercentage={heap} {existing}"
    ).strip()


_STARTED = False


def start() -> None:
    """Idempotently launch the JVM + Ghidra (pyghidra). Sets the env first."""
    global _STARTED
    if _STARTED:
        return
    _setup_env()
    import pyghidra

    pyghidra.start()
    _STARTED = True


def program_name(artifact: str) -> str:
    """The name the program is stored under (the artifact basename — /artifact -> 'artifact')."""
    return os.path.basename(artifact) if artifact else "artifact"


def _is_warm(proj_dir: str) -> bool:
    """A committed, non-empty persistent slot (the marker is written as the last cold step).

    Mirrors the host's authoritative `GhidraProject.exists()`: the committed marker loads AND the
    project LOCATION (`proj_dir` = /ghidra-project/project) is non-empty. Ghidra lays a project out
    as `hexgraph.gpr` + `hexgraph.rep/` directly under the location (NOT a `hexgraph/` subdir), so
    it's the location itself that must be non-empty — same signal the Jython probe committed."""
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    try:
        with open(marker) as fh:
            json.load(fh)
    except (OSError, ValueError):
        return False
    return os.path.isdir(proj_dir) and bool(os.listdir(proj_dir))


def _commit_marker(**fields) -> None:
    """Commit the warm marker atomically — the LAST step of a successful cold analyze.

    MERGES, like `update_marker`. A cold analyze normally runs after `_clear_partial` has removed
    any old marker, so there is usually nothing to preserve — but this is also the live writer of a
    file the recovery stage records its resume state in, and a replace here would silently discard a
    completed or partially-completed pass and make the next run redo tens of minutes of work."""
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    data = read_marker()
    data.update({"program_name": PROJECT_NAME, "created_at": time.time(), **fields})
    tmp = marker + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, marker)
    except OSError:
        pass


def read_marker() -> dict:
    """The committed warm marker as a dict (empty when absent/unreadable)."""
    try:
        with open(os.path.join(PROJECT_MOUNT, META_NAME)) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def update_marker(**fields) -> None:
    """MERGE `fields` into the committed marker, atomically, preserving every key already there.

    The marker is written by both the host (`engine.re.ghidra_project.write_meta`: content_hash /
    ghidra_version / …) and `_commit_marker`, so a stage that records its own state must merge
    rather than replace — clobbering `content_hash` would make the host re-analyze a warm slot."""
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    data = read_marker()
    data.update(fields)
    tmp = marker + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, marker)
    except OSError:
        pass


def _hex(value):
    """Stable JSON rendering for an address/offset, including a negative mapping delta."""
    value = int(value)
    return ("-0x" + format(-value, "x")) if value < 0 else ("0x" + format(value, "x"))


def _elf_load_map(artifact):
    """Parse the bounded ELF header + PT_LOAD table from `artifact` inside the sandbox.

    Returns None for a non-ELF (the cache still works, but no ELF coordinate contract applies).
    Malformed/extended layouts return an `unverified` report instead of guessing. No target bytes
    are parsed on the host, and only the fixed-size headers are read here.
    """
    try:
        file_size = os.path.getsize(artifact)
        with open(artifact, "rb") as fh:
            ident = fh.read(16)
            if len(ident) != 16 or ident[:4] != b"\x7fELF":
                return None
            elf_class, elf_data = ident[4], ident[5]
            if elf_class not in (1, 2) or elf_data not in (1, 2):
                raise ValueError("unsupported ELF class or byte order")
            endian = "<" if elf_data == 1 else ">"
            hdr_fmt = endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
            hdr_size = struct.calcsize(hdr_fmt)
            raw = fh.read(hdr_size)
            if len(raw) != hdr_size:
                raise ValueError("truncated ELF header")
            header = struct.unpack(hdr_fmt, raw)
            entry = header[3]
            phoff = header[4]
            phentsize = header[8]
            phnum = header[9]
            # PN_XNUM stores the real count in section-header zero. It is uncommon and requires a
            # second parser; fail explicitly instead of treating 65,535 hostile headers as real.
            if phnum == 0xFFFF:
                raise ValueError("extended ELF program-header counts are not supported")
            if phnum > 4096:
                raise ValueError("ELF program-header count exceeds validation limit")
            ph_fmt = endian + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ")
            ph_size = struct.calcsize(ph_fmt)
            if phnum and (phentsize < ph_size or phoff + phentsize * phnum > file_size):
                raise ValueError("ELF program-header table is out of bounds")
            segments = []
            for i in range(phnum):
                fh.seek(phoff + i * phentsize)
                raw = fh.read(ph_size)
                if len(raw) != ph_size:
                    raise ValueError("truncated ELF program header")
                values = struct.unpack(ph_fmt, raw)
                if elf_class == 1:
                    p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, p_align = values
                else:
                    p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = values
                if p_type != 1:  # PT_LOAD
                    continue
                if p_offset + p_filesz > file_size or p_filesz > p_memsz:
                    raise ValueError("ELF PT_LOAD range is out of bounds")
                segments.append({
                    "file_offset": p_offset,
                    "virtual_address": p_vaddr,
                    "file_size": p_filesz,
                    "memory_size": p_memsz,
                    "flags": p_flags,
                    "alignment": p_align,
                })
            if not segments and header[0] == 1:  # ET_REL has no runtime PT_LOAD coordinate system
                return {
                    "schema": ADDRESS_MAPPING_SCHEMA,
                    "format": "elf",
                    "elf_type": header[0],
                    "status": "not_applicable",
                    "coordinate_system": "ghidra_program_address",
                    "reason": "relocatable ELF has no PT_LOAD segments",
                }
            if not segments:
                raise ValueError("ELF has no PT_LOAD segments")
            return {
                "elf_type": header[0],
                "entry_point": entry,
                "preferred_image_base": min(s["virtual_address"] for s in segments),
                "segments": segments,
            }
    except (OSError, ValueError, struct.error) as exc:
        return {
            "schema": ADDRESS_MAPPING_SCHEMA,
            "format": "elf",
            "status": "unverified",
            "reason": str(exc),
            "coordinate_system": "elf_virtual_address",
        }


def _address_offset(address):
    """Convert a Ghidra Address to a non-negative Python integer."""
    try:
        return int(address.getUnsignedOffset())
    except Exception:  # noqa: BLE001 — older Ghidra Address implementations expose getOffset only
        value = int(address.getOffset())
        if value >= 0:
            return value
        try:
            bits = int(address.getAddressSpace().getSize())
        except Exception:  # noqa: BLE001
            bits = 64
        return value + (1 << bits)


def _mapping_segment_json(segment, load_bias=0):
    flags = int(segment["flags"])
    result = {
        "file_offset": _hex(segment["file_offset"]),
        "virtual_address": _hex(segment["virtual_address"]),
        "file_size": _hex(segment["file_size"]),
        "memory_size": _hex(segment["memory_size"]),
        "flags": ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-")
                 + ("X" if flags & 1 else "-"),
        "file_to_virtual_delta": _hex(segment["virtual_address"] - segment["file_offset"]),
    }
    if load_bias:
        result["ghidra_address"] = _hex(segment["virtual_address"] + load_bias)
    return result


def validate_address_mapping(program, artifact, *, allow_existing_base=False):
    """Validate a live Ghidra Program against the ELF's declared virtual-address ranges.

    Ghidra addresses are ELF *virtual addresses*, while debugger/module reports sometimes use raw
    file offsets. Those differ whenever a PT_LOAD has `p_vaddr != p_offset`. Separately, Ghidra's
    ELF loader gives PIEs a default non-zero image base (commonly +0x100000); HexGraph normalizes
    that cold import back to the ELF's preferred base so every backend uses one coordinate system.
    Cold imports require the canonical image base plus every non-empty PT_LOAD's start, file-backed
    end, memory end, and ELF entry point at its declared virtual address. Warm projects may predate
    that policy: with `allow_existing_base`, their existing load bias is validated and reported as
    a warning rather than forcing an expensive rebuild. Unsupported/non-ELF formats are reported
    honestly and not guessed at.
    """
    parsed = _elf_load_map(artifact)
    if parsed is None:
        return {
            "schema": ADDRESS_MAPPING_SCHEMA,
            "format": "other",
            "status": "not_applicable",
            "coordinate_system": "ghidra_program_address",
            "image_base": _hex(_address_offset(program.getImageBase())),
        }
    if parsed.get("status") == "not_applicable":
        parsed["image_base"] = _hex(_address_offset(program.getImageBase()))
        return parsed
    if parsed.get("status") == "unverified":
        image_base = _hex(_address_offset(program.getImageBase()))
        parsed["image_base"] = image_base
        if allow_existing_base:
            parsed["coordinate_system"] = "ghidra_program_address"
            parsed["warning"] = (
                f"Warm Ghidra project uses image base {image_base}; its ELF address mapping "
                f"could not be verified ({parsed.get('reason', 'unknown reason')})."
            )
            return parsed
        # A cold import has no durable analysis to preserve. Committing one whose ELF mapping this
        # bounded parser could not verify would silently keep Ghidra's loader-selected base while
        # promising the normalized coordinate contract. Warm projects take the warn-and-preserve
        # path above; new projects fail closed and leave no committed marker.
        raise AddressMappingMismatch(parsed)

    image_base = _address_offset(program.getImageBase())
    preferred_base = parsed["preferred_image_base"]
    load_bias = image_base - preferred_base
    memory = program.getMemory()
    space = program.getAddressFactory().getDefaultAddressSpace()
    missing = []

    def _mapped(value):
        try:
            return memory.getBlock(space.getAddress(int(value))) is not None
        except Exception:  # noqa: BLE001 — an out-of-space address is definitively not mapped
            return False

    accepted_bias = load_bias if allow_existing_base else 0
    for segment in parsed["segments"]:
        start = segment["virtual_address"] + accepted_bias
        if not segment["memory_size"]:
            continue
        anchors = [start]
        if segment["file_size"]:
            anchors.append(start + segment["file_size"] - 1)
        if segment["memory_size"]:
            anchors.append(start + segment["memory_size"] - 1)
        for anchor in dict.fromkeys(anchors):
            if not _mapped(anchor):
                missing.append(_hex(anchor))
    entry = parsed["entry_point"] + accepted_bias if parsed["entry_point"] else 0
    if entry and not _mapped(entry):
        missing.append(_hex(entry))

    report = {
        "schema": ADDRESS_MAPPING_SCHEMA,
        "format": "elf",
        "status": "mismatch" if missing else "validated",
        "coordinate_system": ("elf_virtual_address_plus_load_bias"
                              if accepted_bias else "elf_virtual_address"),
        "image_base": _hex(image_base),
        "preferred_image_base": _hex(preferred_base),
        "ghidra_load_bias": _hex(load_bias),
        "entry_point": _hex(parsed["entry_point"]),
        "ghidra_entry_point": _hex(entry),
        "load_segments": [_mapping_segment_json(s, accepted_bias) for s in parsed["segments"]],
    }
    if load_bias and not allow_existing_base:
        report["status"] = "mismatch"
        report["unexpected_image_base"] = True
    if allow_existing_base and load_bias:
        report["legacy_image_base"] = True
        report["warning"] = (
            f"Warm Ghidra project uses image base {_hex(image_base)} "
            f"(ELF preferred base {_hex(preferred_base)}; load bias {_hex(load_bias)}). "
            "Ghidra addresses include this bias; new PIE imports use their ELF preferred base "
            "(normally 0x0)."
        )
    if missing:
        report["status"] = "warning" if allow_existing_base else "mismatch"
        detail = (" Existing project address ranges could not be fully verified."
                  if allow_existing_base else "")
        base_note = (
            f"Warm Ghidra project uses image base {_hex(image_base)} "
            f"(ELF preferred base {_hex(preferred_base)}; load bias {_hex(load_bias)})."
        )
        report["warning"] = report.get("warning", base_note) + detail
    if missing or (load_bias and not allow_existing_base):
        report["unmapped_addresses"] = list(dict.fromkeys(missing))[:32]
    if missing and allow_existing_base:
        return report
    if missing or (load_bias and not allow_existing_base):
        raise AddressMappingMismatch(report)
    return report


def normalize_program_image_base(program, artifact):
    """Rebase a newly imported ELF Program to its preferred PT_LOAD base before analysis.

    Ghidra 12.x defaults PIE imports to 0x100000 even when the ELF's lowest PT_LOAD begins at zero.
    That makes an exact address from the ELF, radare2, or a debugger resolve one megabyte away in
    Ghidra. Cold imports are writable, so normalize once before auto-analysis and persist the shared
    coordinate system. Warm projects are never mutated or rejected here; their existing image base
    is reported with every result so expensive legacy analyses remain usable.
    """
    parsed = _elf_load_map(artifact)
    if (parsed is None or parsed.get("status") == "unverified"
            or parsed.get("elf_type") != 3):  # ET_DYN (PIE/shared object)
        return
    preferred = int(parsed["preferred_image_base"])
    current = _address_offset(program.getImageBase())
    if current == preferred:
        return
    space = program.getAddressFactory().getDefaultAddressSpace()
    txid = program.startTransaction("hexgraph normalize ELF image base")
    commit = False
    try:
        program.setImageBase(space.getAddress(preferred), True)
        commit = True
    finally:
        program.endTransaction(txid, commit)


def _mapping_value(value):
    """Normalize an int/hex string/Ghidra Address passed to a re_script mapping helper."""
    if hasattr(value, "getOffset"):
        return _address_offset(value)
    return int(str(value), 0) if isinstance(value, str) else int(value)


def mapping_file_offset_to_vaddr(mapping, value):
    """Translate an ELF file offset into the reported Ghidra Program coordinate system."""
    offset = _mapping_value(value)
    for segment in (mapping or {}).get("load_segments") or []:
        start = int(segment["file_offset"], 0)
        size = int(segment["file_size"], 0)
        if start <= offset < start + size:
            program_start = segment.get("ghidra_address", segment["virtual_address"])
            return int(program_start, 0) + offset - start
    return None


def mapping_vaddr_to_file_offset(mapping, value):
    """Translate a reported Ghidra Program address to an ELF file offset."""
    address = _mapping_value(value)
    for segment in (mapping or {}).get("load_segments") or []:
        start = int(segment.get("ghidra_address", segment["virtual_address"]), 0)
        size = int(segment["file_size"], 0)
        if start <= address < start + size:
            return int(segment["file_offset"], 0) + address - start
    return None


def _validate_warm_address_mapping(program, artifact, mapping_out=None):
    """Publish a warm mapping without mutating or rejecting an expensive existing project."""
    address_mapping = validate_address_mapping(program, artifact, allow_existing_base=True)
    update_marker(address_mapping=address_mapping)
    if mapping_out is not None:
        mapping_out["address_mapping"] = address_mapping
    return address_mapping


@contextlib.contextmanager
def _read_only_program(project, prog_name):
    """Open the warm program IMMUTABLE via DomainFile.getReadOnlyDomainObject — the returned
    Program cannot be saved back into the persistent project (Ghidra rejects a write on a read-only
    domain object). Used by the re_script path so an AGENT-SUPPLIED script can query the warm
    project but NEVER mutate/corrupt it (the equivalent of the Jython path's analyzeHeadless
    `-readOnly`). The consumer is released on exit; the project is closed by the caller."""
    from java.lang import Object as _JavaObject
    from ghidra.framework.model import DomainFile
    from ghidra.program.model.listing import Program
    from ghidra.util.task import ConsoleTaskMonitor

    # The consumer is a reference token for get/release; it must bind to `java.lang.Object`, which a
    # plain Python object() can't (jpype rejects the overload) — use an actual Java Object.
    consumer = _JavaObject()
    df = project.getProjectData().getFile("/" + prog_name)
    if df is None:
        raise FileNotFoundError(f"program /{prog_name} not found in the warm project")
    # int(...) coerces DEFAULT_VERSION to a primitive: jpype hands the JInt static field back as a
    # boxed value and can't match the getReadOnlyDomainObject(Object, int, TaskMonitor) overload.
    dobj = df.getReadOnlyDomainObject(consumer, int(DomainFile.DEFAULT_VERSION), ConsoleTaskMonitor())
    if not Program.class_.isAssignableFrom(dobj.getClass()):
        with contextlib.suppress(Exception):
            dobj.release(consumer)
        raise TypeError(f"/{prog_name} exists but is not a Program")
    try:
        yield dobj
    finally:
        with contextlib.suppress(Exception):
            dobj.release(consumer)


@contextlib.contextmanager
def open_target(artifact, *, cold_analyze=True, read_only=False, mapping_out=None):
    """Yield `(program, flat, cached)` for the target. WARM (a committed slot at PROJECT_MOUNT):
    open the resident project + program, NO re-analysis. COLD: import + analyze; persist into the
    slot (+ commit the marker) when the mount is present, else a throwaway /scratch project.

    `read_only` (re_script) opens the WARM program IMMUTABLE (getReadOnlyDomainObject) so an
    agent-supplied script can query but never write the persistent project; it also forces warm-only
    (no cold analysis for a read-only query) — a cold miss raises so the probe returns the re_analyze
    lead. `cached` is True on the warm path. Before ANY warm Program is yielded, its address space
    is checked against the artifact's ELF PT_LOAD virtual-address map. Legacy image bases are kept
    intact and returned as warnings rather than invalidating a costly project. `mapping_out`, when
    supplied, receives the JSON-safe validation report without changing
    the long-standing `(program, flat, cached)` tuple. The Program is closed / project released on
    exit."""
    import pyghidra
    from ghidra.program.flatapi import FlatProgramAPI

    proj_dir = os.path.join(PROJECT_MOUNT, "project") if os.path.isdir(PROJECT_MOUNT) else None
    prog_name = program_name(artifact)

    if proj_dir and _is_warm(proj_dir):
        project = pyghidra.open_project(proj_dir, PROJECT_NAME)
        try:
            if read_only:
                with _read_only_program(project, prog_name) as program:
                    _validate_warm_address_mapping(program, artifact, mapping_out)
                    yield program, FlatProgramAPI(program), True
            else:
                with pyghidra.program_context(project, "/" + prog_name) as program:
                    _validate_warm_address_mapping(program, artifact, mapping_out)
                    yield program, FlatProgramAPI(program), True
        finally:
            with contextlib.suppress(Exception):
                project.close()
        return

    if read_only or not cold_analyze:
        # re_script is warm-only: never pay a cold import for a read-only query. The caller maps
        # this to the re_analyze lead (mirrors the Jython --script warm-only refusal).
        raise RuntimeError("no warm analysis for this target (run re_analyze first)")

    # COLD import + analyze. Persist into the slot when mounted; else a throwaway.
    persist = bool(proj_dir)
    if persist:
        _clear_partial(proj_dir)
        loc, name = proj_dir, PROJECT_NAME
    else:
        loc = os.path.join(SCRATCH, "ghidra_proj")
        name = PROJECT_NAME
        os.makedirs(loc, exist_ok=True)
    # open_program imports (analyze=False so WE drive analysis with the fast profile) into loc/name
    # and yields the FlatProgramAPI. PERSISTENCE is handled by open_program's own context exit
    # (`project.save(program)`), NOT an explicit `program.save()`: auto-analysis leaves the program's
    # DB transaction settling, and `project.save` handles that the way analyzeHeadless does, whereas a
    # direct `program.save()` raises "Unable to lock due to active transaction" on any non-trivial
    # binary. The marker is committed only AFTER a clean exit (save succeeded), so a failed analysis
    # leaves no committed marker and the host re-analyzes.
    with pyghidra.open_program(artifact, project_location=loc, project_name=name,
                               program_name=prog_name, analyze=False,
                               nested_project_location=False) as flat:
        program = flat.getCurrentProgram()
        normalize_program_image_base(program, artifact)
        _analyze(program, artifact)
        address_mapping = validate_address_mapping(program, artifact)
        if mapping_out is not None:
            mapping_out["address_mapping"] = address_mapping
        yield program, flat, False
    if persist:
        _commit_marker(address_mapping=address_mapping)


def _slow_analyzer(name: str) -> bool:
    """The auto-analysis passes disabled under the fast profile — matched by name, with the
    constant-prop passes matched by suffix so it's architecture-agnostic ("PowerPC/ARM/x86 …
    Constant Reference Analyzer"). Mirrors the Jython FAST_PROFILE_SCRIPT: drop the O(n^2)
    Call-Fixup Installer, the per-processor constant/scalar propagation, the decompile-EVERY-function
    passes, and the Non-Returning Functions analyzers (their ClearFlowAndRepair wedges on a monolith);
    KEEP function + call-graph discovery (HexGraph decompiles on demand).

    NOT "keep reference discovery" — dropping the constant/scalar passes specifically empties the
    code->DATA reference index (control flow is unaffected, which is why the call graph survives).
    On a real 895 MB x86-64 image that is ~10M missing references: every `xrefs_core(mode="data")`
    on a string returns its data->data pointers and NONE of the code that loads it. `recover_data_refs_core`
    rebuilds the statically-resolvable majority of that index; see its comment for what it cannot."""
    if "." in name:
        return False
    if name in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                "Aggressive Instruction Finder"):
        return True
    # Non-Returning Functions ("- Discovered"/"- Known"): when a heavily-called routine is flagged
    # non-returning, the analyzer's ClearFlowAndRepair walks the instruction-flow graph (a CodeManager
    # DB lookup per node) to repair downstream flow. On a monolith with dense/mis-disassembled code
    # that traversal explodes — observed wedged for >40h in FindNoReturnFunctionsAnalyzer.repairDamagedLocations
    # on a ~900 MB image. Flow past no-return calls stays intact; we lose only the auto no-return marking,
    # which does not affect on-demand xrefs/decompiles.
    if name.startswith("Non-Returning Functions"):
        return True
    return name.endswith("Constant Reference Analyzer") or name.endswith("Scalar Operand References")


def _apply_fast_profile(program) -> None:
    """Disable the pathological analyzers on a large binary (in a transaction, as option writes
    modify the program). Best-effort per option so one failure doesn't abort the profile."""
    txid = program.startTransaction("hexgraph fast-profile")
    try:
        opts = program.getOptions("Analyzers")
        for name in list(opts.getOptionNames()):
            if _slow_analyzer(name):
                with contextlib.suppress(Exception):
                    opts.setBoolean(name, False)
    finally:
        program.endTransaction(txid, True)


def _analyze(program, artifact) -> None:
    """Run Ghidra auto-analysis over a freshly-imported program to completion: the fast profile for
    a large binary (disables the passes pathological on a monolith), then AutoAnalysisManager, then
    mark the program analyzed so a warm re-open skips analysis.

    NO in-process timeout: the Jython `-analysisTimeoutPerFile` graceful-partial-save doesn't port
    cleanly (cancelling AutoAnalysisManager mid-pass corrupts the DB transaction, so the partial
    can't be saved), and it's superseded anyway — `re_analyze` runs this DETACHED with a generous
    budget, and the fast profile is the real bound on a monolith. A pathological binary that outruns
    even the detached budget is stopped by the operator (re_bridge/re_analyze), not silently."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import ConsoleTaskMonitor

    large = False
    with contextlib.suppress(OSError):
        large = artifact is not None and os.path.getsize(artifact) >= _FAST_PROFILE_BYTES
    if large:
        _apply_fast_profile(program)

    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.initializeOptions()
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(ConsoleTaskMonitor())  # synchronous; persistence is open_program's exit save
    with contextlib.suppress(Exception):
        GhidraProgramUtilities.markProgramAnalyzed(program)


def fast_profile_applies(artifact) -> bool:
    """Whether a COLD analysis of `artifact` runs (or ran) under the fast profile — the same
    size predicate `_analyze` uses, exposed so callers can report the capability state instead of
    leaving an agent to infer it from empty results. Stateless on purpose: it is derived from the
    artifact, not from a flag set during the analysis that produced the warm slot."""
    try:
        return artifact is not None and os.path.getsize(artifact) >= _FAST_PROFILE_BYTES
    except OSError:
        return False


# --- code->data reference recovery ---------------------------------------------------------------
# The fast profile disables the per-processor "* Constant Reference Analyzer" / "* Scalar Operand
# References" passes because their cost on a monolith is unbounded (the parallel pass is capped at
# `Max Threads`, but whatever falls OUTSIDE a recognized function body is then walked SINGLE-THREADED
# — see ConstantPropagationAnalyzer.added, "now slog through the rest single threaded"). Disabling
# them also empties the code->DATA reference index, so `xrefs_core(mode="data")` on a string returns
# only the data->data pointers and none of the CODE that loads it — the string->callers pivot dies.
#
# Most of that index does not need constant propagation to rebuild. On x86-64 a RIP-relative operand
# is resolved by SLEIGH at DISASSEMBLY time (`LEA RDI,[0x102004]` decodes to pcode
# `COPY (const,0x102004,8)`), so the final address is already sitting in the instruction as a Scalar
# operand. One linear pass over the listing recovers those references with no propagation at all.
#
# Measured IN-REGIME, against full-analysis ground truth on a 130 MB x86-64 library (this stage only
# ever runs above the 100 MB threshold, so a small-binary number does not characterise it — an
# earlier 6.1 MB sample read precision 1.000 / 63% of the gap and BOTH figures were optimistic):
#     135,273 references recovered, 742 of which full analysis does not produce
#     precision 0.9945 — a ~0.55% false-positive rate, written as SourceType.ANALYSIS
#     closes 21% of the gap the fast profile opens
# It is a PARTIAL recovery by construction: the rest are addresses computed across several
# instructions (MIPS lui/addiu, AArch64 adrp/add), which genuinely require propagation. The
# trade is deliberate — ~135k code->data references that otherwise do not exist at all, against a
# sub-1% error rate in a graph whose whole purpose is finding candidate leads to verify.
#
# The pass runs in RESUMABLE SLICES rather than one long pass. Two reasons, both measured:
#   * A full pass on a 160M-instruction image measured ~48 min as a SINGLE pass. That is over three
#     slices at the 15-min default below, and a restart-from-zero retry would truncate at the same
#     address forever, never converging. Each slice records how far it got (`through`) so the next
#     one starts there; `_DATA_REF_TOTAL_S` (6h) bounds the whole multi-slice run.
#   * Ghidra allows ONE writer per project. A slice holds that lock only for its own budget and
#     releases it between slices, so the per-call tools contend for minutes, not an hour.
def _env_num(name, default, cast=float, minimum=None):
    """Parse a numeric env override, falling back to `default` on anything unparseable.

    These are read at MODULE IMPORT, and this module backs decompile/xrefs/taint/emulate/script — a
    bare `float(os.environ[...])` would take the whole Ghidra surface down on one typo'd value
    rather than just mis-configuring the pass it belongs to."""
    try:
        value = cast(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = cast(default)
    return value if minimum is None else max(minimum, value)


# Per-SLICE wall clock, not the whole job (see above). Sized so the write lock is held in bounded
# windows; a monolith simply takes several slices.
_DATA_REF_SLICE_S = _env_num("HEXGRAPH_DATA_REF_SLICE_S", "900", float, 1.0)
# Total wall clock across all slices in one container run, so a runaway can't sit on the project.
_DATA_REF_TOTAL_S = _env_num("HEXGRAPH_DATA_REF_TOTAL_S", "21600", float, 1.0)
# References committed per transaction — see the chunking comment in recover_data_refs_core.
# Floored at 1: it is a modulus, so a 0 from the environment would be a ZeroDivisionError mid-pass.
_DATA_REF_TX_CHUNK = int(_env_num("HEXGRAPH_DATA_REF_TX_CHUNK", "250000", int, 1))


def recover_data_refs_core(program, monitor=None, *, budget_s=None, start_after=None,
                           save=True) -> dict:
    """Rebuild the statically-resolvable half of the code->DATA reference index in ONE linear pass.

    For every instruction operand that decodes to a Scalar which lands in mapped, NON-executable
    memory and has no reference from that instruction yet, add a DATA memory reference. Executable
    targets are skipped: control flow is already indexed by the passes the fast profile keeps, and
    they are not what a string/global xref query is asking for.

    `start_after` resumes: the scan begins at the instruction FOLLOWING that hex address, so a
    budget-truncated slice is continued rather than restarted (a restart would re-truncate at the
    same place and never converge). `budget_s` bounds this slice (default `_DATA_REF_SLICE_S`);
    on truncation the result carries `through`, the last address scanned, for the next slice.

    `save` persists via the mid-life `program.save()` the warm path requires —
    `pyghidra.program_context` releases the consumer WITHOUT saving, so an unsaved write is silently
    discarded on reopen (the same reason `_apply_rename` saves explicitly). Idempotent: a second
    pass over the same range adds 0.
    """
    from ghidra.program.model.scalar import Scalar
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    budget = _DATA_REF_SLICE_S if budget_s is None else float(budget_s)
    listing, mem = program.getListing(), program.getMemory()
    factory = program.getAddressFactory()
    # The space DATA lives in, which is not always the default one: on a Harvard-architecture or
    # overlay program code and data occupy separate spaces, and resolving a data address in the
    # default (code) space would silently produce addresses in the wrong space.
    space = None
    with contextlib.suppress(Exception):
        space = factory.getDefaultDataSpace()
    if space is None:
        space = factory.getDefaultAddressSpace()
    refmgr = program.getReferenceManager()

    start = None
    if start_after:
        with contextlib.suppress(Exception):
            start = factory.getAddress(start_after)

    t0 = time.time()
    scanned = added = chunks = 0
    truncated = False
    last_addr = None
    txid = program.startTransaction("hexgraph recover data refs")
    try:
        # `getInstructions(addr, True)` is inclusive of `addr`; the caller passes the last address
        # already DONE, so step past it rather than re-scanning it.
        it = listing.getInstructions(start, True) if start is not None else listing.getInstructions(True)
        if start is not None and it.hasNext():
            first = it.next()
            if first.getAddress() != start:
                it = listing.getInstructions(first.getAddress(), True)
        while it.hasNext():
            insn = it.next()
            scanned += 1
            # Check the clock rarely — time.time() per instruction is a measurable share of the pass.
            # Checked BEFORE this instruction is processed, and `last_addr` is only advanced AFTER
            # it is: `through` must name the last instruction actually SCANNED, never the one we
            # stopped at. Recording it up front would resume past an instruction neither slice
            # examined, silently dropping one instruction's references per slice boundary.
            if (scanned & 0xFFFF) == 0 and (time.time() - t0) > budget:
                truncated = True
                break
            existing = None                      # refs-from, fetched at most once per instruction
            for opnd in range(insn.getNumOperands()):
                for obj in (insn.getOpObjects(opnd) or []):
                    if not isinstance(obj, Scalar):
                        continue
                    try:
                        dest = space.getAddress(obj.getUnsignedValue())
                    except Exception:  # noqa: BLE001 - a scalar that is not a valid address
                        continue
                    block = mem.getBlock(dest)
                    if block is None or block.isExecute():
                        continue
                    # NOTE: an `isInitialized()` filter was measured here and REJECTED. The theory
                    # (a scalar landing in .bss is likelier a constant than a pointer) is reasonable,
                    # but in-regime it removed 2 of 742 false positives while discarding 8,664 TRUE
                    # ones — 0.3% of the error for 6.4% of the recall. `OperandType.isScalarAsAddress`
                    # is worse than useless here: that flag is set as a CONSEQUENCE of a reference
                    # existing, so under the fast profile it matches nothing and drops the pass to
                    # ZERO proposals. Re-measure before adding any further filter; both of these
                    # sounded right and one would have silently disabled the whole stage.
                    if existing is None:
                        existing = [r.getToAddress() for r in insn.getReferencesFrom()]
                    if dest in existing:
                        continue
                    refmgr.addMemoryReference(insn.getAddress(), dest, RefType.DATA,
                                              SourceType.ANALYSIS, opnd)
                    existing.append(dest)
                    added += 1
                    # Commit in CHUNKS to bound Ghidra's undo/redo buffer: a monolith yields ~10M
                    # references, and holding them all in one open transaction grows that buffer
                    # until the commit itself is what dies. NOTE this does NOT make the work durable
                    # incrementally — nothing reaches the project DB until the single `program.save()`
                    # below, so a kill mid-slice loses the whole slice. Durability across slices is
                    # the `through` marker's job, not the chunking's.
                    if added % _DATA_REF_TX_CHUNK == 0:
                        program.endTransaction(txid, True)
                        chunks += 1
                        txid = program.startTransaction("hexgraph recover data refs")
            last_addr = insn.getAddress()      # fully scanned — safe to resume after it
    finally:
        program.endTransaction(txid, True)
        chunks += 1

    saved, save_error = False, None
    if save and added:
        try:
            program.save("hexgraph recover data refs", monitor or ConsoleTaskMonitor())
            saved = True
        except Exception as exc:  # noqa: BLE001 - report it; never raise out of a best-effort stage
            save_error = str(exc)
    out = {"scanned": scanned, "added": added, "seconds": round(time.time() - t0, 1),
           "truncated": truncated, "saved": saved, "tx_chunks": chunks}
    # `through` is only meaningful when the slice stopped early AND its writes actually persisted;
    # advertising a resume point whose refs were never saved would skip that range on the next slice.
    if truncated and last_addr is not None and (saved or not added):
        out["through"] = last_addr.toString()
    elif truncated:
        out["through"] = None                    # save failed — the next slice must redo this range
    if save_error:
        out["save_error"] = save_error
    return out


def _clear_partial(proj_dir: str) -> None:
    """Wipe a partially-written slot before a cold re-import (marker + project dir)."""
    with contextlib.suppress(OSError):
        os.remove(os.path.join(PROJECT_MOUNT, META_NAME))
    with contextlib.suppress(OSError):
        if os.path.isdir(proj_dir):
            shutil.rmtree(proj_dir)
    os.makedirs(proj_dir, exist_ok=True)


# --- Cores (ported from the Jython scripts; the Ghidra Java API is identical) ---------------

def _apply_rename(program, flat, addr, new_name) -> bool:
    """Rename the function CONTAINING `addr` to `new_name` and PERSIST it (a transaction-wrapped
    write + save). Shared by the headless `--rename` path and the bridge `rename` op — a warm-opened
    program has no lingering analysis transaction, so `program.save()` commits cleanly mid-life
    (a resident bridge keeps serving from the same program afterward). Returns True on a rename."""
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    fn = None
    with contextlib.suppress(Exception):
        fn = flat.getFunctionContaining(flat.toAddr(addr))
    if fn is None:
        return False
    txid = program.startTransaction("hexgraph rename")
    ok = False
    try:
        fn.setName(new_name, SourceType.USER_DEFINED)
        ok = True
    except Exception:  # noqa: BLE001 — a bad name leaves the program unchanged
        ok = False
    finally:
        program.endTransaction(txid, ok)
    if ok:
        # Persist the rename. On the WARM path (a resident bridge, or a warm headless rename) this
        # explicit save is what makes it durable — open_target's warm branch closes the project
        # WITHOUT saving, and a resident bridge never exits. On the rare COLD headless rename (slot
        # not yet analyzed) auto-analysis leaves the DB transaction settling, so this save raises and
        # is suppressed — but there the rename still persists via open_program's context-exit
        # project.save (the #265 cold-analyze mechanism). Either way the rename sticks.
        with contextlib.suppress(Exception):
            program.save("hexgraph rename", ConsoleTaskMonitor())
    return ok


# The whole-program function-name inventory is returned in FULL (names are cheap) up to this defensive
# upper bound, always alongside `functions_total` (the true count). The old hard [:400] made a large
# firmware look like it had only 400 functions and hid the rest from list_functions entirely.
MAX_FUNCTION_NAMES = 20000


def decompile_core(program, flat, monitor, *, focus=None, rename=None) -> dict:
    """Ported POST_SCRIPT: whole-program inventory (functions/calls/structs) + a focused decompile
    with recovered facts. `focus` is a function NAME or hex ADDRESS; `rename` is (addr, new_name).
    The actual decompilation lives in `_focus_facts` (which opens its own DecompInterface)."""
    if rename:
        addr, new_name = rename
        if _apply_rename(program, flat, addr, new_name):
            focus = addr

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    all_names = [f.getName() for f in funcs]
    result = {"functions": all_names[:MAX_FUNCTION_NAMES], "functions_total": len(all_names),
              "focus": None, "calls": [], "structs": []}

    edges = []
    for f in funcs[:600]:
        with contextlib.suppress(Exception):
            for callee in f.getCalledFunctions(monitor):
                edges.append([f.getName(), callee.getName()])
                if len(edges) >= 2000:
                    break
        if len(edges) >= 2000:
            break
    result["calls"] = edges

    dtm = program.getDataTypeManager()
    with contextlib.suppress(Exception):
        for dt in dtm.getAllStructures():
            comps = dt.getComponents()
            builtin = False
            with contextlib.suppress(Exception):
                sa = dt.getSourceArchive()
                if sa is not None and str(sa.getArchiveType()) == "BUILTIN":
                    builtin = True
                else:
                    cp = dt.getCategoryPath().getPath()
                    if not cp.startswith("/DWARF") and ("/std" in cp or "/__" in cp):
                        builtin = True
            result["structs"].append({
                "name": dt.getName(), "size": dt.getLength(), "builtin": builtin,
                "fields": [{"name": c.getFieldName(), "type": str(c.getDataType()),
                            "offset": c.getOffset()} for c in comps[:64]]})
            if len(result["structs"]) >= 200:
                break

    if focus:
        target = None
        if _ADDR.match(focus):
            with contextlib.suppress(Exception):
                target = flat.getFunctionContaining(flat.toAddr(focus))
        else:
            target = next((f for f in funcs if f.getName() == focus), None)
        if target is not None:
            result["focus"] = _focus_facts(program, target, monitor)
    return result


def _focus_facts(program, target, monitor) -> dict:
    """The recovered facts for one function: pseudo-C + prototype/params/locals/callees (PREFER the
    decompiler's HighFunction over the listing-DB guess)."""
    from ghidra.app.decompiler import DecompInterface

    deci = DecompInterface()
    try:
        deci.openProgram(program)
        res = deci.decompileFunction(target, 60, monitor)
        pseudo, hf, df = "", None, None
        if res is not None and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df is not None:
                pseudo = df.getC()
            hf = res.getHighFunction()

        callees = []
        with contextlib.suppress(Exception):
            callees = [c.getName() for c in target.getCalledFunctions(monitor)]
        addr = None
        with contextlib.suppress(Exception):
            addr = "0x" + target.getEntryPoint().toString()

        prototype = None
        with contextlib.suppress(Exception):
            if df is not None:
                prototype = df.getSignature()
        if not prototype:
            with contextlib.suppress(Exception):
                prototype = target.getSignature().getPrototypeString()
        calling_convention = None
        with contextlib.suppress(Exception):
            calling_convention = target.getCallingConventionName()

        params, local_vars, from_hf = [], [], False
        if hf is not None:
            try:
                proto = hf.getFunctionPrototype()
                if proto is not None:
                    for i in range(proto.getNumParams()):
                        ps = proto.getParam(i)
                        params.append({"name": ps.getName(), "type": str(ps.getDataType())})
                pnames = {p["name"] for p in params}
                it = hf.getLocalSymbolMap().getSymbols()
                while it.hasNext():
                    sym = it.next()
                    if not sym.isParameter() and sym.getName() not in pnames:
                        local_vars.append({"name": sym.getName(), "type": str(sym.getDataType())})
                from_hf = True
            except Exception:
                params, local_vars, from_hf = [], [], False
        if not from_hf:
            with contextlib.suppress(Exception):
                params = [{"name": p.getName(), "type": str(p.getDataType())}
                          for p in target.getParameters()]
            with contextlib.suppress(Exception):
                pnames = {p["name"] for p in params}
                local_vars = [{"name": v.getName(), "type": str(v.getDataType())}
                              for v in target.getLocalVariables() if v.getName() not in pnames]

        focus = {"name": target.getName(), "resolved": target.getName(), "address": addr,
                 "pseudocode": pseudo, "disasm": "", "callees": callees}
        if prototype:
            focus["prototype"] = prototype
        if calling_convention:
            focus["calling_convention"] = calling_convention
        if params:
            focus["params"], focus["param_count"] = params, len(params)
        if local_vars:
            focus["locals"], focus["local_count"] = local_vars, len(local_vars)
        return focus
    finally:
        # A DecompInterface spawns a native `decompile` subprocess + its I/O threads. The RESIDENT
        # bridge serves thousands of decompiles off ONE long-lived process, so leaking an interface
        # per request exhausts threads (`pthread_create failed (EAGAIN)`) until every later decompile
        # fails to start its subprocess and returns an EMPTY body (signature + callees, no pseudo-C).
        # dispose() tears the subprocess down. (Headless never leaked — one process per call, so
        # process exit reclaimed it; only the resident bridge accumulates.) The focus dict above is
        # built entirely from extracted primitives, so disposing before the return is safe.
        with contextlib.suppress(Exception):
            deci.dispose()


# --- Taint: grounded P-Code source->sink data-flow (ported from TAINT_SCRIPT) --------------

# Library calls whose RETURN value is attacker-influenced (a taint source).
_SOURCE_RET = {"getenv", "getchar", "fgetc"}
# Buffer-filling input calls: name -> the 0-based C-arg index of the dest buffer (op input i+1).
_SOURCE_BUF = {"fgets": 0, "gets": 0, "fread": 0, "read": 1, "recv": 1, "recvfrom": 1, "pread": 1}
# Calls that COPY a (possibly tainted) source arg into a dest pointer = input[1].
_COPY_TO_DEST = {"strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove",
                 "stpcpy", "sprintf", "snprintf", "vsprintf", "vsnprintf"}
# Calls whose RETURN is tainted iff a source arg is (string locators/tokenizers/duplicators).
_COPY_TO_RET = {"strdup", "strndup", "strtok", "strtok_r", "strsep",
                "strchr", "strrchr", "strstr", "strpbrk"}
_SINK_EXEC = {"system", "popen", "execl", "execlp", "execle",
              "execv", "execvp", "execvpe", "execve"}
_SINK_OVERFLOW = {"strcpy", "strcat", "sprintf"}
_SINKS = _SINK_EXEC | _SINK_OVERFLOW
_SANITIZERS = {"sanitize", "escape", "quote", "filter", "validate", "clean", "encode"}


def taint_core(program, flat, monitor) -> dict:
    """Grounded P-Code source->sink taint over each function's HighFunction SSA (ported 1:1 from
    the Jython TAINT_SCRIPT; the Java API is identical). Marks untrusted SOURCES (params + returns
    of source calls + buffer-fill dest slots), propagates to a fixpoint through data ops AND
    string/mem copy calls, and reports every tainted value reaching a dangerous SINK. Returns
    `{taint: {flows, analyzed}}`. Intra-procedural (reachability stitches across the call graph)."""
    from java.lang import System
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp

    prop_ops = {PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ADD, PcodeOp.INT_SUB,
                PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_MULT,
                PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE,
                PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_DIV,
                PcodeOp.INT_REM, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.PTRADD, PcodeOp.PTRSUB,
                PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT, PcodeOp.LOAD}

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    def callee_name(op):
        t = op.getInput(0)
        if t is None:
            return None
        fa = None
        with contextlib.suppress(Exception):
            fa = flat.getFunctionAt(t.getAddress())
        return fa.getName() if fa is not None else None

    def addr_of(op):
        with contextlib.suppress(Exception):
            return "0x" + op.getSeqnum().getTarget().toString()
        return None

    def calls_a_sink(f):
        with contextlib.suppress(Exception):
            for c in f.getCalledFunctions(monitor):
                if c.getName() in _SINKS:
                    return True
        return False

    candidates = [f for f in funcs if not f.isExternal() and calls_a_sink(f)][:200]
    deci = DecompInterface()
    try:
        deci.openProgram(program)
        flows = []
        for f in candidates:
            res = None
            with contextlib.suppress(Exception):
                res = deci.decompileFunction(f, 60, monitor)
            if res is None or not res.decompileCompleted():
                continue
            hf = res.getHighFunction()
            if hf is None:
                continue

            tainted = set()        # identity hashes of value-tainted varnodes
            src_of = {}            # identity hash -> source descriptor
            tainted_slot = {}      # stack-slot key -> source descriptor

            def vmark(vn, desc):
                if vn is None:
                    return False
                h = System.identityHashCode(vn)
                if h in tainted:
                    return False
                tainted.add(h)
                src_of[h] = desc
                return True

            def slot_key(vn, depth=0):
                if vn is None or depth > 6:
                    return None
                d = vn.getDef()
                if d is None:
                    sp = None
                    with contextlib.suppress(Exception):
                        sp = vn.getAddress().getAddressSpace().getName()
                    return ("stk", sp, vn.getOffset()) if sp == "stack" else None
                mn = d.getMnemonic()
                if mn == "PTRSUB" and d.getNumInputs() == 2 and d.getInput(1).isConstant():
                    b = d.getInput(0)
                    bs = "?"
                    with contextlib.suppress(Exception):
                        bs = b.getAddress().getAddressSpace().getName()
                    return ("stk", bs, b.getOffset(), d.getInput(1).getOffset())
                if mn in ("COPY", "CAST"):
                    return slot_key(d.getInput(0), depth + 1)
                if mn == "INT_ADD" and d.getNumInputs() == 2 and d.getInput(1).isConstant():
                    return slot_key(d.getInput(0), depth + 1)
                return None

            def arg_taint(vn):
                if vn is None:
                    return None
                h = System.identityHashCode(vn)
                if h in tainted:
                    return src_of[h]
                k = slot_key(vn)
                if k is not None and k in tainted_slot:
                    return tainted_slot[k]
                return None

            # Sources A: function parameters.
            with contextlib.suppress(Exception):
                it = hf.getLocalSymbolMap().getSymbols()
                while it.hasNext():
                    sym = it.next()
                    if sym.isParameter():
                        hv = sym.getHighVariable()
                        if hv is not None:
                            for inst in hv.getInstances():
                                vmark(inst, {"kind": "param", "detail": sym.getName()})

            ops = list(hf.getPcodeOps())
            # Sources B/C: library-call sources in one pass over the CALL ops.
            for op in ops:
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                cn = callee_name(op)
                if cn in _SOURCE_RET and op.getOutput() is not None:
                    vmark(op.getOutput(), {"kind": "call_return", "detail": cn})
                elif cn in _SOURCE_BUF:
                    di = _SOURCE_BUF[cn] + 1
                    if op.getNumInputs() > di:
                        k = slot_key(op.getInput(di))
                        if k is not None and k not in tainted_slot:
                            tainted_slot[k] = {"kind": "libc_input", "detail": cn}

            # Forward propagation to a fixpoint over BOTH domains.
            changed, guard = True, 0
            while changed and guard < 4096:
                changed, guard = False, guard + 1
                for op in ops:
                    oc = op.getOpcode()
                    out = op.getOutput()
                    n = op.getNumInputs()
                    ins = [op.getInput(i) for i in range(n)]
                    if oc in prop_ops:
                        d = None
                        for v in ins:
                            d = arg_taint(v)
                            if d is not None:
                                break
                        if d is not None and out is not None and vmark(out, d):
                            changed = True
                    elif oc == PcodeOp.CALL:
                        cn = callee_name(op)
                        if cn in _COPY_TO_DEST and n > 2:
                            d = None
                            for i in range(2, n):
                                d = arg_taint(ins[i])
                                if d is not None:
                                    break
                            if d is not None:
                                k = slot_key(ins[1])
                                if k is not None and k not in tainted_slot:
                                    tainted_slot[k] = d
                                    changed = True
                        if cn in _COPY_TO_RET and out is not None:
                            d = None
                            for i in range(1, n):
                                d = arg_taint(ins[i])
                                if d is not None:
                                    break
                            if d is not None and vmark(out, d):
                                changed = True

            sanitizer_hits = set()
            for op in ops:
                if op.getOpcode() == PcodeOp.CALL and callee_name(op) in _SANITIZERS:
                    sanitizer_hits.add(callee_name(op))

            for op in ops:
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                cn = callee_name(op)
                cat, lo = None, 1
                if cn in _SINK_EXEC:
                    cat = "command_exec"
                elif cn in _SINK_OVERFLOW:
                    cat, lo = "buffer_overflow", 2
                if cat is None:
                    continue
                n = op.getNumInputs()
                hit_idx, src = None, None
                for i in range(lo, n):
                    d = arg_taint(op.getInput(i))
                    if d is not None:
                        hit_idx, src = i, d
                        break
                if hit_idx is None:
                    continue
                flows.append({
                    "function": f.getName(),
                    "function_addr": "0x" + f.getEntryPoint().toString(),
                    "source": src or {"kind": "unknown"},
                    "sink": {"func": cn, "category": cat,
                             "call_addr": addr_of(op), "arg_index": hit_idx},
                    "sanitized": sorted(sanitizer_hits),
                })
                if len(flows) >= 200:
                    break
            if len(flows) >= 200:
                break
        return {"taint": {"flows": flows, "analyzed": len(candidates)}}
    finally:
        # A DecompInterface spawns a native `decompile` subprocess + I/O threads; the resident
        # bridge reuses ONE across this whole taint op, so dispose it in a finally (like
        # _focus_facts — the candidate loop calls raw Java that can raise) to free it on every path.
        with contextlib.suppress(Exception):
            deci.dispose()


# --- Emulation: constant recovery via Ghidra's P-Code emulator (ported from EMU_SCRIPT) ------

def emulate_core(program, flat, monitor, focus) -> dict:
    """Emulate a self-contained parameterless routine in Ghidra's P-Code emulator and recover the
    constant it returns (no native execution — the routine runs inside the JVM interpreter).
    Ported 1:1 from EMU_SCRIPT. Returns `{emulation: {...}}`."""
    from ghidra.app.emulator import EmulatorHelper

    MAX_STEPS = 500000
    STACK_TOP = 0x10000000
    fm = program.getFunctionManager()
    ptr_size = program.getDefaultPointerSize()
    ret_sentinel = 0xbabecafe if ptr_size <= 4 else 0x0000babecafe0000

    target, err_msg = None, None
    if focus is not None:
        if _ADDR.match(focus):
            with contextlib.suppress(Exception):
                target = flat.getFunctionContaining(flat.toAddr(focus))
        else:
            matches = [f for f in fm.getFunctions(True) if f.getName() == focus]
            if len(matches) > 1:
                err_msg = (f"ambiguous function name {focus} ({len(matches)} matches) "
                           "- pass an address")
            elif matches:
                target = matches[0]

    if err_msg is not None:
        return {"emulation": {"error": err_msg}}
    if target is None:
        return {"emulation": {"error": f"function not found: {focus}"}}
    if target.getParameterCount() > 0:
        return {"emulation": {
            "function": target.getName(),
            "function_addr": "0x" + target.getEntryPoint().toString(),
            "param_count": target.getParameterCount(),
            "reached_ret": False, "steps": 0, "skipped": "arg_dependent",
            "error": (f"function takes {target.getParameterCount()} argument(s) — recover_constant "
                      "needs a self-contained, parameterless routine; use the solver instead"),
        }}

    ret = target.getReturn()
    ret_reg = ret.getRegister() if ret is not None else None
    ret_size = ret.getLength() if ret is not None else 0
    entry = target.getEntryPoint()

    emu = EmulatorHelper(program)
    pc_reg = emu.getPCRegister()
    sp_reg = emu.getStackPointerRegister()
    emu.writeRegister(sp_reg, STACK_TOP)
    emu.writeStackValue(0, ptr_size, ret_sentinel)
    emu.writeRegister(pc_reg, entry.getOffset())

    steps, reached_ret, err = 0, False, None
    while steps < MAX_STEPS:
        pc = emu.getExecutionAddress()
        if pc.getOffset() == ret_sentinel:
            reached_ret = True
            break
        try:
            ok = emu.step(monitor)
        except Exception:  # noqa: BLE001
            import traceback
            err = "step exception: %s" % traceback.format_exc().splitlines()[-1]
            break
        if not ok:
            err = emu.getLastError()
            break
        steps += 1

    emu_out = {
        "function": target.getName(),
        "function_addr": "0x" + entry.toString(),
        "steps": steps,
        "reached_ret": reached_ret,
        "return_register": ret_reg.getName() if ret_reg is not None else None,
    }
    if err:
        emu_out["error"] = err
    if not reached_ret and steps >= MAX_STEPS:
        emu_out["error"] = "step budget exhausted before return (%d)" % MAX_STEPS
    if reached_ret and ret_reg is not None:
        # readRegister returns a java.math.BigInteger; under jpype (unlike Jython) `int()` can't
        # consume it directly, so go via its decimal string. The mask normalizes to unsigned 64-bit.
        raw = int(str(emu.readRegister(ret_reg))) & 0xFFFFFFFFFFFFFFFF
        emu_out["value_hex"] = "0x%x" % raw
        if ret_size and ret_size < 8:
            mask = (1 << (ret_size * 8)) - 1
            emu_out["value"] = "0x%0*x" % (ret_size * 2, raw & mask)
            emu_out["width_bytes"] = ret_size
        else:
            emu_out["value"] = "0x%x" % raw
            emu_out["width_bytes"] = 8
    emu.dispose()
    return {"emulation": emu_out}


# --- Xrefs: cross-reference queries from the warm reference index (ported from XREFS_SCRIPT) --

_XREF_DEFAULT_SINKS = ["system", "popen", "execl", "execlp", "execle", "execv", "execvp",
                       "execve", "strcpy", "strcat", "gets", "scanf", "sscanf", "memcpy",
                       "alloca", "stpcpy"]
_XREF_FORMAT_SINKS = ["printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf",
                      "vfprintf", "vsprintf", "vsnprintf", "syslog", "vsyslog", "asprintf"]
_XREF_NETWORK_SINKS = ["socket", "bind", "listen", "accept", "accept4", "connect", "recv",
                       "recvfrom", "recvmsg", "read", "send", "sendto", "sendmsg",
                       "setsockopt", "getaddrinfo", "gethostbyname", "socketpair"]


def xrefs_core(program, flat, monitor, mode, subject) -> dict:
    """Cross-reference queries served from the program's already-built ReferenceManager index
    (ported from XREFS_SCRIPT). Mirrors the r2 xrefs_probe output contract key-for-key.
    `mode` is callers | function | data | callgraph | sinks; `subject` a symbol/address (None for
    callgraph/sinks). A symbol the index doesn't know returns `not_found` (NOT a top-level error)."""
    MAX_REFS, MAX_SINK_REFS = 200, 30
    MAX_GRAPH_FUNCS, MAX_GRAPH_EDGES = 600, 2000

    st = program.getSymbolTable()
    fm = program.getFunctionManager()
    refmgr = program.getReferenceManager()

    def _rt_name(ref):
        try:
            return ref.getReferenceType().getName()
        except Exception:  # noqa: BLE001
            return str(ref.getReferenceType())

    def _syms_named(name):
        # Resolve the symbol by name off the built symbol table. A leading '.' (a section-relative
        # or thunk decoration) is stripped so a bare name still resolves.
        base = (name or "").lstrip(".")
        forms = [base] if base else []
        out, seen = [], set()
        for form in forms:
            it = st.getSymbols(form)
            while it.hasNext():
                sym = it.next()
                key = id(sym)
                if key in seen:
                    continue
                seen.add(key)
                out.append(sym)
        return out

    def _caller_target_addrs(name):
        addrs, seen_a = [], set()

        def _add(a):
            if a is not None and a.toString() not in seen_a:
                seen_a.add(a.toString())
                addrs.append(a)

        for sym in _syms_named(name):
            a = sym.getAddress()
            _add(a)
            f = fm.getFunctionAt(a) if a is not None else None
            if f is not None:
                thunk_addrs = None
                try:
                    thunk_addrs = f.getFunctionThunkAddresses(True)
                except Exception:  # noqa: BLE001
                    with contextlib.suppress(Exception):
                        thunk_addrs = f.getFunctionThunkAddresses()
                for ta in (thunk_addrs or []):
                    _add(ta)
        return addrs

    def _callers_of(name):
        out, seen = [], set()
        for addr in _caller_target_addrs(name):
            for ref in refmgr.getReferencesTo(addr):
                frm = ref.getFromAddress()
                if frm is None:
                    continue
                caller = flat.getFunctionContaining(frm)
                if caller is None or caller.isThunk():
                    continue
                key = (caller.getName(), frm.toString())
                if key in seen:
                    continue
                seen.add(key)
                caddr = None
                with contextlib.suppress(Exception):
                    caddr = "0x" + caller.getEntryPoint().toString()
                out.append({"caller": caller.getName(), "caller_addr": caddr,
                            "at": "0x" + frm.toString(), "kind": _rt_name(ref)})
        return out

    def _resolve_function(subj):
        if _ADDR.match(subj):
            with contextlib.suppress(Exception):
                return flat.getFunctionContaining(flat.toAddr(subj))
            return None
        for sym in _syms_named(subj):
            f = None
            with contextlib.suppress(Exception):
                f = fm.getFunctionAt(sym.getAddress())
            if f is not None:
                return f
        return None

    def _callees_of(func):
        out, seen = [], set()
        called = []
        with contextlib.suppress(Exception):
            called = func.getCalledFunctions(monitor)
        for c in called:
            nm = c.getName()
            if nm in seen:
                continue
            seen.add(nm)
            addr = None
            with contextlib.suppress(Exception):
                addr = "0x" + c.getEntryPoint().toString()
            out.append({"name": nm, "addr": addr})
        return out

    if mode == "callgraph":
        edges = []
        for f in list(fm.getFunctions(True))[:MAX_GRAPH_FUNCS]:
            with contextlib.suppress(Exception):
                for callee in f.getCalledFunctions(monitor):
                    edges.append([f.getName(), callee.getName()])
                    if len(edges) >= MAX_GRAPH_EDGES:
                        break
            if len(edges) >= MAX_GRAPH_EDGES:
                break
        return {"mode": "callgraph", "calls": edges, "total": len(edges)}

    if mode == "function":
        func = _resolve_function(subject) if subject else None
        if func is None:
            return {"mode": "function", "subject": subject, "callers": [], "callees": [],
                    "total_callers": 0, "total_callees": 0, "not_found": True}
        callers = _callers_of(func.getName())
        callees = _callees_of(func)
        return {"mode": "function", "subject": subject,
                "callers": callers[:MAX_REFS], "callees": callees[:MAX_REFS],
                "total_callers": len(callers), "total_callees": len(callees)}

    if mode == "data":
        addr = None
        if subject and _ADDR.match(subject):
            with contextlib.suppress(Exception):
                addr = flat.toAddr(subject)
        if addr is None and subject:
            for sym in _syms_named(subject):
                a = sym.getAddress()
                if a is not None:
                    addr = a
                    break
        if addr is None:
            return {"mode": "data", "subject": subject, "data_refs": [], "total": 0,
                    "not_found": True}
        refs, seen = [], set()
        for ref in refmgr.getReferencesTo(addr):
            frm = ref.getFromAddress()
            if frm is None:
                continue
            fn = flat.getFunctionContaining(frm)
            fname = fn.getName() if fn is not None else "?"
            key = (fname, frm.toString())
            if key in seen:
                continue
            seen.add(key)
            refs.append({"from_function": fname, "at": "0x" + frm.toString(),
                         "kind": _rt_name(ref)})
        return {"mode": "data", "subject": subject,
                "data_refs": refs[:MAX_REFS], "total": len(refs)}

    if mode == "callers":
        refs = _callers_of(subject) if subject else []
        return {"mode": "callers", "symbol": subject,
                "callers": refs[:MAX_REFS], "total": len(refs)}

    # sinks sweep (no subject)
    def _sweep(names):
        grp = {}
        for s in names:
            refs = _callers_of(s)
            if refs:
                grp[s] = {"callers": refs[:MAX_SINK_REFS], "total": len(refs)}
        return grp

    return {"mode": "sinks", "sinks": _sweep(_XREF_DEFAULT_SINKS),
            "format_sinks": _sweep(_XREF_FORMAT_SINKS), "network": _sweep(_XREF_NETWORK_SINKS)}


# --- re_script: run an AGENT-SUPPLIED Python-3 script over the WARM program READ-ONLY -----------
# The escape-hatch (gated OFF by default). Since the PyGhidra re-platform the agent's script is real
# Python 3 (not a Jython postScript), so it runs IN-PROCESS against the resident program via exec()
# in a controlled namespace — no analyzeHeadless, no -postScript, no subprocess. The program is
# opened READ-ONLY by the caller (open_target(read_only=True) → getReadOnlyDomainObject) so the
# script can query the warm project but never mutate/corrupt it. Delivery is unchanged from the
# Jython path (HEXGRAPH_USER_SCRIPT_B64 → the probe → here); only the runtime moved in-process.

def script_core(program, flat, monitor, user_script, *, out_path=None, address_mapping=None) -> dict:
    """Run the agent-supplied Python-3 `user_script` body against the RESIDENT (read-only) program
    and return its JSON result. The script's namespace exposes:

        program  — the Ghidra Program (read-only DomainObject; writes are rejected by Ghidra)
        flat     — a FlatProgramAPI over it
        monitor  — a TaskMonitor
        out_path — a scratch file path; write your JSON result there (the built-in-core convention)
        getScriptArgs() — a shim returning [out_path] (so a script written to the postScript
                          `out_path = getScriptArgs()[0]` contract keeps working unchanged)
        address_mapping — the reported ELF PT_LOAD / Ghidra coordinate report
        file_offset_to_address(value) — translate an ELF file offset to a Ghidra Address
        address_to_file_offset(value) — translate a Ghidra Address/vaddr to an ELF file offset
        result   — OR: assign a JSON-serializable object to `result` instead of writing out_path

    The result is taken from an explicit `result` binding if the script set one, else parsed from
    whatever the script wrote to `out_path` (JSON). Any exception in the body is caught and returned
    as `{"error": ...}` (never propagated) so one bad script can't take down the probe/bridge. The
    body runs with normal Python builtins — the ISOLATION is the sandbox (no network, --read-only
    rootfs, dropped caps, non-root) + the read-only program, NOT a Python-level sandbox (which is
    not a real boundary); the same trust model as every other probe running in the hardened cell."""
    import traceback

    if out_path is None:
        out_path = os.path.join(SCRATCH, "hexgraph_user_script_out.json")
    # Start each run from a clean out_path so a stale prior file can't be mistaken for this result.
    with contextlib.suppress(OSError):
        if os.path.exists(out_path):
            os.remove(out_path)

    def _get_script_args():
        # Back-compat shim for scripts written to the Jython postScript contract (out_path = args[0]).
        return [out_path]

    def _file_offset_to_address(value):
        mapped = mapping_file_offset_to_vaddr(address_mapping, value)
        if mapped is None:
            raise ValueError(f"ELF file offset {_hex(_mapping_value(value))} is not file-backed")
        return flat.toAddr(mapped)

    def _address_to_file_offset(value):
        mapped = mapping_vaddr_to_file_offset(address_mapping, value)
        if mapped is None:
            raise ValueError(f"virtual address {_hex(_mapping_value(value))} is not file-backed")
        return mapped

    ns = {
        "__name__": "hexgraph_user_script",
        "__builtins__": __builtins__,
        "program": program,
        "currentProgram": program,  # Ghidra-habit alias for the same read-only program
        "flat": flat,
        "monitor": monitor,
        "out_path": out_path,
        "getScriptArgs": _get_script_args,
        "address_mapping": address_mapping,
        "file_offset_to_address": _file_offset_to_address,
        "address_to_file_offset": _address_to_file_offset,
        "result": None,
    }
    try:
        exec(compile(user_script, "<hexgraph_user_script>", "exec"), ns)  # noqa: S102 — see docstring
    except Exception as exc:  # noqa: BLE001 — a script fault is DATA, never a crash of the probe
        return {"tool": "ghidra_script", "error": f"user script exception: {exc}",
                "tb": traceback.format_exc()}

    # Prefer an explicit `result` binding; otherwise read the JSON the script wrote to out_path.
    res = ns.get("result")
    if res is not None:
        out = res if isinstance(res, dict) else {"result": res}
    else:
        try:
            with open(out_path) as fh:
                out = json.load(fh)
        except (OSError, ValueError) as exc:
            return {"tool": "ghidra_script",
                    "error": ("user script produced no result — assign a JSON-serializable object to "
                              f"`result` or write JSON to out_path ({exc})")}
    if not isinstance(out, dict):
        out = {"result": out}
    out.setdefault("tool", "ghidra_script")
    return out


# --- Byte/immediate search over the warm program's loaded memory -----------------------------

_MAX_SEARCH_HITS = 200  # bound a scan so a common pattern can't flood (mirrors xrefs_probe)


def _search_patterns(program, bytes_pattern, immediate):
    """The byte pattern(s) to scan for, as Python `bytes`. A hex `bytes_pattern` -> one pattern; an
    `immediate` -> the value encoded at the program's endianness in 4- AND 8-byte widths (so a
    constant stored as int32 OR int64 both match). Returns None when neither is given / invalid."""
    if bytes_pattern:
        try:
            return [bytes.fromhex(str(bytes_pattern).replace(" ", ""))]
        except ValueError:
            return None
    if immediate is not None:
        try:
            val = int(str(immediate), 0)  # 0x.. or decimal
        except (TypeError, ValueError):
            return None
        if val < 0:
            # Reject negatives to match the r2 fallback's _IMM (which has no leading `-`), so the same
            # `immediate` resolves identically on either backend. Search a two's-complement value via
            # bytes_pattern instead (e.g. `ffffffff` for -1).
            return None
        big = False
        with contextlib.suppress(Exception):
            big = program.getLanguage().isBigEndian()
        order = "big" if big else "little"
        pats = []
        for width in (4, 8):
            try:
                pats.append(val.to_bytes(width, order))
            except OverflowError:
                pass  # value doesn't fit this width
        return pats or None
    return None


def search_bytes_core(program, flat, monitor, *, bytes_pattern=None, immediate=None,
                      max_hits=_MAX_SEARCH_HITS) -> dict:
    """Scan the WARM program's already-loaded memory image for a BYTE pattern (hex) or an IMMEDIATE
    value, returning hits `[{addr, in_function}]` each mapped to its containing function (None for a
    data hit). This is the byte-scan analog of re_xrefs consulting the warm reference index: it
    reuses the resident/warm program — NO analysis — so it's a fast `Memory.findBytes` scan, NOT the
    whole-binary r2 `aaa` sweep that times out on a large target. Output mirrors the r2 xrefs_probe
    `search` contract so the host formats either backend identically. Exactly one of the inputs."""
    patterns = _search_patterns(program, bytes_pattern, immediate)
    term = ({"kind": "bytes", "pattern": bytes_pattern} if bytes_pattern
            else {"kind": "immediate", "value": immediate})
    if patterns is None:
        return {"tool": "ghidra_search", "mode": "search", **term,
                "error": "search needs a bytes_pattern (hex pairs) or an immediate value"}

    mem = program.getMemory()
    hits, seen = [], set()
    for pat in patterns:  # an immediate scans multiple widths
        addr = program.getMinAddress()
        while addr is not None and len(hits) < max_hits:
            found = None
            with contextlib.suppress(Exception):
                found = mem.findBytes(addr, pat, None, True, monitor)  # bytes -> byte[] via jpype
            if found is None:
                break
            off = found.getOffset()
            if off not in seen:
                seen.add(off)
                fn = flat.getFunctionContaining(found)
                hits.append({"addr": "0x" + found.toString(),
                             "in_function": fn.getName() if fn is not None else None})
            # add(1) throws AddressOverflowException at the very top of the space — stop cleanly
            # there rather than raise out of the core (which would drop the hits already found).
            try:
                addr = found.add(1)
            except Exception:  # noqa: BLE001
                break
        if len(hits) >= max_hits:
            break
    hits.sort(key=lambda h: int(h["addr"], 16))
    return {"tool": "ghidra_search", "mode": "search", **term,
            "hits": hits[:max_hits], "total": len(hits)}


def ghidra_version() -> str | None:
    """The GHIDRA application version (e.g. '12.1') from application.properties — the SAME token
    the Jython probe reported, so the persistent-project cache key (`<sha>__<version>`) is stable
    across the Jython->pyghidra flip. NOT pyghidra's own package version (3.1.0)."""
    props = os.path.join(os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra"),
                         "Ghidra", "application.properties")
    try:
        with open(props) as fh:
            for line in fh:
                if line.startswith("application.version"):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


# --- Resident bridge: serve the cores over a line-delimited JSON socket -----------------------
# HexGraph's OWN managed bridge (engine.re.bridge) keeps a warm project resident behind this tiny
# stdlib RPC — replacing the Jython analyzeHeadless + jfx_bridge harness. The transport is plain
# newline-delimited JSON over TCP (no ghidra_bridge/jfx_bridge dependency): the client sends a
# vetted, structured request; the server runs the matching in-process core and returns JSON — no
# remote_eval of Ghidra internals (a smaller surface than the researcher-Ghidra `_RemoteOps` path).

def bridge_dispatch(program, flat, monitor, req) -> dict:
    """Map one bridge request to a core call over the RESIDENT program. A live bridge OWNS the
    project, so EVERY Ghidra op for the target routes here instead of a conflicting headless open:
      `ping`     liveness + function count
      `list`     function inventory
      `decompile`  focus = name or 0xADDR
      `xrefs`    mode (callers|function|data|callgraph|sinks) + optional subject
      `taint`    grounded source->sink flows
      `emulate`  focus = a parameterless routine (constant recovery)
      `search`   bytes_pattern (hex) or immediate — a memory scan of the resident image
      `rename`   address + new_name — the one WRITE, persisted into the resident project via
                 `_apply_rename`'s mid-life save (so it sticks for future reads over the bridge)."""
    import traceback

    op = (req or {}).get("op")
    try:
        if op == "ping":
            return {"ok": True, "functions_total": program.getFunctionManager().getFunctionCount()}
        if op == "list":
            names = [f.getName() for f in program.getFunctionManager().getFunctions(True)]
            return {"functions": names[:MAX_FUNCTION_NAMES], "functions_total": len(names),
                    "tool": "ghidra_bridge"}
        if op == "decompile":
            result = decompile_core(program, flat, monitor, focus=req.get("focus"))
            result["tool"] = "ghidra_bridge"
            return result
        if op == "xrefs":
            return xrefs_core(program, flat, monitor, req.get("mode", "sinks"), req.get("subject"))
        if op == "taint":
            return taint_core(program, flat, monitor)
        if op == "emulate":
            return emulate_core(program, flat, monitor, req.get("focus"))
        if op == "search":
            return search_bytes_core(program, flat, monitor,
                                     bytes_pattern=req.get("bytes_pattern"),
                                     immediate=req.get("immediate"))
        if op == "rename":
            address, new_name = req.get("address"), req.get("new_name")
            if not address or not new_name:
                return {"error": "rename requires 'address' and 'new_name'"}
            result = decompile_core(program, flat, monitor, rename=(address, new_name))
            result["tool"] = "ghidra_bridge"
            return result
        return {"error": f"unknown bridge op {op!r}"}
    except Exception as exc:  # noqa: BLE001 — one bad request must NEVER kill the resident server
        return {"error": f"bridge op {op} failed: {exc}", "tb": traceback.format_exc()}


def _serve_one(conn, program, flat, make_monitor, address_mapping=None) -> None:
    """Handle one connection: read one JSON request line, dispatch, write one JSON response line.

    Mints a FRESH TaskMonitor for THIS request via `make_monitor()`. A resident bridge serves many
    requests off ONE long-lived program, so the monitor must NEVER be shared across them: Ghidra's
    `DecompInterface.decompileFunction(f, timeout, monitor)` CANCELS the monitor it is handed when
    the per-function timeout elapses, and a `ConsoleTaskMonitor` stays cancelled once cancelled — so
    a single slow function would poison EVERY later decompile into `decompileCompleted()==false`,
    i.e. an empty body (signature + callees, no pseudo-C). A per-request monitor can't leak that
    cancelled state between requests. (Headless never hit this — one process, one monitor, per call.)"""
    conn.settimeout(600)
    fh = conn.makefile("rwb")
    line = fh.readline()
    if not line:
        return
    try:
        req = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        resp = {"error": "bad request json"}
    else:
        resp = bridge_dispatch(program, flat, make_monitor(), req)
    if address_mapping is not None and isinstance(resp, dict):
        resp.setdefault("address_mapping", address_mapping)
        if address_mapping.get("warning"):
            resp.setdefault("warning", address_mapping["warning"])
    fh.write((json.dumps(resp) + "\n").encode("utf-8"))
    fh.flush()


def serve_bridge(host, port, program, flat, make_monitor, address_mapping=None) -> None:
    """Block forever serving line-delimited JSON bridge requests over TCP against the RESIDENT
    (program, flat). Single-threaded — Ghidra program access is NOT concurrency-safe, so one
    connection + one request at a time (two host processes serialize). The caller binds AFTER the
    project is open, so a host TCP-liveness probe only succeeds once the project can serve.

    `make_monitor` is a 0-arg factory (e.g. the `ConsoleTaskMonitor` class) invoked ONCE PER REQUEST
    so no request can inherit a prior one's cancelled monitor — see `_serve_one` for why that matters."""
    import socket

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    while True:
        try:
            conn, _addr = srv.accept()
        except OSError:
            continue
        try:
            _serve_one(conn, program, flat, make_monitor, address_mapping)
        except Exception:  # noqa: BLE001 — never let one connection kill the resident loop
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

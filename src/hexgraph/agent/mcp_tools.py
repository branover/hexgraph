"""MCP tool surface — HexGraph's primitives exposed to an external coding agent
(Claude Code / Codex / gemini-cli) in *driver* mode.

These are the safe, sandboxed operations the agent calls instead of touching the
target itself: read recon facts, decompile/inspect in the `--network none`
sandbox, search the graph, run a HexGraph task, and record findings. Each function
is pure-ish (opens its own session, returns JSON-able dicts) so the logic is
unit-testable without the MCP runtime; `mcp_server.py` wires these to the SDK.

The agent never receives target bytes — only tool output — exactly like the
in-process agent loop. `record_finding` validates against the frozen schema.
"""

from __future__ import annotations

import json

from hexgraph.db.models import Finding, Node, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import is_verified
from hexgraph.models.finding import Finding as FModel


def list_projects() -> list[dict]:
    with session_scope() as s:
        return [{"id": p.id, "name": p.name, "backend": p.llm_backend.value}
                for p in s.query(Project).all()]


def doctor(clean: bool = False) -> dict:
    """Reconcile the on-disk project dirs (under HEXGRAPH_HOME/projects/) against the DB and
    report drift: orphan dirs (no matching DB project) and DB projects whose dir is missing.
    Read-only by default; pass clean=true to DELETE orphan dirs (never a DB project — those
    go only through the explicit delete path). The CLI mirror is `hexgraph doctor [--clean]`."""
    from hexgraph.engine import maintenance

    with session_scope() as s:
        if clean:
            return maintenance.prune_orphan_dirs(s)
        return maintenance.project_dir_report(s)


def list_targets(project_id: str, include_hidden: bool = False) -> list[dict]:
    with session_scope() as s:
        q = s.query(Target).filter(Target.project_id == project_id, Target.archived.is_(False))
        if not include_hidden:
            # Hidden firmware children (unpack registers every ELF hidden) are excluded by
            # default — addressable/searchable, but they'd flood the list. Pass
            # include_hidden=true to enumerate them (then target_set_visible to reveal).
            q = q.filter(Target.visible.is_(True))
        rows = q.all()
        return [{"id": t.id, "name": t.name, "kind": t.kind.value, "arch": t.arch,
                 "parent_id": t.parent_id, "visible": t.visible} for t in rows]


# libc/shell sinks worth pointing a researcher straight at.
_DANGEROUS = {"system", "popen", "execve", "execl", "execlp", "execvp", "exec", "strcpy", "strcat",
              "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "alloca", "realpath"}


def target_facts(target_id: str) -> dict:
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        meta = t.metadata_json or {}
        imports = meta.get("imports", [])
        return {"id": t.id, "name": t.name, "kind": t.kind.value, "format": t.format, "arch": t.arch,
                "imports": imports, "exports": meta.get("exports", []),
                "libraries": meta.get("libraries", []), "mitigations": meta.get("mitigations", {}),
                # derived: which imports are classic vuln sinks — start here.
                "dangerous_imports": sorted(set(imports) & _DANGEROUS)}


def list_filesystem(target_id: str, path_prefix: str | None = None, offset: int = 0,
                    limit: int = 200, elf_only: bool = False) -> dict:
    """List a firmware target's unpacked filesystem (paths, sizes, which are ELFs / already
    child targets, and whether those child targets are REVEALED into the graph). Use it to
    find config files, scripts, keys, web assets to inspect — then read_file to view one, or
    target_set_visible to reveal a hidden ELF child.

    PAGINATED + filterable so it stays usable on a big firmware (a real image unpacks to
    hundreds-to-thousands of files): `path_prefix` scopes to a directory (e.g. "usr/sbin"),
    `elf_only` lists only binaries, `offset`/`limit` page (default 200, max 2000). The result's
    `total` + `next_offset` tell you the full size + where to page on. Returns {unpacked, method,
    files:[{rel,size,is_elf,added,revealed,child_target_id}], total, offset, next_offset,
    has_more} (added=a child target exists; revealed=it's visible in the graph — unpack registers
    ELF children hidden)."""
    from hexgraph.engine.targets.filesystem import list_filesystem as _ls

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        return _ls(s.get(Project, t.project_id), t, session=s,
                   path_prefix=path_prefix or None, offset=max(0, int(offset)),
                   limit=max(1, min(int(limit), 2000)), elf_only=bool(elf_only))


def read_file(target_id: str, path: str) -> dict:
    """Read ONE file from a firmware target's unpacked filesystem (a config, script, key,
    web template — NOT the raw binary; decompile_function for code). Bounded (256 KiB),
    path-traversal safe; text is returned as-is, binary as hex. `path` is relative to the
    firmware's extracted root (see list_filesystem). Returns {rel,size,encoding,content,truncated}."""
    from hexgraph.engine.targets.filesystem import FilesystemError, read_file as _read

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return _read(s.get(Project, t.project_id), t, path)
        except FilesystemError as exc:
            return {"error": str(exc)}


def promote_file(target_id: str, path: str) -> dict:
    """Promote ONE file from a firmware target's unpacked filesystem into its OWN child
    target so you can analyze it directly (decompile/list_functions/run_task/fuzz) — the
    bridge from browsing the rootfs to analyzing a binary in it. `path` is relative to the
    extracted root (see list_filesystem; an entry's `is_elf` flags a binary worth promoting,
    `added` means it's already a target). Real bytes → runs recon in the sandbox when Docker
    is up. Idempotent per path (returns the existing child if already promoted). Use it when
    list_filesystem surfaces an interesting binary (a CGI, a service daemon, a helper) that
    unpack didn't already register. Returns {id, name, kind, parent_id, arch}."""
    from hexgraph.engine.targets.filesystem import FilesystemError, promote_file as _add

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            child = _add(s, s.get(Project, t.project_id), t, path)
        except FilesystemError as exc:
            return {"error": str(exc)}
        return {"id": child.id, "name": child.name, "kind": child.kind.value,
                "parent_id": target_id, "arch": (child.metadata_json or {}).get("arch")}


def list_source_trees(project_id: str) -> dict:
    """List the project's managed SOURCE trees (trusted source we possess/build —
    NOT the hostile target; harnesses/PoCs/scripts live here as role-tagged
    source_files). Returns {source_trees:[{id,name,origin,editable,file_count,
    target_ids}]}. Use read_source_file to view one tree's files."""
    from hexgraph.engine.build.source import list_source_trees as _ls

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        return {"source_trees": _ls(s, p)}


def read_source_file(tree_id: str, rel: str | None = None) -> dict:
    """Browse/read a managed SOURCE tree. Omit `rel` to LIST the tree's files
    (rel/size/role); pass `rel` to READ one file's text (bounded, traversal-safe;
    binary as hex). This is trusted source text (a harness/PoC/build recipe or
    imported library source) — distinct from read_file (a firmware's hostile
    unpacked bytes). Returns the file listing or {rel,size,role,encoding,content}."""
    from hexgraph.engine.build.source import (
        SourceError, list_source_files, read_source_file as _read,
    )
    from hexgraph.db.models import SourceTree

    with session_scope() as s:
        tree = s.get(SourceTree, tree_id)
        if tree is None:
            return {"error": "source tree not found"}
        p = s.get(Project, tree.project_id)
        if rel is None:
            return list_source_files(s, p, tree)
        try:
            return _read(p, tree, rel)
        except SourceError as exc:
            return {"error": str(exc)}


def create_project(name: str, backend: str | None = None) -> dict:
    """Create a new EMPTY project (no target required) and return {id, name, backend} —
    the source-first entry point. `ingest` only makes a project alongside a binary/firmware
    path, so a pure source/fuzzing workflow (import_source_tree → build_target → fuzz) starts
    here, then feeds the returned id to those tools. `backend` is the LLM backend
    (mock|anthropic|claude_code; defaults to mock). Returns {error} on a blank name or an
    unknown backend."""
    from hexgraph.db.models import LLMBackendName
    from hexgraph.engine.targets.ingest import create_project as _create

    name = (name or "").strip()
    if not name:
        return {"error": "project name is required"}
    backend = backend or "mock"
    try:
        LLMBackendName(backend)
    except ValueError:
        choices = "|".join(b.value for b in LLMBackendName)
        return {"error": f"unknown backend {backend!r}; choose one of {choices}"}
    with session_scope() as s:
        p = _create(s, name=name, llm_backend=backend)
        return {"id": p.id, "name": p.name, "backend": p.llm_backend.value}


def import_source_tree(project_id: str, name: str, files: list | None = None,
                       origin: str = "scratch") -> dict:
    """Create a managed SOURCE tree and (optionally) populate it with files. `files`
    is a list of {rel, content, role?} (role in code|harness|poc|script|build_recipe);
    `path` is accepted as an alias for `rel`. Use this to bring in a harness/PoC you
    authored or a small library's source for later building. Trusted text only (NOT target
    bytes — those are added as targets). Returns {id, name, written}; a malformed `files`
    entry (not an object, or missing both `rel` and `path`) is reported as an ERROR rather
    than silently skipped, so a wrong-key call never looks like a successful 0-file import."""
    from hexgraph.engine.build.source import SourceError, create_source_tree, write_source_file

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        # Validate the shape BEFORE creating the tree — surface a wrong key (the common
        # `path`-instead-of-`rel` slip) as a clear error instead of a silent no-op success.
        for i, f in enumerate(files or []):
            if not isinstance(f, dict):
                return {"error": f"files[{i}] must be an object {{rel, content, role?}}, got {type(f).__name__}"}
            if not (f.get("rel") or f.get("path")):
                return {"error": f"files[{i}] is missing `rel` (the relative path); "
                                 f"got keys {sorted(f.keys())}"}
        try:
            tree = create_source_tree(s, p, name=name, origin=origin, editable=True)
            written = 0
            for f in (files or []):
                rel = f.get("rel") or f.get("path")
                write_source_file(s, p, tree, rel, f.get("content", ""),
                                  role=f.get("role", "code"))
                written += 1
        except SourceError as exc:
            return {"error": str(exc)}
        return {"id": tree.id, "name": tree.name, "written": written}


def link_finding_to_source(finding_id: str, tree_id: str, rel: str,
                            line: int | None = None, col: int | None = None) -> dict:
    """Link a finding to its location in a managed source file (a `located_in` edge
    + evidence.extra.source_ref) — the jump-from-finding-to-source link, so the IDE
    opens the file at the line. `tree_id`/`rel` from list_source_trees/read_source_file.
    Use this when a vuln/harness corresponds to known source. Returns {node_id,rel}."""
    from hexgraph.db.models import Finding, SourceTree
    from hexgraph.engine.build.source import SourceError, link_finding_to_source as _link

    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return {"error": "finding not found"}
        tree = s.get(SourceTree, tree_id)
        if tree is None or tree.project_id != f.project_id:
            return {"error": "source tree not found in this project"}
        try:
            node = _link(s, s.get(Project, f.project_id), finding_id=finding_id,
                         tree=tree, rel=rel, line=line, col=col)
        except SourceError as exc:
            return {"error": str(exc)}
        return {"node_id": node.id, "tree_id": tree_id, "rel": rel}


def list_builds(project_id: str, source_tree_id: str | None = None) -> dict:
    """List builds in a project (the build ledger) — each with status, the
    reproducibility triple (recipe_sha/source_content_hash/toolchain_digest),
    artifacts as CAS shas, and the instrumented derived_target_id it registered.
    Optionally filter by source_tree_id. Returns {build_specs, builds}."""
    from hexgraph.engine.build import builds as B

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        return {"build_specs": B.list_build_specs(s, p, source_tree_id=source_tree_id),
                "builds": B.list_builds(s, p, source_tree_id=source_tree_id)}


def build_log(build_id: str) -> dict:
    """The full build log (stdout+stderr of every phase, from CAS) for a build — the
    recipe-iteration signal on a FAILED build: read it to see WHY a compile/instrumentation
    step failed (a missing header, a flag the sanitizer rejected, a cross-compile sysroot
    miss), then fix `phases`/`env`/`arch` and rebuild. `build_id` from list_builds. Returns
    {build_id, status, returncode, error, log}."""
    from hexgraph.db.models import Build
    from hexgraph.engine import cas

    with session_scope() as s:
        b = s.get(Build, build_id)
        if b is None:
            return {"error": "build not found"}
        text = cas.get_text(s.get(Project, b.project_id), b.log_cas) if b.log_cas else None
        return {"build_id": build_id, "status": b.status, "returncode": b.returncode,
                "error": b.error, "log": text or ""}


def import_oss_fuzz(project_id: str, source_tree_id: str, build_sh: str,
                    instrumentation: dict | None = None, artifacts: list | None = None) -> dict:
    """Import an OSS-Fuzz-style `build.sh` into a recorded build_spec so an existing
    OSS-Fuzz target builds in HexGraph with minimal hand-authoring. The script is stored
    in the tree (role=script); HexGraph maps the OSS-Fuzz env contract ($CC/$CXX/$CFLAGS/
    $LIB_FUZZING_ENGINE/$SRC/$OUT) to ours, so the script runs essentially unchanged via a
    single shell phase. The tree must be EDITABLE. Returns the build_spec; then build_target
    (or POST builds with the spec id) runs it. Detects the $OUT/<name> fuzz targets to capture."""
    from hexgraph.db.models import SourceTree
    from hexgraph.engine.build import builds as B
    from hexgraph.engine.build.build import BuildError
    from hexgraph.engine.build.source import SourceError

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        tree = s.get(SourceTree, source_tree_id)
        if tree is None or tree.project_id != project_id:
            return {"error": "source tree not found in this project"}
        try:
            row = B.import_oss_fuzz_build(s, p, tree, build_sh=build_sh,
                                          instrumentation=instrumentation, artifacts=artifacts)
        except (BuildError, SourceError) as exc:
            return {"error": str(exc)}
        return B.spec_to_dict(row)


def save_source_revision(tree_id: str, rel: str, content: str, role: str | None = None,
                         note: str | None = None) -> dict:
    """Edit a HexGraph-AUTHORED source file (a harness/PoC/script you wrote) and save it as
    a NEW REVISION — never an in-place mutation, so the edit is durable + reversible and a
    build can be launched rebuild-from-revision (pass the returned revision id as the
    recipe's source_revision_id). SCRATCH/HexGraph-authored trees are editable by default;
    editing OTHER authored trees needs features.source.edit. ALWAYS REFUSES an imported/
    extracted/vendor (read-only) tree — editing those would break the build content_hash.
    Returns the revision {id, seq, rel, role, ...}. Use to iterate on a harness/PoC in-place."""
    from hexgraph.db.models import SourceTree
    from hexgraph.engine.build import revisions as R
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        tree = s.get(SourceTree, tree_id)
        if tree is None:
            return {"error": "source tree not found"}
        p = s.get(Project, tree.project_id)
        try:
            return R.save_revision(s, p, tree, rel, content, role=role, note=note)
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc}"}
        except R.SourceError as exc:
            return {"error": str(exc)}


def coverage_diff(campaign_id: str, other_campaign_id: str) -> dict:
    """Run-to-run COVERAGE DIFF between two fuzz campaigns: what NEW source lines did
    `other_campaign_id` reach that `campaign_id` (the base) did not (and which did it
    lose)? The 'did this run reach new edges?' answer — use to judge whether a harness/
    corpus/engine change actually improved reach. Returns per-file {gained, lost} + totals;
    `available=False` when either campaign exposed no per-line coverage map."""
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine.fuzz import campaigns as C

    with session_scope() as s:
        base = s.get(FuzzCampaign, campaign_id)
        oth = s.get(FuzzCampaign, other_campaign_id)
        if base is None or oth is None:
            return {"error": "campaign not found"}
        if base.project_id != oth.project_id:
            return {"error": "campaigns belong to different projects"}
        return C.coverage_diff(s, base, oth)


def build_target(project_id: str, source_tree_id: str, system: str | None = None,
                 phases: list | None = None, instrumentation: dict | None = None,
                 artifacts: list | None = None, env: dict | None = None,
                 arch: str | None = None, network: str | None = None,
                 fetch_phases: list | None = None, source_revision_id: str | None = None) -> dict:
    """Build a managed SOURCE tree into an INSTRUMENTED artifact in the sandbox via a
    RECORDED, REPRODUCIBLE recipe (build-as-API). You author/approve a BuildSpec and
    REQUEST the build — you never run a compiler yourself; HexGraph runs the recipe.

    The recipe: `system` (make|cmake|autotools|meson|cargo|go|custom — auto-detected if
    omitted), `phases` (ordered explicit-argv steps, recorded verbatim; default phases
    are derived from the system), `instrumentation` ({sanitizers:[address,undefined,…],
    coverage:[sancov|afl_pcguard], engine:libfuzzer|afl}), `artifacts` (rel paths to
    capture — the fuzz target/.so/binary), `env` (NON-secret build env — secrets are
    rejected). Instrumentation is INJECTED as CC/CXX/CFLAGS by HexGraph (the base-image
    contract), so the SAME phases yield ASan/SanCov/AFL++ builds by swapping the profile.

    CROSS-COMPILE: pass `arch` (mips/mipsel/arm/armhf/aarch64/…) to cross-build for a
    firmware's arch — HexGraph injects clang --target + the parent firmware's extracted
    rootfs as the --sysroot, so the instrumented binary is binary-compatible with the
    device userland (runs under qemu-user; a cross-build failure degrades to qemu-mode
    binary-only fuzzing of the original).

    DEPENDENCIES: `network` defaults 'none' (VENDORED/OFFLINE — fully reproducible, the
    recommendation). 'fetch' (requires features.build_fetch) runs a SEPARATE, audited,
    ALLOWLISTED fetch phase (`fetch_phases`, default per system) that hash-pins deps into a
    LOCKFILE, then DROPS NETWORK and compiles --network none — a fetched dep can never run
    during compile or exfiltrate. The build records a LOCKFILE + SBOM-lite + a reproducibility
    BADGE. Reproducibility: recipe_sha=hash{phases,fetch_phases,env,base_image,instrumentation,
    arch}; same recipe_sha + source content_hash + toolchain_digest (+ lockfile) ⇒ the same
    build — a cache HIT REUSES the prior CAS artifact (skips the rebuild).

    `source_revision_id` builds from a specific editable-IDE revision (rebuild-from-revision).
    If the source tree is built_from a target, the rebuild is registered as a DERIVED target
    wired instrumented_build_of→ the original — ready for coverage-guided fuzzing. Requires
    features.build (else error)."""
    from hexgraph.engine.build import builds as B
    from hexgraph.engine.build.build import BuildError, BuildSpec, CROSS_TRIPLES
    from hexgraph.policy import PolicyViolation, assert_allows_build

    try:
        assert_allows_build()
    except PolicyViolation:
        return {"error": "building not permitted — enable features.build in Settings"}
    with session_scope() as s:
        from hexgraph.db.models import SourceTree

        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        tree = s.get(SourceTree, source_tree_id)
        if tree is None or tree.project_id != project_id:
            return {"error": "source tree not found in this project"}
        detected = B.propose_build_spec(tree)
        net = network or "none"
        fp = fetch_phases
        if net == "fetch" and fp is None:
            fp = [ph.to_dict() for ph in B.default_fetch_phases(system or detected["system"])]
        # Cross-build sysroot: the parent firmware's extracted rootfs (best-effort; native
        # fallback degrades to qemu-mode binary-only fuzzing per §3.4).
        sysroot = None
        eff_arch = arch or "x86_64"
        if CROSS_TRIPLES.get(eff_arch.lower()):
            origin = B._origin_target(s, p, tree)
            if origin is not None and origin.parent_id:
                from hexgraph.db.models import Target
                fw = s.get(Target, origin.parent_id)
                if fw is not None and (fw.metadata_json or {}).get("filesystem"):
                    try:
                        from pathlib import Path as _P
                        from hexgraph.engine.targets.filesystem import host_root as _fs
                        from hexgraph.engine.findings.poc import _find_sysroot
                        r = _find_sysroot(_fs(p, fw))
                        sysroot = str(r) if r and _P(str(r)).is_dir() else None
                    except Exception:  # noqa: BLE001
                        sysroot = None
        try:
            spec = BuildSpec.from_dict({
                "source_tree_id": tree.id,
                "system": system or detected["system"],
                "phases": phases if phases is not None else detected["phases"],
                "fetch_phases": fp or [],
                "instrumentation": instrumentation or {},
                "artifacts": artifacts or [],
                "env": env or {},
                "arch": eff_arch,
                "network": net,
                "sysroot": sysroot,
            })
            spec_row = B.create_build_spec(s, p, spec)
            if source_revision_id:
                build = B.rebuild_from_revision(s, p, spec_row, source_revision_id)
            else:
                build = B.run_build(s, p, spec_row)
        except BuildError as exc:
            return {"error": str(exc)}
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc}"}
        return B.build_to_dict(build)


# ── Fuzz campaigns (run/read) — design §5.7. The LLM REQUESTS a campaign; HexGraph
# spawns + reaps a detached sandbox container. The model never runs afl-fuzz. ──────

def start_fuzz_campaign(target_id: str, surface: str | None = None, engine: str | None = None,
                        function: str | None = None, max_total_time: int | None = None,
                        max_len: int | None = None, max_crashes: int | None = None,
                        instances: int | None = None, seeds: list | None = None,
                        dictionary: list | None = None,
                        host: str | None = None, port: int | None = None,
                        protocol: str | None = None, proto_spec: dict | None = None,
                        launch: bool | None = None, launch_binary: str | None = None,
                        launch_command: list | None = None,
                        bug_oracles: bool | None = None, path_coverage: int | None = None,
                        cmplog: bool | None = None,
                        resources: dict | None = None, environment: str | None = None) -> dict:
    """Start a fuzz CAMPAIGN on a target; returns immediately with {id, status:'running'}.
    HexGraph spawns a DETACHED hardened sandbox container that fuzzes continuously + a
    reaper streams crashes → fuzz_crash findings (each one-click-re-verifiable). The model
    never runs a fuzzer.

    The `surface` is auto-inferred from the target; the engine defaults per surface
    (override with `engine`): source_lib→afl (coverage-guided, needs features.fuzzing/poc),
    binary_only→qemu-mode (no source; full coverage via QEMU TCG; foreign-arch MIPS/ARM via
    qemu-user + the parent firmware rootfs as sysroot; needs features.fuzzing/poc),
    network→boofuzz (a LIVE service over a real socket — needs features.network, bounded to
    loopback/private + every send audited; pass host/port if not recorded on the target, or
    engine='desock' to coverage-fuzz a LOCAL server binary with --network none). For a LOCAL
    service HexGraph can START itself (a launchable server binary + no externally-reachable
    host), it uses LAUNCH-AND-JOIN: it starts the service in its OWN hardened container and
    joins the fuzzer to that container's netns so 127.0.0.1:port is reachable WITHOUT
    --network host (needs features.network for the fuzz egress + features.fuzzing/poc to run
    the service). `launch` forces it on (auto-detected otherwise); `launch_binary` overrides
    the server ELF path. To fuzz a service ALREADY running on your host, bind it to a
    reachable private IP (192.168/10.x) — a fuzz container's bridge cannot reach the host's
    bare 127.0.0.1; launch-and-join is the supported way to fuzz a service HexGraph starts.
    file_format
    →afl + an auto-dictionary. A crash becomes a re-verifiable finding climbing the assurance
    ladder: a binary-only crash is code_present/dynamic; a network service-death is
    input_reachable/dynamic (reached + triggered end-to-end through the live input boundary).
    NOTE: remote blind network-fuzz of a physical bench device is OFF by default (destructive
    — prefer replay/PoC).

    AFL source-fuzz (source_lib/file_format) instrumentation knobs (each defaults to its
    features.fuzzing.* setting when omitted): `bug_oracles` enables AFL++ 5.x's bug-detection
    oracles (SCALAR/BUDGET/SIZEFILL/ALLOCSIZE/SLACK — catches arithmetic/OOB bugs ASan alone
    misses); `path_coverage` (1=relaxed, 2=restricted, 3=strict Ball-Larus) adds per-function
    path sensitivity (more coverage signal, more overhead); `cmplog` builds the CmpLog `-c`
    binary to defeat magic-byte/memcmp gates. Ignored by the binary-only/network engines.

    `environment` selects WHERE the container runs (design §5.8b): omit / 'local' for the
    host Docker daemon, or a registered remote fuzz-environment id (see
    list_fuzz_environments) to run the WHOLE campaign on a beefier user-owned remote Docker
    host — building + fuzzing run there with no analysis change, gated by
    features.fuzz_remote, the SAME sandbox boundary, connection details secret + audited."""
    from hexgraph.db.models import Task as _Task
    from hexgraph.engine.fuzz import campaigns as C
    from hexgraph.engine.fuzz import fuzz_env as FE
    from hexgraph.engine.fuzzers import FuzzCampaignSpec
    from hexgraph.engine.fuzz.fuzzing import resolve_harness, resolve_target_sources
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        p = s.get(Project, t.project_id)
        fake = _Task(project_id=p.id, target_id=t.id, type="fuzzing", params_json={})
        source, _fid, fn = resolve_harness(s, t, fake)
        sources = resolve_target_sources(t, fake)
        spec = FuzzCampaignSpec(
            target_id=t.id, surface=surface or C.infer_surface(t), engine=engine,
            harness_source=source, function=function or fn, target_sources=sources,
            max_total_time=max_total_time or 60, max_len=max_len or 4096,
            max_crashes=max_crashes or 10, instances=instances or 1,
            seeds=seeds or [], dictionary=dictionary or [],
            host=host, port=port,
            protocol=protocol or "tcp", proto_spec=proto_spec,
            launch=launch, launch_binary=launch_binary, launch_command=launch_command,
            bug_oracles=bug_oracles, path_coverage=path_coverage, cmplog=cmplog,
            environment_id=environment,
        )
        try:
            row = C.start_campaign(s, p, t, spec=spec, resources=resources)
        except (C.CampaignError, FE.FuzzEnvError, ValueError) as exc:
            return {"error": str(exc)}
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc} (features.fuzzing/poc for binary fuzzing; "
                             "features.network for live network fuzzing; features.fuzz_remote "
                             "for a remote environment)"}
        return C.campaign_to_dict(row)


def list_fuzz_environments(project_id: str | None = None) -> dict:
    """List registered fuzz ENVIRONMENTS — where a campaign's container can run (design
    §5.8b): `local` (the host Docker daemon) + N user-owned remote Docker hosts. Each
    carries the non-secret label/descriptor, the ResourceSpec ceiling, presence-only
    connection status (`connection_present` — the secret DOCKER_HOST/creds are in
    env/config.toml, never stored/returned), and the cached health-check. Pass the
    `environment` id to start_fuzz_campaign to run a campaign there (gated by
    features.fuzz_remote)."""
    from hexgraph.engine.fuzz import fuzz_env as FE

    with session_scope() as s:
        return {"environments": FE.list_environments(s)}


def fuzz_environment_health(environment_id: str) -> dict:
    """Health-check a remote fuzz environment: is it reachable + authorized + does it have
    the fuzz image present (the one-time remote build/pull). Gated by features.fuzz_remote.
    Returns a NON-SECRET dict {ok, reachable, authorized, image_present, docker_version,
    detail} — the connection string is never echoed."""
    from hexgraph.engine.fuzz import fuzz_env as FE
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        try:
            return FE.health_check(s, environment_id)
        except FE.FuzzEnvError as exc:
            return {"error": str(exc)}
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc}"}


def stop_fuzz_campaign(campaign_id: str) -> dict:
    """Stop a running fuzz campaign — kills the container PRESERVING the corpus in CAS
    (resumable). Reaps any final crashes first so nothing is lost."""
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine.fuzz import campaigns as C

    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            return {"error": "campaign not found"}
        return C.campaign_to_dict(C.stop_campaign(s, c))


def resume_fuzz_campaign(campaign_id: str) -> dict:
    """Resume a FINISHED fuzz campaign (stopped/completed/failed/degraded), re-seeded from
    its preserved CAS corpus so it continues accumulating coverage + crashes instead of
    starting cold — the other half of stop_fuzz_campaign's 'resumable'. AFL++ resumes
    natively from the snapshot. The surface-correct policy gate is re-applied inside (exec
    for a binary/source campaign, egress for a live-socket network campaign) — NO new gate.
    Returns the campaign dict ({id, status:'running', …}); poll fuzz_status as before."""
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine.fuzz import campaigns as C
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            return {"error": "campaign not found"}
        try:
            return C.campaign_to_dict(C.resume_campaign(s, c))
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc}; enable the matching gate in Settings "
                             "(features.fuzzing/poc to execute a binary/source campaign, "
                             "features.network for a live-socket one)"}
        except (C.CampaignError, ValueError) as exc:
            # A network-tier egress denial arrives here wrapped as CampaignError (start_campaign
            # re-applies the gate); its message already states the reason, so surface it as-is.
            return {"error": str(exc)}


def fuzz_status(campaign_id: str) -> dict:
    """Live status + stats of a campaign (execs, edges_covered, crash_count, coverage,
    status). Reaps on read so the figures are fresh. Poll this while a campaign runs."""
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine.fuzz import campaigns as C

    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            return {"error": "campaign not found"}
        try:
            C.reap_campaign(s, c)
        except Exception:  # noqa: BLE001
            s.rollback()
            c = s.get(FuzzCampaign, campaign_id)
        return C.campaign_to_dict(c)


def list_fuzz_artifacts(campaign_id: str) -> dict:
    """List a campaign's deduplicated artifacts (crash/hang/leak/oom/corpus) — each with
    the normalized dedup_key, dupe_count, sanitizer kind, faulting function, deterministic
    exploitability, the CAS reproducer sha (re-runnable via verify_poc), and the
    fuzz_crash finding it produced."""
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine.fuzz import campaigns as C

    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            return {"error": "campaign not found"}
        return {"campaign_id": campaign_id, "artifacts": C.list_artifacts(s, c)}


def minimize_artifact(artifact_id: str) -> dict:
    """Re-verify a crash artifact's reproducer by replaying its stored, CAS
    content-addressed minimized input IN THE SANDBOX — the crash→verify tie-in. A binary/
    harness crash replays the input against the instrumented binary (the unforgeable
    `crash` oracle); a NETWORK crash re-sends its crashing message over the live socket +
    a liveness oracle. LLM-free; the surface-correct gate is applied inside verify_artifact.
    Returns {verified, detail, assurance}."""
    from hexgraph.db.models import FuzzArtifact
    from hexgraph.engine.fuzz import campaigns as C
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        a = s.get(FuzzArtifact, artifact_id)
        if a is None:
            return {"error": "artifact not found"}
        if not a.content_cas:
            return {"error": "artifact has no stored reproducer to re-verify"}
        try:
            res = C.verify_artifact(s, a)
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc}"}
        except (C.CampaignError, ValueError) as exc:
            return {"error": str(exc)}
        return {"artifact_id": artifact_id, "verified": bool(res.get("verified")),
                "detail": res.get("detail"), "assurance": res.get("assurance")}


def verify_fuzz_artifact(artifact_id: str) -> dict:
    """Replay a fuzz crash ARTIFACT byte-faithfully against its harness/binary and report
    whether it still crashes (the unforgeable `crash` oracle) + the assurance rung. This is
    the first-class 'verify this crash reproducer' verb (battle-test GAP: re-verify was only
    reachable via the misleadingly-named `minimize_artifact`; `verify_poc` corrupts a binary
    reproducer over text-mode stdin). The reproducer is materialized from CAS and mounted as
    a FILE (raw bytes — 0x00/0xff preserved exactly, never text-encoded) and run against the
    campaign's preserved instrumented harness binary; a NETWORK crash re-sends its crashing
    message over the live socket + a liveness oracle. LLM-free; the surface-correct exec/egress
    gate is applied inside. Returns {artifact_id, verified, detail, assurance, output}."""
    from hexgraph.db.models import FuzzArtifact
    from hexgraph.engine.fuzz import campaigns as C
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        a = s.get(FuzzArtifact, artifact_id)
        if a is None:
            return {"error": "artifact not found"}
        if not a.content_cas:
            return {"error": "artifact has no stored reproducer to re-verify"}
        try:
            res = C.verify_artifact(s, a)
        except PolicyViolation as exc:
            return {"error": f"not permitted — {exc} (enable features.fuzzing/poc to replay a "
                             "crash; features.network for a live-socket crash)"}
        except (C.CampaignError, ValueError) as exc:
            return {"error": str(exc)}
        return {"artifact_id": artifact_id, "verified": bool(res.get("verified")),
                "detail": res.get("detail"), "assurance": res.get("assurance"),
                "output": res.get("output")}


def _tool(target_id: str, name: str, args: dict) -> str:
    """Run a sandboxed inspection tool (decompile/strings/…) via the shared registry."""
    from hexgraph.agent.agent_tools import ToolContext, run_tool

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return "error: target not found"
        ctx = ToolContext(session=s, project=s.get(Project, t.project_id), target=t)
        return run_tool(ctx, name, args or {})


def decompile_function(target_id: str, function: str, max_chars: int | None = None) -> str:
    """Decompile (and promote) one function. `max_chars` raises the inlined-body cap (default
    6000, clamped) when the function is long; get_observation reads the full body either way."""
    a: dict = {"function": function}
    if max_chars is not None:
        a["max_chars"] = max_chars
    return _tool(target_id, "decompile_function", a)


def decompile_at(target_id: str, address: str, max_chars: int | None = None) -> str:
    """Decompile (and promote) the function CONTAINING a hex address — analyze-at-address.
    `max_chars` raises the inlined-body cap (default 6000, clamped); get_observation is uncapped."""
    a: dict = {"address": address}
    if max_chars is not None:
        a["max_chars"] = max_chars
    return _tool(target_id, "decompile_at", a)


def disassemble(target_id: str, function: str | None = None, address: str | None = None,
                max_chars: int | None = None) -> str:
    """Disassemble one function by name or by address (the address resolves to the
    function containing it). `max_chars` raises the inlined cap (default 6000, clamped)."""
    a = {"address": address} if address else {"function": function}
    if max_chars is not None:
        a["max_chars"] = max_chars
    return _tool(target_id, "disassemble", a)


def disassemble_range(target_id: str, address: str, length: int | None = None,
                      count: int | None = None, max_chars: int | None = None) -> str:
    """Disassemble a RAW address+length byte range — no function required, the fallback for a
    CFG blind spot both backends miss. `length` bytes (default 256) or `count` instructions;
    `max_chars` raises the inlined cap (default 6000, clamped)."""
    a: dict = {"address": address}
    if length is not None:
        a["length"] = length
    if count is not None:
        a["count"] = count
    if max_chars is not None:
        a["max_chars"] = max_chars
    return _tool(target_id, "disassemble_range", a)


def reanalyze(target_id: str) -> str:
    """Re-run analysis at a higher depth (busting the cache) so a missed function/edge retries."""
    return _tool(target_id, "reanalyze", {})


def list_functions(target_id: str) -> str:
    return _tool(target_id, "list_functions", {})


def read_imports(target_id: str) -> str:
    return _tool(target_id, "read_imports", {})


def binutils_facts(target_id: str) -> str:
    """Authoritative low-level ELF facts via GNU binutils (nm/objdump/readelf/strings)."""
    return _tool(target_id, "binutils_facts", {})


def floss_strings(target_id: str, min_length: int | None = None) -> str:
    """Recover OBFUSCATED strings (stack/tight/decoded) a plain strings pass misses, via
    FLARE FLOSS run in the sandbox. Always-on static tool — it relaxes no boundary."""
    return _tool(target_id, "floss_strings",
                 {"min_length": min_length} if min_length is not None else {})


def yara_scan(target_id: str, ruleset: str | None = None) -> str:
    """Match ONE target's bytes against YARA rules (bundled + user) in the sandbox,
    promoting matched rules to pattern nodes + matches_rule edges. Always-on static tool —
    it relaxes no boundary. Use yara_sweep for the whole project."""
    return _tool(target_id, "yara_scan", {"ruleset": ruleset} if ruleset else {})


def yara_sweep(project_id: str, ruleset: str | None = None) -> dict:
    """Project-wide YARA sweep: match every non-archived byte target AND every extracted
    firmware file against the chosen rules, recording a yara_matches Observation per
    artifact and promoting matches to shared project-level `pattern` nodes via `matches_rule`
    edges. The cross-target n-day complement to link_same_code (exact hash): one rule, swept
    corpus-wide. `ruleset` is a bundled ruleset id (or 'all', default). Always-on static tool
    — it relaxes no boundary. Returns a roll-up of scanned/match/promotion counts + hits."""
    from hexgraph.engine.re.yara import sweep_project

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            return {"error": "project not found"}
        return sweep_project(s, p, ruleset=ruleset, source="agent")


def list_strings(target_id: str, pattern: str | None = None,
                 offset: int | None = None, limit: int | None = None) -> str:
    """GREP a target's FULL string table (the real strings(1) pass, not the recon sample)
    for `pattern`, paged by `offset`/`limit` (default 200, max 1000). The result reports the
    total match count + the next offset so a broad grep pages on without an obs_get dance."""
    a: dict = {}
    if pattern:
        a["pattern"] = pattern
    if offset is not None:
        a["offset"] = offset
    if limit is not None:
        a["limit"] = limit
    return _tool(target_id, "list_strings", a)


def xrefs(target_id: str, symbol: str | None = None) -> str:
    """Find which functions CALL a symbol/sink and where (cross-references). With no
    `symbol`, map every dangerous sink (system/popen/strcpy/sprintf/…) and who reaches
    it — the fast way to trace from a sink back to the code that can drive it."""
    return _tool(target_id, "xrefs", {"symbol": symbol} if symbol else {})


def call_graph(target_id: str, function: str | None = None, depth: int | None = None) -> str:
    """The target's call graph (or the neighbourhood rooted at `function` out to `depth`)."""
    a: dict = {}
    if function:
        a["function"] = function
    if depth is not None:
        a["depth"] = depth
    return _tool(target_id, "call_graph", a)


def function_xrefs(target_id: str, function: str) -> str:
    """Callers AND callees of one function — the bidirectional call-graph neighbourhood."""
    return _tool(target_id, "function_xrefs", {"function": function})


def data_xrefs(target_id: str, address: str) -> str:
    """Every code/data/string reference TO a hex address (or a symbol that resolves to one)."""
    return _tool(target_id, "data_xrefs", {"address": address})


def search_decompiled(target_id: str, query: str, max_chars: int | None = None) -> str:
    """Substring search across already-decompiled function bodies on a target (mines the
    Observation store; no re-decompile). `max_chars` raises the inlined-results cap (default
    6000, clamped); the recorded Observation holds the full hit list."""
    a: dict = {"query": query}
    if max_chars is not None:
        a["max_chars"] = max_chars
    return _tool(target_id, "search_decompiled", a)


def _node_dict(n: Node) -> dict:
    return {"id": n.id, "node_type": n.node_type, "name": n.name, "fq_name": n.fq_name,
            "address": n.address, "target_id": n.target_id, "attrs": n.attrs_json or {}}


def get_node(node_id: str) -> dict:
    """Read a node back in full — including its address and attrs (params/notes you
    set). Use this to confirm what you wrote landed."""
    with session_scope() as s:
        n = s.get(Node, node_id)
        return _node_dict(n) if n is not None else {"error": "node not found"}


def list_nodes(project_id: str, target_id: str | None = None, node_type: str | None = None) -> list[dict]:
    """List graph nodes (optionally filtered by target and/or node_type), with
    their address + attrs. The read path for the graph you've been building."""
    with session_scope() as s:
        q = s.query(Node).filter(Node.project_id == project_id, Node.archived.is_(False))
        if target_id:
            q = q.filter(Node.target_id == target_id)
        if node_type:
            q = q.filter(Node.node_type == node_type)
        return [_node_dict(n) for n in q.limit(500).all()]


def graph_stats(project_id: str) -> dict:
    """Per-type node/edge tallies for the project's live graph — before/after counts
    without listing (and truncating on) every node."""
    from hexgraph.engine.graph.graph import graph_stats as _stats

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        return _stats(s, project_id)


def set_node_attr(node_id: str, key: str, value: Any) -> dict:
    """Set ONE attribute on a node (e.g. is_sink=true) without re-creating it. Sets the
    single `key`; other attrs are untouched. Returns the updated node."""
    with session_scope() as s:
        n = s.get(Node, node_id)
        if n is None:
            return {"error": "node not found"}
        attrs = dict(n.attrs_json or {})
        attrs[key] = value
        n.attrs_json = attrs
        s.flush()
        return _node_dict(n)


def list_edges(project_id: str, node_id: str | None = None) -> list[dict]:
    """List edges in the project (or just those touching `node_id`) so you can
    confirm the dataflow/relationships you wired (calls/taints/about/…)."""
    from hexgraph.db.models import Edge
    from sqlalchemy import or_

    with session_scope() as s:
        q = s.query(Edge).filter(Edge.project_id == project_id)
        if node_id:
            q = q.filter(or_((Edge.src_kind == "node") & (Edge.src_id == node_id),
                             (Edge.dst_kind == "node") & (Edge.dst_id == node_id)))
        return [{"id": e.id, "type": e.type, "src_kind": e.src_kind, "src_id": e.src_id,
                 "dst_kind": e.dst_kind, "dst_id": e.dst_id, "attrs": e.attrs_json or {}}
                for e in q.limit(500).all()]


def search(project_id: str, q: str) -> dict:
    from hexgraph.engine.graph.search import search_project

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        return search_project(s, project_id, q)


# --- Observation store: discoverable prior analysis (design §5.6) --------------
# Reuse hint appended to every result so the agent learns the contract inline.
_OBS_REUSE = ("Tool results persist as Observations on the target; they do NOT add graph "
              "nodes. Check obs_list(target_id) before re-running an analysis, and "
              "obs_get(id) for a prior payload.")


def list_observations(target_id: str, tool: str | None = None, kind: str | None = None,
                      limit: int = 100) -> dict:
    """Prior deterministic analysis recorded on this target (decompilations, function
    lists, xrefs, taint, strings, structs, …) — the substrate, NOT the curated graph.
    Returns row metadata newest-first; pull a payload with get_observation(id). CHECK
    THIS BEFORE RE-RUNNING a heavy analysis (analyze once, reuse forever)."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        if s.get(Target, target_id) is None:
            return {"error": "target not found"}
        rows = O.list_observations(s, target_id, tool=tool, kind=kind, limit=limit)
        return {"observations": rows, "count": len(rows), "reuse_hint": _OBS_REUSE}


def get_observation(observation_id: str) -> dict:
    """Read ONE Observation in full, including the complete payload loaded back from
    CAS — so you can reuse a prior decompilation/xref/taint result instead of paying
    to re-run it. Results live here; promote the few that matter into the graph."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        out = O.get_observation(s, observation_id)
        if out is None:
            return {"error": "observation not found"}
        out["observation_id"] = out["id"]
        out["reuse_hint"] = _OBS_REUSE
        return out


def search_observations(query: str, project_id: str | None = None,
                        target_id: str | None = None, limit: int = 100) -> dict:
    """Search prior Observations (substring over tool / summary / result_kind) across a
    project or one target — find earlier analysis to reuse before re-running it."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        rows = O.search_observations(s, project_id=project_id, target_id=target_id,
                                     query=query, limit=limit)
        return {"observations": rows, "count": len(rows), "reuse_hint": _OBS_REUSE}


def list_findings(project_id: str, limit: int = 100, offset: int = 0,
                  finding_type: str | None = None, status: str | None = None,
                  severity: str | None = None, target_id: str | None = None,
                  verified: bool | None = None,
                  include_recon: bool = False) -> list[dict]:
    """Existing findings, NEWEST-FIRST, so the agent doesn't re-report what's already known.
    Paginated (`limit`/`offset`) and filterable (`finding_type`/`status`/`severity`/
    `target_id`/`verified`). By DEFAULT excludes the high-volume `recon` findings (ingest
    mints one per child target — easily hundreds) so the substantive findings aren't drowned;
    pass include_recon=True (or finding_type='recon') to see them. Each row carries `verified`,
    the compact `assurance` triple {standard, method, precondition} (the rung — so you see
    code_present/static vs input_reachable/dynamic at a glance, no per-finding get_finding
    needed) and, for a PoC that ran, a compact `verification` summary {verified, detail};
    a fuzz_crash carries a compact `fuzz` summary {exploitability, coverage_instrumented,
    dupe_count} so you can triage at a glance — call get_finding(id) for the full evidence
    (incl. the PoC/fuzz detail in evidence.extra).

    `limit=0` means NO limit (every matching row), not zero rows; `offset` still applies. The
    `verified` filter derives from nested evidence JSON (not a SQL column), so when it is set
    pagination is computed OVER the verified-filtered set in Python — otherwise a verified finding
    beyond page 1 would be unreachable and a page could come back short while more matched."""
    from hexgraph.engine.findings.assurance import assurance_of, compact_assurance

    try:
        limit = max(0, int(limit))
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        limit, offset = 100, 0

    def _row(f):
        ev = f.evidence_json or {}
        extra = ev.get("extra") or {}
        row = {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
               "status": f.status, "finding_type": f.finding_type, "cwe": f.cwe,
               "verified": is_verified(ev), "target_id": f.target_id,
               "function": ev.get("function"),
               "assurance": compact_assurance(assurance_of(ev))}
        ver = extra.get("verification")
        if ver:
            row["verification"] = {"verified": bool(ver.get("verified")), "detail": ver.get("detail")}
        fz = extra.get("fuzz")
        if fz:
            # coverage_instrumented=False => a black-box run; don't over-trust dedup.
            row["fuzz"] = {
                "exploitability": (fz.get("exploitability") or {}).get("rating"),
                "coverage_instrumented": fz.get("coverage_instrumented"),
                "dupe_count": fz.get("dupe_count"),
            }
        return row

    with session_scope() as s:
        q = s.query(Finding).filter(Finding.project_id == project_id)
        if finding_type:
            q = q.filter(Finding.finding_type == finding_type)
        elif not include_recon:
            # Default: keep the per-child recon flood out of the list.
            q = q.filter(Finding.finding_type != "recon")
        if status:
            q = q.filter(Finding.status == status)
        if severity:
            q = q.filter(Finding.severity == severity)
        if target_id:
            q = q.filter(Finding.target_id == target_id)
        q = q.order_by(Finding.created_at.desc())

        if verified is not None:
            # `verified` is a nested-JSON predicate, not a SQL column, so it can't be pushed into
            # the LIMIT/OFFSET. Stream the ordered rows, keep only those matching the flag, and
            # paginate OVER that filtered set in Python — so page N is correct and a full page is
            # returned whenever enough matches exist past the offset. (offset/limit slice the
            # filtered, newest-first sequence; limit==0 ⇒ no cap.)
            want = bool(verified)
            matched = (f for f in q.yield_per(200) if is_verified(f.evidence_json or {}) == want)
            out = []
            for i, f in enumerate(matched):
                if i < offset:
                    continue
                if limit and len(out) >= limit:
                    break
                out.append(_row(f))
            return out

        # No verified filter: the cheap path — push offset/limit straight into SQL.
        q = q.offset(offset)
        if limit:  # limit==0 ⇒ no cap (return everything past the offset)
            q = q.limit(limit)
        return [_row(f) for f in q.all()]


def get_finding(finding_id: str) -> dict:
    """Read ONE finding back in full — including the complete `evidence` (with
    evidence.extra, where verify_poc stores the PoC spec + verification result).
    Use this to confirm a write landed (the finding analog of get_node): after
    verify_poc(finding_id=…), get_finding shows evidence.extra.verification."""
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return {"error": "finding not found"}
        ev = f.evidence_json or {}
        verified = is_verified(ev)
        return {"id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
                "category": f.category, "status": f.status, "finding_type": f.finding_type,
                "cwe": f.cwe, "origin": f.origin, "target_id": f.target_id, "task_id": f.task_id,
                "summary": f.summary, "reasoning": f.reasoning, "evidence": ev,
                "human_notes": f.human_notes, "verified": verified}


def record_finding(project_id: str, target_id: str, finding: dict, task_id: str | None = None,
                   finding_type: str | None = None) -> dict:
    """Persist an agent-produced finding (the `finding` dict must match the frozen
    Finding schema — call get_schemas). `finding_type` is a SEPARATE classifier
    (vulnerability|poc|recon|harness|fuzz_crash|annotation|other) — pass it here,
    NOT inside the finding dict. Pass the given `task_id` in delegate mode.

    ASSURANCE (get_schemas['assurance']): a vuln finding is auto-floored to code_present/static
    — the engine documents at least the minimum. STRIVE HIGHER: to claim input_reachable, either
    verify it dynamically (verify_poc) or, for a static reachability argument, set
    evidence.extra.assurance = {standard, method, precondition} (e.g. input_reachable/static/
    unauthenticated) — state requires_credentials honestly; don't claim what you didn't show."""
    from hexgraph.db.models import Task
    from hexgraph.engine.findings.findings import FINDING_TYPES, persist_finding
    from hexgraph.engine.tasks import create_task

    if finding_type is not None and finding_type not in FINDING_TYPES:
        return {"error": f"invalid finding_type {finding_type!r} (allowed: {list(FINDING_TYPES)})"}
    try:
        model = FModel.model_validate(finding)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"finding does not match the schema: {exc} — call meta_get_schemas; note "
                         "finding_type is a separate finding_record arg, not a finding field."}
    with session_scope() as s:
        project = s.get(Project, project_id)
        target = s.get(Target, target_id)
        if project is None or target is None:
            return {"error": "project or target not found"}
        task = s.get(Task, task_id) if task_id else None
        if task is None or task.project_id != project.id:
            task = create_task(s, project=project, target_id=target.id, type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id,
                              finding=model, finding_type=finding_type)
        row.origin = "agent"
        return {"id": row.id, "title": row.title, "severity": row.severity, "finding_type": row.finding_type}


def propagate_finding(finding_id: str, target_id: str, function: str | None = None,
                      notes: str | None = None) -> dict:
    """N-day propagation: clone an existing finding onto ANOTHER binary (`target_id`)
    that shares the same vulnerable code (see link_same_code) — as a fresh finding to
    triage, wired `derived_from` → the source. Saves re-typing the whole finding dict
    for "the same bug, other binary". Pass `function` to point it at the sibling's
    function name. Returns the new finding id."""
    from hexgraph.db.models import EdgeType, Finding, Task
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.findings.findings import persist_finding
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Finding as FModelCls

    with session_scope() as s:
        src = s.get(Finding, finding_id)
        target = s.get(Target, target_id)
        if src is None:
            return {"error": "source finding not found"}
        if target is None or target.project_id != src.project_id:
            return {"error": "target not found in the source finding's project"}
        ev = dict(src.evidence_json or {})
        if function:
            ev["function"] = function
        ev.setdefault("extra", {})
        ev["extra"] = {**(ev.get("extra") or {}),
                       "propagated_from": src.id, "propagated_from_target": src.target_id}
        model = FModelCls(
            title=src.title, severity=src.severity, confidence=src.confidence,
            category=src.category,
            summary=(src.summary or "") + f"\n\n[n-day] Same code as finding {src.id} in another binary; "
                    "review/confirm this instance." + (f"\nNotes: {notes}" if notes else ""),
            reasoning=src.reasoning, evidence=ev,
        )
        task = create_task(s, project=s.get(Project, src.project_id), target_id=target.id,
                           type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=src.project_id, target_id=target.id, task_id=task.id,
                              finding=model, finding_type=src.finding_type)
        row.origin = "agent"
        # Wire the n-day link: new instance derived_from the original.
        add_edge(s, project_id=src.project_id, src=("finding", row.id), dst=("finding", src.id),
                 type=EdgeType.derived_from, origin="agent", confidence=0.9, attrs={"by": "n-day propagation"})
        return {"id": row.id, "title": row.title, "target_id": target.id, "finding_type": row.finding_type,
                "status": getattr(row.status, "value", row.status), "derived_from": src.id}


def create_node(project_id: str, node_type: str, name: str, target_id: str | None = None,
                address: str | None = None, attrs: dict | None = None) -> dict:
    """Add a node to the graph (function/symbol/string/struct/input/sink/endpoint/param/
    hypothesis/pattern). Target-bound types REQUIRE target_id (else the node is an orphan)
    and are auto-linked to their target with a `contains` edge. Pass `address` for a code
    node's location, and populate `attrs` with the type's recommended fields — call
    get_schemas first and read node_attribute_schemas[<type>] for what's expected (e.g. a
    function wants {"summary","params":[{"name","type","note"}]}; an input wants {"source"};
    a sink wants {"operation","why"}). DON'T create a `sink` node for a known dangerous call
    (system/strcpy/…) — that's a symbol/function node with is_sink=true. Populating the
    recommended attrs is what makes repeated runs of the same analysis converge."""
    from hexgraph.engine.graph.authoring import InvariantError, create_node as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            n = _create(s, project, node_type=node_type, name=name, target_id=target_id,
                        address=address, attrs=attrs)
        except InvariantError as exc:
            return {"error": str(exc)}
        # Echo back the stored address + attrs: a function node materialized by
        # recon already exists by identity (target, fq_name), so create_node merges
        # into it — the agent sees here whether its address/attrs actually landed.
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "address": n.address,
                "target_id": n.target_id, "attrs": n.attrs_json or {}}


def create_edge(project_id: str, src_kind: str, src_id: str, dst_kind: str, dst_id: str,
                type: str, attrs: dict | None = None, merge: bool = False) -> dict:
    """Connect two graph entities (target|node|finding|task). Both must exist.
    `attrs` carries edge-type-specific facts — call get_schemas to see what's
    meaningful per type (e.g. a `calls` edge's `call_sites`/`arg_constraints`, a
    `listens_on` edge's `address`). With `merge=True`, a repeat of the same
    (src,dst,type) folds into the existing edge: list attributes like `call_sites`
    accumulate instead of drawing a parallel edge."""
    from hexgraph.engine.graph.authoring import InvariantError, create_edge as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            e = _create(s, project, src_kind=src_kind, src_id=src_id, dst_kind=dst_kind,
                        dst_id=dst_id, type=type, attrs=attrs, merge=merge)
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": e.id, "type": e.type, "src_id": e.src_id, "dst_id": e.dst_id,
                "attrs": e.attrs_json or {}}


def update_edge(edge_id: str, attrs: dict, merge: bool = True) -> dict:
    """Add/update attributes on an EXISTING edge (by id). Default `merge=True`
    accumulates list attributes (e.g. append a newly-found `call_sites` address)
    and overwrites scalars; `merge=False` replaces attrs wholesale. See get_schemas
    for the attributes meaningful to each edge type."""
    from hexgraph.db.models import Edge
    from hexgraph.engine.graph.edge_schemas import merge_edge_attrs

    with session_scope() as s:
        e = s.get(Edge, edge_id)
        if e is None:
            return {"error": "edge not found"}
        e.attrs_json = merge_edge_attrs(e.type, e.attrs_json, attrs) if merge else dict(attrs or {})
        return {"id": e.id, "type": e.type, "attrs": e.attrs_json}


def archive_node(project_id: str, node_id: str) -> dict:
    """Soft-remove a node from the graph (reversible). The node and the edges touching
    it are hidden; re-adding the same node (create_node / a task) or restore_node brings
    it and its edges back — nothing is deleted."""
    from hexgraph.engine.graph.removal import archive_node as _archive

    with session_scope() as s:
        try:
            n = _archive(s, project_id, node_id)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "archived": n.archived}


def restore_node(project_id: str, node_id: str) -> dict:
    """Un-archive a previously soft-removed node (its hidden edges reappear)."""
    from hexgraph.engine.graph.removal import restore_node as _restore

    with session_scope() as s:
        try:
            n = _restore(s, project_id, node_id)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "archived": n.archived}


def archive_target(project_id: str, target_id: str) -> dict:
    """Soft-remove a target + its whole subtree (children, nodes, findings) from the graph
    (REVERSIBLE): they're hidden, not deleted; re-ingesting the same bytes, or restore_target,
    brings them back. Use to declutter (e.g. an irrelevant firmware component). Returns how
    many targets were archived. (Whole-project deletion is operator-only — not an MCP tool.)"""
    from hexgraph.engine.targets.targets import archive_target as _archive

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return {"archived": _archive(s, project_id, target_id)}
        except ValueError as exc:
            return {"error": str(exc)}


def restore_target(project_id: str, target_id: str) -> dict:
    """Un-archive a previously soft-removed target subtree (its nodes/findings reappear)."""
    from hexgraph.engine.targets.targets import restore_target as _restore

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return {"restored": _restore(s, project_id, target_id)}
        except ValueError as exc:
            return {"error": str(exc)}


def set_visible(project_id: str, target_id: str, visible: bool = True) -> dict:
    """REVEAL (visible=true) or re-HIDE (visible=false) one target in the curated graph.
    Firmware ELF children are HIDDEN by default (unpack registers each so it's searchable
    and addressable, but a 765-ELF firmware would otherwise flood the graph/Targets pane);
    recon already enriched them. Revealing materializes the target's recon nodes from the
    already-stored facts (no re-run) so it joins the graph. Returns
    {target_id, name, visible, materialized}."""
    from hexgraph.engine.targets.reveal import set_visible as _set

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return _set(s, project_id, target_id, visible)
        except ValueError as exc:
            return {"error": str(exc)}


def reveal_dir(project_id: str, target_id: str, prefix: str = "") -> dict:
    """REVEAL every HIDDEN child of a firmware whose rootfs path is under `prefix`
    (e.g. prefix='usr/sbin' reveals all ELFs in /usr/sbin) — the bulk counterpart to
    target_set_visible for bringing a whole directory of binaries into the curated graph
    at once. An empty prefix reveals ALL hidden children. Materializes each revealed
    child's recon nodes from stored facts (no re-run). `target_id` is the firmware.
    Returns {firmware_target_id, prefix, revealed, target_ids}."""
    # NB: the catalog advertises this arg as `target_id` (the firmware), and the MCP
    # server dispatches by KEYWORD (`fn(**arguments)`), so this param name MUST match
    # the catalog schema — otherwise every MCP call raises TypeError.
    from hexgraph.engine.targets.reveal import reveal_dir as _reveal

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return _reveal(s, project_id, target_id, prefix)
        except ValueError as exc:
            return {"error": str(exc)}


def delete_edge(edge_id: str) -> dict:
    """Permanently delete one edge (hard delete — re-create it with create_edge to
    bring it back). To remove a node's edges reversibly, archive the node instead."""
    from hexgraph.engine.graph.removal import delete_edge as _del

    with session_scope() as s:
        return {"deleted": _del(s, edge_id), "edge_id": edge_id}


def delete_finding(finding_id: str) -> dict:
    """Permanently DELETE a junk finding (hard delete — IRREVERSIBLE). Use this to
    remove a finding that's pure noise/garbage you never want to see again. To set a
    finding aside reversibly instead (keep the row, greyed, restorable), call
    update_finding(status='dismissed'). Deleting also removes every edge/annotation
    touching the finding, leaving no dangling reference. Safe no-op if already gone."""
    from hexgraph.engine.graph.removal import delete_finding as _del

    with session_scope() as s:
        out = _del(s, finding_id)
        if not out.get("found"):
            return {"error": "finding not found", "deleted": False, "finding_id": finding_id}
        return {"deleted": True, **out}


def create_socket(project_id: str, kind: str = "tcp", port: int | str | None = None,
                  name: str | None = None, bind_addr: str | None = None,
                  attrs: dict | None = None) -> dict:
    """Create (or reuse) a SOCKET node — a network/IPC endpoint shared across the
    firmware's binaries. `kind` ∈ tcp|udp|unix|io|netlink|raw|other; give a `port`
    (tcp/udp) or a `name` (unix path / identifier). A server `listens_on` it and a
    client `connects_to` it — both resolve to this ONE node, so you can see which
    binaries talk over the same endpoint. Put the listen/connect code address on
    those edges (create_edge attrs={'address': '0x...'})."""
    from hexgraph.engine.graph.authoring import InvariantError, create_socket as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            n = _create(s, project, kind=kind, port=port, name=name, bind_addr=bind_addr,
                        attrs=attrs, created_by="agent")
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "attrs": n.attrs_json or {}}


def list_sockets(project_id: str) -> list[dict]:
    """List socket endpoints in the project with who listens/connects on each — the
    network map of the firmware (server↔client over shared sockets)."""
    from hexgraph.db.models import Edge, NodeType

    with session_scope() as s:
        socks = (s.query(Node)
                 .filter(Node.project_id == project_id, Node.node_type == NodeType.socket.value)
                 .all())
        out = []
        for n in socks:
            edges = (s.query(Edge)
                     .filter(Edge.project_id == project_id, Edge.dst_kind == "node", Edge.dst_id == n.id,
                             Edge.type.in_(("listens_on", "connects_to")))
                     .all())
            peers = [{"relation": e.type, "src_kind": e.src_kind, "src_id": e.src_id,
                      "address": (e.attrs_json or {}).get("address")} for e in edges]
            out.append({"id": n.id, "name": n.name, "attrs": n.attrs_json or {}, "peers": peers})
        return out


def list_egress(project_id: str) -> list[dict]:
    """The egress audit log — every outbound network action (allowed or denied) the
    bounded-network tier recorded for this project. Durable proof of what HexGraph
    connected to and when."""
    from hexgraph.engine.audit import list_egress as _list

    with session_scope() as s:
        return _list(s, project_id)


def update_finding(finding_id: str, status: str | None = None, severity: str | None = None,
                   confidence: str | None = None, human_notes: str | None = None,
                   cwe: str | None = None) -> dict:
    """Update an EXISTING finding in place (don't create a duplicate) — e.g. raise
    confidence/severity and set status='confirmed' after a PoC verifies, 'dismissed'
    if it's a false positive, or set/correct the triage `cwe`."""
    from hexgraph.db.models import Finding, FindingStatus
    from hexgraph.engine.findings.findings import normalize_cwe

    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return {"error": "finding not found"}
        if status is not None:
            try:
                f.status = FindingStatus(status).value
            except ValueError:
                return {"error": f"invalid status {status!r} (use new|triaging|confirmed|dismissed|reported)"}
        if severity:
            f.severity = severity
        if confidence:
            f.confidence = confidence
        if human_notes is not None:
            f.human_notes = human_notes
        if cwe is not None:
            f.cwe = normalize_cwe(cwe)
        return {"id": f.id, "status": f.status, "severity": f.severity,
                "confidence": f.confidence, "cwe": f.cwe}


def link_evidence(hypothesis_id: str, finding_id: str, relation: str) -> dict:
    """Attach a finding to a hypothesis as supporting/refuting evidence. This is how
    you CONFIRM a hypothesis — the hypothesis status is recomputed from its evidence
    (open → supported / refuted / contested). relation = 'supports' | 'refutes'
    ('confirms'→supports and 'contradicts'→refutes are accepted aliases). To pin a
    hard verdict on a verified finding, also call set_hypothesis_status(id,'confirmed')."""
    from hexgraph.engine.graph.hypotheses import HypothesisError, link_evidence as _le, summary

    with session_scope() as s:
        node = s.get(Node, hypothesis_id)
        project = s.get(Project, node.project_id) if node is not None else None
        if project is None:
            return {"error": "hypothesis not found"}
        try:
            _le(s, project, hypothesis_id=hypothesis_id, finding_id=finding_id, relation=relation)
        except HypothesisError as exc:
            return {"error": str(exc)}
        return summary(s, hypothesis_id)


def set_hypothesis_status(hypothesis_id: str, status: str | None = None,
                          work_state: str | None = None, rationale: str | None = None) -> dict:
    """Update a hypothesis along EITHER axis (pass at least one). `status` pins the evidence
    verdict (confirmed | rejected | open | supported | refuted | contested). `work_state` moves
    the worklist axis (investigating | parked | done) — orthogonal to the verdict. Pass
    `rationale` to record WHY (kept as the hypothesis's status_note)."""
    from hexgraph.engine.graph.hypotheses import HypothesisError, set_status, set_work_state, summary

    if status is None and work_state is None:
        return {"error": "pass status and/or work_state"}
    with session_scope() as s:
        try:
            if status is not None:
                set_status(s, hypothesis_id, status, rationale=rationale)
            if work_state is not None:
                set_work_state(s, hypothesis_id, work_state, rationale=rationale)
            return summary(s, hypothesis_id)
        except HypothesisError as exc:
            return {"error": str(exc)}


def close_hypothesis(hypothesis_id: str, verdict: str | None = None,
                     rationale: str | None = None) -> dict:
    """CHECK OFF a hypothesis: set work_state='done' and optionally record the evidence
    `verdict` (confirmed | rejected | supported | refuted | …) explaining how it resolved.
    A proven question closes confirmed/supported; a ruled-out one closes refuted/rejected (a
    documented dead end). Use when you've settled a hypothesis either way."""
    from hexgraph.engine.graph.hypotheses import HypothesisError, set_work_state, summary

    with session_scope() as s:
        try:
            set_work_state(s, hypothesis_id, "done", verdict=verdict, rationale=rationale)
            return summary(s, hypothesis_id)
        except HypothesisError as exc:
            return {"error": str(exc)}


def list_hypotheses(project_id: str, work_state: str | None = None,
                    status: str | None = None) -> dict:
    """List the project's hypothesis WORKLIST — a row per hypothesis with its statement,
    evidence status, work_state, pinned_to_graph, and support/refute counts. Filter by
    `work_state` (investigating | parked | done) and/or evidence `status`. Your "what am I
    working on" orient before recording a new hypothesis or resuming a session."""
    from hexgraph.engine.graph.hypotheses import HypothesisError, list_hypotheses as _list

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            return {"hypotheses": _list(s, project, work_state=work_state, status=status)}
        except HypothesisError as exc:
            return {"error": str(exc)}


# --- journal: the freeform research notebook (design-working-memory.md §5/§8) --
# Function names DROP the `journal_` domain prefix (a routing concern): advertised
# journal_add ↔ add_journal_entry, journal_search ↔ search_journal, etc. The write
# tools enforce the authorship rule (an agent may touch only its OWN entries):
# journal_add forces author="agent"; journal_update/journal_delete refuse a human entry.

def add_journal_entry(body: str, project_id: str, origin_task_id: str | None = None) -> dict:
    """Add an AGENT journal entry to a project's research notebook (always author=agent —
    you can never post as the human). Parse @[label](kind:id) mentions from the body."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            entry = J.add_journal_entry(s, project, body=body, author="agent",
                                        origin_task_id=origin_task_id)
        except J.JournalError as exc:
            return {"error": str(exc)}
        return J.serialize_entry(s, entry)


def list_journal_entries(project_id: str, author: str | None = None, limit: int = 50) -> dict:
    """A project's journal entries newest-first (filter by author=human|agent)."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        rows = J.list_journal_entries(s, project_id, author=author, limit=limit)
        return {"entries": rows, "count": len(rows)}


def get_journal_entry(entry_id: str) -> dict:
    """Read ONE journal entry in full, with its @-mentions resolved (danglers flagged)."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        out = J.get_journal_entry(s, entry_id)
        if out is None:
            return {"error": "journal entry not found"}
        return out


def search_journal(query: str, project_id: str, limit: int = 50) -> dict:
    """Substring search over a project's journal bodies — cross-session re-orient."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        rows = J.search_journal(s, project_id, query, limit=limit)
        return {"entries": rows, "count": len(rows)}


def update_journal_entry(entry_id: str, body: str) -> dict:
    """Edit one of YOUR OWN journal entries (refuses a human-authored entry); marks it
    edited and re-parses mentions."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        try:
            entry = J.update_journal_entry(s, entry_id, body=body, as_author="agent")
        except J.JournalError as exc:
            return {"error": str(exc)}
        return J.serialize_entry(s, entry)


def delete_journal_entry(entry_id: str) -> dict:
    """Delete one of YOUR OWN journal entries (refuses a human-authored entry)."""
    from hexgraph.engine import journal as J

    with session_scope() as s:
        try:
            J.delete_journal_entry(s, entry_id, as_author="agent")
        except J.JournalError as exc:
            return {"error": str(exc)}
        return {"deleted": entry_id}


def _sandbox_image_built(tag: str) -> bool:
    """Is the sandbox image actually built locally? Cheap `docker image inspect` (no run);
    used so the radare2 health verdict isn't a false-positive when Docker is up but the
    image was never built. Returns False on any error."""
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", tag],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=30).returncode == 0
    except Exception:  # noqa: BLE001 — treat an inspect failure as "can't confirm built"
        return False


def _decompiler_health(active: str) -> dict:
    """Does the ACTIVE decompiler actually work right now (not merely configured)?
    Returns {working: bool, detail: str, mode?, version?}. Never raises — a broken
    decompiler is a reportable fact, not an exception."""
    try:
        from hexgraph.sandbox.runner import docker_available

        if active in ("ghidra", "ghidra_bridge", "bridge"):
            # Ghidra (headless or bridge) — defer to the real status probe.
            from hexgraph.engine.re.ghidra import check_ghidra

            g = check_ghidra()
            return {
                "working": bool(g.get("ok")),
                "mode": g.get("mode"),
                "version": g.get("ghidra_version"),
                "detail": g.get("detail")
                or ("Ghidra is configured but its status could not be confirmed."),
            }

        # radare2 — the always-available default, shipped in the sandbox image.
        if not docker_available():
            return {
                "working": False,
                "detail": "Docker is not running; radare2 decompilation runs inside the "
                          "sandbox image. Start Docker (and `just sandbox-build` if the image "
                          "is missing).",
            }
        # Docker being up isn't enough — the sandbox image must actually be built, or a
        # decompile would still fail. Confirm it exists (cheap `image inspect`, no run).
        from hexgraph.sandbox.runner import sandbox_image

        image = sandbox_image()
        if not _sandbox_image_built(image):
            return {
                "working": False,
                "detail": f"the sandbox image '{image}' is not built — run `just sandbox-build` "
                          "(radare2 decompilation runs inside it).",
            }
        return {
            "working": True,
            "detail": f"radare2 is available in the sandbox image '{image}'.",
        }
    except Exception as exc:  # noqa: BLE001 — health probing must never crash a read call
        return {"working": False, "detail": f"could not determine decompiler health: {exc}"}


def _decompiler_info() -> dict:
    """Which decompiler decompile_function/disassemble use right now, whether it
    actually WORKS, and how to change it — so an agent knows it can't flip it itself
    (the operator does, in Settings) and isn't misled by a configured-but-broken tool."""
    from hexgraph.sandbox.decompiler import _resolve_name

    active = _resolve_name(None)
    health = _decompiler_health(active)
    return {
        "active": active,
        "available_default": "radare2",
        "working": health["working"],
        "health": health,
        "note": "re_decompile_function / re_disassemble use the OPERATOR-configured decompiler "
                "automatically — you don't select it. radare2 is the always-available default; "
                "Ghidra is used when the operator enables features.ghidra in Settings AND the "
                "sandbox image was built with Ghidra (`just sandbox-build with_ghidra=1`). There "
                "is intentionally no MCP tool to toggle this (it's an operator setting). If you "
                "want Ghidra and `active` here is 'radare2', ask the operator to enable it. "
                "`working` reports whether `active` ACTUALLY functions right now — if it's false, "
                "see health.detail (run meta_check_decompiler for the full diagnostic).",
    }


def check_decompiler() -> dict:
    """Diagnose the decompiler decompile_function / disassemble use — does the active
    one ACTUALLY work, or is it merely configured? get_schemas reports the configured
    `active` name; this VERIFIES it, so you don't waste turns decompiling against a
    broken backend (e.g. Ghidra named active while every call fails because the sandbox
    image was built without it). Returns {active, working, mode, version, detail}:
    `active` is radare2|ghidra|ghidra_bridge; `working` is the real verdict (radare2 ⇒
    the sandbox image is up; Ghidra ⇒ the headless binary is present / the bridge is
    reachable); `mode` is headless|bridge for Ghidra; `detail` is an ACTIONABLE string
    when broken (rebuild the sandbox with WITH_GHIDRA=1, start the Ghidra bridge server,
    start Docker, …). Read-only — no target is touched. If working is False, fall back to
    radare2-level reading or tell the operator what to fix; don't keep retrying."""
    from hexgraph.sandbox.decompiler import _resolve_name

    active = _resolve_name(None)
    health = _decompiler_health(active)
    return {
        "active": active,
        "working": health["working"],
        "mode": health.get("mode"),
        "version": health.get("version"),
        "detail": health["detail"],
    }


def _image_smoke(image: str, argv: list[str], *, timeout: int = 30) -> tuple[bool, str]:
    """Run a TINY, side-effect-free command in `image` and report (ok, detail). No target
    is mounted, auto-removed — this is a dependency presence check, not an analysis run.
    Returns (False, reason) when Docker is down, the image is unbuilt, or the command exits
    non-zero (the missing-dep / stale-image case). Never raises.

    Even though it mounts no target, the launch reuses the FULL sandbox hardening posture
    (`SandboxRunner._hardening_args`: `--network none`, `--read-only`, `--cap-drop ALL`,
    `--security-opt no-new-privileges`, `--user 1000`, the resource caps + tmpfs scratch) so
    EVERY container HexGraph spawns is uniformly locked down — a dependency probe is no
    weaker than a real probe run."""
    import shutil
    import subprocess

    from hexgraph.sandbox.resources import ResourceSpec
    from hexgraph.sandbox.runner import SandboxRunner

    if not shutil.which("docker"):
        return False, "the docker CLI is not on PATH"
    if not _sandbox_image_built(image):
        return False, f"the image '{image}' is not built"
    # Mirror run_probe's hardened posture exactly (no network, read-only rootfs, dropped
    # caps, no-new-privileges, unprivileged uid, resource ceilings + tmpfs) — the dep check
    # is a presence probe, not an analysis run, but it must not be a softer container.
    hardening = SandboxRunner(image=image)._hardening_args(
        allow_network=False, net_container=None, resources=ResourceSpec(), secret=False)
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", *hardening, "--entrypoint", "", image, *argv],
            capture_output=True, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        return False, f"the dependency check timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001 — a smoke failure is a reportable fact, not a crash
        return False, f"could not run the dependency check: {exc}"
    if proc.returncode == 0:
        return True, (proc.stdout or "").strip()
    reason = (proc.stderr or proc.stdout or "non-zero exit").strip().splitlines()
    return False, (reason[-1] if reason else f"exit {proc.returncode}")[:200]


# Features to health-check — those whose RUNTIME availability can diverge from what's
# configured. Two flavours:
#   * GATED features (angr, ghidra, emulation) carry a dotted `gate` path; an enabled feature
#     whose dependency/image is missing (the stale-image trap) reads "available" in Settings
#     yet errors on first use, so check_features reports disabled / available / broken.
#   * ALWAYS-ON static tools (floss, yara) have NO gate (`gate=None`) — they relax no boundary
#     and ride the static surface ungated. They have no `disabled` state, only available /
#     broken (the stale-sandbox-image staleness check stays valuable: they're always reachable,
#     so a missing dep is a silent failure waiting to happen).
# Each entry pairs the gate (or None) with a callable -> (ok, detail) that LIGHTLY checks the
# runtime dep (no analysis run) and a remediation hint shown when broken. The gate→image/build
# mapping mirrors setup_catalog (the single source of truth for which feature needs which
# image); we assert that alignment in the guard test rather than re-deriving it here.
def _feature_health_specs() -> list[dict]:
    """The features to health-check, with their lightweight runtime probe. Built lazily (it
    imports the sandbox/solver image selectors) so importing this module stays cheap and a
    missing optional dep never breaks the catalog. floss + yara are always-on (gate=None);
    Ghidra and P-Code emulation share the with-Ghidra sandbox image and both defer to
    check_ghidra for their verdict."""
    from hexgraph.engine.re.solver import angr_image
    from hexgraph.sandbox.runner import sandbox_image

    sbx = sandbox_image()

    def _floss() -> tuple[bool, str]:
        ok, detail = _image_smoke(sbx, ["floss", "--version"])
        return ok, (f"FLOSS (flare-floss) is present in the sandbox image '{sbx}': {detail}"
                    if ok else f"the `floss` CLI is missing from the sandbox image '{sbx}' ({detail})")

    def _yara() -> tuple[bool, str]:
        ok, detail = _image_smoke(sbx, ["python3", "-c", "import yara; print(yara.__version__)"])
        return ok, (f"yara-python is importable in the sandbox image '{sbx}' (v{detail})"
                    if ok else f"yara-python won't import in the sandbox image '{sbx}' ({detail})")

    def _angr() -> tuple[bool, str]:
        img = angr_image()
        ok, detail = _image_smoke(img, ["python3", "-c", "import angr; print(angr.__version__)"])
        return ok, (f"angr is importable in the angr image '{img}' (v{detail})"
                    if ok else f"angr won't import in the angr image '{img}' ({detail})")

    def _ghidra() -> tuple[bool, str]:
        from hexgraph.engine.re.ghidra import check_ghidra

        g = check_ghidra()
        return bool(g.get("ok")), g.get("detail") or "Ghidra status could not be confirmed."

    return [
        # floss + yara are always-on (gate=None) — availability-only (available | broken).
        {"feature": "floss", "gate": None, "check": _floss,
         "remediation": "rebuild the sandbox image: `just sandbox-build`."},
        {"feature": "yara", "gate": None, "check": _yara,
         "remediation": "rebuild the sandbox image: `just sandbox-build`."},
        {"feature": "angr", "gate": "features.angr.enabled", "check": _angr,
         "remediation": "build the angr image: `just angr-build`."},
        {"feature": "ghidra", "gate": "features.ghidra.enabled", "check": _ghidra,
         "remediation": "rebuild the sandbox image with Ghidra: `just sandbox-build with_ghidra=1` "
                        "(or, in bridge mode, start the Ghidra bridge server)."},
        {"feature": "emulation", "gate": "features.emulation.enabled", "check": _ghidra,
         "remediation": "needs Ghidra: enable features.ghidra and rebuild the sandbox image with "
                        "`just sandbox-build with_ghidra=1`."},
    ]


def check_features() -> dict:
    """Preflight the features whose runtime dependency can diverge from what's configured —
    so you can tell 'configured but broken' from ready BEFORE spending a run. Each feature
    reports a `state`: `available` (its runtime dep/image is actually present), `broken` (the
    dep/image is MISSING — the stale-sandbox-image trap that silently errored YARA/FLOSS in an
    eval) with an ACTIONABLE `remediation` hint, or `disabled` (ONLY for the GATED features —
    angr, ghidra/emulation — when their features.X.enabled gate is off; nothing to check). The
    always-on static tools floss + yara have no gate, so they're checked unconditionally and
    report availability only. The check is LIGHTWEIGHT (a tiny in-image dep probe, --network
    none, no target, no analysis) and read-only. Returns {features: [{feature, gate, enabled,
    state, detail, remediation?}], summary, image_stale}. `image_stale` is a PROACTIVE hint
    (tri-state: true = the sandbox image PREDATES docker/sandbox.Dockerfile so a rebuild is
    due; false = up to date; null = unknown) — the per-feature checks above catch a missing
    dep REACTIVELY, this catches an image that's merely old before a tool silently misbehaves.
    Run this in your orient step before reaching for floss/yara or an opt-in tool (re_solve_*)
    so you don't burn turns against a broken feature."""
    from hexgraph import settings

    rows: list[dict] = []
    for spec in _feature_health_specs():
        gate = spec["gate"]
        # An always-on tool (gate=None) is ALWAYS checked — it has no disabled state, only
        # available/broken. A gated feature is checked only when its gate is on.
        if gate is None:
            enabled = True
        else:
            try:
                enabled = bool(settings.get(gate))
            except Exception:  # noqa: BLE001 — a settings hiccup reads as "off", never crashes
                enabled = False
            if not enabled:
                rows.append({"feature": spec["feature"], "gate": gate, "enabled": False,
                             "state": "disabled",
                             "detail": f"{spec['feature']} is gated off ({gate}=false); "
                                       "nothing to check."})
                continue
        try:
            ok, detail = spec["check"]()
        except Exception as exc:  # noqa: BLE001 — a broken dep is a reportable state, not a crash
            ok, detail = False, f"the dependency check failed: {exc}"
        row = {"feature": spec["feature"], "gate": gate, "enabled": enabled,
               "state": "available" if ok else "broken", "detail": detail}
        if not ok:
            row["remediation"] = spec["remediation"]
        rows.append(row)

    broken = [r["feature"] for r in rows if r["state"] == "broken"]
    available = [r["feature"] for r in rows if r["state"] == "available"]
    if broken:
        summary = (f"{len(broken)} feature(s) BROKEN (dep/image missing): "
                   f"{', '.join(broken)} — see each row's remediation.")
    elif available:
        summary = f"all checked features available: {', '.join(available)}."
    else:
        summary = "no features available to check."

    # Proactive staleness hint: is the sandbox image OLDER than its Dockerfile? This is
    # orthogonal to the per-feature dep probes above (those catch a MISSING dep; this catches
    # a merely-OLD image that may silently lack newer tools). Tri-state, never raises.
    try:
        from hexgraph.sandbox.runner import sandbox_image_staleness

        image_stale = sandbox_image_staleness()
    except Exception:  # noqa: BLE001 — the hint must never crash the read call
        image_stale = None
    if image_stale:
        summary += (" The sandbox image is STALE (older than docker/sandbox.Dockerfile) — "
                    "rebuild it: `just sandbox-build`.")
    return {"features": rows, "summary": summary, "image_stale": image_stale}


def get_schemas() -> dict:
    """The write-API contract: allowed enums + the Finding shape. Read this before
    finding_record / graph_create_node / graph_create_edge / graph_annotate to avoid guessing."""
    import typing

    from hexgraph.db.models import EdgeType, FindingStatus, NodeType
    from hexgraph.engine.graph.annotations import KINDS as ANN_KINDS, NODE_KINDS as ANN_NODE_KINDS
    from hexgraph.engine.findings.assurance import LADDER as _ASSURANCE_LADDER, PRECONDITIONS as _PRECONDITIONS
    from hexgraph.engine.graph.edge_schemas import SOCKET_KINDS, describe_edges
    from hexgraph.engine.journal import AUTHORS as _JOURNAL_AUTHORS, REF_KINDS as _JOURNAL_REF_KINDS
    from hexgraph.engine.graph.hypotheses import STATUSES as HYP_STATUSES, WORK_STATES as HYP_WORK_STATES
    from hexgraph.engine.graph.node_schemas import describe_nodes
    from hexgraph.engine.findings.findings import FINDING_TYPES
    from hexgraph.models.finding import Finding as FModelCls

    cats = list(typing.get_args(FModelCls.model_fields["category"].annotation))
    sevs = list(typing.get_args(FModelCls.model_fields["severity"].annotation))
    confs = list(typing.get_args(FModelCls.model_fields["confidence"].annotation))
    return {
        "finding": {
            "required": ["title", "severity", "confidence", "category", "summary", "reasoning", "evidence"],
            "severity": sevs, "confidence": confs, "category": cats,
            "evidence_fields": ["function", "file", "address", "line", "decompiled_snippet",
                                "reproducer", "backtrace", "sink", "strings", "extra"],
            "evidence_note": "evidence.extra is a FREE-FORM object — put the PoC spec, verification "
                             "result, CWE, dataflow, etc. there. `reproducer` is a free-text PoC string. "
                             "Top-level evidence keys other than those listed are rejected.",
            "status": [s.value for s in FindingStatus],
        },
        "finding_type": {
            "values": list(FINDING_TYPES),
            "note": "NOT a field of the finding object — pass it as the separate `finding_type` "
                    "argument to finding_record (and read it back via finding_list). Defaults to "
                    "'vulnerability' / is auto-classified from the producing task.",
        },
        "record_finding_signature": "finding_record(project_id, target_id, finding, task_id=None, "
                                    "finding_type=None) — project_id is FIRST, then target_id. Prefer "
                                    "keyword args. For 'the same bug in another binary' use "
                                    "finding_propagate(finding_id, target_id) instead of re-typing it.",
        "node_types": [t.value for t in NodeType if t != NodeType.task],
        "node_attribute_schemas": describe_nodes(),
        "node_attributes_note": "Per node type: what it IS, `use_when` (when to create it vs an "
                                "alternative), and the `recommended` attrs to populate on graph_create_node "
                                "for a complete, consistent graph. KEY RULE: a dangerous library call "
                                "(system/exec/strcpy/sprintf) is a `symbol`/`function` node with "
                                "is_sink=true — do NOT also create a separate `sink` node for it; reserve "
                                "`sink` for an abstract dangerous point that is not already a node. Always "
                                "pass target_id for target-bound types so the node isn't an orphan.",
        "edge_types": [t.value for t in EdgeType],
        "edge_endpoint_kinds": ["target", "node", "finding", "task"],
        "edge_note": "Pass an `edge_types` value to graph_create_edge as the `type` param (it is "
                     "NOT named `edge_type`). A hypothesis IS a node (node_type='hypothesis'); "
                     "link a finding to it with dst_kind='node' + its id, or better use "
                     "graph_link_evidence(hypothesis_id, finding_id, relation) which also updates "
                     "the hypothesis status.",
        "edge_attribute_schemas": describe_edges(),
        "edge_attributes_note": "Edges carry attributes (edge.attrs) — the schema above lists what's "
                                "meaningful per type (e.g. a calls edge's call_sites + arg_constraints, a "
                                "listens_on edge's address). Pass them via graph_create_edge(attrs=…); use "
                                "graph_create_edge(merge=True) or graph_update_edge to ACCUMULATE list attrs.",
        "socket": {
            "kinds": list(SOCKET_KINDS),
            "note": "A `socket` node is a network/IPC endpoint SHARED across binaries. Make it with "
                    "graph_create_socket(kind, port|name); a server `listens_on` it and a client "
                    "`connects_to` it (both resolve to the one node). graph_list_sockets shows the map.",
        },
        "link_evidence_relations": ["supports", "refutes", "confirms", "contradicts"],
        "link_evidence_note": "relation is supports|refutes (confirms→supports, contradicts→refutes are "
                              "accepted aliases). The hypothesis status is then recomputed from its "
                              "evidence; pin a hard verdict with graph_set_hypothesis_status(id,'confirmed').",
        "hypothesis": {
            "status": list(HYP_STATUSES),
            "work_state": list(HYP_WORK_STATES),
            "note": "A hypothesis carries TWO orthogonal axes. `status` (evidence verdict, derived from "
                    "linked findings unless a human pins confirmed/rejected) answers 'what does the "
                    "evidence say?'. `work_state` (investigating/parked/done) is the WORKLIST axis — 'am "
                    "I on this?'. 'Checking off' = graph_close_hypothesis (work_state='done' + optional "
                    "verdict); list the worklist with graph_list_hypotheses. attrs.pinned_to_graph (default "
                    "off) controls whether it draws on the canvas — most live only in the worklist panel.",
        },
        "create_node_note": "Function/symbol/struct identity is (target, normalized name) — recon "
                            "pre-materializes function nodes (address=null). graph_create_node on an existing "
                            "one MERGES: it fills a missing address and unions attrs (it won't overwrite "
                            "a known address). The returned address/attrs show what actually landed.",
        "decompiler": _decompiler_info(),
        "substrate_vs_graph": "Two distinct stores, never conflated. The SUBSTRATE (the "
                              "Observation store + future persistent project) is the exhaustive, "
                              "queryable record of every tool result — the full function inventory, "
                              "the call graph, decompilations, xrefs. The GRAPH is the CURATED "
                              "subset you deliberately PROMOTE because it's an analysis result (the "
                              "functions under investigation, the sinks that matter, the taint path "
                              "behind a finding). Query freely against the substrate; promote only "
                              "what matters into the graph.",
        "observations": {
            "what": "Every deterministic tool call (decompile/decompile_at/disassemble/list/"
                    "call_graph/xrefs/function_xrefs/data_xrefs/strings/structs/taint/…) writes a "
                    "durable Observation: the call + a summary + the FULL payload in CAS, scoped to "
                    "the exact bytes by content_hash. Read them with obs_list(target_id) / "
                    "obs_get(id) / obs_search(query) over the metadata, or "
                    "re_search_decompiled(query) to grep across the decompiled function BODIES.",
            "contract": "Results persist HERE — they do NOT auto-populate the graph. CHECK HERE "
                        "BEFORE RE-RUNNING a heavy analysis (an identical call against identical "
                        "bytes is returned from the store, flagged cached — analyze once, reuse "
                        "forever). PROMOTE what matters into the graph deliberately (record a "
                        "finding, create a node/edge); an Observation is never itself a graph node.",
            "provenance": "A node/edge/finding promoted or enriched from a call carries "
                          "attrs.provenance=[observation_id,…]; the Observation carries node_refs "
                          "back — bidirectional navigation without polluting the graph.",
        },
        "annotation_kinds": sorted(ANN_KINDS),
        "annotation_node_kinds": sorted(ANN_NODE_KINDS),
        "annotation_note": "Annotations from an agent land status='proposed' (pending analyst approval).",
        "journal": {
            "authors": list(_JOURNAL_AUTHORS),
            "mention_ref_kinds": list(_JOURNAL_REF_KINDS),
            "mention_syntax": "@[label](kind:id)",
            "note": "The freeform research JOURNAL is interpreted NARRATIVE (idea/tried/worked/learned) — "
                    "NOT Observations (raw tool output) or findings (substantiated results). journal_add "
                    "always posts as the agent; journal_update/journal_delete refuse a HUMAN-authored entry "
                    "(authorship rule). @[label](kind:id) mentions (kind one of mention_ref_kinds) become "
                    "clickable links resolved through the merge keeper; a merged/archived target greys out.",
        },
        "verify_poc_oracles": {
            "note": "finding_verify_poc's oracle vocabulary. The classic in-band oracles prove a "
                    "REFLECTED side effect (best for reflected cmdi / auth-bypass); the extended "
                    "oracles below prove BROADER vuln classes by observing a side effect on a "
                    "channel INDEPENDENT of the exploit's request, so the model can't forge them "
                    "(docs/design/design-verification-oracles.md). All carry {{NONCE}} substitution.",
            "in_band": {
                "binary": ["output_contains", "exit_code", "exit_nonzero", "crash"],
                "web": ["body_contains", "status_is", "status_differs"],
                "tcp": ["response_contains"],
                "udp": ["response_contains"],  # a {transport:"udp", port, payload, oracle} raw-datagram PoC
            },
            "binary_spec": {
                "input_fields": "argv (TEXT list) | argv_b64 (RAW-BYTE list, each element base64'd) | "
                                "stdin (TEXT) | stdin_b64 (RAW BYTES, base64'd) | env (dict) | timeout.",
                "byte_faithful": "Use argv_b64/stdin_b64 — NOT argv/stdin — when the input contains "
                                 "NON-PRINTABLE bytes (e.g. an angr-SOLVER serial 0x3b25065c4b20040f). "
                                 "argv_b64 elements are decoded to bytes and exec'd as a RAW argv (POSIX "
                                 "exec takes a bytes argv); the text argv would str()-mangle them. "
                                 "argv_b64 takes precedence over argv; stdin_b64 over stdin. A byte-input "
                                 "PoC pairs with an output_contains/exit_code/crash oracle (NOT a "
                                 "reflected {{NONCE}}, which can't ride inside raw bytes).",
                "solver_handoff": "To verify an angr-solver finding's reproducer byte-faithfully, call "
                                  "finding_verify_poc(finding_id=<the solver finding>, poc={oracle:{…}}) "
                                  "with NO argv/stdin in the spec — HexGraph fills argv_b64 (or stdin_b64) "
                                  "from evidence.extra.solver (input_model + minimal_input_hex/"
                                  "concrete_input_hex). Pass an oracle matching the success path (e.g. "
                                  "output_contains the success string the solved path prints).",
            },
            "callback": {
                "use_for": "blind command-injection, SSRF, blind RCE, OOB exfil (NO reflected output)",
                "spec": "{steps|request|transport+port..., oracle:{type:'callback', timeout?:secs, "
                        "bind_host?}} — put a {{CALLBACK}} token (host:port + per-run nonce path) in "
                        "the injected command/SSRF URL (e.g. 'wget http://{{CALLBACK}}'). HexGraph "
                        "stands up a bounded LOCAL listener (loopback/private only, features.network-"
                        "gated, audited) and verifies it received a hit carrying the nonce.",
            },
            "canary_read": {
                "use_for": "arbitrary/relative file READ, path traversal, info/memory disclosure",
                "spec": "{plant:{channel:'rootfs', path} OR {known_value:'<a secret HexGraph reads "
                        "independently>'}, steps:[...the read...], oracle:{type:'canary_read'}}. "
                        "HexGraph plants a RANDOM canary out-of-band (or uses known_value) BEFORE "
                        "the exploit; the read primitive must return it. Use {{CANARY}} in the spec "
                        "to reference the planted value. Unforgeable: a random planted value can't "
                        "be guessed.",
            },
            "oob_write": {
                "use_for": "arbitrary file/config/NVRAM WRITE, persistence",
                "spec": "{steps:[...the write of {{NONCE}}...], oracle:{type:'oob_write', "
                        "channel:'rootfs'|'remote'|'http', path?:'/loc' | request?:{method,path}}}. "
                        "The exploit writes {{NONCE}}; HexGraph then INDEPENDENTLY reads that "
                        "location (rootfs read_file / remote read_file / a follow-up GET) and checks "
                        "the nonce landed. Reuses existing channels.",
            },
            "liveness": {
                "use_for": "denial of service / crash of a LIVE web or raw-TCP service (a rehosted "
                           "device, web_app, custom daemon). For a one-shot binary use the in-band "
                           "'crash' oracle instead (process death already covers it).",
                "spec": "{steps:[...the DoS request...]|transport+port+payload, oracle:{type:'liveness'"
                        "|'unavailable', probe?:{method,path}, port?:N, reprobes?:int=3 (1..20), "
                        "delay?:secs=0.5 (0..10)}}. "
                        "HexGraph probes the service is UP on its own channel (baseline), sends the "
                        "DoS input, then RE-PROBES it is DOWN and STAYS down across `reprobes` probes "
                        "(hysteresis) — a single transient blip does NOT verify. The verdict is "
                        "HexGraph's own out-of-band re-probe, never the exploit's response, so it's "
                        "unforgeable; if the service was already down at baseline the result is "
                        "INCONCLUSIVE (not verified). `probe` is the benign liveness GET (default "
                        "'GET /'); `port` is the raw-TCP port to connect-probe.",
            },
        },
        "assurance": {
            "ladder": _ASSURANCE_LADDER,
            "note": "Two STANDARDS of 'verified': code_present (the flaw exists in code) vs "
                    "input_reachable (it's triggerable via user input in normal operation), each by "
                    "method static (argued) or dynamic (a live trigger fired an unforgeable oracle), "
                    f"under a precondition ({' / '.join(_PRECONDITIONS)}). The "
                    "engine records this per finding in evidence.extra.assurance: a verified finding_verify_poc "
                    "→ input_reachable/dynamic (the strongest claims are engine-set and can't be faked); "
                    "any other vuln finding defaults to the FLOOR code_present/static. AIM FOR THE "
                    "STRICTEST: don't stop at code_present — craft a finding_verify_poc to demonstrate "
                    "input_reachable/dynamic, and prefer an unauthenticated precondition (pass "
                    "spec.precondition to finding_verify_poc, or evidence.extra.assurance to finding_record, to "
                    "declare the precondition / an argued input_reachable-static — but state "
                    "requires_credentials honestly; never claim unauth you didn't achieve).",
            "static_reachability": "When you CAN'T trigger it live (the service won't boot, no "
                    "exec tier), ARGUE reachability instead: build the input→sink path in the graph "
                    "(graph_create_node the input/param/endpoint/sink, graph_create_edge the taints/calls/"
                    "routes_to path), then call finding_reachability(finding_id=…). If a source→sink path "
                    "exists it UPGRADES code_present/static → input_reachable/static and records the "
                    "path + derived precondition (auth boundary on the path ⇒ requires_credentials; "
                    "an unauth boundary ⇒ unauthenticated). It NEVER downgrades a dynamic claim — a "
                    "live trigger always wins. taints is the strongest edge; a pure calls/routes_to "
                    "path argues reach but not operand-control, so prefer a taint path.",
            "presentation": "A verified PoC is shown to the analyst with its assurance triple, the "
                    "steps in plain language, and a copy-paste reproduction command (curl/nc/binary "
                    "invocation) HexGraph derives from the spec. The analyst can one-click Re-verify "
                    "(re-runs the STORED spec, no agent) — so keep the spec self-contained (complete "
                    "steps/argv/oracle, {{NONCE}} in payload AND oracle; target resolved from the "
                    "finding) and put a short how-it-works in summary/reasoning so it's actionable "
                    "without your trace.",
        },
        "yara": {
            "rulesets": _yara_rulesets_for_schema(),
            "note": "The ruleset ids re_yara_scan / re_yara_sweep accept (a bundled rule-file id, or "
                    "'all'). The agent picks WHICH ruleset by id — never a yara command line; the "
                    "rule files + match flags are fixed. User .yar files dropped in the "
                    "<HEXGRAPH_HOME>/yara_rules dir are ALWAYS included. A match promotes to a "
                    "`pattern` node + a `matches_rule` edge carrying the rule's declared severity/"
                    "cve; the matcher never fabricates a severity or auto-mints a finding — promote "
                    "a hit to a finding deliberately.",
        },
    }


def _yara_rulesets_for_schema() -> list[str]:
    """The bundled YARA ruleset ids for get_schemas. YARA is always-on (it relaxes no
    boundary), so the rulesets are always advertised — only an unreadable bundled dir
    yields an empty list."""
    try:
        from hexgraph.engine.re.yara import available_rulesets

        return available_rulesets()
    except Exception:  # noqa: BLE001
        return []


def create_hypothesis(project_id: str, statement: str, rationale: str | None = None,
                      target_id: str | None = None) -> dict:
    """Record a research hypothesis (findings can later support/refute it)."""
    from hexgraph.engine.graph.hypotheses import HypothesisError, create_hypothesis as _create, summary

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            node = _create(s, project, statement=statement, rationale=rationale, target_id=target_id)
            return summary(s, node.id)
        except HypothesisError as exc:
            return {"error": str(exc)}


def annotate(project_id: str, node_kind: str, node_id: str, kind: str, value: str) -> dict:
    """Attach a note/tag/rename to a graph entity (lands as an agent proposal)."""
    from hexgraph.engine.graph.annotations import AnnotationError, create_annotation

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            a = create_annotation(s, project_id, node_kind=node_kind, node_id=node_id,
                                  kind=kind, value=value, origin="agent")
        except AnnotationError as exc:
            return {"error": str(exc)}
        return {"id": a.id, "kind": a.kind, "status": a.status}


_INGEST_CHILD_PREVIEW = 20  # firmware can unpack into 100s of children; preview only


def ingest(path: str, name: str | None = None, project_id: str | None = None) -> dict:
    """Ingest a binary/firmware from a local path as a target (firmware unpacks into
    children), running recon in the sandbox. Creates a project if none is given. Returns a
    bounded summary (children_count + a preview of the first ~20 children); call
    target_list(project_id) for the full set."""
    import os

    from hexgraph.engine.targets.ingest import create_project, ingest_file
    from hexgraph.engine.pipeline import ingest_and_analyze
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not os.path.isfile(path):
        return {"error": f"file not found: {path!r} (resolved from the MCP server's working "
                          f"directory {os.getcwd()!r}). Pass an ABSOLUTE path."}
    with session_scope() as s:
        project = s.get(Project, project_id) if project_id else None
        if project is None:
            project = create_project(s, name=(name or os.path.basename(path)))
        if not docker_available():
            t = ingest_file(s, project, path, name=name)
            return {"project_id": project.id, "root_target_id": t.id, "recon": False,
                    "note": "Docker not running — registered without recon/unpack"}
        summary = ingest_and_analyze(s, project, path, name=name, runner=get_executor())
        children = summary.get("children", [])
        result = {
            "project_id": project.id,
            "root_target_id": summary["root_target_id"],
            "children_count": summary.get("children_count", len(children)),
            "children": children[:_INGEST_CHILD_PREVIEW],
        }
        if summary.get("format"):
            result["format"] = summary["format"]
        if len(children) > _INGEST_CHILD_PREVIEW:
            result["note"] = (f"{len(children)} children unpacked; showing the first "
                              f"{_INGEST_CHILD_PREVIEW}. Use target_list(project_id) for the "
                              f"full set.")
        else:
            result["note"] = "Use target_list(project_id) for the full target tree."
        return result


def register_web_surface(project_id: str, base_url: str, name: str | None = None,
                     endpoints: list | None = None) -> dict:
    """Register a WEB attack surface (a `web_app` target reached via an HTTP Channel —
    no bytes). Optionally pass an offline route spec `endpoints`:
    [{"method","path","params"?,"handler"?,"auth"?}]. Then run_task(target_id,
    "surface_recon") materialises endpoint/param nodes and `routes_to` edges linking
    each route to its handler function in the firmware. Phase 1 is offline (no egress)."""
    from hexgraph.engine.targets.surfaces import register_web_surface as _register_web_surface

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            t = _register_web_surface(s, project, base_url, name=name, endpoints=endpoints)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": t.id, "name": t.name, "kind": t.kind.value,
                "endpoints": len((t.metadata_json or {}).get("endpoints", []))}


def rehost(target_id: str, brand: str | None = None) -> dict:
    """Boot a FIRMWARE target under full-system emulation and register its live web server
    as a `web_app` surface child — so you can then assess the running device (surface_recon /
    web_recon / http_request / verify_poc), fused to the firmware's static graph. The rehoster
    is auto-selected from the image: qemu+KVM for a full-OS disk image (boots its own kernel),
    FirmAE for a vendor firmware blob (extracts the rootfs + supplies a kernel). Returns
    {surface_id, base_url}. Requires features.rehost (to boot) — and features.network to then
    talk to it. Heavy + best-effort: many images don't boot cleanly; the error says so.

    `brand` (FirmAE path only): the device vendor — linksys/netgear/dlink/tplink/tenda/… —
    FirmAE keys its network-inference NVRAM profiles on it. It's auto-inferred from the
    firmware's strings when present, but if rehost reports it couldn't bring up the device
    network, RETRY with the right brand explicitly (a stripped image won't name its vendor).

    If the booted device exposes SSH/telnet, rehost ALSO auto-registers it as a `remote`
    target (returned as `remote_target_id`) pinned to the emulator — run remote_list_files /
    remote_run on it to enumerate the LIVE device, not just the extracted rootfs (needs
    features.remote). `ports` lists every device port that answered, so you know which
    raw-TCP services are up to test."""
    from hexgraph.engine.targets.rehost import RehostError, rehost_firmware
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            surface = rehost_firmware(s, s.get(Project, t.project_id), t, brand=brand)
        except PolicyViolation:
            return {"error": "rehosting not permitted — enable features.rehost in Settings"}
        except RehostError as exc:
            return {"error": str(exc)}
        ch = (surface.metadata_json or {}).get("channel", {})
        rehost_info = ch.get("rehost") or {}
        return {"surface_id": surface.id, "name": surface.name, "base_url": ch.get("base_url"),
                "rehost": rehost_info,
                "remote_target_id": rehost_info.get("remote_target_id"),
                "ports": rehost_info.get("ports", [])}


def register_service(project_id: str, host: str, port: int, name: str | None = None,
                    transport: str = "tcp", proto: str | None = None,
                    parent_ref: str | None = None) -> dict:
    """Register a bare NON-HTTP network service (a raw TCP/UDP listener) as a `service`
    target — the FIRST-CLASS home for a bind shell, a vendor binary control protocol, or a
    custom daemon on some high port. Reached via a Channel `{kind: tcp|udp, host, port}`, no
    bytes, NO credentials (a socket service is a protocol endpoint you talk to, not a box you
    log into — do NOT misuse register_remote(transport=telnet) for this).

    Once registered you can fuzz it directly — start_fuzz_campaign(target) infers the
    `network` surface and points boofuzz at this host:port — and probe/prove it with the
    matching transport: tcp_request / verify_poc({transport:"tcp", port, …}) for a TCP
    service, udp_request / verify_poc({transport:"udp", port, …}) for a UDP one. All on the
    EXISTING bounded local-network tier: loopback/private host only (refused otherwise),
    features.network-gated, every send audited. `parent_ref` makes it a child of e.g. a
    rehosted firmware (the probe then reaches the device on its private IP through the
    emulator netns)."""
    from hexgraph.engine.targets.surfaces import register_service_target

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        parent = None
        net_container = None
        if parent_ref:
            parent = s.get(Target, parent_ref)
            if parent is None or parent.project_id != project_id:
                return {"error": "parent target not found in this project"}
            # Inherit a rehosted parent's emulator netns so the service on the device's
            # private IP is reachable (mirrors how rehost wires its remote/web children).
            net_container = (((parent.metadata_json or {}).get("channel") or {})
                             .get("rehost") or {}).get("container")
        try:
            t = register_service_target(s, project, host, port, transport=transport,
                                       proto=proto, name=name, parent=parent,
                                       net_container=net_container)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": t.id, "name": t.name, "kind": t.kind.value,
                "channel": (t.metadata_json or {}).get("channel")}


def register_remote(project_id: str, host: str, port: int | None = None, username: str = "root",
                    transport: str = "ssh", name: str | None = None) -> dict:
    """Register a LIVE remote device (a physical box on the bench, or a rehosted device) as a
    `remote` target reached over SSH/telnet — then run read-only analysis on it with
    remote_list_files / remote_read_file / remote_run. Credentials are NOT passed here: the
    operator sets them via env (HEXGRAPH_REMOTE_PASSWORD/KEY) or config.toml [remote], read
    only at connect (never stored). Requires features.remote."""
    from hexgraph.engine.targets.remote import register_remote_target

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            t = register_remote_target(s, project, host, port=port, username=username,
                                       transport=transport, name=name)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": t.id, "name": t.name, "kind": t.kind.value,
                "channel": (t.metadata_json or {}).get("channel")}


def _remote_op(target_id: str, **kw) -> dict:
    from hexgraph.engine.targets.remote import run_remote
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return run_remote(s, s.get(Project, t.project_id), t, **kw)
        except PolicyViolation:
            return {"error": "remote access not permitted — enable features.remote in Settings"}
        except ValueError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"remote op failed: {exc}"}


def remote_list_files(target_id: str, path: str = "/", max_depth: int = 3,
                      max_entries: int = 2000) -> dict:
    """Enumerate files on a live remote target (SSH/telnet) under `path` (bounded depth/count)
    — like list_filesystem for a box you don't have firmware for. Read-only. features.remote."""
    return _remote_op(target_id, op="list_files", path=path)


def remote_read_file(target_id: str, path: str, max_bytes: int | None = None) -> dict:
    """Read ONE file from a live remote target (bounded; text as-is, binary as hex) — configs,
    scripts, keys, /etc/passwd. Read-only, the device's own bytes. features.remote."""
    return _remote_op(target_id, op="read_file", path=path, max_bytes=max_bytes)


def remote_run(target_id: str, tool: str, path: str | None = None) -> dict:
    """Run ONE allowlisted READ-ONLY recon tool on a live remote target — `tool` in
    {uname,id,ps,netstat,mount,ifconfig,df,env,passwd,release,ls}. No arbitrary shell; a `path`
    (for ls) is shell-quoted. The same kinds of recon we'd run on a rehosted rootfs. features.remote."""
    if tool == "ls":
        return _remote_op(target_id, op="ls", path=path or "/")
    return _remote_op(target_id, op="run_tool", tool=tool, path=path)


def remote_launch(target_id: str, path: str, args: list | None = None) -> dict:
    """Start a service on a live remote/rehosted device that didn't auto-start — by BINARY
    PATH (+ optional args), backgrounded — so its socket comes up and you can test it live
    (e.g. a rehosted firmware's vulnerable daemon that emulation didn't launch). `path` and
    each arg are shell-quoted; this is the one non-read-only remote op (no arbitrary shell).
    Then reach it with tcp_request / verify_poc (a `tcp` spec) on its port. Returns the launch
    output (e.g. the pid). features.remote; egress pinned to the device + audited."""
    return _remote_op(target_id, op="launch", path=path, args=args or [])


def tcp_request(target_id: str, port: int, payload: str | None = None,
                read_bytes: int | None = None) -> dict:
    """Talk to a raw TCP service on a live device (rehosted surface or `remote` target) — the
    non-HTTP analogue of http_request. Connect to the device's `<port>` (reached through the
    emulator netns when rehosted), optionally send `payload` bytes, and read the response
    (bounded). Omit `payload` to just grab a banner. Use it to fingerprint a listening
    `socket`, or to drive a binary-protocol bug; to PROVE one, use verify_poc with a `tcp`
    spec ({transport:"tcp", port, payload:"…{{NONCE}}…", oracle:{type:"response_contains",
    value:"{{NONCE}}"}}) — the probe strips your sent bytes before matching, so a reflected
    payload can't forge it. Bounded to the device's loopback/private host:port, audited.
    `read_bytes` caps the response captured (default 64 KiB). Requires features.network."""
    from hexgraph.engine.targets.surfaces import run_tcp_probe
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return run_tcp_probe(s, s.get(Project, t.project_id), t, port=int(port),
                                 payload=payload, read_bytes=read_bytes)
        except PolicyViolation as exc:
            return {"error": f"not permitted: {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}


def udp_request(target_id: str, port: int, payload: str | None = None,
                read_bytes: int | None = None) -> dict:
    """Talk to a raw UDP service on a live device (rehosted surface or `remote` target) — the
    datagram analogue of tcp_request, for the firmware's large UDP surface (infosvr/9999,
    SSDP/1900, mDNS/5353, DNS, DHCP, WS-Discovery, a vendor discovery responder). Send one
    datagram of `payload` bytes to the device's `<port>` (reached through the emulator netns
    when rehosted) and read the bounded response; omit `payload` to probe with an empty packet.
    UDP is connectionless, so a silent service just yields no response (not an error). Use it
    to fingerprint a listening udp `socket`, or to drive a datagram-protocol bug; to PROVE one,
    use verify_poc with a `udp` spec ({transport:"udp", port, payload:"…{{NONCE}}…",
    oracle:{type:"response_contains", value:"{{NONCE}}"}}) — the probe strips your sent bytes
    before matching, so a reflected payload can't forge it. Bounded to the device's
    loopback/private host:port, audited. `read_bytes` caps the response captured (default
    64 KiB). Requires features.network."""
    from hexgraph.engine.targets.surfaces import run_udp_probe
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return run_udp_probe(s, s.get(Project, t.project_id), t, port=int(port),
                                 payload=payload, read_bytes=read_bytes)
        except PolicyViolation as exc:
            return {"error": f"not permitted: {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}


def http_request(target_id: str, method: str, path: str, params: dict | None = None,
                 headers: dict | None = None, body=None, json_body: bool = False,
                 session: str | None = None) -> dict:
    """Send ONE crafted HTTP request to a registered web surface and return the response
    (status, headers, and the body, capped at 64 KiB) — your hands for live web testing:
    log in, probe an auth check, fire an injection payload, read what comes back. `body`
    is form-encoded by default; set json_body=true to send it as JSON.

    Pass `session` (any label, e.g. "admin") to keep a COOKIE JAR across calls: cookies the
    server sets are remembered and re-sent on the next http_request with the same label, so
    a free-form auth flow works — log in once, then explore protected routes — without
    copying the session cookie by hand. The response lists the jar's cookie names in
    `session_cookies`. (For a single self-contained PoC, verify_poc's multi-step `steps`
    still carries cookies within one run; `session` is for interactive, multi-call probing.)

    Egress is bounded and audited exactly like web_recon: it runs in the sandbox, follows
    no redirects, and the destination must be the surface's own loopback/private host.
    Requires features.network enabled in Settings."""
    from hexgraph.engine.targets.surfaces import run_http_request
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        req = {"method": method, "path": path, "params": params or None,
               "headers": headers or None, "body": body, "json": bool(json_body)}
        req = {k: v for k, v in req.items() if v is not None}
        try:
            return run_http_request(s, s.get(Project, t.project_id), t, request=req,
                                    http_session=session)
        except PolicyViolation:
            return {"error": "egress not permitted — enable features.network in Settings (bounded, local-only)"}
        except ValueError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"request failed: {exc}"}


def verify_poc(target_id: str, poc: dict, finding_id: str | None = None) -> dict:
    """Prove an exploit really works and report verified true/false. Two flavours, chosen
    by the target:
    - **binary target** → executes it IN THE SANDBOX. Spec: {argv?, argv_b64?, env?, stdin?,
      stdin_b64?, timeout?, oracle:{type:"output_contains|exit_code|exit_nonzero|crash",
      value}}. Requires features.poc enabled. For RAW-BYTE input (a non-printable argv serial
      like 0x3b25065c4b20040f, or binary stdin) use `argv_b64` (a list of base64'd elements,
      exec'd as raw bytes) / `stdin_b64` instead of the text `argv`/`stdin` (which str()-mangle
      non-printable bytes); the byte fields take precedence and pair with an
      output_contains/exit_code/crash oracle. SOLVER HANDOFF: to verify an angr-solver finding's
      reproducer byte-faithfully, pass `finding_id`=<that finding> with poc={oracle:{…}} and NO
      argv/stdin — HexGraph fills argv_b64/stdin_b64 from evidence.extra.solver (input_model +
      minimal_input_hex/concrete_input_hex), so the solved input reaches the sink as a real
      argv[1] instead of being text-mangled.
    - **web surface** (a web_app registered with register_web_surface) → sends HTTP step(s).
      Spec: {steps:[{method,path,params?,headers?,body?,json?}, ...],
      oracle:{type:"body_contains|status_is|status_differs", value}}. Cookies carry across
      steps, so an auth flow works (e.g. step 1 POST /api/login with the bypass cred → step
      2 GET the protected route; oracle = body_contains the secret only an authed user
      sees). Requires features.network enabled (bounded local-only egress, audited).

    For an UNFORGEABLE check put {{NONCE}} in BOTH the injected command/payload and an
    `output_contains`/`body_contains` oracle value — HexGraph substitutes a fresh random
    token, so a match proves the injected behaviour actually happened (not something the
    model could fabricate).

    Beyond reflected output, extra oracles prove broader vuln classes by observing a side
    effect on a channel INDEPENDENT of the exploit's request (see get_schemas['verify_poc_oracles']):
    - blind cmdi / SSRF / blind RCE → oracle {type:'callback'} + a {{CALLBACK}} token in the
      payload (the target dials a bounded local listener HexGraph stands up; receiving the
      per-run nonce is proof even with NO reflected output);
    - arbitrary READ / traversal / disclosure → {plant:{channel,path}|{known_value}} + oracle
      {type:'canary_read'} (HexGraph plants a random canary out-of-band, the read must return it);
    - arbitrary WRITE / persistence → write {{NONCE}}, oracle {type:'oob_write', channel, path?}
      (HexGraph reads the written location back out-of-band and checks the nonce landed);
    - denial of service of a LIVE web/TCP service → oracle {type:'liveness', reprobes?, delay?,
      port?} (HexGraph probes UP, sends the DoS input, then re-probes DOWN and STAYS down across
      N probes — a transient blip does NOT verify; a binary degrades to the 'crash' oracle).

    A verified run records the strongest assurance — input_reachable / dynamic (see
    get_schemas['assurance']) — which an agent CANNOT fake (it requires the oracle to fire).
    Declare the access level the PoC needed via `spec.precondition` ("unauthenticated" /
    "requires_credentials:<which>"); otherwise it's inferred conservatively. AIM for an
    unauthenticated trigger; if you had to authenticate, say so — don't overstate reachability.

    Pass `finding_id` to attach the result to that finding (its evidence.extra.poc +
    .verification + .assurance) so it shows as `verified` in list_findings — the typed home for a
    confirmed exploit. ALWAYS attach: a confirmed vuln finding must carry its verified PoC."""
    from hexgraph.db.models import Finding
    from hexgraph.engine.findings.poc import (
        _spec_has_input,
        spec_from_solver_finding,
        verify_poc as _verify,
    )
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        poc = dict(poc or {})
        # SOLVER HANDOFF: when attaching to an angr-solver finding and the caller didn't supply
        # its OWN input, fill the recovered reaching-input as a BYTE-FAITHFUL argv_b64/stdin_b64
        # (input_model-driven) — so a solved non-printable argv serial verifies as a real argv[1]
        # instead of being str()-mangled. The caller's oracle (output_contains the success
        # string / crash / exit_code) is preserved; only the input is filled in.
        if finding_id and not _spec_has_input(poc):
            f0 = s.get(Finding, finding_id)
            derived = spec_from_solver_finding(f0, base_spec=poc) if f0 is not None else None
            if derived is not None:
                poc = derived
        try:
            r = _verify(s, s.get(Project, t.project_id), t, poc)
        except PolicyViolation:
            from hexgraph.engine.findings.poc import _is_web
            return {"error": ("egress not permitted — enable features.network in Settings to verify a web PoC"
                              if _is_web(t) else
                              "execution not permitted — enable features.poc in Settings to verify PoCs")}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"verification failed: {exc}"}
        # The rung to report back: when attached, the MERGED (never-downgraded) stored rung;
        # otherwise the rung this run alone established.
        out_assurance = r.get("assurance")
        if finding_id:
            f = s.get(Finding, finding_id)
            if f is not None:
                ev = dict(f.evidence_json or {})
                extra = dict(ev.get("extra") or {})
                # Store the ORIGINAL spec (with its {{NONCE}} placeholder intact), not the
                # nonce-substituted copy verify_poc ran — otherwise the placeholder is gone
                # and a later re-verify carries a stale literal nonce that can never match.
                extra["poc"] = poc
                # Record the target the PoC was authored/verified AGAINST so a later one-click
                # re-verify resolves the PoC's OWN target — which may differ from the finding's
                # target_id (e.g. a binary finding whose PoC fires against a child/live surface).
                extra["poc_target_id"] = target_id
                # The engine-computed assurance (standard/method/precondition) at the canonical
                # extra.assurance AND nested in verification (matching _poc_finding). MERGE via the
                # partial order so a write NEVER downgrades an already-stronger stored rung — a
                # failed/weaker re-verify keeps the prior assurance; a real re-confirmation at the
                # same/higher rung is fine. The triple is engine-computed and cannot be faked.
                from hexgraph.engine.findings.assurance import assurance_of, merge_assurance
                out_assurance = merge_assurance(assurance_of(ev), r.get("assurance"))
                extra["assurance"] = out_assurance
                extra["verification"] = {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                                         "exit_code": r.get("exit_code"), "nonce": r.get("nonce"),
                                         "output": (r.get("output") or "")[:2000],
                                         "assurance": out_assurance}
                # A human copy-paste reproduction command (display only; verify uses the spec).
                from hexgraph.engine.findings.poc_repro import repro_command
                repro = None
                try:
                    repro = extra["repro_command"] = repro_command(poc, t)
                except Exception:  # noqa: BLE001
                    pass
                ev["extra"] = extra
                if not ev.get("reproducer"):
                    repro_str = repro if isinstance(repro, str) else (" ".join(repro) if repro else None)
                    ev["reproducer"] = repro_str or json.dumps(poc)
                f.evidence_json = ev
        # Surface the engine-computed assurance triple {standard, method, precondition} in the
        # return so the agent sees the rung WITHOUT a follow-up get_finding.
        from hexgraph.engine.findings.assurance import compact_assurance
        return {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                "exit_code": r.get("exit_code"), "output": (r.get("output") or "")[:4000],
                "assurance": compact_assurance(out_assurance),
                "attached_to": finding_id if finding_id else None}


def recover_constant(target_id: str, function: str) -> dict:
    """Recover the CONSTANT/key a self-contained routine derives at runtime — a license code,
    an XOR key, a decoded string — by emulating it in Ghidra's P-Code interpreter IN THE
    SANDBOX (the JVM interpreter; NEVER native execution, no network). Use when a value never
    appears as a literal and decompile_function shows only the arithmetic that computes it.

    ENRICH: on success, tags the recovered value onto the function node
    (attrs.recovered_constant / _hex) and records an `emulation` Observation — it adds no new
    graph nodes (review it, then promote/record what matters).

    Opt-in: requires features.emulation (a heavy-analysis gate that relaxes NO sandbox
    boundary). Returns available=false when the Ghidra headless decompiler isn't active. Best on a
    SELF-CONTAINED, parameterless routine — one that takes arguments is emulated over uninitialized
    inputs and usually won't reach a clean `ret`, so it yields no recoverable value. When the
    routine's recovered signature shows it takes arguments, this RETURNS EARLY without emulating
    ({skipped:"arg_dependent", param_count, error pointing at re_solve_constraint}) — recover a
    value/input that satisfies a check with the solver instead. Returns {available, function,
    value, value_hex, reached_ret, steps, observation_id, error}."""
    from hexgraph.engine.re.emulation import emulate_constant
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return emulate_constant(s, s.get(Project, t.project_id), t, function=function)
        except PolicyViolation:
            return {"error": "emulation not permitted — enable features.emulation in Settings "
                             "to recover a constant by emulating a routine in the sandbox"}
        except Exception as exc:  # noqa: BLE001 — a sandbox/Ghidra hiccup degrades to an error note
            return {"error": f"emulation failed: {exc}"}


def solve_reaching_input(target_id: str, sink_func: str, function: str | None = None,
                         budget: str | None = None) -> dict:
    """SOLVE for a concrete input that DRIVES execution to a sink (e.g. system) via angr symbolic
    execution in the dedicated angr sandbox image — the strongest STATIC claim short of a live
    PoC, because it produces a concrete reaching input (often non-ASCII bytes). You give the sink
    selector; HexGraph runs the bounded, deterministic solve (DFS + wall-clock/step/state caps) —
    you never write an angr script.

    PROMOTE: on success it promotes the grounded path (the sink + the enclosing function + a `calls`
    edge) and emits a high-confidence `vulnerability` finding whose evidence.reproducer is the solved
    input (hex), assurance input_reachable/static; records a `solver` Observation either way. Opt-in
    (features.angr — heavy, policy-gated like emulation; relaxes no boundary). `budget` is
    quick|default|deep. Returns {solved, observation_id, finding_id, concrete_input, ...} or
    {solved:false, reason} / {error}."""
    from hexgraph.engine.re.solving import solve_reaching_input as _solve

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        return _solve(s, s.get(Project, t.project_id), t, sink_func=sink_func,
                      function=function, budget=budget, source="agent")


def solve_constraint(target_id: str, function: str | None = None, check_addr: str | None = None,
                     sink_func: str | None = None, budget: str | None = None) -> dict:
    """Recover the VALUE/input that SATISFIES a single check (a secret a strcmp compares against,
    a serial a gate validates) via angr — the symbolic-execution analogue of recover_constant.
    ENRICH: on success annotates the function node with the recovered value (attrs.recovered_value
    / satisfying_input_hex) and records a `solver` Observation; adds no new graph nodes. Single-
    check solving ONLY. `function` names the routine; optionally `check_addr` pins the pass block,
    or `sink_func` when the check gates a sink. Opt-in (features.angr). `budget` is
    quick|default|deep. Returns {solved, observation_id, recovered_value, ...} / {error}."""
    from hexgraph.engine.re.solving import solve_constraint as _solve

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        return _solve(s, s.get(Project, t.project_id), t, function=function,
                      check_addr=check_addr, sink_func=sink_func, budget=budget, source="agent")


def reachability(finding_id: str | None = None, sink_node_id: str | None = None,
                 max_depth: int = 12, precondition: str | None = None) -> dict:
    """Argue STATIC input-reachability (Standard B, static) — search the typed graph for a
    directed source→sink path so a finding can claim `input_reachable/static` even when you can't
    trigger it live (the DIR-823G case: a real sink, but the service won't boot). Pass `finding_id`
    (resolves the sink it cites + RECORDS the path & upgraded assurance on the finding) and/or
    `sink_node_id`. With finding_id ALONE the sink is resolved from the finding's `about`→sink edge
    / evidence.sink; pass BOTH to OVERRIDE that resolution with an explicit sink node while still
    recording the upgraded assurance on the finding (use this when the finding doesn't cite the
    sink via an `about` edge yet). `sink_node_id` ALONE just reports a path to that sink.

    Sources = the untrusted boundary (input/param/endpoint/socket nodes, or a function/symbol you
    marked attrs.entry); the search follows taints/calls/routes_to/reads/writes/references FORWARD
    (taints is the strongest dataflow signal) and is depth-bounded + cycle-safe. The precondition
    is derived from the path: crossing an auth boundary (an endpoint/param with attrs.auth set, or
    a `bypasses` edge) ⇒ requires_credentials; starting at an explicitly-unauth boundary ⇒
    unauthenticated; else unspecified. It is an ARGUMENT, not a trigger: it only UPGRADES a
    code_present/static floor and NEVER downgrades a dynamic claim. Build the graph first
    (create_node the input/sink + create_edge the taints/calls path), then call this."""
    from hexgraph.engine.findings.reachability import (ReachabilityError,
                                              argue_reachability_for_finding,
                                              find_source_to_sink_path)

    if not finding_id and not sink_node_id:
        return {"error": "pass finding_id and/or sink_node_id"}
    from hexgraph.engine.findings.assurance import PRECONDITIONS

    if precondition is not None and precondition not in PRECONDITIONS:
        return {"error": f"precondition must be one of {PRECONDITIONS}"}
    with session_scope() as s:
        try:
            if finding_id:
                # Thread sink_node_id through so an explicit sink OVERRIDES the finding's
                # about→sink / evidence.sink resolution (F12: it was silently dropped before).
                return argue_reachability_for_finding(s, finding_id, max_depth=max_depth,
                                                      precondition=precondition,
                                                      sink_node_id=sink_node_id)
            n = s.get(Node, sink_node_id)
            if n is None:
                return {"error": "sink node not found"}
            res = find_source_to_sink_path(s, n.project_id, sink_node_id, max_depth=max_depth,
                                           precondition=precondition)
            if res is None:
                return {"found": False, "sink_node_id": sink_node_id,
                        "detail": f"no source→sink path within {max_depth} hops to {n.name!r}"}
            return {"found": True, "sink_node_id": sink_node_id, **res}
        except ReachabilityError as exc:
            return {"error": str(exc)}


def merge_duplicates(project_id: str) -> dict:
    """Collapse duplicate binaries/nodes (e.g. sym.foo == foo) in a project, moving
    all edges/findings/annotations to the keeper. Safe to call anytime."""
    from hexgraph.engine.graph.nodemerge import merge_duplicates as _merge

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        return _merge(s, project_id)


def link_same_code(project_id: str) -> dict:
    """Cross-target n-day primitive: link function nodes that share identical code
    (same content_hash) across DIFFERENT binaries with a `similar_to` edge. After you
    confirm a bug in one binary, call this to find the same routine reused in other
    firmware components, then check each for the same flaw. Returns the matched pairs."""
    from hexgraph.db.models import Edge, EdgeType
    from hexgraph.engine.graph.crosstarget import link_same_code as _link

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        created = _link(s, project_id)
        s.flush()

        def findings_about(node_id: str) -> list[str]:
            # Findings attached to this node via an `about` edge.
            rows = (s.query(Edge)
                    .filter(Edge.project_id == project_id, Edge.type == EdgeType.about.value,
                            Edge.src_kind == "finding", Edge.dst_kind == "node", Edge.dst_id == node_id)
                    .all())
            return [r.src_id for r in rows]

        def side(n: Node) -> dict:
            fids = findings_about(n.id)
            return {"node_id": n.id, "target_id": n.target_id, "finding_ids": fids,
                    "has_findings": bool(fids)}

        matches = []
        edges = (s.query(Edge)
                 .filter(Edge.project_id == project_id, Edge.type == EdgeType.similar_to.value)
                 .limit(200).all())
        for e in edges:
            a, b = s.get(Node, e.src_id), s.get(Node, e.dst_id)
            if a is None or b is None:
                continue
            matches.append({"function": a.name, "a": side(a), "b": side(b)})
        return {"edges_created": created, "matches": matches,
                "hint": "If one side has_findings and the other doesn't, the bug likely "
                        "propagates — use finding_propagate(finding_id, target_id) on the bare side."}


def run_task(target_id: str, type: str, objective: str | None = None, params: dict | None = None) -> dict:
    """Run a HexGraph task synchronously (recon/static_analysis/harness_generation/
    fuzzing/…) and return its status + the findings it produced."""
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        project = s.get(Project, t.project_id)
        project_id = project.id
        task = create_task(s, project=project, target_id=t.id, type=type, objective=objective,
                           backend=project.llm_backend.value, params=params or {})
        task_id = task.id
    status = run_task_sync(task_id)
    with session_scope() as s:
        # Fold any duplicate function/symbol nodes (e.g. an agent's `foo` colliding with a
        # decompiler-seeded `sym.foo`) so the graph converges instead of accumulating dupes.
        from hexgraph.engine.graph.nodemerge import merge_duplicate_nodes
        merged = merge_duplicate_nodes(s, project_id)
        findings = s.query(Finding).filter(Finding.task_id == task_id).all()
        out = {"task_id": task_id, "status": status,
               "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in findings]}
        if merged:
            out["nodes_merged"] = merged
        return out


# The catalog (GROUPS + the (group, name, fn, description, schema) tuples = the
# agent-facing prompt copy) lives in the sibling `mcp_catalog` module to keep this
# file to the tool implementations. `mcp_catalog` imports the tool functions from
# here, so the dependency runs ONE WAY (catalog -> tools). To keep existing callers
# of `mcp_tools.catalog` / `from hexgraph.agent.mcp_tools import GROUPS, catalog`
# working WITHOUT importing `mcp_catalog` at module load (which would close the
# cycle), re-export lazily via PEP 562 — resolved on first attribute access, after
# both modules are fully initialized regardless of which was imported first.
_CATALOG_REEXPORTS = ("GROUPS", "_CATALOG", "catalog")


def __getattr__(name: str):  # noqa: D401 — module-level lazy re-export (PEP 562)
    if name in _CATALOG_REEXPORTS:
        from hexgraph.agent import mcp_catalog
        return getattr(mcp_catalog, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

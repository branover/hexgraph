"""The `binutils` quick-facts helper (design §3.1, Phase 5A PR 5A-1).

Runs the sandboxed `binutils_probe` over a target — the canonical GNU binutils
(nm / objdump / readelf / strings) — and records its authoritative low-level facts
as a single `binutils_facts` Observation, scoped to the analyzed bytes. There is NO
new seam (these are deterministic facts, not a swappable backend) and NO policy gate
(static, no execution, no network — it rides the existing recon/analysis surface,
exactly like recon).

It does NOT mint nodes. The Observation is the durable substrate; the always-welcome
SUBSET of these facts auto-enriches objects that already exist via the enrichment
extractor registered below (imports → `symbol`/`is_sink`, mitigation flags →
target metadata). Promote what matters into the graph deliberately — the probe feeds
the substrate, it does not re-flood the graph (the Phase O curation rule; it defers
to recon's tight import/string caps).
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.engine import observations as O

RESULT_KIND = "binutils_facts"

# search_symbols_project caps (mirrors the single-target grep's no-silent-flood discipline).
_SEARCH_MATCH_CAP = 500
_SEARCH_PATTERN_MAX = 512

_REUSE_HINT = (
    "binutils facts persist as a binutils_facts Observation on this target; they do NOT "
    "add graph nodes. Check list_observations(target_id) before re-running, and "
    "get_observation(id) for the full payload (symbols/imports/exports/relocations/"
    "sections/mitigations)."
)


def _summary(facts: dict) -> str:
    mit = facts.get("mitigations", {}) or {}
    weak = [k for k in ("nx", "canary", "pie") if mit.get(k) is False]
    relro = mit.get("relro")
    if relro in ("none", "partial"):
        weak.append(f"relro={relro}")
    weak_str = f"weak: {', '.join(weak)}" if weak else "standard mitigations"
    return (f"{facts.get('elf_type') or 'ELF'} {facts.get('machine') or ''}: "
            f"{len(facts.get('imports', []))} imports, {len(facts.get('exports', []))} exports, "
            f"{len(facts.get('sections', []))} sections; {weak_str}").strip()


def collect_binutils_facts(
    session: Session,
    project: Project,
    target: Target,
    *,
    source: str = "agent",
    runner=None,
) -> dict:
    """Run `binutils_probe` in the sandbox and record a `binutils_facts` Observation.

    Returns a dict with the raw `facts`, the recorded `observation_id`, a `cached`
    flag (the call dedups by content_hash, so a repeat returns the prior row), and the
    standing reuse hint — or `{"error": ...}` when the sandbox is down or the artifact
    isn't an analyzable ELF. Creates ZERO graph nodes; enrichment of ALREADY-existing
    nodes fires automatically inside record_observation.
    """
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import SandboxError, docker_available

    if runner is None:
        if not docker_available():
            return {"error": "binutils facts unavailable (Docker/sandbox not running)"}
        runner = get_executor()
    if not str(target.path or "").strip():
        return {"error": "this target has no byte artifact (a Channel-reached surface has no ELF to inspect)"}
    try:
        facts = runner.run_json_probe("binutils_probe.py", target.path)
    except SandboxError as exc:
        # A non-ELF / unreadable artifact exits non-zero with an error JSON; the runner
        # surfaces that reason. Return it rather than raising so the tool call survives.
        return {"error": f"binutils facts failed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"binutils facts failed: {exc}"}

    obs, cached = O.record_observation(
        session,
        project_id=project.id,
        target_id=target.id,
        source=source,
        tool="binutils_facts",
        args={},
        result_kind=RESULT_KIND,
        payload=facts,
        summary=_summary(facts),
        content_hash=O.content_hash_for(target),
    )
    # The dangerous-import `is_sink` enrichment fired inside record_observation (the
    # shared extractor). Mitigation flags are the TARGET analogue — fold them onto the
    # target's metadata (idempotent; a re-apply is a no-op).
    apply_mitigations_to_target(target, facts)
    return {
        "facts": facts,
        "observation_id": obs.id if obs is not None else None,
        "cached": cached,
        "reuse_hint": _REUSE_HINT,
    }


# --- the always-welcome target-metadata enrichment (design §3.1, §5.4) --------
# The `is_sink` enrichment for dangerous imports rides the SHARED extractor registered
# in engine.re.enrichment ("binutils_facts" → DANGEROUS_IMPORTS path), so it fires
# automatically inside record_observation. Mitigation flags describe the TARGET, not a
# node, so they don't pass through the node-fact index — they're recorded here instead.

def apply_mitigations_to_target(target: Target, facts: dict) -> bool:
    """Record the always-welcome mitigation flags on the TARGET's metadata_json (the
    target analogue of the symbol enrichment — a mitigation describes the whole binary,
    not a node). Idempotent: returns True only if anything actually changed, so a
    re-apply is a no-op. Never overwrites a value with None."""
    mit = facts.get("mitigations") if isinstance(facts, dict) else None
    if not isinstance(mit, dict):
        return False
    meta = dict(target.metadata_json or {})
    existing = dict(meta.get("mitigations") or {})
    merged = dict(existing)
    for k, v in mit.items():
        if v is not None and merged.get(k) != v:
            merged[k] = v
    if merged == existing:
        return False
    meta["mitigations"] = merged
    target.metadata_json = meta
    return True


# --- project-wide symbol/function NAME search (the name analogue of yara_sweep) ------
# Cross-target, engine-level: iterate every non-archived target and test a NAME pattern
# against its symbol/function set — reading ALREADY-stored substrate (recon metadata +
# prior binutils_facts / function_list Observations), NEVER running a probe or a decompile.
# So it locates which binary in a firmware DEFINES/IMPORTS a shared helper without paying a
# per-target sweep. The feasibility caveat (surfaced in the result): a target whose symbols
# were never collected can't be searched — reported as `targets_without_symbols`.

def _symbol_source_for_target(session: Session, target: Target) -> dict | None:
    """The name sets to search for one target: {imports, exports, functions}. Prefers the
    cached binutils_facts Observation (facts.symbols/imports/exports), falls back to the
    recon metadata imports/exports, and adds function names from a prior function_list
    Observation when present. Returns None when NO symbol source exists for this target
    (so a miss on it isn't read as authoritative — it's counted in targets_without_symbols)."""
    imports: set[str] = set()
    exports: set[str] = set()
    functions: set[str] = set()
    have_source = False

    # 1) the authoritative binutils_facts Observation (newest), when one was collected.
    rows = O.list_observations(session, target.id, kind=RESULT_KIND, limit=1)
    if rows:
        full = O.get_observation(session, rows[0]["id"]) or {}
        facts = full.get("payload") if isinstance(full.get("payload"), dict) else None
        if isinstance(facts, dict):
            have_source = True
            imports.update(str(n) for n in (facts.get("imports") or []) if n)
            exports.update(str(n) for n in (facts.get("exports") or []) if n)
            # facts.symbols carries nm rows {name,type,address}; an UND (U/w) row is an import,
            # a defined row is an export/definition. Fold both so a defined symbol not in the
            # `exports` list (a local T) is still searchable.
            for sym in (facts.get("symbols") or []):
                name = sym.get("name") if isinstance(sym, dict) else None
                if not name:
                    continue
                typ = (sym.get("type") or "").strip() if isinstance(sym, dict) else ""
                (imports if typ in ("U", "w", "v") else exports).add(str(name))

    # 2) recon metadata imports/exports — the cheap fallback (present without a facts probe).
    meta = target.metadata_json or {}
    m_imports = [str(n) for n in (meta.get("imports") or []) if n]
    m_exports = [str(n) for n in (meta.get("exports") or []) if n]
    if m_imports or m_exports:
        have_source = True
        imports.update(m_imports)
        exports.update(m_exports)

    # 3) function names from a prior function_list Observation (optional; the decompiler's
    # whole-program inventory — a name that's neither an import nor an export can still match).
    frows = O.list_observations(session, target.id, kind="function_list", limit=1)
    if frows:
        ffull = O.get_observation(session, frows[0]["id"]) or {}
        fpayload = ffull.get("payload") if isinstance(ffull.get("payload"), dict) else None
        if isinstance(fpayload, dict):
            fns = [str(n) for n in (fpayload.get("functions") or []) if n]
            if fns:
                have_source = True
                functions.update(fns)

    if not have_source:
        return None
    return {"imports": imports, "exports": exports, "functions": functions}


def search_symbols_project(
    session: Session, project: Project, *, pattern: str,
    kind: str | None = None, regex: bool = False, limit: int | None = None,
) -> dict:
    """Search a symbol/function NAME pattern across ALL non-archived targets in a project —
    which target(s) DEFINE or IMPORT a match. Reads per-target recon metadata + prior
    binutils_facts / function_list Observations (no probe, no per-target decompile), so it
    mirrors yara_sweep's cross-target roll-up over already-computed substrate.

    `kind` scopes to imports|exports|defined|all (default all; `defined`==exports here).
    `regex=true` matches a regex (guarded — a too-long/un-compilable pattern falls back to a
    case-insensitive substring test, never raises). Returns {pattern, matches:[{target_id,
    name, kind(import|export|function), address?}], scanned, hits, targets_without_symbols}.
    A target with NO stored symbol source is counted in `targets_without_symbols` (run
    re_binutils_facts on it first) so a miss there isn't mistaken for the whole-project truth."""
    pat = (pattern or "").strip()
    if not pat:
        return {"error": "pattern is required"}
    scope = (kind or "all").lower()
    if scope not in ("imports", "exports", "defined", "all"):
        return {"error": "kind must be one of imports|exports|defined|all "
                         f"(got {kind!r})"}

    # A cheap, SAFE matcher (mirrors agent_tools._compile_grep): case-insensitive regex when
    # asked and it compiles, else a case-insensitive substring test.
    if regex and len(pat) <= _SEARCH_PATTERN_MAX:
        try:
            rx = re.compile(pat, re.IGNORECASE)
            def match(name: str) -> bool:
                return bool(rx.search(name))
        except re.error:
            low = pat.lower()
            def match(name: str) -> bool:  # bad regex -> substring, no crash
                return low in name.lower()
    else:
        low = pat.lower()
        def match(name: str) -> bool:
            return low in name.lower()

    want_imports = scope in ("imports", "all")
    want_exports = scope in ("exports", "defined", "all")

    targets = (
        session.query(Target)
        .filter(Target.project_id == project.id, Target.archived.is_(False))
        .all()
    )
    matches: list[dict] = []
    scanned = 0
    without: list[dict] = []
    capped = False
    for t in targets:
        src = _symbol_source_for_target(session, t)
        if src is None:
            without.append({"target_id": t.id, "name": t.name})
            continue
        scanned += 1
        # (name, kind) rows for this target, de-duped, scoped by `kind`. A name that is both an
        # import and an export is reported once per role it satisfies within the requested scope.
        seen: set[tuple] = set()
        buckets = []
        if want_imports:
            buckets.append(("import", src["imports"]))
        if want_exports:
            buckets.append(("export", src["exports"]))
        # Function names only broaden an `all` search (they're neither an import nor export role).
        if scope == "all":
            buckets.append(("function", src["functions"]))
        for role, names in buckets:
            for name in names:
                if not match(name):
                    continue
                key = (name, role)
                if key in seen:
                    continue
                seen.add(key)
                matches.append({"target_id": t.id, "name": name, "kind": role})
                if len(matches) >= (limit or _SEARCH_MATCH_CAP):
                    capped = True
                    break
            if capped:
                break
        if capped:
            break

    return {
        "pattern": pat,
        "kind": scope,
        "regex": bool(regex),
        "matches": matches,
        "scanned": scanned,
        "hits": len(matches),
        "targets_without_symbols": without,
        "capped": capped,
    }

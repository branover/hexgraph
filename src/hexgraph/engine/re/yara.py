"""The YARA pattern-sweep helper (design §3.3, Phase 5B).

Matches the project's targets and extracted firmware files against a set of YARA rules
— a researcher's (or a bundled rule's) signature for a vulnerable code pattern, an
embedded credential, a known-bad library banner, a weak-crypto constant, a packer
signature. This is the *fuzzy/structural* complement to the *exact-hash* n-day link
`crosstarget.link_same_code`: where that finds byte-identical functions, YARA finds the
pattern matches an analyst can author.

There is NO new seam (YARA is a matcher, not a swappable analysis backend) and NO policy
gate: matching is static — it reads bytes, never executes the target, opens no socket, so
it relaxes no sandbox/exec/egress boundary and touches NO policy tier (`policy.py` is
untouched). YARA rides the static surface UNGATED, like recon and binutils — it relaxes no
boundary, so there is no `features.yara` toggle; it is always available wherever the
sandbox is up. Rule management is still an operator surface (drop your own `.yar` files in
the HEXGRAPH_HOME rules dir), but that no longer gates whether the matcher runs.

Curation (design §2.5, §3.3). Every scan records a `yara_matches` Observation on the
scanned target, scoped to the analyzed bytes. A match PROMOTES to a project-level
`pattern` node (the kind already exists, identity `(project, content_hash)`) and a
`matches_rule` edge from the scanned target → that pattern. The pattern node carries the
rule's declared meta (severity/confidence/category/cve), surfaced so a deliberate
finding-promotion is grounded in the RULE — the matcher itself NEVER fabricates a severity
and never auto-mints a finding (the design's §7 ruling). We do not auto-flood the graph:
one pattern node per matched rule, deduped across the whole project.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Node, NodeType, Project, Target
from hexgraph.engine import observations as O

RESULT_KIND = "yara_matches"
MATCHES_RULE = EdgeType.matches_rule  # zero-migration String edge vocab (registered in edge_schemas)

# Container mount points for the read-only rule directories (the runner mounts the host
# rule dirs here; the probe reads them with --rules-dir). Bundled rules are HexGraph's own
# trusted bytes — NOT target bytes — so mounting them needs no sandboxing; the MATCH still
# runs in the locked-down container.
_BUNDLED_MOUNT = "/rules/bundled"
_USER_MOUNT = "/rules/user"

# The agent's single knob (design §2.8): WHICH bundled ruleset to sweep, by id, or "all".
# A ruleset id is the rule FILE stem under the bundled dir; "all" includes every bundled
# file (plus any user rules, always). Everything else (the rule files, the match flags) is
# fixed. The id maps to a file here — the agent never supplies a path or a yara command line.
RULESET_ALL = "all"


_REUSE_HINT = (
    "YARA matches persist as a yara_matches Observation on the scanned target and promote to "
    "project-level `pattern` nodes via `matches_rule` edges (one pattern per matched rule, "
    "deduped). Check list_observations(target_id, kind='yara_matches') before re-running. A "
    "match carries the rule's declared severity/cve in the pattern's attrs — promote a match "
    "to a finding deliberately (the sweep never fabricates a severity or auto-mints a finding)."
)


def available_rulesets() -> list[str]:
    """The bundled ruleset ids the agent may choose from (plus the implicit "all").

    A ruleset id is a bundled rule FILE stem (e.g. `hexgraph_packers`). User rules in the
    HEXGRAPH_HOME rules dir are ALWAYS included regardless of the chosen bundled set, so
    they're not listed as separable ids."""
    from hexgraph.paths import bundled_yara_rules_dir

    d = bundled_yara_rules_dir()
    if not d.is_dir():
        return [RULESET_ALL]
    stems = sorted({p.stem for p in d.iterdir()
                    if p.is_file() and p.suffix.lower() in (".yar", ".yara")})
    return [RULESET_ALL, *stems]


def _validate_ruleset(ruleset: str | None) -> str:
    """Validate + normalize the ruleset id (the agent knob); raise ValueError on an unknown
    id. No staging/mounting, so the project sweep can validate once up front cheaply."""
    eff = (ruleset or RULESET_ALL).strip() or RULESET_ALL
    valid = set(available_rulesets())
    if eff not in valid:
        raise ValueError(f"unknown ruleset {eff!r}; choose one of {sorted(valid)} (or 'all')")
    return eff


def _cleanup_dirs(dirs: list[Path]) -> None:
    """Remove staged temp rule dirs after a scan (best-effort; nothing to do on the 'all' path)."""
    import shutil

    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)


def _resolve_rule_mounts(
    ruleset: str | None,
) -> tuple[list[tuple[str, str]], list[str], str, list[Path]]:
    """Resolve the (host, container) read-only mounts and the probe's --rules-dir args for
    a chosen ruleset.

    Returns `(mounts, rules_dir_args, effective_ruleset, cleanup_dirs)` — the caller MUST
    remove `cleanup_dirs` after the run. The bundled set is mounted at a container dir holding
    only the selected file(s); the user rules dir (if it exists and has rules) is ALWAYS
    mounted too. Raises ValueError on an unknown ruleset id."""
    import tempfile

    from hexgraph import config
    from hexgraph.paths import bundled_yara_rules_dir

    bundled = bundled_yara_rules_dir()
    eff = _validate_ruleset(ruleset)

    mounts: list[tuple[str, str]] = []
    rules_dir_args: list[str] = []
    cleanup: list[Path] = []

    if eff == RULESET_ALL:
        if bundled.is_dir():
            mounts.append((str(bundled), _BUNDLED_MOUNT))
            rules_dir_args += ["--rules-dir", _BUNDLED_MOUNT]
    else:
        # A single bundled ruleset: mount a tmp dir holding just that file so the probe
        # compiles only the requested rules. The tmp dir is the runner's host-side bind
        # source; the container sees it read-only at _BUNDLED_MOUNT.
        src = None
        for ext in (".yar", ".yara"):
            cand = bundled / f"{eff}{ext}"
            if cand.is_file():
                src = cand
                break
        if src is not None:
            # The sandbox runs as a NON-ROOT user (uid 1000); mkdtemp is 0700, so the staged
            # dir + file must be made world-readable or the container can't read the mounted
            # rules (the in-sandbox PermissionError CI caught). Hand the dir back for cleanup.
            staged = Path(tempfile.mkdtemp(prefix="hg-yara-rules-"))
            dst = staged / src.name
            dst.write_bytes(src.read_bytes())
            staged.chmod(0o755)
            dst.chmod(0o644)
            cleanup.append(staged)
            mounts.append((str(staged), _BUNDLED_MOUNT))
            rules_dir_args += ["--rules-dir", _BUNDLED_MOUNT]

    user_dir = config.yara_rules_dir()
    if user_dir.is_dir() and any(
        p.suffix.lower() in (".yar", ".yara") for p in user_dir.iterdir() if p.is_file()
    ):
        mounts.append((str(user_dir), _USER_MOUNT))
        rules_dir_args += ["--rules-dir", _USER_MOUNT]

    return mounts, rules_dir_args, eff, cleanup


def _summary(facts: dict, ruleset: str) -> str:
    n = facts.get("match_count", 0)
    rules = [m.get("rule") for m in (facts.get("matches") or [])][:6]
    rs = "all" if ruleset == RULESET_ALL else ruleset
    head = f"YARA [{rs}]: {n} rule match{'es' if n != 1 else ''}"
    return (head + (": " + ", ".join(r for r in rules if r) if rules else "")).strip()


def _pattern_hash(rule: str, namespace: str | None) -> str:
    """Stable project-level identity for a matched rule's `pattern` node. A `pattern`
    node's identity is (project, content_hash); deriving it from the rule's name +
    namespace dedups the SAME rule's matches across every target to ONE pattern node,
    so the graph shows 'rule X matched in targets A, B, C' rather than N copies."""
    key = f"yara::{namespace or ''}::{rule}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _promote_matches(
    session: Session, project: Project, target: Target, facts: dict, observation_id: str | None,
) -> list[dict]:
    """Promote each matched rule to a project-level `pattern` node + a `matches_rule` edge
    from the scanned target to it. Idempotent (pattern identity is the rule; the edge
    merges), so a re-sweep doesn't duplicate. Returns a compact list of the promotions."""
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.graph.nodes import get_or_create_node

    promoted: list[dict] = []
    for m in facts.get("matches") or []:
        rule = m.get("rule")
        if not rule:
            continue
        meta = m.get("meta") or {}
        ch = _pattern_hash(rule, m.get("namespace"))
        # The pattern node: a reusable signature, identity = (project, content_hash).
        # `signature` is the recommended attr (node_schemas); we also carry the rule's
        # declared meta so a deliberate finding-promotion is grounded in the rule, never
        # a guess. attrs are merged on re-create (get_or_create_node), so the latest
        # rule meta refreshes in place.
        attrs = {
            "signature": meta.get("description") or rule,
            "rule": rule,
            "source": "yara",
        }
        for k in ("severity", "confidence", "category", "cve", "author", "reference"):
            if meta.get(k) is not None:
                attrs[k] = meta[k]
        if observation_id:
            O.add_provenance(attrs, observation_id)
        node = get_or_create_node(
            session, project_id=project.id, node_type=NodeType.pattern,
            name=rule, target_id=None, content_hash=ch, attrs=attrs, created_by="derived",
        )
        # The match edge: the scanned target matched this pattern. Merge so a re-sweep
        # (or a sweep that re-scans the same target) folds in rather than drawing parallels.
        edge_attrs = {"by": "yara"}
        if observation_id:
            edge_attrs["observation_id"] = observation_id
        if m.get("namespace"):
            edge_attrs["namespace"] = m["namespace"]
        add_edge(
            session, project_id=project.id, src=("target", target.id), dst=("node", node.id),
            type=MATCHES_RULE, origin="derived", confidence=1.0, directed=True,
            attrs=edge_attrs, merge=True,
        )
        # node_refs (the reverse pointer from the Observation to these pattern nodes) are
        # recorded on the Observation in scan_target after promotion returns.
        entry = {"rule": rule, "pattern_node_id": node.id,
                 "severity": meta.get("severity"), "cve": meta.get("cve")}
        # Surface WHICH string fired and WHERE (a bounded sample) so a sweep hit is triable
        # without re-fetching the Observation payload by hand — the dogfood pain point was a
        # HIGH backdoor "match" with no clue what substring tripped it. The probe already
        # records the full bounded list on the Observation; here we carry a tiny sample.
        sample = _string_evidence(m.get("strings"))
        if sample:
            entry["matched_strings"] = sample
        promoted.append(entry)
    return promoted


# How many matched-string instances to echo onto a promotion entry (the full bounded list
# stays on the Observation payload; this is just enough to triage the hit at a glance).
_PROMOTE_STRING_SAMPLE = 3


def _string_evidence(strings: list[dict] | None) -> list[dict]:
    """A tiny `[{identifier, offset, value}]` sample of what fired, pulled from the probe's
    bounded matched-string list, so a promoted match says WHICH string matched and WHERE
    (e.g. "$c at 0x1a40 = /bin/telnetd -l /bin/sh") without a manual Observation dig."""
    out: list[dict] = []
    for s in (strings or [])[:_PROMOTE_STRING_SAMPLE]:
        if not isinstance(s, dict):
            continue
        out.append({"identifier": s.get("identifier"), "offset": s.get("offset"),
                    "value": s.get("value")})
    return out


def scan_target(
    session: Session,
    project: Project,
    target: Target,
    *,
    ruleset: str | None = None,
    source: str = "agent",
    runner=None,
    path: str | None = None,
) -> dict:
    """Match ONE artifact (a byte target, or an extracted firmware file via `path`) against
    the chosen rules, record a `yara_matches` Observation, and promote matches.

    `path` overrides the artifact scanned (used by the project sweep to scan an extracted
    firmware file that isn't its own target); it defaults to `target.path`. Returns a dict
    with the raw `facts`, `observation_id`, `cached`, the `promoted` pattern list, and the
    reuse hint — or `{"error": ...}` when Docker is down, the artifact isn't readable, or
    the ruleset id is unknown.

    `ruleset` is the single validated agent knob (design §2.8) — which bundled ruleset (or
    'all') to sweep; the rule files and match flags are fixed by HexGraph.
    """
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import SandboxError, docker_available

    if runner is None:
        if not docker_available():
            return {"error": "YARA unavailable (Docker/sandbox not running)"}
        runner = get_executor()

    artifact = path if path is not None else str(target.path or "")
    if not str(artifact).strip():
        return {"error": "this target has no byte artifact to scan (a Channel-reached surface "
                         "has no file); YARA scans bytes."}

    try:
        mounts, rules_dir_args, eff_ruleset, cleanup = _resolve_rule_mounts(ruleset)
    except ValueError as exc:
        return {"error": str(exc)}
    if not rules_dir_args:
        _cleanup_dirs(cleanup)
        return {"error": "no YARA rules available to scan with (bundled rules missing and no "
                         "user rules in the HEXGRAPH_HOME rules dir)"}

    # Release the write lock before the (slow) YARA sandbox scan: a caller sweeping many
    # artifacts (sweep_project) reaches here still holding the PREVIOUS artifact's just-promoted
    # match nodes/edges, which would otherwise be pinned across this scan and starve other
    # writers. scan_target records + promotes only AFTER the probe, so the only write held across
    # it is the caller's pending one.
    from hexgraph.db.session import release_write_lock

    release_write_lock(session)
    try:
        facts = runner.run_json_probe(
            "yara_probe.py", artifact, extra_args=rules_dir_args, extra_ro_mounts=mounts,
        )
    except SandboxError as exc:
        return {"error": f"YARA scan failed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"YARA scan failed: {exc}"}
    finally:
        _cleanup_dirs(cleanup)

    if isinstance(facts, dict) and facts.get("error"):
        return {"error": f"YARA scan failed: {facts['error']}"}

    # Scope the Observation to the EXACT analyzed bytes. For the target's own artifact use
    # the recon sha256; for an extracted firmware file (path override) hash the file so a
    # re-sweep of an unchanged file dedups.
    if path is not None and path != (target.path or ""):
        content_hash = _hash_file(path)
        rel = _rel_for(target, path)
    else:
        content_hash = O.content_hash_for(target)
        rel = None

    args = {"ruleset": eff_ruleset}
    if rel:
        args["file"] = rel
    obs, cached = O.record_observation(
        session,
        project_id=project.id,
        target_id=target.id,
        source=source,
        tool="yara_matches",
        args=args,
        result_kind=RESULT_KIND,
        payload=facts,
        summary=_summary(facts, eff_ruleset),
        content_hash=content_hash,
    )

    promoted = _promote_matches(session, project, target, facts, obs.id if obs is not None else None)
    # Record the promoted pattern nodes as back-references on the Observation.
    if obs is not None:
        for p in promoted:
            O.add_node_ref(obs, p["pattern_node_id"])

    return {
        "facts": facts,
        "observation_id": obs.id if obs is not None else None,
        "cached": cached,
        "promoted": promoted,
        "ruleset": eff_ruleset,
        "scanned": rel or target.name,
        "reuse_hint": _REUSE_HINT,
    }


def sweep_project(
    session: Session,
    project: Project,
    *,
    ruleset: str | None = None,
    source: str = "agent",
    runner=None,
    max_files_per_firmware: int = 200,
) -> dict:
    """Sweep the WHOLE project: every non-archived byte target, plus the extracted
    firmware files under each firmware target's unpacked filesystem.

    This is YARA's cross-target shape (unlike the single-target binutils/FLOSS): one
    finding's pattern becomes a corpus-wide hunt. Each scanned artifact records its own
    `yara_matches` Observation (scoped to its bytes) and promotes matches to the shared
    project-level `pattern` nodes, so the graph shows which targets/files a rule matched.
    Returns a roll-up: per-target results + the aggregate match/promotion counts.
    """
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if runner is None:
        if not docker_available():
            return {"error": "YARA unavailable (Docker/sandbox not running)"}
        runner = get_executor()

    # Validate the ruleset once up front (so a bad id fails the whole sweep cleanly).
    try:
        _validate_ruleset(ruleset)
    except ValueError as exc:
        return {"error": str(exc)}

    targets = (
        session.query(Target)
        .filter(Target.project_id == project.id, Target.archived.is_(False))
        .all()
    )

    scanned = 0  # artifacts ATTEMPTED (ok + errored) — kept for backward compat
    scanned_ok = 0  # artifacts the probe actually scanned cleanly
    errors: list[dict] = []
    total_matches = 0
    total_promoted = 0
    per_target: list[dict] = []

    for t in targets:
        # 1) the target's own bytes, when it has a file artifact.
        if str(t.path or "").strip():
            res = scan_target(session, project, t, ruleset=ruleset, source=source, runner=runner)
            scanned += 1
            if res.get("error"):
                errors.append({"target_id": t.id, "name": t.name, "error": res["error"]})
            else:
                scanned_ok += 1
                mc = res.get("facts", {}).get("match_count", 0)
                pc = len(res.get("promoted") or [])
                total_matches += mc
                total_promoted += pc
                if mc:
                    per_target.append({"target_id": t.id, "name": t.name, "file": None,
                                       "match_count": mc, "promoted": res.get("promoted")})

        # 2) every extracted firmware file under this target's unpacked filesystem.
        for rel, abspath in _firmware_files(project, t, limit=max_files_per_firmware):
            res = scan_target(session, project, t, ruleset=ruleset, source=source,
                              runner=runner, path=abspath)
            scanned += 1
            if res.get("error"):
                errors.append({"target_id": t.id, "name": t.name, "file": rel,
                               "error": res["error"]})
                continue
            scanned_ok += 1
            mc = res.get("facts", {}).get("match_count", 0)
            pc = len(res.get("promoted") or [])
            total_matches += mc
            total_promoted += pc
            if mc:
                per_target.append({"target_id": t.id, "name": t.name, "file": rel,
                                   "match_count": mc, "promoted": res.get("promoted")})

    return _assemble_sweep_result(
        scanned=scanned,
        scanned_ok=scanned_ok,
        targets=len(targets),
        total_matches=total_matches,
        total_promoted=total_promoted,
        per_target=per_target,
        errors=errors,
    )


def _assemble_sweep_result(
    *,
    scanned: int,
    scanned_ok: int,
    targets: int,
    total_matches: int,
    total_promoted: int,
    per_target: list[dict],
    errors: list[dict],
) -> dict:
    """Assemble the sweep roll-up so the OUTCOME is honest — a clean scan and a scan where
    every artifact errored must NEVER look the same.

    The bug this guards against: a sweep whose every artifact failed (e.g. the runtime YARA
    dep was missing, so each probe raised) would still return `match_count: 0, hits: []` with
    the failures buried only in `errors[]` — indistinguishable from a genuinely clean sweep, a
    dangerous false all-clear. So we surface `scanned_ok` vs `errored`, mark an all-errored
    sweep as a `status: "error"` outcome (with a top-level `error` reason bubbled up from a
    representative per-file failure), and a partial as `status: "partial"` (some scanned, some
    errored), reserving the bare `match_count: 0` shape for a real clean scan.
    """
    errored = len(errors)
    result: dict = {
        "scanned": scanned,
        "scanned_ok": scanned_ok,
        "errored": errored,
        "targets": targets,
        "match_count": total_matches,
        "promoted_count": total_promoted,
        "hits": per_target,
        "errors": errors,
        "reuse_hint": _REUSE_HINT,
    }

    if scanned == 0:
        # Nothing to scan (no byte targets / all archived) — not an error, but not "clean"
        # in any meaningful sense either; say so plainly.
        result["status"] = "empty"
        return result

    if scanned_ok == 0:
        # EVERY artifact errored — this is NOT a clean 0-match scan. Make it an explicit error
        # outcome and bubble a representative reason into the summary so the agent/UI can't
        # mistake it for "clean" (the reason was previously only in errors[]).
        reason = errors[0].get("error") if errors else "all scanned artifacts errored"
        result["status"] = "error"
        result["error"] = (
            f"YARA sweep produced NO usable result: all {errored} scanned artifact(s) errored "
            f"(e.g. {reason}). This is NOT a clean scan — fix the underlying error and re-run."
        )
        return result

    if errored:
        # Partial: report both so "0 matches in the N we COULD scan, but M errored" is
        # distinguishable from a fully clean sweep.
        reason = errors[0].get("error")
        result["status"] = "partial"
        result["partial_note"] = (
            f"{scanned_ok} artifact(s) scanned cleanly, {errored} errored "
            f"(e.g. {reason}) — the match counts cover only the {scanned_ok} scanned, "
            f"not the {errored} that failed."
        )
        return result

    result["status"] = "ok"
    return result


# --- extracted-firmware-file enumeration --------------------------------------

# Cap an individual file we scan (a YARA match reads the whole file into the matcher; a
# multi-hundred-MB blob would be slow and the runner timeout would bite). A real firmware
# binary/config is far smaller; the genuinely huge entries are nested images recon already
# unpacked separately.
_MAX_FILE_BYTES = 64 * 1024 * 1024


def _firmware_files(project: Project, firmware: Target, *, limit: int):
    """Yield (rel, abspath) for each extracted file under a firmware target's unpacked
    filesystem (design §3.3 — sweep the extracted firmware files, not just the byte
    targets). Bounded by `limit` and a per-file size cap; path-traversal safe (the
    resolved path must stay within the firmware's extracted root). A non-firmware target
    (no `metadata_json['filesystem']`) yields nothing."""
    from hexgraph.engine.targets import filesystem as FS

    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        return
    try:
        root = FS.host_root(project, firmware).resolve()
    except Exception:  # noqa: BLE001 — a missing/relocated unpack dir simply yields nothing
        return
    if not root.is_dir():
        return
    count = 0
    for entry in fs.get("files", []):
        if count >= limit:
            return
        rel = entry.get("rel")
        if not rel:
            continue
        path = (root / rel).resolve()
        # Stay within the extracted root and only scan regular files within the size cap.
        if root not in path.parents and path != root:
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield rel, str(path)


def _rel_for(target: Target, path: str) -> str | None:
    """A short label for an extracted file relative to its firmware's unpacked root,
    for the Observation args/summary. Falls back to the basename."""
    try:
        from sqlalchemy.orm import object_session

        from hexgraph.engine.targets import filesystem as FS

        sess = object_session(target)
        if sess is not None:
            project = sess.get(Project, target.project_id)
            if project is not None:
                root = FS.host_root(project, target).resolve()
                rp = Path(path).resolve()
                if root in rp.parents:
                    return str(rp.relative_to(root))
    except Exception:  # noqa: BLE001
        pass
    return Path(path).name


def _hash_file(path: str) -> str | None:
    """sha256 of an extracted file, so a re-sweep of an unchanged file dedups its
    Observation. Best-effort: returns None if the file can't be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

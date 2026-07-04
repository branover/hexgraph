"""Explicit, detached whole-binary analysis — `re_analyze` (the analyze half of the
analyze/decompile split).

Analysis (Ghidra import + auto-analysis) is the ONE expensive step. The per-call tools
(decompile / xref / list_functions / call_graph / taint / emulate) must NOT trigger it
implicitly — they gate on a saved analysis and point here (that gating is a follow-up). `re_analyze`
runs the analysis as a DETACHED background container with its OWN generous budget, so it actually
runs to completion and COMMITS the warm project — unlike a per-call cold analysis, which the
size-scaled per-call timeout kills before it can commit (an operator hit exactly that: repeated
40-minute cold analyses that never became warm).

**Single-flight.** The detached container is named deterministically from the artifact's content
hash (`hexgraph-analyze-<sha16>`). A second `re_analyze` of the same target ATTACHES to the running
one instead of starting a duplicate — docker container names are host-global, so this dedups across
sessions and processes AND survives the launching process (unlike the fcntl slot lock, whose release
on a dead launcher caused the incident's duplicate cold analyses). The warm marker the probe commits
as its last step is the completion signal: container-exit + `slot.exists()` == analyzed.

Ghidra-first: `re_analyze` targets the headless-Ghidra warm project. r2 project persistence (and its
`re_analyze` path) rides with a separate change.
"""

from __future__ import annotations

import logging
import tempfile

log = logging.getLogger(__name__)

# Deterministic detached-container name prefix — the single-flight key (host-global).
CONTAINER_PREFIX = "hexgraph-analyze-"

# Generous default analysis budget (seconds). NOT the per-call size-scaled timeout — analysis is a
# deliberate long operation and gets its own budget so it finishes + commits. Ghidra reads it as
# `-analysisTimeoutPerFile` (via HEXGRAPH_PROBE_TIMEOUT_S), so a monolith's analysis stops+saves
# within budget rather than being torn down with nothing.
_ANALYSIS_TIMEOUT_DEFAULT = 6 * 3600


def _ghidra_active() -> bool:
    """True when headless Ghidra is the active backend (the only backend with a persistent warm
    project today). A settings hiccup ⇒ False."""
    try:
        from hexgraph.engine.re.ghidra import ghidra_config

        g = ghidra_config()
        return bool(g.get("enabled") and (g.get("mode") or "headless") == "headless")
    except Exception:  # noqa: BLE001
        return False


def _analysis_timeout() -> int:
    """The configured analysis budget (`features.ghidra.analysis_timeout_s`), or the generous
    default. This is re_analyze's OWN budget — deliberately separate from the small per-call
    timeouts — so a monolith's whole-binary analysis runs to completion. Never raises."""
    try:
        from hexgraph import settings as st

        v = (st.resolved().get("features", {}).get("ghidra", {}) or {}).get("analysis_timeout_s")
        if v and int(v) > 0:
            return int(v)
    except Exception:  # noqa: BLE001
        pass
    return _ANALYSIS_TIMEOUT_DEFAULT


def container_name(content_sha: str) -> str:
    """The single-flight container name for an artifact hash."""
    return f"{CONTAINER_PREFIX}{content_sha[:16]}"


def _reap_if_present(ex, name) -> None:
    """Best-effort: `docker rm` a detached container by name if it still exists — housekeeping so a
    completed/failed analysis doesn't leave a stopped container behind. Never raises."""
    if not name:
        return
    try:
        if (ex.poll_detached(name) or {}).get("exists"):
            ex.stop_detached(name, remove=True)
    except Exception:  # noqa: BLE001 — reaping is best-effort, never breaks the caller
        pass


def _slot_ctx(project, target, *, runner):
    """Resolve `(slot, artifact_path, container_name)` for a target's Ghidra analysis, or None when
    it isn't applicable (no byte artifact / no data dir / resolve failure)."""
    artifact = getattr(target, "path", None)
    data_dir = getattr(project, "data_dir", None)
    if not artifact or not data_dir:
        return None
    try:
        from hexgraph.engine.re import ghidra_project as gp
        from hexgraph.sandbox.runner import sandbox_image

        sha = gp.content_hash(artifact)
        version = gp.ghidra_version_for_image(sandbox_image(), runner=runner)
        slot = gp.resolve(data_dir, sha, version)
        return slot, artifact, container_name(sha)
    except Exception:  # noqa: BLE001 — analysis is best-effort; a resolve failure reads as n/a
        return None


def analysis_state(project, target, *, runner=None) -> dict:
    """Read-only: the analysis state of `target`'s Ghidra warm project. Starts nothing. Returns
    ``{state, detail, container?}`` where state is one of:
      analyzed    — a committed warm project is ready (per-call tools will be instant)
      running     — a detached analysis is in progress (attach / keep polling)
      failed      — the analysis container exited WITHOUT committing a warm project
      none        — no saved analysis and nothing running (call re_analyze to build it)
      unavailable — Ghidra isn't the active backend / Docker down / no byte artifact
    """
    if not _ghidra_active():
        return {"state": "unavailable",
                "detail": "explicit analysis is Ghidra-only for now (headless Ghidra is not the "
                          "active backend); radare2 project persistence is coming separately"}
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return {"state": "unavailable", "detail": "Docker/sandbox not running"}
    ctx = _slot_ctx(project, target, runner=runner)
    if ctx is None:
        return {"state": "unavailable",
                "detail": "this target has no byte artifact / data dir to analyze"}
    slot, _artifact, name = ctx
    if slot.exists():
        return {"state": "analyzed", "detail": "warm Ghidra project is ready", "container": name}

    from hexgraph.sandbox.executor import get_executor

    poll = (runner or get_executor()).poll_detached(name) or {}
    if poll.get("running"):
        return {"state": "running", "detail": "a whole-binary analysis is in progress",
                "container": name}
    if poll.get("exists"):
        return {"state": "failed",
                "detail": f"the analysis container exited (code {poll.get('exit_code')}) without "
                          "committing a warm project — re_analyze will retry it",
                "container": name}
    return {"state": "none", "detail": "no saved analysis for this target — run re_analyze to "
                                       "build it", "container": name}


def start_analysis(project, target, *, runner=None) -> dict:
    """Start OR attach to a detached whole-binary analysis. Idempotent and single-flight:
    already-warm ⇒ no-op ``analyzed``; already-running ⇒ ``running`` (attach); otherwise launch a
    detached Ghidra analysis and return ``started``. A failed prior container is reaped and retried.
    Poll by calling this (or `analysis_state`) again until state is ``analyzed``."""
    from hexgraph.sandbox.executor import get_executor

    ex = runner or get_executor()
    state = analysis_state(project, target, runner=ex)
    if state["state"] == "analyzed":
        # Completed — reap the exit-0 detached container if it's still lingering, so a done
        # analysis doesn't leave a stopped container behind per binary (best-effort housekeeping).
        _reap_if_present(ex, state.get("container"))
        return state
    if state["state"] in ("running", "unavailable"):
        return state  # in-flight / not applicable — nothing to start

    ctx = _slot_ctx(project, target, runner=ex)
    if ctx is None:  # (analysis_state already returned unavailable, but be defensive)
        return {"state": "unavailable", "detail": "this target has no byte artifact to analyze"}
    slot, artifact, name = ctx

    if state["state"] == "failed":
        # Reap the exited-but-not-warm container so a fresh analysis can take the name.
        try:
            ex.stop_detached(name, remove=True)
        except Exception:  # noqa: BLE001 — best-effort reap; the start below re-checks
            pass

    slot.prepare()
    # The analysis writes its project into the project mount and its JSON to /scratch — /out is
    # unused under --analyze. Give it a THROWAWAY outdir OUTSIDE the slot so the warm project stays
    # project-only (the probe keeps the persistent mount lean by design).
    outdir = tempfile.mkdtemp(prefix="hexgraph-analyze-out-")
    try:
        ex.start_detached(
            "ghidra_probe.py", artifact, name=name, outdir=outdir,
            project_mount=str(slot.root),
            # `--analyze`: full cold import + inventory + COMMIT, no focus (start_detached appends
            # a /out positional the probe would otherwise treat as a focus).
            extra_args=["--analyze"],
            # Ghidra's own analysis cap (-analysisTimeoutPerFile) — the generous analysis budget.
            extra_env={"HEXGRAPH_PROBE_TIMEOUT_S": str(_analysis_timeout())},
        )
    except Exception as exc:  # noqa: BLE001
        # A concurrent start won the deterministic name (docker refuses a duplicate) — that's the
        # single-flight win, not an error: attach to the running one.
        msg = str(exc).lower()
        if "already in use" in msg or ("name" in msg and "in use" in msg):
            return {"state": "running", "detail": "a whole-binary analysis is already in progress "
                                                  "(attached)", "container": name}
        return {"state": "failed", "detail": f"could not start analysis: {exc}", "container": name}
    return {"state": "started",
            "detail": "detached whole-binary analysis started with a generous budget; call "
                      "re_analyze again to poll until state is 'analyzed'", "container": name}

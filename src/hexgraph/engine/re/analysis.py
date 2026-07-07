"""Explicit, detached whole-binary analysis — `re_analyze` (the analyze half of the
analyze/decompile split).

Analysis — Ghidra's import + auto-analysis, or radare2's whole-binary `aaa` — is the ONE expensive
step. The per-call tools (decompile / xref / list_functions / call_graph / taint / emulate) must NOT
trigger it implicitly — they gate on a saved analysis and point here. `re_analyze` runs the analysis
as a DETACHED background container with its OWN generous budget, so it actually runs to completion
and COMMITS the warm project — unlike a per-call cold analysis, which the size-scaled per-call
timeout kills before it can commit (an operator hit exactly that: repeated 40-minute cold analyses
that never became warm).

**Backend-aware.** Both persistent backends are covered: headless Ghidra (the `ghidra_project` warm
project, `ghidra_probe --analyze`) and radare2 (the `r2_project` named project, `decompile_probe
--analyze`). The active decompiler (env `HEXGRAPH_DECOMPILER` > Ghidra settings > radare2 default)
picks the slot + probe; ghidra_bridge attaches to a running Ghidra and has no on-disk warm project to
build here, so it reads as `unavailable`.

**Single-flight.** The detached container is named deterministically from the backend + the
artifact's content hash (`hexgraph-analyze-<backend>-<sha16>`). A second `re_analyze` of the same
target ATTACHES to the running one instead of starting a duplicate — docker container names are
host-global, so this dedups across sessions and processes AND survives the launching process (unlike
the fcntl slot lock, whose release on a dead launcher caused the incident's duplicate cold analyses).
The backend is in the name so a Ghidra and an r2 analysis of the same target (different slots) never
collide. The warm marker the probe commits as its last step is the completion signal: container-exit
+ `slot.exists()` == analyzed.
"""

from __future__ import annotations

import logging
import os
import tempfile

log = logging.getLogger(__name__)

# Deterministic detached-container name prefix — the single-flight key (host-global).
CONTAINER_PREFIX = "hexgraph-analyze-"

# Generous default analysis budget (seconds). NOT the per-call size-scaled timeout — analysis is a
# deliberate long operation and gets its own budget so it finishes + commits. Ghidra reads it as
# `-analysisTimeoutPerFile` (via HEXGRAPH_PROBE_TIMEOUT_S), so a monolith's analysis stops+saves
# within budget rather than being torn down with nothing. (radare2's `aaa` has no such knob and
# ignores it; the detached container simply runs to completion.)
_ANALYSIS_TIMEOUT_DEFAULT = 6 * 3600


def _active_backend() -> str | None:
    """The active decompiler backend that HAS a persistent warm slot: 'ghidra' | 'radare2', or None.
    Mirrors decompiler._resolve_name — env `HEXGRAPH_DECOMPILER` > Ghidra settings > radare2 default.
    ghidra_bridge attaches to a running Ghidra (no on-disk warm project to build here), so it maps to
    None → `unavailable`. A settings hiccup falls back to radare2 (the always-available default)."""
    name = (os.environ.get("HEXGRAPH_DECOMPILER") or "").strip().lower()
    if not name:
        try:
            from hexgraph.engine.re.ghidra import ghidra_config

            g = ghidra_config()
            if g.get("enabled"):
                name = "ghidra_bridge" if (g.get("mode") == "bridge") else "ghidra"
            else:
                name = "radare2"
        except Exception:  # noqa: BLE001 — a config hiccup falls back to the default backend
            name = "radare2"
    if name in ("radare2", "r2"):
        return "radare2"
    if name == "ghidra":
        return "ghidra"
    return None  # ghidra_bridge / unknown → no persistent slot to build


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


def container_name(content_sha: str, backend: str = "ghidra") -> str:
    """The single-flight container name for an artifact hash + backend. Backend-scoped so a Ghidra
    analysis and an r2 analysis of the SAME target (which persist to DIFFERENT slots) never collide
    on the name (docker names are host-global)."""
    return f"{CONTAINER_PREFIX}{backend}-{content_sha[:16]}"


_ANALYZE_OUTDIR: str | None = None


def _analyze_outdir() -> str:
    """A throwaway `/out` dir for detached analyses. `/out` is bind-mounted but UNUSED under
    `--analyze` (both probes write their project into the persistent mount and any JSON to /scratch).
    Created ONCE per process via `mkdtemp` — an unpredictable, self-owned path, NOT a fixed
    `/tmp/hexgraph-analyze-out` a foreign user on a shared host could pre-create with hostile perms
    (which would make the runner's outdir chmod raise) — and reused, so re_analyze leaks no empty
    tempdir per analyzed target (the per-call `mkdtemp` residual from #260)."""
    global _ANALYZE_OUTDIR
    if _ANALYZE_OUTDIR is None or not os.path.isdir(_ANALYZE_OUTDIR):
        _ANALYZE_OUTDIR = tempfile.mkdtemp(prefix="hexgraph-analyze-out-")
    return _ANALYZE_OUTDIR


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
    """Resolve `(slot, artifact_path, container_name, probe)` for the ACTIVE backend's analysis of
    `target`, or None when it isn't applicable (no byte artifact / no data dir / no persistent-slot
    backend / resolve failure). `probe` is the detached whole-binary analysis probe for that backend
    (`ghidra_probe.py` / `decompile_probe.py`, both run with `--analyze`)."""
    artifact = getattr(target, "path", None)
    data_dir = getattr(project, "data_dir", None)
    if not artifact or not data_dir:
        return None
    backend = _active_backend()
    if backend is None:
        return None
    try:
        from hexgraph.sandbox.runner import sandbox_image

        image = sandbox_image()
        if backend == "ghidra":
            from hexgraph.engine.re import ghidra_project as gp

            sha = gp.content_hash(artifact)
            version = gp.ghidra_version_for_image(image, runner=runner)
            slot = gp.resolve(data_dir, sha, version)
            probe = "ghidra_probe.py"
        else:  # radare2
            from hexgraph.engine.re import r2_project as rp

            sha = rp.content_hash(artifact)
            version = rp.r2_version_for_image(image, runner=runner)
            slot = rp.resolve(data_dir, sha, version)
            probe = "decompile_probe.py"
        return slot, artifact, container_name(sha, backend), probe
    except Exception:  # noqa: BLE001 — analysis is best-effort; a resolve failure reads as n/a
        return None


def analysis_state(project, target, *, runner=None) -> dict:
    """Read-only: the analysis state of `target` for the ACTIVE backend's warm slot. Starts nothing.
    Returns ``{state, detail, container?}`` where state is one of:
      analyzed    — a committed warm analysis is ready (per-call tools will be instant)
      running     — a detached analysis is in progress (attach / keep polling)
      failed      — the analysis container exited WITHOUT committing a warm analysis
      none        — no saved analysis and nothing running (call re_analyze to build it)
      unavailable — no persistent-slot backend (ghidra_bridge) / Docker down / no byte artifact
    """
    if _active_backend() is None:
        return {"state": "unavailable",
                "detail": "the active decompiler has no persistent analysis to build "
                          "(Ghidra bridge mode, or an unknown backend)"}
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return {"state": "unavailable", "detail": "Docker/sandbox not running"}
    ctx = _slot_ctx(project, target, runner=runner)
    if ctx is None:
        return {"state": "unavailable",
                "detail": "this target has no byte artifact / data dir to analyze"}
    slot, _artifact, name, _probe = ctx
    if slot.exists():
        return {"state": "analyzed", "detail": "warm analysis is ready", "container": name}

    from hexgraph.sandbox.executor import get_executor

    poll = (runner or get_executor()).poll_detached(name) or {}
    if poll.get("running"):
        return {"state": "running", "detail": "a whole-binary analysis is in progress",
                "container": name}
    if poll.get("exists"):
        return {"state": "failed",
                "detail": f"the analysis container exited (code {poll.get('exit_code')}) without "
                          "committing a warm analysis — re_analyze will retry it",
                "container": name}
    return {"state": "none", "detail": "no saved analysis for this target — run re_analyze to "
                                       "build it", "container": name}


def analysis_lead(project, target, *, runner=None) -> str | None:
    """A re_analyze lead when `target` has NO saved analysis for the active backend, else None
    (proceed). `analyzed` → None; `unavailable` (Ghidra-bridge / Docker down / no byte artifact) →
    None too, since those paths serve warm anyway or can't be gated. This is the single host-side
    gate for the analysis-needing tools/tasks that DON'T go through agent_tools.run_tool's gate
    (recover_constant, the taint task) — so, like every per-call tool, they point at re_analyze on a
    cold target instead of triggering a full analysis themselves. Best-effort: any error ⇒ None."""
    try:
        st = analysis_state(project, target, runner=runner)
    except Exception:  # noqa: BLE001 — a gate hiccup must never block a tool that could run
        return None
    state = st.get("state")
    if state in ("analyzed", "unavailable"):
        return None
    lead = {"none": "No saved analysis for this target yet.",
            "running": "A whole-binary analysis is already in progress.",
            "failed": "The last analysis did not finish."}.get(state, "No saved analysis.")
    return (f"{lead} Run re_analyze(target) first — it builds the warm analysis ONCE with a generous "
            "budget (detached; re-call re_analyze to poll until state='analyzed'), then retry this — "
            f"it's warm-only and never runs a cold analysis itself. [{st.get('detail', '')}]")


def start_analysis(project, target, *, runner=None) -> dict:
    """Start OR attach to a detached whole-binary analysis for the ACTIVE backend. Idempotent and
    single-flight: already-warm ⇒ no-op ``analyzed``; already-running ⇒ ``running`` (attach);
    otherwise launch the detached analysis and return ``started``. A failed prior container is reaped
    and retried. Poll by calling this (or `analysis_state`) again until state is ``analyzed``."""
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
    slot, artifact, name, probe = ctx

    if state["state"] == "failed":
        # Reap the exited-but-not-warm container so a fresh analysis can take the name.
        try:
            ex.stop_detached(name, remove=True)
        except Exception:  # noqa: BLE001 — best-effort reap; the start below re-checks
            pass

    slot.prepare()
    # `/out` is unused under --analyze (the project lives on the persistent mount); a SHARED throwaway
    # outdir avoids leaking an empty dir per analyzed target.
    outdir = _analyze_outdir()
    # A monolith's whole-binary analysis needs the SIZE-SCALED mem/tmpfs (e.g. ~18 GB for a ~500 MB
    # ELF, so the decompiler DB buffer doesn't OOM) — NOT the 2 GB base spec. start_detached defaults
    # to resource_spec_for("sandbox") (base) because its only other callers (fuzz) pass their own
    # spec; re_analyze passes the size-scaled one for EITHER backend (a Ghidra import or an r2 `aaa`
    # over a huge binary both need it). The detached path ignores the spec's `timeout` (no outer
    # kill); the analysis budget is HEXGRAPH_PROBE_TIMEOUT_S below.
    from hexgraph.sandbox.resources import resource_spec_for_artifact

    analysis_resources = resource_spec_for_artifact(artifact, "sandbox")
    try:
        ex.start_detached(
            probe, artifact, name=name, outdir=outdir,
            project_mount=str(slot.root),
            resources=analysis_resources,
            # `--analyze`: full cold analysis + COMMIT the warm slot, no focus (start_detached
            # appends a /out positional the probe would otherwise treat as a focus — BOTH the Ghidra
            # and r2 probes force focus off under --analyze).
            extra_args=["--analyze"],
            # The analysis budget: Ghidra reads it as -analysisTimeoutPerFile; r2 ignores it.
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

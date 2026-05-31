"""Proof-of-concept findings — an exploit HexGraph can EXECUTE and verify (dynamic).

A PoC spec says how to run the target (argv/env/stdin) and how to know it worked
(an oracle). `verify_poc` substitutes a fresh random **nonce** into the spec and
runs it in the sandbox, so "verified" means the injected behaviour actually
happened (e.g. an injected `echo <nonce>` really executed) — not something the
model could fake. A `poc` task generates a PoC (LLM/mock) and verifies it,
emitting a `poc`-type finding whose evidence carries the spec + the verification.

Execution is policy-gated (`assert_allows_execution()` — PoC/fuzzing enabled) and
runs --network none, capped, timed, disposable. Native-arch targets only (no
emulation yet).
"""

from __future__ import annotations

import copy
import json
import secrets

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, Task, TaskStatus
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.tasks import write_trace
from hexgraph.models.finding import Evidence, Finding, FollowupSuggestion
from hexgraph.sandbox.executor import Executor, get_executor

NONCE_PLACEHOLDER = "{{NONCE}}"


def _find_sysroot(root):
    """The firmware's FHS root for use as a qemu `-L` sysroot. The unpack root often
    sits ABOVE the real rootfs (binwalk nests it under `_artifact.extracted/
    squashfs-root/`), so locate the directory whose `lib/` holds the dynamic loader
    (ld-*.so* / libc.so*) and return that. Falls back to `root`."""
    from pathlib import Path

    root = Path(root)
    if not root.is_dir():
        return None
    # The dir whose lib/ has the loader IS the rootfs.
    for libdir in [root / "lib", *root.rglob("lib")]:
        if not libdir.is_dir():
            continue
        if any(libdir.glob("ld-*.so*")) or any(libdir.glob("libc.so*")) or any(libdir.glob("ld-uClibc*")):
            return libdir.parent
    return root


def _substitute(obj, nonce: str):
    if isinstance(obj, str):
        return obj.replace(NONCE_PLACEHOLDER, nonce)
    if isinstance(obj, list):
        return [_substitute(x, nonce) for x in obj]
    if isinstance(obj, dict):
        return {k: _substitute(v, nonce) for k, v in obj.items()}
    return obj


def verify_poc(session: Session, project: Project, target: Target, spec: dict,
               *, runner: Executor | None = None) -> dict:
    """Run a PoC spec against `target` in the sandbox and report whether it worked.

    A `{{NONCE}}` placeholder anywhere in the spec is replaced with a fresh random
    token before running, making an `output_contains` oracle unforgeable. Returns
    {verified, exit_code, output, detail, nonce, spec}."""
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # opt-in gate: raises unless PoC/fuzzing is enabled
    runner = runner or get_executor()
    import tempfile

    nonce = "HEXGRAPH_PWNED_" + secrets.token_hex(6)
    live = _substitute(copy.deepcopy(spec or {}), nonce)

    # Foreign-arch firmware binaries run under qemu-user (poc_probe picks qemu-<arch>
    # from the ELF header). A dynamically-linked one needs its sibling libs, so mount
    # the parent firmware's extracted rootfs as the qemu sysroot.
    extra_mounts: list[tuple[str, str]] = []
    if target.parent_id and not live.get("sysroot"):
        from hexgraph.engine.filesystem import host_root
        fw = session.get(Target, target.parent_id)
        if fw is not None and (fw.metadata_json or {}).get("filesystem"):
            root = _find_sysroot(host_root(project, fw))
            if root is not None and root.is_dir():
                extra_mounts.append((str(root), "/sysroot"))
                live["sysroot"] = "/sysroot"

    out = tempfile.mkdtemp(prefix="hexgraph-poc-")
    result = runner.run_json_probe(
        "poc_probe.py", target.path, outdir=out, extra_args=["--spec", json.dumps(live)],
        requires_execution=True, extra_ro_mounts=extra_mounts or None,
    )
    return {**result, "nonce": nonce, "spec": live}


def _poc_finding(spec: dict, verification: dict, function: str | None, target_name: str, category: str) -> Finding:
    verified = bool(verification.get("verified"))
    return Finding(
        title=("Verified PoC" if verified else "PoC (unverified)")
        + f": {category} in {function or target_name}",
        severity="critical" if verified else "high",
        confidence="high" if verified else "low",
        category=category,
        summary=("A proof-of-concept was executed in the sandbox and "
                 + ("succeeded" if verified else "did NOT confirm the issue")
                 + f" against {target_name}."),
        reasoning="Oracle: " + (verification.get("detail") or "—")
        + (f"\nExit: {verification.get('exit_code')}" if verification.get("exit_code") is not None else ""),
        evidence=Evidence(
            function=function,
            reproducer=json.dumps(spec),
            extra={"poc": spec, "verification": {
                "verified": verified, "detail": verification.get("detail"),
                "exit_code": verification.get("exit_code"),
                "output": (verification.get("output") or "")[:2000],
                "nonce": verification.get("nonce"),
            }},
        ),
        suggested_followups=[FollowupSuggestion(
            task_type="static_analysis", label=f"Root-cause and fix {function or target_name}",
            params={"function": function or ""})] if verified else None,
    )


def execute_poc(session: Session, project: Project, target: Target, task: Task,
                runner: Executor | None = None) -> int:
    """Generate a PoC (from task params, or the LLM/mock) and verify it, recording
    a `poc`-type finding with the verification result. Returns findings created."""
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()
    runner = runner or get_executor()
    params = task.params_json or {}

    spec = params.get("poc")
    function = params.get("function")
    category = params.get("category", "command-injection")
    if not spec:
        spec, function, category = _generate_spec(session, project, target, task)
    if not spec:
        raise ValueError("no PoC spec available — provide params.poc or run a backend that can craft one")

    verification = verify_poc(session, project, target, spec, runner=runner)
    write_trace(task, "poc.json", {"spec": verification.get("spec"), "verification": verification})

    row = persist_finding(
        session, project_id=project.id, target_id=target.id, task_id=task.id,
        finding=_poc_finding(spec, verification, function, target.name, category),
        finding_type="poc",
    )
    if not verification.get("verified"):
        task.status = TaskStatus.needs_triage
    return 1 if row else 0


def _generate_spec(session: Session, project: Project, target: Target, task: Task):
    """Ask the backend (mock/LLM) for a PoC spec. The mock's `poc` fixtures return a
    ready spec; a real backend crafts one from the decompilation in context."""
    from hexgraph.engine.llm_tasks import _build_context
    from hexgraph.llm.registry import get_backend
    from hexgraph.llm.base import LLMRequest

    ctx = _build_context(session, project, target, task)
    backend = get_backend(task.backend if task.backend not in (None, "none") else None)
    req = ctx.build_request(prompt="Produce a PoC spec (JSON) for the most serious issue.")
    try:
        resp = backend.complete(req)
        data = json.loads(resp.text)
        spec = data.get("poc") or data.get("spec") or data
        return spec, data.get("function"), data.get("category", "command-injection")
    except Exception:  # noqa: BLE001
        return None, task.params_json.get("function") if task.params_json else None, "command-injection"

"""Proof-of-concept findings — an exploit HexGraph can EXECUTE and verify (dynamic).

A PoC spec says how to run the target (argv/env/stdin) and how to know it worked
(an oracle). `verify_poc` substitutes a fresh random **nonce** into the spec and
runs it in the sandbox, so "verified" means the injected behaviour actually
happened (e.g. an injected `echo <nonce>` really executed) — not something the
model could fake. A `poc` task generates a PoC (LLM/mock) and verifies it,
emitting a `poc`-type finding whose evidence carries the spec + the verification.

Execution is policy-gated (`assert_allows_execution()` — PoC/fuzzing enabled) and
runs --network none, capped, timed, disposable. Foreign-arch targets run under
qemu-user (poc_probe picks `qemu-<arch>` from the ELF header and mounts the parent
firmware's extracted rootfs as the qemu sysroot), verified end-to-end on real
MIPS/ARM firmware.
"""

from __future__ import annotations

import copy
import json
import secrets

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, Task, TaskStatus
from hexgraph.engine import cas
from hexgraph.engine.findings.findings import persist_finding
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


# Spec keys whose values are RAW base64 byte data, NOT a {{NONCE}} substitution surface:
# rewriting them would corrupt the encoded bytes (and a nonce literal can't appear in base64).
# An argv_b64 reproducer pairs with an output/exit/crash oracle, not a reflected-nonce oracle.
_RAW_BYTE_KEYS = frozenset({"argv_b64", "stdin_b64"})


def _substitute(obj, nonce: str):
    if isinstance(obj, str):
        return obj.replace(NONCE_PLACEHOLDER, nonce)
    if isinstance(obj, list):
        return [_substitute(x, nonce) for x in obj]
    if isinstance(obj, dict):
        # Leave raw base64 byte fields (argv_b64/stdin_b64) verbatim — they are bytes, not text.
        return {k: (v if k in _RAW_BYTE_KEYS else _substitute(v, nonce)) for k, v in obj.items()}
    return obj


def _is_web(target: Target) -> bool:
    """A web/service surface is reached via an HTTP Channel, not executed bytes."""
    from hexgraph.db.models import TargetKind

    return target.kind == TargetKind.web_app or bool(
        (target.metadata_json or {}).get("channel", {}).get("base_url"))


def _is_tcp(spec: dict) -> bool:
    """A raw-TCP PoC: `{transport:"tcp", port, payload?, oracle}` (or a nested `tcp` block).
    Reaches a live socket service on the device — the network tier, not byte execution.

    Requires BOTH a tcp marker AND a port: an incidental/stray `tcp` field (or a
    `transport:"tcp"` left on an otherwise-web/binary spec) without a reachable port
    can't misroute a web spec into the TCP path or slip past the exec gate. The port
    may sit at the top level or inside a nested `tcp` block."""
    tcp = spec.get("tcp") if isinstance(spec.get("tcp"), dict) else {}
    has_marker = (spec.get("transport") == "tcp") or bool(spec.get("tcp"))
    has_port = bool(spec.get("port") or tcp.get("port"))
    return has_marker and has_port


def _verify_tcp_poc(session, project, target, spec, runner, nonce) -> dict:
    """Raw-TCP PoC: send the spec's payload to the device's port and evaluate the oracle on
    the response (the probe strips the sent payload first, so a match is unforgeable).
    {{NONCE}} is already substituted. Gated by the SAME bounded-egress policy as the web
    tools (network on + local-only scope) and audited."""
    from hexgraph.engine.targets.surfaces import run_tcp_probe

    tcp = spec.get("tcp") if isinstance(spec.get("tcp"), dict) else spec
    port = tcp.get("port") or spec.get("port")
    if not port:
        raise ValueError("a tcp PoC spec needs a `port` (and usually `payload` + `oracle`)")
    oracle = spec.get("oracle") or tcp.get("oracle") or {}
    result = run_tcp_probe(session, project, target, port=int(port), payload=tcp.get("payload"),
                           oracle=oracle, runner=runner)
    return {"verified": bool(result.get("verified")), "detail": result.get("detail"),
            "exit_code": None, "output": (result.get("response") or "")[:2000],
            "nonce": nonce, "spec": spec}


def _verify_web_poc(session, project, target, spec, runner, nonce) -> dict:
    """Web PoC: run the spec's HTTP steps and evaluate its oracle on the final response
    (cookies carry across steps). {{NONCE}} is already substituted. Gated by the SAME
    bounded-egress policy as web_recon (network on + local-only scope) and audited."""
    from hexgraph.engine.targets.surfaces import run_web_poc

    steps = spec.get("steps") or ([spec["request"]] if spec.get("request") else [])
    if not steps:
        raise ValueError("a web PoC spec needs `steps` (or a single `request`) and an `oracle`")
    result = run_web_poc(session, project, target, steps=steps,
                         oracle=spec.get("oracle") or {}, runner=runner)
    last = (result.get("steps") or [{}])[-1]
    return {"verified": bool(result.get("verified")), "detail": result.get("detail"),
            "exit_code": last.get("status"), "output": (last.get("body") or "")[:2000],
            "nonce": nonce, "spec": spec, "steps": result.get("steps")}


def verify_poc(session: Session, project: Project, target: Target, spec: dict,
               *, runner: Executor | None = None) -> dict:
    """Run a PoC spec against `target` and report whether it worked.

    A `{{NONCE}}` placeholder anywhere in the spec is replaced with a fresh random
    token before running, making the oracle unforgeable. Three flavours:
    - **raw TCP** (spec has `transport:"tcp"` or a `tcp` block) → send `payload` to the
      device's `port` and check a `response_contains` oracle; reaches a live socket service
      on a rehosted/remote device, gated by the bounded-egress network tier. Checked FIRST,
      since a rehosted device is also a web surface.
    - **web surface** (a `web_app` Channel) → send the spec's HTTP `steps` and check a
      `body_contains`/`status_is`/`status_differs` oracle on the final response; gated by
      the bounded-egress network tier.
    - **binary** → run it in the sandbox (argv/env/stdin + an output/exit/crash oracle);
      policy-gated by `assert_allows_execution` (PoC/fuzzing enabled).
    Beyond the in-band `{{NONCE}}`-in-output oracle (best for reflected cmdi), extra oracles
    prove broader vuln classes by observing a side effect on an INDEPENDENT channel
    (engine.findings.oracles, docs/design/design-verification-oracles.md): **oob_write** (the exploit writes
    `{{NONCE}}`, HexGraph reads it back out-of-band), **canary_read** (HexGraph plants a random
    canary out-of-band, the exploit must read it back), **callback** (a bounded local
    listener the target dials back, substituted as `{{CALLBACK}}` — proves blind cmdi/SSRF/RCE),
    and **liveness**/**unavailable** (DoS: HexGraph probes the live service UP, sends the DoS
    input, then re-probes that it is DOWN and STAYS down across N probes — a transient blip does
    not count; for a binary this degrades to the sandbox `crash` oracle).
    Every result also carries an **`assurance`** triple ({standard, method, precondition},
    docs/design/design-verification-oracles.md) the engine computes — so the two standards of "verified"
    (code-present vs input-reachable) are differentiated by code, not prose."""
    from hexgraph.engine.findings import oracles

    nonce = "HEXGRAPH_PWNED_" + secrets.token_hex(6)
    live = _substitute(copy.deepcopy(spec or {}), nonce)
    is_tcp, is_web = _is_tcp(live), _is_web(target)

    if oracles.is_new_oracle(live) and oracles.is_liveness(live) and not (is_web or is_tcp):
        # DoS against a BINARY is already the sandbox `crash` oracle (signal/exit/timeout) — the
        # process dying IS the liveness transition for a one-shot binary. Don't reimplement it:
        # rewrite the binary liveness oracle to a `crash` oracle and run the normal binary path.
        live = dict(live)
        live["oracle"] = {"type": "crash"}
        result = _verify_binary_poc(session, project, target, live, runner, nonce)
    elif oracles.is_new_oracle(live):
        # Phase-1/2 oracles observe a side effect on a channel INDEPENDENT of the exploit's
        # request (a read-back, a planted canary, a bounded callback listener, or — for liveness —
        # HexGraph's own out-of-band re-probe of the service) — not just the in-band response.
        # Each runs the SAME exploit flow (web/tcp/binary) but evaluates its own unforgeable
        # oracle. docs/design/design-verification-oracles.md.
        result = oracles.verify(session, project, target, live, runner, nonce,
                                is_web=is_web, is_tcp=is_tcp)
    elif is_tcp:
        result = _verify_tcp_poc(session, project, target, live, runner, nonce)
    elif is_web:
        result = _verify_web_poc(session, project, target, live, runner, nonce)
    else:
        result = _verify_binary_poc(session, project, target, live, runner, nonce)

    # Label what was actually proven (the engine decides this, not the caller): a PoC is a
    # DYNAMIC method, but the SCOPE decides the standard — a verified live web/tcp surface PoC
    # establishes `input_reachable`, while a verified isolated binary exec is `code_present`
    # (lab-confirmed); see derive_poc_assurance / docs/design/design-verification-oracles.md.
    from hexgraph.engine.findings.assurance import derive_poc_assurance
    result["assurance"] = derive_poc_assurance(result, live, is_web=is_web, is_tcp=is_tcp)
    return result


def _verify_binary_poc(session, project, target, live, runner, nonce) -> dict:
    """Binary PoC: execute the target in the sandbox (argv/env/stdin + an output/exit/crash
    oracle). {{NONCE}} already substituted. Policy-gated by `assert_allows_execution` (PoC/
    fuzzing on). Foreign-arch firmware binaries run under qemu-user (poc_probe picks qemu-<arch>
    from the ELF header); a dynamically-linked one needs its sibling libs, so mount the parent
    firmware's extracted rootfs as the qemu sysroot."""
    import tempfile

    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # opt-in gate: raises unless PoC/fuzzing is enabled
    runner = runner or get_executor()

    extra_mounts: list[tuple[str, str]] = []
    if target.parent_id and not live.get("sysroot"):
        from hexgraph.engine.targets.filesystem import host_root
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


def _assurance_str(a: dict | None) -> str:
    """One-line `standard / method / precondition` for the finding reasoning."""
    if not a:
        return "—"
    s = f"{a.get('standard')} / {a.get('method')} / {a.get('precondition')}"
    return s + " (inferred precondition)" if a.get("precondition_inferred") else s


def _repro(spec: dict, target: Target | None):
    """The human-facing reproduction command; never let rendering break a finding."""
    try:
        from hexgraph.engine.findings.poc_repro import repro_command
        return repro_command(spec, target)
    except Exception:  # noqa: BLE001
        return None


def _repro_str(repro) -> str | None:
    if not repro:
        return None
    return repro if isinstance(repro, str) else " ".join(str(p) for p in repro)


def _poc_finding(spec: dict, verification: dict, function: str | None, target_name: str,
                 category: str, target: Target | None = None) -> Finding:
    verified = bool(verification.get("verified"))
    repro = _repro(spec, target)
    repro_str = _repro_str(repro)
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
        + (f"\nExit: {verification.get('exit_code')}" if verification.get("exit_code") is not None else "")
        + (f"\nAssurance: {_assurance_str(verification.get('assurance'))}"
           if verification.get("assurance") else "")
        + (f"\nReproduce: {repro_str}" if repro_str else ""),
        evidence=Evidence(
            function=function,
            # A human-readable reproduction command, NOT the raw JSON; the structured
            # spec (the re-verify source of truth) stays in extra.poc.
            reproducer=repro_str or json.dumps(spec),
            extra={"poc": spec, "repro_command": repro,
                   "assurance": verification.get("assurance"),
                   "verification": {
                "verified": verified, "detail": verification.get("detail"),
                "exit_code": verification.get("exit_code"),
                "output": (verification.get("output") or "")[:2000],
                "nonce": verification.get("nonce"),
                "assurance": verification.get("assurance"),
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
        finding=_poc_finding(spec, verification, function, target.name, category, target),
        finding_type="poc",
    )
    if not verification.get("verified"):
        task.status = TaskStatus.needs_triage
    return 1 if row else 0


def verify_reproducer(session: Session, project: Project, target: Target, *,
                      reproducer_ref: str, function: str | None = None,
                      runner: Executor | None = None) -> dict:
    """Re-run a fuzz-crash reproducer against the target and report whether it still
    crashes — the crash→verify tie-in (design §4.6). A fuzz crash's minimized
    reproducer is a self-contained, content-addressed input in CAS (`reproducer_ref`):
    we read the bytes, feed them to the target IN THE SANDBOX as stdin, and check the
    unforgeable `crash` oracle (signal/ASan abort). So a one-click re-verify is
    identical to re-running a hand-written PoC — LLM-free, gated by the same
    `assert_allows_execution`. Returns the verify_poc result dict (incl. `assurance`,
    code_present/dynamic for an isolated reproducer replay)."""
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # the same exec gate fuzzing/poc already require
    raw = cas.get(project, reproducer_ref)
    if raw is None:
        raise ValueError(f"reproducer {reproducer_ref!r} not found in CAS")
    # The reproducer bytes drive the target directly. A compiled fuzzer/harness reads
    # its input from stdin in our harness template; the `crash` oracle (signal/ASan
    # abort) is unforgeable — the process really died on this input.
    import base64
    spec = {
        # BYTE-FAITHFUL: the raw reproducer bytes, base64'd — the probe feeds them on stdin
        # in byte mode (0x00/0xff preserved exactly). A text `stdin` field is UTF-8 re-encoded
        # by the subprocess and would corrupt a binary reproducer (battle-test GAP).
        "stdin_b64": base64.b64encode(raw).decode(),
        "oracle": {"type": "crash"},
        "scope": "harness",  # an isolated reproducer replay → code_present/dynamic
    }
    return verify_poc(session, project, target, spec, runner=runner)


def verify_finding_reproducer(session: Session, project: Project, finding,
                              *, runner: Executor | None = None) -> dict:
    """Re-verify a `fuzz_crash` finding by replaying its stored reproducer (read from
    `evidence.extra.fuzz.reproducer_ref`). The one-click re-verify for a fuzz finding —
    no LLM, the assurance ladder applies. Returns the verification result."""
    ev = finding.evidence_json or {}
    fuzz = (ev.get("extra") or {}).get("fuzz") or {}
    ref = fuzz.get("reproducer_ref")
    if not ref:
        raise ValueError("this finding has no stored reproducer (reproducer_ref) to re-verify")
    target = session.get(Target, finding.target_id)
    if target is None:
        raise ValueError("finding target not found")
    return verify_reproducer(session, project, target, reproducer_ref=ref,
                             function=ev.get("function"), runner=runner)


def _spec_has_input(spec: dict) -> bool:
    """True if the spec already supplies its OWN input/exploit surface — so the solver-
    handoff must NOT clobber a caller-authored argv/stdin/steps/payload with the recovered
    bytes. (An oracle / precondition / timeout alone is not an input.)"""
    return any(spec.get(k) is not None
               for k in ("argv", "argv_b64", "stdin", "stdin_b64", "steps", "request",
                         "payload", "tcp"))


def spec_from_solver_finding(finding, base_spec: dict | None = None) -> dict | None:
    """Build a byte-faithful binary PoC spec from an angr-SOLVER finding's recovered input —
    the handoff that lets `finding_verify_poc` confirm a solved argv reproducer actually
    reaches the sink, byte-for-byte.

    A solver finding (engine.re.solving) carries `evidence.extra.solver` with `input_model`
    ('argv'|'stdin'), the recovered bytes as `minimal_input_hex` (the constrained prefix —
    "the part that matters", preferred) / `concrete_input_hex`, and `evidence.reproducer`
    (hex). We decode those hex bytes and feed them RAW: for `input_model=='argv'` as a single
    `argv_b64` element (so a non-printable serial like 0x3b25065c4b20040f survives as a real
    argv[1] that str() would mangle); for `'stdin'` as `stdin_b64`. The default oracle is the
    sink-execution evidence `output_contains "License valid."`-style success isn't knowable
    generically, so we default to `exit_code 0` ONLY when the caller gives no oracle — but a
    caller SHOULD pass an oracle (output_contains/crash/exit_code) that matches the success
    path. Returns None when the finding carries no recovered input (nothing to hand off)."""
    ev = (finding.evidence_json or {}) if finding is not None else {}
    solver = ((ev.get("extra") or {}).get("solver") or {})
    if not solver:
        return None
    input_hex = solver.get("minimal_input_hex") or solver.get("concrete_input_hex") or ev.get("reproducer")
    if not input_hex:
        return None
    try:
        raw = bytes.fromhex(str(input_hex))
    except ValueError:
        return None
    if not raw:
        return None

    import base64

    spec = dict(base_spec or {})
    model = (solver.get("input_model") or "argv").strip().lower()
    if model == "stdin":
        spec.setdefault("stdin_b64", base64.b64encode(raw).decode())
    else:  # 'argv' (the common solver input model) — feed the bytes as a single raw argv[1]
        spec.setdefault("argv_b64", [base64.b64encode(raw).decode()])
    # An argv_b64/stdin_b64 reproducer pairs with an output/exit/crash oracle (NOT a reflected
    # nonce). Default to a clean-exit oracle when the caller supplied none; a caller is
    # encouraged to pass a tighter oracle (output_contains the success string / crash).
    spec.setdefault("oracle", {"type": "exit_code", "value": 0})
    return spec


def _generate_spec(session: Session, project: Project, target: Target, task: Task):
    """Ask the backend (mock/LLM) for a PoC spec. The mock's `poc` fixtures return a
    ready spec; a real backend crafts one from the decompilation in context."""
    from hexgraph.engine.llm_tasks import _build_context
    from hexgraph.llm.registry import get_backend

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

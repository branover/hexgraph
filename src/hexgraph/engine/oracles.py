"""Unforgeable verification oracles beyond reflected command-injection
(docs/design-verification-oracles.md, Phase 1).

The principle: an unforgeable oracle observes the vuln's side effect on a channel
INDEPENDENT of the exploit's own request. `verify_poc` already covers reflected cmdi
(`{{NONCE}}` in the response, reflection-stripped). This module adds three oracle types that
prove broader vuln classes, all reusing the existing bounded channels (filesystem/remote/web/
tcp) + the new bounded callback listener, and all still behind the policy seam:

  - **oob_write** (write primitives) — the exploit writes `{{NONCE}}` to a target-controlled
    location; HexGraph then INDEPENDENTLY reads that location back and checks the nonce landed.
    Read-back channel: `rootfs` (engine.filesystem.read_file), `remote`
    (engine.remote.run_remote read_file), or `http` (a follow-up GET). Unforgeable because the
    verifier observes the side-effect location out-of-band.
  - **canary_read** (read primitives — traversal / file or info disclosure) — BEFORE running the
    exploit, HexGraph PLANTS a random `{{NONCE}}` canary at a known path on the target via the
    OOB channel (or independently reads a known secret); the exploit's read primitive must
    retrieve it, and the oracle checks the response contains the planted canary. Unforgeable
    because HexGraph established the ground truth on a separate channel — the model cannot know
    a freshly-planted random value.
  - **callback** (blind cmdi / SSRF / blind RCE / OOB exfil) — HexGraph stands up a bounded local
    listener, substitutes a `{{CALLBACK}}` token (host:port + per-run nonce path) into the spec
    like `{{NONCE}}`, runs the exploit, and verifies the listener received a hit carrying the
    nonce. The listener is the audited INGRESS mirror of the bounded-egress tier
    (engine.callback_listener).
  - **liveness** / **unavailable** (denial of service — Phase 2) — proves DoS by an unforgeable
    LIVENESS TRANSITION HexGraph observes out-of-band: probe the live service is UP (a baseline
    response on its own, independent channel) BEFORE the exploit, send the DoS input, then
    RE-PROBE that it is DOWN and STAYS down across N probes (hysteresis), so a single transient
    blip is NOT a verified DoS — only a sustained baseline-UP → sustained-DOWN transition counts.
    The verdict comes from HexGraph's own re-probe, never the exploit's response, so it can't be
    forged. For a BINARY target, process death is already the sandbox `crash` oracle
    (signal/exit/timeout) — liveness degrades to that path rather than reimplementing it.

Each is a DYNAMIC oracle and flows through `derive_poc_assurance` unchanged: fired through a
live web/tcp/remote surface ⇒ input_reachable/dynamic; an isolated binary/harness ⇒
code_present/dynamic. The oracle results live in `evidence.extra` — the DB envelope, NOT the
frozen finding schema.
"""

from __future__ import annotations

import secrets
import time
import urllib.parse

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target

# Oracle type names (extend the verify_poc oracle vocabulary).
OOB_WRITE = "oob_write"
CANARY_READ = "canary_read"
CALLBACK = "callback"
LIVENESS = "liveness"
UNAVAILABLE = "unavailable"  # alias of LIVENESS (denial-of-service / service-unavailable)

NEW_ORACLE_TYPES = frozenset({OOB_WRITE, CANARY_READ, CALLBACK, LIVENESS, UNAVAILABLE})

# Liveness-oracle defaults (hysteresis): after the DoS input, re-probe DOWN this many times with
# this delay between probes, and ALL must read DOWN — so a single transient hiccup never verifies.
_LIVENESS_REPROBES = 3
_LIVENESS_REPROBE_DELAY = 0.5  # seconds between down re-probes

# A canary big enough that it can't be guessed/confabulated by the model.
_CANARY_PREFIX = "HEXGRAPH_CANARY_"

# Reflection-stripping only removes echoes at least this long: the matched secrets (nonce/canary)
# are long random tokens, so a shorter reflected fragment can't BE/contain the secret — skipping
# short structural tokens (HTTP verb, param/header key names) avoids over-stripping a legit secret.
_MIN_ECHO_LEN = 12


def is_new_oracle(spec: dict) -> bool:
    """True if the spec's oracle is one of the extended (Phase 1/2) types handled here."""
    return ((spec or {}).get("oracle") or {}).get("type") in NEW_ORACLE_TYPES


def is_liveness(spec: dict) -> bool:
    """True if the spec's oracle is the DoS liveness/unavailable oracle (Phase 2)."""
    return ((spec or {}).get("oracle") or {}).get("type") in (LIVENESS, UNAVAILABLE)


def fresh_canary() -> str:
    return _CANARY_PREFIX + secrets.token_hex(10)


def _steps_of(spec: dict) -> list:
    """The request step(s) the EXPLOIT submits (web/single-request shape)."""
    return (spec or {}).get("steps") or ([spec["request"]] if (spec or {}).get("request") else [])


def _collect_strings(obj, out: list[str]) -> None:
    """Recursively gather every string/scalar value from a request component (params/headers/
    body/json may be nested dicts/lists). EVERYTHING the request carries is attacker-controlled."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (int, float)):
        out.append(str(obj))
    elif isinstance(obj, bytes):
        out.append(obj.decode("utf-8", "replace"))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _collect_strings(k, out)   # KEY NAMES are submitted too (KEY=value, Header-Name: v)
            _collect_strings(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_strings(v, out)


def _request_echoes(req: dict) -> list[str]:
    """Everything a request SUBMITTED — the method, path, ALL params (keys+values), ALL header
    names+values, and the FULL body (recursively) — in raw + URL/HTML-encoded forms, so a server's
    reflection of our own input (via ANY field, incl. a header, the verb, or a param NAME) is
    stripped from a response before the oracle matches. Stripping the WHOLE request (not a
    hand-picked field list) closes the 'reflect-via-some-other-field' forgery class by construction."""
    if not isinstance(req, dict):
        return []
    raw: list[str] = []
    for key in ("method", "path", "params", "headers", "body", "json"):
        if key in req and req[key] is not None and not isinstance(req[key], bool):
            _collect_strings(req[key], raw)
    out: list[str] = []
    for v in raw:
        # Only strip echoes long enough to plausibly CARRY the matched secret (the nonce/canary are
        # long random tokens, ~27+ chars). A short submitted token (the verb, `id`, `data`, `q`)
        # can't contain the secret, so stripping it would only risk scrubbing a coincidental
        # fragment out of a legitimate secret (a false-negative). Skipping them is forgery-safe.
        if not v or len(v) < _MIN_ECHO_LEN:
            continue
        out += [v, urllib.parse.quote(v), urllib.parse.quote_plus(v),
                v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")]
    return out


def _strip_reflections(text: str, requests) -> str:
    """Remove the verification path's own submitted input (reflections) from `text` before the
    oracle matches its secret. A value that survives stripping was PRODUCED by the target (a real
    read/write), not echoed back from what we sent — this is what closes the reflection-forgery."""
    for req in requests or []:
        for echo in _request_echoes(req):
            if echo:
                text = text.replace(echo, "")
    return text


# --------------------------------------------------------------------------------------
# OOB channels — read-back and plant, reusing the EXISTING bounded channels. Each is gated
# + audited by the channel it delegates to (filesystem read is host-local; remote/http run
# through run_remote / run_web_poc which assert the policy + record EgressEvent).
# --------------------------------------------------------------------------------------

def _read_back(session: Session, project: Project, target: Target, *, channel: str,
               path: str | None, request: dict | None, runner) -> str:
    """Independently read the side-effect location and return its content as text. The read
    uses a channel the EXPLOIT'S REQUEST does not control, which is what makes the oracle
    unforgeable. Raises ValueError on a misspecified channel."""
    channel = (channel or "").lower()
    if channel == "rootfs":
        return _rootfs_read(session, project, target, path)
    if channel == "remote":
        return _remote_read(session, project, target, path, runner)
    if channel == "http":
        return _http_read(session, project, target, request, runner)
    raise ValueError(f"unknown OOB channel {channel!r} (expected rootfs|remote|http)")


def _rootfs_read(session: Session, project: Project, target: Target, rel: str | None) -> str:
    """Read a file from the firmware's extracted rootfs (engine.filesystem). The target is the
    firmware (or a child whose parent is the firmware); `rel` is relative to the rootfs root."""
    from hexgraph.engine.filesystem import host_root

    if not rel:
        raise ValueError("oob channel 'rootfs' needs a `path` (relative to the rootfs)")
    fw = _firmware_for(session, target)
    if fw is None:
        raise ValueError("no firmware filesystem to read back from (channel 'rootfs')")
    root = host_root(project, fw).resolve()
    p = (root / rel.lstrip("/")).resolve()
    # Path-traversal safe: the read-back path must stay within the extracted rootfs.
    if root != p and root not in p.parents:
        raise ValueError("read-back path escapes the unpacked filesystem")
    if not p.is_file():
        return ""  # the write didn't land (or wrong path) → empty read-back, oracle fails
    return p.read_bytes()[: 256 * 1024].decode("utf-8", "replace")


def _firmware_for(session: Session, target: Target):
    """The firmware target carrying the extracted filesystem: `target` itself if it has one,
    else its parent (a child ELF's parent firmware)."""
    if (target.metadata_json or {}).get("filesystem"):
        return target
    if target.parent_id:
        fw = session.get(Target, target.parent_id)
        if fw is not None and (fw.metadata_json or {}).get("filesystem"):
            return fw
    return None


def _remote_read(session: Session, project: Project, target: Target, path: str | None, runner) -> str:
    """Read a file from a LIVE remote/rehosted device over the read-only remote channel
    (engine.remote.run_remote), which asserts features.remote + audits the egress."""
    from hexgraph.engine.remote import run_remote

    if not path:
        raise ValueError("oob channel 'remote' needs a `path`")
    res = run_remote(session, project, target, op="read_file", path=path, runner=runner)
    return str(res.get("content") or res.get("data") or "")


def _http_read(session: Session, project: Project, target: Target, request: dict | None, runner) -> str:
    """Independently GET a location over HTTP (a follow-up request the exploit did not make) —
    e.g. read back a file the write primitive dropped into the webroot. Gated + audited by
    run_http_request."""
    from hexgraph.engine.surfaces import run_http_request

    if not request:
        raise ValueError("oob channel 'http' needs a `request` (e.g. {method:'GET', path:'/x'})")
    resp = run_http_request(session, project, target, request=request, runner=runner)
    return str((resp or {}).get("body") or "")


def _plant(session: Session, project: Project, target: Target, *, channel: str, path: str | None,
           value: str) -> None:
    """Plant a canary out-of-band so the exploit's read primitive must retrieve it. Only the
    `rootfs` channel can WRITE (filesystem); `remote`/`http` are read-only here, so canary_read
    over them must instead read an EXISTING secret HexGraph reads independently (see
    `plant.known={channel,path}`)."""
    channel = (channel or "").lower()
    if channel == "rootfs":
        _rootfs_plant(session, project, target, path, value)
        return
    raise ValueError(
        f"cannot PLANT a canary over channel {channel!r} — only 'rootfs' supports an OOB write. "
        "For a live remote/web target, supply `plant.known={channel,path}` (an existing secret "
        "HexGraph reads out-of-band) instead of planting one.")


def _rootfs_plant(session: Session, project: Project, target: Target, rel: str | None, value: str) -> None:
    from hexgraph.engine.filesystem import host_root

    if not rel:
        raise ValueError("plant channel 'rootfs' needs a `path`")
    fw = _firmware_for(session, target)
    if fw is None:
        raise ValueError("no firmware filesystem to plant a canary into (channel 'rootfs')")
    root = host_root(project, fw).resolve()
    p = (root / rel.lstrip("/")).resolve()
    if root != p and root not in p.parents:
        raise ValueError("plant path escapes the unpacked filesystem")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value)


# --------------------------------------------------------------------------------------
# Running the exploit. The new oracles reuse the SAME exploit-execution flow as the
# baseline oracles — web steps / raw tcp / binary exec — but evaluate a different,
# independent side-effect. `run_exploit` runs the steps WITHOUT the baseline oracle (we
# don't trust the in-band response); the independent oracle decides verified.
# --------------------------------------------------------------------------------------

def run_exploit(session, project, target, spec, runner, *, is_web, is_tcp):
    """Run the exploit portion of `spec` (already nonce/callback-substituted) and return the
    raw run result, WITHOUT applying any in-band oracle (the new oracle observes an independent
    channel). Mirrors verify_poc's branch selection so the exploit reaches the same boundary."""
    from hexgraph.engine import poc as poc_mod

    sub = dict(spec)
    sub.pop("oracle", None)  # the in-band oracle is irrelevant; we observe out-of-band
    if is_tcp:
        return poc_mod._verify_tcp_poc(session, project, target, sub, runner, sub.get("nonce", ""))
    if is_web:
        return poc_mod._verify_web_poc(session, project, target, sub, runner, sub.get("nonce", ""))
    return poc_mod._verify_binary_poc(session, project, target, sub, runner, sub.get("nonce", ""))


# --------------------------------------------------------------------------------------
# The oracle evaluators. Each returns a dict like the existing _verify_* results:
#   {verified, detail, exit_code, output, nonce, spec}
# --------------------------------------------------------------------------------------

def verify_oob_write(session, project, target, spec, runner, nonce, *, is_web, is_tcp) -> dict:
    """oob_write: run the write exploit, then INDEPENDENTLY read the side-effect location and
    check `nonce` landed there. `spec.oracle = {type:'oob_write', channel, path?|request?}`."""
    oracle = spec.get("oracle") or {}
    run = run_exploit(session, project, target, spec, runner, is_web=is_web, is_tcp=is_tcp)
    try:
        content = _read_back(session, project, target, channel=oracle.get("channel"),
                             path=oracle.get("path"), request=oracle.get("request"), runner=runner)
    except ValueError as exc:
        return {"verified": False, "detail": f"oob_write read-back error: {exc}",
                "exit_code": run.get("exit_code"), "output": run.get("output"),
                "nonce": nonce, "spec": spec}
    # Reflection-strip the READ-BACK's own request from its response before matching. For
    # rootfs/remote the read-back is a direct file read (no request to echo); for the `http`
    # channel a reflective read-back endpoint could echo a nonce we put in its params — strip
    # that, so a match means the nonce was genuinely WRITTEN to the location, not reflected.
    matchable = _strip_reflections(content, [oracle.get("request")] if oracle.get("request") else [])
    verified = bool(nonce) and nonce in matchable
    note = ""
    if not verified and bool(nonce) and nonce in content:
        note = " [present only as reflected read-back input — not proof of a write]"
    return {"verified": verified, "exit_code": run.get("exit_code"),
            "output": (content or "")[:2000], "nonce": nonce, "spec": spec,
            "detail": (f"oob_write: nonce {'FOUND' if verified else 'NOT found'} at the "
                       f"independently-read {oracle.get('channel')} location "
                       f"{oracle.get('path') or oracle.get('request')!r}{note}")}


def verify_canary_read(session, project, target, spec, runner, nonce, *, is_web, is_tcp) -> dict:
    """canary_read: establish a secret OUT-OF-BAND, then check the read exploit retrieves it.
    Two forms (both unforgeable — HexGraph knows the value, the agent/exploit does not):
      - `spec.plant = {channel:'rootfs', path}` → plant a FRESH random canary at `path`.
      - `spec.plant = {known:{channel,path|request}}` → read an EXISTING secret out-of-band; that
        read IS the ground truth. (An agent-supplied `known_value` literal is REJECTED — it could
        be reflected.) `spec.oracle = {type:'canary_read'}`. The exploit's request references the
        PATH, never the value, and the response is reflection-stripped before matching."""
    plant = spec.get("plant") or {}
    if plant.get("known_value") is not None:
        # An agent-supplied literal is NOT ground truth — a reflective endpoint would echo it and
        # forge the read. Require HexGraph to establish the value out-of-band instead.
        return {"verified": False, "exit_code": None, "output": "", "nonce": nonce, "spec": spec,
                "detail": "canary_read: `plant.known_value` (an agent literal) is not accepted — "
                          "use `plant.known={channel,path}` so HexGraph reads the ground-truth "
                          "secret out-of-band, or `plant={channel:'rootfs',path}` to plant a fresh canary."}
    known = plant.get("known")
    if known:
        # Ground truth must come from a NON-REFLECTIVE channel — a real file read (rootfs/remote)
        # of an EXISTING secret. An agent-crafted HTTP request is NOT allowed here: a reflective
        # endpoint can always echo an attacker-chosen value through SOME request field (param/header
        # name, the verb, …), laundering it in as the "secret" — the exact forgery class. A file
        # read returns the actual stored bytes, with no request to reflect.
        if (known.get("channel") or "").lower() not in ("rootfs", "remote"):
            return {"verified": False, "exit_code": None, "output": "", "nonce": nonce, "spec": spec,
                    "detail": "canary_read: `known` must read an existing secret via a non-reflective "
                              "file channel (rootfs|remote), NOT an agent-crafted http request — a "
                              "reflective endpoint could launder an attacker-chosen value as the secret."}
        try:
            canary = _read_back(session, project, target, channel=known.get("channel"),
                                path=known.get("path"), request=None, runner=runner).strip()
        except ValueError as exc:
            return {"verified": False, "detail": f"canary_read known-secret read error: {exc}",
                    "exit_code": None, "output": "", "nonce": nonce, "spec": spec}
        if not canary:
            return {"verified": False, "exit_code": None, "output": "", "nonce": nonce, "spec": spec,
                    "detail": "canary_read: the known-secret file read returned nothing — no ground truth."}
    else:
        canary = fresh_canary()
        try:
            _plant(session, project, target, channel=plant.get("channel"),
                   path=plant.get("path"), value=canary)
        except ValueError as exc:
            return {"verified": False, "detail": f"canary_read plant error: {exc}",
                    "exit_code": None, "output": "", "nonce": nonce, "spec": spec}

    # Run the read exploit AS WRITTEN — its request references the PATH where the canary lives
    # (a traversal the agent chose), NOT the canary VALUE. We deliberately do NOT substitute the
    # canary into the request: the value is a fresh random HexGraph established out-of-band, so the
    # exploit cannot know it, and a reflective endpoint cannot echo it. Belt-and-suspenders, we
    # also strip the exploit request's own reflections from the response before matching.
    run = run_exploit(session, project, target, spec, runner, is_web=is_web, is_tcp=is_tcp)
    body = str(run.get("output") or "")
    matchable = _strip_reflections(body, _steps_of(spec))
    verified = bool(canary) and canary in matchable
    return {"verified": verified, "exit_code": run.get("exit_code"),
            "output": body[:2000], "nonce": nonce, "spec": spec,
            "detail": (f"canary_read: out-of-band-established secret {'RETRIEVED' if verified else 'NOT retrieved'} "
                       f"by the read primitive (value never sent in the request → not reflection-forgeable)")}


def verify_callback(session, project, target, spec, runner, nonce, *, is_web, is_tcp) -> dict:
    """callback: stand up a bounded local listener, substitute `{{CALLBACK}}` (host:port +
    per-run nonce path) into the spec, run the exploit, and verify the listener got a hit
    carrying the nonce. Proves a blind cmdi/SSRF/RCE with ZERO reflected output.
    `spec.oracle = {type:'callback', timeout?, bind_host?}`. The listener is the audited ingress
    mirror of the bounded-egress tier (loopback/private only, features.network-gated)."""
    from hexgraph.engine.audit import record_egress
    from hexgraph.engine.callback_listener import CallbackListener
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, current_policy,
                                 local_tcp_scope)

    oracle = spec.get("oracle") or {}
    bind_host = oracle.get("bind_host") or "127.0.0.1"
    timeout = float(oracle.get("timeout", 15) or 15)

    # Gate FIRST (before binding any socket): the callback listener is the ingress mirror of the
    # bounded-egress tier, so it requires the SAME bounded-network policy as every live-target
    # tool. The denial is audited and PROPAGATES (like _egress_gate / assert_allows_execution) —
    # the MCP/CLI layer turns it into the "enable features.network" message. No gate is relaxed
    # outside the policy seam.
    gate_scope = local_tcp_scope(bind_host, 1)  # port-independent: the gate is host/network-level
    try:
        assert_allows_egress(next(iter(gate_scope.allow)), gate_scope, current_policy())
    except PolicyViolation:
        record_egress(session, project_id=project.id, target_id=target.id,
                      dest=f"{bind_host} (callback listener, pre-bind)", allowed=False,
                      tool="callback_listener",
                      detail="blocked: callback listener requires the bounded-network tier")
        raise

    listener = CallbackListener(host=bind_host).start()  # loopback/private only (fail-closed)
    try:
        dest = f"{listener.bound_host}:{listener.bound_port}"
        record_egress(session, project_id=project.id, target_id=target.id, dest=dest, allowed=True,
                      tool="callback_listener", detail="bounded local callback listener (ingress)")

        sub = _sub_token(spec, "{{CALLBACK}}", listener.token())
        run = run_exploit(session, project, target, sub, runner, is_web=is_web, is_tcp=is_tcp)
        hit = listener.wait(timeout=timeout)
        verified = hit is not None
        if verified:
            record_egress(session, project_id=project.id, target_id=target.id, dest=hit.peer,
                          allowed=True, tool="callback_hit",
                          detail=f"callback received carrying nonce {listener.nonce}")
        return {"verified": verified, "exit_code": run.get("exit_code"),
                "output": (hit.data[:2000] if hit else (run.get("output") or "")[:2000]),
                "nonce": nonce, "spec": spec,
                "detail": (f"callback: listener {'RECEIVED' if verified else 'did NOT receive'} a "
                           f"hit carrying the per-run nonce within {timeout:g}s "
                           f"(blind side-channel, unforgeable)")}
    finally:
        listener.stop()


def _sub_token(spec: dict, token: str, value: str) -> dict:
    """Replace `token` everywhere in the spec with `value` (the {{CALLBACK}}/{{CANARY}}
    analogue of poc._substitute), returning a new dict."""
    def walk(obj):
        if isinstance(obj, str):
            return obj.replace(token, value)
        if isinstance(obj, list):
            return [walk(x) for x in obj]
        if isinstance(obj, dict):
            return {k: walk(v) for k, v in obj.items()}
        return obj

    return walk(spec)


# --------------------------------------------------------------------------------------
# liveness / unavailable (denial of service). The oracle is a LIVENESS TRANSITION HexGraph
# observes ITSELF on the service's own channel, independent of the exploit's response:
#   baseline UP  →  send the DoS input  →  re-probe DOWN, and STAYS down (hysteresis).
# A liveness probe is just a benign request HexGraph sends through the SAME bounded, gated,
# audited channel as web/tcp verify (run_http_request / run_tcp_probe) — so the probes are
# policy-gated + every one is audited to EgressEvent. We never trust the exploit's own output.
# --------------------------------------------------------------------------------------

def _liveness_probe_web(session, project, target, request: dict | None, runner) -> tuple[bool, str]:
    """Probe a live web surface ONCE and decide UP/DOWN. UP = we got a real HTTP response with a
    non-5xx status; DOWN = connection refused/timeout/error OR a 5xx (per the spec). The request
    is a benign liveness GET (default `GET /`); it goes through run_http_request, which is policy-
    gated + audits the egress, so every probe is logged. Returns (up?, detail)."""
    from hexgraph.engine.surfaces import run_http_request

    req = dict(request or {"method": "GET", "path": "/"})
    req.setdefault("method", "GET")
    req.setdefault("path", "/")
    resp = run_http_request(session, project, target, request=req, runner=runner) or {}
    if not resp.get("ok"):
        return False, f"no response ({resp.get('error') or 'unreachable'})"
    status = resp.get("status")
    try:
        is_5xx = 500 <= int(status) < 600
    except (TypeError, ValueError):
        is_5xx = False
    if is_5xx:
        return False, f"server-error status {status}"
    return True, f"status {status}"


def _liveness_probe_tcp(session, project, target, port: int, runner) -> tuple[bool, str]:
    """Probe a live raw-TCP service ONCE: UP = the connect succeeds (we got `ok`), DOWN = the
    connect is refused/times out. A bare connect (no payload, no oracle) through run_tcp_probe,
    which is policy-gated + audits the egress. Returns (up?, detail)."""
    from hexgraph.engine.surfaces import run_tcp_probe

    resp = run_tcp_probe(session, project, target, port=int(port), payload=None, oracle=None,
                         read_bytes=1, runner=runner) or {}
    if resp.get("ok"):
        return True, f"connect to :{port} succeeded"
    return False, f"connect to :{port} failed ({resp.get('error') or 'refused'})"


def _probe_once(session, project, target, oracle, port, runner, *, is_tcp) -> tuple[bool, str]:
    if is_tcp:
        return _liveness_probe_tcp(session, project, target, port, runner)
    return _liveness_probe_web(session, project, target, oracle.get("probe"), runner)


def verify_liveness(session, project, target, spec, runner, nonce, *, is_web, is_tcp) -> dict:
    """liveness/unavailable (DoS): prove the service transitions UP → sustained-DOWN.

    `spec.oracle = {type:'liveness'|'unavailable', probe?, reprobes?, delay?, port?}`. `probe`
    is the benign liveness HTTP request (default `GET /`); `port` is the raw-TCP port. We:
      1. Baseline-probe UP. If it's ALREADY down, the result is INCONCLUSIVE (not a verified DoS).
      2. Send the DoS input (the exploit, via the same web/tcp boundary), discarding its response.
      3. Re-probe DOWN `reprobes` times (default 3) with `delay`s between; ALL must read DOWN
         (hysteresis), so a single transient blip is NOT a verified DoS.
    For a BINARY target this routes to the sandbox `crash` oracle instead (process death is
    already covered there) — see verify_poc's dispatch. The verdict is HexGraph's own out-of-band
    re-probe, never the exploit's response — unforgeable."""
    oracle = spec.get("oracle") or {}
    reprobes = max(1, int(oracle.get("reprobes", _LIVENESS_REPROBES)))
    delay = max(0.0, float(oracle.get("delay", _LIVENESS_REPROBE_DELAY)))
    port = oracle.get("port") or spec.get("port") or (
        (spec.get("tcp") or {}).get("port") if isinstance(spec.get("tcp"), dict) else None)

    if is_tcp and not port:
        return {"verified": False, "exit_code": None, "output": "", "nonce": nonce, "spec": spec,
                "detail": "liveness: a tcp liveness oracle needs a `port` to probe"}

    # 1. Baseline — must be UP before we can claim we knocked it down.
    up, base_detail = _probe_once(session, project, target, oracle, port, runner, is_tcp=is_tcp)
    if not up:
        return {"verified": False, "exit_code": None, "output": "", "nonce": nonce, "spec": spec,
                "detail": (f"liveness: INCONCLUSIVE — the service was already DOWN at baseline "
                           f"({base_detail}); a DoS can only be verified against a service that "
                           f"was UP first")}

    # 2. Send the DoS input through the live boundary (we don't trust its response).
    run = run_exploit(session, project, target, spec, runner, is_web=is_web, is_tcp=is_tcp)

    # 3. Re-probe DOWN with hysteresis: EVERY re-probe must read DOWN. A single UP re-probe means
    #    the service recovered / only blipped → NOT a verified DoS (transient hiccup rejected).
    down_details: list[str] = []
    for i in range(reprobes):
        if i and delay:
            time.sleep(delay)
        up, d = _probe_once(session, project, target, oracle, port, runner, is_tcp=is_tcp)
        down_details.append(("UP" if up else "DOWN") + f":{d}")
        if up:
            return {"verified": False, "exit_code": run.get("exit_code"),
                    "output": "; ".join(down_details)[:2000], "nonce": nonce, "spec": spec,
                    "detail": (f"liveness: NOT verified — after the DoS input the service was still "
                               f"reachable on re-probe {i + 1}/{reprobes} ({d}); a transient blip is "
                               f"not a sustained outage")}

    return {"verified": True, "exit_code": run.get("exit_code"),
            "output": "; ".join(down_details)[:2000], "nonce": nonce, "spec": spec,
            "detail": (f"liveness: VERIFIED denial of service — baseline UP ({base_detail}), then "
                       f"DOWN across all {reprobes} re-probe(s) after the DoS input (sustained "
                       f"outage; verdict from HexGraph's own out-of-band probe, unforgeable)")}


_EVALUATORS = {
    OOB_WRITE: verify_oob_write,
    CANARY_READ: verify_canary_read,
    CALLBACK: verify_callback,
    LIVENESS: verify_liveness,
    UNAVAILABLE: verify_liveness,
}


def verify(session, project, target, spec, runner, nonce, *, is_web, is_tcp) -> dict:
    """Dispatch to the Phase-1 oracle evaluator named by `spec.oracle.type`. Caller has
    already confirmed `is_new_oracle(spec)`."""
    typ = (spec.get("oracle") or {}).get("type")
    return _EVALUATORS[typ](session, project, target, spec, runner, nonce, is_web=is_web, is_tcp=is_tcp)

"""Render a PoC spec as a human, copy-paste reproduction COMMAND.

`verify_poc` re-runs the structured `evidence.extra.poc` spec inside the sandbox (the
source of truth, with `{{NONCE}}` intact). This module produces the OTHER half of an
actionable finding: a literal shell command a human can paste to reproduce the issue by
hand — a `curl` per web step, an `nc`/`printf` for a raw-TCP spec, the `argv`/stdin/env
invocation for a binary spec. It is a human-facing RENDERING only; it is NEVER fed back
to verify (which always uses the structured spec). Any `{{NONCE}}`/`{{CALLBACK}}`
placeholder is left verbatim so the reader sees exactly what HexGraph substitutes.
"""

from __future__ import annotations

import shlex
from urllib.parse import quote_plus, urlencode

from hexgraph.db.models import Target


def _urlencode_keep_placeholders(params: dict) -> str:
    """urlencode params but leave {{...}} placeholders verbatim, so a human reading the
    command sees exactly the token HexGraph substitutes at verify time (not %7B%7B…)."""
    return urlencode(params, doseq=True, quote_via=lambda s, safe, enc, errs: quote_plus(s, safe="{}"))


def _web_base_url(target: Target | None) -> str:
    """The surface base_url for a web PoC, or a readable placeholder if unknown."""
    if target is None:
        return "$BASE_URL"
    ch = (target.metadata_json or {}).get("channel") or {}
    return ch.get("base_url") or "$BASE_URL"


def _curl_for_step(base_url: str, step: dict) -> str:
    """One `curl` line reproducing a single HTTP step (method/path/params/headers/body)."""
    method = str(step.get("method") or "GET").upper()
    path = str(step.get("path") or "/")
    url = base_url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
    params = step.get("params") or {}
    if params:
        url += ("&" if "?" in url else "?") + _urlencode_keep_placeholders(params)

    parts = ["curl", "-sk", "-X", method]
    for k, v in (step.get("headers") or {}).items():
        parts += ["-H", f"{k}: {v}"]
    # cookies carry across steps in verify; mirror that hint for the human.
    parts += ["-c", "/tmp/poc.jar", "-b", "/tmp/poc.jar"]

    if step.get("json") is not None:
        import json as _json
        parts += ["-H", "Content-Type: application/json", "--data", _json.dumps(step["json"])]
    else:
        body = step.get("body")
        if isinstance(body, dict):
            parts += ["--data", _urlencode_keep_placeholders(body)]
        elif body is not None:
            parts += ["--data", str(body)]

    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


def _web_command(spec: dict, target: Target | None) -> str:
    base = _web_base_url(target)
    steps = spec.get("steps") or ([spec["request"]] if spec.get("request") else [])
    if not steps:
        return f"# (web PoC has no steps) curl -sk {shlex.quote(base)}"
    return " \\\n  && ".join(_curl_for_step(base, s) for s in steps)


def _tcp_command(spec: dict, target: Target | None) -> str:
    tcp = spec.get("tcp") if isinstance(spec.get("tcp"), dict) else {}
    port = tcp.get("port") or spec.get("port")
    host = "DEVICE_IP"
    if target is not None:
        ch = (target.metadata_json or {}).get("channel") or {}
        host = (ch.get("rehost") or {}).get("ip") or ch.get("host") or host
        if host == "DEVICE_IP" and ch.get("base_url"):
            from urllib.parse import urlparse
            host = urlparse(ch["base_url"]).hostname or host
    payload = tcp.get("payload") if tcp.get("payload") is not None else spec.get("payload")
    if payload is None:
        return f"nc {shlex.quote(str(host))} {port}"
    # printf the payload (preserving \n, \r etc. the author wrote) and pipe into nc.
    return f"printf {shlex.quote(str(payload))} | nc {shlex.quote(str(host))} {port}"


def _ansi_c_quote(raw: bytes) -> str:
    r"""Render raw bytes as a shell ANSI-C `$'\xNN…'` literal — the portable idiom for a
    non-printable byte sequence as a single argv element (a solved serial like 0x3b…0f). Every
    byte is escaped as `\xNN`, so it stays one inert word with no quoting surprises."""
    return "$'" + "".join(f"\\x{b:02x}" for b in raw) + "'"


def _binary_command_str(spec: dict, target: Target | None) -> str:
    import base64

    path = (target.path if target is not None else None) or "./target"
    parts: list[str] = []
    # Set env via the `env` utility so the WHOLE `KEY=VALUE` token can be shlex-quoted —
    # a bare `KEY=VALUE` prefix can't quote the key (quoting it stops being an assignment),
    # so a hostile key (`A; rm -rf /`) would inject. `env 'KEY=VALUE'` neutralizes it.
    env = spec.get("env") or {}
    if env:
        parts.append("env")
        parts += [shlex.quote(f"{k}={v}") for k, v in env.items()]
    parts.append(shlex.quote(path))
    # Prefer the BYTE-FAITHFUL argv_b64 (each element raw bytes) over the text argv — rendered
    # as $'\xNN…' so a human pastes the exact non-printable serial the solver recovered.
    argv_b64 = spec.get("argv_b64")
    if argv_b64 is not None:
        for a in argv_b64:
            try:
                parts.append(_ansi_c_quote(base64.b64decode(a)))
            except Exception:  # noqa: BLE001
                parts.append("''")
    else:
        parts += [shlex.quote(str(a)) for a in (spec.get("argv") or [])]
    cmd = " ".join(parts)
    # stdin: the byte-faithful stdin_b64 (printf '\xNN…') wins over the text stdin field.
    stdin_b64 = spec.get("stdin_b64")
    if stdin_b64 is not None:
        try:
            raw = base64.b64decode(stdin_b64)
            return "printf " + "'" + "".join(f"\\x{b:02x}" for b in raw) + "'" + f" | {cmd}"
        except Exception:  # noqa: BLE001
            pass
    stdin = spec.get("stdin")
    if stdin is not None:
        return f"printf {shlex.quote(str(stdin))} | {cmd}"
    return cmd


def repro_command(spec: dict, target: Target | None):
    """Derive a copy-paste reproduction command from a PoC spec.

    Returns a `str` (a shell pipeline) for web/tcp/binary specs. The flavour is detected
    the SAME way `verify_poc` routes: a tcp marker+port ⇒ `nc`/`printf`; a web surface
    (web_app kind or a channel base_url) ⇒ `curl` per step; otherwise a binary
    `env … ./target argv` (optionally `printf stdin |`). Placeholders ({{NONCE}}…) are
    left verbatim. This is for HUMANS — verify always uses the structured spec."""
    from hexgraph.engine.poc import _is_tcp, _is_web

    spec = spec or {}
    if _is_tcp(spec):
        return _tcp_command(spec, target)
    if target is not None and _is_web(target):
        return _web_command(spec, target)
    # No target context but the spec is clearly web (has steps/request and no binary argv intent)?
    if target is None and (spec.get("steps") or spec.get("request")):
        return _web_command(spec, None)
    return _binary_command_str(spec, target)

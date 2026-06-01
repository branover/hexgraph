#!/usr/bin/env python3
"""Connect to ONE operator-authorized live device (SSH/telnet) from INSIDE the sandbox and
run a BOUNDED, read-only analysis op — the same KINDS of things we'd do to a static or
rehosted firmware image (enumerate the filesystem, read a file, run a recon tool), but on a
physical/networked box we don't have the firmware for.

  argv: remote_probe.py --channel <json>

channel = {transport: "ssh"|"telnet", host, port, username, password?, key?, timeout,
           op: "list_files"|"read_file"|"run_tool"|"launch", path?, tool?, args?, max_bytes?, max_entries?}

Read-only by construction, with ONE bounded exception: every op maps to a FIXED command
template; a caller-supplied path is shell-quoted (never concatenated raw), and `run_tool` only
accepts an allowlisted recon tool — there is no arbitrary-command op. The lone non-read-only op
is `launch` (start a not-auto-started service by binary path + shell-quoted args, backgrounded)
— still no arbitrary shell string, and the host gates it behind features.remote and audits it.
Egress is pinned by the host-side scope to this one host:port (the live-remote tier) and
audited. Credentials arrive in the channel (the host read them from env/config and never
persists them) and are not echoed back.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import sys

MAX_OUT = 256 * 1024


def _merge_secret(ch: dict) -> dict:
    """Merge credentials delivered out-of-band via the HG_CHANNEL_SECRET env var (not argv,
    so they never appear on the world-readable docker command line). Env-supplied fields
    take precedence; the var is cleared once consumed."""
    blob = os.environ.pop("HG_CHANNEL_SECRET", None)
    if not blob:
        return ch
    try:
        secret = json.loads(blob)
    except (ValueError, TypeError):
        return ch
    if isinstance(secret, dict):
        ch = {**ch, **secret}
    return ch

# Allowlisted read-only recon tools (fixed command templates; no caller shell). A few take an
# optional `path` arg (shell-quoted). Mirrors what we'd run on an extracted/rehosted rootfs.
TOOLS = {
    "uname": "uname -a",
    "id": "id",
    "ps": "ps w 2>/dev/null || ps aux 2>/dev/null || ps",
    "netstat": "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null || netstat -an",
    "mount": "mount",
    "ifconfig": "ip addr 2>/dev/null || ifconfig -a 2>/dev/null",
    "df": "df -h 2>/dev/null || df",
    "env": "env",
    "passwd": "cat /etc/passwd",
    "release": "cat /etc/os-release /etc/openwrt_release /etc/issue 2>/dev/null",
    "processes_full": "cat /proc/1/status 2>/dev/null",
}


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def _build_command(ch: dict) -> str:
    """Map the requested op → a single read-only shell command (caller paths shell-quoted)."""
    op = ch.get("op")
    if op == "list_files":
        path = shlex.quote(ch.get("path") or "/")
        depth = max(1, min(int(ch.get("max_depth", 3)), 8))
        n = max(1, min(int(ch.get("max_entries", 2000)), 10000))
        return f"find {path} -maxdepth {depth} 2>/dev/null | head -n {n}"
    if op == "read_file":
        path = shlex.quote(ch.get("path") or "")
        n = max(1, min(int(ch.get("max_bytes", MAX_OUT)), MAX_OUT))
        return f"head -c {n} -- {path}"
    if op == "run_tool":
        tool = ch.get("tool")
        if tool not in TOOLS:  # allowlist boundary: anything not in TOOLS (incl. `ls`) is rejected
            return ""
        return TOOLS[tool]
    if op == "ls":
        return f"ls -la {shlex.quote(ch.get('path') or '/')}"
    if op == "launch":
        # Bring up a service that didn't auto-start (so its socket can be tested live). NOT
        # read-only — this runs a binary on the operator-authorized device — but bounded: a
        # single shell-quoted binary path + shell-quoted args, backgrounded + detached with a
        # redirect so we return immediately. The caller gates (features.remote) and audits it.
        path = ch.get("path")
        if not path:
            return ""
        argv = " ".join(shlex.quote(str(a)) for a in (ch.get("args") or []))
        cmd = f"{shlex.quote(path)}{(' ' + argv) if argv else ''}"
        return f"setsid {cmd} >/tmp/hg_launch.log 2>&1 < /dev/null & echo \"launched pid $!\""
    return ""


def _ssh_exec(ch: dict, command: str) -> dict:
    import paramiko

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # assessing, not trusting
    timeout = int(ch.get("timeout", 30))
    kwargs = {"hostname": ch["host"], "port": int(ch.get("port", 22)),
              "username": ch.get("username") or "root", "timeout": timeout,
              "banner_timeout": timeout, "auth_timeout": timeout, "look_for_keys": False,
              "allow_agent": False}
    if ch.get("key"):
        for kc in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                kwargs["pkey"] = kc.from_private_key(io.StringIO(ch["key"])); break
            except Exception:  # noqa: BLE001 — try the next key type
                continue
    if ch.get("password"):
        kwargs["password"] = ch["password"]
    try:
        cli.connect(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"ssh connect failed: {type(exc).__name__}: {exc}"}
    try:
        _in, out, err = cli.exec_command(command, timeout=timeout)
        data = out.read(MAX_OUT + 1)
        errd = err.read(8192)
        status = out.channel.recv_exit_status()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"ssh exec failed: {type(exc).__name__}: {exc}"}
    finally:
        cli.close()
    return {"ok": True, "exit_status": status, "raw": data[:MAX_OUT],
            "truncated": len(data) > MAX_OUT, "stderr": errd.decode("utf-8", "replace")[:2000]}


def _telnet_exec(ch: dict, command: str) -> dict:
    import telnetlib  # noqa: S401 — deprecated stdlib but fine for an assessment client

    timeout = int(ch.get("timeout", 30))
    try:
        tn = telnetlib.Telnet(ch["host"], int(ch.get("port", 23)), timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"telnet connect failed: {type(exc).__name__}: {exc}"}
    try:
        idx, _m, _t = tn.expect([b"login:", b"[#$] ", b"~ #"], timeout=timeout)
        if idx == 0 and ch.get("username"):
            tn.write(ch["username"].encode() + b"\n")
            tn.read_until(b"assword:", timeout=timeout)
            tn.write((ch.get("password") or "").encode() + b"\n")
            tn.read_until(b"# ", timeout=timeout)
        # Bracket the output with a sentinel so we can cut the prompt/echo noise.
        tn.write(b"echo __HG_BEGIN__; " + command.encode() + b"; echo __HG_END__\n")
        raw = tn.read_until(b"__HG_END__", timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"telnet exec failed: {type(exc).__name__}: {exc}"}
    finally:
        tn.close()
    text = raw.decode("utf-8", "replace")
    if "__HG_BEGIN__" in text:
        text = text.split("__HG_BEGIN__", 1)[1]
    text = text.split("__HG_END__", 1)[0]
    return {"ok": True, "exit_status": None, "raw": text.encode("utf-8", "replace")[:MAX_OUT],
            "truncated": False, "stderr": ""}


def main() -> int:
    rest = sys.argv[1:]
    try:
        ch = json.loads(_flag(rest, "--channel", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --channel json: {exc}"}))
        return 2
    ch = _merge_secret(ch)  # creds arrive via HG_CHANNEL_SECRET env (never argv)
    # Defense-in-depth on top of the host-side scope: only ever dial the allowlisted host:port.
    allow = set(ch.get("allow") or [])
    if f"{ch.get('host')}:{int(ch.get('port', 22))}" not in allow:
        print(json.dumps({"ok": False, "error": "destination not in allowlist"}))
        return 0
    command = _build_command(ch)
    if not command:
        print(json.dumps({"ok": False, "error": f"unsupported op/tool: {ch.get('op')}/{ch.get('tool')}"}))
        return 0
    transport = (ch.get("transport") or "ssh").lower()
    res = _ssh_exec(ch, command) if transport == "ssh" else _telnet_exec(ch, command)

    if res.get("ok") and "raw" in res:
        raw = res.pop("raw")
        if ch.get("op") == "list_files":
            res["files"] = [ln for ln in raw.decode("utf-8", "replace").splitlines() if ln.strip()]
        elif ch.get("op") == "read_file":
            if b"\x00" in raw:
                res["encoding"] = "binary"; res["content"] = raw.hex()
            else:
                res["encoding"] = "text"; res["content"] = raw.decode("utf-8", "replace")
        else:
            res["output"] = raw.decode("utf-8", "replace")
    res["op"] = ch.get("op")
    print(json.dumps({"tool": "remote_probe", **res}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Remote live-device targets (SSH/telnet, the live-remote tier): bounded read-only ops over
a connection. Offline tests cover the command-building/allowlist + the policy gate + target
registration + secret-handling; a Docker-gated test drives a real sshd container end to end."""

import importlib.util
import os
import subprocess
import tempfile

import pytest

from conftest import SANDBOX_READY, container_ip, wait_for_port

_spec = importlib.util.spec_from_file_location(
    "remote_probe", os.path.join(os.path.dirname(__file__), "..", "src", "hexgraph",
                                 "sandbox", "probes", "remote_probe.py"))
remote_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(remote_probe)


# ---------------- offline: command building is read-only + injection-safe ----------------

def test_build_command_ops_and_quoting():
    assert remote_probe._build_command({"op": "read_file", "path": "/etc/shadow", "max_bytes": 100}) \
        == "head -c 100 -- /etc/shadow"
    lf = remote_probe._build_command({"op": "list_files", "path": "/etc", "max_depth": 2, "max_entries": 50})
    assert lf.startswith("find /etc -maxdepth 2") and "head -n 50" in lf
    assert remote_probe._build_command({"op": "run_tool", "tool": "uname"}) == "uname -a"
    # a path with shell metacharacters is QUOTED, never injected
    bad = remote_probe._build_command({"op": "read_file", "path": "/etc/x; rm -rf /"})
    assert "; rm -rf /" not in bad.replace("'/etc/x; rm -rf /'", "")  # the dangerous chars are inside quotes
    assert bad == "head -c 262144 -- '/etc/x; rm -rf /'"
    # unknown tool / op → empty (refused)
    assert remote_probe._build_command({"op": "run_tool", "tool": "rm"}) == ""
    assert remote_probe._build_command({"op": "exec", "tool": "sh"}) == ""


def test_run_tool_allowlist_is_readonly():
    for t in ("rm", "sh", "bash", "dd", "wget", "curl", "nc", "kill"):
        assert remote_probe._build_command({"op": "run_tool", "tool": t}) == ""
    for t in remote_probe.TOOLS:
        assert remote_probe._build_command({"op": "run_tool", "tool": t})  # all map to a command


# ---------------- offline: policy gate + scope ----------------

def test_remote_gate_off_by_default(hg_home):
    from hexgraph import policy
    assert policy.current_policy().allow_remote is False
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_remote()


def test_remote_tier_opt_in(hg_home):
    from hexgraph import policy, settings
    settings.update_settings({"features": {"remote": {"enabled": True}}})
    pol = policy.current_policy()
    assert pol.allow_remote and pol.tier == policy.TIER_LIVE_REMOTE
    assert pol.allow_network is True            # the tier inherently permits egress (to the one host)
    policy.assert_allows_remote()
    scope = policy.remote_scope("203.0.113.9", 2222)   # NOT private — operator-authorized host
    assert scope.allow == frozenset({"203.0.113.9:2222"})
    policy.assert_allows_egress("203.0.113.9:2222", scope, pol)
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("10.0.0.1:22", scope, pol)   # any other host refused


# ---------------- offline: registration + secrets never stored ----------------

def test_register_remote_target_no_secret_stored(hg_home, monkeypatch):
    from hexgraph.db.models import TargetKind
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.remote import _remote_secret, register_remote_target

    with session_scope() as s:
        p = create_project(s, name="rem")
        t = register_remote_target(s, p, "192.168.1.1", port=22, username="root", transport="ssh")
        assert t.kind == TargetKind.remote
        ch = t.metadata_json["channel"]
        assert ch == {"kind": "ssh", "host": "192.168.1.1", "port": 22,
                      "username": "root", "transport": "ssh"}
        # no password/key anywhere in the stored target
        assert "password" not in str(t.metadata_json) and "key" not in ch

    monkeypatch.setenv("HEXGRAPH_REMOTE_PASSWORD", "s3cr3t")
    assert _remote_secret() == {"password": "s3cr3t"}


# ---------- offline: creds reach the probe via env, NEVER via the docker argv ----------

def test_secret_not_in_docker_argv_but_reaches_env(hg_home, monkeypatch):
    """run_remote must NOT put the password/key on the docker command line (visible via
    `ps`/`/proc/<pid>/cmdline`); it delivers them through HG_CHANNEL_SECRET (env), where
    remote_probe merges them back onto the channel. Asserts both halves."""
    import subprocess as _subprocess

    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.remote import register_remote_target, run_remote
    from hexgraph.sandbox.runner import RunResult, SandboxRunner

    settings.update_settings({"features": {"remote": {"enabled": True}}})
    monkeypatch.setenv("HEXGRAPH_REMOTE_PASSWORD", "SUPERSECRETpw")
    monkeypatch.setenv("HEXGRAPH_REMOTE_KEY", "-----PRIVATE-KEY-MATERIAL-----")

    captured = {}

    def fake_run(cmd, *a, **kw):
        captured["cmd"] = cmd
        captured["env"] = kw.get("env")
        # Emulate the probe: read the secret from the env we were handed and prove it merged.
        env = kw.get("env") or {}
        blob = env.get("HG_CHANNEL_SECRET")
        out = {"tool": "remote_probe", "ok": True, "saw_password": False, "saw_key": False}
        if blob:
            import json as _json
            sec = _json.loads(blob)
            out["saw_password"] = sec.get("password") == "SUPERSECRETpw"
            out["saw_key"] = sec.get("key") == "-----PRIVATE-KEY-MATERIAL-----"
        return type("P", (), {"returncode": 0, "stdout": _subprocess_json(out), "stderr": ""})()

    monkeypatch.setattr(_subprocess, "run", fake_run)

    with session_scope() as s:
        p = create_project(s, name="rem-argv")
        t = register_remote_target(s, p, "203.0.113.9", port=2222, username="root", transport="ssh")
        res = run_remote(s, p, t, op="run_tool", tool="uname", runner=SandboxRunner())

    argv = " ".join(captured["cmd"])
    # The secret must NOT appear anywhere on the docker argv (the world-readable surface).
    assert "SUPERSECRETpw" not in argv
    assert "PRIVATE-KEY-MATERIAL" not in argv
    # ...and the docker invocation passes the secret by NAME only (value pulled from our env).
    assert "HG_CHANNEL_SECRET" in captured["cmd"]
    assert captured["env"]["HG_CHANNEL_SECRET"]  # the value lives in the child process env
    # ...and the probe genuinely received + merged it.
    assert res.get("saw_password") is True and res.get("saw_key") is True
    # secrets are still scrubbed from the returned result
    assert "password" not in res and "key" not in res


def _subprocess_json(obj):
    import json as _json
    return _json.dumps(obj)


def test_run_remote_scrubs_password_and_key_from_result(hg_home):
    """Offline pin (review #11) of the no-secret-leak scrub: even if the probe's result dict
    carries `password`/`key` (e.g. a /etc/passwd dump or echoed creds), run_remote must strip
    BOTH from what it returns. A fake runner stands in for the sandbox, no Docker."""
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.remote import register_remote_target, run_remote

    class LeakyRunner:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None, **kw):
            # The probe layer returned secret-looking keys — run_remote must scrub them.
            return {"tool": "remote_probe", "ok": True, "output": "root:x:0:0",
                    "password": "leaked-pw", "key": "-----LEAKED-KEY-----"}

    settings.update_settings({"features": {"remote": {"enabled": True}}})
    with session_scope() as s:
        p = create_project(s, name="rem-scrub")
        t = register_remote_target(s, p, "192.168.1.9", port=22, username="root")
        res = run_remote(s, p, t, op="read_file", path="/etc/passwd", runner=LeakyRunner())

    assert res.get("ok") is True and "root:x:0:0" in res.get("output", "")
    assert "password" not in res and "key" not in res        # BOTH scrubbed
    assert "leaked-pw" not in str(res) and "LEAKED-KEY" not in str(res)


# ---------------- live: a real sshd container ----------------

@pytest.fixture(scope="module")
def sshd():
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image")
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "Dockerfile"), "w") as fh:
        fh.write(
            "FROM alpine:3.19\n"
            "RUN apk add --no-cache openssh && ssh-keygen -A "
            "&& echo 'root:testpass123' | chpasswd "
            "&& sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config "
            "&& sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config "
            "&& echo 'hexgraph-marker-7Q2X' > /etc/hg_marker\n"
            'CMD ["/usr/sbin/sshd","-D","-e"]\n')
    img, name = "hexgraph-sshd-test:latest", "hexgraph-sshd-test"
    subprocess.run(["docker", "build", "-q", "-t", img, d], check=True, capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, img], check=True, capture_output=True)
    try:
        ip = container_ip(name)
        wait_for_port(ip, 22)
        yield ip
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_live_remote_ssh_ops(hg_home, sshd, monkeypatch):
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.agent import mcp_tools as M
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.remote import register_remote_target

    settings.update_settings({"features": {"remote": {"enabled": True}}})
    monkeypatch.setenv("HEXGRAPH_REMOTE_PASSWORD", "testpass123")
    with session_scope() as s:
        p = create_project(s, name="rem-live")
        t = register_remote_target(s, p, sshd, port=22, username="root", transport="ssh")
        tid = t.id

    # run_tool: uname
    r = M.remote_run(tid, "uname")
    assert r.get("ok") and "Linux" in (r.get("output") or "")
    # read_file: the marker we baked in
    rf = M.remote_read_file(tid, "/etc/hg_marker")
    assert rf.get("ok") and "hexgraph-marker-7Q2X" in (rf.get("content") or "")
    # list_files: /etc enumerated
    lf = M.remote_list_files(tid, "/etc")
    assert lf.get("ok") and any("ssh" in f for f in lf.get("files", []))
    # passwd recon tool
    pw = M.remote_run(tid, "passwd")
    assert pw.get("ok") and "root:" in (pw.get("output") or "")
    # secrets are never echoed back
    assert "testpass123" not in str(r) and "password" not in r


def test_live_remote_denied_when_feature_off(hg_home, sshd):
    from hexgraph.db.session import session_scope
    from hexgraph.agent import mcp_tools as M
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.remote import register_remote_target

    with session_scope() as s:
        p = create_project(s, name="rem-off")
        t = register_remote_target(s, p, sshd, port=22, username="root")
        tid = t.id
    out = M.remote_run(tid, "uname")          # features.remote off → refused, no connection
    assert "error" in out and "features.remote" in out["error"]

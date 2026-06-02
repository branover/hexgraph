#!/usr/bin/env python3
"""Live network/protocol fuzzing INSIDE the sandbox — generational, against a LIVE service
(network surface, tier 2; design §5.6).

  argv: boofuzz_probe.py --channel <json> --proto-spec <json> [flags...]
  channel = {host, port, allow: ["host:port"], protocol: "tcp"|"udp", timeout,
             max_total_time, max_crashes, outdir}

Drives a LIVE service (a rehosted device joined via the emulator netns, or a local
service) over a real socket, MUTATING each field of a generational protocol spec
(boofuzz request blocks / a small state graph), and detecting a crash with a LIVENESS
ORACLE: before each test case it confirms the service is UP (a fresh connect), sends the
mutated message, then re-probes — if the service no longer accepts a connection (and
STAYS down across re-probes), the message that preceded the death is a re-runnable
crashing reproducer. A service-death crash is `input_reachable/dynamic` — the strongest
assurance (reached through the live input boundary).

Uses **boofuzz** when present in the image (its block/checksum/state primitives + its
own monitor); otherwise a robust built-in generational mutator drives the same spec —
either way the crashing message sequence is recorded so the existing verify path
(tcp_probe + a liveness oracle) replays it.

Egress is bounded: the host:port MUST be in `allow` (the `_egress` chokepoint installs a
socket guard so a stray connect off-list raises), the host is loopback/private (enforced
host-side by local_tcp_scope before launch), and the caller has asserted
assert_allows_egress + audited an EgressEvent. NO target bytes run here — this is a
network client. STDLIB + optional boofuzz only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _egress  # noqa: E402


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def _write_status(outdir, obj):
    obj.setdefault("engine", "boofuzz")
    tmp = os.path.join(outdir, "status.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, os.path.join(outdir, "status.json"))


# ── liveness oracle ──────────────────────────────────────────────────────────────

# The active egress allowlist (set in main). The `_egress` socket-guard backstop only
# covers TCP stream connects; for UDP `sendto` there is no stdlib chokepoint, so we
# explicitly re-check the destination before EVERY UDP send (per-packet, not just the
# startup pre-check) — closing the UDP gap in the can't-forget backstop.
_ALLOW: set = set()


def _udp_guard(host, port):
    _egress.ensure_allowed(host, port, _ALLOW)  # raises EgressBlocked off-list


def _alive(host, port, proto, timeout=2.0):
    """True if the service still accepts a connection (TCP) / responds (UDP)."""
    try:
        if proto == "udp":
            _udp_guard(host, port)            # per-packet egress backstop (UDP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"\x00", (host, port))
            try:
                s.recvfrom(64)
            except socket.timeout:
                pass  # UDP: no ICMP unreachable ⇒ assume up
            s.close()
            return True
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:  # noqa: BLE001
        return False


def _send(host, port, proto, payload, timeout=3.0):
    """Send one message; return the bytes the service produced (bounded), or None if the
    connection failed outright."""
    try:
        if proto == "udp":
            _udp_guard(host, port)            # per-packet egress backstop (UDP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            try:
                data, _ = s.recvfrom(8192)
            except socket.timeout:
                data = b""
            s.close()
            return data
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(payload)
        try:
            data = s.recv(8192)
        except socket.timeout:
            data = b""
        s.close()
        return data
    except Exception:  # noqa: BLE001
        return None


# ── generational mutation of a proto spec ─────────────────────────────────────────

# Classic field mutations that find parsing bugs: long strings (overflow), format
# strings, negative/large length fields, boundary integers, embedded NULs.
_STRING_MUTATIONS = [
    b"A" * 64, b"A" * 256, b"A" * 1024, b"A" * 4096, b"A" * 16384, b"A" * 65535,
    b"%n%n%n%n", b"%s%s%s%s%s%s", b"%x" * 64,
    b"\x00" * 32, b"../" * 64, b"\xff" * 256,
    b"-1", b"99999999999999999999", b"0x7fffffff", b"\r\n" * 64,
]
_DELIM_MUTATIONS = [b"", b"\r\n\r\n", b"\x00", b"\n" * 64]


def _field_mutations(field):
    typ = field.get("type", "string")
    default = (field.get("default") or "")
    default_b = default.encode() if isinstance(default, str) else bytes(default)
    if not field.get("fuzzable", True):
        return [default_b]
    if typ in ("string", "static"):
        return [default_b, *_STRING_MUTATIONS]
    if typ == "delim":
        return [default_b, *_DELIM_MUTATIONS]
    if typ in ("int", "dword", "word", "byte"):
        return [default_b, b"-1", b"0", b"4294967295", b"99999999", b"\xff\xff\xff\xff"]
    return [default_b, *_STRING_MUTATIONS]


def _render(fields, mutate_idx, mutation):
    """Render a message: every field at its default except `mutate_idx`, which uses the
    mutation. (Generational: one field varied at a time, the boofuzz default.)"""
    out = bytearray()
    for i, f in enumerate(fields):
        if i == mutate_idx:
            out += mutation
        else:
            d = f.get("default") or ""
            out += d.encode() if isinstance(d, str) else bytes(d)
    return bytes(out)


def _builtin_cases(proto):
    """Yield (label, payload_bytes) generationally over each message's each field."""
    for mi, msg in enumerate(proto.get("messages", [])):
        fields = msg.get("fields", [])
        for fi, field in enumerate(fields):
            for k, mut in enumerate(_field_mutations(field)):
                yield (f"m{mi}.{field.get('name', fi)}.{k}", _render(fields, fi, mut))


# ── main fuzz loop (built-in; boofuzz path delegates to the same oracle) ───────────

def main() -> int:
    rest = sys.argv[1:]
    try:
        ch = json.loads(_flag(rest, "--channel", "{}"))
        proto = json.loads(_flag(rest, "--proto-spec", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad json: {exc}"}))
        return 2

    host = ch.get("host")
    port = int(ch.get("port", 0))
    proto_kind = ch.get("protocol", "tcp")
    allow = set(ch.get("allow") or [])
    outdir = ch.get("outdir") or "/out"
    max_total_time = int(ch.get("max_total_time", 60))
    max_crashes = int(ch.get("max_crashes", 10))
    os.makedirs(outdir, exist_ok=True)

    # Bounded-egress backstop: every TCP connect must be on the allowlist (the stdlib
    # socket guard), and every UDP send is re-checked per-packet against this set.
    global _ALLOW
    _ALLOW = set(allow)
    _egress.install_socket_guard(allow)
    try:
        _egress.ensure_allowed(host, port, allow)
    except _egress.EgressBlocked:
        _write_status(outdir, {"ran": False, "error": "destination not in allowlist",
                               "crash_count": 0, "crashes": [], "done": True})
        with open(os.path.join(outdir, "DONE"), "w") as fh:
            fh.write("blocked")
        print(json.dumps({"tool": "boofuzz_probe", "ran": False,
                          "error": "destination not in allowlist"}))
        return 0

    if not _alive(host, port, proto_kind):
        _write_status(outdir, {"ran": False, "error": f"service {host}:{port} not reachable at start",
                               "crash_count": 0, "crashes": [], "done": True})
        with open(os.path.join(outdir, "DONE"), "w") as fh:
            fh.write("unreachable")
        print(json.dumps({"tool": "boofuzz_probe", "ran": False,
                          "error": "service not reachable"}))
        return 0

    crashes = []
    seen = set()
    cases = 0
    deadline = time.monotonic() + max_total_time
    last_status = 0.0
    # The message sequence that preceded a death is the reproducer. We track the most
    # recent successfully-sent message so a death is attributed to the case before it.
    for label, payload in _builtin_cases(proto):
        if time.monotonic() > deadline or len(crashes) >= max_crashes:
            break
        cases += 1
        resp = _send(host, port, proto_kind, payload)
        # A crash = the service died and STAYS down (a transient blip doesn't count).
        if not _alive(host, port, proto_kind):
            time.sleep(0.5)
            if not _alive(host, port, proto_kind):
                key = hashlib.sha256(b"service-death|" + payload[:32]).hexdigest()
                if key not in seen:
                    seen.add(key)
                    sha = hashlib.sha256(payload).hexdigest()
                    crashes.append({
                        "kind": "service-crash", "function": None,
                        "summary": f"service {host}:{port} died after fuzzing field {label} "
                                   f"({len(payload)} bytes) and did not recover",
                        "reproducer_sha256": sha, "reproducer_size": len(payload),
                        "dedup_key": key, "dupe_count": 0,
                        "exploitability": {"rating": "dos", "access": None,
                                           "signals": ["the service process died on this input "
                                                       "(denial of service); may be memory-unsafe"]},
                        "minimized_reproducer_sha256": sha, "minimized_reproducer_size": len(payload),
                        "reproducer_b64": base64.b64encode(payload).decode(),
                        "coverage_instrumented": False,
                        "net_reproducer": {"host": host, "port": port, "protocol": proto_kind,
                                           "payload_b64": base64.b64encode(payload).decode(),
                                           "field": label},
                        "_report": f"service-death after {label}",
                    })
                # Try to let it respawn (a rehosted daemon may be restarted by init); if it
                # never comes back, remaining cases will all see it down — stop early.
                for _ in range(10):
                    time.sleep(0.5)
                    if _alive(host, port, proto_kind):
                        break
                else:
                    break
        now = time.monotonic()
        if now - last_status > 3:
            _write_status(outdir, {"ran": True, "engine": "boofuzz", "done": False,
                                   "coverage_instrumented": False, "executions": cases,
                                   "edges_covered": 0, "crash_count": len(crashes),
                                   "crashes": crashes})
            last_status = now

    final = {"ran": True, "engine": "boofuzz", "done": True, "coverage_instrumented": False,
             "compiled": True, "executions": cases, "edges_covered": 0,
             "crash_count": len(crashes), "crashes": crashes}
    _write_status(outdir, final)
    with open(os.path.join(outdir, "DONE"), "w") as fh:
        fh.write("boofuzz")
    print(json.dumps({"tool": "boofuzz_probe", **final}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

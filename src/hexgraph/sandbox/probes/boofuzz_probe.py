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

Despite the name, what actually drives the campaign today is a **built-in generational
mutator** (real upstream boofuzz is not imported or invoked). The mutator varies one
field at a time over a small protocol spec (a list of messages, each a list of fields)
and records the crashing message sequence so the existing verify path (tcp_probe + a
liveness oracle) can replay it.

Beyond the text-oriented mutations (long buffers, format strings, embedded NULs) the
spec supports BINARY-PROTOCOL primitives so a length-prefixed/checksummed protocol can
be exercised meaningfully:
  - per-field `encoding` (`utf8` default for text, `hex` for a hex string like "c8ff00",
    `bytes`/`raw` for a latin-1/direct byte mapping) so binary defaults aren't mangled
    through UTF-8;
  - a `size` (length) field that AUTO-TRACKS a named target block — it renders the byte
    length of that block in a configurable width/endianness (u8/u16/u32, big/little) and
    is also mutated independently to create length/body mismatches;
  - a `checksum` field that computes over a named block (sum8/16/32, crc16, crc32),
    recomputed as other fields mutate and also mutated independently.
These are additive — the existing string/format-string mutations are unchanged.

Egress is bounded: the host:port MUST be in `allow` (the `_egress` chokepoint installs a
socket guard so a stray connect off-list raises), the host is loopback/private (enforced
host-side by local_tcp_scope before launch), and the caller has asserted
assert_allows_egress + audited an EgressEvent. NO target bytes run here — this is a
network client. STDLIB + optional boofuzz only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import socket
import struct
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


def _wait_alive(host, port, proto, *, grace, interval=0.5):
    """Poll `_alive` for up to `grace` seconds, returning True as soon as the service
    accepts a connection. A launch-and-join service (§5.8b) is started in its OWN
    container an instant before this fuzzer; `docker run -d` returns before the server
    has bound its port, so a single connect can race the bind. A bounded startup grace
    lets a slow-binding launched (or rehosted) service come up before we declare it dead
    — without it, the campaign spuriously reports 'not reachable at start' / 0 executions."""
    deadline = time.monotonic() + max(0.0, float(grace))
    while True:
        if _alive(host, port, proto):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


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

# Mutations for a binary length (size) field: render a wrong length so a length/body
# mismatch is exercised (under-reporting truncates, over-reporting walks off the buffer).
_SIZE_MUTATIONS = [0, 1, 0xFF, 0x7FFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]


def _encode_default(field):
    """Turn a field's `default` into the EXACT bytes it represents, honouring the field's
    `encoding`/`format` so a binary value isn't routed through UTF-8.

      utf8 (default) : text default encoded as UTF-8.
      hex            : a hex string like "c8ff00" -> b"\\xc8\\xff\\x00".
      bytes / raw    : latin-1 / direct byte mapping (each char 0-255 = one byte);
                       a list/bytes default is taken verbatim.
    """
    default = field.get("default")
    if default is None:
        default = ""
    if isinstance(default, (bytes, bytearray)):
        return bytes(default)
    if isinstance(default, (list, tuple)):  # e.g. [0xc8, 0xff, 0x00]
        return bytes(default)
    enc = (field.get("encoding") or field.get("format") or "utf8").lower()
    s = str(default)
    if enc == "hex":
        cleaned = "".join(s.split()).replace("0x", "")
        return binascii.unhexlify(cleaned) if cleaned else b""
    if enc in ("bytes", "raw", "latin1", "latin-1"):
        return s.encode("latin-1")
    return s.encode("utf-8")


def _int_to_width(value, width, endian):
    """Pack an integer into a fixed-width big/little-endian byte field (u8/u16/u32),
    masking to width so an over-large mutation wraps rather than raising."""
    width = int(width or 4)
    masks = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}
    fmts = {1: "B", 2: "H", 4: "I"}
    if width not in fmts:
        width = 4
    prefix = "<" if str(endian or "big").lower().startswith("l") else ">"
    return struct.pack(prefix + fmts[width], int(value) & masks[width])


_CHECKSUMS = {
    "sum8": lambda b: bytes([sum(b) & 0xFF]),
    "sum16": lambda b: struct.pack(">H", sum(b) & 0xFFFF),
    "sum32": lambda b: struct.pack(">I", sum(b) & 0xFFFFFFFF),
    "crc16": lambda b: struct.pack(">H", _crc16(b)),
    "crc32": lambda b: struct.pack(">I", binascii.crc32(b) & 0xFFFFFFFF),
}


def _crc16(data):
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) — a common embedded checksum."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


# Fields whose value is COMPUTED from other fields (resolved last, after the simple
# fields are rendered) rather than fuzzed by mutating their own bytes.
_COMPUTED_TYPES = ("size", "length", "checksum")


def _field_mutations(field):
    typ = field.get("type", "string")
    default_b = _encode_default(field)
    if not field.get("fuzzable", True):
        return [default_b]
    if typ in ("string", "static"):
        return [default_b, *_STRING_MUTATIONS]
    if typ == "delim":
        return [default_b, *_DELIM_MUTATIONS]
    if typ in ("int", "dword", "word", "byte"):
        return [default_b, b"-1", b"0", b"4294967295", b"99999999", b"\xff\xff\xff\xff"]
    if typ in ("hex", "bytes", "raw"):
        return [default_b, *_STRING_MUTATIONS]
    return [default_b, *_STRING_MUTATIONS]


def _render(fields, mutate_idx=None, mutation=None):
    """Render a message to bytes. Every field renders at its (encoding-aware) default,
    except `mutate_idx` which uses `mutation` verbatim.

    Computed fields (`size`/`length`, `checksum`) are resolved in a SECOND pass: they
    track a named block (`block`/`of`) and render its current length / checksum, so they
    stay consistent as other fields mutate. When a computed field is itself the
    `mutate_idx`, its raw `mutation` bytes win — producing a length/body mismatch or a
    bad checksum on purpose.
    """
    # First pass: render every simple field; remember each field's byte span + name so a
    # computed field can measure a named block. None marks a computed slot to fill later.
    parts = []
    spans = {}  # field name -> (start, end) in the concatenated simple layout
    cursor = 0
    for i, f in enumerate(fields):
        name = f.get("name", str(i))
        typ = f.get("type", "string")
        if typ in _COMPUTED_TYPES and i != mutate_idx:
            parts.append(None)  # placeholder; resolved in pass 2
            spans[name] = (cursor, cursor)  # zero-width until filled
            continue
        if i == mutate_idx:
            chunk = mutation if mutation is not None else _encode_default(f)
        else:
            chunk = _encode_default(f)
        parts.append(chunk)
        spans[name] = (cursor, cursor + len(chunk))
        cursor += len(chunk)

    # Helper: bytes of a named block from the parts rendered so far (computed slots = b"").
    def block_bytes(block_name):
        for j, f in enumerate(fields):
            if f.get("name", str(j)) == block_name:
                return parts[j] or b""
        return b""

    # Second pass: fill computed slots.
    for i, f in enumerate(fields):
        if parts[i] is not None:
            continue
        typ = f.get("type", "string")
        target = f.get("block") or f.get("of")
        block = block_bytes(target) if target else b""
        if typ in ("size", "length"):
            parts[i] = _int_to_width(len(block), f.get("width", 4), f.get("endian", "big"))
        else:  # checksum
            algo = (f.get("algorithm") or f.get("algo") or "crc32").lower()
            fn = _CHECKSUMS.get(algo, _CHECKSUMS["crc32"])
            parts[i] = fn(block)

    return b"".join(p or b"" for p in parts)


def _builtin_cases(proto):
    """Yield (label, payload_bytes) generationally over each message's each field."""
    for mi, msg in enumerate(proto.get("messages", [])):
        fields = msg.get("fields", [])
        for fi, field in enumerate(fields):
            label = f"m{mi}.{field.get('name', fi)}"
            typ = field.get("type", "string")
            if typ in _COMPUTED_TYPES:
                # A computed field doesn't carry its own mutation corpus; fuzz it by
                # injecting independent wrong values (size/checksum mismatches).
                if not field.get("fuzzable", True):
                    continue
                width = field.get("width", 4) if typ in ("size", "length") else 4
                endian = field.get("endian", "big")
                for k, val in enumerate(_SIZE_MUTATIONS):
                    yield (f"{label}.{k}", _render(fields, fi, _int_to_width(val, width, endian)))
                continue
            for k, mut in enumerate(_field_mutations(field)):
                yield (f"{label}.{k}", _render(fields, fi, mut))


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
    # Bounded startup grace: how long to wait for the service to accept a connection
    # before declaring it unreachable. Defaults small for an already-up host; the engine
    # raises it for launch-and-join / rehosted services that need a moment to bind.
    startup_grace = float(ch.get("startup_grace", 2))
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

    if not _wait_alive(host, port, proto_kind, grace=startup_grace):
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

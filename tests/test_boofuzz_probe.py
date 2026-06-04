"""Offline unit tests for the network ("boofuzz") fuzzer's PURE proto-spec rendering
(F8 + F9). The render/mutation logic is plain Python (no socket, no Docker), so these
run in plain CI; the live-service campaign loop is Docker-gated elsewhere.

F9: a field `encoding` (`hex`/`bytes`) must produce EXACT bytes, not UTF-8 mojibake.
F8: a `size` field auto-tracks a named block's byte length (and updates as that block
    mutates); a `checksum` field recomputes over its block; both are also mutable
    independently to forge length/body mismatches and bad checksums.
"""

import binascii
import struct

from hexgraph.sandbox.probes import boofuzz_probe as bp


# ── F9: encoding-aware defaults ────────────────────────────────────────────────────

def test_hex_encoding_default_produces_exact_bytes():
    f = {"type": "hex", "name": "magic", "default": "c8ff00", "encoding": "hex"}
    assert bp._encode_default(f) == b"\xc8\xff\x00"  # NOT UTF-8 'È' (0xc3 0x88 ...)


def test_hex_encoding_tolerates_spaces_and_0x():
    f = {"type": "hex", "name": "m", "default": "0xde 0xad be ef", "encoding": "hex"}
    assert bp._encode_default(f) == b"\xde\xad\xbe\xef"


def test_bytes_encoding_is_latin1_direct_mapping_with_embedded_nul():
    f = {"type": "bytes", "name": "b", "default": "\xc8\x00\xff", "encoding": "bytes"}
    assert bp._encode_default(f) == b"\xc8\x00\xff"


def test_utf8_is_the_default_for_text():
    assert bp._encode_default({"type": "string", "name": "s", "default": "AB"}) == b"AB"
    # A non-ASCII char in a text field still goes through UTF-8 (multibyte) — the point of
    # F9 is that BINARY fields opt out, text stays text.
    assert bp._encode_default({"type": "string", "default": "È"}) == "È".encode("utf-8")


def test_malformed_hex_default_falls_back_not_raises():
    # An odd-length / non-hex `hex` default must not abort the campaign; it falls back to
    # a UTF-8 view of the literal instead of raising binascii.Error.
    f = {"type": "hex", "name": "m", "default": "abc", "encoding": "hex"}
    assert bp._encode_default(f) == b"abc"
    f2 = {"type": "hex", "name": "m", "default": "zz", "encoding": "hex"}
    assert bp._encode_default(f2) == b"zz"


def test_bytes_default_above_latin1_falls_back_not_raises():
    # A char > 0xFF in a `bytes` field can't be latin-1 encoded; fall back to UTF-8
    # rather than raising UnicodeEncodeError mid-campaign.
    f = {"type": "bytes", "name": "b", "default": "€", "encoding": "bytes"}
    assert bp._encode_default(f) == "€".encode("utf-8")


def test_list_default_is_taken_verbatim():
    f = {"type": "bytes", "name": "b", "default": [0xc8, 0xff, 0x00]}
    assert bp._encode_default(f) == b"\xc8\xff\x00"


def test_render_routes_binary_default_through_encoding_not_utf8():
    fields = [{"type": "hex", "name": "magic", "default": "c8ff", "encoding": "hex",
               "fuzzable": False}]
    assert bp._render(fields) == b"\xc8\xff"


# ── F8: size (length) field auto-tracking ──────────────────────────────────────────

def test_size_field_tracks_block_length_default():
    fields = [
        {"type": "size", "name": "len", "block": "body", "width": 2, "endian": "big"},
        {"type": "bytes", "name": "body", "default": "AAAA", "encoding": "bytes"},
    ]
    out = bp._render(fields)
    assert out == struct.pack(">H", 4) + b"AAAA"


def test_size_field_endianness_and_width():
    fields = [
        {"type": "size", "name": "len", "block": "body", "width": 4, "endian": "little"},
        {"type": "bytes", "name": "body", "default": "ABC", "encoding": "bytes"},
    ]
    assert bp._render(fields) == struct.pack("<I", 3) + b"ABC"

    fields[0]["width"] = 1
    fields[0]["endian"] = "big"
    assert bp._render(fields) == bytes([3]) + b"ABC"


def test_size_updates_when_tracked_block_mutates():
    fields = [
        {"type": "size", "name": "len", "block": "body", "width": 2, "endian": "big"},
        {"type": "string", "name": "body", "default": "AAAA"},
    ]
    # Mutate the body (index 1) to a long buffer; the size field must reflect the new len.
    big = b"A" * 1024
    out = bp._render(fields, mutate_idx=1, mutation=big)
    assert out == struct.pack(">H", 1024) + big


def test_size_field_can_be_mutated_independently_for_mismatch():
    fields = [
        {"type": "size", "name": "len", "block": "body", "width": 2, "endian": "big"},
        {"type": "bytes", "name": "body", "default": "AAAA", "encoding": "bytes"},
    ]
    # Forge the length field to 0xFFFF while the body stays 4 bytes — a length/body mismatch.
    out = bp._render(fields, mutate_idx=0, mutation=struct.pack(">H", 0xFFFF))
    assert out == struct.pack(">H", 0xFFFF) + b"AAAA"


def test_builtin_cases_emits_size_mismatch_cases():
    proto = {"messages": [{"name": "req", "fields": [
        {"type": "size", "name": "len", "block": "body", "width": 2, "endian": "big"},
        {"type": "bytes", "name": "body", "default": "AAAA", "encoding": "bytes"},
    ]}]}
    payloads = [p for _, p in bp._builtin_cases(proto)]
    # Some emitted case must claim a length != actual body length (4).
    assert any(struct.unpack(">H", p[:2])[0] != 4 for p in payloads)


# ── F8: checksum field ─────────────────────────────────────────────────────────────

def test_checksum_crc32_recomputes_over_block():
    fields = [
        {"type": "bytes", "name": "body", "default": "hello", "encoding": "bytes"},
        {"type": "checksum", "name": "ck", "block": "body", "algorithm": "crc32"},
    ]
    out = bp._render(fields)
    expected = struct.pack(">I", binascii.crc32(b"hello") & 0xFFFFFFFF)
    assert out == b"hello" + expected


def test_checksum_updates_when_block_mutates():
    fields = [
        {"type": "string", "name": "body", "default": "hello"},
        {"type": "checksum", "name": "ck", "block": "body", "algorithm": "crc32"},
    ]
    out = bp._render(fields, mutate_idx=0, mutation=b"WORLD")
    expected = struct.pack(">I", binascii.crc32(b"WORLD") & 0xFFFFFFFF)
    assert out == b"WORLD" + expected


def test_checksum_sum8_and_crc16():
    body = b"ABC"
    sum8 = bytes([sum(body) & 0xFF])
    fields = [
        {"type": "bytes", "name": "body", "default": "ABC", "encoding": "bytes"},
        {"type": "checksum", "name": "ck", "block": "body", "algorithm": "sum8"},
    ]
    assert bp._render(fields) == body + sum8

    fields[1]["algorithm"] = "crc16"
    assert bp._render(fields) == body + struct.pack(">H", bp._crc16(body))


def test_checksum_can_be_mutated_independently():
    fields = [
        {"type": "bytes", "name": "body", "default": "ABC", "encoding": "bytes"},
        {"type": "checksum", "name": "ck", "block": "body", "algorithm": "crc32"},
    ]
    out = bp._render(fields, mutate_idx=1, mutation=b"\x00\x00\x00\x00")
    assert out == b"ABC" + b"\x00\x00\x00\x00"  # a deliberately wrong checksum


# ── existing text mutations still work (additive) ──────────────────────────────────

def test_string_mutations_still_present():
    proto = {"messages": [{"name": "req", "fields": [
        {"type": "string", "name": "cmd", "default": "FUZZ"},
        {"type": "delim", "name": "crlf", "default": "\r\n", "fuzzable": False},
    ]}]}
    payloads = [p for _, p in bp._builtin_cases(proto)]
    assert any(b"A" * 1024 in p for p in payloads)       # long-buffer overflow case
    assert any(b"%n%n%n%n" in p for p in payloads)       # format-string case
    assert all(p.endswith(b"\r\n") for p in payloads)    # static delim preserved

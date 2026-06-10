"""G01: an unrecognized large container must NOT ingest to a silent 0-child result. recon flags a
large unknown blob + captures its magic header; analyze_target ATTEMPTS a carve and, if that yields
no analyzable child, surfaces an `unrecognized_container` diagnostic with the header bytes — so the
operator isn't left dead in the water with zero diagnostics on an unsupported firmware image."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

from hexgraph.db.session import session_scope
from hexgraph.engine.pipeline import analyze_target
from hexgraph.engine.targets.ingest import create_project, ingest_file

_RECON_PROBE = str(pathlib.Path(__file__).resolve().parents[1]
                   / "src/hexgraph/sandbox/probes/recon_probe.py")


def _recon(blob: bytes) -> dict:
    """Run recon_probe on a blob (host-safe: only the ELF path needs pyelftools)."""
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, blob); os.close(fd)
        out = subprocess.run([sys.executable, _RECON_PROBE, path], capture_output=True, text=True)
        return json.loads(out.stdout)
    finally:
        os.unlink(path)


def test_recon_flags_large_unrecognized_blob_with_magic():
    big = _recon(b"\xde\xad\xbe\xef\x01\x02\x03\x04" + b"\x00" * (1 << 20))  # >=1 MiB, no fw signature
    assert big["format"] == "unknown"
    assert big["magic_hex"].startswith("deadbeef")
    assert big["likely_unrecognized_container"] is True          # large unknown -> carve candidate
    small = _recon(b"\xde\xad\xbe\xef hello world")              # small unknown blob
    assert small["format"] == "unknown" and small.get("magic_hex")   # magic still captured
    assert "likely_unrecognized_container" not in small          # but NOT flagged as a container


class _FakeExecutor:
    """No-Docker executor: canned recon facts + an empty unpack (the unsupported-carve case)."""
    def __init__(self, recon_facts, files=None):
        self._recon = recon_facts
        self._files = files or []

    def run_json_probe(self, probe, artifact, *, outdir=None, **kw):
        if probe == "recon_probe.py":
            return self._recon
        if probe == "unpack_probe.py":
            return {"method": "binwalk", "root": "/out", "files": self._files}
        return {}


def test_unrecognized_container_emits_diagnostic_not_silent_zero(hg_home, tmp_path):
    blob = tmp_path / "image.bin"; blob.write_bytes(b"\x12\x34\x56\x78" + b"\x00" * 64)
    with session_scope() as s:
        p = create_project(s, name="uc")
        t = ingest_file(s, p, blob, name="image.bin")
        runner = _FakeExecutor({"tool": "recon_probe", "format": "unknown", "kind": "unknown",
                                "magic_hex": "12345678", "magic_ascii": ".4Vx",
                                "likely_unrecognized_container": True})
        summary = analyze_target(s, p, t, runner)
    assert summary["children_count"] == 0
    uc = summary["unrecognized_container"]          # the carve found nothing -> say so
    assert uc["magic_hex"] == "12345678"
    assert "did not recognize" in uc["note"] and "isn't supported" in uc["note"]


def test_plain_small_unknown_blob_is_not_treated_as_firmware(hg_home, tmp_path):
    """An ordinary small unknown blob (no container flag) takes the non-firmware path — no carve,
    no false 'unsupported container' warning."""
    blob = tmp_path / "data.bin"; blob.write_bytes(b"\x12\x34" + b"\x00" * 16)
    with session_scope() as s:
        p = create_project(s, name="plain")
        t = ingest_file(s, p, blob, name="data.bin")
        runner = _FakeExecutor({"tool": "recon_probe", "format": "unknown", "kind": "unknown",
                                "magic_hex": "1234"})  # no likely_unrecognized_container
        summary = analyze_target(s, p, t, runner)
    assert "unrecognized_container" not in summary
    assert summary["children_count"] == 0

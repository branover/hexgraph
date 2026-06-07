"""Hermetic, offline tests for the venv guard in ``setup.sh``.

The bootstrap script (``setup.sh``, the single source of truth that ``just setup`` wraps)
used to skip venv creation whenever a ``.venv`` *directory* merely existed. An interrupted
earlier run leaves a partial ``.venv`` behind — directory + ``bin/python`` present but pip
never bootstrapped in — and the re-run then died on ``.venv/bin/pip: No such file or
directory``. The fix made the guard self-healing: ``ensure_venv`` rebuilds any venv that
lacks a working pip.

These tests source ``setup.sh`` (which defines its functions but does NOT run ``main`` when
sourced) and call ``ensure_venv`` directly, with a **stubbed ``python3`` on PATH** so no real
venv/network is needed. The stub records each ``python3 -m venv`` invocation, so we can assert
exactly when the script (re)creates the venv and when it leaves a healthy one alone.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SETUP_SH = REPO_ROOT / "setup.sh"

# A fake `python3` whose only job is to satisfy `python3 -m venv <dir>` the way the guard
# expects: it records the call and lays down a *working* venv (a python+pip pair where
# `python -m pip --version` and `pip` both exit 0). Any other invocation is a harmless no-op.
FAKE_PYTHON3 = r"""#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
    echo "venv ${3}" >> "$VENV_CALLS"
    mkdir -p "${3}/bin"
    cat > "${3}/bin/python" <<'PYEOF'
#!/usr/bin/env bash
# A "working" venv python: report pip is present.
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then echo "pip 99.0 (stub)"; exit 0; fi
exit 0
PYEOF
    chmod +x "${3}/bin/python"
    cp "${3}/bin/python" "${3}/bin/pip"
    exit 0
fi
exit 0
"""

# A "working venv" python that already reports pip present (used to pre-seed a healthy .venv).
WORKING_VENV_PYTHON = r"""#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then echo "pip 99.0 (stub)"; exit 0; fi
exit 0
"""

# A "broken venv" python that errors on `-m pip` — the real-world failure (a .venv whose
# python resolves to a system interpreter with no pip module).
BROKEN_VENV_PYTHON = r"""#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then
    echo "No module named pip" >&2; exit 1
fi
exit 0
"""

# A `python3` whose `-m venv` builds a venv but WITHOUT a pip (the distro-ships-python3-venv-
# without-ensurepip case). Drives the guard's "created .venv but it has no pip" die path.
FAKE_PYTHON3_NO_PIP = r"""#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
    echo "venv ${3}" >> "$VENV_CALLS"
    mkdir -p "${3}/bin"
    cat > "${3}/bin/python" <<'PYEOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then echo "No module named pip" >&2; exit 1; fi
exit 0
PYEOF
    chmod +x "${3}/bin/python"
    exit 0
fi
exit 0
"""


def _run_ensure_venv(
    workdir: Path, python3_body: str = FAKE_PYTHON3
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Source setup.sh and run `ensure_venv` in `workdir` with a stubbed python3 on PATH.

    Returns the completed process plus the path to the file recording `python3 -m venv` calls
    (one line per invocation), so callers can assert whether (re)creation happened.
    """
    fakebin = workdir / "fakebin"
    fakebin.mkdir()
    py = fakebin / "python3"
    py.write_text(python3_body)
    py.chmod(0o755)

    venv_calls = workdir / "venv_calls.log"
    venv_calls.write_text("")

    env = {
        "PATH": f"{fakebin}:/usr/bin:/bin",
        "VENV_CALLS": str(venv_calls),
        # keep `say`/`die` output predictable & uncoloured-irrelevant; nothing else needed
    }
    proc = subprocess.run(
        ["bash", "-c", f'source "{SETUP_SH}"; ensure_venv', "--"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
    )
    return proc, venv_calls


def _seed_venv(workdir: Path, python_body: str) -> None:
    """Create a `.venv/bin/python` stub with the given behaviour (healthy or broken)."""
    binv = workdir / ".venv" / "bin"
    binv.mkdir(parents=True)
    py = binv / "python"
    py.write_text(python_body)
    py.chmod(0o755)


def test_creates_venv_when_absent(tmp_path: Path):
    """No .venv at all → ensure_venv builds one (exactly one `python3 -m venv`)."""
    proc, venv_calls = _run_ensure_venv(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / ".venv" / "bin" / "pip").exists()
    assert venv_calls.read_text().count("venv ") == 1


def test_rebuilds_partial_venv_without_pip(tmp_path: Path):
    """The reported bug: a leftover .venv whose python has no pip module is recreated,
    not skipped — and the result has a working pip."""
    _seed_venv(tmp_path, BROKEN_VENV_PYTHON)
    proc, venv_calls = _run_ensure_venv(tmp_path)
    assert proc.returncode == 0, proc.stderr
    # It rebuilt (one venv call) and the recreated venv now has pip.
    assert venv_calls.read_text().count("venv ") == 1
    assert (tmp_path / ".venv" / "bin" / "pip").exists()
    # The recreated python answers `-m pip` (i.e. it's the stub's healthy python, not the
    # broken seed we started with).
    check = subprocess.run(
        [str(tmp_path / ".venv" / "bin" / "python"), "-m", "pip", "--version"],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0


def test_rebuilds_directory_only_venv(tmp_path: Path):
    """An even-more-partial leftover (the .venv directory exists but bin/python doesn't)
    is also recreated rather than tripping the old `[ -d .venv ]` skip."""
    (tmp_path / ".venv").mkdir()
    proc, venv_calls = _run_ensure_venv(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert venv_calls.read_text().count("venv ") == 1
    assert (tmp_path / ".venv" / "bin" / "pip").exists()


def test_errors_clearly_when_created_venv_has_no_pip(tmp_path: Path):
    """If `python3 -m venv` succeeds but produces no pip (a distro shipping python3-venv
    without ensurepip), the guard must fail loudly with a fix hint rather than letting the
    next line die obscurely on `.venv/bin/pip install`."""
    proc, venv_calls = _run_ensure_venv(tmp_path, python3_body=FAKE_PYTHON3_NO_PIP)
    assert proc.returncode != 0  # die'd
    assert "no pip" in proc.stderr.lower()
    assert venv_calls.read_text().count("venv ") == 1  # it did attempt to build


def test_leaves_healthy_venv_untouched(tmp_path: Path):
    """A .venv that already has a working pip is left alone — no `python3 -m venv` call."""
    _seed_venv(tmp_path, WORKING_VENV_PYTHON)
    # Also drop a marker so we can prove the dir wasn't blown away and rebuilt.
    marker = tmp_path / ".venv" / "MARKER"
    marker.write_text("keep me")
    proc, venv_calls = _run_ensure_venv(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert venv_calls.read_text().strip() == ""  # never recreated
    assert marker.exists() and marker.read_text() == "keep me"


def test_sourcing_does_not_run_the_installer(tmp_path: Path):
    """Sourcing setup.sh must define its functions WITHOUT running main() — otherwise these
    tests (and any other consumer) would trigger a real pip/npm install.

    Sourced against a *copy* in tmp_path (so `dirname "${BASH_SOURCE[0]}"` is the tmp dir,
    not the real repo) with stubbed python3/npm that record their calls. We assert the
    functions are defined, the install banner never printed, and npm was never invoked."""
    script = tmp_path / "setup.sh"
    script.write_text(SETUP_SH.read_text())

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    npm_calls = tmp_path / "npm_calls.log"
    npm_calls.write_text("")
    for tool in ("python3", "npm"):
        stub = fakebin / tool
        # npm records invocations; both are otherwise harmless no-ops.
        stub.write_text(f'#!/usr/bin/env bash\necho "{tool} $*" >> "{npm_calls}"\nexit 0\n')
        stub.chmod(0o755)

    proc = subprocess.run(
        ["bash", "-c", f'source "{script}"; type ensure_venv >/dev/null && type main >/dev/null'],
        cwd=tmp_path,
        env={"PATH": f"{fakebin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr  # functions defined
    assert "Installing the hexgraph package" not in proc.stdout  # main() never ran
    assert npm_calls.read_text().strip() == ""  # main()'s npm build never fired

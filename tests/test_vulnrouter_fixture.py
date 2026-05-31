"""Lock in the vulnrouter fixture's planted bugs (offline — no container needed), so
the test target can't silently lose the vulnerabilities it exists to exercise."""

import importlib.util
import os

from conftest import fixture_path


def _load(monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-admin-token")
    monkeypatch.setenv("ROUTER_FLAG", "FLAG-TEST")
    spec = importlib.util.spec_from_file_location(
        "vulnrouter", os.path.join(fixture_path("vulnrouter"), "vulnrouter.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_auth_bypass_present(monkeypatch):
    vr = _load(monkeypatch)
    assert vr._check_token("") is True              # the bug: empty token authenticates
    assert vr._check_token("s3c") is True           # any prefix authenticates
    assert vr._check_token("wrong-token") is False  # a non-prefix is correctly rejected
    assert vr._check_token("s3cret-admin-token") is True  # the real token still works

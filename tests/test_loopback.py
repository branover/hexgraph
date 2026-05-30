"""The loopback bind guard refuses non-loopback by default (SPEC §1, §7)."""

import pytest

from hexgraph.api.loopback import OVERRIDE_ENV, assert_loopback, is_loopback


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.5.5.5"])
def test_loopback_hosts_allowed(host):
    assert is_loopback(host)
    assert_loopback(host)  # no raise


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "10.0.0.1", "example.com"])
def test_non_loopback_refused(host, monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    assert not is_loopback(host)
    with pytest.raises(RuntimeError):
        assert_loopback(host)


def test_override_allows_non_loopback(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, "1")
    assert_loopback("0.0.0.0")  # warns loudly but does not raise

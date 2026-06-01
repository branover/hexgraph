"""Operator-machine trust boundary on the loopback API (security review FINDING 1).

The loopback API has no auth by design, so two browser-facing defenses guard it:
  1) TrustedHostMiddleware — a foreign Host header (DNS-rebinding) is rejected; loopback passes.
  2) A same-origin guard — a state-changing /api/* request with `Sec-Fetch-Site: cross-site`
     is rejected; a same-origin one (the SPA) passes. GETs and non-browser clients are unaffected.

These guard exactly the policy-relaxing settings writes and the destructive DELETE endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.api.loopback import OVERRIDE_ENV, allowed_hosts


# ---------------- TrustedHost: DNS-rebinding defense ----------------

def test_foreign_host_rejected(hg_home):
    c = TestClient(create_app())
    # A DNS-rebinding page reaches 127.0.0.1 but carries the attacker's own Host header.
    r = c.get("/health", headers={"host": "evil.attacker.example"})
    assert r.status_code == 400  # TrustedHostMiddleware rejects before any handler


def test_loopback_host_passes(hg_home):
    c = TestClient(create_app())
    for host in ("127.0.0.1", "localhost", "127.0.0.1:8765"):
        r = c.get("/health", headers={"host": host})
        assert r.status_code == 200, host


def test_allowed_hosts_loopback_only_by_default(monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    hosts = allowed_hosts("127.0.0.1")
    assert "127.0.0.1" in hosts and "localhost" in hosts
    assert "*" not in hosts


def test_allowed_hosts_widens_on_deliberate_nonloopback_bind(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, "1")
    # Operator deliberately bound a non-loopback address → don't fight their choice.
    assert allowed_hosts("0.0.0.0") == ["*"]
    # ...but a loopback bind stays locked down even with the override present.
    assert "*" not in allowed_hosts("127.0.0.1")


# ---------------- Same-origin (CSRF) guard ----------------

def test_cross_site_mutation_rejected(hg_home):
    c = TestClient(create_app())
    # A cross-site page's browser fetch to a policy-relaxing settings write.
    r = c.patch("/api/settings", json={"features": {"poc": {"enabled": True}}},
                headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    assert "cross-site" in r.json()["detail"]


def test_cross_site_delete_rejected(hg_home):
    c = TestClient(create_app())
    r = c.delete("/api/projects/does-not-exist", headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403  # guarded BEFORE the handler (so 403, not 404)


def test_same_origin_mutation_passes(hg_home):
    """The served SPA's fetches are same-origin → must NOT be blocked."""
    from hexgraph import settings as st

    c = TestClient(create_app())
    r = c.patch("/api/settings", json={"features": {"poc": {"enabled": True}}},
                headers={"sec-fetch-site": "same-origin"})
    assert r.status_code == 200
    assert st.get("features.poc.enabled") is True  # the write actually landed


def test_no_sec_fetch_site_header_passes(hg_home):
    """Non-browser HTTP clients omit Sec-Fetch-Site → treated as non-browser, allowed."""
    c = TestClient(create_app())
    r = c.patch("/api/settings", json={"features": {"fuzzing": {"enabled": True}}})
    assert r.status_code == 200


def test_cross_site_get_is_allowed(hg_home):
    """Read/navigation (GET) is not a state change → never blocked by the guard."""
    c = TestClient(create_app())
    r = c.get("/api/settings", headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 200

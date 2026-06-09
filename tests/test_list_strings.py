"""list_strings greps the FULL string table, not the ~40-entry recon sample (dogfood F13/F15).

The bug: `re_list_strings`/`list_strings` filtered `target.metadata_json["strings"]`, which recon
populates with a tiny SAMPLE (~40 entries). A real string like `.cgi`, `%s`, `aes`, or `factory`
that lives in the binary but past the sample returned "(none)", misleading the analyst into "no
command templates here." Now the pattern grep is backed by the binutils probe's full `strings -a`
pass (recorded/cached as a binutils_facts Observation), with server-side filtering + pagination —
and a flagged fallback to the recon sample when the full pass is unavailable (non-ELF / no sandbox).

Offline + mock: the binutils strings pass needs the sandbox, so these monkeypatch
`collect_binutils_facts` to stand in for the probe — the unit under test is the grep/pagination/
fallback logic in `_list_strings`, not the sandboxed `strings` run itself.
"""

import hexgraph.engine.re.binutils as B
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


# The recon SAMPLE the target carries (tiny — the bug was filtering only this). The needle
# strings below are deliberately ABSENT from it.
_SAMPLE = ["/cgi-bin/admin", "token=secret", "Mitis Relay Agent"]


def _ctx(s, *, full_strings=None):
    """A target whose metadata carries only the small recon SAMPLE. When `full_strings` is
    given, the binutils strings pass is stubbed to return that full table (the probe stand-in)."""
    p = create_project(s, name="liststr")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123", "strings": list(_SAMPLE)}
    s.flush()
    ctx = ToolContext(session=s, project=p, target=t)
    return ctx, p, t


def _stub_binutils(monkeypatch, full_strings):
    """Stand in for the sandboxed binutils probe — return a full `strings` table offline."""
    def _fake(session, project, target, *, source="agent", runner=None):
        return {"facts": {"strings": list(full_strings)}, "observation_id": None,
                "cached": False, "reuse_hint": ""}
    monkeypatch.setattr(B, "collect_binutils_facts", _fake)


# --- F13: a pattern grep finds a string in the FULL table but NOT in the sample ----------

def test_pattern_finds_string_absent_from_recon_sample(hg_home, monkeypatch):
    """The whole point: `.cgi` is in the binary's full strings but NOT in the 40-entry sample.
    The old code returned "(none)"; the fix greps the full table and finds it."""
    full = [*_SAMPLE, "/www/factory_reset.cgi", "%s: aes-128-cbc", "AdminPassword"]
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _stub_binutils(monkeypatch, full)

        # The needle is provably NOT in the recon sample the old code searched.
        assert not any(".cgi" in x for x in _SAMPLE)

        out = run_tool(ctx, "list_strings", {"pattern": ".cgi"})
        assert "/www/factory_reset.cgi" in out
        assert "source=binutils" in out  # the result tells the analyst it grepped the full table
        # Other full-table-only needles also resolve.
        ctx.cache.clear()
        assert "aes-128-cbc" in run_tool(ctx, "list_strings", {"pattern": "aes"})
        ctx.cache.clear()
        assert "factory_reset" in run_tool(ctx, "list_strings", {"pattern": "factory"})

        # Still a pure QUERY: no graph mutation.
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        # And the page is recorded as a discoverable Observation scoped to the bytes.
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "strings").all()
        assert obs and obs[0].content_hash == "abc123"


def test_no_match_reports_zero_not_a_false_negative(hg_home, monkeypatch):
    """A genuinely-absent pattern reports 0 total — distinct from the old sample-miss."""
    _stub_binutils(monkeypatch, [*_SAMPLE, "/www/index.html"])
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "list_strings", {"pattern": "no_such_needle_xyz"})
        assert "(none)" in out and "0 total" in out


# --- F15: pagination over the full table, inline (no obs_get dance) ----------------------

def test_pagination_bounds_and_reports_next_offset(hg_home, monkeypatch):
    """A broad grep is bounded to a page and reports the total + the next offset to page on,
    rather than silently clipping (the no-silent-caps discipline)."""
    full = [f"match_{i:04d}" for i in range(500)]
    _stub_binutils(monkeypatch, full)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # Page 1: limit 10 of 500 matches.
        out = run_tool(ctx, "list_strings", {"pattern": "match_", "limit": 10})
        assert "500 total" in out
        assert "match_0000" in out and "match_0009" in out
        assert "match_0010" not in out                 # clipped to the page
        assert "490 more" in out and "offset=10" in out  # tells the agent how to page on

        # Page 2: offset picks up exactly where page 1 stopped.
        ctx.cache.clear()
        out2 = run_tool(ctx, "list_strings", {"pattern": "match_", "limit": 10, "offset": 10})
        assert "match_0010" in out2 and "match_0019" in out2
        assert "match_0009" not in out2


def test_limit_is_clamped_no_silent_flood(hg_home, monkeypatch):
    """An over-large limit clamps to the ceiling — a broad grep can't flood the context."""
    full = [f"needle{i:05d}" for i in range(3000)]
    _stub_binutils(monkeypatch, full)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "list_strings", {"pattern": "needle", "limit": 99999})
        # 3000 matches, but the page is clamped to the 1000 ceiling and says there's more.
        assert "3000 total" in out
        assert "showing 0-1000" in out          # limit clamped to the ceiling, not 99999
        assert "2000 more" in out and "offset=1000" in out


# --- fallback: the recon sample, FLAGGED, when the full pass is unavailable --------------

def test_falls_back_to_sample_when_binutils_unavailable(hg_home, monkeypatch):
    """When the binutils strings pass can't run (non-ELF, sandbox down), list_strings still
    answers over the recon sample — but FLAGS that the result is sample-only / may be incomplete,
    so a miss isn't mistaken for the full-table truth."""
    def _err(session, project, target, *, source="agent", runner=None):
        return {"error": "binutils facts unavailable (Docker/sandbox not running)"}
    monkeypatch.setattr(B, "collect_binutils_facts", _err)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "list_strings", {"pattern": "cgi"})
        assert "/cgi-bin/admin" in out          # the sample still answers
        assert "source=sample" in out           # ...flagged as the sample
        assert "may be incomplete" in out       # ...with the caveat

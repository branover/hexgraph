"""Agent-ergonomics: the body-returning tools truncate with an ACTIONABLE marker, and the
agent can raise the inline cap with `max_chars`.

The original `_clip` cut a body at 6000 chars and appended a bare `…[truncated]` — opaque and
lossy: a head-truncated decompile could hide a tail sink (e.g. `system()`) with no way to
recover it. Now a truncated body-returning tool (re_decompile_function/_at, re_disassemble,
re_search_decompiled) emits a marker naming BOTH recovery paths (re-call with a bigger
max_chars, or get_observation for the full body) plus the sizes, and `max_chars` lets the
agent pull the whole thing in one call. The full body is always in the Observation.

search_decompiled mines the recorded Observation store (no decompiler/Docker), so it drives
the truncation contract fully offline: record one fat decompilation, then grep it.
"""

from hexgraph.agent import mcp_tools as M
from hexgraph.engine import observations as O
from hexgraph.agent.agent_tools import (
    _MAX,
    _MAX_CEILING,
    _MAX_FLOOR,
    _clip_body,
    _effective_limit,
    ToolContext,
    run_tool,
)
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="trunc")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


def _record_decomp(ctx, name, pseudocode):
    O.record_observation(
        ctx.session, project_id=ctx.project.id, target_id=ctx.target.id, source="test",
        tool="decompile_function", args={"function": name}, result_kind="decompilation",
        payload={"focus": {"name": name, "pseudocode": pseudocode, "callees": []}},
        summary=f"decompiled {name}", content_hash="abc123")


# A long shared token present in every recorded body; querying it makes each hit's snippet
# (~the matched token + 120 chars of context) long, so a handful of hits blow past _MAX.
NEEDLE = "ATTACKER_CONTROLLED_" * 12  # ~240 chars


def _record_many_matching(ctx, n):
    """Record `n` distinct decompiled functions, each whose body contains the long NEEDLE —
    so the rendered hit list (one long snippet line per function) comfortably exceeds _MAX."""
    for i in range(n):
        _record_decomp(ctx, f"fn_{i:03d}",
                       f"void fn_{i:03d}() {{ char b[64]; copy(b, {NEEDLE}); }}")


# --- the clamp (pure) --------------------------------------------------------------------

def test_effective_limit_default_and_clamp():
    assert _effective_limit(None) == _MAX            # default unchanged (6000)
    assert _effective_limit(50) == _MAX_FLOOR        # below the floor → floor
    assert _effective_limit(10 ** 9) == _MAX_CEILING  # fat-finger backstop → ceiling
    assert _effective_limit(8000) == 8000            # an honest request passes through
    assert _effective_limit("nope") == _MAX          # a bad value falls back to the default


# --- the marker (pure) -------------------------------------------------------------------

def test_clip_body_marker_is_actionable_with_sizes_and_obs_id():
    body = "X" * 14213
    out = _clip_body(body, limit=6000, obs_id="obs-42")
    head, marker = out[:6000], out[6000:]
    assert head == "X" * 6000                         # the head is intact, exactly `limit`
    assert "[truncated 6000/14213 chars" in marker    # both sizes present
    assert "max_chars≥14213" in marker                # the re-call knob to get the whole body
    assert "get_observation/obs_get('obs-42')" in marker      # both tool names (in-process + MCP)      # the full-data channel, with the id
    assert "…[truncated]" not in out                  # the bare opaque marker is gone


def test_clip_body_no_marker_when_under_limit():
    body = "small body"
    assert _clip_body(body, limit=6000, obs_id="obs-42") == body  # full body, no marker


def test_clip_body_marker_drops_obs_path_when_no_id():
    out = _clip_body("Y" * 100, limit=10, obs_id=None)
    assert "max_chars≥100" in out          # the re-call knob is still named
    assert "get_observation" not in out    # but no obs path when there's no id to give


# --- end-to-end via search_decompiled (offline; no decompiler/Docker) --------------------

def test_search_decompiled_truncates_with_actionable_marker(hg_home):
    """A hit list over the default cap → truncated WITH the actionable marker (obs id +
    both sizes), never a head-truncation that silently drops the tail."""
    from hexgraph.db.session import session_scope
    with session_scope() as s:
        ctx, _p, t = _ctx(s)
        # Many matching functions → a hit list (one snippet line each) past the 6000 cap.
        _record_many_matching(ctx, 60)
        s.flush()

        out = run_tool(ctx, "search_decompiled", {"query": NEEDLE})
        assert len(out) > _MAX
        marker = out[_MAX:]
        assert "[truncated" in marker and "chars" in marker
        # the marker names BOTH recovery paths
        assert "max_chars≥" in marker
        assert "get_observation/obs_get('" in marker
        # and the obs id it points at is the search_decompiled Observation just recorded
        from hexgraph.db.models import Observation
        obs = s.query(Observation).filter(
            Observation.target_id == t.id,
            Observation.result_kind == "search_decompiled").one()
        assert obs.id in marker


def test_search_decompiled_max_chars_n_returns_about_n(hg_home):
    """max_chars=N (N < body) → exactly N chars of body + the marker."""
    from hexgraph.db.session import session_scope
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        _record_many_matching(ctx, 60)
        s.flush()

        out = run_tool(ctx, "search_decompiled", {"query": NEEDLE, "max_chars": 1000})
        body, marker = out[:1000], out[1000:]
        assert len(body) == 1000                  # exactly the requested window of body
        assert "[truncated 1000/" in marker       # marker reports the limit it applied
        assert "get_observation/obs_get('" in marker


def test_search_decompiled_max_chars_over_body_returns_full_no_marker(hg_home):
    """max_chars ≥ body length → the full body, no truncation marker."""
    from hexgraph.db.session import session_scope
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        _record_decomp(ctx, "small", "a small body with the needle in it")
        s.flush()

        # default cap (6000) already exceeds this tiny body — full result, no marker …
        default = run_tool(ctx, "search_decompiled", {"query": "needle"})
        assert "[truncated" not in default
        # … and an explicit big max_chars is equivalent (still no marker)
        big = run_tool(ctx, "search_decompiled", {"query": "needle", "max_chars": _MAX_CEILING})
        assert "[truncated" not in big
        assert big == default                     # max_chars over the body length is a no-op


def test_search_decompiled_default_cap_is_6000(hg_home):
    """The DEFAULT (no max_chars) still caps the inlined body at _MAX (6000) — context
    stays bounded — and the marker begins exactly at the cap."""
    from hexgraph.db.session import session_scope
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        _record_many_matching(ctx, 60)
        s.flush()

        out = run_tool(ctx, "search_decompiled", {"query": NEEDLE})
        assert out.index("\n…[truncated") == _MAX  # the marker begins right at the cap


# --- the advertised surface (catalog + in-process specs) ---------------------------------

_BODY_TOOLS_MCP = ["re_decompile_function", "re_decompile_at",
                   "re_disassemble", "re_search_decompiled"]


def test_catalog_advertises_max_chars_on_body_tools(hg_home):
    by_name = {s["name"]: s["schema"]["properties"] for s in M.catalog()}
    for t in _BODY_TOOLS_MCP:
        prop = by_name[t].get("max_chars")
        assert prop is not None, f"{t} missing max_chars"
        assert prop.get("type") == "integer"
        # the one-line description points at the full-payload escape hatch
        assert "get_observation" in prop.get("description", "")


def test_inprocess_specs_advertise_max_chars(hg_home):
    """The mock fixtures call the agent-loop tools by their bare names; those specs carry
    max_chars too, so a BYOK model can ask for a bigger body on a single pass."""
    from hexgraph.agent.agent_tools import _STATIC_SPECS
    by_name = {s.name: s.input_schema for s in _STATIC_SPECS}
    for name in ("decompile_function", "decompile_at", "disassemble", "search_decompiled"):
        props = by_name[name].get("properties", {})
        assert "max_chars" in props, f"{name} spec missing max_chars"
        assert props["max_chars"]["type"] == "integer"

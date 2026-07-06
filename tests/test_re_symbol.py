"""re_symbol resolves/searches the symbol table by name -> {name,address,type,bind,defined,section}.

The name->address hop that turns a symbol into a re_decompile_at/re_xrefs target. Server-side over
the binutils facts.symbols list (nm rows: {name, type(letter), address}); coarse type/bind are
derived from the nm type-LETTER (precise ELF bind/type/section are deferred to an additive readelf
probe field). Filtered by substring/regex with offset/limit pagination, mirroring list_strings —
records a symbol_resolve Observation, mutates no graph. A substring query is prefix-agnostic, so a
bare name (strcpy) ALSO surfaces vendor-wrapped/aliased forms (a *_strcpy copy).

Offline + mock: facts.symbols comes from the sandboxed binutils probe, so these monkeypatch
`collect_binutils_facts` to stand in for it (like test_list_strings) — the unit under test is the
filter/classify/pagination in `_resolve_symbol`, not the sandboxed nm run.
"""

import hexgraph.engine.re.binutils as B
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


# A synthetic nm symbol table mixing UND imports, defined funcs/data, a weak sym, and a
# vendor-wrapped libc copy. `type` is the nm type-LETTER the probe records.
_SYMBOLS = [
    {"name": "strcpy", "type": "U", "address": None},          # undefined import
    {"name": "printf", "type": "U", "address": None},          # undefined import
    {"name": "parse", "type": "T", "address": "0x1139"},       # defined FUNC (global)
    {"name": "config_table", "type": "D", "address": "0x4020"},  # defined OBJECT (global data)
    {"name": "helper_local", "type": "t", "address": "0x1200"},  # defined FUNC (local)
    {"name": "os_strcpy", "type": "T", "address": "0x1500"},  # vendor-wrapped libc copy (defined)
    {"name": "maybe_weak", "type": "w", "address": None},       # weak undefined
]


def _ctx(s):
    p = create_project(s, name="resym")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "sym123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


def _stub_facts(monkeypatch, symbols):
    """Stand in for the sandboxed binutils probe — return a facts dict with a fixed symbol table."""
    def _fake(session, project, target, *, source="agent", runner=None):
        return {"facts": {"symbols": list(symbols)}, "observation_id": None,
                "cached": False, "reuse_hint": ""}
    monkeypatch.setattr(B, "collect_binutils_facts", _fake)


# --- resolve a defined function: address + defined + bind ---------------------------------

def test_defined_func_resolves_with_address_and_bind(hg_home, monkeypatch):
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"pattern": "parse"})
        assert "parse" in out
        assert "0x1139" in out            # its address
        assert "FUNC" in out              # coarse type from nm 'T'
        assert "GLOBAL" in out            # upper-case nm letter => global
        assert "defined" in out
        assert "1 total" in out


# --- substring search: a bare name ALSO surfaces a vendor-wrapped form --------------------

def test_bare_name_also_surfaces_wrapped_form(hg_home, monkeypatch):
    """`strcpy` matches BOTH the UND strcpy import AND the defined os_strcpy wrapper (a
    vendor-wrapped libc copy). The bare-name substring query surfaces the wrapped form too."""
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"pattern": "strcpy"})
        assert "os_strcpy" in out       # the wrapped form (substring match)
        # the plain UND import is present too, flagged UND (not defined)
        assert "UND" in out
        assert "2 total" in out


# --- kind scopes the table ---------------------------------------------------------------

def test_kind_imports_returns_only_undefined(hg_home, monkeypatch):
    """kind='imports' returns only UND rows (strcpy/printf/maybe_weak), never the defined syms."""
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"kind": "imports"})
        assert "strcpy" in out and "printf" in out
        assert "parse" not in out and "config_table" not in out
        # all rows are UND
        assert "defined" not in out


def test_kind_exports_returns_only_defined(hg_home, monkeypatch):
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"kind": "exports"})
        assert "parse" in out and "config_table" in out
        assert "printf" not in out        # UND import excluded


def test_bad_kind_is_reported(hg_home, monkeypatch):
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"kind": "bogus"})
        assert "error" in out.lower() and "kind" in out


# --- pagination identical to strings -----------------------------------------------------

def test_pagination_bounds_and_clamps(hg_home, monkeypatch):
    """A broad match is bounded to a page; an over-large limit clamps to the 1000 ceiling."""
    big = [{"name": f"sym_{i:05d}", "type": "T", "address": f"0x{i:x}"} for i in range(2500)]
    _stub_facts(monkeypatch, big)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"pattern": "sym_", "limit": 10})
        assert "2500 total" in out
        assert "sym_00000" in out and "sym_00009" in out
        assert "sym_00010" not in out
        assert "2490 more" in out and "offset=10" in out

        ctx.cache.clear()
        out2 = run_tool(ctx, "resolve_symbol", {"pattern": "sym_", "limit": 99999})
        assert "showing 0-1000" in out2
        assert "1500 more" in out2 and "offset=1000" in out2


def test_empty_pattern_lists_the_table_paged(hg_home, monkeypatch):
    """No pattern lists the whole table, paged (7 synthetic rows fit in one default page)."""
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {})
        assert "7 total" in out
        assert "parse" in out and "strcpy" in out


# --- the nm 4000-symbol cap is flagged (a miss isn't read as authoritative) ---------------

def test_symbol_cap_is_flagged(hg_home, monkeypatch):
    """When facts.symbols hit the nm cap (_NM_SYMBOL_CAP), the result flags the table CAPPED so a
    miss on a huge binary isn't mistaken for the full truth (the no-silent-caps discipline)."""
    import hexgraph.agent.agent_tools as AT
    capped = [{"name": f"s{i:05d}", "type": "T", "address": "0x1"} for i in range(AT._NM_SYMBOL_CAP)]
    _stub_facts(monkeypatch, capped)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"pattern": "s0000"})
        assert "CAPPED" in out


# --- QUERY contract: an Observation recorded, zero graph mutation ------------------------

def test_records_observation_and_no_graph(hg_home, monkeypatch):
    _stub_facts(monkeypatch, _SYMBOLS)
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "resolve_symbol", {"pattern": "parse"})
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "symbol_resolve").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "sym123"


def test_error_when_facts_unavailable(hg_home, monkeypatch):
    """When the binutils pass can't run (sandbox down / non-ELF), resolve_symbol surfaces the
    clean error rather than crashing."""
    def _err(session, project, target, *, source="agent", runner=None):
        return {"error": "binutils facts unavailable (Docker/sandbox not running)"}
    monkeypatch.setattr(B, "collect_binutils_facts", _err)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_symbol", {"pattern": "strcpy"})
        assert "unavailable" in out

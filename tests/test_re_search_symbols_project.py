"""search_symbols_project — the NAME analogue of yara_sweep (project-wide symbol/function search).

Cross-target, engine-level: iterate every non-archived target and test a NAME pattern against its
symbol/function set — reading ALREADY-stored substrate (recon metadata imports/exports + prior
binutils_facts / function_list Observations), NEVER running a probe or a per-target decompile. So
it locates WHICH binary in a firmware defines/imports a shared helper (e.g. os_strcpy) without a
heavy sweep. The feasibility caveat it must be honest about: a target whose symbols were never
collected can't be searched — it's reported in `targets_without_symbols` (not counted as a clean
miss), so the operator knows to re_binutils_facts it first.

Offline + mock: no probe is run — the test seeds each target's symbol source directly (recon
metadata and/or a recorded binutils_facts Observation), which is exactly what the helper reads.
Mirrors test_yara.py's sweep-test structure (a project with a few fixture targets).
"""

from hexgraph.db.models import Edge, Node
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.re.binutils import RESULT_KIND, search_symbols_project
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _seed_facts(s, project, target, *, imports=None, exports=None, symbols=None):
    """Record a binutils_facts Observation carrying a symbol set — the authoritative source the
    helper prefers (stands in for a prior re_binutils_facts run, no probe needed here)."""
    facts = {"imports": list(imports or []), "exports": list(exports or []),
             "symbols": list(symbols or [])}
    O.record_observation(s, project_id=project.id, target_id=target.id, source="agent",
                         tool="binutils_facts", args={}, result_kind=RESULT_KIND,
                         payload=facts, summary="seeded", content_hash=O.content_hash_for(target))


def _project_with_targets(s):
    """A project with three targets carrying DISTINCT symbol sets:
      httpd  — defines parse_http (an export)   [via binutils_facts obs]
      libc   — imports strcpy                    [via binutils_facts obs]
      wrap   — DEFINES os_strcpy (a vendor-wrapped libc copy) [via binutils_facts obs]
    """
    p = create_project(s, name="symsearch")
    httpd = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    httpd.metadata_json = {**(httpd.metadata_json or {}), "sha256": "httpd1"}
    libc = ingest_file(s, p, fixture_path("libupnp.so"), name="libc")
    libc.metadata_json = {**(libc.metadata_json or {}), "sha256": "libc1"}
    wrap = ingest_file(s, p, fixture_path("libupnp.so"), name="wrap")
    wrap.metadata_json = {**(wrap.metadata_json or {}), "sha256": "wrap1"}
    s.flush()
    _seed_facts(s, p, httpd, exports=["parse_http", "main"], imports=["malloc"])
    _seed_facts(s, p, libc, imports=["strcpy", "memcpy"], exports=["upnp_init"])
    _seed_facts(s, p, wrap, exports=["os_strcpy"], imports=["read"])
    s.flush()
    return p, httpd, libc, wrap


# --- the core: a pattern locates which target(s) define/import it -------------------------

def test_pattern_returns_importer_and_wrapped_definer(hg_home):
    """`strcpy` returns BOTH the target that IMPORTS it (libc) and the one that DEFINES the
    vendor-wrapped copy os_strcpy (wrap), with the correct kind for each — the shared-helper locator."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        res = search_symbols_project(s, p, pattern="strcpy")
        by_tid = {(m["target_id"], m["kind"]): m for m in res["matches"]}
        # libc imports strcpy
        assert (libc.id, "import") in by_tid
        assert by_tid[(libc.id, "import")]["name"] == "strcpy"
        # wrap DEFINES os_strcpy (a substring hit on 'strcpy'), reported as an export
        assert (wrap.id, "export") in by_tid
        assert by_tid[(wrap.id, "export")]["name"] == "os_strcpy"
        # httpd (no strcpy anywhere) is NOT a match
        assert not any(m["target_id"] == httpd.id for m in res["matches"])
        assert res["hits"] == len(res["matches"]) >= 2
        assert res["scanned"] == 3


def test_regex_matches(hg_home):
    """A regex anchors the search — `^parse_` hits parse_http (httpd) and nothing else."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        res = search_symbols_project(s, p, pattern=r"^parse_.*", regex=True)
        assert [m["target_id"] for m in res["matches"]] == [httpd.id]
        assert res["matches"][0]["name"] == "parse_http"


def test_kind_scopes_to_imports(hg_home):
    """kind='imports' searches ONLY the import side — `strcpy` then matches the importer (libc)
    but NOT the wrap target that merely DEFINES os_strcpy."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        res = search_symbols_project(s, p, pattern="strcpy", kind="imports")
        tids = {m["target_id"] for m in res["matches"]}
        assert libc.id in tids
        assert wrap.id not in tids            # the definer is scoped out by kind=imports
        assert all(m["kind"] == "import" for m in res["matches"])


def test_kind_defined_scopes_to_exports(hg_home):
    """kind='defined' (==exports) finds the os_strcpy DEFINER (wrap) but not the importer."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        res = search_symbols_project(s, p, pattern="strcpy", kind="defined")
        tids = {m["target_id"] for m in res["matches"]}
        assert wrap.id in tids and libc.id not in tids


# --- the honesty gate: a target with NO symbol source is reported, not a silent clean miss ---

def test_target_without_symbols_is_reported(hg_home):
    """A target with no recon imports/exports AND no binutils_facts obs can't be searched — it's
    counted in targets_without_symbols (so a miss on it isn't read as authoritative), not scanned."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        # A fourth target with NO symbol source at all.
        bare = ingest_file(s, p, fixture_path("vuln_httpd"), name="bare")
        bare.metadata_json = {"sha256": "bare1"}  # no imports/exports, no facts obs
        s.flush()
        res = search_symbols_project(s, p, pattern="strcpy")
        without = {t["target_id"] for t in res["targets_without_symbols"]}
        assert bare.id in without
        assert res["scanned"] == 3               # the three seeded targets, not the bare one


# --- recon-metadata fallback: a target with imports only in metadata (no facts obs) is searched ---

def test_recon_metadata_fallback_is_searched(hg_home):
    """When a target has NO binutils_facts obs but DOES carry recon metadata imports/exports, the
    helper falls back to those (the cheap source) rather than skipping it."""
    with session_scope() as s:
        p = create_project(s, name="metafallback")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="meta_only")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "meta1",
                           "imports": ["system", "strcpy"], "exports": ["cgi_main"]}
        s.flush()  # NO facts obs recorded
        res = search_symbols_project(s, p, pattern="system")
        assert [m["target_id"] for m in res["matches"]] == [t.id]
        assert res["matches"][0]["kind"] == "import"
        assert res["targets_without_symbols"] == []   # metadata IS a source


# --- hidden firmware children are included (like yara_sweep) ------------------------------

def test_hidden_firmware_children_included(hg_home):
    """A HIDDEN firmware child (visible=False) is still searched — the helper scans all non-
    archived targets exactly like yara_sweep, so a match in an un-revealed child isn't missed."""
    with session_scope() as s:
        p = create_project(s, name="fwchildren")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.metadata_json = {**(fw.metadata_json or {}), "sha256": "fw1"}
        child = ingest_file(s, p, fixture_path("libupnp.so"), name="hidden_child")
        child.metadata_json = {**(child.metadata_json or {}), "sha256": "child1"}
        child.parent_id = fw.id
        child.visible = False                     # a hidden firmware child
        s.flush()
        _seed_facts(s, p, child, exports=["os_sprintf"])
        s.flush()
        res = search_symbols_project(s, p, pattern="sprintf")
        assert child.id in {m["target_id"] for m in res["matches"]}


# --- a clean miss is scanned>0 + empty matches, NOT an error -----------------------------

def test_no_hits_is_not_an_error(hg_home):
    """A genuinely-absent pattern returns scanned>0 with empty matches (a real 'searched, found
    nothing' answer) — distinct from an error and from the can't-search targets_without_symbols."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        res = search_symbols_project(s, p, pattern="no_such_symbol_xyz")
        assert "error" not in res
        assert res["scanned"] == 3 and res["matches"] == []
        assert res["hits"] == 0


def test_limit_caps_matches_no_silent_flood(hg_home):
    """A broad pattern is bounded by `limit` and flags `capped` — a project-wide name search can't
    flood the context (the no-silent-caps discipline, matching the single-target greps)."""
    with session_scope() as s:
        p = create_project(s, name="capped")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="many")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "cap1"}
        s.flush()
        _seed_facts(s, p, t, imports=[f"a_import_{i}" for i in range(20)])
        s.flush()
        res = search_symbols_project(s, p, pattern="a_import_", limit=5)
        assert res["hits"] == 5 and res["capped"] is True
        assert len(res["matches"]) == 5


def test_empty_pattern_is_an_error(hg_home):
    """A blank pattern is a caller error (not a whole-table dump)."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        assert "error" in search_symbols_project(s, p, pattern="")
        assert "error" in search_symbols_project(s, p, pattern="   ")


# --- QUERY contract: reads the substrate, mutates NO graph -------------------------------

def test_no_graph_mutation(hg_home):
    """Pure read over already-stored facts — no nodes, no edges created (like yara_sweep's
    Observation roll-up, this helper adds nothing to the curated graph)."""
    with session_scope() as s:
        p, httpd, libc, wrap = _project_with_targets(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        search_symbols_project(s, p, pattern="strcpy")
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb


# --- symbols carried as nm rows (name/type) are folded in --------------------------------

def test_symbols_rows_are_searched_by_role(hg_home):
    """facts.symbols nm rows are folded into the search: a DEFINED row (type T) is searchable as
    an export even when it's not in the `exports` list; an UND row (type U) as an import."""
    with session_scope() as s:
        p = create_project(s, name="nmrows")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="nm")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "nm1"}
        s.flush()
        _seed_facts(s, p, t, symbols=[
            {"name": "local_helper", "type": "T", "address": "0x1000"},   # defined -> export
            {"name": "imported_fn", "type": "U", "address": None},         # undefined -> import
        ])
        s.flush()
        exp = search_symbols_project(s, p, pattern="local_helper", kind="defined")
        assert [m["target_id"] for m in exp["matches"]] == [t.id]
        imp = search_symbols_project(s, p, pattern="imported_fn", kind="imports")
        assert imp["matches"] and imp["matches"][0]["kind"] == "import"


# --- the wrapper (mcp_tools) resolves the project + delegates ----------------------------

def test_wrapper_reports_project_not_found(hg_home):
    from hexgraph.agent.mcp_tools import search_symbols_project as wrapper

    assert wrapper("does-not-exist", "strcpy") == {"error": "project not found"}

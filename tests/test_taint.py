"""Phase 4 — grounded P-Code data-flow taint (engine.taint + the ghidra_probe --taint pass).

Offline tests (no Docker) pin the seam selection, the graceful-degrade contract, and the
grounded graph promotion with a faked analyzer. The Docker+Ghidra integration test
(WITH_GHIDRA lane) proves the real HighFunction P-Code pass finds a command-injection flow
(stdin/param → popen) on the netcfgd fixture and promotes it into the graph.
"""

import shutil
import subprocess
import tempfile

import pytest

from hexgraph.db.models import Edge, Node
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as obs
from hexgraph.engine import taint as T
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph import settings as st

from conftest import SANDBOX_READY, fixture_path


# ── offline: the TAINT_SCRIPT must compile (Jython 2.7 runs it; a syntax/encoding error
#    writes NO output and is undiagnosable) ────────────────────────────────────────────

def test_taint_script_is_jython_safe():
    from hexgraph.sandbox.probes import ghidra_probe as GP

    src = GP.TAINT_SCRIPT
    first_line = src.lstrip("\n").splitlines()[0]
    has_cookie = "coding" in first_line and ("utf-8" in first_line.lower() or "latin" in first_line.lower())
    is_ascii = all(ord(c) < 128 for c in src)
    assert has_cookie or is_ascii, "TAINT_SCRIPT is non-ASCII without an encoding cookie"
    # Catches the gross syntax errors Python 3 and Jython 2.7 share (a broken edit here would
    # otherwise only surface as a silent no-output failure inside Ghidra).
    compile(src, "<taint_script>", "exec")


# ── offline: the seam selects by Settings, degrades gracefully ───────────────────────

def test_get_taint_analyzer_selects_by_settings(hg_home):
    # Ghidra off → Null (unavailable); the deterministic core emits no taint, fabricates none.
    assert isinstance(T.get_taint_analyzer(), T.NullTaintAnalyzer)
    assert T.get_taint_analyzer().available is False
    # Ghidra headless on → the grounded P-Code analyzer.
    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    a = T.get_taint_analyzer()
    assert isinstance(a, T.GhidraTaintAnalyzer) and a.available is True
    # Bridge mode is not the headless taint backend → degrade to Null.
    st.update_settings({"features.ghidra.mode": "bridge"})
    assert isinstance(T.get_taint_analyzer(), T.NullTaintAnalyzer)


def test_null_analyzer_emits_nothing():
    out = T.NullTaintAnalyzer().analyze("/whatever")
    assert out == {"available": False, "flows": [], "analyzed": 0, "error": None}


# ── offline: analyze_taint promotes ONLY the grounded few nodes/edges on each flow ───

_FAKE_FLOWS = [
    {"function": "run_probe", "function_addr": "0x1014a4",
     "source": {"kind": "param", "detail": "host"},
     "sink": {"func": "popen", "category": "command_exec",
              "call_addr": "0x10158b", "arg_index": 1},
     "sanitized": ["sanitize"]},
    {"function": "register_license", "function_addr": "0x101252",
     "source": {"kind": "param", "detail": "key"},
     "sink": {"func": "strcpy", "category": "buffer_overflow",
              "call_addr": "0x1012b8", "arg_index": 2},
     "sanitized": []},
]


class _FakeAnalyzer(T.TaintAnalyzer):
    name = "fake"
    available = True

    def __init__(self, flows):
        self._flows = flows

    def analyze(self, artifact, *, project=None):
        return {"available": True, "flows": self._flows, "analyzed": 2, "error": None}


def test_analyze_taint_records_observation_and_promotes_graph(hg_home):
    with session_scope() as s:
        p = create_project(s, name="taint")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = T.analyze_taint(s, p, t, analyzer=_FakeAnalyzer(_FAKE_FLOWS))

        assert out["available"] is True
        assert out["promoted"] == {"functions": 2, "sinks": 2, "edges": 2}

        # The full flow list is in the substrate as a `taint` Observation (not bulk nodes).
        recorded = obs.list_observations(s, t.id, kind="taint")
        assert len(recorded) == 1
        assert "2 flow(s)" in recorded[0]["summary"] and "1 command-exec" in recorded[0]["summary"]

        # Exactly the grounded sink + function nodes were promoted.
        sinks = s.query(Node).filter_by(project_id=p.id, node_type="sink").all()
        assert {n.name for n in sinks} == {"popen@0x10158b", "strcpy@0x1012b8"}
        assert all(n.attrs_json.get("is_sink") is True for n in sinks)
        funcs = s.query(Node).filter_by(project_id=p.id, node_type="function").all()
        assert {"run_probe", "register_license"} <= {n.name for n in funcs}

        # A grounded `taints` edge per flow, carrying the source + category + sanitizer note.
        edges = s.query(Edge).filter(Edge.project_id == p.id, Edge.type == "taints").all()
        assert len(edges) == 2
        by_cat = {e.attrs_json.get("category"): e for e in edges}
        assert by_cat["command_exec"].attrs_json["source"] == "param host"
        assert by_cat["command_exec"].attrs_json["sanitized"] == "sanitize"
        assert by_cat["command_exec"].attrs_json["via_param"] == "1"
        assert by_cat["buffer_overflow"].attrs_json["sanitized"] == "none"


def test_analyze_taint_unavailable_promotes_nothing(hg_home):
    with session_scope() as s:
        p = create_project(s, name="t2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = T.analyze_taint(s, p, t, analyzer=T.NullTaintAnalyzer())
        assert out["available"] is False
        assert out["promoted"] == {"functions": 0, "sinks": 0, "edges": 0}
        assert s.query(Edge).filter(Edge.project_id == p.id, Edge.type == "taints").count() == 0
        assert obs.list_observations(s, t.id, kind="taint") == []


# ── Docker + Ghidra: the REAL P-Code pass finds the command-injection flow ────────────

def _ghidra_in_image() -> bool:
    """Whether the sandbox image actually carries Ghidra (only the WITH_GHIDRA lane builds it)."""
    if not SANDBOX_READY:
        return False
    try:
        from hexgraph.sandbox.runner import SandboxRunner

        chk = SandboxRunner().run_json_probe(
            "ghidra_probe.py", fixture_path("vuln_httpd"), extra_args=["--check"])
        return bool(chk.get("present"))
    except Exception:
        return False


GHIDRA_READY = _ghidra_in_image()


@pytest.mark.skipif(not GHIDRA_READY,
                    reason="requires Docker + a WITH_GHIDRA=1 sandbox image")
def test_ghidra_taint_finds_command_injection_on_netcfgd(hg_home):
    if shutil.which("gcc") is None:
        pytest.skip("gcc unavailable to compile the netcfgd fixture")
    src = fixture_path("challenges/netcfgd.c")
    binpath = tempfile.mktemp(prefix="netcfgd-")
    rc = subprocess.run(["gcc", "-O0", "-g", "-o", binpath, src], capture_output=True)
    if rc.returncode != 0:
        pytest.skip("could not compile netcfgd: %s" % rc.stderr.decode()[:200])

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    with session_scope() as s:
        p = create_project(s, name="nc")
        t = ingest_file(s, p, binpath, name="netcfgd")
        out = T.analyze_taint(s, p, t, analyzer=T.GhidraTaintAnalyzer())

        assert out["available"] is True, out
        # The grounded claim: in run_probe, a parameter reaches popen (command injection),
        # and the incomplete sanitize() on the path is recorded (never assumed sufficient).
        cmd_flows = [f for f in out["flows"]
                     if (f.get("sink") or {}).get("category") == "command_exec"]
        assert cmd_flows, "no command-exec taint flow found: %s" % out["flows"]
        f = cmd_flows[0]
        assert f["sink"]["func"] == "popen"
        assert f["function"] == "run_probe"
        assert "sanitize" in f.get("sanitized", [])

        # And it was promoted into the graph (a popen sink node + a taints edge).
        sinks = s.query(Node).filter_by(project_id=p.id, node_type="sink").all()
        assert any(n.attrs_json.get("sink_func") == "popen" for n in sinks)
        assert s.query(Edge).filter(Edge.project_id == p.id, Edge.type == "taints").count() >= 1

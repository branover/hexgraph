"""Node identity + lazy-materialization invariants.

The address-fill case guards a real regression: recon materializes function nodes
with address=None, so a later decompile/author supplying an address must fill it
in (not silently drop it) while never overwriting a known address.
"""

from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node, materialize_function

from conftest import fixture_path


def test_address_fills_when_missing_and_never_overwrites(hg_home):
    with session_scope() as s:
        p = create_project(s, name="addr")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")

        # Recon-style materialization: no address yet.
        n1 = materialize_function(s, project_id=p.id, target_id=t.id, name="cgi_handler")
        assert n1.address is None

        # A later author/decompile supplies the address → it fills the SAME node.
        n2 = get_or_create_node(
            s, project_id=p.id, node_type="function", name="cgi_handler",
            target_id=t.id, address="0x401422", created_by="human",
        )
        assert n2.id == n1.id
        assert n2.address == "0x401422"

        # A known address is never overwritten by a later (different) one.
        n3 = get_or_create_node(
            s, project_id=p.id, node_type="function", name="cgi_handler",
            target_id=t.id, address="0xdeadbeef", created_by="agent",
        )
        assert n3.id == n1.id
        assert n3.address == "0x401422"


def test_attrs_union_on_existing_node(hg_home):
    with session_scope() as s:
        p = create_project(s, name="attrs")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        n1 = materialize_function(s, project_id=p.id, target_id=t.id, name="run_probe",
                                  attrs={"summary": "runs a shell probe"})
        n2 = get_or_create_node(
            s, project_id=p.id, node_type="function", name="run_probe", target_id=t.id,
            attrs={"params": [{"name": "host", "note": "attacker-controlled"}]},
            created_by="agent",
        )
        assert n2.id == n1.id
        assert n2.attrs_json["summary"] == "runs a shell probe"
        assert n2.attrs_json["params"][0]["name"] == "host"

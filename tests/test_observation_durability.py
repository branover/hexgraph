"""F11-1b — the Observation durability contract.

An Observation is RAW, reusable tool output (a decompile/strings/xref/taint/yara result that
already succeeded). It MUST survive a later failure of the task that produced it — the whole
point of "analyze once, reuse forever". `record_observation(durable=True, the default)`
checkpoints (commits) it immediately so a later rollback of the long task transaction can't
wipe it; `durable=False` keeps the legacy share-the-caller's-transaction behavior.

This directly guards the F11-1b change (and the class of regression an indirect test missed —
the denied-egress audit that a worker rollback was silently discarding).
"""

from hexgraph.db.models import Observation
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _record(s, pid, tid, *, durable):
    obs, _ = O.record_observation(
        s, project_id=pid, target_id=tid, source="task", tool="list_functions", args={},
        result_kind="function_list", payload={"functions": ["main"]},
        summary="recon", content_hash="deadbeef", durable=durable)
    return obs.id


def test_durable_observation_survives_a_later_task_rollback(hg_home):
    """durable=True checkpoints the Observation, so a later failure of the long task
    transaction (simulated by an explicit rollback after recording) can NOT wipe it."""
    with session_scope() as s:
        p = create_project(s, name="dur")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id
        oid = _record(s, pid, tid, durable=True)
        # The task hits a lock/error at a LATER step → the long transaction rolls back.
        s.rollback()
    with session_scope() as s2:
        assert s2.get(Observation, oid) is not None, \
            "a durable Observation must survive a later rollback (checkpointed)"


def test_non_durable_observation_rolls_back_with_the_caller(hg_home):
    """durable=False shares the caller's transaction lifetime — a rollback wipes the row."""
    with session_scope() as s:
        p = create_project(s, name="nondur")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id
        s.commit()  # make the project + target durable so only the observation is at risk
        oid = _record(s, pid, tid, durable=False)
        s.rollback()
    with session_scope() as s2:
        assert s2.get(Observation, oid) is None, \
            "a non-durable Observation should roll back with the caller's transaction"

"""The research JOURNAL (working-memory layer, design-working-memory.md §5/§6):
CRUD, the authorship invariant, mention parse + resolution through the merge keeper
(incl. archived → dangling), search, and the discipline loop (Layer-1 auto-entry on a
mock task, Layer-2 context nudge). Mock backend, offline — no Docker, no key."""

import pytest

from hexgraph.db.models import JournalEntry, JournalMention, NodeType
from hexgraph.db.session import session_scope
from hexgraph.engine import journal as J
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.graph.hypotheses import create_hypothesis
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node
from hexgraph.engine.graph.nodemerge import merge_duplicate_nodes
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _project_target(s, name="jrnl"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    return p, t


def _finding(s, project, target, task, title="bug"):
    return persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id,
                           finding=FModel(title=title, severity="high", confidence="medium",
                                          category="memory-safety", summary="s", reasoning="r",
                                          evidence=Evidence(function="f")))


# --- CRUD ---------------------------------------------------------------------

def test_add_and_get_entry(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        e = J.add_journal_entry(s, p, body="tried the cgi handler", author="agent")
        assert e.author == "agent" and e.edited is False
        out = J.get_journal_entry(s, e.id)
        assert out["body"] == "tried the cgi handler"
        assert out["author"] == "agent" and out["edited"] is False
        assert out["mentions"] == []


def test_serialized_timestamps_are_utc_aware(hg_home):
    # SQLite hands back naive datetimes even though the column is DateTime(timezone=True),
    # so the serializer must attach +00:00 — otherwise the browser parses the bare ISO
    # string as LOCAL time and the relative-time "ago()" clamps to "just now" for hours.
    with session_scope() as s:
        p, _ = _project_target(s)
        e = J.add_journal_entry(s, p, body="check the timestamps", author="agent")
        # single-entry path (get-by-id)
        out = J.get_journal_entry(s, e.id)
        assert out["created_at"].endswith("+00:00")
        assert out["updated_at"].endswith("+00:00")
        # batched path (list/search)
        rows = J.list_journal_entries(s, p.id)
        assert rows and rows[0]["created_at"].endswith("+00:00")
        assert rows[0]["updated_at"].endswith("+00:00")


def test_add_rejects_blank_body_and_bad_author(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        with pytest.raises(J.JournalError):
            J.add_journal_entry(s, p, body="   ", author="agent")
        with pytest.raises(J.JournalError):
            J.add_journal_entry(s, p, body="ok", author="robot")


def test_list_newest_first_and_author_filter(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        J.add_journal_entry(s, p, body="first (human)", author="human")
        J.add_journal_entry(s, p, body="second (agent)", author="agent")
        J.add_journal_entry(s, p, body="third (agent)", author="agent")
        rows = J.list_journal_entries(s, p.id)
        assert [r["body"] for r in rows] == ["third (agent)", "second (agent)", "first (human)"]
        agents = J.list_journal_entries(s, p.id, author="agent")
        assert {r["author"] for r in agents} == {"agent"} and len(agents) == 2


# --- authorship invariant (the permission rule) -------------------------------

def test_agent_can_edit_own_entry_marks_edited(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        e = J.add_journal_entry(s, p, body="draft", author="agent")
        J.update_journal_entry(s, e.id, body="revised", as_author="agent")
        out = J.get_journal_entry(s, e.id)
        assert out["body"] == "revised" and out["edited"] is True
        assert out["updated_at"] >= out["created_at"]


def test_agent_may_not_edit_or_delete_human_entry(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        h = J.add_journal_entry(s, p, body="the human's note", author="human")
        with pytest.raises(J.JournalError):
            J.update_journal_entry(s, h.id, body="hijacked", as_author="agent")
        with pytest.raises(J.JournalError):
            J.delete_journal_entry(s, h.id, as_author="agent")
        # untouched
        assert J.get_journal_entry(s, h.id)["body"] == "the human's note"


def test_human_path_may_edit_anything(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        a = J.add_journal_entry(s, p, body="agent entry", author="agent")
        # as_author=None is the human/REST path — no restriction.
        J.update_journal_entry(s, a.id, body="human fixed it", as_author=None)
        assert J.get_journal_entry(s, a.id)["body"] == "human fixed it"
        J.delete_journal_entry(s, a.id, as_author=None)
        assert J.get_journal_entry(s, a.id) is None


# --- @-mentions: parse, persist, resolve --------------------------------------

def test_parse_mentions_dedups_and_filters_unknown_kinds():
    body = ("see @[parse_cgi](node:n1) and @[the bug](finding:f1); again @[parse_cgi](node:n1); "
            "ignore @[x](bogus:z) and a plain @handle.")
    parsed = J.parse_mentions(body)
    assert parsed == [("node", "n1", "parse_cgi"), ("finding", "f1", "the bug")]


def test_mentions_persisted_and_resolved(hg_home):
    with session_scope() as s:
        p, t = _project_target(s)
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = _finding(s, p, t, task, "stack overflow")
        node = get_or_create_node(s, project_id=p.id, node_type=NodeType.function,
                                  name="parse_cgi", target_id=t.id)
        body = (f"traced @[parse_cgi](node:{node.id}) into the sink; filed "
                f"@[stack overflow](finding:{f.id}); on @[httpd](target:{t.id}).")
        e = J.add_journal_entry(s, p, body=body, author="agent")

        # the join is populated (one row per distinct ref)
        rows = s.query(JournalMention).filter(JournalMention.entry_id == e.id).all()
        assert {r.ref_kind for r in rows} == {"node", "finding", "target"}

        out = J.get_journal_entry(s, e.id)
        by_kind = {m["ref_kind"]: m for m in out["mentions"]}
        assert by_kind["node"]["label"] == "parse_cgi" and by_kind["node"]["dangling"] is False
        assert by_kind["finding"]["label"] == "stack overflow" and by_kind["finding"]["dangling"] is False
        assert by_kind["target"]["label"] == "httpd" and by_kind["target"]["dangling"] is False


def test_mention_to_missing_object_is_dangling(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        e = J.add_journal_entry(s, p, body="ghost @[gone](node:does-not-exist)", author="agent")
        m = J.get_journal_entry(s, e.id)["mentions"][0]
        assert m["dangling"] is True and m["label"] is None


def test_archived_target_mention_greys_out(hg_home):
    with session_scope() as s:
        p, t = _project_target(s)
        e = J.add_journal_entry(s, p, body=f"on @[httpd](target:{t.id})", author="agent")
        assert J.get_journal_entry(s, e.id)["mentions"][0]["dangling"] is False
        # archive the target (soft-remove) → the mention greys, never errors
        t.archived = True
        s.flush()
        assert J.get_journal_entry(s, e.id)["mentions"][0]["dangling"] is True


def test_mention_resolves_through_merge_keeper(hg_home):
    """Link-stability across a nodemerge fold (design §5.3): a mention of the KEEPER
    still resolves after duplicates collapse onto it, and a mention of a now-folded-away
    duplicate degrades to a greyed `dangling` reference rather than crashing the render."""
    from hexgraph.db.models import Node

    with session_scope() as s:
        p, t = _project_target(s)
        # Raw rows that share a canonical key (normalized 'get_param') but distinct ids,
        # so nodemerge actually folds the dup onto the keeper (get_or_create_node would
        # normalize them to one node up front, leaving nothing to merge).
        keeper = Node(project_id=p.id, node_type="function", name="get_param",
                      fq_name="get_param", target_id=t.id, content_hash="abc")
        dup = Node(project_id=p.id, node_type="function", name="sym.get_param",
                   fq_name="sym.get_param", target_id=t.id)
        s.add(keeper); s.add(dup); s.flush()
        kid, did = keeper.id, dup.id

        e_keeper = J.add_journal_entry(s, p, body=f"@[get_param](node:{kid})", author="agent")
        e_dup = J.add_journal_entry(s, p, body=f"@[get_param](node:{did})", author="agent")

        removed = merge_duplicate_nodes(s, p.id)
        assert removed >= 1

        # mention of the keeper survives the fold, byte-stable
        mk = J.get_journal_entry(s, e_keeper.id)["mentions"][0]
        assert mk["dangling"] is False and mk["resolved_id"] == kid
        # mention of the folded-away duplicate greys out — no crash
        md = J.get_journal_entry(s, e_dup.id)["mentions"][0]
        assert md["dangling"] is True


def test_hypothesis_mention_and_backreference_filter(hg_home):
    with session_scope() as s:
        p, t = _project_target(s)
        h = create_hypothesis(s, p, statement="cgi trusts a length field", target_id=t.id)
        e = J.add_journal_entry(s, p, body=f"chasing @[len bug](hypothesis:{h.id})", author="agent")
        J.add_journal_entry(s, p, body="unrelated note", author="agent")
        # back-reference: entries mentioning this hypothesis
        hits = J.list_journal_entries(s, p.id, mentions_kind="hypothesis", mentions_id=h.id)
        assert [r["id"] for r in hits] == [e.id]


def test_edit_reparses_mentions(hg_home):
    with session_scope() as s:
        p, t = _project_target(s)
        node = get_or_create_node(s, project_id=p.id, node_type=NodeType.function,
                                  name="f", target_id=t.id)
        e = J.add_journal_entry(s, p, body=f"@[f](node:{node.id})", author="agent")
        assert len(s.query(JournalMention).filter(JournalMention.entry_id == e.id).all()) == 1
        J.update_journal_entry(s, e.id, body="no mentions now", as_author="agent")
        assert s.query(JournalMention).filter(JournalMention.entry_id == e.id).count() == 0


def test_delete_removes_mention_rows(hg_home):
    with session_scope() as s:
        p, t = _project_target(s)
        node = get_or_create_node(s, project_id=p.id, node_type=NodeType.function,
                                  name="f", target_id=t.id)
        e = J.add_journal_entry(s, p, body=f"@[f](node:{node.id})", author="agent")
        J.delete_journal_entry(s, e.id, as_author="agent")
        assert s.query(JournalMention).filter(JournalMention.entry_id == e.id).count() == 0
        assert J.get_journal_entry(s, e.id) is None


# --- search -------------------------------------------------------------------

def test_search_substring_over_bodies(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        J.add_journal_entry(s, p, body="the CGI handler trusts a length field", author="agent")
        J.add_journal_entry(s, p, body="unrelated firmware notes", author="agent")
        hits = J.search_journal(s, p, "cgi handler")  # case-insensitive
        assert len(hits) == 1 and "CGI handler" in hits[0]["body"]
        assert J.search_journal(s, p, "nothing-matches") == []


# --- batched mention resolution (no N+1 on list/search) -----------------------

import contextlib

from sqlalchemy import event

from hexgraph.db.session import get_engine


@contextlib.contextmanager
def _count_queries():
    """Count SQL statements emitted on the shared engine inside the block.

    A `before_cursor_execute` listener bumps a counter per statement so a test can
    assert the query count is BOUNDED (independent of the number of entries/mentions),
    proving the batched serialization path doesn't fan out into a per-mention point
    query (the N+1 regression guard)."""
    counter = {"n": 0}
    engine = get_engine()

    def _on_exec(conn, cursor, statement, parameters, context, executemany):
        counter["n"] += 1

    event.listen(engine, "before_cursor_execute", _on_exec)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", _on_exec)


def _entries_with_mentions(s, p, t, *, n_entries, mentions_each):
    """Make `n_entries` entries each mentioning `mentions_each` distinct real nodes
    (so resolution actually does work, not just dangling no-ops)."""
    nodes = [
        get_or_create_node(s, project_id=p.id, node_type=NodeType.function,
                           name=f"fn_{i}", target_id=t.id)
        for i in range(mentions_each)
    ]
    for e in range(n_entries):
        body = " ".join(f"@[{nd.name}](node:{nd.id})" for nd in nodes)
        J.add_journal_entry(s, p, body=f"entry {e}: {body}", author="agent")
    return nodes


def test_list_query_count_is_bounded_not_n_times_m(hg_home):
    """Serializing N entries with M mentions each must NOT issue O(N*M) point queries.
    The batched path resolves all mentions in a bounded number of statements regardless
    of how many entries/mentions there are — this is the N+1 guard."""
    with session_scope() as s:
        p, t = _project_target(s)
        _entries_with_mentions(s, p, t, n_entries=6, mentions_each=4)
        s.flush()

        with _count_queries() as small:
            rows_small = J.list_journal_entries(s, p.id)
        # sanity: every entry carries its 4 resolved mentions
        assert len(rows_small) == 6
        assert all(len(r["mentions"]) == 4 for r in rows_small)

    # A second project with MANY more entries/mentions must not cost proportionally
    # more queries — the batch is O(kinds), not O(entries*mentions).
    with session_scope() as s:
        p2, t2 = _project_target(s, name="jrnl2")
        _entries_with_mentions(s, p2, t2, n_entries=20, mentions_each=6)
        s.flush()

        with _count_queries() as big:
            rows_big = J.list_journal_entries(s, p2.id)
        assert len(rows_big) == 20
        assert all(len(r["mentions"]) == 6 for r in rows_big)

    # 6 entries * 4 mentions = 24 vs 20 entries * 6 = 120 mentions. A per-mention path
    # would balloon (~24 vs ~120 queries); the batched path stays flat (a small constant
    # apart for the entries query + the mention-rows query + one query per kind present).
    assert big["n"] <= small["n"] + 3
    # And the absolute count is tiny — far below "one query per mention".
    assert big["n"] <= 8


def test_batched_serialization_matches_per_mention_resolution(hg_home):
    """`serialize_entries` (batched) produces output byte-identical to resolving each
    mention one-by-one with `resolve_mention` — across the live, archived/dangling, and
    merge-folded-duplicate cases."""
    from hexgraph.db.models import Node

    with session_scope() as s:
        p, t = _project_target(s)
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = _finding(s, p, t, task, "the bug")
        node = get_or_create_node(s, project_id=p.id, node_type=NodeType.function,
                                  name="parse_cgi", target_id=t.id)
        h = create_hypothesis(s, p, statement="len field is trusted", target_id=t.id)

        # a merge-fold case: keeper + dup sharing a canonical key
        keeper = Node(project_id=p.id, node_type="function", name="get_param",
                      fq_name="get_param", target_id=t.id, content_hash="abc")
        dup = Node(project_id=p.id, node_type="function", name="sym.get_param",
                   fq_name="sym.get_param", target_id=t.id)
        s.add(keeper); s.add(dup); s.flush()
        kid, did = keeper.id, dup.id

        # one entry exercising live node/finding/target/hypothesis + a missing ref
        J.add_journal_entry(s, p, body=(
            f"@[parse_cgi](node:{node.id}) @[the bug](finding:{f.id}) "
            f"@[httpd](target:{t.id}) @[h](hypothesis:{h.id}) @[gone](node:does-not-exist)"
        ), author="agent")
        # entries on the keeper and the soon-to-be-folded dup
        J.add_journal_entry(s, p, body=f"@[get_param](node:{kid})", author="agent")
        J.add_journal_entry(s, p, body=f"@[get_param](node:{did})", author="agent")

        merge_duplicate_nodes(s, p.id)  # folds dup → keeper, deleting the dup row

        # archive the target so the target mention degrades to dangling
        t.archived = True
        s.flush()

        rows = J.list_journal_entries(s, p.id)

        # Re-derive every mention the SLOW way and compare field-for-field.
        for r in rows:
            stored = (
                s.query(JournalMention)
                .filter(JournalMention.entry_id == r["id"])
                .all()
            )
            expected = []
            for mr in stored:
                d = J.resolve_mention(s, r["project_id"], mr.ref_kind, mr.ref_id)
                d["stored_label"] = mr.label
                expected.append(d)
            key = lambda m: (m["ref_kind"], m["ref_id"])  # order-insensitive compare
            assert sorted(r["mentions"], key=key) == sorted(expected, key=key), r["id"]


# --- Layer 1: auto-entry on a mock task ---------------------------------------

def test_layer1_auto_journal_on_mock_task(hg_home):
    """A mock LLM task auto-creates exactly one closing AGENT journal entry, tied to
    the task via origin_task_id, drafted deterministically (offline/zero-token)."""
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        p, t = _project_target(s)
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        tid, pid, task_id = t.id, p.id, task.id

    status = run_task_sync(task_id)
    assert status in ("succeeded", "needs_triage"), status

    with session_scope() as s:
        entries = J.list_journal_entries(s, pid)
        auto = [e for e in entries if e["origin_task_id"] == task_id]
        assert len(auto) == 1, entries
        body = auto[0]["body"]
        assert auto[0]["author"] == "agent"
        assert "Session log" in body and "static_analysis" in body
        # deterministic structure: the four-prompt skeleton is present
        assert "*Tried:*" in body and "*Worked:*" in body


def test_layer1_draft_is_deterministic_and_skimmable():
    body = J._draft_session_log(
        task_type="reverse_engineering", target_name="httpd",
        transcript=[{"tool": "re_decompile_function"}, {"tool": "re_xrefs"},
                    {"tool": "re_decompile_function"}],
        finding_titles=["overflow in parse_cgi"], summary="the length check is missing")
    assert "re_decompile_function, re_xrefs" in body  # deduped, ordered
    assert "3 tool call(s)" in body
    assert "recorded 1 finding(s)" in body and "overflow in parse_cgi" in body
    assert "*Learned:* the length check is missing" in body
    # deterministic: same inputs → byte-identical draft
    assert body == J._draft_session_log(
        task_type="reverse_engineering", target_name="httpd",
        transcript=[{"tool": "re_decompile_function"}, {"tool": "re_xrefs"},
                    {"tool": "re_decompile_function"}],
        finding_titles=["overflow in parse_cgi"], summary="the length check is missing")


# --- Layer 2: the context nudge -----------------------------------------------

def test_layer2_nudge_when_no_agent_entry(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        nudge = J.staleness_nudge(s, p.id)
        assert nudge and "No agent journal entry yet" in nudge


def test_layer2_nudge_quiet_when_fresh(hg_home):
    with session_scope() as s:
        p, _ = _project_target(s)
        J.add_journal_entry(s, p, body="just wrote this", author="agent")
        # no tasks have run since → no nudge
        assert J.staleness_nudge(s, p.id) is None


def test_layer2_nudge_appears_in_task_context(hg_home):
    """The nudge is injected into the assembled task context (Layer-2 seam)."""
    from hexgraph.engine.context import preview_context
    from hexgraph.tasks.base import TaskContext

    with session_scope() as s:
        p, t = _project_target(s)
        ctx = TaskContext(task_id="preview", task_type="static_analysis", project_id=p.id,
                          target_id=t.id, target_name=t.name)
        out = preview_context(s, p, t, ctx)
        # first task, no agent entry yet → the "start journaling" nudge is present
        kinds = {it["kind"] for it in out["items"]}
        assert "journal_nudge" in kinds

"""P0-1: Alembic migrations bring a fresh DB to head and adopt a legacy DB."""

from sqlalchemy import create_engine, inspect


def _names(monkeypatch, db):
    from hexgraph.db.session import db_url

    return set(inspect(create_engine(db_url())).get_table_names())


def test_fresh_db_upgrades_to_head(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(tmp_path / "hg.db"))
    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import reset_engine_for_tests

    reset_engine_for_tests()
    res = prepare_database()
    assert res["action"] == "upgraded"
    assert res["revision"]  # stamped at head
    names = _names(monkeypatch, tmp_path / "hg.db")
    assert {"project", "target", "edge", "task", "finding", "alembic_version"} <= names

    # Idempotent: second run stays at the same head and does nothing destructive.
    res2 = prepare_database()
    assert res2["revision"] == res["revision"]
    reset_engine_for_tests()


def test_legacy_create_all_db_is_adopted(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(tmp_path / "hg.db"))
    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import init_db, reset_engine_for_tests

    reset_engine_for_tests()
    init_db()  # create_all, no alembic_version (simulates an MVP-era DB)
    res = prepare_database()
    assert res["action"] == "stamped"
    assert res["revision"]
    assert "alembic_version" in _names(monkeypatch, tmp_path / "hg.db")
    reset_engine_for_tests()


def test_legacy_mvp_schema_db_upgrades_forward(tmp_path, monkeypatch):
    """A pre-Alembic create_all'd MVP-schema DB (old edge, no alembic_version) is
    adopted at baseline and migrated forward — not wrongly stamped at head."""
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(tmp_path / "legacy.db"))
    from alembic import command
    from sqlalchemy import create_engine, inspect, text

    from hexgraph.db.migrate import BASELINE, _alembic_config, prepare_database
    from hexgraph.db.session import db_url, reset_engine_for_tests

    reset_engine_for_tests()
    command.upgrade(_alembic_config(), BASELINE)  # build the old MVP schema
    e = create_engine(db_url())
    with e.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))  # mimic pre-migrations DB
    e.dispose()

    res = prepare_database(backup=False)
    assert res["action"] == "upgraded" and res["revision"]
    cols = {c["name"] for c in inspect(create_engine(db_url())).get_columns("edge")}
    assert "src_kind" in cols  # the typed-graph rewrite actually ran
    reset_engine_for_tests()


def test_backup_written_on_upgrade(tmp_path, monkeypatch):
    db = tmp_path / "hg.db"
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(db))
    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import reset_engine_for_tests

    reset_engine_for_tests()
    prepare_database()  # creates + stamps head (no backup; file was empty)
    # Force a no-op upgrade on the now-populated, versioned DB with backup on.
    res = prepare_database(backup=True)
    assert res["action"] == "upgraded"
    assert (tmp_path / "hg.db.bak").exists()
    reset_engine_for_tests()

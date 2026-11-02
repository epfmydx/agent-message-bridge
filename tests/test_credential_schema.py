"""Additive credential schema upgrades preserve one-time config baselines."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, inspect, text

from bridge.models import database
from bridge.schema import ensure_profile_schema


def old_schema(engine):
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE participants (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, active BOOLEAN NOT NULL, sequence INTEGER NOT NULL, managed_source VARCHAR NOT NULL DEFAULT 'config')")
        db.exec_driver_sql("CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY REFERENCES participants(id), email VARCHAR UNIQUE, managed_source VARCHAR NOT NULL DEFAULT 'config', creation_token_hash VARCHAR, password_hash VARCHAR NOT NULL, api_key_hash VARCHAR UNIQUE, active BOOLEAN NOT NULL)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('synthetic', 'Synthetic', true, 0, 'config')")
        db.exec_driver_sql("INSERT INTO oauth_users VALUES ('synthetic','synthetic@example.com','config',NULL,'synthetic-config-password','synthetic-config-key',true)")


def test_additive_upgrade_backfills_baseline_once_and_serializes_repeated_init(tmp_path):
    engine, _ = database("sqlite:///" + str(tmp_path / "credentials.sqlite"))
    old_schema(engine)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ensure_profile_schema(engine), range(2)))
    assert {"participant_api_keys", "credential_operations"} <= set(inspect(engine).get_table_names())
    with engine.begin() as db:
        row = db.execute(text("SELECT credential_generation,credential_baseline_set,configured_password_hash,configured_api_key_hash FROM oauth_users")).one()
        assert tuple(row) == (1, 1, "synthetic-config-password", "synthetic-config-key")
        db.exec_driver_sql("UPDATE oauth_users SET password_hash='synthetic-ui-password', api_key_hash=NULL, password_source='database', api_key_source='database', credential_generation=3")
    ensure_profile_schema(engine)
    with engine.connect() as db:
        row = db.execute(text("SELECT credential_generation,password_hash,api_key_hash,configured_password_hash,configured_api_key_hash FROM oauth_users")).one()
        assert tuple(row) == (3, "synthetic-ui-password", None, "synthetic-config-password", "synthetic-config-key")
        assert not db.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    engine.dispose()


def test_interrupted_additive_upgrade_rolls_back_baseline_and_tables(tmp_path):
    engine, _ = database("sqlite:///" + str(tmp_path / "retry.sqlite"))
    old_schema(engine)
    def interrupt(connection, cursor, statement, *args):
        if "CREATE TABLE credential_operations" in statement:
            raise RuntimeError("synthetic schema interruption")
    event.listen(engine, "before_cursor_execute", interrupt)
    try:
        with pytest.raises(RuntimeError, match="synthetic schema interruption"):
            ensure_profile_schema(engine)
    finally:
        event.remove(engine, "before_cursor_execute", interrupt)
    with engine.connect() as db:
        assert "credential_generation" not in {c["name"] for c in inspect(db).get_columns("oauth_users")}
        assert not inspect(db).has_table("participant_api_keys")
        assert db.exec_driver_sql("SELECT password_hash FROM oauth_users").scalar() == "synthetic-config-password"
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    ensure_profile_schema(engine)
    assert {"participant_api_keys", "credential_operations"} <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_postgres_additive_upgrade_backfills_without_replacing_owner_changes(bridge_app):
    engine = bridge_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL upgrade requires disposable TEST_DATABASE_URL")
    # Fixture uses a synthetic isolated schema; remove only feature-owned additions.
    with engine.begin() as db:
        db.exec_driver_sql("DROP TABLE credential_operations")
        db.exec_driver_sql("DROP TABLE participant_api_keys")
        for name in ("credential_generation", "credential_baseline_set", "configured_password_hash",
                     "configured_api_key_hash", "password_source", "api_key_source"):
            db.exec_driver_sql("ALTER TABLE oauth_users DROP COLUMN " + name)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ensure_profile_schema(engine), range(2)))
    with engine.begin() as db:
        baseline = db.execute(text("SELECT configured_password_hash,configured_api_key_hash FROM oauth_users WHERE id='agent-b'")).one()
        db.exec_driver_sql("UPDATE oauth_users SET password_hash='synthetic-ui-password',api_key_hash=NULL WHERE id='agent-b'")
    ensure_profile_schema(engine)
    with engine.connect() as db:
        assert db.execute(text("SELECT configured_password_hash,configured_api_key_hash FROM oauth_users WHERE id='agent-b'")).one() == baseline
        assert db.exec_driver_sql("SELECT password_hash FROM oauth_users WHERE id='agent-b'").scalar() == "synthetic-ui-password"

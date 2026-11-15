"""Fresh and pre-webhook SQLite schema compatibility regressions."""
import pytest
from sqlalchemy import inspect, select, text

from bridge.models import Base, Delivery, Member, Message, Participant, database
from bridge.models_auth import User
from bridge.schema import ensure_profile_schema
from bridge.worker import deliver_one


def test_fresh_profile_schema_webhook_columns_are_nullable_and_repeatable(tmp_path):
    engine, _ = database("sqlite:///" + str(tmp_path / "fresh-profile-webhook.sqlite"))
    Base.metadata.create_all(engine)
    ensure_profile_schema(engine)
    ensure_profile_schema(engine)

    participants = {column["name"]: column for column in inspect(engine).get_columns("participants")}
    deliveries = {column["name"]: column for column in inspect(engine).get_columns("deliveries")}
    assert participants["webhook_enabled"]["nullable"]
    assert participants["webhook_url"]["nullable"] and participants["webhook_token"]["nullable"]
    assert not participants["webhook_generation"]["nullable"]
    assert deliveries["webhook_generation"]["nullable"]

    with engine.begin() as db:
        db.exec_driver_sql("INSERT INTO browser_owners (id,name,email,password_hash,active) VALUES ('synthetic-owner','Owner','owner@example.com','synthetic',true)")
        db.exec_driver_sql("INSERT INTO participants (id, stable_id, name, active, sequence, owner_account_id) VALUES ('old-writer', 'private-old', 'Old', 1, 0, 'synthetic-owner')")
        values = db.execute(text("SELECT webhook_enabled, webhook_url, webhook_token, webhook_generation FROM participants WHERE id='old-writer'")).one()
        assert tuple(values) == (None, None, None, 1)
    engine.dispose()


def _v016_shaped_schema(engine):
    """Small faithful pre-profile-webhook shape with identity and delivery rows."""
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE participants (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, managed_source VARCHAR NOT NULL DEFAULT 'config', active BOOLEAN NOT NULL, sequence INTEGER NOT NULL)")
        db.exec_driver_sql("CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY REFERENCES participants(id), email VARCHAR UNIQUE, password_hash VARCHAR NOT NULL, api_key_hash VARCHAR UNIQUE, active BOOLEAN NOT NULL, managed_source VARCHAR NOT NULL DEFAULT 'config', creation_token_hash VARCHAR UNIQUE)")
        db.exec_driver_sql("CREATE TABLE threads (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE thread_members (thread_id VARCHAR NOT NULL REFERENCES threads(id), participant_id VARCHAR NOT NULL REFERENCES participants(id), PRIMARY KEY(thread_id, participant_id))")
        db.exec_driver_sql("CREATE TABLE messages (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE subscriptions (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE deliveries (id VARCHAR PRIMARY KEY, message_id VARCHAR NOT NULL REFERENCES messages(id), kind VARCHAR NOT NULL, destination VARCHAR NOT NULL, subscription_id VARCHAR REFERENCES subscriptions(id), state VARCHAR NOT NULL)")
        db.exec_driver_sql("CREATE INDEX ix_v016_delivery_message ON deliveries(message_id)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('agent-a', 'Agent A', 'config', 1, 5)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('agent-b', 'Agent B', 'database', 1, 3)")
        db.exec_driver_sql("INSERT INTO oauth_users VALUES ('agent-b', NULL, '', 'synthetic-api-key-hash', 1, 'database', NULL)")
        db.exec_driver_sql("INSERT INTO threads VALUES ('shared-thread')")
        db.exec_driver_sql("INSERT INTO thread_members VALUES ('shared-thread', 'agent-a')")
        db.exec_driver_sql("INSERT INTO thread_members VALUES ('shared-thread', 'agent-b')")
        db.exec_driver_sql("INSERT INTO messages VALUES ('retained-message')")
        db.exec_driver_sql("INSERT INTO deliveries VALUES ('retained-delivery', 'retained-message', 'webhook', 'webhook:agent-a', NULL, 'retry')")


def test_v016_sqlite_upgrade_retains_profiles_memberships_and_delivery_for_old_writers(tmp_path):
    engine, _ = database("sqlite:///" + str(tmp_path / "v016-profile-webhook.sqlite"))
    _v016_shaped_schema(engine)
    ensure_profile_schema(engine)
    ensure_profile_schema(engine)

    participant_columns = {column["name"]: column for column in inspect(engine).get_columns("participants")}
    delivery_columns = {column["name"]: column for column in inspect(engine).get_columns("deliveries")}
    assert {"webhook_enabled", "webhook_url", "webhook_token", "webhook_generation"} <= set(participant_columns)
    assert "webhook_generation" in delivery_columns and delivery_columns["webhook_generation"]["nullable"]
    assert "ix_v016_delivery_message" in {index["name"] for index in inspect(engine).get_indexes("deliveries")}

    with engine.begin() as db:
        assert not db.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert db.exec_driver_sql("SELECT COUNT(*) FROM participants").scalar_one() == 2
        assert db.exec_driver_sql("SELECT managed_source FROM participants WHERE id='agent-b'").scalar_one() == "database"
        assert db.exec_driver_sql("SELECT api_key_hash FROM oauth_users WHERE id='agent-b'").scalar_one() == "synthetic-api-key-hash"
        assert db.exec_driver_sql("SELECT COUNT(*) FROM thread_members WHERE thread_id='shared-thread'").scalar_one() == 2
        assert db.exec_driver_sql("SELECT state FROM deliveries WHERE id='retained-delivery'").scalar_one() == "retry"
        # Older API/worker versions omit the additive nullable generation.
        db.exec_driver_sql("INSERT INTO deliveries (id, message_id, kind, destination, state) VALUES ('old-writer-delivery', 'retained-message', 'webhook', 'webhook:agent-a', 'pending')")
        assert db.exec_driver_sql("SELECT webhook_generation FROM deliveries WHERE id='old-writer-delivery'").scalar_one() is None
        db.exec_driver_sql("INSERT INTO participants (id, name, managed_source, active, sequence) VALUES ('old-writer-profile', 'Old writer', 'config', 1, 0)")
        values = db.execute(text("SELECT webhook_enabled, webhook_url, webhook_token, webhook_generation FROM participants WHERE id='old-writer-profile'")).one()
        assert tuple(values) == (None, None, None, 1)
    engine.dispose()


def test_postgres_profile_webhook_schema_repeatable_and_delivers_explicit_generation(bridge_app):
    app = bridge_app
    if app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Requires isolated disposable PostgreSQL schema")
    ensure_profile_schema(app.extensions["engine"])
    ensure_profile_schema(app.extensions["engine"])
    response = app.test_client().post("/api/messages", headers={
        "Authorization": "Bearer " + app.extensions["test_credentials"]["agent-b"]
    }, json=dict(message_id="pg-profile-webhook", recipient="agent-a", text="Synthetic profile notification",
                 status="received", needs_reply=True))
    assert response.status_code == 200
    requests = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda url, body, headers: requests.append((url, headers)) or (200,b""))
    assert requests == [("https://agent-a.example.com/bridge-hook", {"Content-Type":"application/json", "Authorization":"Bearer synthetic-webhook-bearer"})]
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == "pg-profile-webhook"))
        assert delivery.state == "accepted" and delivery.webhook_generation == 1

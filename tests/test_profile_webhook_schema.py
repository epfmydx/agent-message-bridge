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
        db.exec_driver_sql("INSERT INTO participants (id, name, active, sequence) VALUES ('old-writer', 'Old', 1, 0)")
        values = db.execute(text("SELECT webhook_enabled, webhook_url, webhook_token, webhook_generation FROM participants WHERE id='old-writer'")).one()
        assert tuple(values) == (None, None, None, 1)
    engine.dispose()


def _v010_shaped_schema(engine):
    """Small faithful pre-profile-webhook shape with identity and delivery rows."""
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE participants (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, managed_source VARCHAR NOT NULL DEFAULT 'config', active BOOLEAN NOT NULL, sequence INTEGER NOT NULL)")
        db.exec_driver_sql("CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY REFERENCES participants(id), email VARCHAR UNIQUE, password_hash VARCHAR NOT NULL, api_key_hash VARCHAR UNIQUE, active BOOLEAN NOT NULL, managed_source VARCHAR NOT NULL DEFAULT 'config', creation_token_hash VARCHAR UNIQUE)")
        db.exec_driver_sql("CREATE TABLE threads (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE thread_members (thread_id VARCHAR NOT NULL REFERENCES threads(id), participant_id VARCHAR NOT NULL REFERENCES participants(id), PRIMARY KEY(thread_id, participant_id))")
        db.exec_driver_sql("CREATE TABLE messages (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE subscriptions (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE deliveries (id VARCHAR PRIMARY KEY, message_id VARCHAR NOT NULL REFERENCES messages(id), kind VARCHAR NOT NULL, destination VARCHAR NOT NULL, subscription_id VARCHAR REFERENCES subscriptions(id), state VARCHAR NOT NULL)")
        db.exec_driver_sql("CREATE INDEX ix_v010_delivery_message ON deliveries(message_id)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('agent-a', 'Agent A', 'config', 1, 5)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('agent-b', 'Agent B', 'database', 1, 3)")
        db.exec_driver_sql("INSERT INTO oauth_users VALUES ('agent-b', NULL, '', 'synthetic-api-key-hash', 1, 'database', NULL)")
        db.exec_driver_sql("INSERT INTO threads VALUES ('shared-thread')")
        db.exec_driver_sql("INSERT INTO thread_members VALUES ('shared-thread', 'agent-a')")
        db.exec_driver_sql("INSERT INTO thread_members VALUES ('shared-thread', 'agent-b')")
        db.exec_driver_sql("INSERT INTO messages VALUES ('retained-message')")
        db.exec_driver_sql("INSERT INTO deliveries VALUES ('retained-delivery', 'retained-message', 'webhook', 'webhook:agent-a', NULL, 'retry')")


def test_v010_sqlite_upgrade_retains_profiles_memberships_and_delivery_for_old_writers(tmp_path):
    engine, _ = database("sqlite:///" + str(tmp_path / "v010-profile-webhook.sqlite"))
    _v010_shaped_schema(engine)
    ensure_profile_schema(engine)
    ensure_profile_schema(engine)

    participant_columns = {column["name"]: column for column in inspect(engine).get_columns("participants")}
    delivery_columns = {column["name"]: column for column in inspect(engine).get_columns("deliveries")}
    assert {"webhook_enabled", "webhook_url", "webhook_token", "webhook_generation"} <= set(participant_columns)
    assert "webhook_generation" in delivery_columns and delivery_columns["webhook_generation"]["nullable"]
    assert "ix_v010_delivery_message" in {index["name"] for index in inspect(engine).get_indexes("deliveries")}

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


def test_postgres_v010_additive_webhook_upgrade_is_repeatable_and_delivers_legacy_row(bridge_app):
    """Uses only bridge_app's disposable per-test schema; never an external schema."""
    app = bridge_app
    engine = app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires bridge_app's isolated disposable PostgreSQL schema")

    client = app.test_client()
    created = client.post("/api/messages", headers={
        "Authorization": "Bearer " + app.extensions["test_credentials"]["agent-b"]
    }, json={"message_id": "pg-v010-retained-message", "recipient": "agent-a",
             "text": "synthetic migration evidence", "status": "received", "needs_reply": True})
    assert created.status_code == 200
    message = created.get_json()

    with app.extensions["sessions"]() as db:
        recipient = db.get(Participant, "agent-a")
        original = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert original.kind == "webhook" and original.webhook_generation == 1
        credential_hash = db.get(User, "agent-a").api_key_hash
        member_ids = set(db.scalars(select(Member.participant_id).where(Member.thread_id == message["thread_id"])))
        identities = set(db.scalars(select(Participant.id)))
        assert recipient.active and identities >= {"agent-a", "agent-b"}

    # Roll only the five webhook columns back to the exact pre-feature shape.
    # bridge_app created this fixture's own unique PostgreSQL schema.
    with engine.begin() as db:
        for name in ("webhook_enabled", "webhook_url", "webhook_token", "webhook_generation"):
            db.exec_driver_sql("ALTER TABLE participants DROP COLUMN " + name)
        db.exec_driver_sql("ALTER TABLE deliveries DROP COLUMN webhook_generation")
    indexes_before = {index["name"] for table in ("participants", "deliveries", "messages", "thread_members")
                      for index in inspect(engine).get_indexes(table)}

    ensure_profile_schema(engine)
    ensure_profile_schema(engine)

    indexes_after = {index["name"] for table in ("participants", "deliveries", "messages", "thread_members")
                     for index in inspect(engine).get_indexes(table)}
    assert indexes_after == indexes_before
    with app.extensions["sessions"]() as db:
        participant = db.get(Participant, "agent-a")
        user = db.get(User, "agent-a")
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert participant.active and participant.webhook_enabled is None
        assert participant.webhook_url is None and participant.webhook_token is None
        assert participant.webhook_generation == 1
        assert user.api_key_hash == credential_hash
        assert set(db.scalars(select(Participant.id))) == identities
        assert set(db.scalars(select(Member.participant_id).where(Member.thread_id == message["thread_id"]))) == member_ids
        assert delivery.state == "pending" and delivery.webhook_generation is None

    # Older API writers can omit all additive profile fields and receive the
    # generation default while their nullable configuration stays inherited.
    with engine.begin() as db:
        db.exec_driver_sql("INSERT INTO participants (id, name, managed_source, active, sequence) VALUES ('pg-old-writer', 'Old writer', 'config', true, 0)")
        values = db.execute(text("SELECT webhook_enabled, webhook_url, webhook_token, webhook_generation FROM participants WHERE id='pg-old-writer'")).one()
        assert tuple(values) == (None, None, None, 1)

    requests = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: requests.append((url, headers)) or (200, b""))
    assert requests == [("https://agent-a.example.com/bridge-hook", {
        "Content-Type": "application/json", "Authorization": "Bearer synthetic-webhook-bearer"})]
    with app.extensions["sessions"]() as db:
        delivered = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivered.state == "accepted" and delivered.webhook_generation is None

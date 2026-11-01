"""Shared synthetic API setup for bridge message, event, and worker tests."""
import base64
import hashlib
import os
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash

from bridge.app import bootstrap, create_app
from bridge.models import Base


@pytest.fixture
def bridge_app(tmp_path):
    """Create a private test schema and three synthetic bearer-authenticated Agents."""
    users = []
    credentials = {}
    for ident, name in (("agent-a", "Agent A"), ("agent-b", "Agent B"), ("intruder", "Outside Agent")):
        raw_key = "synthetic-api-key-" + ident
        credentials[ident] = raw_key
        users.append({
            "id": ident,
            "name": name,
            "email": ident + "@example.com",
            "password_hash": generate_password_hash("synthetic-password-" + ident),
            "api_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        })
    settings = {
        "DATABASE_URL": "sqlite:///unused.db",
        "BASE_URL": "https://bridge.example.com",
        "SECRET_KEY": "synthetic-session-secret",
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "USERS": users,
        "WEBHOOK_PARTICIPANT_ID": "agent-a",
        "WEBHOOK_URL": "https://agent-a.example.com/bridge-hook",
        "WEBHOOK_TOKEN": "synthetic-webhook-bearer",
        "CLOUDFLARE_ORIGIN_SECRET": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
        "TRUSTED_PROXY_CIDRS": ["127.0.0.1/32"],
    }
    root_url = os.environ.get("TEST_DATABASE_URL")
    admin = schema = None
    if root_url:
        admin = create_engine(root_url, hide_parameters=True)
        schema = "agent_message_bridge_test_" + uuid.uuid4().hex
        with admin.begin() as connection:
            connection.execute(text('CREATE SCHEMA "' + schema + '"'))
        settings["DATABASE_URL"] = make_url(root_url).update_query_dict(
            {"options": "-csearch_path=" + schema}
        ).render_as_string(hide_password=False)
    else:
        settings["DATABASE_URL"] = "sqlite:///" + str(tmp_path / "bridge.sqlite")

    app = create_app(settings)
    app.config["TESTING"] = True
    engine, sessions = app.extensions["engine"], app.extensions["sessions"]
    Base.metadata.create_all(engine)
    with sessions.begin() as db:
        bootstrap(db, settings)
    app.extensions["verify_callback"] = lambda callback, secret, ident: None
    app.extensions["test_credentials"] = credentials
    try:
        yield app
    finally:
        engine.dispose()
        if admin:
            with admin.begin() as connection:
                connection.execute(text('DROP SCHEMA "' + schema + '" CASCADE'))
            admin.dispose()


@pytest.fixture
def bridge_client(bridge_app):
    return bridge_app.test_client()


def bearer_headers(app, participant_id):
    return {"Authorization": "Bearer " + app.extensions["test_credentials"][participant_id]}

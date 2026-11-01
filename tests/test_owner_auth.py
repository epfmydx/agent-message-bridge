"""Synthetic browser-owner authentication remains separate from Agent authority."""
import base64
import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from flask import g, jsonify
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from bridge.app import bootstrap
from bridge.auth import browser_identity, browser_owner, browser_user, digest
from bridge.config import load_settings, validate_settings
from bridge.models import Participant
from bridge.models_auth import BrowserOwner, Code, Family, Token, User

BASE = "https://bridge.example.com"
CALLBACK = "https://client.example.com/callback"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}
OWNER_PASSWORD = "synthetic-personal-owner-password"


@pytest.fixture
def owner_app(bridge_app):
    bridge_app.config["BROWSER_OWNERS"] = [{"id": "personal-owner", "name": "Personal Owner",
        "email": "personal@example.com", "password_hash": generate_password_hash(OWNER_PASSWORD)}]
    with bridge_app.extensions["sessions"].begin() as db:
        bootstrap(db, bridge_app.config)

    @bridge_app.get("/test/browser-identity")
    def identity_probe():
        identity = browser_identity(g.db)
        return jsonify(identity=identity.id if identity else None,
                       owner=bool(browser_owner(g.db)), participant=bool(browser_user(g.db)))

    return bridge_app


def get(client, path, **kwargs):
    return client.get(path, headers=HEADERS, base_url=BASE, **kwargs)


def post(client, path, **kwargs):
    return client.post(path, headers=HEADERS, base_url=BASE, **kwargs)


def csrf(response):
    return re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()


def login(client, *, email="personal@example.com", password=OWNER_PASSWORD):
    page = get(client, "/login")
    return post(client, "/login", data={"email": email, "password": password, "csrf": csrf(page)})


def register(client):
    response = client.post("/oauth/register", base_url=BASE, json={"redirect_uris": [CALLBACK],
        "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"]})
    assert response.status_code == 201
    return response.json["client_id"]


def oauth_fields(client_id):
    verifier = "v"*64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return dict(response_type="code", client_id=client_id, redirect_uri=CALLBACK,
        resource=BASE+"/mcp", scope="bridge:messages", code_challenge=challenge,
        code_challenge_method="S256", state="synthetic-state")


def participant_connection(app):
    client = app.test_client()
    cid = register(client)
    assert login(client, email="agent-b@example.com", password="synthetic-password-agent-b").status_code == 302
    fields = oauth_fields(cid)
    consent = get(client, "/oauth/authorize", query_string=fields)
    assert consent.status_code == 200
    approved = post(client, "/oauth/authorize", data={**fields, "csrf": csrf(consent), "approve": "yes"})
    code = parse_qs(urlsplit(approved.location).query)["code"][0]
    tokens = client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code",
        client_id=cid, code=code, redirect_uri=CALLBACK, code_verifier="v"*64, resource=BASE+"/mcp"))
    assert tokens.status_code == 200
    return client, cid, tokens.json


def test_owner_login_rotates_session_requires_csrf_and_origin(owner_app):
    client = owner_app.test_client()
    assert client.get("/login", base_url=BASE).status_code == 403
    assert post(client, "/login", data={"email": "personal@example.com", "password": OWNER_PASSWORD}).status_code == 400
    page = get(client, "/login")
    old_csrf = csrf(page)
    with client.session_transaction(base_url=BASE) as state:
        state["authorize_next"] = "/oauth/authorize?pending=synthetic"
        state["unrelated"] = "stale-session-data"
    response = post(client, "/login", data={"email": "PERSONAL@example.com", "password": OWNER_PASSWORD, "csrf": old_csrf})
    assert response.status_code == 302 and response.location == "/"
    cookie = response.headers["Set-Cookie"]
    assert all(value in cookie for value in ("Secure", "HttpOnly", "SameSite=Lax"))
    with client.session_transaction(base_url=BASE) as state:
        assert state["owner"] == "personal-owner" and state["account_kind"] == "owner"
        assert state["_permanent"]
        assert "csrf" not in state and "authorize_next" not in state and "unrelated" not in state
    assert get(client, "/test/browser-identity").json == {"identity": "personal-owner", "owner": True, "participant": False}
    assert post(client, "/logout", data={"csrf": old_csrf}).status_code == 400
    fresh_csrf = csrf(get(client, "/login"))
    assert fresh_csrf != old_csrf
    assert post(client, "/logout", data={"csrf": fresh_csrf}).location == "/login"
    assert get(client, "/test/browser-identity").json["identity"] is None
    with owner_app.extensions["sessions"]() as db:
        assert db.get(BrowserOwner, "personal-owner").email == "personal@example.com"
        assert db.get(Participant, "personal-owner") is None
        assert db.get(User, "personal-owner") is None


def test_owner_invalid_login_and_session_markers(owner_app):
    client = owner_app.test_client()
    response = login(client, password="synthetic-wrong-password")
    assert response.status_code == 200 and b"Email or password is incorrect" in response.data
    assert get(client, "/test/browser-identity").json["identity"] is None
    with owner_app.extensions["sessions"]() as db:
        owner_hash = digest(db.get(BrowserOwner, "personal-owner").password_hash)
        participant_hash = digest(db.get(User, "agent-b").password_hash)
    for marker in (None, "participant", "unrecognized"):
        with client.session_transaction(base_url=BASE) as state:
            state.clear()
            state.update(owner="personal-owner", credential=owner_hash)
            if marker is not None:
                state["account_kind"] = marker
        assert get(client, "/test/browser-identity").json["identity"] is None
    with client.session_transaction(base_url=BASE) as state:
        state.clear()
        state.update(owner="personal-owner", account_kind="owner")
    assert get(client, "/test/browser-identity").json["identity"] is None
    # Legacy participant cookies remain valid, but explicit unknown kinds do not.
    with client.session_transaction(base_url=BASE) as state:
        state.clear()
        state.update(owner="agent-b", credential=participant_hash)
    assert get(client, "/test/browser-identity").json["participant"] is True
    for marker in (None, "owner", "unrecognized"):
        with client.session_transaction(base_url=BASE) as state:
            state["account_kind"] = marker
        assert get(client, "/test/browser-identity").json["identity"] is None


def test_owner_rotation_and_removal_leave_agent_credentials_unchanged(owner_app):
    agent_client, cid, tokens = participant_connection(owner_app)
    client = owner_app.test_client()
    login(client)
    sessions = owner_app.extensions["sessions"]
    with sessions() as db:
        before = [(u.id, u.password_hash, u.api_key_hash, u.active) for u in db.scalars(select(User).order_by(User.id))]
        family_id = db.scalar(select(Token.family))
    owner_app.config["BROWSER_OWNERS"][0]["password_hash"] = generate_password_hash("synthetic-rotated-owner-password")
    with sessions.begin() as db:
        bootstrap(db, owner_app.config)
    assert get(client, "/test/browser-identity").json["identity"] is None
    assert login(client, password="synthetic-rotated-owner-password").status_code == 302
    assert get(client, "/test/browser-identity").json["owner"] is True
    owner_app.config["BROWSER_OWNERS"] = []
    with sessions.begin() as db:
        bootstrap(db, owner_app.config)
    assert get(client, "/test/browser-identity").json["identity"] is None
    assert login(client, password="synthetic-rotated-owner-password").status_code == 200
    with sessions() as db:
        assert not db.get(BrowserOwner, "personal-owner").active
        assert before == [(u.id, u.password_hash, u.api_key_hash, u.active) for u in db.scalars(select(User).order_by(User.id))]
        assert db.get(Family, family_id).active
        assert not db.scalar(select(Token)).revoked
    assert get(agent_client, "/oauth/connections").status_code == 200
    assert agent_client.get("/api/profile", base_url=BASE, headers={"Authorization": "Bearer "+tokens["access_token"]}).json["participant_id"] == "agent-b"
    refreshed = agent_client.post("/oauth/token", base_url=BASE, data=dict(grant_type="refresh_token",
        client_id=cid, refresh_token=tokens["refresh_token"], resource=BASE+"/mcp"))
    assert refreshed.status_code == 200


@pytest.mark.parametrize("remove_first", [False, True])
def test_owner_replacement_reuses_email_and_preserves_agent_authority(owner_app, remove_first):
    agent_client, cid, tokens = participant_connection(owner_app)
    client = owner_app.test_client()
    assert login(client).status_code == 302
    sessions = owner_app.extensions["sessions"]
    with sessions() as db:
        agent_before = [(u.id, u.password_hash, u.api_key_hash, u.active)
                      for u in db.scalars(select(User).order_by(User.id))]
        family_id = db.scalar(select(Token.family))
    if remove_first:
        owner_app.config["BROWSER_OWNERS"] = []
        with sessions.begin() as db:
            bootstrap(db, owner_app.config)
        assert get(client, "/test/browser-identity").json["identity"] is None
    replacement_password = "synthetic-replacement-owner-password"
    owner_app.config["BROWSER_OWNERS"] = [{"id": "replacement-owner", "name": "Replacement Owner",
        "email": "personal@example.com", "password_hash": generate_password_hash(replacement_password)}]
    validate_settings(owner_app.config)
    with sessions.begin() as db:
        bootstrap(db, owner_app.config)
    assert get(client, "/test/browser-identity").json["identity"] is None
    assert login(client).status_code == 200
    assert login(client, password=replacement_password).status_code == 302
    assert get(client, "/test/browser-identity").json["identity"] == "replacement-owner"
    with sessions() as db:
        previous = db.get(BrowserOwner, "personal-owner")
        replacement = db.get(BrowserOwner, "replacement-owner")
        assert not previous.active and replacement.active
        assert previous.email == replacement.email == "personal@example.com"
        assert agent_before == [(u.id, u.password_hash, u.api_key_hash, u.active)
                              for u in db.scalars(select(User).order_by(User.id))]
        assert db.get(Family, family_id).active
        assert not db.scalar(select(Token)).revoked
    assert get(agent_client, "/oauth/connections").status_code == 200
    assert agent_client.get("/api/profile", base_url=BASE,
        headers={"Authorization": "Bearer "+tokens["access_token"]}).json["participant_id"] == "agent-b"
    assert agent_client.post("/oauth/token", base_url=BASE, data=dict(grant_type="refresh_token",
        client_id=cid, refresh_token=tokens["refresh_token"], resource=BASE+"/mcp")).status_code == 200


def test_owner_email_swap_preserves_same_id_password_sessions(owner_app):
    other_password = "synthetic-other-owner-password"
    first = dict(owner_app.config["BROWSER_OWNERS"][0])
    second = {"id": "second-owner", "name": "Second Owner", "email": "second@example.com",
              "password_hash": generate_password_hash(other_password)}
    owner_app.config["BROWSER_OWNERS"] = [first, second]
    sessions = owner_app.extensions["sessions"]
    with sessions.begin() as db:
        bootstrap(db, owner_app.config)
    first_client, second_client = owner_app.test_client(), owner_app.test_client()
    assert login(first_client).status_code == 302
    assert login(second_client, email="second@example.com", password=other_password).status_code == 302
    first["email"], second["email"] = second["email"], first["email"]
    validate_settings(owner_app.config)
    with sessions.begin() as db:
        bootstrap(db, owner_app.config)
    assert get(first_client, "/test/browser-identity").json["identity"] == "personal-owner"
    assert get(second_client, "/test/browser-identity").json["identity"] == "second-owner"
    assert login(owner_app.test_client(), email="second@example.com").status_code == 302
    assert login(owner_app.test_client(), password=other_password).status_code == 302
    with sessions() as db:
        assert db.get(BrowserOwner, "personal-owner").email == "second@example.com"
        assert db.get(BrowserOwner, "second-owner").email == "personal@example.com"


def test_owner_database_uniqueness_applies_only_to_active_emails(owner_app):
    sessions = owner_app.extensions["sessions"]
    password_hash = owner_app.config["BROWSER_OWNERS"][0]["password_hash"]
    with sessions.begin() as db:
        db.add(BrowserOwner(id="inactive-owner", name="Inactive Owner", email="personal@example.com",
                            password_hash=password_hash, active=False))
    with pytest.raises(IntegrityError):
        with sessions.begin() as db:
            db.add(BrowserOwner(id="duplicate-owner", name="Duplicate Owner", email="personal@example.com",
                                password_hash=password_hash, active=True))
            db.flush()
    with pytest.raises(IntegrityError):
        with sessions.begin() as db:
            db.get(BrowserOwner, "inactive-owner").active = True
            db.flush()
    with sessions() as db:
        assert db.get(BrowserOwner, "personal-owner").active
        assert not db.get(BrowserOwner, "inactive-owner").active
        assert db.get(BrowserOwner, "duplicate-owner") is None


def test_owner_synchronization_rollback_preserves_previous_session(owner_app):
    client = owner_app.test_client()
    assert login(client).status_code == 302
    settings = dict(owner_app.config)
    settings["BROWSER_OWNERS"] = [{**settings["BROWSER_OWNERS"][0], "id": "replacement-owner"}]
    sessions = owner_app.extensions["sessions"]
    with pytest.raises(RuntimeError, match="synthetic transaction rollback"):
        with sessions.begin() as db:
            bootstrap(db, settings)
            db.flush()
            assert not db.get(BrowserOwner, "personal-owner").active
            assert db.get(BrowserOwner, "replacement-owner").active
            raise RuntimeError("synthetic transaction rollback")
    assert get(client, "/test/browser-identity").json["identity"] == "personal-owner"
    with sessions() as db:
        assert db.get(BrowserOwner, "personal-owner").active
        assert db.get(BrowserOwner, "replacement-owner") is None


def test_owner_cannot_authorize_or_disconnect_agent(owner_app):
    _, cid, _ = participant_connection(owner_app)
    client = owner_app.test_client()
    login(client)
    with owner_app.extensions["sessions"]() as db:
        family_id = db.scalar(select(Family.id))
        counts = [len(db.scalars(select(model)).all()) for model in (Code, Family, Token)]
    fields = oauth_fields(cid)
    assert get(client, "/oauth/authorize", query_string=fields).status_code == 403
    assert post(client, "/oauth/authorize", data={**fields, "approve": "yes"}).status_code == 403
    assert get(client, "/oauth/connections").status_code == 403
    assert post(client, "/oauth/connections", data={"family": family_id}).status_code == 403
    with owner_app.extensions["sessions"]() as db:
        assert counts == [len(db.scalars(select(model)).all()) for model in (Code, Family, Token)]
        assert db.get(Family, family_id).active
        assert not db.scalar(select(Token)).revoked


def test_owner_cookie_password_and_hash_have_no_machine_authority(owner_app):
    client = owner_app.test_client()
    login(client)
    with owner_app.extensions["sessions"]() as db:
        password_hash = db.get(BrowserOwner, "personal-owner").password_hash
    for credential in (None, OWNER_PASSWORD, password_hash, digest(password_hash)):
        headers = {"Authorization": "Bearer "+credential} if credential else {}
        assert client.get("/api/profile", base_url=BASE, headers=headers).status_code == 401
        assert client.post("/api/messages", base_url=BASE, headers=headers, json={}).status_code == 401
        assert client.post("/mcp", base_url=BASE, headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 401
    # Public client registration still creates no user, grant, family or token.
    cid = register(client)
    assert get(client, "/oauth/authorize", query_string=oauth_fields(cid)).status_code == 403
    with owner_app.extensions["sessions"]() as db:
        assert all(not db.scalars(select(model)).all() for model in (Code, Family, Token))
        assert db.get(User, "personal-owner") is None
        assert db.get(Participant, "personal-owner") is None
    # Supplying an actual Agent bearer retains its own participant identity.
    key = owner_app.extensions["test_credentials"]["agent-a"]
    assert client.get("/api/profile", base_url=BASE, headers={"Authorization": "Bearer "+key}).json["participant_id"] == "agent-a"


@pytest.mark.parametrize("change", [
    {"id": "agent-b"}, {"email": "AGENT-B@example.com"}, {"password_hash": ""},
    {"id": " "}, {"name": ""}, {"email": ""}, {"password_hash": 123},
    {"api_key_hash": "synthetic-key-hash"}, {"api_key_env": "SYNTHETIC_API_KEY"},
    {"service": "synthetic"}, {"mcp": {"token": "synthetic"}},
])
def test_owner_config_rejects_ambiguous_identity_and_machine_fields(owner_app, change):
    settings = dict(owner_app.config)
    settings["BROWSER_OWNERS"] = [{**owner_app.config["BROWSER_OWNERS"][0], **change}]
    with pytest.raises(ValueError):
        validate_settings(settings)


def test_owner_config_duplicates_and_backward_compatibility(owner_app):
    settings = dict(owner_app.config)
    original = settings["BROWSER_OWNERS"][0]
    for duplicate in ({**original, "email": "other@example.com"},
                      {**original, "id": "other-owner", "email": "PERSONAL@example.com"}):
        settings["BROWSER_OWNERS"] = [original, duplicate]
        with pytest.raises(ValueError):
            validate_settings(settings)
    settings.pop("BROWSER_OWNERS")
    validate_settings(settings)
    assert settings["BROWSER_OWNERS"] == []


def test_runtime_owner_password_env_and_optional_owners(owner_app, monkeypatch, tmp_path):
    config = {"participants": [{"id": "agent-a", "name": "Agent A", "email": "agent-a@example.com",
        "password_hash_env": "SYNTHETIC_AGENT_A_PASSWORD_HASH"}], "webhook_participant_id": "agent-a"}
    path = tmp_path/"synthetic-runtime.json"
    monkeypatch.setenv("BRIDGE_CONFIG", str(path))
    for setting, env in (("DATABASE_URL", "DATABASE_URL"), ("BASE_URL", "BASE_URL"),
                         ("SECRET_KEY", "SESSION_SECRET"), ("ENCRYPTION_KEY", "ENCRYPTION_KEY")):
        monkeypatch.setenv(env, owner_app.config[setting])
    monkeypatch.setenv("SYNTHETIC_AGENT_A_PASSWORD_HASH", owner_app.config["USERS"][0]["password_hash"])
    monkeypatch.setenv("SYNTHETIC_OWNER_PASSWORD_HASH", owner_app.config["BROWSER_OWNERS"][0]["password_hash"])
    path.write_text(json.dumps(config))
    assert load_settings()["BROWSER_OWNERS"] == []
    config["owners"] = [{"id": "personal-owner", "name": "Personal Owner", "email": "personal@example.com",
        "password_hash_env": "SYNTHETIC_OWNER_PASSWORD_HASH"}]
    path.write_text(json.dumps(config))
    loaded = load_settings()
    assert loaded["BROWSER_OWNERS"][0]["password_hash"] == owner_app.config["BROWSER_OWNERS"][0]["password_hash"]
    config["owners"][0]["api_key_env"] = "SYNTHETIC_IGNORED_API_KEY"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError):
        load_settings()

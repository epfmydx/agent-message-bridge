"""Synthetic Agent Message Bridge credentials; no provider connection is made."""
import base64
import hashlib
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest
from flask import Flask, g, jsonify
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash

from bridge.auth import bearer, bootstrap_users, digest, family_active, install_auth
from bridge.models import Base, Participant, Subscription, database
from bridge.models_auth import Client, Code, Family, Token, User

BASE = "https://bridge.example.com"
RESOURCE = BASE+"/mcp"
CALLBACK = "https://client.example.com/callback"
VERIFIER = "v"*64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


@pytest.fixture
def auth_app(tmp_path):
    app = Flask(__name__, template_folder="../bridge/templates")
    app.config.update(TESTING=True, SECRET_KEY="synthetic-session-key", BASE_URL=BASE)
    root_url = os.environ.get("TEST_DATABASE_URL")
    admin = schema = None
    if root_url:
        admin = create_engine(root_url, hide_parameters=True)
        schema = "bridge_auth_test_"+uuid.uuid4().hex
        with admin.begin() as db:
            db.execute(text('CREATE SCHEMA "'+schema+'"'))
        url = make_url(root_url).update_query_dict({"options":"-csearch_path="+schema}).render_as_string(hide_password=False)
    else:
        url = "sqlite:///"+str(tmp_path/"auth.sqlite")
    engine, sessions = database(url)
    app.extensions["engine"] = engine
    Base.metadata.create_all(engine)
    app.extensions["sessions"] = sessions
    with sessions.begin() as db:
        db.add(Participant(id="owner", name="Agent B"))
        db.flush()
        bootstrap_users(db, [{"id":"owner", "email":"owner@example.com", "password_hash":generate_password_hash("synthetic-password")}])

    @app.before_request
    def start():
        g.db = sessions()

    @app.after_request
    def finish(response):
        if response.status_code < 400 or g.db.info.get("commit_security_changes"):
            g.db.commit()
        else:
            g.db.rollback()
        return response

    @app.teardown_request
    def close(error):
        g.db.close()

    @app.get("/probe")
    def probe():
        identity = bearer(g.db)
        return jsonify(owner=identity.owner_id, client_id=identity.client_id, family=identity.family)

    install_auth(app)
    from bridge.web import install_web
    install_web(app)
    try:
        yield app
    finally:
        engine.dispose()
        if admin:
            with admin.begin() as db:
                db.execute(text('DROP SCHEMA "'+schema+'" CASCADE'))
            admin.dispose()


def browser(app):
    return app.test_client()


def csrf_from(response):
    return re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()


def register(client, method="none", **extra):
    return client.post("/oauth/register", base_url=BASE, json={"redirect_uris":[CALLBACK], "grant_types":["authorization_code", "refresh_token"], "token_endpoint_auth_method":method, **extra})


def login(client):
    page = client.get("/login", base_url=BASE)
    return client.post("/login", base_url=BASE, data={"csrf":csrf_from(page), "email":"owner@example.com", "password":"synthetic-password"})


def authorize(client, client_id, **extra):
    login(client)
    data = dict(response_type="code", client_id=client_id, redirect_uri=CALLBACK, scope="bridge:messages", resource=RESOURCE,
                state="synthetic-state", code_challenge=CHALLENGE, code_challenge_method="S256")
    data.update(extra)
    page = client.get("/oauth/authorize", base_url=BASE, query_string=data)
    if page.status_code != 200:
        return page
    return client.post("/oauth/authorize", base_url=BASE, data={**data, "csrf":csrf_from(page), "approve":"yes"})


def obtain_code(client, client_id):
    response = authorize(client, client_id)
    assert response.status_code == 302, response.data
    query = parse_qs(urlsplit(response.location).query)
    assert query["state"] == ["synthetic-state"]
    return query["code"][0]


def exchange(client, cid, code, **extra):
    return client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code", client_id=cid,
                       code=code, redirect_uri=CALLBACK, code_verifier=VERIFIER, resource=RESOURCE, **extra))


def refresh(client, cid, value, **extra):
    return client.post("/oauth/token", base_url=BASE, data=dict(grant_type="refresh_token", client_id=cid,
                       refresh_token=value, resource=RESOURCE, **extra))


def probe(client, value):
    return client.get("/probe", base_url=BASE, headers={"Authorization":"Bearer "+value})


def test_metadata_and_dcr_no_users_or_grants(auth_app):
    client = browser(auth_app)
    assert client.get("/.well-known/oauth-authorization-server", base_url=BASE).json["code_challenge_methods_supported"] == ["S256"]
    assert client.get("/.well-known/oauth-protected-resource/mcp", base_url=BASE).json["resource"] == RESOURCE
    response = register(client)
    assert response.status_code == 201
    with auth_app.extensions["sessions"]() as db:
        assert len(db.scalars(select(User)).all()) == 1
        assert len(db.scalars(select(Participant)).all()) == 1
    for uri in ["https://client.example.com/*", "http://client.example.com/callback", "https://client.example.com/callback#x", "https://user@client.example.com/callback", "https://client.example.com/\ncallback"]:
        assert register(client, redirect_uris=[uri]).status_code == 400
    assert register(client, redirect_uris=["http://127.0.0.1:5555/callback"]).status_code == 201


def test_pkce_csrf_and_exact_redirect(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    assert client.post("/login", base_url=BASE, data={"email":"owner@example.com", "password":"synthetic-password"}).status_code == 400
    assert authorize(client, cid, redirect_uri=CALLBACK+"/other").status_code == 400
    assert authorize(client, cid, code_challenge_method="plain").status_code == 400
    assert authorize(client, cid, code_challenge="", code_challenge_method="").status_code == 400
    fields = dict(response_type="code", client_id=cid, redirect_uri=CALLBACK, scope="bridge:messages", resource=RESOURCE,
                  code_challenge=CHALLENGE, code_challenge_method="S256", approve="yes")
    assert client.post("/oauth/authorize", base_url=BASE, data=fields).status_code == 400
    code = obtain_code(client, cid)
    bad = client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code", client_id=cid, code=code,
                      redirect_uri=CALLBACK, code_verifier="z"*64, resource=RESOURCE))
    assert bad.status_code == 400
    token = exchange(client, cid, code)
    assert token.status_code == 200, token.data
    assert probe(client, token.json["access_token"]).status_code == 200
    # Credentials and authorization codes never appear verbatim in persistent records.
    with auth_app.extensions["sessions"]() as db:
        assert db.scalar(select(Code)).code_hash != code
        assert db.scalar(select(Token)).access_hash != token.json["access_token"]
    assert exchange(client, cid, code).status_code == 400
    assert probe(client, token.json["access_token"]).status_code == 401


def test_refresh_rotation_reuse_and_subscription_disconnect(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    first = exchange(client, cid, obtain_code(client, cid)).json
    with auth_app.extensions["sessions"].begin() as db:
        item = db.scalar(select(Token))
        family = item.family
        db.add(Subscription(id="sub", owner_id="owner", client_id=cid, family=family, callback="https://callback.example.com/events", secret="synthetic", start_sequence=0))
    second = refresh(client, cid, first["refresh_token"])
    assert second.status_code == 200, second.data
    assert second.json["refresh_token"] != first["refresh_token"]
    assert probe(client, first["access_token"]).status_code == 401
    assert probe(client, second.json["access_token"]).status_code == 200
    assert refresh(client, cid, first["refresh_token"]).status_code == 400
    assert probe(client, second.json["access_token"]).status_code == 401
    with auth_app.extensions["sessions"]() as db:
        assert not family_active(db, "owner", cid, family)
        sub = db.get(Subscription, "sub")
        assert not sub.active and sub.generation == 2


def test_audience_scope_client_and_user_binding(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    other = register(client).json["client_id"]
    code = obtain_code(client, cid)
    assert exchange(client, other, code).status_code == 400
    bad_audience = client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code", client_id=cid,
                   code=code, redirect_uri=CALLBACK, code_verifier=VERIFIER, resource="https://other.example.com/mcp"))
    assert bad_audience.status_code == 400
    token = exchange(client, cid, code).json
    assert refresh(client, other, token["refresh_token"]).status_code == 400
    assert refresh(client, cid, token["refresh_token"], scope="bridge:messages other").status_code == 400
    assert probe(client, token["access_token"]).status_code == 200
    with auth_app.extensions["sessions"].begin() as db:
        db.scalar(select(Token)).resource = "https://other.example.com/mcp"
    assert probe(client, token["access_token"]).status_code == 401
    with auth_app.extensions["sessions"].begin() as db:
        db.scalar(select(Token)).resource = RESOURCE
        db.get(User, "owner").active = False
    assert probe(client, token["access_token"]).status_code == 401


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post", "none"])
def test_revocation_and_confidential_authentication(auth_app, method):
    client = browser(auth_app)
    registration = register(client, method).json
    cid = registration["client_id"]
    code = obtain_code(client, cid)
    data = dict(grant_type="authorization_code", client_id=cid, code=code, redirect_uri=CALLBACK,
                code_verifier=VERIFIER, resource=RESOURCE)
    headers = {}
    if method == "client_secret_basic":
        headers["Authorization"] = "Basic "+base64.b64encode((cid+":"+registration["client_secret"]).encode()).decode()
        data.pop("client_id")
    elif method == "client_secret_post":
        data["client_secret"] = registration["client_secret"]
    response = client.post("/oauth/token", base_url=BASE, data=data, headers=headers)
    assert response.status_code == 200, response.data
    revoke_data = dict(token=response.json["refresh_token"])
    if method != "client_secret_basic":
        revoke_data["client_id"] = cid
    if method == "client_secret_post":
        revoke_data["client_secret"] = registration["client_secret"]
    revoked = client.post("/oauth/revoke", base_url=BASE, data=revoke_data, headers=headers)
    assert revoked.status_code == 200, revoked.data
    assert probe(client, response.json["access_token"]).status_code == 401


def test_participant_deactivation_revokes_access(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    first = exchange(client, cid, obtain_code(client, cid)).json
    with auth_app.extensions["sessions"].begin() as db:
        db.get(Participant, "owner").active = False
    assert probe(client, first["access_token"]).status_code == 401
    assert refresh(client, cid, first["refresh_token"]).status_code == 400


def test_disconnect_owner_csrf_and_security_headers(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    tokens = exchange(client, cid, obtain_code(client, cid)).json
    page = client.get("/oauth/connections", base_url=BASE)
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert "HttpOnly" in page.headers["Set-Cookie"] and "Secure" in page.headers["Set-Cookie"]
    family = re.search(rb'name="family" value="([^"]+)"', page.data)[1].decode()
    assert client.post("/oauth/connections", base_url=BASE, data={"family":family}).status_code == 400
    assert probe(client, tokens["access_token"]).status_code == 200
    assert client.post("/oauth/connections", base_url=BASE, data={"family":family, "csrf":csrf_from(page)}).status_code == 302
    assert probe(client, tokens["access_token"]).status_code == 401
    assert refresh(client, cid, tokens["refresh_token"]).status_code == 400


def test_no_password_grant_no_cross_client_revocation_or_query_injection(auth_app):
    client = browser(auth_app)
    registration = register(client, "client_secret_post").json
    cid = registration["client_id"]
    code = obtain_code(client, cid)
    # Confidential clients cannot exchange with missing credentials.
    assert exchange(client, cid, code).status_code in (400, 401)
    token = exchange(client, cid, code, client_secret=registration["client_secret"]).json
    other = register(client).json["client_id"]
    assert client.post("/oauth/revoke", base_url=BASE, data={"token":token["refresh_token"], "client_id":other}).status_code == 200
    assert probe(client, token["access_token"]).status_code == 200
    assert client.post("/oauth/token", base_url=BASE, data={"grant_type":"password", "client_id":other, "resource":RESOURCE,
                       "username":"owner@example.com", "password":"synthetic-password"}).status_code == 400
    assert client.post("/oauth/token?client_id="+other, base_url=BASE, data={"resource":RESOURCE}).status_code == 400
    assert client.post("/oauth/revoke?client_id="+other, base_url=BASE).status_code == 400
    for uri in ["https://client.example.com#", "https://@client.example.com/callback", "https://client.example.com';script-src/callback"]:
        assert register(client, redirect_uris=[uri]).status_code == 400


def test_second_configured_user_issues_own_tokens_and_absent_users_deactivate(auth_app):
    client = browser(auth_app)
    second = {"id":"second", "email":"second@example.com", "password_hash":generate_password_hash("synthetic-password")}
    with auth_app.extensions["sessions"].begin() as db:
        db.add(Participant(id="second", name="Agent A"))
        db.flush()
        bootstrap_users(db, [second])
    page = client.get("/login", base_url=BASE)
    assert client.post("/login", base_url=BASE, data=dict(csrf=csrf_from(page), email=second["email"], password="synthetic-password")).status_code == 302
    cid = register(client).json["client_id"]
    fields = dict(response_type="code", client_id=cid, redirect_uri=CALLBACK, scope="bridge:messages", resource=RESOURCE,
                  code_challenge=CHALLENGE, code_challenge_method="S256")
    page = client.get("/oauth/authorize", base_url=BASE, query_string=fields)
    approved = client.post("/oauth/authorize", base_url=BASE, data={**fields, "csrf":csrf_from(page), "approve":"yes"})
    code = parse_qs(urlsplit(approved.location).query)["code"][0]
    token = exchange(client, cid, code)
    assert token.status_code == 200
    assert probe(client, token.json["access_token"]).json["owner"] == "second"
    with auth_app.extensions["sessions"]() as db:
        assert not db.get(User, "owner").active


def test_dcr_code_only_and_metadata_are_not_fetched(auth_app):
    client = browser(auth_app)
    # RFC 7591 defaults grant_types to authorization_code. URL metadata is never fetched.
    registration = client.post("/oauth/register", base_url=BASE, json={"redirect_uris":[CALLBACK],
        "token_endpoint_auth_method":"none", "client_uri":"https://metadata.example.com/client"})
    assert registration.status_code == 201
    assert registration.json["grant_types"] == ["authorization_code"]
    cid = registration.json["client_id"]
    response = exchange(client, cid, obtain_code(client, cid))
    assert response.status_code == 200
    assert "refresh_token" not in response.json
    assert probe(client, response.json["access_token"]).status_code == 200


def concurrent_credential_requests(app, operation):
    """Release two native PostgreSQL client-row lock acquisitions together."""
    engine = app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL locking requires TEST_DATABASE_URL")
    barrier = threading.Barrier(2)
    acquisitions = []
    guard = threading.Lock()

    def synchronize(connection, cursor, statement, parameters, context, executemany):
        if "FROM oauth_clients" in statement and "FOR UPDATE" in statement:
            with guard:
                acquisitions.append(id(connection))
            # Both transactions have entered client authentication before either
            # may acquire the row lock and perform credential redemption.
            barrier.wait(timeout=10)

    def worker():
        # Flask test clients and request/DB contexts must belong to each thread.
        return operation(browser(app))

    event.listen(engine, "before_cursor_execute", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            responses = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(engine, "before_cursor_execute", synchronize)
    assert len(acquisitions) == 2
    assert len(set(acquisitions)) == 2
    assert sorted(response.status_code for response in responses) == [200, 400]
    return next(response.json for response in responses if response.status_code == 200)


def test_postgres_concurrent_authorization_code_redemption_revokes_family(auth_app):
    if auth_app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL locking requires TEST_DATABASE_URL")
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    code = obtain_code(client, cid)
    issued = concurrent_credential_requests(auth_app, lambda worker: exchange(worker, cid, code))
    with auth_app.extensions["sessions"]() as db:
        tokens = db.scalars(select(Token)).all()
        assert len(tokens) == 1  # Exactly one exchange issued credentials.
        assert tokens[0].revoked
        assert db.scalar(select(Code)).used
        assert not db.get(Family, tokens[0].family).active
        assert not family_active(db, "owner", cid, tokens[0].family)
    # The losing redemption commits replay revocation despite its OAuth 400.
    assert probe(client, issued["access_token"]).status_code == 401
    assert refresh(client, cid, issued["refresh_token"]).status_code == 400
    with auth_app.extensions["sessions"]() as db:
        assert len(db.scalars(select(Token)).all()) == 1


def test_postgres_concurrent_refresh_reuse_revokes_issued_token_and_subscription(auth_app):
    if auth_app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL locking requires TEST_DATABASE_URL")
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    original = exchange(client, cid, obtain_code(client, cid)).json
    with auth_app.extensions["sessions"].begin() as db:
        initial = db.scalar(select(Token))
        family = initial.family
        db.add(Subscription(id="concurrent-sub", owner_id="owner", client_id=cid, family=family,
                            callback="https://callback.example.com/events",
                            secret="synthetic", start_sequence=0))
    issued = concurrent_credential_requests(auth_app, lambda worker: refresh(worker, cid, original["refresh_token"]))
    with auth_app.extensions["sessions"]() as db:
        tokens = db.scalars(select(Token)).all()
        assert len(tokens) == 2  # Initial issuance plus exactly one rotation.
        assert all(token.revoked for token in tokens)
        assert {token.family for token in tokens} == {family}
        assert not db.get(Family, family).active
        assert not family_active(db, "owner", cid, family)
        subscription = db.get(Subscription, "concurrent-sub")
        assert not subscription.active and subscription.generation == 2
    for credentials in (original, issued):
        assert probe(client, credentials["access_token"]).status_code == 401
        assert refresh(client, cid, credentials["refresh_token"]).status_code == 400
    with auth_app.extensions["sessions"]() as db:
        assert len(db.scalars(select(Token)).all()) == 2
        assert db.get(Subscription, "concurrent-sub").generation == 2


def test_service_key_sender_binding_rotation_and_removal(auth_app):
    client = browser(auth_app)
    settings = [{"id":"owner", "email":"owner@example.com", "password_hash":"synthetic-password-hash",
                 "api_key_hash":digest("synthetic-service-key")}]
    with auth_app.extensions["sessions"].begin() as db:
        bootstrap_users(db, settings)
    result = probe(client, "synthetic-service-key")
    assert result.status_code == 200
    assert result.json["owner"] == "owner"
    assert result.json["client_id"] == "service:owner"
    family = result.json["family"]
    with auth_app.extensions["sessions"].begin() as db:
        assert family_active(db, "owner", "service:owner", family)
        assert not family_active(db, "other", "service:owner", family)
        db.add(Subscription(id="service-sub", owner_id="owner", client_id="service:owner", family=family,
                            callback="https://callback.example.com/events", secret="synthetic", start_sequence=0))
        assert db.get(User, "owner").api_key_hash != "synthetic-service-key"
    # Claimed sender in payload/query cannot change authenticated identity.
    assert client.get("/probe?owner_id=other", base_url=BASE,
        headers={"Authorization":"Bearer synthetic-service-key"}).json["owner"] == "owner"
    settings[0]["api_key_hash"] = digest("rotated-synthetic-service-key")
    with auth_app.extensions["sessions"].begin() as db:
        bootstrap_users(db, settings)
    assert probe(client, "synthetic-service-key").status_code == 401
    rotated = probe(client, "rotated-synthetic-service-key")
    assert rotated.status_code == 200 and rotated.json["family"] != family
    with auth_app.extensions["sessions"]() as db:
        assert not family_active(db, "owner", "service:owner", family)
        assert not db.get(Subscription, "service-sub").active
        assert db.get(Subscription, "service-sub").generation == 2
    settings[0].pop("api_key_hash")
    with auth_app.extensions["sessions"].begin() as db:
        bootstrap_users(db, settings)
    assert probe(client, "rotated-synthetic-service-key").status_code == 401


def test_password_rotation_ends_oauth_connections_and_browser_session(auth_app):
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    credentials = exchange(client, cid, obtain_code(client, cid)).json
    with auth_app.extensions["sessions"].begin() as db:
        bootstrap_users(db, [{"id":"owner", "email":"owner@example.com",
            "password_hash":generate_password_hash("rotated-synthetic-password")}])
    assert probe(client, credentials["access_token"]).status_code == 401
    assert refresh(client, cid, credentials["refresh_token"]).status_code == 400
    assert client.get("/oauth/connections", base_url=BASE).location == "/login"


def test_consent_escapes_registered_name_and_callback(auth_app):
    client = browser(auth_app)
    cid = register(client, client_name='<script>alert("synthetic")</script>').json["client_id"]
    login(client)
    page = client.get("/oauth/authorize", base_url=BASE, query_string=dict(response_type="code", client_id=cid,
        redirect_uri=CALLBACK, scope="bridge:messages", resource=RESOURCE,
        code_challenge=CHALLENGE, code_challenge_method="S256"))
    assert page.status_code == 200
    assert b"<script>" not in page.data and b"&lt;script&gt;" in page.data


def test_two_active_agents_keep_oauth_and_service_identity_separate(auth_app):
    settings = [
        {"id":"owner", "email":"owner@example.com", "password_hash":generate_password_hash("synthetic-password"),
         "api_key_hash":digest("agent_b-synthetic-key")},
        {"id":"webhook", "email":"webhook@example.com", "password_hash":generate_password_hash("synthetic-password"),
         "api_key_hash":digest("webhook-synthetic-key")},
    ]
    with auth_app.extensions["sessions"].begin() as db:
        db.add(Participant(id="webhook", name="Agent A"))
        db.flush()
        bootstrap_users(db, settings)
    agent_b, webhook = browser(auth_app), browser(auth_app)
    assert probe(agent_b, "agent_b-synthetic-key").json["owner"] == "owner"
    assert probe(webhook, "webhook-synthetic-key").json["owner"] == "webhook"
    cid = register(agent_b).json["client_id"]
    credentials = exchange(agent_b, cid, obtain_code(agent_b, cid)).json
    assert probe(agent_b, credentials["access_token"]).json["owner"] == "owner"
    with auth_app.extensions["sessions"]() as db:
        family = db.scalar(select(Token)).family
    page = webhook.get("/login", base_url=BASE)
    assert webhook.post("/login", base_url=BASE, data=dict(csrf=csrf_from(page),
        email="webhook@example.com", password="synthetic-password")).status_code == 302
    page = webhook.get("/oauth/connections", base_url=BASE)
    assert family.encode() not in page.data
    assert webhook.post("/oauth/connections", base_url=BASE,
        data={"csrf":csrf_from(page), "family":family}).status_code == 302
    assert probe(agent_b, credentials["access_token"]).status_code == 200


def test_postgres_password_rotation_during_refresh_has_no_family_fk_deadlock(auth_app):
    """Refresh holds Token; configuration revocation holds Family before both proceed."""
    engine = auth_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL locking requires TEST_DATABASE_URL")
    client = browser(auth_app)
    cid = register(client).json["client_id"]
    original = exchange(client, cid, obtain_code(client, cid)).json
    sessions = auth_app.extensions["sessions"]
    with sessions.begin() as db:
        family = db.scalar(select(Token.family))
        db.add(Subscription(id="password-race-sub", owner_id="owner", client_id=cid, family=family,
            callback="https://callback.example.com/events", secret="synthetic", start_sequence=0))
    token_locked = threading.Event()
    family_locked = threading.Event()
    role = threading.local()
    acquired_family_lock = []

    def synchronize(connection, cursor, statement, parameters, context, executemany):
        if (getattr(role, "name", None) == "refresh" and "FROM oauth_tokens" in statement
                and "FOR UPDATE" in statement):
            token_locked.set()
            assert family_locked.wait(10), "Configuration did not acquire the family lock"
        elif (getattr(role, "name", None) == "configuration" and "FROM oauth_families" in statement
                and "FOR " in statement):
            acquired_family_lock.append(statement)
            family_locked.set()

    def refreshing():
        role.name = "refresh"
        return refresh(browser(auth_app), cid, original["refresh_token"])

    password_hash = generate_password_hash("rotated-synthetic-password")

    def rotating():
        role.name = "configuration"
        assert token_locked.wait(10), "Refresh did not acquire its token lock"
        with sessions.begin() as db:
            # An actual bounded DB failure replaces an indefinitely hanging test.
            db.execute(text("SET LOCAL statement_timeout = '15s'"))
            bootstrap_users(db, [{"id":"owner", "email":"owner@example.com", "password_hash":password_hash}])

    event.listen(engine, "after_cursor_execute", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            refreshed = pool.submit(refreshing)
            rotated = pool.submit(rotating)
            issued_response = refreshed.result(timeout=25)
            rotated.result(timeout=25)
    finally:
        token_locked.set()
        family_locked.set()
        event.remove(engine, "after_cursor_execute", synchronize)
    assert acquired_family_lock and "FOR NO KEY UPDATE" in acquired_family_lock[0]
    assert issued_response.status_code == 200, issued_response.data
    issued = issued_response.json
    with sessions() as db:
        assert db.get(User, "owner").password_hash == password_hash
        assert not db.get(Family, family).active
        assert not family_active(db, "owner", cid, family)
        sub = db.get(Subscription, "password-race-sub")
        assert not sub.active and sub.generation == 2
        # A concurrent INSERT may be outside revocation UPDATE's initial snapshot.
        # The durable family, rather than that row's revoked flag, is authoritative.
        assert len(db.scalars(select(Token)).all()) == 2
    for credential in (original, issued):
        assert probe(client, credential["access_token"]).status_code == 401
        assert refresh(client, cid, credential["refresh_token"]).status_code == 400

"""Synthetic credential handover, durable form replay, and config authority."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event, select, text
from werkzeug.security import check_password_hash, generate_password_hash

from bridge.app import bootstrap
from bridge.auth import digest, family_active, service_client, service_family
from bridge.credentials import create_api_key, credential_view, reset_password, revoke_api_key
from bridge.errors import Conflict, Invalid
from bridge.models import Member, Message, Participant, Subscription, Thread
from bridge.models_auth import APIKey, Client, Code, CredentialOperation, Family, Token, User
from bridge.schema import ensure_profile_schema
from tests.test_events import subscribe_params
from test_profiles import BASE, get, hidden, post, profile_app, sign_in


def make_key(app, ident="agent-b", token="synthetic-key-form"):
    with app.extensions["sessions"].begin() as db:
        user = db.get(User, ident)
        return create_api_key(db, user, user.credential_generation, token)


def probe(app, raw):
    return app.test_client().get("/api/profile", headers={"Authorization": "Bearer " + raw})


def subscription(app, raw):
    return app.test_client().post("/mcp", headers={"Authorization": "Bearer " + raw},
        json={"jsonrpc": "2.0", "id": "synthetic", "method": "events/subscribe", "params": subscribe_params()})


def oauth_connection(db, owner="agent-b"):
    db.add(Client(client_id="synthetic-client", name="Synthetic", redirect_uris=["https://client.example.com/callback"], auth_method="none"))
    db.flush()
    db.add(Family(id="synthetic-family", owner_id=owner, client_id="synthetic-client"))
    db.flush()
    db.add(Token(id="synthetic-token", owner_id=owner, client_id="synthetic-client", family="synthetic-family",
                 access_hash=digest("synthetic-oauth-access"), resource="https://bridge.example.com/mcp", scope="bridge:messages",
                 expires_at=9e10, refresh_expires_at=9e10))
    db.add(Subscription(id="synthetic-oauth-sub", owner_id=owner, client_id="synthetic-client", family="synthetic-family",
                        callback="https://oauth.example.com/events", secret="synthetic", start_sequence=0))


def test_same_callback_handover_selected_revoke_and_secret_storage(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    old = app.extensions["test_credentials"]["agent-b"]
    old_sub = subscription(app, old).json["result"]["id"]
    raw, key_id = make_key(app)
    new_sub = subscription(app, raw).json["result"]["id"]
    assert old_sub != new_sub
    assert probe(app, old).status_code == probe(app, raw).status_code == 200
    with sessions.begin() as db:
        oauth_connection(db)
        user = db.get(User, "agent-b")
        view = credential_view(db, user)
        assert {k["id"] for k in view["keys"]} == {"legacy", key_id}
        assert raw not in str(view) and digest(raw) not in str(view)
        assert db.get(APIKey, key_id).key_hash == digest(raw)
        operation = db.get(CredentialOperation, digest("synthetic-key-form"))
        assert operation.key_id == key_id
        assert raw not in str(vars(operation))
        assert family_active(db, user.id, service_client(user.id, key_id), service_family(digest(raw)))
        assert not family_active(db, "agent-a", service_client(user.id, key_id), service_family(digest(raw)))
        revoke_api_key(db, user, "legacy", view["generation"], "synthetic-revoke-legacy")
    assert probe(app, old).status_code == 401
    assert probe(app, raw).status_code == probe(app, "synthetic-oauth-access").status_code == 200
    with sessions() as db:
        assert not db.get(Subscription, old_sub).active
        assert db.get(Subscription, new_sub).active
        assert db.get(Subscription, "synthetic-oauth-sub").active
    with sessions.begin() as db:
        user = db.get(User, "agent-b")
        revoke_api_key(db, user, key_id, user.credential_generation, "synthetic-revoke-new")
    assert probe(app, raw).status_code == 401
    assert probe(app, "synthetic-oauth-access").status_code == 200
    with sessions() as db:
        assert not db.get(Subscription, new_sub).active


def test_password_reset_revokes_only_oauth_and_browser_digest(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, _ = make_key(app)
    old = app.extensions["test_credentials"]["agent-b"]
    service_sub = subscription(app, raw).json["result"]["id"]
    with sessions.begin() as db:
        oauth_connection(db)
        db.add(Thread(id="synthetic-thread"))
        db.flush()
        db.add(Member(thread_id="synthetic-thread", participant_id="agent-b"))
        user = db.get(User, "agent-b")
        old_digest = digest(user.password_hash)
        webhook = (db.get(Participant, user.id).webhook_generation, db.get(Participant, user.id).webhook_enabled)
        reset_password(db, user, "synthetic-new-password", user.credential_generation, "synthetic-password-form")
        assert check_password_hash(user.password_hash, "synthetic-new-password")
        assert digest(user.password_hash) != old_digest
        assert user.password_source == "database"
        assert db.get(Subscription, service_sub).active
        assert not db.get(Family, "synthetic-family").active
        assert not db.get(Subscription, "synthetic-oauth-sub").active
        assert db.get(Member, ("synthetic-thread", "agent-b"))
        assert (db.get(Participant, user.id).webhook_generation, db.get(Participant, user.id).webhook_enabled) == webhook
    assert probe(app, "synthetic-oauth-access").status_code == 401
    assert probe(app, old).status_code == probe(app, raw).status_code == 200


def test_unchanged_sync_upgrade_preserves_ui_then_config_type_change_wins(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, key_id = make_key(app)
    old = app.extensions["test_credentials"]["agent-b"]
    service_sub = subscription(app, raw).json["result"]["id"]
    with sessions.begin() as db:
        user = db.get(User, "agent-b")
        reset_password(db, user, "synthetic-ui-password", user.credential_generation, "synthetic-reset")
        revoke_api_key(db, user, "legacy", user.credential_generation, "synthetic-revoke")
    for _ in range(2):
        ensure_profile_schema(app.extensions["engine"])
        with sessions.begin() as db:
            bootstrap(db, app.config)
            user = db.get(User, "agent-b")
            assert check_password_hash(user.password_hash, "synthetic-ui-password")
            assert not user.api_key_hash
    assert probe(app, old).status_code == 401
    assert probe(app, raw).status_code == 200
    settings = dict(app.config, USERS=[dict(u) for u in app.config["USERS"]])
    item = next(u for u in settings["USERS"] if u["id"] == "agent-b")
    item["password_hash"] = generate_password_hash("synthetic-config-password")
    with sessions.begin() as db:
        bootstrap(db, settings)
        assert check_password_hash(db.get(User, "agent-b").password_hash, "synthetic-config-password")
        assert db.get(APIKey, key_id).active
    item.pop("api_key_hash")
    with sessions.begin() as db:
        bootstrap(db, settings)
        assert not db.get(APIKey, key_id).active
        assert not db.get(Subscription, service_sub).active
    assert probe(app, raw).status_code == 401
    with sessions.begin() as db:
        bootstrap(db, settings)
        assert not db.get(APIKey, key_id).active


def test_config_removal_revokes_all_and_unchanged_sync_cannot_reactivate(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, key_id = make_key(app)
    with sessions.begin() as db:
        oauth_connection(db)
    settings = dict(app.config, USERS=[u for u in app.config["USERS"] if u["id"] != "agent-b"])
    for _ in range(2):
        with sessions.begin() as db:
            bootstrap(db, settings)
            assert not db.get(User, "agent-b").active
            assert not db.get(Participant, "agent-b").active
            assert not db.get(APIKey, key_id).active
            assert not db.get(Family, "synthetic-family").active
    assert probe(app, raw).status_code == 401
    with sessions.begin() as db:
        bootstrap(db, app.config)
        assert db.get(User, "agent-b").active
        assert not db.get(APIKey, key_id).active
        assert not db.get(Family, "synthetic-family").active


def test_replay_generation_rollback_and_input_rejections(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, _ = make_key(app, token="synthetic-replay-token")
    with sessions.begin() as db:
        user = db.get(User, "agent-b")
        for generation, token in [(user.credential_generation, "synthetic-replay-token"), (1, "synthetic-stale-token")]:
            with pytest.raises(Conflict), db.begin_nested():
                create_api_key(db, user, generation, token)
        for generation, token in [(True, "x"), (0, "x"), (user.credential_generation, "")]:
            with pytest.raises(Invalid), db.begin_nested():
                create_api_key(db, user, generation, token)
        with pytest.raises(RuntimeError), db.begin_nested():
            interrupted, _ = create_api_key(db, user, user.credential_generation, "synthetic-interrupted")
            raise RuntimeError("synthetic interruption before commit")
        assert not db.get(CredentialOperation, digest("synthetic-interrupted"))
        assert not db.scalar(select(APIKey).where(APIKey.key_hash == digest(interrupted)))
        assert len(list(db.scalars(select(APIKey)))) == 1
        user.email = None
        with pytest.raises(Invalid), db.begin_nested():
            reset_password(db, user, "synthetic-password", user.credential_generation, "synthetic-no-email")
    assert probe(app, raw).status_code == 200


@pytest.mark.parametrize("change", ["selected-key", "configured-key", "profile-removal"])
def test_subscribe_revalidates_after_auth_before_credential_change(bridge_app, change):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, key_id = make_key(app)
    observations = []
    def verified(*_):
        from flask import g
        observations.append(g.db.in_transaction())
        with sessions.begin() as db:
            if change == "selected-key":
                user = db.get(User, "agent-b")
                revoke_api_key(db, user, key_id, user.credential_generation, "synthetic-callback-revoke")
            else:
                settings = dict(app.config, USERS=[dict(u) for u in app.config["USERS"]])
                if change == "profile-removal":
                    settings["USERS"] = [u for u in settings["USERS"] if u["id"] != "agent-b"]
                else:
                    next(u for u in settings["USERS"] if u["id"] == "agent-b")["api_key_hash"] = digest("synthetic-rotated-config")
                bootstrap(db, settings)
    app.extensions["verify_callback"] = verified
    assert subscription(app, raw).status_code == 401
    assert observations == [False]
    with sessions() as db:
        assert not db.scalar(select(Subscription))


def test_concurrent_duplicate_key_create_only_one_commit(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    with sessions() as db:
        generation = db.get(User, "agent-b").credential_generation
    def submit(_):
        try:
            with sessions.begin() as db:
                user = db.get(User, "agent-b")
                return create_api_key(db, user, generation, "synthetic-racing-form")[1]
        except Conflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert sum(result is not None for result in results) == 1
    with sessions() as db:
        assert len(list(db.scalars(select(APIKey)))) == len(list(db.scalars(select(CredentialOperation)))) == 1


def test_concurrent_create_and_selected_revoke_use_one_generation(bridge_app):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    raw, key_id = make_key(app)
    with sessions() as db:
        generation = db.get(User, "agent-b").credential_generation
    barrier = Barrier(2)
    def change(action):
        try:
            with sessions.begin() as db:
                user = db.get(User, "agent-b")
                barrier.wait(10)
                if action == "create":
                    return create_api_key(db, user, generation, "synthetic-concurrent-create")[0]
                revoke_api_key(db, user, key_id, generation, "synthetic-concurrent-revoke")
                return "revoked"
        except Conflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, ["create", "revoke"]))
    assert sum(result is not None for result in results) == 1
    assert probe(app, raw).status_code == (401 if results[1] else 200)
    if results[0]:
        assert probe(app, results[0]).status_code == 200


@pytest.mark.parametrize("rotate", [False, True])
def test_concurrent_key_create_and_config_sync_preserve_authority(bridge_app, rotate):
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    settings = dict(app.config, USERS=[dict(u) for u in app.config["USERS"]])
    if rotate:
        next(u for u in settings["USERS"] if u["id"] == "agent-b")["api_key_hash"] = digest("synthetic-concurrent-config-key")
    with sessions() as db:
        generation = db.get(User, "agent-b").credential_generation
    barrier = Barrier(2)
    def create():
        try:
            with sessions.begin() as db:
                user = db.get(User, "agent-b")
                barrier.wait(10)
                return create_api_key(db, user, generation, "synthetic-config-race-form")[0]
        except Conflict:
            return None
    def sync():
        barrier.wait(10)
        with sessions.begin() as db:
            bootstrap(db, settings)
    with ThreadPoolExecutor(max_workers=2) as pool:
        generated, synchronized = pool.submit(create), pool.submit(sync)
        raw = generated.result(timeout=20)
        synchronized.result(timeout=20)
    if rotate:
        assert probe(app, "synthetic-concurrent-config-key").status_code == 200
        if raw:
            assert probe(app, raw).status_code == 401
    else:
        assert raw and probe(app, raw).status_code == 200
    with sessions.begin() as db:
        bootstrap(db, settings)
    if rotate and raw:
        assert probe(app, raw).status_code == 401


@pytest.mark.parametrize("key_modes", [("legacy", "legacy"), ("legacy", "added"),
                                      ("added", "legacy"), ("added", "added")])
def test_postgres_opposite_direction_service_messages_preserve_sorted_lock_order(bridge_app, monkeypatch, key_modes):
    """Both real bearer requests finish auth before either starts message locks."""
    app = bridge_app
    if app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Native PostgreSQL row-lock regression requires disposable TEST_DATABASE_URL")
    from flask import g, request
    from bridge import messages
    ids = ("agent-b", "agent-a")
    keys = {ident: (make_key(app, ident, "synthetic-opposite-" + ident)[0] if mode == "added"
                    else app.extensions["test_credentials"][ident]) for ident, mode in zip(ids, key_modes)}
    # A bounded server timeout also prevents a regression from hanging the suite.
    @app.before_request
    def bound_message_lock_wait():
        if request.path == "/api/messages":
            g.db.execute(text("SET LOCAL statement_timeout = '5s'"))
    after_auth = Barrier(2)
    send = messages.send_message
    def synchronized_send(*args, **kwargs):
        after_auth.wait(10)
        return send(*args, **kwargs)
    monkeypatch.setattr(messages, "send_message", synchronized_send)
    def post(ident):
        recipient = ids[1] if ident == ids[0] else ids[0]
        return app.test_client().post("/api/messages", headers={"Authorization": "Bearer " + keys[ident]},
            json=dict(message_id="synthetic-opposite-" + ident, recipient=recipient,
                      text="Synthetic concurrent message", status="received", needs_reply=False))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(post, ident) for ident in ids]
        responses = [future.result(timeout=20) for future in futures]
    assert [response.status_code for response in responses] == [200, 200]
    with app.extensions["sessions"]() as db:
        for ident in ids:
            message = db.get(Message, "synthetic-opposite-" + ident)
            assert message and message.sender_id == ident


@pytest.mark.parametrize("reset_point", ["password-match", "current-hash-check"])
def test_postgres_overlapping_login_never_binds_old_password_to_reset_hash(profile_app, monkeypatch, reset_point):
    """Exercise actual login and owner reset forms in independent transactions."""
    app = profile_app
    if app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Overlapping login/reset requires PostgreSQL read-committed transactions")
    import bridge.auth as auth
    from test_credential_ui import PATH, credential_form
    owner = sign_in(app)
    reset_form = credential_form(owner, "reset_password")
    client = app.test_client()
    login_page = get(client, "/login")
    old_password = "synthetic-password-agent-b"
    with app.extensions["sessions"]() as db:
        old_hash = db.get(User, "agent-b").password_hash
    paused, resume = Event(), Event()
    def pause():
        paused.set()
        assert resume.wait(10), "Password reset did not finish"
    if reset_point == "password-match":
        original = auth.check_password_hash
        def checked(value, password):
            result = original(value, password)
            if value == old_hash and password == old_password and result and not paused.is_set():
                pause()
            return result
        monkeypatch.setattr(auth, "check_password_hash", checked)
    else:
        original = auth.hmac.compare_digest
        def compared(left, right):
            result = original(left, right)
            if left == old_hash and right == old_hash and result and not paused.is_set():
                pause()
            return result
        monkeypatch.setattr(auth.hmac, "compare_digest", compared)
    def login_old():
        return post(client, "/login", data=dict(csrf=hidden(login_page, "csrf"),
                    email="agent-b@example.com", password=old_password))
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(login_old)
        try:
            assert paused.wait(10), "Login did not reach the intended race point"
            reset = post(owner, PATH, data=dict(reset_form, password="synthetic-reset-password",
                                              password_confirmation="synthetic-reset-password"))
            assert reset.status_code == 303
        finally:
            resume.set()
        response = pending.result(timeout=20)
    assert response.status_code == (200 if reset_point == "password-match" else 302)
    with client.session_transaction(base_url=BASE) as cookie:
        if "credential" in cookie:
            assert cookie["credential"] == digest(old_hash)
    assert get(client, "/").status_code == 302
    page = get(client, "/login")
    assert post(client, "/login", data=dict(csrf=hidden(page, "csrf"), email="agent-b@example.com",
                                           password=old_password)).status_code == 200
    assert post(client, "/login", data=dict(csrf=hidden(page, "csrf"), email="agent-b@example.com",
                                           password="synthetic-reset-password")).status_code == 302
    assert get(client, "/").status_code == 200


@pytest.mark.parametrize("winner", ["reset", "consent"])
def test_postgres_consent_and_password_reset_cannot_create_persistent_stale_authority(profile_app, monkeypatch, winner):
    app, sessions = profile_app, profile_app.extensions["sessions"]
    engine = app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Consent/reset row-lock ordering requires disposable PostgreSQL")
    import bridge.auth as auth
    from flask import g
    from test_auth import CALLBACK, CHALLENGE, RESOURCE, VERIFIER
    from test_credential_ui import PATH, credential_form
    owner = sign_in(app)
    reset_form = credential_form(owner, "reset_password")
    client = sign_in(app, "agent-b", "participant")
    registered = client.post("/oauth/register", base_url=BASE, json=dict(redirect_uris=[CALLBACK],
                                token_endpoint_auth_method="none", grant_types=["authorization_code", "refresh_token"]))
    client_id = registered.json["client_id"]
    fields = dict(response_type="code", client_id=client_id, redirect_uri=CALLBACK,
                  scope="bridge:messages", resource=RESOURCE, code_challenge=CHALLENGE, code_challenge_method="S256")
    page = get(client, "/oauth/authorize", query_string=fields)
    assert page.status_code == 200
    paused, resume, reset_waiting = Event(), Event(), Event()
    original = auth.CodeGrant.save_authorization_code
    def save(self, code, req):
        if winner == "consent":
            original(self, code, req)
            g.db.flush()
        paused.set()
        assert resume.wait(10), "Concurrent reset did not reach its intended point"
        if winner == "reset":
            original(self, code, req)
    monkeypatch.setattr(auth.CodeGrant, "save_authorization_code", save)
    def approve():
        return post(client, "/oauth/authorize", data=dict(fields, csrf=hidden(page, "csrf"), approve="yes"))
    def reset():
        return post(owner, PATH, data=dict(reset_form, password="synthetic-consent-reset",
                                          password_confirmation="synthetic-consent-reset"))
    # In the consent-first case this observes reset waiting for Participant;
    # consent already holds that row after its final cookie revalidation.
    def before(connection, cursor, statement, *args):
        if winner == "consent" and "FROM participants" in statement and "FOR UPDATE" in statement:
            reset_waiting.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(approve)
        try:
            assert paused.wait(10), "Consent did not reach code issuance"
            if winner == "reset":
                assert reset().status_code == 303
            else:
                event.listen(engine, "before_cursor_execute", before)
                resetting = pool.submit(reset)
                assert reset_waiting.wait(10), "Reset did not attempt the participant lock"
        finally:
            resume.set()
        approved = pending.result(timeout=20)
        if winner == "consent":
            try:
                assert resetting.result(timeout=20).status_code == 303
            finally:
                event.remove(engine, "before_cursor_execute", before)
    if winner == "reset":
        assert approved.status_code == 401
        with sessions() as db:
            assert not db.scalar(select(Family).where(Family.client_id == client_id))
            assert not db.scalar(select(Code).where(Code.client_id == client_id))
    else:
        assert approved.status_code == 302
        code = parse_qs(urlsplit(approved.location).query)["code"][0]
        token = client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code", code=code,
                            client_id=client_id, redirect_uri=CALLBACK, code_verifier=VERIFIER, resource=RESOURCE))
        assert token.status_code == 400
        with sessions() as db:
            families = list(db.scalars(select(Family).where(Family.client_id == client_id)))
            assert len(families) == 1 and not families[0].active
            assert not db.scalar(select(Token).where(Token.client_id == client_id))
    assert get(client, "/oauth/authorize", query_string=fields).status_code == 302

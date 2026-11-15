"""Synthetic 0.2.0 acceptance: invitation tenancy and recipient-only policy."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import func, inspect, select, update

from bridge.app import bootstrap
from bridge.auth import digest
from bridge.invitations import create_invitation
from bridge.models import Artifact, BotAllowlist, Member, Message, Participant
from bridge.models_auth import BrowserOwner, OwnerInvitation, User
from bridge.schema import ensure_multi_owner_schema
from conftest import bearer_headers
from test_profiles import created_id, BASE, HEADERS, get, hidden, post, sign_in


def invite(app):
    with app.extensions["sessions"].begin() as db:
        item, raw = create_invitation(db, db.get(BrowserOwner, "seed-admin"))
        return item.id, raw


def register_owner(app, code, email="new-owner@example.com", **extra):
    client = app.test_client()
    page = get(client, "/register")
    return post(client, "/register", data=dict(csrf=hidden(page, "csrf"), name="New Owner", email=email,
                                               password="synthetic-owner-password", code=code, **extra))


def test_invite_create_once_register_records_and_sync_preserves_owner(bridge_app):
    app = bridge_app
    client = sign_in(app, "seed-admin")
    page = get(client, "/invitations")
    response = post(client, "/invitations", data=dict(csrf=hidden(page, "csrf"), action="create"))
    assert response.status_code == 303
    response = get(client, response.location)
    assert response.status_code == 200
    import re
    raw = re.search(rb'id="code" value="([^"]+)"', response.data)[1].decode()
    assert response.headers["Cache-Control"] == "no-store"
    assert raw not in str(response.headers)
    assert raw.encode() not in get(client, "/invitations").data
    with client.session_transaction(base_url=BASE) as cookie:
        assert raw not in str(dict(cookie))
    assert register_owner(app, raw).status_code == 303
    with app.extensions["sessions"].begin() as db:
        owner = db.scalar(select(BrowserOwner).where(BrowserOwner.email == "new-owner@example.com"))
        item = db.scalar(select(OwnerInvitation).where(OwnerInvitation.code_hash == digest(raw)))
        assert item.creator_id == "seed-admin" and item.redeemer_id == owner.id
        assert item.expires_at - item.created_at == 7 * 86400 and item.redeemed_at is not None
        assert owner.role == "owner" and db.get(Participant, owner.id) is None and db.get(User, owner.id) is None
        bootstrap(db, app.config)
        assert owner.active and owner.role == "owner"
    login = app.test_client()
    page = get(login, "/login")
    assert post(login, "/login", data=dict(csrf=hidden(page, "csrf"), email="new-owner@example.com",
                                           password="synthetic-owner-password")).status_code == 302
    assert get(login, "/invitations").status_code == 403


@pytest.mark.parametrize("state", ["expired", "reused", "revoked", "unknown", "duplicate-email"])
def test_invite_generic_failures_are_atomic(bridge_app, state):
    app = bridge_app
    ident, raw = invite(app)
    with app.extensions["sessions"].begin() as db:
        if state == "expired":
            db.get(OwnerInvitation, ident).expires_at = 0
        elif state == "revoked":
            db.get(OwnerInvitation, ident).revoked_at = 1
    if state == "reused":
        assert register_owner(app, raw, "first@example.com").status_code == 303
    if state == "unknown":
        raw = "synthetic-invalid-code"
    email = "seed-admin@example.com" if state == "duplicate-email" else "rejected@example.com"
    response = register_owner(app, raw, email)
    assert response.status_code == 400
    assert b"Registration failed. Check your details and invitation code." in response.data
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(BrowserOwner.id).where(BrowserOwner.email == email)) == ("seed-admin" if state == "duplicate-email" else None)
        if state != "reused":
            assert db.get(OwnerInvitation, ident).redeemer_id is None


def test_invite_revoke_and_nonadmin_cannot_create_codes(bridge_app):
    app = bridge_app
    ident, raw = invite(app)
    admin = sign_in(app, "seed-admin")
    page = get(admin, "/invitations")
    assert post(admin, "/invitations", data=dict(csrf=hidden(page, "csrf"), action="revoke", invitation_id=ident)).status_code == 303
    assert register_owner(app, raw).status_code == 400
    _, other = invite(app)
    assert register_owner(app, other).status_code == 303
    with app.extensions["sessions"]() as db:
        owner_id = db.scalar(select(BrowserOwner.id).where(BrowserOwner.email == "new-owner@example.com"))
    for client in (sign_in(app, owner_id), sign_in(app, "agent-b", "participant")):
        assert get(client, "/invitations").status_code == 403
        assert post(client, "/invitations", data=dict(action="create")).status_code == 403
    assert post(admin, "/invitations", data=dict(action="create")).status_code == 400


def test_concurrent_invite_redemption_commits_exactly_one_owner(bridge_app):
    app = bridge_app
    ident, raw = invite(app)
    barrier = Barrier(2)
    def submit(index):
        client = app.test_client()
        page = get(client, "/register")
        barrier.wait(10)
        return post(client, "/register", data=dict(csrf=hidden(page, "csrf"), name="Concurrent Owner",
            email=f"concurrent-{index}@example.com", password="synthetic-password", code=raw)).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == [303, 400]
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count()).select_from(BrowserOwner).where(BrowserOwner.email.like("concurrent-%"))) == 1
        assert db.get(OwnerInvitation, ident).redeemer_id is not None


def test_register_guard_csrf_and_shared_burst_limiter(bridge_app, monkeypatch):
    app, client = bridge_app, bridge_app.test_client()
    sessions = app.extensions["sessions"]
    # Origin rejection must happen before the limiter or request SQL session.
    with monkeypatch.context() as guard:
        guard.setattr(sessions, "class_", lambda **kwargs: pytest.fail("unexpected session allocation"))
        assert client.get("/register", base_url=BASE).status_code == 403
        assert client.post("/register", base_url=BASE).status_code == 403
    assert post(client, "/register", data={}).status_code == 400
    import bridge.login_rate as rate
    # The public limiter derives this hostname from configured BASE_URL.
    from bridge.login_rate import REQUESTS
    for _ in range(REQUESTS):
        response = post(client, "/login", data={})
        if response.status_code == 429:
            break
    assert post(client, "/register", data={}).status_code == 429


@pytest.fixture
def tenants(bridge_app):
    app = bridge_app
    _, code = invite(app)
    assert register_owner(app, code, "second@example.com").status_code == 303
    with app.extensions["sessions"].begin() as db:
        second = db.scalar(select(BrowserOwner).where(BrowserOwner.email == "second@example.com"))
        db.get(Participant, "intruder").owner_account_id = second.id
        second_id = second.id
    return app, "seed-admin", second_id


def send(app, sender="agent-a", recipient="intruder", ident="multi-message", **extra):
    payload = dict(message_id=ident, recipient=recipient, text="Synthetic multi-owner message",
                   status="received", needs_reply=False)
    payload.update(extra)
    return app.test_client().post("/api/messages", base_url=BASE, headers=bearer_headers(app, sender), json=payload)


def policies(app, receiver, policy, senders=()):
    with app.extensions["sessions"].begin() as db:
        db.get(Participant, receiver).reachability_policy = policy
        from sqlalchemy import delete
        db.execute(delete(BotAllowlist).where(BotAllowlist.receiver_id == receiver))
        db.add_all([BotAllowlist(receiver_id=receiver, sender_id=sender) for sender in senders])


def participants(app, sender):
    response = app.test_client().get("/api/participants", headers=bearer_headers(app, sender))
    return {p["participant_id"] for p in response.json["participants"]}


def test_default_isolation_and_same_owner_reach(tenants):
    app, _, _ = tenants
    assert participants(app, "agent-a") == {"agent-b"}
    assert participants(app, "intruder") == set()
    assert send(app).status_code == 404
    assert send(app, recipient="agent-b").status_code == 200
    with app.extensions["sessions"]() as db:
        assert db.get(Message, "multi-message").recipient_id == "agent-b"


@pytest.mark.parametrize("policy", ["allowlist", "open"])
def test_receiver_policy_and_thread_reply_permission_keep_history(tenants, policy):
    app, _, _ = tenants
    policies(app, "intruder", policy, ("agent-a",))
    assert "intruder" in participants(app, "agent-a")
    assert "agent-a" not in participants(app, "intruder")
    first = send(app)
    assert first.status_code == 200
    thread_id = first.json["thread_id"]
    # A bot may reply to the other member who already wrote in this thread.
    assert send(app, sender="intruder", recipient="agent-a", ident="reverse", thread_id=thread_id).status_code == 200
    if policy == "allowlist":
        assert "intruder" not in participants(app, "agent-b")
        assert send(app, sender="agent-b", ident="unlisted").status_code == 404
    policies(app, "intruder", "own_owner")
    assert "intruder" not in participants(app, "agent-a")
    assert send(app, ident="after-revoke", thread_id=thread_id).status_code == 200
    assert send(app, ident="new-after-revoke").status_code == 404
    # An exact retry returns the retained receipt, without new work or wakes.
    assert send(app).json["duplicate"] is True
    for member in ("agent-a", "intruder"):
        client = app.test_client()
        assert client.get("/api/messages/multi-message", headers=bearer_headers(app, member)).status_code == 200
        assert client.get(f"/api/threads/{thread_id}/messages", headers=bearer_headers(app, member)).status_code == 200


def test_owner_scope_threads_messages_feeds_profiles_files_and_mutations(tenants):
    app, first_id, second_id = tenants
    own = send(app, recipient="agent-b", ident="first-private").json
    policies(app, "agent-a", "open")
    cross = send(app, sender="intruder", recipient="agent-a", ident="cross").json
    # B's private thread has no member owned by A (a one-bot synthetic history).
    from bridge.models import Thread
    with app.extensions["sessions"].begin() as db:
        db.add(Thread(id="second-private-thread"))
        db.flush()
        db.add(Member(thread_id="second-private-thread", participant_id="intruder"))
        db.add(Message(id="second-private", thread_id="second-private-thread", sender_id="intruder", recipient_id="intruder",
                       text="Second owner private text", status="completed", needs_reply=False, sequence=1, fingerprint="synthetic"))
        for bot in ("agent-b", "intruder"):
            db.add(Artifact(id=bot+"-file", owner_id=bot, idempotency_key=bot, object_key=bot, filename=bot+".txt",
                            content_type="text/plain", size_bytes=0, sha256="0"*64, state="ready"))
        db.flush()
        from bridge.models import MessageArtifact
        db.add(MessageArtifact(message_id=cross["message_id"], artifact_id="intruder-file"))
    from test_files import FakeStore
    app.extensions["object_store"] = FakeStore()
    from test_web import rendered
    for owner, allowed, forbidden, bot, other_bot in ((first_id, own["thread_id"], "second-private-thread", "agent-b", "intruder"),
                                                     (second_id, "second-private-thread", own["thread_id"], "intruder", "agent-b")):
        client = sign_in(app, owner)
        with rendered(app) as contexts:
            assert get(client, "/").status_code == 200
        ids = {t["thread_id"] for t in contexts[-1]["threads"]}
        assert allowed in ids and cross["thread_id"] in ids and forbidden not in ids
        assert get(client, "/conversation?thread_id="+forbidden).status_code == 404
        assert get(client, "/message?message_id="+("second-private" if owner == first_id else "first-private")).status_code == 404
        from bridge.owner_web import _cursor
        with app.test_request_context():
            with app.extensions["sessions"]() as db:
                cursor = _cursor(db.get(BrowserOwner, owner), "owner-conversation", "newer", 0, 25, forbidden)
        assert get(client, "/conversation/messages?thread_id="+forbidden+"&cursor="+cursor).status_code == 404
        cross_page = get(client, "/conversation?thread_id="+cross["thread_id"])
        assert b"intruder.txt" in cross_page.data
        assert (b'href="/files/intruder-file/download"' in cross_page.data) == (owner == second_id)
        listing = get(client, "/profiles")
        assert bot.encode() in listing.data and (f'class="profile-id">{other_bot}<').encode() not in listing.data
        for page in ("credentials", "notifications", "reachability"):
            path = f"/profiles/{page}?profile_id={other_bot}"
            assert get(client, path).status_code == 404
            assert post(client, path, data=dict(csrf=hidden(get(client, "/profiles/new"), "csrf"), policy="open")).status_code in (400, 404)
        assert get(client, f"/files/{bot}-file/download").status_code == 302
        assert get(client, f"/files/{other_bot}-file/download").status_code == 404
    # Admin's invitations authority does not include a global data bypass.
    assert get(sign_in(app, first_id), "/conversation?thread_id=second-private-thread&owner_account_id="+second_id).status_code == 400


def test_owner_created_bot_belongs_to_session_and_policy_form(tenants):
    app, _, second = tenants
    from test_profiles import create
    client = sign_in(app, second)
    response = create(client, profile_id="second-bot", owner_account_id="seed-admin")
    assert response.status_code == 200
    with app.extensions["sessions"]() as db:
        bot = db.get(Participant, created_id(app,"second-bot",second))
        assert bot.owner_account_id == second and bot.reachability_policy == "own_owner"
    path = "/profiles/reachability?profile_id=intruder"
    page = get(client, path)
    assert post(client, path, data=dict(csrf=hidden(page, "csrf"), policy="allowlist", sender_ids="amb_"+"g"*32)).status_code == 303
    with app.extensions["sessions"]() as db:
        assert db.get(BotAllowlist,("intruder","amb_"+"g"*32))
    assert post(client, path, data=dict(csrf=hidden(page, "csrf"), policy="open", owner_account_id="seed-admin")).status_code == 400
    assert post(client, path, data=dict(csrf=hidden(page, "csrf"), policy="allowlist", sender_ids="amb_"+"u"*32)).status_code == 303


def test_multi_owner_schema_idempotent_and_nonnull(bridge_app):
    engine = bridge_app.extensions["engine"]
    ensure_multi_owner_schema(engine)
    ensure_multi_owner_schema(engine)
    columns = {c["name"]: c for c in inspect(engine).get_columns("participants")}
    assert columns["owner_account_id"]["nullable"] is False
    assert any(i["column_names"] == ["owner_account_id", "id"] for i in inspect(engine).get_indexes("participants"))
    assert {"bot_allowlist", "owner_invitations"} <= set(inspect(engine).get_table_names())


def test_runtime_admin_only_config_and_legacy_setup_rejected(bridge_app, monkeypatch, tmp_path):
    import json
    from bridge.config import load_settings, validate_settings
    path = tmp_path / "synthetic-config.json"
    for env, value in dict(BRIDGE_CONFIG=str(path), DATABASE_URL=bridge_app.config["DATABASE_URL"],
                           BASE_URL=BASE, SESSION_SECRET="synthetic-session", ENCRYPTION_KEY=bridge_app.config["ENCRYPTION_KEY"],
                           SYNTHETIC_ADMIN_PASSWORD_HASH=bridge_app.config["BROWSER_ADMIN"]["password_hash"]).items():
        monkeypatch.setenv(env, value)
    admin = dict(id="bootstrap-admin", name="Bootstrap Admin", email="admin@example.com", password_hash_env="SYNTHETIC_ADMIN_PASSWORD_HASH")
    path.write_text(json.dumps(dict(admin=admin)))
    loaded = load_settings()
    assert loaded["BROWSER_ADMIN"]["id"] == "bootstrap-admin" and "USERS" not in loaded and "BROWSER_OWNERS" not in loaded
    for empty in ({}, dict(admin=None)):
        path.write_text(json.dumps(empty))
        assert load_settings()["BROWSER_ADMIN"] is None
    for legacy in (dict(admin=admin, participants=[]), dict(owners=[admin]), dict(participants=[])):
        path.write_text(json.dumps(legacy))
        with pytest.raises(ValueError):
            load_settings()
    for legacy in (dict(USERS=[dict(id="bot")]), dict(BROWSER_OWNERS=[admin])):
        with pytest.raises(ValueError):
            validate_settings(dict(bridge_app.config, **legacy))


def test_init_db_empty_database_is_idempotent(bridge_app, monkeypatch):
    import sys
    import bridge.__main__ as cli
    # A separate schema/database is already provided by bridge_app.
    engine = bridge_app.extensions["engine"]
    from bridge.models import Base
    Base.metadata.drop_all(engine)
    monkeypatch.setattr(cli, "create_app", lambda: bridge_app)
    monkeypatch.setattr(sys, "argv", ["bridge", "init-db"])
    cli.main()
    cli.main()
    with bridge_app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count()).select_from(BrowserOwner)) == 1
        assert db.scalar(select(func.count()).select_from(Participant)) == 0
        assert db.get(BrowserOwner, "seed-admin").role == "admin"


def test_additive_tenancy_schema_rejects_nonempty_legacy_ownership(tmp_path):
    from bridge.models import database
    engine, _ = database("sqlite:///" + str(tmp_path / "legacy.sqlite"))
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE browser_owners (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("CREATE TABLE participants (id VARCHAR PRIMARY KEY)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('synthetic-legacy')")
    with pytest.raises(RuntimeError, match="fresh database"):
        ensure_multi_owner_schema(engine)
    assert "owner_account_id" not in {c["name"] for c in inspect(engine).get_columns("participants")}
    engine.dispose()


def test_admin_removal_through_runtime_loader_and_cli_preserves_registered_accounts(tenants, tmp_path, monkeypatch):
    import json
    import sys
    import bridge.__main__ as cli
    from bridge.app import create_app
    app, admin_id, owner_id = tenants
    admin_client, owner_client = sign_in(app, admin_id), sign_in(app, owner_id)
    config = tmp_path / "synthetic-admin-removal.json"
    config.write_text(json.dumps(dict(admin=None)))
    for env, value in dict(BRIDGE_CONFIG=str(config), DATABASE_URL=app.config["DATABASE_URL"], BASE_URL=BASE,
                           SESSION_SECRET=app.secret_key, ENCRYPTION_KEY=app.config["ENCRYPTION_KEY"]).items():
        monkeypatch.setenv(env, value)
    created = []
    def runtime():
        result = create_app()
        created.append(result)
        return result
    monkeypatch.setattr(cli, "create_app", runtime)
    monkeypatch.setattr(sys, "argv", ["bridge", "sync-config"])
    with app.extensions["sessions"]() as db:
        credentials = [(u.id, u.password_hash, u.api_key_hash, u.active) for u in db.scalars(select(User).order_by(User.id))]
    try:
        cli.main()
    finally:
        for current in created:
            current.extensions["engine"].dispose()
    assert get(admin_client, "/").status_code == 302
    assert get(owner_client, "/profiles").status_code == 200
    with app.extensions["sessions"]() as db:
        assert not db.get(BrowserOwner, admin_id).active and db.get(BrowserOwner, owner_id).active
        assert credentials == [(u.id, u.password_hash, u.api_key_hash, u.active) for u in db.scalars(select(User).order_by(User.id))]


def test_pair_filter_does_not_disclose_unrelated_foreign_bots(tenants):
    app, first, _ = tenants
    client = sign_in(app, first)
    for other in ("intruder", "unknown"):
        assert get(client, "/?participant_a=agent-a&participant_b="+other).status_code == 404
    policies(app, "intruder", "open")
    message = send(app).json
    path = "/?participant_a=agent-a&participant_b=intruder"
    assert get(client, path).status_code == 200
    policies(app, "intruder", "own_owner")
    assert get(client, path).status_code == 200
    assert get(client, "/conversation?thread_id="+message["thread_id"]+"&participant_a=agent-a&participant_b=intruder").status_code == 200


def test_invite_expiring_during_password_hash_is_rejected(bridge_app, monkeypatch):
    import bridge.invitations as invitations
    import werkzeug.security as security
    app = bridge_app
    ident, raw = invite(app)
    with app.extensions["sessions"].begin() as db:
        db.get(OwnerInvitation, ident).expires_at = 100
    clock = [99]
    original = security.generate_password_hash
    def hash_password(value):
        result = original(value)
        clock[0] = 101
        return result
    monkeypatch.setattr(invitations, "now", lambda: clock[0])
    monkeypatch.setattr(security, "generate_password_hash", hash_password)
    assert register_owner(app, raw).status_code == 400
    with app.extensions["sessions"]() as db:
        assert db.get(OwnerInvitation, ident).redeemer_id is None
        assert not db.scalar(select(BrowserOwner.id).where(BrowserOwner.email == "new-owner@example.com"))


def test_registration_hash_does_not_hold_profile_write_lock(bridge_app, monkeypatch):
    from threading import Event
    from flask import g
    from bridge.profiles import lock_profile_changes
    import werkzeug.security as security
    app = bridge_app
    _, raw = invite(app)
    paused, resume = Event(), Event()
    original = security.generate_password_hash
    def hash_password(value):
        assert not g.db.in_transaction()
        paused.set()
        assert resume.wait(10)
        return original(value)
    monkeypatch.setattr(security, "generate_password_hash", hash_password)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(register_owner, app, raw)
        try:
            assert paused.wait(10)
            with app.extensions["sessions"].begin() as db:
                if db.bind.dialect.name == "postgresql":
                    from sqlalchemy import text
                    db.execute(text("SET LOCAL lock_timeout = '1s'"))
                lock_profile_changes(db)
                db.get(Participant, "agent-b").name = "Synthetic independently updated bot"
        finally:
            resume.set()
        assert pending.result(timeout=20).status_code == 303


def test_invitation_identity_and_reachability_error_recovery(tenants):
    app, admin_id, second_id = tenants
    client = sign_in(app, admin_id)
    page = get(client, "/invitations")
    created = post(client, "/invitations", data=dict(csrf=hidden(page, "csrf"), action="create"))
    assert created.status_code == 303
    created = get(client, created.location)
    with app.extensions["sessions"]() as db:
        ident = db.scalar(select(OwnerInvitation.id).where(OwnerInvitation.redeemer_id.is_(None)))
    assert ident.encode() in created.data and ident.encode() in get(client, "/invitations").data
    owner = sign_in(app, second_id)
    path = "/profiles/reachability?profile_id=intruder"
    fields = dict(csrf=hidden(get(owner, path), "csrf"), policy="allowlist", sender_ids="agent-a\nintruder")
    rejected = post(owner, path, data=fields)
    assert rejected.status_code == 400 and b'agent-a\nintruder' in rejected.data
    assert b'value="allowlist" selected' in rejected.data and b'aria-invalid="true"' in rejected.data
    with app.extensions["sessions"]() as db:
        assert db.get(Participant, "intruder").reachability_policy == "own_owner"
        assert not db.scalar(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == "intruder"))

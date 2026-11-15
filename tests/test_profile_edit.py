"""Synthetic owner profile/account edits and irreversible retirement acceptance."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import event, inspect, select, text

from bridge.app import bootstrap
from bridge.auth import digest
from bridge.lifecycle import deactivate_bot, delivery_fence
from bridge.models import BotAllowlist, Delivery, Message, Participant, Subscription
from bridge.models_auth import APIKey, BrowserOwner, Family, Token, User
from bridge.profiles import lock_profile_changes
from bridge.schema import ensure_deactivation_schema
from bridge.worker import deliver_one
from conftest import bearer_headers
from test_credentials import oauth_connection
from test_multi_owner import tenants, send, policies, participants
from test_profiles import BASE, get, post, hidden, sign_in, create


def edit(client, ident="agent-b", **values):
    path = "/profiles/edit?profile_id=" + ident
    data = dict(csrf=hidden(get(client, path), "csrf"), name="Renamed Kai", email="")
    data.update(values)
    return post(client, path, data=data)


def retire(client, ident="agent-b", **values):
    path = "/profiles/deactivate?profile_id=" + ident
    data = dict(csrf=hidden(get(client, path), "csrf"), confirm="deactivate")
    data.update(values)
    return post(client, path, data=data)


def test_profile_edit_email_set_change_clear_and_immutable_ids(bridge_app):
    app = bridge_app
    owner = sign_in(app, "seed-admin")
    for email, saved in ((" SHARED@EXAMPLE.COM ", "shared@example.com"),
                         ("new@example.com", "new@example.com"), ("", None)):
        assert edit(owner, email=email).status_code == 303
        with app.extensions["sessions"]() as db:
            assert db.get(User, "agent-b").email == saved
            profile = db.get(Participant, "agent-b")
            assert profile.id == profile.stable_id == "agent-b" and profile.name == "Renamed Kai"
    assert edit(owner, email="agent-a@example.com").status_code == 303
    for field in ("profile_id", "stable_id", "owner_account_id"):
        assert edit(owner, **{field: "replacement"}).status_code == 400


@pytest.mark.parametrize("path", ["/profiles/edit?profile_id=agent-b", "/profiles/deactivate?profile_id=agent-b", "/account"])
def test_edit_account_retire_origin_csrf_and_participant_denial(bridge_app, monkeypatch, path):
    app = bridge_app
    owner = sign_in(app, "seed-admin")
    assert post(owner, path, data={}).status_code == 400
    for method in ("get", "post"):
        assert getattr(app.test_client(), method)(path, base_url=BASE).status_code == 403
        assert getattr(sign_in(app, "agent-b", "participant"), method)(path, base_url=BASE,
            headers=__import__('test_profiles').HEADERS).status_code == 403
    with monkeypatch.context() as patch:
        patch.setattr(app.extensions["sessions"], "class_", lambda **kw: pytest.fail("origin rejection must precede session access"))
        assert owner.get(path, base_url=BASE).status_code == 403
        assert owner.post(path, base_url=BASE).status_code == 403


@pytest.mark.parametrize("page", ["edit", "deactivate"])
def test_cross_owner_edit_retire_has_same_missing_response(tenants, page):
    app, _, second = tenants
    owner = sign_in(app, second)
    csrf = hidden(get(owner, "/account"), "csrf")
    for ident in ("agent-b", "missing"):
        path = f"/profiles/{page}?profile_id={ident}"
        assert get(owner, path).status_code == 404
        response = post(owner, path, data=dict(csrf=csrf, **(dict(name="Attempt", email="") if page == "edit" else dict(confirm="deactivate"))))
        assert response.status_code == 404 and response.json == {"error": "Not Found"}
    with app.extensions["sessions"]() as db:
        assert db.get(Participant, "agent-b").name == "Agent B" and db.get(Participant, "agent-b").active


@pytest.mark.parametrize("field", ["name", "email"])
@pytest.mark.parametrize("value", ["\x00", "\x1f", "\x85", "\n", "\x7f"])
def test_profile_controls_never_bound_to_sql(bridge_app, field, value):
    app = bridge_app
    owner = sign_in(app, "seed-admin")
    engine = app.extensions["engine"]
    def check(conn, cursor, statement, parameters, context, many):
        values = parameters.values() if isinstance(parameters, dict) else parameters
        assert all(not isinstance(v, str) or value not in v for v in values)
    event.listen(engine, "before_cursor_execute", check)
    try:
        response = edit(owner, **{field: "Invalid" + value + ("@example.com" if field == "email" else "Name")})
        assert response.status_code == 400 and b'role="alert"' in response.data
        assert create(owner, profile_id="invalid-control", **{field: "Invalid" + value + ("@example.com" if field == "email" else "Name")}).status_code == 400
    finally:
        event.remove(engine, "before_cursor_execute", check)


@pytest.mark.parametrize("name", ["", "   ", "Bad\x00Name", "Bad\x85Name", "N" * 201])
def test_invalid_display_names_are_form_errors(bridge_app, name):
    owner = sign_in(bridge_app, "seed-admin")
    assert edit(owner, name=name).status_code == 400
    page = get(owner, "/account")
    response = post(owner, "/account", data=dict(csrf=hidden(page, "csrf"), name=name))
    assert response.status_code == 400 and b'role="alert"' in response.data


def test_renames_reflect_rest_mcp_threads_browser_and_future_notifications(tenants):
    import json
    app, first, second = tenants
    policies(app, "agent-a", "open")
    message = send(app, sender="intruder", recipient="agent-a", ident="rename", needs_reply=True).json
    client = sign_in(app, second)
    assert edit(client, "intruder", name="New Bot").status_code == 303
    csrf = hidden(get(client, "/account"), "csrf")
    assert post(client, "/account", data=dict(csrf=csrf, name="New Owner")).status_code == 303
    headers = bearer_headers(app, "intruder")
    rest = app.test_client().get("/api/profile", headers=headers).json
    assert rest["name"] == "New Bot" and rest["owner_name"] == "New Owner"
    for tool in ("get_profile", "list_threads"):
        response = app.test_client().post("/mcp", headers=headers, json=dict(jsonrpc="2.0", id=1,
            method="tools/call", params=dict(name=tool, arguments={}))).json
        assert "New Bot" in str(response) and "New Owner" in str(response)
    policies(app, "intruder", "open")
    listing = app.test_client().get("/api/participants", headers=bearer_headers(app, "agent-a")).json
    assert "New Bot" in str(listing) and "New Owner" in str(listing)
    assert b"New Bot (New Owner)" in get(sign_in(app, first), "/conversation?thread_id="+message["thread_id"]).data
    assert b"New Bot (you)" in get(client, "/profiles").data
    history = app.test_client().get("/api/messages/rename", headers=bearer_headers(app, "agent-a")).json
    assert history["sender_name"] == "New Bot" and history["sender_owner_name"] == "New Owner"
    calls = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda u,b,h: calls.append(json.loads(b)) or (200,b""))
    assert calls[0]["data"]["sender_name"] == "New Bot" and calls[0]["data"]["sender_owner_name"] == "New Owner"
    with app.extensions["sessions"].begin() as db:
        db.get(Participant, "intruder").name = "Later Bot"
    assert calls[0]["data"]["sender_name"] == "New Bot"


def test_retirement_confirmation_atomic_revocation_and_reserved_label(bridge_app):
    app = bridge_app
    owner = sign_in(app, "seed-admin")
    participant_session = sign_in(app, "agent-a", "participant")
    with app.extensions["sessions"].begin() as db:
        oauth_connection(db, "agent-a")
        db.flush()
        db.get(Token, "synthetic-token").refresh_hash = digest("synthetic-oauth-refresh")
        db.add(APIKey(id="additional-key", owner_id="agent-a", key_hash=digest("synthetic-additional-key")))
    from test_worker import subscription_params
    assert app.test_client().post("/mcp", headers=bearer_headers(app, "agent-a"), json=dict(jsonrpc="2.0", id=1,
        method="events/subscribe", params=subscription_params())).json.get("result")
    assert send(app, sender="agent-b", recipient="agent-a", ident="queued", needs_reply=True).status_code == 200
    with app.extensions["sessions"].begin() as db:
        for item, state in zip(db.scalars(select(Delivery).order_by(Delivery.id)), ("pending", "retry", "sending")):
            item.state, item.lease, item.lease_until = state, "synthetic-old-lease", 9e10
    assert retire(owner, "agent-a", confirm="").status_code == 400
    with app.extensions["sessions"]() as db:
        assert db.get(Participant, "agent-a").active
    assert retire(owner, "agent-a").status_code == 303
    with app.extensions["sessions"]() as db:
        profile, user = db.get(Participant, "agent-a"), db.get(User, "agent-a")
        assert not profile.active and profile.deactivated_at is not None
        assert not user.active and not user.password_hash and user.api_key_hash is None
        assert not profile.webhook_enabled and profile.webhook_url is None and profile.webhook_token is None
        assert not db.get(APIKey, "additional-key").active
        assert all(not f.active for f in db.scalars(select(Family).where(Family.owner_id == profile.id)))
        assert all(t.revoked for t in db.scalars(select(Token).where(Token.owner_id == profile.id)))
        assert all(not s.active for s in db.scalars(select(Subscription).where(Subscription.owner_id == profile.id)))
        deliveries = list(db.scalars(select(Delivery)))
        assert len(deliveries) == 3 and all(d.state == "stopped" and not d.lease for d in deliveries)
    for raw in (app.extensions["test_credentials"]["agent-a"], "synthetic-additional-key", "synthetic-oauth-access"):
        assert app.test_client().get("/api/profile", headers={"Authorization": "Bearer "+raw}).status_code == 401
        assert app.test_client().post("/mcp", headers={"Authorization": "Bearer "+raw},
            json=dict(jsonrpc="2.0", id=1, method="tools/call", params=dict(name="get_profile", arguments={}))).status_code == 401
    assert get(participant_session, "/").status_code == 302
    refreshed = app.test_client().post("/oauth/token", base_url=BASE, data=dict(grant_type="refresh_token",
        client_id="synthetic-client", refresh_token="synthetic-oauth-refresh", resource=BASE+"/mcp"))
    assert refreshed.status_code == 400 and refreshed.json["error"] == "invalid_grant"
    login = app.test_client()
    page = get(login, "/login")
    assert post(login, "/login", data=dict(csrf=hidden(page, "csrf"), email="agent-a", password="synthetic-password-agent-a")).status_code == 200
    for route in ("edit", "deactivate", "credentials", "reachability", "notifications"):
        assert get(owner, f"/profiles/{route}?profile_id=agent-a").status_code == 404
    page = get(owner, "/profiles")
    assert b"Deactivated" in page.data
    assert b"profile_id=agent-a" not in page.data
    assert create(owner, profile_id="agent-a").status_code == 400
    calls = []
    assert not deliver_one(app.extensions["sessions"], app.config, post=lambda *a: calls.append(a))
    assert not calls


def test_deactivated_recipient_unavailable_for_rest_mcp_and_reply_exception_history_kept(tenants):
    app, first, second = tenants
    policies(app, "intruder", "open")
    first_message = send(app, recipient="intruder", ident="history").json
    thread = first_message["thread_id"]
    assert send(app, sender="intruder", recipient="agent-a", ident="prior-reply", thread_id=thread).status_code == 200
    policies(app, "intruder", "allowlist", ("agent-a",))
    with app.extensions["sessions"].begin() as db:
        db.add(BotAllowlist(receiver_id="agent-a", sender_id="intruder"))
    assert retire(sign_in(app, second), "intruder").status_code == 303
    assert retire(sign_in(app, first), "agent-b").status_code == 303
    for sender, recipient in (("agent-a", "intruder"), ("agent-a", "agent-b")):
        assert recipient not in participants(app, sender)
        for params in ({}, dict(thread_id=thread)):
            response = send(app, sender=sender, recipient=recipient, ident="blocked", **params)
            assert response.status_code == 404 and response.json == {"error": "Recipient is unavailable"}
            payload = dict(message_id="blocked-mcp", recipient=recipient, text="Synthetic", status="received", needs_reply=True, **params)
            rpc = app.test_client().post("/mcp", headers=bearer_headers(app, sender), json=dict(jsonrpc="2.0", id=1,
                method="tools/call", params=dict(name="send_message", arguments=payload))).json
            assert rpc["error"]["message"] == "Recipient is unavailable"
    assert send(app, recipient="intruder", ident="history").status_code == 404
    for client in (sign_in(app, first), sign_in(app, second), sign_in(app, "agent-a", "participant")):
        response = get(client, "/message?message_id=prior-reply")
        assert response.status_code == 200 and b"deactivated" in response.data
    assert b"deactivated" in get(sign_in(app, first), "/conversation?thread_id="+thread).data
    api = app.test_client().get("/api/messages/prior-reply", headers=bearer_headers(app, "agent-a"))
    assert api.status_code == 200 and api.json["sender_deactivated"] is True
    with app.extensions["sessions"]() as db:
        assert db.get(BotAllowlist, ("agent-a", "intruder"))
        assert db.get(BotAllowlist, ("intruder", "agent-a"))


@pytest.mark.parametrize("command", ["sync-config", "init-db"])
def test_account_admin_name_survives_cli_and_config_still_syncs(bridge_app, monkeypatch, command):
    import sys
    import bridge.__main__ as cli
    app = bridge_app
    owner = sign_in(app, "seed-admin")
    csrf = hidden(get(owner, "/account"), "csrf")
    assert post(owner, "/account", data=dict(csrf=csrf, name="Edited Admin")).status_code == 303
    app.config["BROWSER_ADMIN"] = dict(app.config["BROWSER_ADMIN"], name="Config Name", email="updated@example.com")
    monkeypatch.setattr(cli, "create_app", lambda: app)
    monkeypatch.setattr(sys, "argv", ["bridge", command])
    cli.main()
    with app.extensions["sessions"]() as db:
        admin = db.get(BrowserOwner, "seed-admin")
        assert admin.name == "Edited Admin" and admin.email == "updated@example.com" and admin.active
    with app.extensions["sessions"].begin() as db:
        bootstrap(db, dict(app.config, BROWSER_ADMIN=dict(app.config["BROWSER_ADMIN"], id="fresh-admin", name="Fresh Config Name")))
    with app.extensions["sessions"]() as db:
        assert db.get(BrowserOwner, "fresh-admin").name == "Fresh Config Name"


def test_deactivation_schema_populated_v020_and_fresh_idempotent(bridge_app):
    engine = bridge_app.extensions["engine"]
    ensure_deactivation_schema(engine)
    ensure_deactivation_schema(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE participants DROP COLUMN deactivated_at")
        before = connection.exec_driver_sql("SELECT id, name, active FROM participants ORDER BY id").all()
    ensure_deactivation_schema(engine)
    ensure_deactivation_schema(engine)
    columns = {c["name"]: c for c in inspect(engine).get_columns("participants")}
    assert columns["deactivated_at"]["nullable"]
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT id, name, active FROM participants ORDER BY id").all() == before
        assert connection.exec_driver_sql("SELECT deactivated_at FROM participants").all() == [(None,)] * len(before)


@pytest.mark.parametrize("winner", ["send", "deactivate"])
def test_postgres_send_deactivation_serializes(bridge_app, winner):
    app = bridge_app
    if app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("Requires native PostgreSQL participant row locks")
    from bridge.messages import send_message
    from bridge.errors import Unavailable
    sessions = app.extensions["sessions"]
    with sessions.begin() as db:
        target, source = db.get(Participant, "agent-b"), db.get(Participant, "agent-a")
        target.webhook_enabled, target.webhook_url, target.webhook_token = True, source.webhook_url, source.webhook_token
    locked, resume, entered = Event(), Event(), Event()
    payload = dict(message_id="concurrent", recipient="agent-b", text="Synthetic race", status="received", needs_reply=True)
    def first():
        with sessions.begin() as db:
            if winner == "send":
                send_message(db, app.config, "agent-a", payload)
                locked.set(); assert resume.wait(10)
            else:
                with delivery_fence(db, "agent-b"):
                    lock_profile_changes(db)
                    deactivate_bot(db, "seed-admin", "agent-b")
                    locked.set(); assert resume.wait(10)
    def second():
        entered.set()
        with sessions.begin() as db:
            if winner == "send":
                with delivery_fence(db, "agent-b"):
                    lock_profile_changes(db)
                    deactivate_bot(db, "seed-admin", "agent-b")
                return "deactivated"
            try:
                send_message(db, app.config, "agent-a", payload)
            except Unavailable:
                return "unavailable"
            return "sent"
    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(first)
        try:
            assert locked.wait(10)
            two = pool.submit(second)
            assert entered.wait(10)
            with pytest.raises(TimeoutError): two.result(timeout=.2)
        finally:
            resume.set()
        one.result(timeout=15)
        assert two.result(timeout=15) == ("deactivated" if winner == "send" else "unavailable")
    with sessions() as db:
        assert db.get(Participant, "agent-b").deactivated_at is not None
        message = db.get(Message, "concurrent")
        assert bool(message) == (winner == "send")
        if message:
            assert message.created_at <= db.get(Participant, "agent-b").deactivated_at
        deliveries = list(db.scalars(select(Delivery)))
        assert len(deliveries) == (1 if winner == "send" else 0)
        assert all(d.state == "stopped" for d in deliveries)


@pytest.mark.parametrize("stage", ["claimed", "transport"])
def test_dispatch_fence_waits_for_inflight_then_blocks_later_calls(bridge_app, monkeypatch, stage):
    import bridge.worker as worker
    app, sessions = bridge_app, bridge_app.extensions["sessions"]
    owner = sign_in(app, "seed-admin")
    path = "/profiles/deactivate?profile_id=agent-a"
    csrf = hidden(get(owner, path), "csrf")
    assert send(app, sender="agent-b", recipient="agent-a", ident="inflight", needs_reply=True).status_code == 200
    entered, resume, retiring = Event(), Event(), Event()
    calls = []
    original = worker._deliver_one
    def pause():
        entered.set()
        assert resume.wait(10)
    def dispatch(*args):
        if stage == "claimed": pause()
        return original(*args)
    def callback(*args):
        calls.append(args)
        if stage == "transport": pause()
        return 200, b""
    def deactivate():
        retiring.set()
        return post(owner, path, data=dict(csrf=csrf, confirm="deactivate"))
    monkeypatch.setattr(worker, "_deliver_one", dispatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        dispatching = pool.submit(worker.deliver_one, sessions, app.config, callback)
        try:
            assert entered.wait(10)
            retirement = pool.submit(deactivate)
            assert retiring.wait(10)
            with pytest.raises(TimeoutError): retirement.result(timeout=.2)
        finally:
            resume.set()
        assert dispatching.result(timeout=15)
        assert retirement.result(timeout=15).status_code == 303
    assert len(calls) == 1
    # Even a manually retried retained delivery is fenced by recipient state.
    with sessions.begin() as db:
        item = db.scalar(select(Delivery))
        item.state, item.available_at = "pending", 0
    assert worker.deliver_one(sessions, app.config, callback)
    assert len(calls) == 1
    with sessions() as db:
        assert db.scalar(select(Delivery)).state == "stopped"


def test_deactivation_rolls_back_every_change_on_failure(bridge_app, monkeypatch):
    import bridge.lifecycle as lifecycle
    app = bridge_app
    original = lifecycle.revoke_password_connections
    def fail(db, user):
        original(db, user)
        raise RuntimeError("synthetic rollback")
    monkeypatch.setattr(lifecycle, "revoke_password_connections", fail)
    assert retire(sign_in(app, "seed-admin"), "agent-a").status_code == 500
    with app.extensions["sessions"]() as db:
        profile, user = db.get(Participant, "agent-a"), db.get(User, "agent-a")
        assert profile.active and profile.deactivated_at is None and profile.webhook_enabled
        assert user.active and user.api_key_hash and user.password_hash


def test_deactivated_files_keep_owner_and_shared_participant_scope(tenants):
    from bridge.models import Artifact, MessageArtifact
    from test_files import FakeStore
    app, first, second = tenants
    policies(app, "intruder", "open")
    message = send(app, ident="retained-files").json
    with app.extensions["sessions"].begin() as db:
        for ident, bot in (("retired-file", "intruder"), ("other-file", "agent-a")):
            db.add(Artifact(id=ident, owner_id=bot, idempotency_key=ident, object_key=ident,
                filename=ident+".txt", content_type="text/plain", size_bytes=123, sha256="0"*64, state="ready"))
        db.flush()
        db.add_all([MessageArtifact(message_id=message["message_id"], artifact_id=ident) for ident in ("retired-file", "other-file")])
    app.extensions["object_store"] = FakeStore()
    assert retire(sign_in(app, second), "intruder").status_code == 303
    for owner, own_file, foreign in ((first, "other-file", "retired-file"), (second, "retired-file", "other-file")):
        client = sign_in(app, owner)
        assert get(client, f"/files/{own_file}/download").status_code == 302
        assert get(client, f"/files/{foreign}/download").status_code == 404
        page = get(client, "/conversation?thread_id="+message["thread_id"])
        assert (foreign+".txt").encode() in page.data and (f'href="/files/{foreign}/download"').encode() not in page.data
    assert get(sign_in(app, "agent-a", "participant"), "/files/retired-file/download").status_code == 302


def test_retired_sender_notification_matches_event_schema(bridge_app):
    import json
    from test_fix_round4 import validate_published_payload
    app = bridge_app
    message = send(app, sender="agent-b", recipient="agent-a", ident="retired-sender", needs_reply=True)
    assert message.status_code == 200
    assert retire(sign_in(app, "seed-admin")).status_code == 303
    rpc = app.test_client().post("/mcp", headers=bearer_headers(app, "agent-a"),
        json=dict(jsonrpc="2.0", id=1, method="events/list")).json
    schema = rpc["result"]["events"][0]["payloadSchema"]
    calls = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda u,b,h: calls.append(json.loads(b)) or (200,b""))
    assert calls[0]["data"]["sender_deactivated"] is True
    validate_published_payload(calls[0]["data"], schema)


def test_display_name_length_boundary_shared_with_creation_and_registration(bridge_app):
    from test_multi_owner import invite
    app = bridge_app
    client = sign_in(app, "seed-admin")
    assert edit(client, name="N"*200).status_code == 303
    assert create(client, profile_id="too-long-name", name="N"*201).status_code == 400
    assert create(client, profile_id="valid-name", name="N"*200).status_code == 200
    ident, code = invite(app)
    from bridge.models_auth import OwnerInvitation
    registering = app.test_client()
    fields = dict(csrf=hidden(get(registering, "/register"), "csrf"), email="name-boundary@example.com",
                  password="synthetic-password", code=code, name="N"*201)
    assert post(registering, "/register", data=fields).status_code == 400
    with app.extensions["sessions"]() as db:
        assert db.get(OwnerInvitation, ident).redeemed_at is None
    fields["name"] = "N"*200
    assert post(registering, "/register", data=fields).status_code == 303


@pytest.mark.parametrize("ownership", ["same", "cross"])
def test_retired_prior_writer_rejects_valid_existing_and_new_thread_sends(tenants, ownership):
    app, first, second = tenants
    target = "agent-b" if ownership == "same" else "intruder"
    target_owner = first if ownership == "same" else second
    policies(app, "agent-a", "open")
    thread = send(app, sender=target, recipient="agent-a", ident="target-wrote").json["thread_id"]
    assert send(app, recipient=target, ident="allowed-reply", thread_id=thread).status_code == 200
    assert retire(sign_in(app, target_owner), target).status_code == 303
    for extra in ({}, dict(thread_id=thread)):
        assert send(app, recipient=target, ident="retired-rest", **extra).status_code == 404
        rpc = app.test_client().post("/mcp", headers=bearer_headers(app, "agent-a"), json=dict(jsonrpc="2.0", id=1,
            method="tools/call", params=dict(name="send_message", arguments=dict(message_id="retired-mcp", recipient=target,
                text="Synthetic blocked send", status="received", needs_reply=True, **extra)))).json
        assert rpc["error"]["message"] == "Recipient is unavailable"
    assert get(sign_in(app, first), "/conversation?thread_id="+thread).status_code == 200


def test_postgres_deactivation_upgrade_lock_timeout_is_retryable(bridge_app):
    from sqlalchemy.exc import DBAPIError
    engine = bridge_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL DDL lock timeout")
    with engine.begin() as db:
        db.exec_driver_sql("ALTER TABLE participants DROP COLUMN deactivated_at")
    with engine.begin() as locker:
        locker.exec_driver_sql("LOCK TABLE participants IN ACCESS EXCLUSIVE MODE")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(ensure_deactivation_schema, engine)
            with pytest.raises(DBAPIError) as failure:
                future.result(timeout=12)
            assert failure.value.orig.sqlstate == "55P03"
    assert "deactivated_at" not in {c["name"] for c in inspect(engine).get_columns("participants")}
    ensure_deactivation_schema(engine)
    assert "deactivated_at" in {c["name"] for c in inspect(engine).get_columns("participants")}

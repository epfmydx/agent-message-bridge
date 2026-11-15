"""Synthetic private bot labels, public addresses and random invitation handoff."""
import re

import pytest
from sqlalchemy import event, inspect, select

from bridge.auth import digest
from bridge.invitations import REVEAL_LIFETIME, create_invitation, redeem_invitation
from bridge.models import Artifact, BotAllowlist, Message, MessageArtifact, Participant
from bridge.models_auth import BrowserOwner, InvitationReveal, OwnerInvitation, User
from test_files import FakeStore
from test_multi_owner import invite, participants, policies, register_owner, send, tenants
from test_profiles import BASE, create, created_id, get, hidden, post, sign_in


def bot(app, owner, label="mika", **fields):
    response = create(sign_in(app, owner), profile_id=label, **fields)
    assert response.status_code == 200, response.get_data(as_text=True)
    address = created_id(app, label, owner)
    if fields.get("auth_mode", "api_key") == "api_key":
        app.extensions["test_credentials"][address] = re.search(rb'id="profile-api-key">([^<]+)', response.data)[1].decode()
    return address, response


def login(app, identifier, password="synthetic-bot-password"):
    client = app.test_client()
    response = post(client, "/login", data=dict(csrf=hidden(get(client, "/login"), "csrf"),
                                                email=identifier, password=password))
    return client, response


def test_private_labels_are_owner_scoped_and_public_addresses_are_generated(tenants):
    app, first, second = tenants
    left, page = bot(app, first, email="shared@example.com")
    right, _ = bot(app, second, email="shared@example.com")
    assert left != right
    assert all(re.fullmatch(r"amb_[A-Za-z0-9_-]{32}", value) for value in (left, right))
    assert left.encode() in page.data and b"Share this address ID with other owners." in page.data
    assert b"data-copy-address" in page.data
    detail = get(sign_in(app, first), "/profiles/credentials?profile_id=" + left)
    assert b'src="/static/profile-address.js"' in detail.data
    assert "script-src 'self'" in detail.headers["Content-Security-Policy"]
    duplicate = create(sign_in(app, first), profile_id="mika")
    assert duplicate.status_code == 400
    assert b"That chosen ID is already used by one of your bots." in duplicate.data
    with app.extensions["sessions"]() as db:
        assert [db.get(Participant, address).stable_id for address in (left, right)] == ["mika", "mika"]
        assert [db.get(User, address).email for address in (left, right)] == ["shared@example.com"] * 2
    # No runtime fallback from an owner-chosen label to a public address.
    assert send(app, sender=left, recipient="mika", ident="private-label-recipient").status_code == 404
    assert get(sign_in(app, first), "/profiles/credentials?profile_id=mika").status_code == 404


def test_bot_login_uses_address_and_contact_email_is_not_an_identity(tenants):
    app, first, second = tenants
    addresses = []
    for owner in (first, second):
        address, _ = bot(app, owner, auth_mode="oauth", email="seed-admin@example.com",
                         password="synthetic-bot-password")
        addresses.append(address)
        client, result = login(app, address)
        assert result.status_code == 302
        with client.session_transaction(base_url=BASE) as cookie:
            assert cookie["owner"] == address and cookie["account_kind"] == "participant"
    outcomes = []
    for identifier in ("mika", "missing@example.com", "seed-admin@example.com", "amb_" + "x" * 32):
        _, result = login(app, identifier)
        outcomes.append((result.status_code, b"Sign-in details are incorrect." in result.data))
    assert outcomes == [(200, True)] * 4
    # Contact email duplication never prevents independent owner authentication.
    _, result = login(app, "seed-admin@example.com", "synthetic-seed-password")
    assert result.status_code == 302
    # Setting a password on an email-less bot is separately covered by credential tests.
    assert addresses[0] != addresses[1]


def test_cross_owner_interfaces_emit_addresses_not_private_labels_or_contact(tenants):
    app, first, second = tenants
    left, _ = bot(app, first, label="secret-left-label", email="private-left@example.com")
    right, _ = bot(app, second, label="secret-right-label", email="private-right@example.com")
    policies(app, right, "open")
    client = app.test_client()
    from conftest import bearer_headers
    headers = bearer_headers(app, left)
    discovery = client.get("/api/participants", headers=headers)
    mcp = client.post("/mcp", headers=headers, json=dict(jsonrpc="2.0", id=1, method="tools/call",
        params=dict(name="list_participants", arguments={})))
    assert right in str(discovery.json) and right in str(mcp.json)
    message = send(app, sender=left, recipient=right, ident="address-thread").json
    responses = [discovery, mcp,
        client.get("/api/threads/" + message["thread_id"] + "/messages", headers=headers),
        get(sign_in(app, first), "/conversation?thread_id=" + message["thread_id"]),
        get(sign_in(app, first), "/message?message_id=address-thread")]
    for response in responses:
        assert response.status_code == 200
        assert b"secret-right-label" not in response.data and b"private-right@example.com" not in response.data
        assert b"secret-left-label" not in response.data and b"private-left@example.com" not in response.data
    from bridge.events import notification
    from bridge.models import Member
    with app.extensions["sessions"]() as db:
        refs = notification(db, db.get(Message, "address-thread"))["data"]
        assert refs["sender"] == left and refs["recipient"] == right
        assert set(db.scalars(select(Member.participant_id).where(Member.thread_id == message["thread_id"]))) == {left, right}
    # Owner-only forms reject known foreign and unknown addresses identically.
    owner = sign_in(app, first)
    for page in ("credentials", "notifications", "reachability"):
        results = []
        for address in (right, "amb_" + "x" * 32):
            path = "/profiles/" + page + "?profile_id=" + address
            results.append(get(owner, path).status_code)
            assert post(owner, path, data=dict(csrf=hidden(get(owner, "/profiles/new"), "csrf"),
                                               policy="open")).status_code in (400, 404)
        assert results == [404, 404]


def test_generated_addresses_allowlist_replies_and_foreign_file_scope(tenants):
    app, first, second = tenants
    left, _ = bot(app, first)
    right, _ = bot(app, second)
    path = "/profiles/reachability?profile_id=" + right
    owner = sign_in(app, second)
    assert post(owner, path, data=dict(csrf=hidden(get(owner, path), "csrf"), policy="allowlist", sender_ids=left)).status_code == 303
    assert right in participants(app, left) and left not in participants(app, right)
    result = send(app, sender=left, recipient=right, ident="address-first").json
    thread = result["thread_id"]
    policies(app, right, "own_owner")
    # The recipient never wrote: its revoked policy blocks the next message.
    assert send(app, sender=left, recipient=right, ident="address-blocked", thread_id=thread).status_code == 404
    assert send(app, sender=right, recipient=left, ident="address-reply", thread_id=thread).status_code == 200
    assert send(app, sender=left, recipient=right, ident="address-after-revoke", thread_id=thread).status_code == 200
    assert send(app, sender=left, recipient=right, ident="address-new-blocked").status_code == 404
    with app.extensions["sessions"].begin() as db:
        db.add(Artifact(id="address-file", owner_id=right, idempotency_key="file", object_key="synthetic",
            filename="shared-result.txt", content_type="application/x-private", size_bytes=1234, sha256="0" * 64, state="ready"))
        db.flush()
        db.add(MessageArtifact(message_id="address-reply", artifact_id="address-file"))
    app.extensions["object_store"] = FakeStore()
    left_owner, right_owner = sign_in(app, first), sign_in(app, second)
    html = get(left_owner, "/conversation?thread_id=" + thread).data
    assert b"shared-result.txt" in html and b"1.2 kB" in html
    assert b'application/x-private' not in html and b'href="/files/address-file/download"' not in html
    assert get(left_owner, "/files/address-file/download").status_code == 404
    assert get(right_owner, "/files/address-file/download").status_code == 302


def test_allowlist_limit_and_address_validation_preserve_saved_state(tenants):
    app, first, _ = tenants
    address, _ = bot(app, first)
    owner = sign_in(app, first)
    path = "/profiles/reachability?profile_id=" + address
    ids = ["amb_" + format(i, "032x") for i in range(501)]
    def save(text):
        return post(owner, path, data=dict(csrf=hidden(get(owner, path), "csrf"), policy="allowlist", sender_ids=text))
    assert save("\n".join(ids[:500])).status_code == 303
    result = save("\n".join(ids))
    assert result.status_code == 400 and b"Use at most 500 address IDs." in result.data
    result = save("amb_\x00short")
    assert result.status_code == 400 and b"Enter one routing address per line, without control characters." in result.data
    with app.extensions["sessions"]() as db:
        assert set(db.scalars(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == address))) == set(ids[:500])
    page = get(owner, path)
    assert b"even after you restrict access" in page.data


def test_duplicate_owner_email_matches_invalid_code_work_and_keeps_invitation(bridge_app, monkeypatch):
    app = bridge_app
    ident, code = invite(app)
    import werkzeug.security as security
    original = security.generate_password_hash
    calls, queries = [], []
    def hash_password(password):
        calls.append(password)
        return original(password)
    def capture(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().startswith("SELECT") and ("owner_invitations" in statement or "browser_owners" in statement):
            queries.append(statement)
    monkeypatch.setattr(security, "generate_password_hash", hash_password)
    event.listen(app.extensions["engine"], "before_cursor_execute", capture)
    try:
        with app.extensions["sessions"].begin() as db:
            assert redeem_invitation(db, "Synthetic", "seed-admin@example.com", "synthetic-password", code) is None
        first_queries, queries[:] = queries[:], []
        with app.extensions["sessions"].begin() as db:
            assert redeem_invitation(db, "Synthetic", "unknown@example.com", "synthetic-password", "invalid-code") is None
        assert first_queries == queries and len(queries) == 2
        assert calls == ["synthetic-password"] * 2
    finally:
        event.remove(app.extensions["engine"], "before_cursor_execute", capture)
    responses = [register_owner(app, code, "seed-admin@example.com"), register_owner(app, "invalid-code", "unknown@example.com")]
    assert [r.status_code for r in responses] == [400, 400]
    assert all(b"Registration failed. Check your details and invitation code." in r.data for r in responses)
    with app.extensions["sessions"]() as db:
        assert db.get(OwnerInvitation, ident).redeemer_id is None
    assert register_owner(app, code, "valid-new@example.com").status_code == 303


def test_invitation_random_code_survives_secret_rotation_and_is_erased_after_reveal(bridge_app, monkeypatch):
    app = bridge_app
    import bridge.invitations as invitations
    import secrets
    original = secrets.token_urlsafe
    calls = []
    def random_code(size):
        calls.append(size)
        return original(size)
    monkeypatch.setattr(invitations.secrets, "token_urlsafe", random_code)
    with app.extensions["sessions"].begin() as db:
        item, raw = create_invitation(db, db.get(BrowserOwner, "seed-admin"))
        ident = item.id
        assert item.code_hash == digest(raw) and raw not in str(item.__dict__)
        reveal = db.get(InvitationReveal, ident)
        assert reveal.code == raw and reveal.expires_at - item.created_at == REVEAL_LIFETIME
    assert calls == [32] and len(raw) == 43
    app.secret_key = "synthetic-rotated-session-secret"
    owner = sign_in(app, "seed-admin")
    path = "/invitations/created?invitation_id=" + ident
    result = get(owner, path)
    assert result.status_code == 200 and raw.encode() in result.data
    assert raw not in str(result.headers)
    with owner.session_transaction(base_url=BASE) as cookie:
        assert raw not in str(dict(cookie))
    with app.extensions["sessions"]() as db:
        assert db.get(InvitationReveal, ident) is None
    assert get(owner, path).status_code == 303
    assert raw.encode() not in get(owner, "/invitations").data


@pytest.mark.parametrize("action", ["expired", "revoked", "redeemed"])
def test_invitation_temporary_plaintext_is_unavailable_after_expiry_revoke_or_redeem(bridge_app, action):
    app = bridge_app
    ident, raw = invite(app)
    owner = sign_in(app, "seed-admin")
    if action == "expired":
        with app.extensions["sessions"].begin() as db:
            db.get(InvitationReveal, ident).expires_at = 0
    elif action == "revoked":
        assert post(owner, "/invitations", data=dict(csrf=hidden(get(owner, "/invitations"), "csrf"),
            action="revoke", invitation_id=ident)).status_code == 303
    else:
        assert register_owner(app, raw).status_code == 303
    assert get(owner, "/invitations/created?invitation_id=" + ident).status_code == 303
    with app.extensions["sessions"]() as db:
        assert db.get(InvitationReveal, ident) is None
        assert db.get(OwnerInvitation, ident).code_hash == digest(raw)


def test_invitation_list_shows_redeemer_name_and_email(bridge_app):
    app = bridge_app
    _, code = invite(app)
    assert register_owner(app, code, "redeemer@example.com").status_code == 303
    with app.extensions["sessions"]() as db:
        owner = db.scalar(select(BrowserOwner).where(BrowserOwner.email == "redeemer@example.com"))
        ident = owner.id
    page = get(sign_in(app, "seed-admin"), "/invitations")
    assert b"New Owner" in page.data and b"redeemer@example.com" in page.data
    assert ident.encode() not in page.data


def test_private_id_schema_constraints_and_legacy_email_guard(bridge_app, tmp_path):
    from bridge.models import database
    from bridge.schema import ensure_multi_owner_schema
    engine = bridge_app.extensions["engine"]
    ensure_multi_owner_schema(engine)
    ensure_multi_owner_schema(engine)
    inspector = inspect(engine)
    assert any(c["column_names"] == ["owner_account_id", "stable_id"] for c in inspector.get_unique_constraints("participants"))
    assert not any(c["column_names"] == ["email"] for c in inspector.get_unique_constraints("oauth_users"))
    assert "invitation_reveals" in inspector.get_table_names()
    old_engine, _ = database("sqlite:///" + str(tmp_path / "legacy.sqlite"))
    with old_engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY, email VARCHAR UNIQUE)")
    with pytest.raises(RuntimeError, match="fresh database"):
        ensure_multi_owner_schema(old_engine)
    old_engine.dispose()


def test_policy_accepted_send_skips_thread_reply_lookup(tenants):
    app, _, _ = tenants
    policies(app, "intruder", "open")
    thread = send(app, ident="policy-accepted-first").json["thread_id"]
    queries = []
    def capture(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().startswith("SELECT messages.id") and "messages.sender_id =" in statement and "messages.thread_id =" in statement:
            queries.append(statement)
    event.listen(app.extensions["engine"], "before_cursor_execute", capture)
    try:
        assert send(app, ident="policy-accepted-second", thread_id=thread).status_code == 200
    finally:
        event.remove(app.extensions["engine"], "before_cursor_execute", capture)
    assert queries == []


def test_legacy_address_strings_are_accepted_without_existence_or_prefix_oracle(tenants):
    app, first, _ = tenants
    address, _ = bot(app, first)
    owner = sign_in(app, first)
    path = "/profiles/reachability?profile_id=" + address
    for ident in ("legacy-agent", "amb_short"):
        response = post(owner, path, data=dict(csrf=hidden(get(owner, path), "csrf"), policy="allowlist", sender_ids=ident))
        assert response.status_code == 303
        with app.extensions["sessions"]() as db:
            assert list(db.scalars(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == address))) == [ident]

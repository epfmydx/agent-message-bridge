"""Synthetic owner-only webhook forms, atomic provisioning and secret handling."""
import html
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from flask import url_for
from sqlalchemy import event, select
from werkzeug.datastructures import MultiDict

from bridge.auth import digest
from bridge.errors import Conflict, Invalid
from bridge.models import Delivery, Participant, Subscription
from bridge.models_auth import BrowserOwner, User
from bridge.profile_webhooks import view_webhook
from test_events import subscribe
from test_profiles import BASE, HEADERS, create, form, get, hidden, post, profile_app, sign_in


PATH = "/profiles/notifications?profile_id=agent-b"
DESTINATION = "https://receiver.example.com/private-destination?credential=synthetic-url-secret"
OUTBOUND_TOKEN = "synthetic-outbound-bearer-secret"


def notification_form(client, path=PATH, **fields):
    page = get(client, path)
    assert page.status_code == 200
    return dict(csrf=hidden(page, "csrf"),
                expected_generation=hidden(page, "expected_generation"), **fields)


def configure(client, path=PATH):
    return post(client, path, data=notification_form(client, path,
                webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN))


def state(app, ident="agent-b"):
    with app.extensions["sessions"]() as db:
        return view_webhook(app.config, db.get(Participant, ident))


def assert_private(response, *extra):
    for secret in (DESTINATION, OUTBOUND_TOKEN, "private-destination", "synthetic-url-secret", *extra):
        assert secret.encode() not in response.data
        assert secret not in str(response.headers)
    assert response.headers["Cache-Control"] == "no-store"


def assert_blank_fields(response):
    for name in ("webhook_url", "webhook_token"):
        tag = re.search(('<input[^>]+name="'+name+'"[^>]*>').encode(), response.data)[0]
        assert b'value="' not in tag or b'value=""' in tag
        assert b'type="password"' in tag


def test_notification_page_owner_only_and_api_key_is_not_browser_login(profile_app):
    assert get(profile_app.test_client(), PATH).status_code == 302
    for ident in ("agent-b", "intruder"):
        client = sign_in(profile_app, ident, "participant")
        assert get(client, PATH).status_code == 403
        assert post(client, PATH, data={}).status_code == 403
    response = profile_app.test_client().get(PATH, base_url=BASE, headers={**HEADERS,
        "Authorization": "Bearer "+profile_app.extensions["test_credentials"]["agent-b"]})
    assert response.status_code == 302
    assert get(sign_in(profile_app), PATH).status_code == 200


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("headers,environ,status", [
    ({}, {}, 403),
    ({**HEADERS, "X-Bridge-Origin": "wrong"}, {}, 403),
    (HEADERS, {"REMOTE_ADDR": "8.8.4.4"}, 403),
    ({**HEADERS, "X-Forwarded-Proto": "http"}, {}, 403),
    ({k: v for k, v in HEADERS.items() if k != "CF-Connecting-IP"}, {}, 400),
    ({**HEADERS, "CF-Connecting-IP": "127.0.0.1"}, {}, 400),
])
def test_origin_rejected_before_session_and_sql(profile_app, monkeypatch, method, headers, environ, status):
    sessions, statements = [], []
    factory = profile_app.extensions["sessions"]
    def session(*args, **kwargs):
        sessions.append(True)
        return factory(*args, **kwargs)
    monkeypatch.setitem(profile_app.extensions, "sessions", session)
    engine = profile_app.extensions["engine"]
    def capture(*args):
        statements.append(True)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = getattr(profile_app.test_client(), method)(PATH, base_url=BASE,
            headers=headers, environ_overrides=environ)
        assert response.status_code == status
        assert not sessions and not statements
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def test_notifications_csrf_duplicate_fields_generation_and_revocation(profile_app):
    client = sign_in(profile_app)
    data = notification_form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    assert post(client, PATH, data={**data, "csrf": "wrong"}).status_code == 400
    for name in ("csrf", "webhook_enabled", "expected_generation", "webhook_url", "webhook_token"):
        duplicate = MultiDict(data)
        duplicate.add(name, data[name])
        assert post(client, PATH, data=duplicate).status_code == 400
    for generation in ("", "0", "-1", "1.0", "+1", "01", " 1", "１"):
        assert post(client, PATH, data={**data, "expected_generation": generation}).status_code == 400
    assert post(client, PATH, data={**data, "webhook_enabled": "true"}).status_code == 400
    assert state(profile_app)["state"] == "unconfigured"
    with profile_app.extensions["sessions"].begin() as db:
        db.get(BrowserOwner, "profile-owner").password_hash = "synthetic-revoked-hash"
    assert post(client, PATH, data=data).status_code == 302
    assert state(profile_app)["state"] == "unconfigured"


@pytest.mark.parametrize("inactive", ["participant", "user", "missing"])
def test_notifications_do_not_activate_inactive_or_missing_profiles(profile_app, inactive):
    client = sign_in(profile_app)
    data = notification_form(client)
    path = PATH
    with profile_app.extensions["sessions"].begin() as db:
        if inactive == "participant":
            db.get(Participant, "agent-b").active = False
        elif inactive == "user":
            db.get(User, "agent-b").active = False
        else:
            path = "/profiles/notifications?profile_id=missing"
    assert get(client, path).status_code == 404
    assert post(client, path, data=data).status_code == 404
    if inactive != "missing":
        with profile_app.extensions["sessions"]() as db:
            assert not db.get(Participant if inactive == "participant" else User, "agent-b").active


def test_setup_redirects_and_only_safe_metadata_appears(profile_app):
    client = sign_in(profile_app)
    response = configure(client)
    assert response.status_code == 303 and response.location == PATH
    assert_private(response)
    for page in (get(client, PATH), get(client, "/profiles")):
        assert page.status_code == 200
        assert b"Configured" in page.data and b"receiver.example.com" in page.data
        assert_private(page)
    page = get(client, PATH)
    assert_blank_fields(page)
    assert b"new messages" in page.data
    assert b"unsent notifications from old settings are not resent" in page.data
    assert b"in flight" in page.data
    assert b"Test callback" not in page.data and b"catch up" not in page.data
    with client.session_transaction(base_url=BASE) as browser:
        assert DESTINATION not in str(dict(browser)) and OUTBOUND_TOKEN not in str(dict(browser))
    with profile_app.extensions["sessions"]() as db:
        participant = db.get(Participant, "agent-b")
        assert participant.webhook_url == DESTINATION
        assert participant.webhook_token and participant.webhook_token != OUTBOUND_TOKEN


def test_invalid_and_stale_forms_keep_secret_fields_blank(profile_app):
    client = sign_in(profile_app)
    old = notification_form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    assert post(client, PATH, data=old).status_code == 303
    response = post(client, PATH, data={**old, "webhook_url": "https://other.example.com/secret-path"})
    assert response.status_code == 409
    assert b"changed since this form" in response.data
    assert_private(response, "secret-path")
    assert_blank_fields(response)
    current = notification_form(client, webhook_enabled="1", webhook_url="https://new.example.com/private-secret")
    response = post(client, PATH, data=current)
    assert response.status_code == 400
    assert_private(response, "private-secret")
    assert_blank_fields(response)
    assert state(profile_app)["hostname"] == "receiver.example.com"


@pytest.mark.parametrize("exception", [Invalid, Conflict])
def test_backend_validation_details_never_echo(profile_app, monkeypatch, exception):
    import bridge.profiles as profiles
    client = sign_in(profile_app)
    data = notification_form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    def rejected(*args, **kwargs):
        raise exception(DESTINATION+OUTBOUND_TOKEN)
    monkeypatch.setattr(profiles, "update_webhook", rejected)
    response = post(client, PATH, data=data)
    assert response.status_code == (409 if exception is Conflict else 400)
    assert_private(response)
    assert_blank_fields(response)


def test_repeated_interrupted_post_and_unchanged_save_are_safe(profile_app):
    client = sign_in(profile_app)
    data = notification_form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    # Simulate a committed save whose redirect is lost to the caller.
    assert post(client, PATH, data=data).status_code == 303
    committed = state(profile_app)
    assert post(client, PATH, data=data).status_code == 409
    assert state(profile_app) == committed
    keep = notification_form(client, webhook_enabled="1")
    assert post(client, PATH, data=keep).status_code == 303
    assert state(profile_app) == committed
    assert post(client, PATH, data=keep).status_code == 303
    assert state(profile_app) == committed


def test_explicit_disable_prevents_legacy_fallback_and_can_reenable(profile_app):
    client = sign_in(profile_app)
    path = "/profiles/notifications?profile_id=agent-a"
    assert state(profile_app, "agent-a")["state"] == "inherited"
    assert b"Inherited legacy configuration" in get(client, path).data
    inherited = state(profile_app, "agent-a")
    assert post(client, path, data=notification_form(client, path, webhook_enabled="1")).status_code == 303
    assert state(profile_app, "agent-a") == inherited
    assert post(client, path, data=notification_form(client, path)).status_code == 303
    assert state(profile_app, "agent-a")["state"] == "disabled"
    assert b"Disabled" in get(client, path).data
    with profile_app.extensions["sessions"]() as db:
        assert db.get(Participant, "agent-a").webhook_enabled is False
    assert post(client, path, data=notification_form(client, path, webhook_enabled="1")).status_code == 303
    assert state(profile_app, "agent-a")["state"] == "enabled"


@pytest.mark.parametrize("invalid_fields", [
    {"webhook_url": "http://receiver.example.com/private-destination"},
    {"webhook_token": ""},
    {"webhook_url": ""},
    {"webhook_token": "synthetic-token-\u2603"},
])
def test_creation_webhook_failure_rolls_back_identity_and_replay_marker(profile_app, invalid_fields):
    client = sign_in(profile_app)
    data = form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    response = post(client, "/profiles/new", data={**data, **invalid_fields})
    assert response.status_code == 400
    assert_private(response)
    assert_blank_fields(response)
    with profile_app.extensions["sessions"]() as db:
        assert not db.get(Participant, "new-participant") and not db.get(User, "new-participant")
    # A corrected submission can reuse the creation form because failure was atomic.
    assert post(client, "/profiles/new", data=data).status_code == 200
    assert state(profile_app, "new-participant")["state"] == "enabled"
    assert post(client, "/profiles/new", data=data).status_code == 400


def test_unencodable_replacement_token_keeps_current_settings_and_secret_fields_blank(profile_app):
    client = sign_in(profile_app)
    assert configure(client).status_code == 303
    before = state(profile_app)
    data = notification_form(client, webhook_enabled="1", webhook_token="synthetic-token-\u2603")
    response = post(client, PATH, data=data)
    assert response.status_code == 400
    assert state(profile_app) == before
    assert_private(response, "synthetic-token-\u2603")
    assert_blank_fields(response)


def test_latin1_replacement_token_remains_supported(profile_app):
    from bridge.profile_webhooks import callback
    client = sign_in(profile_app)
    assert configure(client).status_code == 303
    token = "synthetic-caf\u00e9-token"
    data = notification_form(client, webhook_enabled="1", webhook_token=token)
    assert post(client, PATH, data=data).status_code == 303
    with profile_app.extensions["sessions"]() as db:
        assert callback(profile_app.config, db.get(Participant, "agent-b"))[1] == token


def test_api_key_once_with_webhook_and_independent_oauth_creation(profile_app):
    client = sign_in(profile_app)
    response = create(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    assert response.status_code == 200
    raw_key = re.search(rb'id="profile-api-key">([^<]+)', response.data)[1].decode()
    assert_private(response)
    for page in (get(client, "/profiles"), get(client, "/profiles/new"),
                 get(client, "/profiles/notifications?profile_id=new-participant")):
        assert_private(page, raw_key)
    with client.session_transaction(base_url=BASE) as browser:
        assert all(secret not in str(dict(browser)) for secret in (raw_key, DESTINATION, OUTBOUND_TOKEN))
    with profile_app.extensions["sessions"]() as db:
        user = db.get(User, "new-participant")
        assert user.api_key_hash == digest(raw_key) and not user.password_hash
    # The outbound credential does not authenticate as the participant.
    assert profile_app.test_client().get("/api/profile", base_url=BASE,
        headers={"Authorization": "Bearer "+OUTBOUND_TOKEN}).status_code == 401
    response = create(client, profile_id="oauth-webhook", auth_mode="oauth", email="new@example.com",
        password="synthetic-password", webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    assert response.status_code == 200 and b'id="profile-api-key"' not in response.data
    assert state(profile_app, "oauth-webhook")["state"] == "enabled"


def test_webhook_settings_preserve_auth_and_client_subscriptions_without_verification(profile_app):
    client = sign_in(profile_app)
    assert "result" in subscribe(profile_app.test_client(), profile_app)
    verifications = []
    profile_app.extensions["verify_callback"] = lambda *args: verifications.append(args)
    with profile_app.extensions["sessions"]() as db:
        user = db.get(User, "agent-b")
        original = (user.password_hash, user.api_key_hash, user.email, user.active)
        subscriptions = db.execute(select(Subscription.__table__)).all()
        assert subscriptions
    assert configure(client).status_code == 303
    assert post(client, PATH, data=notification_form(client)).status_code == 303
    with profile_app.extensions["sessions"]() as db:
        user = db.get(User, "agent-b")
        assert (user.password_hash, user.api_key_hash, user.email, user.active) == original
        assert db.execute(select(Subscription.__table__)).all() == subscriptions
    assert not verifications


def test_creation_checkbox_duplicates_and_disabled_fields_are_not_saved(profile_app):
    client = sign_in(profile_app)
    data = form(client, webhook_enabled="1", webhook_url=DESTINATION, webhook_token=OUTBOUND_TOKEN)
    duplicate = MultiDict(data)
    duplicate.add("webhook_enabled", "1")
    assert post(client, "/profiles/new", data=duplicate).status_code == 400
    data.pop("webhook_enabled")
    profile_app.config["WEBHOOK_PARTICIPANT_ID"] = "new-participant"
    assert post(client, "/profiles/new", data=data).status_code == 200
    with profile_app.extensions["sessions"]() as db:
        participant = db.get(Participant, "new-participant")
        assert participant.webhook_url is None and participant.webhook_token is None
        assert participant.webhook_enabled is False
    assert state(profile_app, "new-participant")["state"] == "disabled"


@pytest.mark.parametrize("ident", ["nested/profile", "/leading/profile", "多言語 profile", "opaque?part", "opaque#fragment"])
def test_notification_links_and_posts_preserve_opaque_profile_ids(profile_app, ident):
    client = sign_in(profile_app)
    assert create(client, profile_id=ident).status_code == 200
    with profile_app.test_request_context(base_url=BASE):
        path = url_for("profile_notifications", profile_id=ident)
    parsed = urlsplit(path)
    assert parsed.path == "/profiles/notifications" and not parsed.fragment
    assert parse_qs(parsed.query) == {"profile_id": [ident]}
    listing = get(client, "/profiles")
    assert ('href="'+html.escape(path, quote=True)+'"').encode() in listing.data
    page = get(client, path)
    assert page.status_code == 200
    action = re.search(rb'<form method="post" action="([^"]+)" class="form-panel">', page.data)[1].decode()
    assert html.unescape(action) == path
    response = configure(client, html.unescape(action))
    assert response.status_code == 303 and response.location == path
    assert state(profile_app, ident)["state"] == "enabled"
    assert get(client, response.location).status_code == 200


@pytest.mark.parametrize("path", [
    "/profiles/notifications",
    "/profiles/notifications?profile_id=agent-b&profile_id=intruder",
    "/profiles/notifications?profile_id=agent-b&extra=value",
])
def test_notifications_require_exactly_one_profile_id_query_argument(profile_app, path):
    client = sign_in(profile_app)
    data = notification_form(client)
    assert get(client, path).status_code == 400
    assert post(client, path, data=data).status_code == 400


def test_unconfigured_inherited_save_preserves_generation_and_retained_queue(profile_app):
    response = profile_app.test_client().post("/api/messages", base_url=BASE,
        headers={"Authorization": "Bearer "+profile_app.extensions["test_credentials"]["agent-b"]},
        json=dict(message_id="synthetic-retained-legacy", recipient="agent-a", text="Synthetic retained notification",
                  status="received", needs_reply=True))
    assert response.status_code == 200
    profile_app.config["WEBHOOK_URL"] = ""
    profile_app.config["WEBHOOK_TOKEN"] = ""
    inherited = state(profile_app, "agent-a")
    assert inherited["state"] == "inherited" and not inherited["configured"]
    with profile_app.extensions["sessions"]() as db:
        queued = db.execute(select(Delivery.__table__)).all()
        assert queued
    client = sign_in(profile_app)
    path = "/profiles/notifications?profile_id=agent-a"
    page = get(client, path)
    assert b"Inherited legacy configuration (unconfigured)" in page.data
    checkbox = re.search(rb'<input[^>]+name="webhook_enabled"[^>]*>', page.data)[0]
    assert b" checked" in checkbox
    data = dict(csrf=hidden(page, "csrf"), expected_generation=hidden(page, "expected_generation"), webhook_enabled="1")
    assert post(client, path, data=data).status_code == 303
    assert state(profile_app, "agent-a") == inherited
    with profile_app.extensions["sessions"]() as db:
        assert db.execute(select(Delivery.__table__)).all() == queued

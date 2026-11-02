"""Owner credential flows through protected forms; all credentials are synthetic."""
import html
import re
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select
from werkzeug.datastructures import MultiDict

from bridge.app import bootstrap
from bridge.models import Participant, Subscription
from bridge.models_auth import APIKey, User
from test_profiles import BASE, HEADERS, create, get, post, profile_app, sign_in

PATH = "/profiles/credentials?profile_id=agent-b"


def test_key_reveal_copy_and_recovery_interactions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the reveal/copy interaction harness")
    subprocess.run([node, "--test", str(Path(__file__).with_name("profile_credentials_dom.cjs"))], check=True,
                   capture_output=True, text=True)


def credential_form(client, action="create_key", path=PATH, key_id=None):
    page = get(client, path)
    assert page.status_code == 200
    for form in re.findall(rb'<form\b[^>]*>(.*?)</form>', page.data, re.S):
        fields = {}
        for tag in re.findall(rb'<input\b[^>]*>', form):
            attrs = dict(re.findall(rb'([\w-]+)="([^"]*)"', tag))
            if b"name" in attrs:
                fields[attrs[b"name"].decode()] = html.unescape(attrs.get(b"value", b"").decode())
        if fields.get("action") == action and (key_id is None or fields.get("key_id") == key_id):
            return fields
    raise AssertionError("Expected credential form")


def bearer(app, raw):
    return app.test_client().get("/api/profile", base_url=BASE, headers={"Authorization": "Bearer " + raw})


def raw_key(response):
    return html.unescape(re.search(rb'id="created-api-key"[^>]+value="([^"]+)"', response.data)[1].decode())


def test_visible_actions_owner_only_and_origin_before_database(profile_app):
    client = sign_in(profile_app)
    listing = get(client, "/profiles")
    assert b'Credentials for Agent B' in listing.data
    assert b'Notifications for Agent B' in listing.data
    assert get(profile_app.test_client(), PATH).status_code == 302
    participant = sign_in(profile_app, "agent-b", "participant")
    assert get(participant, PATH).status_code == 403
    assert post(participant, PATH, data={}).status_code == 403
    statements = []
    engine = profile_app.extensions["engine"]
    def capture(*args): statements.append(True)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert profile_app.test_client().get(PATH, base_url=BASE).status_code == 403
        assert profile_app.test_client().post(PATH, base_url=BASE).status_code == 403
        assert not statements
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def test_real_key_handover_one_time_display_and_selected_revocation(profile_app, caplog):
    client = sign_in(profile_app)
    form = credential_form(client)
    created = post(client, PATH, data=form)
    assert created.status_code == 200
    new_key = raw_key(created)
    old_key = profile_app.extensions["test_credentials"]["agent-b"]
    assert bearer(profile_app, old_key).status_code == bearer(profile_app, new_key).status_code == 200
    assert created.headers["Cache-Control"] == "no-store"
    assert created.headers["Referrer-Policy"] == "no-referrer"
    assert "script-src 'self'" in created.headers["Content-Security-Policy"]
    assert new_key not in str(created.headers) and new_key not in caplog.text
    assert b'type="password" readonly' in created.data
    with client.session_transaction(base_url=BASE) as browser:
        assert new_key not in str(dict(browser))
    assert post(client, PATH, data=form).status_code == 409
    listed = get(client, PATH)
    assert new_key.encode() not in listed.data
    assert b" UTC</time>" in listed.data
    revoke = credential_form(client, "revoke_key", key_id="legacy")
    assert post(client, PATH, data=revoke).status_code == 303
    assert bearer(profile_app, old_key).status_code == 401
    assert bearer(profile_app, new_key).status_code == 200
    page = get(client, PATH)
    assert b"API key revoked" in page.data and b"1 active key" in page.data
    assert post(client, PATH, data=revoke).status_code == 409
    # An unchanged deployment sync cannot resurrect the retired original key.
    with profile_app.extensions["sessions"].begin() as db:
        bootstrap(db, profile_app.config)
    assert bearer(profile_app, old_key).status_code == 401
    assert bearer(profile_app, new_key).status_code == 200


@pytest.mark.parametrize("change", ["rotate", "remove"])
def test_config_key_change_warning_matches_ui_key_and_subscription_revocation(profile_app, change):
    from bridge.auth import digest
    from test_credentials import subscription
    app, client = profile_app, sign_in(profile_app)
    page = get(client, PATH)
    assert b"until revoked here or the configured API key changes" in page.data
    assert b"revokes all profile keys, including keys created here, and their event subscriptions" in page.data
    assert b"Existing keys remain active until you revoke them." not in page.data
    key = raw_key(post(client, PATH, data=credential_form(client)))
    sub_id = subscription(app, key).get_json()["result"]["id"]
    with app.extensions["sessions"].begin() as db:
        bootstrap(db, app.config)
        assert db.get(Subscription, sub_id).active
    assert bearer(app, key).status_code == 200
    settings = dict(app.config, USERS=[dict(item) for item in app.config["USERS"]])
    configured = next(item for item in settings["USERS"] if item["id"] == "agent-b")
    if change == "rotate": configured["api_key_hash"] = digest("synthetic-config-replacement")
    else: configured.pop("api_key_hash")
    with app.extensions["sessions"].begin() as db:
        bootstrap(db, settings)
        assert not db.get(Subscription, sub_id).active
    assert bearer(app, key).status_code == 401
    if change == "rotate":
        assert bearer(app, "synthetic-config-replacement").status_code == 200


def test_database_profile_keeps_local_key_handover_copy_without_config_warning(profile_app):
    client = sign_in(profile_app)
    assert create(client, profile_id="synthetic-ui-profile").status_code == 200
    page = get(client, "/profiles/credentials?profile_id=synthetic-ui-profile")
    assert page.status_code == 200
    assert b"Existing keys remain active until you revoke them." in page.data
    assert b"credential-config-note" not in page.data


def test_csrf_scoped_tokens_duplicates_and_conflicts(profile_app):
    client = sign_in(profile_app)
    data = credential_form(client)
    assert post(client, PATH, data={**data, "csrf": "wrong"}).status_code == 400
    assert post(client, PATH, data={**data, "action": "revoke_key", "key_id": "legacy"}).status_code == 400
    assert post(client, "/profiles/credentials?profile_id=intruder", data=data).status_code == 400
    assert post(client, PATH, data=MultiDict([*data.items(), ("action", "create_key")])).status_code == 400
    assert post(client, PATH, data={**data, "owner": "participant"}).status_code == 400
    with profile_app.extensions["sessions"]() as db:
        assert not list(db.scalars(select(APIKey)))
    assert post(client, PATH, data=data).status_code == 200
    stale = post(client, PATH, data=data)
    assert stale.status_code == 409 and b"Review the current status" in stale.data


def test_password_confirmation_reset_session_impact_and_no_secret_echo(profile_app):
    owner = sign_in(profile_app)
    participant = sign_in(profile_app, "agent-b", "participant")
    data = credential_form(owner, "reset_password")
    password = "synthetic-ui-replacement-password"
    invalid = post(owner, PATH, data={**data, "password": password, "password_confirmation": "different"})
    assert invalid.status_code == 400 and password.encode() not in invalid.data
    assert b'aria-invalid="true"' in invalid.data
    assert b'password_confirmation' in invalid.data and b'value="synthetic-' not in invalid.data
    assert post(owner, PATH, data={**data, "password": password, "password_confirmation": password}).status_code == 303
    assert get(participant, "/").status_code == 302
    assert get(owner, PATH).status_code == 200
    old_key = profile_app.extensions["test_credentials"]["agent-b"]
    assert bearer(profile_app, old_key).status_code == 200
    with profile_app.extensions["sessions"].begin() as db:
        bootstrap(db, profile_app.config)
        assert db.get(User, "agent-b").password_source == "database"
    assert get(participant, "/").status_code == 302


def test_interrupted_reveal_recover_by_metadata_and_revoke(profile_app, monkeypatch):
    import bridge.profiles as profiles
    client = sign_in(profile_app)
    data = credential_form(client)
    original = profiles._credential_response
    def interrupted(template, **context):
        if template == "profile-key-created.html":
            raise RuntimeError("synthetic interrupted response")
        return original(template, **context)
    monkeypatch.setattr(profiles, "_credential_response", interrupted)
    assert post(client, PATH, data=data).status_code == 500
    monkeypatch.setattr(profiles, "_credential_response", original)
    assert post(client, PATH, data=data).status_code == 409
    with profile_app.extensions["sessions"]() as db:
        keys = list(db.scalars(select(APIKey)))
        assert len(keys) == 1
        key_id = keys[0].id
    assert key_id.encode() in get(client, PATH).data
    revoke = credential_form(client, "revoke_key", key_id=key_id)
    assert post(client, PATH, data=revoke).status_code == 303


def test_same_form_concurrent_submission_creates_one_key(profile_app):
    client = sign_in(profile_app)
    data = credential_form(client)
    cookie = client.get_cookie("session", domain="bridge.example.com")
    def submit(_):
        racing = profile_app.test_client()
        racing.set_cookie("session", cookie.value, domain="bridge.example.com")
        return post(racing, PATH, data=data).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == [200, 409]
    with profile_app.extensions["sessions"]() as db:
        assert len(list(db.scalars(select(APIKey)))) == 1


def test_no_email_and_inactive_profile_states(profile_app):
    client = sign_in(profile_app)
    assert create(client).status_code == 200
    path = "/profiles/credentials?profile_id=new-participant"
    page = get(client, path)
    assert b"no email address" in page.data and b'name="password"' not in page.data
    assert b"Create replacement key" in page.data
    with profile_app.extensions["sessions"].begin() as db:
        db.get(Participant, "new-participant").active = False
    assert get(client, path).status_code == 404
    assert get(client, "/profiles/credentials?profile_id=missing").status_code == 404
    assert get(client, "/profiles/credentials?profile_id=agent-b&profile_id=intruder").status_code == 400


def test_owner_revocation_while_form_open_cannot_change_credentials(profile_app):
    from bridge.models_auth import BrowserOwner
    client = sign_in(profile_app)
    data = credential_form(client)
    with profile_app.extensions["sessions"].begin() as db:
        db.get(BrowserOwner, "profile-owner").active = False
    assert post(client, PATH, data=data).status_code == 302
    with profile_app.extensions["sessions"]() as db:
        assert not list(db.scalars(select(APIKey)))

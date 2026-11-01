"""Regression coverage for optional, generation-fenced profile webhooks."""
import json

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import select

from bridge.app import bootstrap
from bridge.errors import Invalid
from bridge.models import Delivery, Member, Message, Participant
from bridge.models_auth import User
from bridge.profile_webhooks import update_webhook, view_webhook
from bridge.worker import deliver_one


def _message(client, app, ident, *, sender="agent-a", recipient="agent-b", needs_reply=True):
    response = client.post("/api/messages", headers={
        "Authorization": "Bearer " + app.extensions["test_credentials"][sender]
    }, json={"message_id": ident, "recipient": recipient, "text": "synthetic payload",
            "status": "received", "needs_reply": needs_reply})
    assert response.status_code == 200
    return response.get_json()


def _enable(app, participant_id="agent-b", *, url="https://agent-b.example.com/hook", token="synthetic-agent-b-token"):
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, participant_id)
        update_webhook(db, app.config, participant, enabled=True, url=url, token=token,
                       expected_generation=participant.webhook_generation)


def _deliveries(app, message_id):
    with app.extensions["sessions"]() as db:
        return list(db.scalars(select(Delivery).where(Delivery.message_id == message_id).order_by(Delivery.kind)))


def test_transport_encodable_token_is_preserved_without_extra_character_policy(bridge_app):
    token = "synthetic-header-token-\u00e9"
    _enable(bridge_app, token=token)
    from bridge.profile_webhooks import callback
    with bridge_app.extensions["sessions"]() as db:
        _, stored = callback(bridge_app.config, db.get(Participant, "agent-b"))
    assert stored == token
    # Preparing a header does not connect or send a request.
    from http.client import HTTPConnection
    connection = HTTPConnection("receiver.example.com")
    connection.putrequest("POST", "/", skip_host=True, skip_accept_encoding=True)
    connection.putheader("Authorization", "Bearer " + stored)
    connection.close()


def test_legacy_null_generation_uses_original_configured_callback_and_contract(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    message = _message(client, app, "legacy-profile-webhook", sender="agent-b", recipient="agent-a")
    with app.extensions["sessions"].begin() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.kind == "webhook"
        delivery.webhook_generation = None  # retained v0.1.0 writer row

    requests = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: requests.append((url, body, headers)) or (200, b""))
    assert len(requests) == 1
    url, body, headers = requests[0]
    assert url == "https://agent-a.example.com/bridge-hook"
    assert headers["Authorization"] == "Bearer synthetic-webhook-bearer"
    from bridge.events import notification
    with app.extensions["sessions"]() as db:
        expected = notification(db.get(Message, message["message_id"]))
    assert json.loads(body) == expected
    with app.extensions["sessions"]() as db:
        row = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert row.state == "accepted" and row.status == 200


def test_legacy_missing_callback_credentials_keeps_delivery_retryable(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    app.config["WEBHOOK_URL"] = ""
    app.config["WEBHOOK_TOKEN"] = ""
    message = _message(client, app, "legacy-callback-not-configured", sender="agent-b", recipient="agent-a")
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: sent.append(args))
    row = _deliveries(app, message["message_id"])[0]
    assert sent == [] and row.state == "retry" and row.reason == "webhook_not_configured"


def test_inherited_unchanged_save_keeps_generation_and_existing_queue(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    message = _message(client, app, "legacy-unchanged-save", sender="agent-b", recipient="agent-a")
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, "agent-a")
        assert participant.webhook_enabled is None and participant.webhook_generation == 1
        changed = update_webhook(db, app.config, participant, enabled=True, url="", token="",
                                 expected_generation=1)
        assert changed is False
        assert participant.webhook_enabled is None and participant.webhook_generation == 1
        assert db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"])).state == "pending"
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append(url) or (200, b""))
    assert sent == ["https://agent-a.example.com/bridge-hook"]
    assert _deliveries(app, message["message_id"])[0].state == "accepted"


def test_nonlegacy_webhook_is_opt_in_and_only_wakes_for_new_messages(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    old_message = _message(client, app, "before-profile-webhook")
    assert _deliveries(app, old_message["message_id"]) == []

    _enable(app)
    with app.extensions["sessions"]() as db:
        participant = db.get(Participant, "agent-b")
        metadata = view_webhook(app.config, participant)
        assert metadata["state"] == "enabled" and metadata["hostname"] == "agent-b.example.com"
        assert "synthetic-agent-b-token" not in str(metadata)
        assert participant.webhook_token != "synthetic-agent-b-token"
        assert Fernet(app.config["ENCRYPTION_KEY"].encode()).decrypt(participant.webhook_token.encode()).decode() == "synthetic-agent-b-token"
    new_message = _message(client, app, "after-profile-webhook")
    rows = _deliveries(app, new_message["message_id"])
    assert [(row.kind, row.webhook_generation) for row in rows] == [("webhook", 2)]
    assert _deliveries(app, old_message["message_id"]) == []

    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append((url, body, headers)) or (200, b""))
    assert sent[0][0] == "https://agent-b.example.com/hook"
    assert sent[0][2]["Authorization"] == "Bearer synthetic-agent-b-token"
    assert json.loads(sent[0][1])["data"]["message_id"] == new_message["message_id"]


def test_enabled_profile_does_not_queue_webhook_for_closing_message(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    message = _message(client, app, "enabled-profile-closing-message", needs_reply=False)
    assert _deliveries(app, message["message_id"]) == []


def test_explicit_disable_overrides_legacy_fallback_and_mcp_stays_independent(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    # Legacy recipient is configured by deployment, but an explicit off marker
    # suppresses that route without affecting a synthetic MCP event.
    from test_worker import subscription_params
    result = client.post("/mcp", headers={"Authorization": "Bearer " + app.extensions["test_credentials"]["agent-a"]},
        json={"jsonrpc": "2.0", "id": "subscribe", "method": "events/subscribe", "params": subscription_params()}).get_json()
    assert "result" in result
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, "agent-a")
        update_webhook(db, app.config, participant, enabled=False, expected_generation=1)
    message = _message(client, app, "disabled-legacy-still-mcp", sender="agent-b", recipient="agent-a")
    rows = _deliveries(app, message["message_id"])
    assert len(rows) == 1 and rows[0].kind == "mcp"

    requests = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: requests.append(url) or (202, b""))
    assert requests == ["https://agent-b.example.com/events"]


def test_disable_and_replace_fence_queued_and_retry_jobs(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    queued = _message(client, app, "queued-before-disable")
    retry = _message(client, app, "retry-before-replacement")
    with app.extensions["sessions"].begin() as db:
        item = db.scalar(select(Delivery).where(Delivery.message_id == retry["message_id"]))
        item.state = "retry"
        item.available_at = 0
        participant = db.get(Participant, "agent-b")
        update_webhook(db, app.config, participant, enabled=False, expected_generation=2)
        update_webhook(db, app.config, participant, enabled=True, url="https://new.example.com/hook",
                       token="synthetic-new-token", expected_generation=3)
    sent = []
    for _ in range(2):
        assert deliver_one(app.extensions["sessions"], app.config,
                           post=lambda *args: sent.append(args) or (200, b""))
    assert sent == []
    for ident in (queued["message_id"], retry["message_id"]):
        row = _deliveries(app, ident)[0]
        assert row.state == "stopped" and row.reason == "webhook_changed"

    current = _message(client, app, "new-message-after-replacement")
    assert _deliveries(app, current["message_id"])[0].webhook_generation == 4
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append((url, headers)) or (200, b""))
    assert sent == [("https://new.example.com/hook", {"Content-Type": "application/json",
                                                      "Authorization": "Bearer synthetic-new-token"})]


def test_in_flight_generation_change_cannot_accept_old_delivery_or_lose_new_job(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    old = _message(client, app, "in-flight-old-generation")
    new_ids = []

    def callback(url, body, headers):
        assert url == "https://agent-b.example.com/hook"
        with app.extensions["sessions"].begin() as db:
            participant = db.get(Participant, "agent-b")
            update_webhook(db, app.config, participant, enabled=True,
                           url="https://replacement.example.com/hook", token="synthetic-replacement-token",
                           expected_generation=2)
        new_ids.append(_message(client, app, "during-in-flight-new-generation")["message_id"])
        return 200, b""

    assert deliver_one(app.extensions["sessions"], app.config, post=callback)
    old_row = _deliveries(app, old["message_id"])[0]
    new_row = _deliveries(app, new_ids[0])[0]
    assert old_row.state == "stopped" and old_row.reason == "webhook_changed" and old_row.status == 200
    assert new_row.state == "pending" and new_row.webhook_generation == 3
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append(url) or (200, b""))
    assert sent == ["https://replacement.example.com/hook"]


def test_worker_preserves_reassigned_lease_and_stops_revoked_membership(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    first = _message(client, app, "lease-reassigned-in-flight")

    def steal_lease(url, body, headers):
        with app.extensions["sessions"].begin() as db:
            item = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
            item.lease = "new-owner-lease"
        return 200, b""

    assert deliver_one(app.extensions["sessions"], app.config, post=steal_lease)
    row = _deliveries(app, first["message_id"])[0]
    assert row.state == "sending" and row.lease == "new-owner-lease"

    second = _message(client, app, "membership-revoked-before-send")
    with app.extensions["sessions"].begin() as db:
        db.delete(db.get(Member, (second["thread_id"], "agent-b")))
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: sent.append(args) or (200, b""))
    stopped = _deliveries(app, second["message_id"])[0]
    assert sent == [] and stopped.state == "stopped"


def test_inactive_profile_or_revoked_user_stops_callback_before_network(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    first = _message(client, app, "inactive-profile-before-send")
    second = _message(client, app, "revoked-user-before-send")
    with app.extensions["sessions"].begin() as db:
        db.get(Participant, "agent-b").active = False
    called = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: called.append(args))
    assert _deliveries(app, first["message_id"])[0].state == "stopped"

    # Restore the participant to isolate authorization revocation on the next row.
    with app.extensions["sessions"].begin() as db:
        db.get(Participant, "agent-b").active = True
        db.get(User, "agent-b").active = False
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: called.append(args))
    assert _deliveries(app, second["message_id"])[0].state == "stopped"
    assert called == []


def test_unreadable_encrypted_profile_token_stops_delivery_without_network_or_crash(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app)
    message = _message(client, app, "unreadable-profile-token")
    healthy = _message(client, app, "healthy-legacy-after-unreadable", sender="agent-b", recipient="agent-a")
    with app.extensions["sessions"].begin() as db:
        db.get(Participant, "agent-b").webhook_token = "not-a-fernet-token"
        # Deterministically process the corrupt row first, then the healthy row.
        db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"])).available_at = 0
        db.scalar(select(Delivery).where(Delivery.message_id == healthy["message_id"])).available_at = 1
    called = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: called.append(args) or (200, b""))
    row = _deliveries(app, message["message_id"])[0]
    assert called == [] and row.state == "stopped" and row.reason == "secret_unreadable"
    # A bad stored credential affects only this profile's work.
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: called.append(args) or (200, b""))
    assert len(called) == 1 and called[0][0] == "https://agent-a.example.com/bridge-hook"
    assert _deliveries(app, healthy["message_id"])[0].state == "accepted"


def test_config_sync_preserves_webhook_fields_and_still_revokes_removed_identity(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable(app, "intruder", url="https://intruder.example.com/hook", token="synthetic-intruder-token")
    queued = _message(client, app, "config-removed-profile", recipient="intruder")
    settings = dict(app.config)
    settings["USERS"] = [user for user in settings["USERS"] if user["id"] != "intruder"]

    with app.extensions["sessions"].begin() as db:
        intruder = db.get(Participant, "intruder")
        before = (intruder.webhook_enabled, intruder.webhook_url, intruder.webhook_token, intruder.webhook_generation)
        bootstrap(db, settings)
        intruder = db.get(Participant, "intruder")
        user = db.get(User, "intruder")
        after = (intruder.webhook_enabled, intruder.webhook_url, intruder.webhook_token, intruder.webhook_generation)
        assert before == after
        assert intruder.active is False and user.active is False and user.api_key_hash is None

    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: sent.append(args) or (200, b""))
    row = _deliveries(app, queued["message_id"])[0]
    assert sent == [] and row.state == "stopped"


def test_origin_secret_cannot_be_profile_webhook_token(bridge_app):
    app = bridge_app
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, "agent-b")
        before = (participant.webhook_enabled, participant.webhook_url, participant.webhook_token,
                  participant.webhook_generation)
        with pytest.raises(Invalid, match="dedicated webhook token"):
            update_webhook(db, app.config, participant, enabled=True, url="https://agent-b.example.com/hook",
                           token=app.config["CLOUDFLARE_ORIGIN_SECRET"], expected_generation=1)
        after = (participant.webhook_enabled, participant.webhook_url, participant.webhook_token,
                 participant.webhook_generation)
        assert after == before

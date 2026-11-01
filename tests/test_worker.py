"""Durable outbound callback retry, fencing, and outcome-state regressions."""
import base64
import json

from sqlalchemy import select

from bridge.models import Delivery, Message, Subscription
from bridge.worker import deliver_one


SECRET = "whsec_" + base64.b64encode(b"synthetic-worker-signing-secret-32").decode()


def headers(app, participant):
    return {"Authorization": "Bearer " + app.extensions["test_credentials"][participant]}


def rpc(client, app, participant, method, params):
    return client.post("/mcp", headers=headers(app, participant), json={
        "jsonrpc": "2.0", "id": method, "method": method, "params": params,
    }).get_json()


def make_subscription(client, app):
    return rpc(client, app, "agent-b", "events/subscribe", {
        "name": "bridge.message.received", "arguments": {}, "delivery": {
            "mode": "webhook", "url": "https://agent-b.example.com/events", "secret": SECRET,
        },
    })["result"]


def make_message(client, app, ident="worker-message"):
    response = client.post("/api/messages", headers=headers(app, "agent-a"), json={
        "message_id": ident, "recipient": "agent-b", "text": "A private synthetic message.",
        "status": "received", "needs_reply": True,
    })
    assert response.status_code == 200
    return response.get_json()


def subscription_params():
    return {"name": "bridge.message.received", "arguments": {}, "delivery": {
        "mode": "webhook", "url": "https://agent-b.example.com/events", "secret": SECRET,
    }}


def cursor_sequence(app, subscription_id, value):
    from bridge.events import parse_cursor
    return parse_cursor(app.config, value, subscription_id)


def test_transient_retry_then_acceptance_does_not_complete_message_or_redeliver(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    make_subscription(client, app)
    message = make_message(client, app)
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append((url, body, headers)) or (503, b""))
    with app.extensions["sessions"].begin() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "retry" and delivery.status == 503 and delivery.attempts == 1
        delivery.available_at = 0
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append((url, body, headers)) or (202, b""))
    assert len(sent) == 2
    body = json.loads(sent[1][1])
    assert body["data"] == {"message_id": message["message_id"], "thread_id": message["thread_id"],
        "sender": "agent-a", "recipient": "agent-b", "status": "received", "needs_reply": True}
    assert "text" not in body["data"] and "attachment_ids" not in body["data"]
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        stored = db.get(Message, message["message_id"])
        assert delivery.state == "accepted" and delivery.status == 202 and delivery.attempts == 2
        assert stored.status == "received"  # Provider acceptance is transport evidence, not work completion.
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: (_ for _ in ()).throw(AssertionError("accepted callback must not redeliver"))) is False


def test_late_callback_after_unsubscribe_is_fenced(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    subscription = make_subscription(client, app)
    message = make_message(client, app, "unsubscribe-in-flight")
    calls = []
    def callback(url, body, request_headers):
        calls.append(json.loads(body))
        params = {"name": "bridge.message.received", "arguments": {}, "delivery": {
            "mode": "webhook", "url": "https://agent-b.example.com/events", "secret": SECRET,
        }}
        result = rpc(client, app, "agent-b", "events/unsubscribe", params)
        assert "result" in result
        return 204, b""
    assert deliver_one(app.extensions["sessions"], app.config, post=callback)
    with app.extensions["sessions"]() as db:
        sub = db.get(Subscription, subscription["id"])
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert not sub.active and sub.generation == 2
        assert delivery.state == "stopped" and delivery.reason == "subscription_changed"
    assert len(calls) == 1
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: (_ for _ in ()).throw(AssertionError("revoked callback must not retry"))) is False


def test_unsubscribe_stops_queued_delivery_and_refresh_requeues_it(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    initial = make_subscription(client, app)
    message = make_message(client, app, "reactivated-pending-message")
    stopped = rpc(client, app, "agent-b", "events/unsubscribe", subscription_params())
    assert "result" in stopped

    # The worker observes revoked subscription state and stops the queued row.
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *args: (204, b""))
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "stopped"

    refreshed = rpc(client, app, "agent-b", "events/subscribe", subscription_params())["result"]
    assert refreshed["id"] == initial["id"]
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "pending"
    attempts = []
    assert deliver_one(app.extensions["sessions"], app.config,
        post=lambda url, body, headers: attempts.append(json.loads(body)) or (204, b""))
    assert len(attempts) == 1
    assert attempts[0]["data"]["message_id"] == message["message_id"]
    assert cursor_sequence(app, initial["id"], attempts[0]["cursor"]) == 1
    assert cursor_sequence(app, initial["id"], refreshed["cursor"]) == 0
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "accepted"


def test_reactivation_does_not_replay_accepted_delivery_without_explicit_cursor(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    initial = make_subscription(client, app)
    message = make_message(client, app, "accepted-before-reactivation")
    first_delivery = []
    assert deliver_one(app.extensions["sessions"], app.config,
        post=lambda url, body, headers: first_delivery.append(json.loads(body)) or (202, b""))
    assert cursor_sequence(app, initial["id"], first_delivery[0]["cursor"]) == 1
    assert "result" in rpc(client, app, "agent-b", "events/unsubscribe", subscription_params())

    # Reconnect without a cursor restores the callback but preserves accepted state.
    refreshed = rpc(client, app, "agent-b", "events/subscribe", subscription_params())["result"]
    assert refreshed["id"] == initial["id"]
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "accepted"
    assert deliver_one(app.extensions["sessions"], app.config,
        post=lambda *args: (_ for _ in ()).throw(AssertionError("accepted delivery replayed without cursor"))) is False

    # An explicit older checkpoint requests replay of that accepted event.
    replay = rpc(client, app, "agent-b", "events/subscribe",
        subscription_params() | {"cursor": initial["cursor"]})["result"]
    assert cursor_sequence(app, initial["id"], replay["cursor"]) == 0
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        assert delivery.state == "pending" and delivery.reason == "cursor_replay"

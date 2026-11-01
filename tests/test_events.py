"""MCP discovery, recipient inbox, webhook verification, and replay regressions."""
import base64
import hashlib
import json
import time

from sqlalchemy import select

from bridge.models import Delivery, Message, Subscription


EVENT_SECRET = "whsec_" + base64.b64encode(b"synthetic-webhook-signing-secret-32").decode()
AGENT_B_CALLBACK = "https://agent-b.example.com/events"


def auth(app, participant):
    return {"Authorization": "Bearer " + app.extensions["test_credentials"][participant]}


def rpc(client, app, participant, method, params=None, ident="test"):
    response = client.post("/mcp", headers=auth(app, participant), json={
        "jsonrpc": "2.0", "id": ident, "method": method, "params": params or {},
    })
    assert response.status_code == 200
    return response.get_json()


def subscribe_params(callback=AGENT_B_CALLBACK, secret=EVENT_SECRET, **extra):
    return {"name": "bridge.message.received", "arguments": {}, "delivery": {
        "mode": "webhook", "url": callback, "secret": secret}, **extra}


def send_to(client, app, recipient, ident, *, needs_reply=True):
    return client.post("/api/messages", headers=auth(app, "agent-a"), json={
        "message_id": ident, "recipient": recipient, "text": "Synthetic event body",
        "status": "received", "needs_reply": needs_reply,
    })


def subscribe(client, app, *, participant="agent-b", params=None, ident="subscribe"):
    return rpc(client, app, participant, "events/subscribe", params or subscribe_params(), ident)


def test_server_discovery_and_mcp_tool_event_schemas(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    discovery = rpc(client, app, "agent-b", "server/discover")
    assert discovery["result"]["supportedVersions"] == ["2026-07-28"]
    assert discovery["result"]["capabilities"] == {"tools": {}, "events": {}}
    tools = rpc(client, app, "agent-b", "tools/list")["result"]["tools"]
    send = next(tool for tool in tools if tool["name"] == "send_message")
    assert set(send["inputSchema"]["required"]) >= {"message_id", "recipient", "status", "needs_reply"}
    event_list = rpc(client, app, "agent-b", "events/list")["result"]["events"]
    assert len(event_list) == 1 and event_list[0]["name"] == "bridge.message.received"
    assert set(event_list[0]["payloadSchema"]["required"]) == {
        "message_id", "thread_id", "sender", "recipient", "status", "needs_reply"}


def test_subscription_catches_up_own_inbox_and_never_emits_closing_message(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    assert send_to(client, app, "agent-b", "backlog-actionable").status_code == 200
    assert send_to(client, app, "intruder", "other-inbox-actionable").status_code == 200
    assert send_to(client, app, "agent-b", "backlog-closing", needs_reply=False).status_code == 200
    response = subscribe(client, app)
    assert "result" in response, response
    with app.extensions["sessions"]() as db:
        deliveries = list(db.scalars(select(Delivery).where(Delivery.kind == "mcp").order_by(Delivery.id)))
        assert len(deliveries) == 1
        assert deliveries[0].message_id == "backlog-actionable"
        assert deliveries[0].subscription_id == response["result"]["id"]


def test_subscription_verification_runs_without_transaction_and_rechecks_auth(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    observations = []
    def verified(url, secret, subscription):
        from flask import g
        from bridge.models_auth import User
        observations.append((url, g.db.in_transaction()))
        with app.extensions["sessions"].begin() as revoke:
            revoke.get(User, "agent-b").api_key_hash = hashlib.sha256(b"rotated-key").hexdigest()
    app.extensions["verify_callback"] = verified
    response = client.post("/mcp", headers=auth(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": "revoked-during-verification", "method": "events/subscribe",
        "params": subscribe_params(),
    })
    assert response.status_code == 401
    # Revalidation is expected to fail after callback-side credential revocation.
    assert observations == [(AGENT_B_CALLBACK, False)]
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(Subscription)) is None


def test_subscribe_rejects_nonempty_arguments_and_invalid_cursor_or_secret(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    for params in (
        subscribe_params() | {"arguments": {"filter": "all"}},
        subscribe_params(secret="not-a-webhook-secret"),
        subscribe_params(cursor="ahead.forbidden"),
    ):
        assert "error" in subscribe(client, app, params=params)


def test_refresh_replay_signed_cursor_and_pending_delivery_cannot_be_skipped(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    created = send_to(client, app, "agent-b", "replay-message").get_json()
    first = subscribe(client, app)["result"]
    with app.extensions["sessions"].begin() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == created["message_id"]))
        delivery.state = "accepted"
        delivery.status = 204
    from bridge.events import cursor
    with app.extensions["sessions"]() as db:
        sub = db.get(Subscription, first["id"])
        acknowledged = cursor(app.config, sub, 1)
    refreshed = subscribe(client, app, params=subscribe_params(cursor=acknowledged), ident="refresh")["result"]
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(Delivery).where(Delivery.message_id == created["message_id"])).state == "accepted"
    replayed = subscribe(client, app, params=subscribe_params(cursor=first["cursor"]), ident="replay")["result"]
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == created["message_id"]))
        assert delivery.state == "pending" and delivery.reason == "cursor_replay"
    with app.extensions["sessions"]() as db:
        ahead_cursor = cursor(app.config, db.get(Subscription, first["id"]), 99)
    ahead = subscribe(client, app, params=subscribe_params(cursor=ahead_cursor), ident="forged")
    assert "error" in ahead
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(Delivery).where(Delivery.message_id == created["message_id"])).state == "pending"


def test_subscription_expiry_refresh_and_secret_rotation_overlap(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    response = subscribe(client, app, params=subscribe_params(ttlMs=1000))["result"]
    with app.extensions["sessions"].begin() as db:
        sub = db.get(Subscription, response["id"])
        sub.expires_at = time.time() - 1
    expired = subscribe(client, app, params=subscribe_params(cursor=response["cursor"], ttlMs=1000))
    assert "result" in expired
    rotated_secret = "whsec_" + base64.b64encode(b"synthetic-rotated-secret-32-bytes").decode()
    rotated = subscribe(client, app, params=subscribe_params(secret=rotated_secret))["result"]
    with app.extensions["sessions"]() as db:
        sub = db.get(Subscription, response["id"])
        assert sub.generation == 3
        assert sub.active and sub.expires_at > time.time()
        assert sub.previous_secret is not None and sub.rotation_until > time.time()
        assert rotated["id"] == response["id"]

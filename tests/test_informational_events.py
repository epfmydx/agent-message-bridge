"""MCP receipt notifications remain separate from actionable claims and callbacks."""
import json
import time

import pytest
from sqlalchemy import func, select

from bridge.events import parse_cursor, watermark
from bridge.models import Artifact, Delivery, Message, Participant, Subscription, Thread, WorkClaim
from bridge.profile_webhooks import update_webhook
from bridge.worker import deliver_one
from conftest import bearer_headers
from test_events import rpc, subscribe_params


def subscribe(app, client, recipient="agent-b", cursor=None):
    params = subscribe_params(callback="https://mcp.example.com/" + recipient)
    if cursor is not None:
        params["cursor"] = cursor
    response = rpc(client, app, recipient, "events/subscribe", params)
    assert "result" in response, response
    return response["result"]


def send(app, client, ident, *, recipient="agent-b", needs_reply=False, **extra):
    sender = "agent-a" if recipient != "agent-a" else "agent-b"
    return client.post("/api/messages", headers=bearer_headers(app, sender), json={
        "message_id": ident, "recipient": recipient, "text": "Synthetic informational update",
        "status": "completed", "needs_reply": needs_reply, **extra})


@pytest.mark.parametrize("needs_reply", [False, True])
@pytest.mark.parametrize("recipient", ["agent-b", "agent-a"])
def test_mcp_receipts_include_false_but_profile_callbacks_remain_actionable_only(bridge_app, recipient, needs_reply):
    app, client = bridge_app, bridge_app.test_client()
    if recipient == "agent-b":
        with app.extensions["sessions"].begin() as db:
            profile = db.get(Participant, recipient)
            update_webhook(db, app.config, profile, enabled=True,
                url="https://custom.example.com/receiver", token="synthetic-receiver-token", expected_generation=1)
    subscription = subscribe(app, client, recipient)
    other = "agent-a" if recipient == "agent-b" else "agent-b"
    other_subscription = subscribe(app, client, other)
    result = send(app, client, "synthetic-receipt", recipient=recipient, needs_reply=needs_reply)
    assert result.status_code == 200
    message = result.get_json()
    sent = []
    def post(url, body, headers):
        sent.append((url, json.loads(body), headers))
        return 200, b""
    while deliver_one(app.extensions["sessions"], app.config, post=post):
        assert len(sent) <= 2
    mcp = [item for item in sent if item[0].startswith("https://mcp.example.com/")]
    bearer = [item for item in sent if "Authorization" in item[2]]
    assert len(mcp) == 1 and len(bearer) == int(needs_reply)
    assert mcp[0][0] == "https://mcp.example.com/" + recipient
    assert "webhook-signature" in mcp[0][2] and "Authorization" not in mcp[0][2]
    assert mcp[0][1]["data"]["needs_reply"] is needs_reply
    assert mcp[0][1]["data"]["recipient"] == recipient
    assert "text" not in mcp[0][1]["data"]
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(Delivery.id)).where(Delivery.subscription_id == other_subscription["id"])) == 0
        assert watermark(db, db.get(Subscription, subscription["id"])) == 1
        assert db.scalar(select(func.count(Message.id))) == 1  # Delivery itself creates no reply.
    if not needs_reply:
        denied = client.post("/api/messages/" + message["message_id"] + "/claim",
            headers=bearer_headers(app, recipient), json={"claim_id": "synthetic-informational-run"})
        assert denied.status_code == 400
        assert denied.get_json() == {"error": "This message is informational and cannot be claimed"}
        with app.extensions["sessions"]() as db:
            assert db.scalar(select(func.count(WorkClaim.message_id))) == 0


def test_legacy_silent_history_stays_silent_through_first_connection_refresh_and_replay(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    first = send(app, client, "synthetic-old-actionable", needs_reply=True).get_json()
    # This is the persisted shape written by the previous runtime: the thread
    # sequence advances, but the recipient sequence remains NULL for silent rows.
    with app.extensions["sessions"].begin() as db:
        thread = db.get(Thread, first["thread_id"])
        thread.sequence += 1
        db.add(Message(id="synthetic-old-silent", thread_id=thread.id, sender_id="agent-a",
            recipient_id="agent-b", text="Synthetic historical information", status="completed",
            needs_reply=False, sequence=thread.sequence, recipient_sequence=None, fingerprint="synthetic-old-silent"))
    informational = send(app, client, "synthetic-new-information", thread_id=first["thread_id"]).get_json()
    last = send(app, client, "synthetic-new-actionable", needs_reply=True, thread_id=first["thread_id"]).get_json()
    subscription = subscribe(app, client)
    expected = {first["message_id"], informational["message_id"], last["message_id"]}
    with app.extensions["sessions"]() as db:
        queued = list(db.scalars(select(Delivery).where(Delivery.subscription_id == subscription["id"])))
        assert {item.message_id for item in queued} == expected
        assert db.get(Message, "synthetic-old-silent").recipient_sequence is None
    assert client.get("/api/messages/synthetic-old-silent", headers=bearer_headers(app, "agent-b")).status_code == 200
    captures = []
    def post(_url, body, _headers):
        captures.append(json.loads(body))
        return 204, b""
    while deliver_one(app.extensions["sessions"], app.config, post=post):
        assert len(captures) <= 3
    assert {p["data"]["message_id"] for p in captures} == expected
    assert parse_cursor(app.config, subscribe(app, client)["cursor"], subscription["id"]) == 3
    assert not deliver_one(app.extensions["sessions"], app.config, post=post)
    subscribe(app, client, cursor=subscription["cursor"])
    replay = []
    while deliver_one(app.extensions["sessions"], app.config,
                     post=lambda _u, body, _h: replay.append(json.loads(body)) or (204, b"")):
        assert len(replay) <= 3
    assert {p["eventId"] for p in replay} == {p["eventId"] for p in captures}
    assert {p["data"]["message_id"] for p in replay} == expected


@pytest.mark.parametrize("offline", ["expired", "inactive"])
def test_new_information_catches_up_after_subscription_is_unavailable(bridge_app, offline):
    app, client = bridge_app, bridge_app.test_client()
    subscription = subscribe(app, client)
    with app.extensions["sessions"].begin() as db:
        row = db.get(Subscription, subscription["id"])
        if offline == "expired": row.expires_at = time.time() - 1
        else: row.active = False
    message = send(app, client, "synthetic-offline-information").get_json()
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(Delivery.id)).where(Delivery.message_id == message["message_id"])) == 0
        assert db.get(Message, message["message_id"]).recipient_sequence == 1
    subscribe(app, client)
    with app.extensions["sessions"]() as db:
        queued = list(db.scalars(select(Delivery).where(Delivery.message_id == message["message_id"])))
        assert len(queued) == 1 and queued[0].subscription_id == subscription["id"]


def test_informational_retry_is_deduplicated_and_cannot_be_upgraded_into_a_claim(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    subscription = subscribe(app, client)
    first = send(app, client, "synthetic-stable-information").get_json()
    assert send(app, client, "synthetic-stable-information").get_json()["duplicate"] is True
    assert send(app, client, "synthetic-stable-information", needs_reply=True).status_code == 409
    denied = rpc(client, app, "agent-b", "tools/call", {"name":"claim_message",
        "arguments":{"message_id":first["message_id"], "claim_id":"synthetic-no-claim"}})
    assert denied["error"]["code"] == -32602
    assert denied["error"]["message"] == "This message is informational and cannot be claimed"
    assert client.get("/api/messages/" + first["message_id"], headers=bearer_headers(app, "intruder")).status_code == 404
    with app.extensions["sessions"]() as db:
        assert db.get(Participant, "agent-b").sequence == 1
        assert db.scalar(select(func.count(Delivery.id)).where(Delivery.subscription_id == subscription["id"])) == 1
        assert db.scalar(select(func.count(WorkClaim.message_id))) == 0


def test_attachment_only_information_notifies_without_changing_file_visibility(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    subscribe(app, client)
    with app.extensions["sessions"].begin() as db:
        db.add(Artifact(id="synthetic-information-file", owner_id="agent-a", idempotency_key="synthetic-file-input",
            object_key="synthetic-information-object", filename="notes.txt", content_type="text/plain",
            size_bytes=5, sha256="a" * 64, state="ready"))
    response = send(app, client, "synthetic-file-information", text="", attachment_ids=["synthetic-information-file"])
    assert response.status_code == 200
    captures = []
    assert deliver_one(app.extensions["sessions"], app.config,
        post=lambda _u, body, _h: captures.append(json.loads(body)) or (204, b""))
    assert captures[0]["data"]["needs_reply"] is False
    read = client.get("/api/messages/synthetic-file-information", headers=bearer_headers(app, "agent-b"))
    assert read.get_json()["attachment_ids"] == ["synthetic-information-file"]
    assert read.get_json()["text"] == ""
    assert client.get("/api/messages/synthetic-file-information", headers=bearer_headers(app, "intruder")).status_code == 404


def test_discovery_describes_informational_receipts_without_claims_or_automatic_replies(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    for method in ("initialize", "server/discover"):
        instructions = rpc(client, app, "agent-b", method)["result"]["instructions"]
        assert "For needs_reply=false" in instructions
        assert "without claiming, delegating work or replying automatically" in instructions
        assert "profile bearer webhooks still notify only needs_reply=true" in instructions
    event = rpc(client, app, "agent-b", "events/list")["result"]["events"][0]
    assert "needs_reply=false" in event["description"]
    assert "without claiming or replying automatically" in event["description"]

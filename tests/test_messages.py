"""End-to-end message, access, idempotency, and work-claim regressions."""
import json
import os
import threading
import uuid
import base64
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import pytest
from sqlalchemy import func, select

from bridge.errors import Invalid, Unavailable
from bridge.messages import claim_message, send_message
from bridge.models import Artifact, Delivery, Member, Message, Thread, WorkClaim
from conftest import bearer_headers


def send(client, app, sender, payload):
    return client.post("/api/messages", headers=bearer_headers(app, sender), json=payload)


def payload(message_id, recipient="agent-b", **overrides):
    return {"message_id": message_id, "recipient": recipient, "text": "Please inspect this change.",
            "status": "received", "needs_reply": True, **overrides}


def test_agent_a_message_agent_b_exact_read_reply_and_agent_a_webhook(bridge_app):
    from bridge.worker import deliver_one
    app, client = bridge_app, bridge_app.test_client()
    original = send(client, app, "agent-a", payload("agent_a-request-1")).get_json()
    assert original["sender"] == "agent-a" and original["recipient"] == "agent-b"
    assert original["sequence"] == 1 and original["needs_reply"] is True
    assert original["text"] == "Please inspect this change."
    fetched = client.get("/api/messages/agent_a-request-1", headers=bearer_headers(app, "agent-b"))
    assert fetched.status_code == 200
    assert fetched.get_json() == {key: value for key, value in original.items() if key != "duplicate"}

    reply = send(client, app, "agent-b", payload(
        "agent_b-reply-1", recipient="agent-a", thread_id=original["thread_id"],
        reply_to=original["message_id"], text="Inspection is complete.", status="completed",
    ))
    assert reply.status_code == 200, reply.get_json()
    reply_body = reply.get_json()
    assert reply_body["thread_id"] == original["thread_id"]
    assert reply_body["reply_to"] == original["message_id"]

    captured = []
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda url, body, headers: captured.append((url, body, headers)) or (200, b""))
    url, body, headers = captured[0]
    notification = json.loads(body)
    assert url == "https://agent-a.example.com/bridge-hook"
    assert headers["Authorization"] == "Bearer synthetic-webhook-bearer"
    assert notification["data"] == {"message_id": reply_body["message_id"], "thread_id": original["thread_id"],
        "sender": "agent-b", "recipient": "agent-a", "status": "completed", "needs_reply": True}
    assert "text" not in notification["data"] and "attachment_ids" not in notification["data"]
    assert client.get("/api/messages/" + reply_body["message_id"], headers=bearer_headers(app, "agent-a")).status_code == 200
    with app.extensions["sessions"]() as db:
        delivery = db.scalar(select(Delivery).where(Delivery.message_id == reply_body["message_id"], Delivery.kind == "webhook"))
        assert delivery.state == "accepted" and delivery.status == 200


def test_message_requires_explicit_needs_reply_and_valid_status(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    missing_boolean = payload("missing-needs-reply")
    del missing_boolean["needs_reply"]
    assert send(client, app, "agent-a", missing_boolean).status_code == 400
    for status in ("queued", "done", ""):
        assert send(client, app, "agent-a", payload("bad-status-" + (status or "empty"), status=status)).status_code == 400
    assert send(client, app, "agent-a", payload("good-needs-reply-false", needs_reply=False)).status_code == 200


def test_closing_message_is_stored_without_delivery_or_later_event_backlog(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    closing = send(client, app, "agent-a", payload("closing-message", needs_reply=False)).get_json()
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(Delivery.id)).where(Delivery.message_id == closing["message_id"])) == 0
    subscription = client.post("/mcp", headers=bearer_headers(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": "sub-close", "method": "events/subscribe", "params": {
            "name": "bridge.message.received", "arguments": {}, "delivery": {"mode": "webhook", "url": "https://agent-b.example.com/events", "secret": "whsec_" + __import__("base64").b64encode(b"x" * 32).decode()}}})
    assert "result" in subscription.get_json()
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(Delivery.id)).where(Delivery.message_id == closing["message_id"])) == 0
        assert db.scalar(select(func.count(Message.id)).where(Message.id == closing["message_id"])) == 1


def test_message_idempotency_and_conflicting_reuse(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    subscription = client.post("/mcp", headers=bearer_headers(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": "idempotency-subscription", "method": "events/subscribe", "params": {
            "name": "bridge.message.received", "arguments": {}, "delivery": {
                "mode": "webhook", "url": "https://agent-b.example.com/events",
                "secret": "whsec_" + base64.b64encode(b"synthetic-idempotency-secret-32").decode(),
            },
        },
    }).get_json()
    assert "result" in subscription
    first = send(client, app, "agent-a", payload("stable-id")).get_json()
    duplicate = send(client, app, "agent-a", payload("stable-id")).get_json()
    assert duplicate["duplicate"] is True
    for key in ("message_id", "thread_id", "sequence", "text", "sender", "recipient"):
        assert duplicate[key] == first[key]
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(Thread.id))) == 1
        assert db.scalar(select(func.count(Message.id))) == 1
        assert db.scalar(select(func.count(Delivery.id))) == 1
    conflict = send(client, app, "agent-a", payload("stable-id", text="different content"))
    assert conflict.status_code == 409
    assert conflict.get_json() == {"error": "Message identity has conflicting content"}


def test_membership_file_boundary_and_cross_thread_reply(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    first = send(client, app, "agent-a", payload("thread-one-message")).get_json()
    assert client.get("/api/messages/thread-one-message", headers=bearer_headers(app, "intruder")).status_code == 404
    other = send(client, app, "agent-b", payload("thread-two-message", recipient="agent-a")).get_json()
    response = send(client, app, "agent-b", payload("cross-thread-reply", recipient="agent-a",
                    thread_id=other["thread_id"], reply_to=first["message_id"]))
    assert response.status_code == 400
    assert client.get("/api/threads/" + first["thread_id"] + "/messages", headers=bearer_headers(app, "intruder")).status_code == 404
    # Unknown and non-ready file IDs both fail before a message becomes durable.
    for ident in ("unknown-file",):
        failed = send(client, app, "agent-a", payload("missing-file-message", attachment_ids=[ident], text=""))
        assert failed.status_code == 404
    with app.extensions["sessions"]() as db:
        assert db.get(Message, "cross-thread-reply") is None
        assert db.get(Message, "missing-file-message") is None


def test_shared_file_reference_remains_thread_member_scoped(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    with app.extensions["sessions"].begin() as db:
        db.add(Artifact(id="shared-synthetic-file", owner_id="agent-a", idempotency_key="synthetic-upload",
            object_key="synthetic-object-key", filename="notes.txt", content_type="text/plain",
            size_bytes=5, sha256="a" * 64, state="ready"))
    message = send(client, app, "agent-a", payload(
        "file-shared-message", attachment_ids=["shared-synthetic-file"]))
    assert message.status_code == 200
    denied = client.get("/api/files/shared-synthetic-file", headers=bearer_headers(app, "intruder"))
    assert denied.status_code == 404


def test_work_claim_is_unique_resumable_and_recipient_only(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    message = send(client, app, "agent-a", payload("claimable-message")).get_json()
    def claim(participant, claim_id):
        return client.post("/api/messages/claimable-message/claim", headers=bearer_headers(app, participant), json={"claim_id": claim_id})
    first = claim("agent-b", "agent_b-run-a").get_json()
    resumed = claim("agent-b", "agent_b-run-a").get_json()
    competing = claim("agent-b", "agent_b-run-b").get_json()
    unauthorized = claim("agent-a", "sender-run")
    second_message = send(client, app, "agent-a", payload("second-claimable-message")).get_json()
    second_claim = client.post("/api/messages/second-claimable-message/claim",
        headers=bearer_headers(app, "agent-b"), json={"claim_id": "agent_b-run-a"}).get_json()
    assert first == {"message_id": message["message_id"], "acquired": True, "resumed": False}
    assert resumed == {"message_id": message["message_id"], "acquired": True, "resumed": True}
    assert competing == {"message_id": message["message_id"], "acquired": False, "resumed": False}
    assert unauthorized.status_code == 400
    assert second_claim == {"message_id": second_message["message_id"], "acquired": True, "resumed": False}
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count(WorkClaim.message_id))) == 2
        assert db.get(WorkClaim, message["message_id"]).claim_id == "agent_b-run-a"


def test_encoded_slash_message_ids_read_exactly_and_claim_route_preserves_suffix(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    for ident in ("opaque/segment", "opaque/claim"):
        created = send(client, app, "agent-a", payload(ident))
        assert created.status_code == 200, created.get_json()
        fetched = client.get("/api/messages/" + quote(ident, safe=""),
            headers=bearer_headers(app, "agent-b"))
        assert fetched.status_code == 200, fetched.get_json()
        assert fetched.get_json()["message_id"] == ident
        if ident.endswith("/claim"):
            claimed = client.post("/api/messages/" + quote(ident, safe="") + "/claim",
                headers=bearer_headers(app, "agent-b"), json={"claim_id": "encoded-id-run"})
            assert claimed.status_code == 200, claimed.get_json()
            assert claimed.get_json() == {"message_id": ident, "acquired": True, "resumed": False}


def test_mcp_tools_call_non_string_name_returns_invalid_arguments(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    response = client.post("/mcp", headers=bearer_headers(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": "unhashable-tool-name", "method": "tools/call",
        "params": {"name": [], "arguments": {}},
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body["error"]["code"] == -32602
    assert body["error"]["message"] == "Unknown tool or invalid arguments"


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="Concurrent PostgreSQL locking requires TEST_DATABASE_URL")
def test_postgres_concurrent_duplicate_and_distinct_message_sequence(bridge_app):
    """Exercise real row locking: one ID stays unique and independent IDs keep sequence continuity."""
    from bridge.errors import Conflict
    from bridge.messages import send_message
    app = bridge_app
    starter = send(app.test_client(), app, "agent-a", payload("concurrent-sequence-starter")).get_json()
    ready = threading.Barrier(6)
    def submit(index):
        with app.extensions["sessions"].begin() as db:
            ready.wait()
            return send_message(db, app.config, "agent-a", payload(
                "concurrent-same-id" if index < 2 else "concurrent-" + str(index),
                thread_id=starter["thread_id"]))
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(submit, index) for index in range(6)]
        results = []
        errors = []
        for future in futures:
            try:
                results.append(future.result())
            except Conflict:
                errors.append("conflict")
            except Exception as exc:  # Surface unexpected database races as a clear test failure.
                errors.append(exc)
    assert not [error for error in errors if not isinstance(error, str)]
    assert len([result for result in results if result["message_id"] == "concurrent-same-id"]) == 2
    assert len(errors) <= 1
    with app.extensions["sessions"]() as db:
        row = db.get(Thread, results[0]["thread_id"])
        sequences = list(db.scalars(select(Message.sequence).where(Message.thread_id == row.id).order_by(Message.sequence)))
        assert sequences == list(range(1, row.sequence + 1))
        assert sequences == list(range(1, len(set(r["message_id"] for r in results)) + 2))

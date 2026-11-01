"""Bounded-query regressions for event checkpoints and paged message files."""
import base64
import json

import pytest
from sqlalchemy import event, insert, select, text, update

from bridge.models import Artifact, Delivery, Member, Message, MessageArtifact, Subscription, Thread
from conftest import bearer_headers


WEBHOOK_SECRET = "whsec_" + base64.b64encode(b"synthetic-performance-secret-32").decode()
CALLBACK = "https://agent-b.example.com/events"


def subscribe(client, app):
    response = client.post("/mcp", headers=bearer_headers(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": "performance-subscription", "method": "events/subscribe", "params": {
            "name": "bridge.message.received", "arguments": {}, "delivery": {
                "mode": "webhook", "url": CALLBACK, "secret": WEBHOOK_SECRET,
            },
        },
    })
    result = response.get_json()
    assert "result" in result, result
    return result["result"]


def first_message(client, app, ident):
    response = client.post("/api/messages", headers=bearer_headers(app, "agent-a"), json={
        "message_id": ident, "recipient": "agent-b", "text": "Synthetic performance fixture",
        "status": "received", "needs_reply": True,
    })
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def test_worker_uses_generation_checkpoint_after_ten_thousand_accepted_deliveries(bridge_app):
    """A cached checkpoint bounds replay lookup and provisional cursors stay transient."""
    from bridge.worker import deliver_one

    app, client = bridge_app, bridge_app.test_client()
    first = first_message(client, app, "performance-history-00001")
    subscription = subscribe(client, app)
    final_sequence = 10_001
    engine = app.extensions["engine"]
    query_observations = []

    # The first message was created through the REST path. Add a realistic
    # recipient history and one pending item using the production schema.
    with app.extensions["sessions"].begin() as db:
        sub = db.get(Subscription, subscription["id"])
        generation = sub.generation
        thread = db.get(Thread, first["thread_id"])
        thread.sequence = final_sequence
        db.execute(update(Delivery).where(Delivery.message_id == first["message_id"])
                   .values(state="accepted", status=204))

        messages = [{
            "id": f"performance-history-{sequence:05d}", "thread_id": thread.id,
            "sender_id": "agent-a", "recipient_id": "agent-b", "reply_to": None,
            "text": "Synthetic accepted history", "status": "received", "needs_reply": True,
            "sequence": sequence, "recipient_sequence": sequence, "fingerprint": f"fp-{sequence}",
            "created_at": 1_800_000_000.0 + sequence,
        } for sequence in range(2, final_sequence)]
        db.execute(insert(Message), messages)
        accepted = [{
            "message_id": row["id"], "kind": "mcp", "destination": "mcp:" + sub.id,
            "subscription_id": sub.id, "state": "accepted", "attempts": 1,
            "available_at": 1_800_000_000.0 + row["sequence"], "status": 204,
        } for row in messages]
        db.execute(insert(Delivery), accepted)

        pending_id = f"performance-history-{final_sequence:05d}"
        db.execute(insert(Message), [{
            "id": pending_id, "thread_id": thread.id, "sender_id": "agent-a", "recipient_id": "agent-b",
            "reply_to": None, "text": "Next pending item", "status": "received", "needs_reply": True,
            "sequence": final_sequence, "recipient_sequence": final_sequence,
            "fingerprint": f"fp-{final_sequence}", "created_at": 1_800_000_000.0 + final_sequence,
        }])
        db.execute(insert(Delivery), [{
            "message_id": pending_id, "kind": "mcp", "destination": "mcp:" + sub.id,
            "subscription_id": sub.id, "state": "pending", "attempts": 0, "available_at": 0,
        }])
        sub.acknowledged_sequence = final_sequence - 1
        sub.acknowledged_generation = generation

    if engine.dialect.name == "postgresql":
        _assert_postgres_recipient_range_plan(engine)

    def observe_sql(_conn, _cursor, statement, parameters, _context, _many):
        compact = " ".join(statement.lower().split())
        if "recipient_sequence" in compact and "deliveries" in compact and "subscriptions" not in compact:
            query_observations.append((compact, parameters))

    event.listen(engine, "before_cursor_execute", observe_sql)
    sent = []

    def reject_once(url, body, headers):
        payload = json.loads(body)
        sent.append(payload)
        # The callback is invoked only after the sending lease transaction has
        # committed. The notification may contain the provisional cursor, but
        # a failed HTTP response must not checkpoint that sequence.
        with app.extensions["sessions"]() as db:
            sub = db.get(Subscription, subscription["id"])
            assert sub.acknowledged_sequence == final_sequence - 1
            assert sub.acknowledged_generation == generation
        return 503, b"retry"

    try:
        assert deliver_one(app.extensions["sessions"], app.config, post=reject_once)
        assert len(sent) == 1
        from bridge.events import parse_cursor
        assert parse_cursor(app.config, sent[0]["cursor"], subscription["id"]) == final_sequence
        with app.extensions["sessions"]() as db:
            sub = db.get(Subscription, subscription["id"])
            delivery = db.scalar(select(Delivery).where(Delivery.message_id == f"performance-history-{final_sequence:05d}"))
            assert sub.acknowledged_sequence == final_sequence - 1
            assert delivery.state == "retry"

        # Retry after making it available; confirmed acceptance advances the
        # persisted generation-scoped checkpoint exactly once.
        with app.extensions["sessions"].begin() as db:
            db.scalar(select(Delivery).where(Delivery.message_id == f"performance-history-{final_sequence:05d}")).available_at = 0
        assert deliver_one(app.extensions["sessions"], app.config,
                           post=lambda url, body, headers: sent.append(json.loads(body)) or (204, b""))
        assert len(sent) == 2
        assert parse_cursor(app.config, sent[-1]["cursor"], subscription["id"]) == final_sequence
        with app.extensions["sessions"]() as db:
            sub = db.get(Subscription, subscription["id"])
            assert sub.acknowledged_sequence == final_sequence
            assert sub.acknowledged_generation == generation
            assert db.scalar(select(Delivery).where(Delivery.message_id == f"performance-history-{final_sequence:05d}")).state == "accepted"
    finally:
        event.remove(engine, "before_cursor_execute", observe_sql)

    # The worker's replay lookup starts beyond the cached prefix. Its bounded
    # result set therefore contains no accepted history rows to walk.
    replay_queries = [(sql, params) for sql, params in query_observations if "recipient_sequence >" in sql]
    assert replay_queries, query_observations
    assert any(final_sequence - 1 in (params if isinstance(params, (tuple, list)) else params.values())
               for _sql, params in replay_queries)


def _artifact_values(message_index, suffix):
    artifact_id = f"perf-file-{message_index:04d}-{suffix}"
    return {"id": artifact_id, "owner_id": "agent-a", "idempotency_key": artifact_id,
            "object_key": "object-" + artifact_id, "filename": artifact_id + ".txt",
            "content_type": "text/plain", "size_bytes": 1, "sha256": "a" * 64, "state": "ready"}


def test_rest_message_page_batches_attachment_lookup_for_large_page(bridge_app):
    """A > SQLite's common bind limit page uses one attachment query and paginates."""
    app, client = bridge_app, bridge_app.test_client()
    first = first_message(client, app, "performance-page-00001")
    total = 1_101
    message_rows = []
    attachment_rows = []
    artifact_rows = []
    for sequence in range(2, total + 1):
        ident = f"performance-page-{sequence:05d}"
        message_rows.append({
            "id": ident, "thread_id": first["thread_id"], "sender_id": "agent-a", "recipient_id": "agent-b",
            "reply_to": None, "text": f"Message {sequence}", "status": "received", "needs_reply": False,
            "sequence": sequence, "recipient_sequence": None, "fingerprint": f"page-fp-{sequence}",
            "created_at": 1_800_000_000.0 + sequence,
        })
        if sequence % 3 == 0:
            # Storage has no ordinal column; the API's stable per-message order
            # is artifact id order, including the empty-list case.
            for suffix in ("z", "a"):
                artifact = _artifact_values(sequence, suffix)
                artifact_rows.append(artifact)
                attachment_rows.append({"message_id": ident, "artifact_id": artifact["id"]})

    with app.extensions["sessions"].begin() as db:
        db.get(Thread, first["thread_id"]).sequence = total
        db.execute(insert(Message), message_rows)
        db.execute(insert(Artifact), artifact_rows)
        db.execute(insert(MessageArtifact), attachment_rows)

    attachment_selects = []
    engine = app.extensions["engine"]

    def count_attachment_selects(_conn, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.lower().split())
        if "message_artifacts" in normalized and normalized.lstrip().startswith("select"):
            attachment_selects.append(normalized)

    event.listen(engine, "before_cursor_execute", count_attachment_selects)
    try:
        first_page = client.get(f"/api/threads/{first['thread_id']}/messages?after_sequence=0&page_size=1100",
                                headers=bearer_headers(app, "agent-a"))
        second_page = client.get(f"/api/threads/{first['thread_id']}/messages?after_sequence=1100&page_size=1100",
                                 headers=bearer_headers(app, "agent-a"))
    finally:
        event.remove(engine, "before_cursor_execute", count_attachment_selects)

    assert first_page.status_code == 200, first_page.get_json()
    first_data = first_page.get_json()
    assert len(first_data["messages"]) == 1100
    assert first_data["next_sequence"] == 1100
    by_sequence = {row["sequence"]: row for row in first_data["messages"]}
    assert by_sequence[3]["attachment_ids"] == ["perf-file-0003-a", "perf-file-0003-z"]
    assert by_sequence[4]["attachment_ids"] == []
    assert by_sequence[1100]["attachment_ids"] == []
    assert second_page.status_code == 200, second_page.get_json()
    second_data = second_page.get_json()
    assert [row["sequence"] for row in second_data["messages"]] == [1101]
    assert second_data["messages"][0]["attachment_ids"] == ["perf-file-1101-a", "perf-file-1101-z"]
    assert second_data["next_sequence"] is None
    assert len(attachment_selects) == 2, attachment_selects


def _walk_plan(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from _walk_plan(child)


def _assert_postgres_recipient_range_plan(engine):
    """Check PostgreSQL's real plan uses the unique recipient/sequence index."""
    with engine.begin() as connection:
        connection.execute(text("ANALYZE messages"))
        result = connection.execute(text("""
            EXPLAIN (FORMAT JSON)
            SELECT recipient_sequence
            FROM messages
            WHERE recipient_id = :recipient AND recipient_sequence > :checkpoint
            ORDER BY recipient_sequence
        """), {"recipient": "agent-b", "checkpoint": 10_000})
        plan_json = result.scalar_one()
    if isinstance(plan_json, str):
        plan_json = json.loads(plan_json)
    plan = plan_json[0]["Plan"]
    scans = [node for node in _walk_plan(plan) if node["Node Type"] in ("Index Scan", "Index Only Scan")]
    assert scans, plan
    assert any("recipient_id" in node.get("Index Cond", "")
               and "recipient_sequence" in node.get("Index Cond", "") for node in scans), plan

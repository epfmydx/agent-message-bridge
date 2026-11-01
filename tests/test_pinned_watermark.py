"""Regressions for a pinned contiguous watermark with a large accepted tail."""
import base64
import json
import sys
import uuid
from unittest.mock import patch

from sqlalchemy import event, insert, select

from bridge.models import Delivery, Message, Participant, Subscription, Thread
from bridge.worker import deliver_one
from conftest import bearer_headers


SECRET = "whsec_" + base64.b64encode(b"synthetic-pinned-watermark-secret").decode()
CALLBACK = "https://agent-b.example.com/events"
TAIL_SIZE = 1_000
WATERMARK_BATCH_BOUND = 256


def rpc(client, app, method, params, ident="pinned-watermark"):
    response = client.post("/mcp", headers=bearer_headers(app, "agent-b"), json={
        "jsonrpc": "2.0", "id": ident, "method": method, "params": params,
    })
    assert response.status_code == 200
    return response.get_json()


def subscription_params(cursor=None):
    params = {"name": "bridge.message.received", "arguments": {}, "delivery": {
        "mode": "webhook", "url": CALLBACK, "secret": SECRET,
    }}
    if cursor is not None:
        params["cursor"] = cursor
    return params


def subscribe(client, app, cursor=None, ident="pinned-subscribe"):
    response = rpc(client, app, "events/subscribe", subscription_params(cursor), ident)
    assert "result" in response, response
    return response["result"]


def send_one(client, app, ident):
    response = client.post("/api/messages", headers=bearer_headers(app, "agent-a"), json={
        "message_id": ident, "recipient": "agent-b", "text": "Synthetic pinned-watermark fixture",
        "status": "received", "needs_reply": True,
    })
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def prepare_terminal_gap(app, client, *, tail=TAIL_SIZE, pending_after_tail=False, stopped=False):
    """Create a real terminal gap followed by bulk accepted history."""
    sub = subscribe(client, app)
    first = send_one(client, app, "pinned-gap-00001")
    # Both gap forms come from the real worker, not an accepted-row shortcut.
    if stopped:
        with app.extensions["sessions"].begin() as db:
            record = db.get(Subscription, sub["id"])
            original_secret = record.secret
            record.secret = "synthetic-unreadable-ciphertext"
        assert deliver_one(app.extensions["sessions"], app.config, post=lambda *_: (400, b""))
        with app.extensions["sessions"].begin() as db:
            # Model a local repair of signing material; stopped work still needs
            # its supported refresh, so later valid deliveries cannot skip it.
            db.get(Subscription, sub["id"]).secret = original_secret
    else:
        assert deliver_one(app.extensions["sessions"], app.config, post=lambda *_: (400, b""))
    with app.extensions["sessions"]() as db:
        gap = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
        assert gap.state == ("stopped" if stopped else "terminal")
        assert gap.reason == ("secret_unreadable" if stopped else "callback_rejected")
        assert db.get(Subscription, sub["id"]).acknowledged_sequence == 0

    thread_id = first["thread_id"]
    message_rows, delivery_rows = [], []
    for sequence in range(2, tail + 2):
        ident = f"pinned-gap-{sequence:05d}"
        message_rows.append({
            "id": ident, "thread_id": thread_id, "sender_id": "agent-a", "recipient_id": "agent-b",
            "reply_to": None, "text": "Synthetic accepted tail", "status": "received", "needs_reply": True,
            "sequence": sequence, "recipient_sequence": sequence, "fingerprint": "fp-" + ident,
            "created_at": 1_800_000_000.0 + sequence,
        })
        delivery_rows.append({
            "id": str(uuid.uuid4()), "message_id": ident, "kind": "mcp", "destination": "mcp:" + sub["id"],
            "subscription_id": sub["id"], "state": "accepted", "attempts": 1,
            "available_at": 1_800_000_000.0 + sequence, "status": 204,
        })

    pending_id = None
    if pending_after_tail:
        sequence = tail + 2
        pending_id = f"pinned-gap-{sequence:05d}"
        message_rows.append({
            "id": pending_id, "thread_id": thread_id, "sender_id": "agent-a", "recipient_id": "agent-b",
            "reply_to": None, "text": "Synthetic next item", "status": "received", "needs_reply": True,
            "sequence": sequence, "recipient_sequence": sequence, "fingerprint": "fp-" + pending_id,
            "created_at": 1_800_000_000.0 + sequence,
        })
        delivery_rows.append({
            "id": str(uuid.uuid4()), "message_id": pending_id, "kind": "mcp", "destination": "mcp:" + sub["id"],
            "subscription_id": sub["id"], "state": "pending", "attempts": 0, "available_at": 0,
        })

    with app.extensions["sessions"].begin() as db:
        db.get(Thread, thread_id).sequence = tail + (2 if pending_after_tail else 1)
        db.get(Participant, "agent-b").sequence = tail + (2 if pending_after_tail else 1)
        db.execute(insert(Message), message_rows)
        db.execute(insert(Delivery), delivery_rows)
    return sub, first, pending_id


def is_watermark_select(statement):
    normalized = " ".join(statement.lower().split())
    return "recipient_sequence" in normalized and "deliveries" in normalized and "recipient_sequence >" in normalized


def assert_bounded_selects(statements):
    assert statements, "worker did not read recipient delivery progress"
    for statement, params in statements:
        assert " limit " in " " + " ".join(statement.lower().split()) + " ", statement
        # SQLite binds the limit; PostgreSQL may render it as an integer. The
        # current fixed internal chunk bound is 256, independent of tail size.
        if isinstance(params, (tuple, list)):
            numeric = [value for value in params if type(value) is int]
            assert numeric and numeric[-1] <= WATERMARK_BATCH_BOUND, (statement, params)
        elif isinstance(params, dict):
            numeric = [value for value in params.values() if type(value) is int]
            if numeric:
                assert numeric[-1] <= WATERMARK_BATCH_BOUND, (statement, params)


def test_terminal_gap_pins_checkpoint_and_replay_keeps_terminal_out_of_requeue(bridge_app, monkeypatch):
    app, client = bridge_app, bridge_app.test_client()
    sub, first, pending_id = prepare_terminal_gap(app, client, pending_after_tail=True)
    statements, fetched, calls = [], [], []
    engine = app.extensions["engine"]
    from bridge import events
    original = events.watermark
    def observed(db, *args, **kwargs):
        execute = db.execute
        calls.append(1)
        def count(statement, *a, **kw):
            rows = list(execute(statement, *a, **kw))
            fetched.append(len(rows))
            return iter(rows)
        with patch.object(db, "execute", count): return original(db, *args, **kwargs)
    monkeypatch.setattr(events, "watermark", observed)

    def capture(_conn, _cursor, statement, params, _context, _many):
        if is_watermark_select(statement):
            statements.append((statement, params))

    event.listen(engine, "before_cursor_execute", capture)
    sent = []
    try:
        # One actual worker delivery is processed while 1,000 later records
        # already exist. The terminal first item must pin the contiguous cursor.
        assert deliver_one(app.extensions["sessions"], app.config,
                           post=lambda url, body, headers: sent.append(json.loads(body)) or (204, b""))
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    assert len(sent) == 1
    from bridge.events import parse_cursor
    assert parse_cursor(app.config, sent[0]["cursor"], sub["id"]) == 0
    assert len(statements) == len(calls) == 1, statements
    assert fetched == [WATERMARK_BATCH_BOUND]
    assert_bounded_selects(statements)
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.exec_driver_sql("ANALYZE messages")
            conn.exec_driver_sql("ANALYZE deliveries")
            sql, parameters = statements[0]
            plan = conn.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, parameters).scalar_one()[0]["Plan"]
        nodes = []
        def walk(node):
            nodes.append(node)
            for child in node.get("Plans", []): walk(child)
        walk(plan)
        message_reads = [node for node in nodes if node.get("Relation Name") == "messages"]
        delivery_reads = [node for node in nodes if node.get("Relation Name") == "deliveries"]
        assert message_reads and delivery_reads
        assert all("Index" in node["Node Type"] and node["Actual Rows"] <= WATERMARK_BATCH_BOUND for node in message_reads)
        assert all("Index" in node["Node Type"] and node["Actual Rows"] <= 1
                   and node["Actual Loops"] <= WATERMARK_BATCH_BOUND for node in delivery_reads)
    with app.extensions["sessions"]() as db:
        checkpoint = db.get(Subscription, sub["id"])
        gap = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
        delivered = db.scalar(select(Delivery).where(Delivery.message_id == pending_id))
        assert checkpoint.acknowledged_sequence == 0
        assert gap.state == "terminal" and gap.status == 400
        assert delivered.state == "accepted"

    # Replaying from the pinned cursor must requeue only accepted events after
    # it. The terminal gap stays terminal and remains the checkpoint boundary.
    refreshed = subscribe(client, app, sub["cursor"], ident="pinned-replay")
    assert parse_cursor(app.config, refreshed["cursor"], sub["id"]) == 0
    with app.extensions["sessions"]() as db:
        gap = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
        later = list(db.scalars(select(Delivery).where(
            Delivery.subscription_id == sub["id"], Delivery.message_id != first["message_id"]
        )))
        assert gap.state == "terminal" and gap.status == 400
        assert len(later) == TAIL_SIZE + 1
        assert all(item.state == "pending" and item.reason == "cursor_replay" for item in later)
        assert db.get(Subscription, sub["id"]).acknowledged_sequence == 0


def test_cli_retry_of_terminal_gap_catches_up_through_accepted_tail_once(bridge_app, monkeypatch):
    import bridge.__main__ as cli

    app, client = bridge_app, bridge_app.test_client()
    sub, first, _ = prepare_terminal_gap(app, client)
    with app.extensions["sessions"]() as db:
        gap_delivery_id = db.scalar(select(Delivery.id).where(Delivery.message_id == first["message_id"]))

    # Exercise the supported operator recovery command against this synthetic
    # app, then let the real worker accept the retried gap.
    monkeypatch.setattr(cli, "create_app", lambda: app)
    monkeypatch.setattr(sys, "argv", ["bridge", "retry-delivery", gap_delivery_id])
    cli.main()

    statements = []
    engine = app.extensions["engine"]

    def capture(_conn, _cursor, statement, params, _context, _many):
        if is_watermark_select(statement):
            statements.append((statement, params))

    event.listen(engine, "before_cursor_execute", capture)
    sent = []
    try:
        assert deliver_one(app.extensions["sessions"], app.config,
                           post=lambda url, body, headers: sent.append(json.loads(body)) or (204, b""))
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    from bridge.events import parse_cursor
    assert len(sent) == 1
    assert parse_cursor(app.config, sent[0]["cursor"], sub["id"]) == TAIL_SIZE + 1
    # Four bounded reads cover 1,001 accepted contiguous rows at a batch size
    # of 256. A second watermark pass would duplicate this full set of reads.
    assert len(statements) <= 4, statements
    assert_bounded_selects(statements)
    with app.extensions["sessions"]() as db:
        checkpoint = db.get(Subscription, sub["id"])
        gap = db.get(Delivery, gap_delivery_id)
        assert checkpoint.acknowledged_sequence == TAIL_SIZE + 1
        assert gap.state == "accepted" and gap.status == 204


def test_inflight_out_of_order_acceptance_keeps_cache_lower_bound_and_refresh_reads_truth(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    sub = subscribe(client, app, ident="parallel-subscribe")
    first = send_one(client, app, "parallel-first")
    second = send_one(client, app, "parallel-second")
    sessions = app.extensions["sessions"]

    entered_first, second_payloads = [], []

    def first_callback(url, body, headers):
        first_payload = json.loads(body)
        # The second worker can claim sequence 2 while sequence 1's callback
        # remains in flight. It finishes first, so the cache must stay behind
        # the still-sending first item.
        assert first_payload["data"]["message_id"] == first["message_id"]
        entered_first.append(first_payload)
        assert deliver_one(sessions, app.config,
                           post=lambda url, body, headers: second_payloads.append(json.loads(body)) or (204, b""))
        from bridge.events import parse_cursor
        assert parse_cursor(app.config, first_payload["cursor"], sub["id"]) == 1
        assert len(second_payloads) == 1
        assert second_payloads[0]["data"]["message_id"] == second["message_id"]
        assert parse_cursor(app.config, second_payloads[0]["cursor"], sub["id"]) == 0
        with sessions() as db:
            current = db.get(Subscription, sub["id"])
            assert current.acknowledged_sequence == 0
        return 204, b""

    assert deliver_one(sessions, app.config, post=first_callback)
    assert len(entered_first) == 1
    with sessions() as db:
        current = db.get(Subscription, sub["id"])
        first_delivery = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
        second_delivery = db.scalar(select(Delivery).where(Delivery.message_id == second["message_id"]))
        # The second callback completed first. The first worker's already-built
        # preview is a safe lower bound, so its checkpoint may lag by one.
        assert current.acknowledged_sequence == 1
        assert current.acknowledged_generation == current.generation == 1
        assert first_delivery.state == "accepted"
        assert second_delivery.state == "accepted"

    # A real refresh recomputes from the safe lower bound and returns the
    # complete accepted prefix, including the suffix committed while the first
    # callback was in flight.
    refreshed = subscribe(client, app, ident="parallel-refresh")
    from bridge.events import parse_cursor
    assert parse_cursor(app.config, refreshed["cursor"], sub["id"]) == 2
    with sessions() as db:
        current = db.get(Subscription, sub["id"])
        assert current.acknowledged_sequence == 2
        assert current.acknowledged_generation == current.generation == 2


def test_unreadable_current_stopped_gap_still_pins_later_valid_delivery(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    sub, first, pending_id = prepare_terminal_gap(app, client, pending_after_tail=True, stopped=True)
    statements = []
    def capture(_conn, _cursor, statement, params, _context, _many):
        if is_watermark_select(statement): statements.append((statement, params))
    event.listen(app.extensions["engine"], "before_cursor_execute", capture)
    sent = []
    try:
        assert deliver_one(app.extensions["sessions"], app.config,
            post=lambda url, body, headers: sent.append(json.loads(body)) or (204, b""))
    finally:
        event.remove(app.extensions["engine"], "before_cursor_execute", capture)
    from bridge.events import parse_cursor
    assert len(sent) == len(statements) == 1
    assert parse_cursor(app.config, sent[0]["cursor"], sub["id"]) == 0
    assert_bounded_selects(statements)
    with app.extensions["sessions"]() as db:
        assert db.get(Subscription, sub["id"]).acknowledged_sequence == 0
        assert db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"])).state == "stopped"
        assert db.scalar(select(Delivery).where(Delivery.message_id == pending_id)).state == "accepted"
    refreshed = subscribe(client, app, sub["cursor"], ident="stopped-resume")
    assert parse_cursor(app.config, refreshed["cursor"], sub["id"]) == 0
    with app.extensions["sessions"]() as db:
        gap = db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"]))
        assert gap.state == "pending" and gap.reason == "subscription_resumed"


def test_missing_delivery_does_not_skip_and_refresh_backfills_gap(bridge_app):
    from sqlalchemy import delete
    from bridge.events import parse_cursor
    app, client = bridge_app, bridge_app.test_client()
    sub = subscribe(client, app)
    for ident in ("missing-first", "missing-middle", "missing-last"):
        send_one(client, app, ident)
    with app.extensions["sessions"].begin() as db:
        db.execute(delete(Delivery).where(Delivery.message_id == "missing-middle"))
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *a: (204, b""))
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
        post=lambda url, body, headers: sent.append(json.loads(body)) or (204, b""))
    assert parse_cursor(app.config, sent[0]["cursor"], sub["id"]) == 1
    with app.extensions["sessions"]() as db:
        assert db.get(Subscription, sub["id"]).acknowledged_sequence == 1
    refreshed = subscribe(client, app)
    assert parse_cursor(app.config, refreshed["cursor"], sub["id"]) == 1
    assert deliver_one(app.extensions["sessions"], app.config, post=lambda *a: (204, b""))
    with app.extensions["sessions"]() as db:
        assert db.get(Subscription, sub["id"]).acknowledged_sequence == 3


def test_older_provisional_cursor_does_not_lower_concurrent_confirmed_cache(bridge_app):
    from bridge.events import parse_cursor, watermark
    import time
    app, client = bridge_app, bridge_app.test_client()
    sub = subscribe(client, app)
    first = send_one(client, app, "concurrent-first")
    second = send_one(client, app, "concurrent-second")
    sessions = app.extensions["sessions"]
    with sessions.begin() as db:
        db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"])).available_at = time.time()+3600
    def second_inflight(url, body, headers):
        assert json.loads(body)["data"]["message_id"] == second["message_id"]
        assert parse_cursor(app.config, json.loads(body)["cursor"], sub["id"]) == 0
        with sessions.begin() as db:
            db.scalar(select(Delivery).where(Delivery.message_id == first["message_id"])).available_at = 0
        assert deliver_one(sessions, app.config, post=lambda *a: (204, b""))
        with sessions() as db:
            assert db.get(Subscription, sub["id"]).acknowledged_sequence == 1
        return 204, b""
    assert deliver_one(sessions, app.config, post=second_inflight)
    with sessions() as db:
        record = db.get(Subscription, sub["id"])
        assert record.acknowledged_sequence == 1 and watermark(db, record) == 2

"""Focused regressions for webhook terminal errors and delivery lease selection."""
import json
import re

import pytest
from sqlalchemy import event, inspect, select

from bridge.models import Delivery, Message, Participant
from bridge.profile_webhooks import update_webhook
from bridge.transport import CallbackError
from bridge.worker import deliver_one


def _message(client, app, ident, *, sender="agent-a", recipient="agent-b"):
    response = client.post("/api/messages", headers={
        "Authorization": "Bearer " + app.extensions["test_credentials"][sender]
    }, json={"message_id": ident, "recipient": recipient, "text": "synthetic payload",
            "status": "received", "needs_reply": True})
    assert response.status_code == 200
    return response.get_json()


def _enable_profile(app):
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, "agent-b")
        update_webhook(db, app.config, participant, enabled=True,
                       url="https://agent-b.example.com/hook", token="synthetic-agent-b-token",
                       expected_generation=participant.webhook_generation)


def _delivery(app, message_id):
    with app.extensions["sessions"]() as db:
        return db.scalar(select(Delivery).where(Delivery.message_id == message_id))


@pytest.mark.parametrize("route", ["legacy", "profile"])
def test_invalid_destination_is_terminal_for_bearer_webhooks(bridge_app, route):
    app, client = bridge_app, bridge_app.test_client()
    if route == "profile":
        _enable_profile(app)
        message = _message(client, app, "invalid-profile-destination")
    else:
        message = _message(client, app, "invalid-configured-destination",
                           sender="agent-b", recipient="agent-a")

    calls = []
    def invalid_destination(*args):
        calls.append(args)
        raise CallbackError("invalid_destination")

    assert deliver_one(app.extensions["sessions"], app.config, post=invalid_destination)
    item = _delivery(app, message["message_id"])
    assert len(calls) == 1
    assert item.state == "terminal" and item.reason == "invalid_destination"
    assert item.attempts == 1
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: pytest.fail("terminal destination was retried")) is False


@pytest.mark.parametrize("reason", ["connection_failed", "timeout"])
@pytest.mark.parametrize("route", ["legacy", "profile"])
def test_transient_transport_errors_remain_retryable_for_bearer_webhooks(bridge_app, route, reason):
    app, client = bridge_app, bridge_app.test_client()
    if route == "profile":
        _enable_profile(app)
        message = _message(client, app, "transient-profile-" + reason)
    else:
        message = _message(client, app, "transient-configured-" + reason,
                           sender="agent-b", recipient="agent-a")

    def transient(*args):
        raise CallbackError(reason)

    assert deliver_one(app.extensions["sessions"], app.config, post=transient)
    item = _delivery(app, message["message_id"])
    assert item.state == "retry" and item.reason == reason
    assert item.attempts == 1


@pytest.mark.parametrize("route,status,expected", [
    ("legacy", 200, "accepted"),
    ("legacy", 204, "terminal"),
    ("profile", 200, "accepted"),
    ("profile", 204, "terminal"),
    ("mcp", 204, "accepted"),
])
def test_response_success_contract_is_exact_for_bearer_and_2xx_for_mcp(bridge_app, route, status, expected):
    app, client = bridge_app, bridge_app.test_client()
    if route == "legacy":
        message = _message(client, app, "response-configured-" + str(status),
                           sender="agent-b", recipient="agent-a")
    else:
        if route == "profile":
            _enable_profile(app)
        else:
            from test_worker import make_subscription
            make_subscription(client, app)
        message = _message(client, app, "response-" + route + "-" + str(status))

    seen = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: seen.append((url, json.loads(body))) or (status, b""))
    item = _delivery(app, message["message_id"])
    assert len(seen) == 1 and item.state == expected and item.status == status


def test_candidate_query_ignores_finished_history_and_live_sending_rows_but_finds_due_work(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable_profile(app)
    message = _message(client, app, "lease-candidate-after-history")
    with app.extensions["sessions"].begin() as db:
        due = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        due.available_at = 0
        # A live lease must not shadow due work even when its available_at is oldest.
        live_message = _message(client, app, "lease-live-sending-row")
        live = db.scalar(select(Delivery).where(Delivery.message_id == live_message["message_id"]))
        live.state, live.available_at, live.lease, live.lease_until = "sending", -100, "live-lease", 9e18
        # Finished history predates every active row. It must not be walked as candidates.
        for i in range(400):
            db.add(Delivery(message_id=message["message_id"], kind="webhook",
                             destination="finished-history-" + str(i), state="accepted",
                             available_at=-1000 - i))

    statements = []
    @event.listens_for(app.extensions["engine"], "before_cursor_execute")
    def capture_candidate_sql(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith("select") and "deliveries" in statement.lower():
            statements.append((statement, parameters))

    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append(url) or (200, b""))
    assert sent == ["https://agent-b.example.com/hook"]
    candidate_sql, parameters = next((sql, parameters) for sql, parameters in statements
                                     if "limit" in sql.lower() and "order by" in sql.lower())
    with app.extensions["engine"].begin() as connection:
        connection.exec_driver_sql("ANALYZE deliveries")
        prefix = "EXPLAIN QUERY PLAN " if connection.dialect.name == "sqlite" else "EXPLAIN "
        plans = [connection.exec_driver_sql(prefix + candidate_sql, parameters).all()]
        assert "ix_deliveries_due" in {index["name"] for index in inspect(connection).get_indexes("deliveries")}
        if connection.dialect.name == "sqlite":
            # DDL set ordering can choose either valid active-row access path.
            # Exercise both creation orders rather than relying on process hash order.
            for name in ("ix_deliveries_due", "ix_deliveries_state"):
                index = next(index for index in Delivery.__table__.indexes if index.name == name)
                index.drop(connection)
                index.create(connection)
                connection.exec_driver_sql("ANALYZE deliveries")
                plans.append(connection.exec_driver_sql(prefix + candidate_sql, parameters).all())
        for plan in plans:
            explained = " ".join(str(row) for row in plan).lower()
            assert "ix_deliveries_due" in explained or "ix_deliveries_state" in explained
            # Scanning the partial active-row index is valid; finished history is absent.
            assert "seq scan on deliveries" not in explained
            assert not re.search(r"\bscan deliveries(?! using (?:covering )?index ix_deliveries_due\b)", explained)
    assert _delivery(app, message["message_id"]).state == "accepted"
    assert _delivery(app, live_message["message_id"]).state == "sending"


def test_expired_legacy_sending_row_reclaims_with_original_future_available_at(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    message = _message(client, app, "expired-legacy-sending-reclaimed",
                       sender="agent-b", recipient="agent-a")
    with app.extensions["sessions"].begin() as db:
        item = db.scalar(select(Delivery).where(Delivery.message_id == message["message_id"]))
        original_available_at = 4e9
        item.state, item.available_at = "sending", original_available_at
        item.lease, item.lease_until = "expired-legacy-lease", 0

    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda url, body, headers: sent.append(url) or (200, b""))
    item = _delivery(app, message["message_id"])
    assert sent == ["https://agent-a.example.com/bridge-hook"]
    assert item.state == "accepted" and item.attempts == 1
    assert item.available_at == original_available_at


def test_future_pending_and_unexpired_retry_rows_are_not_sent(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable_profile(app)
    messages = [
        _message(client, app, "future-pending-row"),
        _message(client, app, "future-retry-row"),
        _message(client, app, "live-lease-not-due-row"),
    ]
    with app.extensions["sessions"].begin() as db:
        pending, retry, sending = [db.scalar(select(Delivery).where(Delivery.message_id == m["message_id"]))
                                   for m in messages]
        pending.available_at = retry.available_at = 4e9
        retry.state = "retry"
        sending.state, sending.available_at = "sending", 0
        sending.lease, sending.lease_until = "live-future-lease", 9e18

    called = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: called.append(args) or (200, b"")) is False
    assert called == []
    assert [_delivery(app, m["message_id"]).state for m in messages] == ["pending", "retry", "sending"]


def test_generation_and_reassigned_lease_fences_remain_effective(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    _enable_profile(app)
    stale = _message(client, app, "queued-old-profile-generation")
    with app.extensions["sessions"].begin() as db:
        participant = db.get(Participant, "agent-b")
        update_webhook(db, app.config, participant, enabled=False, expected_generation=2)
        update_webhook(db, app.config, participant, enabled=True,
                       url="https://replacement.example.com/hook", token="synthetic-replacement-token",
                       expected_generation=3)
    calls = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: calls.append(args) or (200, b""))
    assert calls == []
    assert _delivery(app, stale["message_id"]).state == "stopped"

    current = _message(client, app, "lease-reassigned-during-callback")
    def reassign_lease(*args):
        with app.extensions["sessions"].begin() as db:
            item = db.scalar(select(Delivery).where(Delivery.message_id == current["message_id"]))
            item.lease = "another-worker-lease"
        return 200, b""

    assert deliver_one(app.extensions["sessions"], app.config, post=reassign_lease)
    item = _delivery(app, current["message_id"])
    assert item.state == "sending" and item.lease == "another-worker-lease"


def _dns_test_child(connection, url, body, headers, timeout, addresses, resolutions, connects):
    # Stub only the child resolver/connection boundary, retaining the real
    # parser, public-address checks, IPC outcomes and parent transport mapping.
    import socket
    from unittest.mock import patch
    from bridge import network
    def resolve(*args, **kwargs):
        resolutions.value += 1
        if addresses is None:
            raise socket.gaierror("synthetic NXDOMAIN")
        return [(socket.AF_INET6 if ":" in address else socket.AF_INET,
                 socket.SOCK_STREAM, 0, "", (address, 443)) for address in addresses]
    def forbid_connect(*args, **kwargs):
        connects.value += 1
        raise AssertionError("No receiver connection is permitted in this test")
    with patch.object(network.socket, "getaddrinfo", resolve), patch.object(network, "_pinned_post", forbid_connect):
        network._child(connection, url, body, headers, timeout)


@pytest.mark.parametrize("addresses", [
    ["127.0.0.1"], ["10.1.2.3"], ["169.254.169.254"], ["::1"],
    ["93.184.216.34", "192.168.1.1"], None,
])
def test_real_transport_private_dns_is_terminal_without_connect_but_nxdomain_retries(bridge_app, monkeypatch, addresses):
    import multiprocessing
    from bridge import network
    context = multiprocessing.get_context("spawn")
    connects = context.Value("i", 0, lock=False)
    resolutions = context.Value("i", 0, lock=False)
    class ResolverContext:
        def Pipe(self, **kwargs):
            return context.Pipe(**kwargs)
        def Process(self, *, target, args):
            assert target is network._child
            return context.Process(target=_dns_test_child, args=(*args, addresses, resolutions, connects))
    monkeypatch.setattr(network, "_process_context", ResolverContext)
    app, client = bridge_app, bridge_app.test_client()
    _enable_profile(app)
    message = _message(client, app, "real-dns-refusal")
    assert deliver_one(app.extensions["sessions"], app.config)
    item = _delivery(app, message["message_id"])
    assert resolutions.value == 1 and connects.value == 0 and item.attempts == 1
    assert (item.state, item.reason) == (("terminal", "invalid_destination") if addresses is not None
                                       else ("retry", "connection_failed"))


def test_mcp_invalid_destination_keeps_existing_retry_contract(bridge_app):
    from test_worker import make_subscription
    app, client = bridge_app, bridge_app.test_client()
    make_subscription(client, app)
    message = _message(client, app, "mcp-dns-contract")
    def rejected(*args):
        raise CallbackError("invalid_destination")
    assert deliver_one(app.extensions["sessions"], app.config, post=rejected)
    item = _delivery(app, message["message_id"])
    assert item.kind == "mcp" and item.state == "retry" and item.reason == "invalid_destination"


@pytest.mark.parametrize("replace_settings", [False, True])
def test_operator_retry_respects_profile_generation_after_receiver_repair(bridge_app, monkeypatch, replace_settings):
    from bridge import __main__ as cli
    app, client = bridge_app, bridge_app.test_client()
    _enable_profile(app)
    message = _message(client, app, "explicit-terminal-recovery")
    def rejected(*args):
        raise CallbackError("invalid_destination")
    assert deliver_one(app.extensions["sessions"], app.config, post=rejected)
    item = _delivery(app, message["message_id"])
    assert item.state == "terminal" and item.attempts == 1
    if replace_settings:
        with app.extensions["sessions"].begin() as db:
            participant = db.get(Participant, "agent-b")
            update_webhook(db, app.config, participant, enabled=True,
                           url="https://replacement.example.com/hook", token="synthetic-replacement-token",
                           expected_generation=participant.webhook_generation)
    monkeypatch.setattr(cli, "create_app", lambda: app)
    monkeypatch.setattr("sys.argv", ["bridge", "retry-delivery", item.id])
    cli.main()
    sent = []
    assert deliver_one(app.extensions["sessions"], app.config,
                       post=lambda *args: sent.append(args) or (200, b""))
    item = _delivery(app, message["message_id"])
    if replace_settings:
        assert item.state == "stopped" and item.reason == "webhook_changed" and item.attempts == 1
        assert sent == []
        new_message = _message(client, app, "new-message-after-replacement")
        assert deliver_one(app.extensions["sessions"], app.config,
                           post=lambda *args: sent.append(args) or (200, b""))
        assert len(sent) == 1 and sent[0][0] == "https://replacement.example.com/hook"
        assert _delivery(app, new_message["message_id"]).state == "accepted"
    else:
        assert item.state == "accepted" and item.attempts == 2 and len(sent) == 1

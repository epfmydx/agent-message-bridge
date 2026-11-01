"""Review-agreed regressions through real API, worker and schema paths."""
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, inspect, select, text

from bridge import events, worker
from bridge.models import DELIVERY_INDEXES, Delivery, Message, Subscription
from bridge.schema import ensure_delivery_schema
from test_events import auth, send_to, subscribe, subscribe_params
from test_files import FakeStore, fetch_bytes, import_params, upload_params


def setup_messages(app, count=3):
    client = app.test_client()
    sub = subscribe(client, app)["result"]
    for i in range(1, count+1):
        assert send_to(client, app, "agent-b", f"reliable-{i}").status_code == 200
    return client, sub


def checkpoint(app, sub_id):
    with app.extensions["sessions"]() as db:
        sub = db.get(Subscription, sub_id)
        return sub.acknowledged_sequence, events.watermark(db, sub)


@pytest.mark.parametrize("field", ["secret", "previous_secret"])
def test_unreadable_secret_does_not_block_healthy_destination(bridge_app, field, caplog):
    app = bridge_app
    client, sub = setup_messages(app, 1)
    key = app.config["ENCRYPTION_KEY"]
    with app.extensions["sessions"].begin() as db:
        record = db.get(Subscription, sub["id"])
        setattr(record, field, "synthetic-corrupt-ciphertext")
        record.rotation_until = time.time()+300
    assert client.post("/api/messages", headers=auth(app, "agent-b"), json={"message_id": "healthy-response",
        "recipient": "agent-a", "text": "Synthetic", "status": "completed", "needs_reply": True}).status_code == 200
    posted = []
    def post(url, body, headers):
        posted.append(headers)
        return 200, b""
    assert worker.deliver_one(app.extensions["sessions"], app.config, post)
    assert worker.deliver_one(app.extensions["sessions"], app.config, post)
    with app.extensions["sessions"]() as db:
        mcp = db.scalar(select(Delivery).where(Delivery.kind == "mcp"))
        agent_a = db.scalar(select(Delivery).where(Delivery.kind == "webhook"))
        assert agent_a.state == "accepted"
        assert mcp.state == ("stopped" if field == "secret" else "accepted")
        if field == "secret":
            assert mcp.reason == "secret_unreadable" and mcp.lease is None and mcp.lease_until is None
        else:
            assert len(posted[0]["webhook-signature"].split()) == 1
    assert "synthetic-corrupt-ciphertext" not in caplog.text and key == app.config["ENCRYPTION_KEY"]


@pytest.mark.parametrize("field", ["secret", "previous_secret"])
def test_verified_same_identity_refresh_repairs_both_secret_fields(bridge_app, field):
    app = bridge_app
    client, sub = setup_messages(app, 1)
    with app.extensions["sessions"].begin() as db:
        record = db.get(Subscription, sub["id"])
        setattr(record, field, "synthetic-corruption")
        record.rotation_until = time.time()+300
    worker.deliver_one(app.extensions["sessions"], app.config, lambda *a: (204, b""))
    assert "result" in subscribe(client, app)
    with app.extensions["sessions"]() as db:
        record = db.get(Subscription, sub["id"])
        assert record.previous_secret is None and record.rotation_until == 0
    if field == "secret":
        assert worker.deliver_one(app.extensions["sessions"], app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (1, 1)


def test_expired_interrupted_send_defers_without_busy_loop(bridge_app):
    app = bridge_app
    _, sub = setup_messages(app, 1)
    with app.extensions["sessions"].begin() as db:
        db.get(Subscription, sub["id"]).expires_at = time.time()-1
        item = db.scalar(select(Delivery))
        item.state, item.lease, item.lease_until = "sending", "synthetic-interrupted", time.time()-1
    assert worker.deliver_one(app.extensions["sessions"], app.config)
    assert worker.deliver_one(app.extensions["sessions"], app.config) is False
    with app.extensions["sessions"]() as db:
        item = db.scalar(select(Delivery))
        assert item.state == "retry" and item.lease is None and item.lease_until is None


def test_cli_survives_exception_without_disclosing_dependency_details(bridge_app, monkeypatch, caplog):
    import bridge.__main__ as cli
    calls, sleeps = [], []
    def iteration(*args):
        calls.append(1)
        if len(calls) == 1: raise RuntimeError("synthetic-sensitive-provider-detail")
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "create_app", lambda: bridge_app)
    monkeypatch.setattr(worker, "deliver_one", iteration)
    monkeypatch.setattr(sys, "argv", ["bridge", "worker"])
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)
    cli.main()
    assert len(calls) == 2 and sleeps == [5]
    assert "worker_iteration_failed" in caplog.text and "sensitive-provider" not in caplog.text


def test_provisional_cursor_and_out_of_order_gap_do_not_acknowledge_early(bridge_app):
    app = bridge_app
    _, sub = setup_messages(app)
    sessions = app.extensions["sessions"]
    worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (1, 1)
    with sessions.begin() as db:
        db.scalar(select(Delivery).where(Delivery.message_id == "reliable-2")).available_at = time.time()+3600
    previews = []
    def post(url, body, headers):
        previews.append(events.parse_cursor(app.config, json.loads(body)["cursor"], sub["id"]))
        assert checkpoint(app, sub["id"]) == (1, 1)
        return 204, b""
    worker.deliver_one(sessions, app.config, post)
    assert previews == [1] and checkpoint(app, sub["id"]) == (1, 1)
    with sessions.begin() as db:
        db.scalar(select(Delivery).where(Delivery.message_id == "reliable-2")).available_at = 0
    worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (3, 3)


@pytest.mark.parametrize("accept_first", [False, True])
def test_replay_racing_inflight_accept_obeys_generation_and_rewinds(bridge_app, accept_first):
    app = bridge_app
    client, sub = setup_messages(app)
    sessions = app.extensions["sessions"]
    for _ in range(3): worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (3, 3)
    assert send_to(client, app, "agent-b", "inflight-four").status_code == 200
    entered, release = threading.Event(), threading.Event()
    def post(*args):
        entered.set()
        assert release.wait(5)
        return 204, b""
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(worker.deliver_one, sessions, app.config, post)
        assert entered.wait(3)
        try:
            if accept_first:
                release.set()
                assert running.result(timeout=3)
                assert checkpoint(app, sub["id"]) == (4, 4)
            with sessions() as db:
                old_cursor = events.cursor(app.config, db.get(Subscription, sub["id"]), 1)
            result = subscribe(client, app, params=subscribe_params(cursor=old_cursor))["result"]
            assert events.parse_cursor(app.config, result["cursor"], sub["id"]) == 1
        finally:
            release.set()
        assert running.result(timeout=3)
    assert checkpoint(app, sub["id"]) == (1, 1)
    with sessions() as db:
        item = db.scalar(select(Delivery).where(Delivery.message_id == "inflight-four"))
        assert item.state == ("pending" if accept_first else "retry")
    for _ in range(3): worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (4, 4)


def test_stolen_delivery_lease_cannot_commit_acceptance_or_checkpoint(bridge_app):
    app = bridge_app
    _, sub = setup_messages(app, 1)
    def post(*args):
        with app.extensions["sessions"].begin() as db:
            db.scalar(select(Delivery)).lease = "synthetic-new-lease"
        return 204, b""
    worker.deliver_one(app.extensions["sessions"], app.config, post)
    assert checkpoint(app, sub["id"]) == (0, 0)
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(Delivery)).state == "sending"


def test_nullable_upgrade_and_older_writer_rollback_invalidate_cache(bridge_app):
    app = bridge_app
    client, sub = setup_messages(app, 2)
    sessions, engine = app.extensions["sessions"], app.extensions["engine"]
    for _ in range(2): worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    with engine.begin() as conn:
        original = conn.execute(text("SELECT secret FROM subscriptions WHERE id=:id"), {"id": sub["id"]}).scalar_one()
        for name in ("acknowledged_sequence", "acknowledged_generation"):
            conn.exec_driver_sql("ALTER TABLE subscriptions DROP COLUMN " + name)
    if engine.dialect.name == "postgresql":
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: ensure_delivery_schema(engine), range(2)))
    else: ensure_delivery_schema(engine)
    ensure_delivery_schema(engine)
    assert all(c["nullable"] for c in inspect(engine).get_columns("subscriptions") if c["name"].startswith("acknowledged_"))
    with engine.begin() as conn:
        assert conn.execute(text("SELECT secret FROM subscriptions WHERE id=:id"), {"id": sub["id"]}).scalar_one() == original
    assert checkpoint(app, sub["id"]) == (None, 2)
    # An old worker can update original columns while leaving cache fields NULL.
    assert "result" in subscribe(client, app)
    assert checkpoint(app, sub["id"]) == (2, 2)

    with engine.begin() as conn:
        conn.execute(text("UPDATE subscriptions SET generation=generation+1 WHERE id=:id"), {"id": sub["id"]})
        conn.execute(text("UPDATE deliveries SET state='pending' WHERE message_id='reliable-2'"))
    assert checkpoint(app, sub["id"]) == (2, 1)
    worker.deliver_one(sessions, app.config, lambda *a: (204, b""))
    assert checkpoint(app, sub["id"]) == (2, 2)


def test_concurrent_delivery_index_repair_is_idempotent(bridge_app):
    engine = bridge_app.extensions["engine"]
    for index in DELIVERY_INDEXES: index.drop(engine)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ensure_delivery_schema(engine), range(2)))
    names = {index["name"] for index in inspect(engine).get_indexes("deliveries")}
    assert {index.name for index in DELIVERY_INDEXES} <= names


def test_file_status_schema_and_attachment_only_contract(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    app.extensions["object_store"] = FakeStore()
    app.extensions["file_fetcher"] = lambda url: (_ for _ in ()).throw(OSError("synthetic failure"))
    failed = client.post("/api/files/import", headers=auth(app, "agent-a"), json=import_params())
    assert failed.status_code == 503 and failed.headers["Retry-After"] == "5"
    assert client.get("/api/files/missing", headers=auth(app, "agent-a")).status_code == 404
    app.extensions["file_fetcher"] = fetch_bytes(b"Synthetic file")
    ready = client.post("/api/files/import", headers=auth(app, "agent-a"), json=import_params()).json
    for value in [123, True, [], {}, None, ""]:
        bad = client.post("/mcp", headers=auth(app, "agent-a"), json={"jsonrpc": "2.0", "id": "bad", "method": "tools/call",
            "params": {"name": "complete_upload", "arguments": {"artifact_id": value}}})
        assert bad.status_code == 200 and bad.json["error"]["code"] == -32602
    result = client.post("/mcp", headers=auth(app, "agent-a"), json={"jsonrpc": "2.0", "id": "file-only", "method": "tools/call",
        "params": {"name": "send_message", "arguments": {"message_id": "file-only", "recipient": "agent-b", "text": "",
            "status": "completed", "needs_reply": False, "attachment_ids": [ready["id"]]}}})
    assert result.status_code == 200 and result.json["result"]["structuredContent"]["text"] == ""


def test_store_constructed_once_per_process_and_missing_config_is_lazy(bridge_app, monkeypatch):
    import bridge.files as files
    app, client = bridge_app, bridge_app.test_client()
    assert client.get("/api/profile", headers=auth(app, "agent-a")).status_code == 200
    unconfigured = client.post("/api/files/uploads", headers=auth(app, "agent-a"), json=upload_params())
    assert unconfigured.status_code == 503
    constructed = []
    def create(settings):
        constructed.append(1)
        return FakeStore()
    monkeypatch.setattr(files, "S3Store", create)
    for i in range(2):
        assert client.post("/api/files/uploads", headers=auth(app, "agent-a"), json=upload_params(idempotency_key=str(i))).status_code == 200
    assert len(constructed) == 1
    cache = app.extensions["s3_store_cache"]
    cache.states = {-1: next(iter(cache.states.values()))}
    assert client.post("/api/files/uploads", headers=auth(app, "agent-a"), json=upload_params(idempotency_key="fork")).status_code == 200
    assert len(constructed) == 2


def test_login_miss_and_known_account_both_pay_configured_hash_costs(bridge_app, monkeypatch):
    import bridge.auth as auth_module
    from bridge.app import bootstrap, create_app
    from test_web import BASE, HEADERS
    from werkzeug.security import generate_password_hash
    import re
    settings = {key: bridge_app.config[key] for key in bridge_app.config if key.isupper()}
    settings["USERS"] = [dict(u) for u in settings["USERS"]]
    settings["USERS"][0]["password_hash"] = generate_password_hash("synthetic-other-password", method="pbkdf2:sha256:1000")
    app = create_app(settings)
    with app.extensions["sessions"].begin() as db: bootstrap(db, settings)
    original, observed = auth_module.check_password_hash, []
    def check(value, password):
        observed.append(value.split("$", 1)[0])
        return original(value, password)
    monkeypatch.setattr(auth_module, "check_password_hash", check)
    client = app.test_client()
    counts = []
    for email in ("agent-a@example.com", "agent-b@example.com", "missing@example.com"):
        csrf = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login", base_url=BASE, headers=HEADERS).data)[1].decode()
        observed.clear()
        response = client.post("/login", base_url=BASE, headers=HEADERS, data={"csrf": csrf, "email": email, "password": "wrong"})
        assert response.status_code == 200 and b"Email or password is incorrect." in response.data
        counts.append(sorted(observed))
    assert counts[0] == counts[1] == counts[2] and len(counts[0]) == 2
    app.extensions["engine"].dispose()


def test_new_hash_method_is_prepared_on_unknown_email_after_sync(bridge_app, monkeypatch):
    import bridge.auth as auth_module
    from bridge.models_auth import User
    from test_web import BASE, HEADERS
    from werkzeug.security import generate_password_hash
    import re
    app = bridge_app
    with app.extensions["sessions"].begin() as db:
        db.get(User, "agent-a").password_hash = generate_password_hash("synthetic-changed", method="pbkdf2:sha256:1000")
    original, generated = auth_module.generate_password_hash, []
    def generate(value, **kwargs):
        generated.append(kwargs.get("method"))
        return original(value, **kwargs)
    monkeypatch.setattr(auth_module, "generate_password_hash", generate)
    client = app.test_client()
    csrf = re.search(rb'name="csrf" value="([^"]+)"', client.get("/login", base_url=BASE, headers=HEADERS).data)[1].decode()
    response = client.post("/login", base_url=BASE, headers=HEADERS, data={"csrf": csrf, "email": "missing@example.com", "password": "wrong"})
    assert response.status_code == 200 and generated == ["pbkdf2:sha256:1000"]


def test_simultaneous_first_process_store_calls_publish_one_client(monkeypatch):
    import bridge.files as files
    cache = files._ProcessStore()
    entered, release = threading.Event(), threading.Event()
    made = []
    def construct(settings):
        made.append(1)
        entered.set()
        assert release.wait(3)
        return FakeStore()
    monkeypatch.setattr(files, "S3Store", construct)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(cache.get, {})
        assert entered.wait(2)
        second = pool.submit(cache.get, {})
        release.set()
        assert first.result(timeout=2) is second.result(timeout=2)
    assert len(made) == 1

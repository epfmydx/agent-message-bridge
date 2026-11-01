"""Regression coverage for the bounded, pseudonymous browser login limiter."""
import concurrent.futures
import multiprocessing
import re

import pytest
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy.exc import SQLAlchemyError

from bridge import login_rate
from bridge.models_auth import LoginRate

BASE = "https://bridge.example.com"
CANONICAL = BASE
ORIGIN = "synthetic-origin-secret-for-agent-message-bridge-1234567890"


def _consume_in_process(database_url, key, barrier, result_queue, requests=5):
    """Use an independent process/engine, then start requests together."""
    kwargs = {"connect_args": {"timeout": 30}} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, pool_pre_ping=True, hide_parameters=True, **kwargs)
    try:
        with engine.connect() as connection:
            connection.scalar(text("SELECT 1"))
        login_rate._clock = lambda connection: 1_000.0
        barrier.wait(timeout=45)
        result_queue.put([login_rate.consume(engine, key) for _ in range(requests)])
    finally:
        engine.dispose()


def origin_headers(address="8.8.8.8", **extra):
    headers = {"X-Bridge-Origin": ORIGIN, "X-Forwarded-Proto": "https"}
    if address is not None:
        headers["CF-Connecting-IP"] = address
    headers.update(extra)
    return headers


def post_login(client, address="8.8.8.8", *, host=CANONICAL, headers=None, data=None):
    return client.post("/login", base_url=host, headers=headers or origin_headers(address), data=data or {})


def counter(app, address="8.8.8.8"):
    key = login_rate.client_key(app.secret_key, address)
    with app.extensions["sessions"]() as db:
        return db.get(LoginRate, key)


def freeze_clock(monkeypatch, value=1_000.0):
    now = [value]
    monkeypatch.setattr(login_rate, "_clock", lambda connection: now[0])
    return now


def csrf_token(client, host=CANONICAL):
    response = client.get("/login", base_url=host, headers=origin_headers())
    return re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()


def configured_app(bridge_app, tmp_path, base_url):
    """Build a fresh app so BASE_URL is captured during normal hook setup."""
    from bridge.app import bootstrap, create_app
    from bridge.models import Base

    settings = {key: value for key, value in bridge_app.config.items() if key.isupper()}
    settings["BASE_URL"] = base_url
    settings["DATABASE_URL"] = "sqlite:///" + str(tmp_path / "configured-host.sqlite")
    app = create_app(settings)
    Base.metadata.create_all(app.extensions["engine"])
    with app.extensions["sessions"].begin() as db:
        bootstrap(db, settings)
    return app


def test_only_exact_login_post_on_configured_hostname_is_counted(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)
    client = bridge_app.test_client()

    assert client.get("/login", base_url=BASE, headers=origin_headers()).status_code == 200
    assert post_login(client, host=BASE).status_code == 400
    assert post_login(client, host="https://BRIDGE.EXAMPLE.COM.").status_code == 400
    assert post_login(client, host="https://other.example.com").status_code == 400
    assert client.post("/LOGIN", base_url=BASE, headers=origin_headers()).status_code == 404
    assert client.post("/logout", base_url=BASE, headers=origin_headers()).status_code == 400

    item = counter(bridge_app)
    assert item is not None and len(item.attempts) == 2


def test_login_limiter_binds_to_a_custom_configured_host(bridge_app, tmp_path, monkeypatch):
    freeze_clock(monkeypatch)
    configured = "https://custom-bridge.example.net"
    app = configured_app(bridge_app, tmp_path, configured)
    try:
        client = app.test_client()
        assert post_login(client, host=configured).status_code == 400
        assert post_login(client, host="https://CUSTOM-BRIDGE.EXAMPLE.NET.").status_code == 400
        assert post_login(client, host=BASE).status_code == 400
        item = counter(app)
        assert item is not None and len(item.attempts) == 2
    finally:
        app.extensions["engine"].dispose()


@pytest.mark.parametrize("root_separator", ["。", "．", "｡"])
def test_unicode_base_url_counts_punycode_case_and_mapped_root_separators(
        bridge_app, tmp_path, monkeypatch, root_separator):
    freeze_clock(monkeypatch)
    app = configured_app(bridge_app, tmp_path, "https://bücher.example" + root_separator)
    try:
        client = app.test_client()
        hosts = ["https://xn--bcher-kva.example", "https://XN--BCHER-KVA.EXAMPLE."]
        for index in range(10):
            assert post_login(client, host=hosts[index % len(hosts)]).status_code == 400
        blocked = post_login(client, host="https://XN--BCHER-KVA.EXAMPLE.:8443")
        assert blocked.status_code == 429
        item = counter(app)
        assert item is not None and item.attempts == [] and item.blocked_until == 1_010.0
    finally:
        app.extensions["engine"].dispose()


def test_punycode_base_url_counts_unicode_and_ascii_browser_hosts(bridge_app, tmp_path, monkeypatch):
    freeze_clock(monkeypatch)
    app = configured_app(bridge_app, tmp_path, "https://xn--bcher-kva.example")
    try:
        client = app.test_client()
        assert post_login(client, host="https://bücher.example").status_code == 400
        assert post_login(client, host="https://XN--BCHER-KVA.EXAMPLE.").status_code == 400
        assert len(counter(app).attempts) == 2
    finally:
        app.extensions["engine"].dispose()


def test_nontransitional_sharp_s_host_matches_its_punycode_only(bridge_app, tmp_path, monkeypatch):
    freeze_clock(monkeypatch)
    app = configured_app(bridge_app, tmp_path, "https://faß.example")
    try:
        client = app.test_client()
        assert post_login(client, host="https://fass.example").status_code == 400
        assert counter(app) is None
        for _ in range(10):
            assert post_login(client, host="https://xn--fa-hia.example").status_code == 400
        blocked = post_login(client, host="https://xn--fa-hia.example")
        assert blocked.status_code == 429
        item = counter(app)
        assert item is not None and item.attempts == [] and item.blocked_until == 1_010.0
    finally:
        app.extensions["engine"].dispose()


@pytest.mark.parametrize(("configured", "equivalent", "other"), [
    ("https://127.0.0.1:8443", "https://127.0.0.1:9443", "https://127.0.0.2:9443"),
    ("https://[2001:0db8:0:0::1]:8443", "https://[2001:db8::1]:9443", "https://[2001:db8::2]:9443"),
])
def test_ip_literal_hosts_keep_port_independent_matching(bridge_app, tmp_path, monkeypatch,
                                                         configured, equivalent, other):
    freeze_clock(monkeypatch)
    app = configured_app(bridge_app, tmp_path, configured)
    try:
        client = app.test_client()
        assert post_login(client, host=equivalent).status_code == 400
        assert post_login(client, host=other).status_code == 400
        item = counter(app)
        assert item is not None and len(item.attempts) == 1
    finally:
        app.extensions["engine"].dispose()


@pytest.mark.parametrize("headers,status", [
    ({**origin_headers(None), "X-Forwarded-For": "8.8.8.8"}, 400),
    ({"X-Bridge-Origin": "invalid", "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}, 403),
])
def test_spoofed_or_unverified_origin_is_rejected_before_counter(bridge_app, headers, status, monkeypatch):
    freeze_clock(monkeypatch)
    response = post_login(bridge_app.test_client(), headers=headers)
    assert response.status_code == status
    assert counter(bridge_app) is None


def test_missing_verified_address_fails_closed(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)
    hooks = bridge_app.before_request_funcs[None]
    def clear_verified_ip():
        from flask import request
        request.environ.pop("agent_message_bridge.cloudflare_client_ip", None)
    hooks.insert(1, clear_verified_ip)  # after the origin guard, before the limiter
    try:
        response = post_login(bridge_app.test_client())
    finally:
        hooks.remove(clear_verified_ip)
    assert response.status_code == 400
    assert response.json == {"error": "invalid_cloudflare_client_ip"}
    assert counter(bridge_app) is None
    with pytest.raises(ValueError):
        login_rate.client_key(bridge_app.secret_key, None)


@pytest.mark.parametrize("addresses", [
    ("8.8.8.8", "::ffff:8.8.8.8"),
    ("2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888"),
])
def test_equivalent_ip_spellings_share_one_counter(bridge_app, addresses, monkeypatch):
    freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    for address in addresses:
        response = post_login(client, address)
        assert response.status_code == 400
    first, second = addresses
    first_key = login_rate.client_key(bridge_app.secret_key, first)
    assert first_key == login_rate.client_key(bridge_app.secret_key, second)
    assert re.fullmatch(r"[0-9a-f]{64}", first_key)
    assert first not in first_key and second not in first_key
    assert counter(bridge_app, first).attempts == [1_000.0, 1_000.0]


def test_every_login_post_counts_before_csrf_password_checks(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    page = client.get("/login", base_url=CANONICAL, headers=origin_headers())
    csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()

    assert post_login(client, data={"csrf": csrf, "email": "agent-b@example.com",
                                    "password": "synthetic-password-agent-b"}).status_code == 302
    page = client.get("/login", base_url=CANONICAL, headers=origin_headers())
    csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
    assert post_login(client, data={"csrf": csrf, "email": "agent-b@example.com",
                                    "password": "synthetic-wrong-password"}).status_code == 200
    assert post_login(client, data={"csrf": "bad", "email": "agent-b@example.com",
                                    "password": "synthetic-password-agent-b"}).status_code == 400
    assert len(counter(bridge_app).attempts) == 3


@pytest.fixture
def rate_owner_app(bridge_app):
    from bridge.app import bootstrap
    from werkzeug.security import generate_password_hash

    bridge_app.config["BROWSER_OWNERS"] = [{"id": "personal-owner", "name": "Personal Owner",
        "email": "personal@example.com", "password_hash": generate_password_hash("synthetic-personal-owner-password")}]
    with bridge_app.extensions["sessions"].begin() as db:
        bootstrap(db, bridge_app.config)
    return bridge_app


def test_owner_participant_and_oauth_browser_logins_are_counted(rate_owner_app, monkeypatch):
    freeze_clock(monkeypatch)

    callback = "https://client.example.com/callback"
    resource = rate_owner_app.config["BASE_URL"] + "/mcp"
    challenge = "A" * 43

    def csrf_from(response):
        return re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()

    participant = rate_owner_app.test_client()
    page = participant.get("/login", base_url=CANONICAL, headers=origin_headers())
    response = post_login(participant, data={"csrf": csrf_from(page), "email": "agent-b@example.com",
                                             "password": "synthetic-password-agent-b"})
    assert response.status_code == 302

    owner = rate_owner_app.test_client()
    page = owner.get("/login", base_url=CANONICAL, headers=origin_headers())
    response = post_login(owner, data={"csrf": csrf_from(page), "email": "personal@example.com",
                                       "password": "synthetic-personal-owner-password"})
    assert response.status_code == 302

    oauth = rate_owner_app.test_client()
    registration = oauth.post("/oauth/register", base_url=BASE, json={
        "redirect_uris": [callback], "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none"})
    assert registration.status_code == 201
    fields = dict(response_type="code", client_id=registration.json["client_id"], redirect_uri=callback,
                  scope="bridge:messages", resource=resource, state="synthetic-state",
                  code_challenge=challenge, code_challenge_method="S256")
    start = oauth.get("/oauth/authorize", base_url=CANONICAL, headers=origin_headers(), query_string=fields)
    assert start.status_code == 302 and start.location == "/login"
    page = oauth.get("/login", base_url=CANONICAL, headers=origin_headers())
    response = post_login(oauth, data={"csrf": csrf_from(page), "email": "agent-b@example.com",
                                       "password": "synthetic-password-agent-b"})
    assert response.status_code == 302 and response.location.startswith("/oauth/authorize?")
    assert len(counter(rate_owner_app).attempts) == 3


def test_tenth_is_admitted_eleventh_starts_fixed_cooldown_and_boundaries(bridge_app, monkeypatch):
    now = freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    for _ in range(10):
        assert post_login(client).status_code == 400
    blocked = post_login(client)
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "10"
    now[0] += 5
    still_blocked = post_login(client)
    assert still_blocked.status_code == 429 and still_blocked.headers["Retry-After"] == "5"
    now[0] += 5
    assert post_login(client).status_code == 400
    assert len(counter(bridge_app).attempts) == 1


def test_rolling_window_expires_attempt_at_exact_boundary(bridge_app, monkeypatch):
    now = freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    for _ in range(10):
        assert post_login(client).status_code == 400
    now[0] += 10
    assert post_login(client).status_code == 400
    assert len(counter(bridge_app).attempts) == 1


def test_same_ip_shares_limit_and_other_ip_recovers(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    for _ in range(10):
        assert post_login(client, "8.8.8.8").status_code == 400
    assert post_login(client, "8.8.8.8").status_code == 429
    assert post_login(client, "1.1.1.1").status_code == 400
    assert counter(bridge_app, "8.8.8.8").attempts == []
    assert len(counter(bridge_app, "1.1.1.1").attempts) == 1


def test_rate_database_failure_returns_sanitized_503_without_password_hash(bridge_app, monkeypatch, caplog):
    from bridge import auth
    client = bridge_app.test_client()
    csrf = csrf_token(client)

    def fail(engine, key):
        raise SQLAlchemyError("synthetic-db-secret-and-8.8.8.8")
    def forbidden_hash(*args, **kwargs):
        pytest.fail("password verification ran after the limiter database failed")
    monkeypatch.setattr(login_rate, "consume", fail)
    monkeypatch.setattr(auth, "check_password_hash", forbidden_hash)
    response = post_login(client, data={"csrf": csrf, "email": "agent-b@example.com",
                                        "password": "synthetic-password-agent-b"})
    assert response.status_code == 503 and response.headers["Retry-After"] == "10"
    assert response.json == {"error": "login_temporarily_unavailable"}
    assert b"synthetic-db-secret" not in response.data and b"8.8.8.8" not in response.data
    assert "login_rate_unavailable" in caplog.text
    assert "synthetic-db-secret" not in caplog.text and "8.8.8.8" not in caplog.text


def test_schema_init_repairs_missing_counter_table_and_index_and_rollback_keeps_count(bridge_app, monkeypatch):
    engine = bridge_app.extensions["engine"]
    from bridge.schema import ensure_login_rate_schema

    with engine.begin() as connection:
        connection.execute(text("DROP TABLE login_rate_limits"))
    ensure_login_rate_schema(engine)
    ensure_login_rate_schema(engine)
    assert "login_rate_limits" in inspect(engine).get_table_names()
    expiry_index = next(index for index in LoginRate.__table__.indexes if index.name == "ix_login_rate_expiry")
    assert expiry_index.name in {item["name"] for item in inspect(engine).get_indexes("login_rate_limits")}
    expiry_index.drop(engine)
    ensure_login_rate_schema(engine)
    assert expiry_index.name in {item["name"] for item in inspect(engine).get_indexes("login_rate_limits")}

    freeze_clock(monkeypatch)
    assert post_login(bridge_app.test_client()).status_code == 400
    assert len(counter(bridge_app).attempts) == 1


def test_concurrent_real_login_posts_admit_exactly_ten(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)

    def submit(_):
        return post_login(bridge_app.test_client()).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(submit, range(20)))
    assert statuses.count(400) == 10
    assert statuses.count(429) == 10
    assert counter(bridge_app).attempts == []


def test_cleanup_drains_more_than_one_batch_and_preserves_fresh_rows(bridge_app, monkeypatch):
    now = freeze_clock(monkeypatch, 10_000.0)
    table = LoginRate.__table__
    stale = [{"client_key": f"stale-{i:04d}", "attempts": [], "blocked_until": 0,
              "expires_at": now[0] - 1} for i in range(140)]
    with bridge_app.extensions["engine"].begin() as connection:
        connection.execute(table.insert(), stale)

    fresh_key = login_rate.client_key(bridge_app.secret_key, "8.8.8.8")
    assert login_rate.consume(bridge_app.extensions["engine"], fresh_key) == 0
    with bridge_app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count()).select_from(LoginRate).where(LoginRate.expires_at <= now[0])) == 76
    for i, remaining in enumerate((12, 0)):
        key = login_rate.client_key(bridge_app.secret_key, f"1.1.1.{i+1}")
        assert login_rate.consume(bridge_app.extensions["engine"], key) == 0
        with bridge_app.extensions["sessions"]() as db:
            assert db.scalar(select(func.count()).select_from(LoginRate).where(LoginRate.expires_at <= now[0])) == remaining
    with bridge_app.extensions["sessions"]() as db:
        assert db.get(LoginRate, fresh_key).attempts == [now[0]]


def test_exhausted_login_does_not_change_get_or_machine_routes(bridge_app, monkeypatch):
    freeze_clock(monkeypatch)
    client = bridge_app.test_client()
    for _ in range(11):
        assert post_login(client).status_code in (400, 429)

    login_page = client.get("/login", base_url=CANONICAL, headers=origin_headers())
    profile = client.get("/api/profile", base_url=CANONICAL)
    register = client.post("/oauth/register", base_url=CANONICAL, json={})
    token = client.post("/oauth/token", base_url=CANONICAL, data={})
    mcp = client.post("/mcp", base_url=CANONICAL)
    revoke = client.post("/oauth/revoke", base_url=CANONICAL, data={})
    assert login_page.status_code == 200
    assert profile.status_code == 401
    assert register.status_code == 400
    assert token.status_code == 400
    assert mcp.status_code == 401
    assert revoke.status_code == 401
    assert all(b"login_rate_limited" not in response.data
               for response in (login_page, profile, register, token, mcp, revoke))


def test_missing_counter_table_fails_real_post_before_hash_and_machine_get_survives(bridge_app, monkeypatch):
    from bridge import auth
    from bridge.schema import ensure_login_rate_schema

    engine = bridge_app.extensions["engine"]
    client = bridge_app.test_client()
    csrf = csrf_token(client)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE login_rate_limits"))

    def forbidden_hash(*args, **kwargs):
        pytest.fail("password verification ran while the counter table was missing")
    monkeypatch.setattr(auth, "check_password_hash", forbidden_hash)
    response = post_login(client, data={"csrf": csrf, "email": "agent-b@example.com",
                                        "password": "synthetic-password-agent-b"})
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "10"
    assert response.json == {"error": "login_temporarily_unavailable"}
    assert bridge_app.test_client().get("/api/profile", base_url=CANONICAL).status_code == 401

    ensure_login_rate_schema(engine)
    monkeypatch.undo()
    assert post_login(bridge_app.test_client()).status_code == 400
    assert len(counter(bridge_app).attempts) == 1


def test_multiprocess_independent_engines_share_one_limit(bridge_app):
    engine = bridge_app.extensions["engine"]
    database_url = engine.url.render_as_string(hide_password=False)
    key = login_rate.client_key(bridge_app.secret_key, "8.8.8.8")
    context = multiprocessing.get_context("spawn")
    barrier, result_queue = context.Barrier(5), context.Queue()
    workers = [context.Process(target=_consume_in_process, args=(database_url, key, barrier, result_queue))
               for _ in range(4)]
    try:
        for worker in workers:
            worker.start()
        barrier.wait(timeout=45)
        batches = [result_queue.get(timeout=60) for _ in workers]
        for worker in workers:
            worker.join(timeout=30)
        assert all(worker.exitcode == 0 for worker in workers)
        results = [retry for batch in batches for retry in batch]
        assert len(results) == 20
        assert results.count(0) == 10
        assert sum(retry > 0 for retry in results) == 10
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        result_queue.close()
        result_queue.join_thread()


def test_concurrent_schema_migration_is_idempotent(bridge_app):
    from bridge.schema import ensure_login_rate_schema

    engine = bridge_app.extensions["engine"]
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE login_rate_limits"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ensure_login_rate_schema(engine), range(2)))
    assert results == [None, None]
    assert "login_rate_limits" in inspect(engine).get_table_names()
    assert "ix_login_rate_expiry" in {item["name"] for item in inspect(engine).get_indexes("login_rate_limits")}


def test_postgres_locked_counter_returns_503_without_password_hash(bridge_app, monkeypatch):
    if bridge_app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("requires PostgreSQL row locks")
    from bridge import auth

    freeze_clock(monkeypatch)
    engine = bridge_app.extensions["engine"]
    client = bridge_app.test_client()
    csrf = csrf_token(client)
    key = login_rate.client_key(bridge_app.secret_key, "8.8.8.8")
    assert login_rate.consume(engine, key) == 0
    lock_connection = engine.connect()
    lock_transaction = lock_connection.begin()
    lock_connection.execute(select(LoginRate.client_key).where(LoginRate.client_key == key).with_for_update()).one()

    def forbidden_hash(*args, **kwargs):
        pytest.fail("password verification ran after the locked limiter row timed out")
    monkeypatch.setattr(auth, "check_password_hash", forbidden_hash)
    try:
        response = post_login(client, data={"csrf": csrf, "email": "agent-b@example.com",
                                            "password": "synthetic-password-agent-b"})
    finally:
        lock_transaction.rollback()
        lock_connection.close()
    assert response.status_code == 503 and response.headers["Retry-After"] == "10"
    assert response.json == {"error": "login_temporarily_unavailable"}


def test_postgres_cleanup_skips_locked_expired_row_then_preserves_refreshed_row(bridge_app, monkeypatch):
    if bridge_app.extensions["engine"].dialect.name != "postgresql":
        pytest.skip("requires PostgreSQL SKIP LOCKED")

    now = freeze_clock(monkeypatch, 20_000.0)[0]
    engine = bridge_app.extensions["engine"]
    table = LoginRate.__table__
    stale_key = "ab" * 32
    with engine.begin() as connection:
        connection.execute(table.insert().values(client_key=stale_key, attempts=[], blocked_until=0,
                                                  expires_at=now - 1))
    lock_connection = engine.connect()
    lock_transaction = lock_connection.begin()
    lock_connection.execute(select(LoginRate.client_key).where(LoginRate.client_key == stale_key).with_for_update()).one()
    try:
        other_key = login_rate.client_key(bridge_app.secret_key, "1.1.1.1")
        assert login_rate.consume(engine, other_key) == 0
        lock_connection.execute(update(table).where(table.c.client_key == stale_key).values(
            attempts=[now], blocked_until=0, expires_at=now + login_rate.WINDOW))
        lock_transaction.commit()
    finally:
        if lock_transaction.is_active:
            lock_transaction.rollback()
        lock_connection.close()
    with engine.connect() as connection:
        row = connection.execute(select(table.c.expires_at, table.c.attempts)
                                 .where(table.c.client_key == stale_key)).one()
    assert row.expires_at == now + login_rate.WINDOW
    assert row.attempts == [now]

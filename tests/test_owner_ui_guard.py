"""Security and read-only regressions for the owner conversation browser routes."""
from sqlalchemy import event, text
from werkzeug.security import generate_password_hash

from bridge.auth import digest
from bridge.models import Artifact, Delivery, Member, Message, MessageArtifact, Thread, WorkClaim
from bridge.models_auth import BrowserOwner, User

BASE = "https://bridge.example.com"
ORIGIN = "synthetic-origin-secret-for-agent-message-bridge-1234567890"
VALID = {"X-Bridge-Origin": ORIGIN, "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


def get(client, path, headers=VALID, **kwargs):
    return client.get(path, base_url=BASE, headers=headers, **kwargs)


def sign_in(app, client, ident, owner):
    model = BrowserOwner if owner else User
    with app.extensions["sessions"]() as db:
        credential = digest(db.get(model, ident).password_hash)
    with client.session_transaction(base_url=BASE) as session:
        session.clear()
        session.update(owner=ident, credential=credential,
                       account_kind="owner" if owner else "participant")


def seed_owner_ui(app):
    app.config["BROWSER_OWNERS"] = [{"id": "guard-owner", "name": "Synthetic Owner",
        "email": "guard-owner@example.com", "password_hash": generate_password_hash("synthetic-password")}]
    with app.extensions["sessions"].begin() as db:
        from bridge.app import bootstrap
        bootstrap(db, app.config)
        db.add(Thread(id="guard-thread", created_at=1704067200))
        db.flush()
        db.add_all([Member(thread_id="guard-thread", participant_id=ident)
                    for ident in ("agent-a", "agent-b")])
        db.add_all([
            Message(id="guard-old", thread_id="guard-thread", sender_id="agent-a", recipient_id="agent-b",
                text="<script>old-message()</script>", status="working", needs_reply=True, sequence=1,
                fingerprint="synthetic-old", created_at=1704067201),
            Message(id="guard-new", thread_id="guard-thread", sender_id="agent-b", recipient_id="agent-a",
                text="Synthetic newest message", status="completed", needs_reply=False, sequence=2,
                fingerprint="synthetic-new", created_at=1704067202),
        ])
        db.add_all([
            Artifact(id="guard-old-file", owner_id="agent-a", idempotency_key="old-file",
                object_key="synthetic/guard-old", filename="<svg onload=alert(1)>.txt", content_type="text/plain",
                size_bytes=1, sha256="0" * 64, state="ready"),
            Artifact(id="guard-new-file", owner_id="agent-b", idempotency_key="new-file",
                object_key="synthetic/guard-new", filename="<img src=x onerror=alert(1)>.txt", content_type="text/plain",
                size_bytes=1, sha256="0" * 64, state="ready", lease="synthetic-file-lease", lease_until=1800000000),
        ])
        db.flush()
        db.add_all([MessageArtifact(message_id="guard-old", artifact_id="guard-old-file"),
                    MessageArtifact(message_id="guard-new", artifact_id="guard-new-file")])
        db.add(WorkClaim(message_id="guard-old", claim_id="synthetic-claim", claimed_at=1704067203))
        db.add_all([
            Delivery(id="guard-delivery-pending", message_id="guard-old", kind="webhook",
                destination="synthetic-pending", state="pending", attempts=2, available_at=1704067204,
                lease="synthetic-delivery-lease", lease_until=1704067300, status=None, reason="synthetic-retry"),
            Delivery(id="guard-delivery-done", message_id="guard-new", kind="webhook",
                destination="synthetic-done", state="accepted", attempts=3, available_at=1704067205,
                lease=None, lease_until=None, status=202, reason=None),
        ])


def table_snapshot(engine):
    names = ("threads", "thread_members", "messages", "artifacts", "message_artifacts", "work_claims", "deliveries")
    with engine.connect() as connection:
        return {name: connection.execute(text(f'SELECT * FROM "{name}" ORDER BY 1')).all() for name in names}


def feed_url_for(app, thread_id, size, direction, anchor):
    from bridge.owner_web import _feed_url
    with app.test_request_context("/", base_url=BASE), app.extensions["sessions"]() as db:
        return _feed_url(db.get(BrowserOwner, "guard-owner"), thread_id, size, direction, anchor)


def test_both_owner_conversation_endpoints_reject_untrusted_origin_before_session_or_sql(bridge_app, monkeypatch):
    app = bridge_app
    seed_owner_ui(app)
    paths = ("/conversation?thread_id=guard-thread", "/conversation/messages?thread_id=guard-thread&cursor=synthetic")
    scenarios = (
        ("missing origin", {}, {}, 403, "cloudflare_proxy_required"),
        ("wrong origin", {**VALID, "X-Bridge-Origin": "wrong-synthetic-secret"}, {}, 403, "cloudflare_proxy_required"),
        ("untrusted socket despite forwarded peer", VALID, {"REMOTE_ADDR": "8.8.4.4", "HTTP_X_FORWARDED_FOR": "127.0.0.1"}, 403, "cloudflare_proxy_required"),
        ("non-https forwarded scheme", {**VALID, "X-Forwarded-Proto": "http"}, {}, 403, "cloudflare_https_required"),
        ("missing original client ip", {k: v for k, v in VALID.items() if k != "CF-Connecting-IP"}, {}, 400, "invalid_cloudflare_client_ip"),
        ("spoofed private original client ip", {**VALID, "CF-Connecting-IP": "127.0.0.1", "X-Forwarded-For": "8.8.8.8"}, {}, 400, "invalid_cloudflare_client_ip"),
    )
    sessions = []
    original_factory = app.extensions["sessions"]
    def count_session(*args, **kwargs):
        sessions.append(True)
        return original_factory(*args, **kwargs)
    monkeypatch.setitem(app.extensions, "sessions", count_session)
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        for route in paths:
            for label, headers, environ, code, error in scenarios:
                response = get(app.test_client(), route, headers=headers, environ_overrides=environ)
                assert response.status_code == code, (route, label, response.data)
                assert response.get_json() == {"error": error}, (route, label, response.data)
                assert sessions == [], (route, label, "application database session was created")
                assert statements == [], (route, label, "SQL ran before the origin guard")
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def test_owner_listing_history_and_feed_gets_preserve_all_message_delivery_and_claim_state(bridge_app):
    app = bridge_app
    seed_owner_ui(app)
    owner = app.test_client()
    sign_in(app, owner, "guard-owner", True)
    baseline = table_snapshot(app.extensions["engine"])
    writes = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            writes.append(statement)
    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        listing = get(owner, "/")
        assert listing.status_code == 200
        history = get(owner, "/conversation?thread_id=guard-thread&page_size=1")
        assert history.status_code == 200
        feed_url = feed_url_for(app, "guard-thread", 1, "older", 2)
        feed = get(owner, feed_url)
        assert feed.status_code == 200 and feed.is_json
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert writes == []
    assert table_snapshot(engine) == baseline


def test_owner_csp_escaping_and_participant_scope_stay_separate(bridge_app):
    app = bridge_app
    seed_owner_ui(app)
    owner = app.test_client()
    sign_in(app, owner, "guard-owner", True)
    page = get(owner, "/conversation?thread_id=guard-thread&page_size=1")
    assert page.status_code == 200
    csp = page.headers["Content-Security-Policy"]
    assert csp == ("default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; "
                   "frame-ancestors 'none'; base-uri 'none'")
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert b'<script src="/static/owner-conversations.js" defer></script>' in page.data
    assert b"<img src=x onerror=alert(1)>" not in page.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in page.data

    feed_url = feed_url_for(app, "guard-thread", 1, "older", 2)
    feed = get(owner, feed_url)
    assert feed.status_code == 200
    html = feed.get_json()["html"]
    assert "<script>old-message()" not in html and "&lt;script&gt;old-message()&lt;/script&gt;" in html
    assert "<svg onload=alert(1)>" not in html and "&lt;svg onload=alert(1)&gt;.txt" in html

    participant = app.test_client()
    sign_in(app, participant, "agent-b", False)
    for route in ("/conversation?thread_id=guard-thread", feed_url):
        assert get(participant, route).status_code == 404
    participant_message = get(participant, "/message?message_id=guard-old")
    assert participant_message.status_code == 200
    assert participant_message.headers["Content-Security-Policy"] == (
        "default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

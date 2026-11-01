"""Bounded browser paging and indexed existence-query regressions."""
import os
from contextlib import contextmanager

import pytest
from flask import g, template_rendered
from sqlalchemy import event, select, text

from bridge.auth import digest
from bridge.models import Member, Message, Thread
from bridge.models_auth import BrowserOwner, User

BASE = "https://bridge.example.com"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


def get(client, path):
    return client.get(path, base_url=BASE, headers=HEADERS)


def sign_in(app, client, ident, kind):
    model = BrowserOwner if kind == "owner" else User
    with app.extensions["sessions"]() as db:
        credential = digest(db.get(model, ident).password_hash)
    with client.session_transaction(base_url=BASE) as session:
        session.clear()
        session.update(owner=ident, credential=credential, account_kind=kind)


@contextmanager
def rendered(app):
    contexts = []

    def capture(sender, template, context, **extra):
        contexts.append(context)

    template_rendered.connect(capture, app)
    try:
        yield contexts
    finally:
        template_rendered.disconnect(capture, app)


def page(app, client, path):
    with rendered(app) as contexts:
        response = get(client, path)
    assert response.status_code == 200, response.text
    return contexts[-1], response


def add_message(db, thread_id, sequence):
    db.add(Message(id=f"{thread_id}-message-{sequence:05d}", thread_id=thread_id,
        sender_id="agent-a", recipient_id="agent-b", text=f"Synthetic {thread_id} {sequence}",
        status="completed", needs_reply=False, sequence=sequence,
        fingerprint=f"owner-query-{thread_id}-{sequence}", created_at=1700000000 + sequence))


@pytest.fixture
def query_pages(bridge_app):
    app = bridge_app
    with app.extensions["sessions"].begin() as db:
        db.add(BrowserOwner(id="query-owner", name="Query Owner", email="query-owner@example.com",
            password_hash="synthetic-query-owner-password-hash", active=True))
        db.add_all([Thread(id=f"query-thread-{i}", created_at=i) for i in range(6)])
        db.flush()
        db.add_all([Member(thread_id=f"query-thread-{i}", participant_id=p)
                    for i in range(6) for p in ("agent-a", "agent-b")])
        for sequence in range(1, 206):
            add_message(db, "query-thread-0", sequence)
        add_message(db, "query-thread-1", 1)
    owner = app.test_client()
    sign_in(app, owner, "query-owner", "owner")
    participant = app.test_client()
    sign_in(app, participant, "agent-b", "participant")
    return app, owner, participant


@pytest.mark.parametrize("path", [
    "/?page_size=0", "/?page_size=-1", "/?page_size=x", "/?page_size=101",
    "/?page_size=999999999999999999999999999999999999",
    "/conversation?thread_id=query-thread-0&page_size=0",
    "/conversation?thread_id=query-thread-0&page_size=x",
    "/conversation?thread_id=query-thread-0&page_size=101",
    "/conversation?thread_id=query-thread-0&page_size=999999999999999999999999999999999999",
])
def test_out_of_range_and_huge_sizes_are_rejected_before_message_or_page_sql(query_pages, path):
    app, owner, _ = query_pages
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.lower().split()))

    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = get(owner, path)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 400
    assert not any(" from messages" in sql or " from threads" in sql for sql in statements)


def test_supported_sizes_and_default_apply_to_owner_and_participant_pages(query_pages):
    app, owner, participant = query_pages
    for size in (1, 25, 100):
        owner_context, _ = page(app, owner, f"/?page_size={size}")
        assert owner_context["page_size"] == size
        assert len(owner_context["threads"]) <= size
        participant_context, _ = page(app, participant, f"/?page_size={size}")
        assert participant_context["page_size"] == size
        assert len(participant_context["messages"]) == size
        conversation, _ = page(app, owner,
            f"/conversation?thread_id=query-thread-0&page_size={size}")
        assert len(conversation["messages"]) == size
        feed = get(owner, conversation["older_url"]).get_json()
        assert feed["message_count"] == size
    for client, path, expected in (
        (owner, "/", "threads"),
        (owner, "/conversation?thread_id=query-thread-0", "messages"),
        (participant, "/", "messages"),
    ):
        context, _ = page(app, client, path)
        assert context["page_size"] == 25
        assert len(context[expected]) == (25 if expected == "messages" else 6)


def test_feed_and_participant_out_of_range_sizes_are_rejected_before_page_sql(query_pages):
    app, owner, participant = query_pages
    initial, _ = page(app, owner, "/conversation?thread_id=query-thread-0&page_size=2")
    feed_urls = [initial["older_url"].replace("page_size=2", f"page_size={size}")
                 for size in ("0", "101", "999999999999999999999999999999999999")]
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.lower().split()))

    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        feed_responses = [get(owner, feed_url) for feed_url in feed_urls]
        participant_responses = [get(participant, f"/?page_size={size}") for size in ("0", "101")]
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert all(response.status_code == 400 for response in feed_responses + participant_responses)
    assert not any(" from messages" in sql or " from threads" in sql for sql in statements)


def test_history_remains_unbounded_across_bounded_pages(query_pages):
    app, owner, _ = query_pages
    current, _ = page(app, owner, "/conversation?thread_id=query-thread-0&page_size=100")
    sequences = [message["sequence"] for message in current["messages"]]
    while current["older_page_url"]:
        current, _ = page(app, owner, current["older_page_url"])
        sequences.extend(message["sequence"] for message in current["messages"])
    assert len(sequences) == 205
    assert sorted(sequences) == list(range(1, 206))


def test_first_thread_page_does_not_issue_reverse_existence_probe(query_pages):
    app, owner, _ = query_pages
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if "from threads" in statement.lower():
            statements.append(" ".join(statement.lower().split()))

    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        first, _ = page(app, owner, "/?page_size=2")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert len(first["threads"]) == 2
    # The first page has no newer boundary. Fetching size+1 rows is sufficient
    # to detect its older page, so an extra reverse-boundary probe is wasteful.
    reverse_probes = [sql for sql in statements if "select threads.id from threads" in sql]
    assert reverse_probes == [], statements


def test_thread_list_newer_cursor_returns_nearest_preceding_page(query_pages):
    app, owner, _ = query_pages
    first, _ = page(app, owner, "/?page_size=2")
    second, _ = page(app, owner, first["pagination"]["older_url"])
    third, _ = page(app, owner, second["pagination"]["older_url"])
    returned, _ = page(app, owner, third["pagination"]["newer_url"])
    assert [t["thread_id"] for t in returned["threads"]] == [t["thread_id"] for t in second["threads"]]


def has_message_sql(app, thread_id, direction, anchor):
    from bridge.owner_web import _has_messages
    statements = []
    engine = app.extensions["engine"]
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append((statement, parameters))
    with app.test_request_context():
        g.db = app.extensions["sessions"]()
        event.listen(engine, "before_cursor_execute", capture)
        try:
            assert _has_messages(thread_id, direction, anchor)
        finally:
            event.remove(engine, "before_cursor_execute", capture)
            g.db.close()
    assert len(statements) == 1
    return statements[0]


def test_has_messages_range_uses_thread_sequence_index_sqlite(query_pages):
    app, _, _ = query_pages
    engine = app.extensions["engine"]
    if engine.dialect.name != "sqlite":
        pytest.skip("SQLite query plan assertion")
    sql, parameters = has_message_sql(app, "query-thread-0", "older", 205)
    with engine.connect() as connection:
        plan = connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, parameters).all()
    details = " ".join(row[-1].lower() for row in plan)
    assert "search messages" in details and ("thread_id=? and sequence<?" in details or "autoindex" in details), details
    assert "scan messages" not in details, details


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="Requires disposable PostgreSQL test database")
def test_has_messages_dominant_thread_uses_index_with_normal_postgres_planner(bridge_app):
    engine = bridge_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires native PostgreSQL")
    thread_id = "owner-query-plan-dominant-thread"
    with engine.begin() as connection:
        connection.execute(Thread.__table__.insert().values(id=thread_id, created_at=1, sequence=0))
        connection.execute(Message.__table__.insert(), [{
            "id": f"owner-query-plan-{i:05d}", "thread_id": thread_id,
            "sender_id": "agent-a", "recipient_id": "agent-b", "text": "Synthetic plan row",
            "status": "completed", "needs_reply": False, "sequence": i,
            "fingerprint": f"owner-query-plan-{i}", "created_at": 1700000000 + i,
        } for i in range(1, 24001)])
        connection.exec_driver_sql("ANALYZE messages")
    sql, parameters = has_message_sql(bridge_app, thread_id, "older", 24000)
    with engine.connect() as connection:
        plan = connection.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, parameters).scalar_one()
    if isinstance(plan, str):
        import json
        plan = json.loads(plan)
    root = plan[0]["Plan"]

    def walk(node):
        yield node
        for child in node.get("Plans", []):
            yield from walk(child)

    nodes = list(walk(root))
    assert not any(node["Node Type"] == "Seq Scan" and node.get("Relation Name") == "messages"
                   for node in nodes), root
    scans = [node for node in nodes if node["Node Type"] in ("Index Scan", "Index Only Scan")
             and node.get("Relation Name") == "messages"]
    assert scans, root
    assert any("thread_id" in node.get("Index Cond", "") and "sequence" in node.get("Index Cond", "")
               for node in scans), root

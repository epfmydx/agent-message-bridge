"""Synthetic owner thread paging and immutable, sequence-ordered reads."""
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import pytest
from flask import template_rendered
from sqlalchemy import event, text

from bridge.auth import digest
from bridge.models import Artifact, Member, Message, MessageArtifact, Thread
from bridge.models_auth import BrowserOwner, User

BASE = "https://bridge.example.com"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


def get(client, path):
    return client.get(path, base_url=BASE, headers=HEADERS)


def sign_in(app, client, ident="owner-a", kind="owner"):
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


def page(app, client, path="/"):
    with rendered(app) as contexts:
        response = get(client, path)
    assert response.status_code == 200, response.text
    return contexts[-1], response


def changed(url, **values):
    parsed = urlsplit(url)
    args = parse_qs(parsed.query)
    args.update({key: [value] for key, value in values.items()})
    return parsed.path + "?" + urlencode(args, doseq=True)


def add_message(db, thread_id, sequence, created_at=None, text_value=None):
    db.add(Message(id=f"{thread_id}-message-{sequence}", thread_id=thread_id,
        sender_id="agent-a", recipient_id="agent-b", sequence=sequence,
        text=f"Synthetic {thread_id} {sequence}" if text_value is None else text_value,
        status="completed", needs_reply=False, fingerprint=f"synthetic-{thread_id}-{sequence}",
        created_at=1704067200 + sequence if created_at is None else created_at))


@pytest.fixture
def owner_conversations(bridge_app):
    app = bridge_app
    with app.extensions["sessions"].begin() as db:
        db.add_all([BrowserOwner(id=ident, name=ident, email=ident+"@example.com",
            password_hash="synthetic-owner-password-hash", active=True) for ident in ("owner-a", "owner-b")])
        db.add_all([Thread(id=ident, created_at=date, sequence=0) for ident, date in
            (("alpha", 10), ("beta", 20), ("gamma", 30), ("empty-a", 60), ("empty-b", 60), ("empty-old", 40))])
        db.flush()
        db.add_all([Member(thread_id=ident, participant_id=p) for ident in ("alpha", "beta", "gamma")
            for p in ("agent-a", "agent-b")])
        for seq in range(1, 9):
            # Equal/nonmonotonic dates prove the conversation follows sequence.
            add_message(db, "alpha", seq, 1704067200 + (seq % 2))
        add_message(db, "beta", 1, 1704067200)
        add_message(db, "beta", 2, 1704067201)
        add_message(db, "gamma", 1, 1704067200)
    client = app.test_client()
    sign_in(app, client)
    return app, client


def test_threads_last_sequence_date_ties_empty_group_and_stable_boundaries(owner_conversations):
    app, client = owner_conversations
    first, _ = page(app, client, "/?page_size=2")
    assert [t["thread_id"] for t in first["threads"]] == ["beta", "gamma"]
    assert first["threads"][0]["last_message"]["sequence"] == 2
    assert first["threads"][0]["first_message_text"] == "Synthetic beta 1"
    assert first["threads"][0]["participant_names"] == ["Agent A", "Agent B"]
    second, _ = page(app, client, first["pagination"]["older_url"])
    assert [t["thread_id"] for t in second["threads"]] == ["alpha", "empty-b"]
    assert second["threads"][0]["last_message"]["sequence"] == 8
    assert second["threads"][1]["last_message"] is None
    third, _ = page(app, client, second["pagination"]["older_url"])
    assert [t["thread_id"] for t in third["threads"]] == ["empty-a", "empty-old"]
    assert third["pagination"]["older_url"] is None
    repeated, _ = page(app, client, first["pagination"]["older_url"])
    assert repeated["threads"] == second["threads"]
    returned, _ = page(app, client, second["pagination"]["newer_url"])
    assert returned["threads"] == first["threads"]


def test_conversation_sequence_older_and_incremental_newer(owner_conversations):
    app, client = owner_conversations
    initial, response = page(app, client, "/conversation?thread_id=alpha&page_size=3")
    assert [m["sequence"] for m in initial["messages"]] == [6, 7, 8]
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    first_url = initial["older_url"]
    older = get(client, first_url).get_json()
    assert older["message_count"] == 3 and older["has_more"]
    assert get(client, first_url).get_json() == older
    with rendered(app) as contexts:
        get(client, first_url)
    assert [m["sequence"] for m in contexts[-1]["messages"]] == [3, 4, 5]
    last = get(client, older["older_url"]).get_json()
    assert last["message_count"] == 2 and not last["has_more"] and last["older_url"] is None
    empty = get(client, initial["newer_url"]).get_json()
    assert empty["message_count"] == 0 and not empty["has_more"]
    assert empty["newer_url"] == initial["newer_url"]
    with app.extensions["sessions"].begin() as db:
        for seq in range(9, 16):
            add_message(db, "alpha", seq)
    counts = []
    next_url = empty["newer_url"]
    seen = []
    for expected in ([9, 10, 11], [12, 13, 14], [15]):
        with rendered(app) as contexts:
            result = get(client, next_url).get_json()
        seqs = [m["sequence"] for m in contexts[-1]["messages"]]
        assert seqs == expected
        seen.extend(seqs)
        counts.append(result["message_count"])
        assert result["has_more"] == (expected[-1] < 15)
        next_url = result["newer_url"]
    assert counts == [3, 3, 1] and len(set(seen)) == 7
    assert get(client, next_url).get_json()["message_count"] == 0


def test_html_history_pages_traverse_nearest_boundaries_and_new_arrivals(owner_conversations):
    app, client = owner_conversations
    newest, _ = page(app, client, "/conversation?thread_id=alpha&page_size=3")
    assert not newest["history_page"] and newest["newer_page_url"] is None
    assert [m["sequence"] for m in newest["messages"]] == [6, 7, 8]
    assert urlsplit(newest["older_page_url"]).path == "/conversation"
    middle, _ = page(app, client, newest["older_page_url"])
    assert middle["history_page"] and [m["sequence"] for m in middle["messages"]] == [3, 4, 5]
    oldest, _ = page(app, client, middle["older_page_url"])
    assert oldest["older_page_url"] is None and oldest["older_url"] is None
    assert [m["sequence"] for m in oldest["messages"]] == [1, 2]
    repeated, _ = page(app, client, newest["older_page_url"])
    assert repeated["messages"] == middle["messages"]
    returned, _ = page(app, client, oldest["newer_page_url"])
    assert returned["messages"] == middle["messages"]
    with app.extensions["sessions"].begin() as db:
        add_message(db, "alpha", 9)
        add_message(db, "alpha", 10)
    returned, _ = page(app, client, middle["newer_page_url"])
    assert returned["messages"] == newest["messages"]
    assert returned["history_page"]
    latest, _ = page(app, client, returned["newer_page_url"])
    assert [m["sequence"] for m in latest["messages"]] == [9, 10]
    assert latest["newer_page_url"] is None
    # A feed boundary can also open an HTML page with identical semantics.
    feed_as_html = newest["older_url"].replace("/conversation/messages?", "/conversation?")
    assert page(app, client, feed_as_html)[0]["messages"] == middle["messages"]


def test_html_history_cursors_preserve_owner_thread_size_and_purpose(owner_conversations):
    app, client = owner_conversations
    initial, _ = page(app, client, "/conversation?thread_id=alpha&page_size=2")
    url = initial["older_page_url"]
    assert get(client, url+"x").status_code == 400
    assert get(client, changed(url, page_size=3)).status_code == 400
    assert get(client, changed(url, thread_id="beta")).status_code == 400
    assert get(client, url+"&cursor=duplicate").status_code == 400
    listing, _ = page(app, client, "/?page_size=2")
    list_cursor = parse_qs(urlsplit(listing["pagination"]["older_url"]).query)["cursor"][0]
    assert get(client, changed(url, cursor=list_cursor)).status_code == 400
    other = app.test_client()
    sign_in(app, other, "owner-b")
    assert get(other, url).status_code == 400
    agent = app.test_client()
    sign_in(app, agent, "agent-b", "participant")
    assert get(agent, url).status_code == 404


@pytest.mark.parametrize("field,value", [("anchor", True), ("anchor", 1.0), ("anchor", "1"),
    ("anchor", -1), ("anchor", 2**63), ("anchor", [1]), ("anchor", None),
    ("direction", "sideways"), ("page_size", True), ("page_size", 1.0),
    ("purpose", "inbox"), ("thread_id", None)])
def test_html_history_rejects_invalid_signed_payload_types(owner_conversations, field, value):
    from bridge.owner_web import _signer
    app, client = owner_conversations
    initial, _ = page(app, client, "/conversation?thread_id=alpha&page_size=1")
    url = initial["older_page_url"]
    token = parse_qs(urlsplit(url).query)["cursor"][0]
    with app.app_context():
        payload = _signer().loads(token)
        payload[field] = value
        invalid = _signer().dumps(payload)
    assert get(client, changed(url, cursor=invalid)).status_code == 400


def test_empty_thread_poll_and_exact_opaque_query_identity(owner_conversations):
    app, client = owner_conversations
    opaque = "/../thread?x=1&slash=/ percent=%#fragment ü"
    with app.extensions["sessions"].begin() as db:
        db.add(Thread(id=opaque, created_at=70))
    threads, _ = page(app, client)
    href = next(t["url"] for t in threads["threads"] if t["thread_id"] == opaque)
    normalized = urljoin(BASE+"/some/path", href)
    assert urlsplit(normalized).path == "/conversation" and not urlsplit(normalized).fragment
    initial, _ = page(app, client, normalized)
    assert initial["thread"]["thread_id"] == opaque and initial["messages"] == []
    assert initial["older_url"] is None
    poll = get(client, initial["newer_url"]).get_json()
    assert poll["message_count"] == 0 and poll["newer_url"] == initial["newer_url"]
    with app.extensions["sessions"].begin() as db:
        add_message(db, opaque, 1)
    assert get(client, poll["newer_url"]).get_json()["message_count"] == 1


def test_cursor_binding_identity_thread_size_purpose_and_tampering(owner_conversations):
    app, client = owner_conversations
    listing, _ = page(app, client, "/?page_size=2")
    detail, _ = page(app, client, "/conversation?thread_id=alpha&page_size=2")
    feed = detail["older_url"]
    assert get(client, feed+"x").status_code == 400
    assert get(client, changed(feed, page_size=3)).status_code == 400
    assert get(client, changed(feed, thread_id="beta")).status_code == 400
    list_cursor = parse_qs(urlsplit(listing["pagination"]["older_url"]).query)["cursor"][0]
    feed_cursor = parse_qs(urlsplit(feed).query)["cursor"][0]
    assert get(client, changed(feed, cursor=list_cursor)).status_code == 400
    assert get(client, changed(listing["pagination"]["older_url"], cursor=feed_cursor)).status_code == 400
    other = app.test_client()
    sign_in(app, other, "owner-b")
    assert get(other, feed).status_code == 400
    assert get(other, listing["pagination"]["older_url"]).status_code == 400
    agent = app.test_client()
    sign_in(app, agent, "agent-b", "participant")
    assert get(agent, feed).status_code == 404
    assert get(agent, "/conversation?thread_id=alpha").status_code == 404
    assert get(agent, listing["pagination"]["older_url"]).status_code == 400


@pytest.mark.parametrize("path", ["/conversation", "/conversation?thread_id=", "/conversation?thread_id=a&thread_id=b",
    "/conversation?thread_id=alpha&cursor=x", "/conversation?thread_id=alpha&extra=x",
    "/conversation?thread_id=alpha&page_size=0", "/conversation?thread_id=alpha&page_size=-1",
    "/conversation?thread_id=alpha&page_size=x", "/conversation?thread_id=alpha&page_size=1&page_size=2",
    "/conversation/messages?thread_id=alpha", "/conversation/messages?thread_id=alpha&cursor=x&cursor=y",
    "/?page_size=0", "/?page_size=2&page_size=3", "/?extra=x"])
def test_invalid_parameters(owner_conversations, path):
    _, client = owner_conversations
    assert get(client, path).status_code == 400


def test_defaults_bounded_page_size_missing_thread_and_expired_session(owner_conversations):
    app, client = owner_conversations
    initial, _ = page(app, client, "/conversation?thread_id=alpha")
    assert initial["page_size"] == 25 and len(initial["messages"]) == 8
    assert get(client, "/conversation?thread_id=alpha&page_size="+str(2**80)).status_code == 400
    assert get(client, "/conversation?thread_id=absent").status_code == 404
    anon = app.test_client()
    assert get(anon, "/conversation?thread_id=alpha").location == "/login"
    response = get(anon, initial["newer_url"])
    assert response.status_code == 401 and response.get_json()["login_url"] == "/login"
    with app.extensions["sessions"].begin() as db:
        db.get(BrowserOwner, "owner-a").password_hash = "synthetic-rotated-hash"
    assert get(client, "/conversation?thread_id=alpha").location == "/login"
    assert get(client, initial["newer_url"]).status_code == 401


def test_bulk_page_attachments_autoescape_and_no_database_mutations(owner_conversations):
    app, client = owner_conversations
    with app.extensions["sessions"].begin() as db:
        for seq in (6, 7, 8):
            db.get(Message, f"alpha-message-{seq}").text = '<script>alert("synthetic")</script>'
            db.add(Artifact(id=f"synthetic-file-{seq}", owner_id="intruder", idempotency_key=str(seq),
                object_key=f"synthetic/{seq}", filename='<img src=x>.txt', content_type="text/plain",
                size_bytes=2, sha256="0"*64, state="ready"))
        db.flush()
        db.add_all([MessageArtifact(message_id=f"alpha-message-{seq}", artifact_id=f"synthetic-file-{seq}")
                    for seq in (6, 7, 8)])
    engine = app.extensions["engine"]
    def snapshot():
        with engine.connect() as connection:
            return {table: connection.execute(text('SELECT * FROM "'+table+'" ORDER BY 1')).all()
                    for table in ("threads", "thread_members", "messages", "artifacts", "message_artifacts", "deliveries", "work_claims")}
    before = snapshot()
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        initial, response = page(app, client, "/conversation?thread_id=alpha&page_size=3")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert sum("message_artifacts" in s for s in statements) == 1
    assert all(not s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for s in statements)
    assert "<script>alert" not in response.text and "&lt;script&gt;" in response.text
    assert "<img src=x>" not in response.text and "&lt;img src=x&gt;" in response.text
    for message in initial["messages"]:
        assert message["attachments"][0]["download_url"].startswith("/files/")
    listing, _ = page(app, client)
    get(client, initial["older_url"])
    get(client, initial["newer_url"])
    assert snapshot() == before
    assert all(t["thread_id"] for t in listing["threads"])


def test_thread_list_bulk_loads_page_metadata_with_indexed_sequence_lookups(owner_conversations):
    app, client = owner_conversations
    with app.extensions["sessions"].begin() as db:
        # Many history rows and participants must not produce one attachment or
        # membership query per thread or enumerate each thread's whole history.
        for index in range(12):
            ident = f"bulk-{index}"
            db.add(Thread(id=ident, created_at=1, sequence=0))
            db.flush()
            db.add(Member(thread_id=ident, participant_id="agent-a"))
            for sequence in range(1, 21):
                add_message(db, ident, sequence)
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        listing, _ = page(app, client, "/?page_size=12")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert len(listing["threads"]) == 12
    assert all(t["last_message"]["sequence"] == 20 for t in listing["threads"])
    assert all(t["first_message_text"].endswith(" 1") for t in listing["threads"])
    assert sum("message_artifacts" in statement for statement in statements) == 1
    assert sum("thread_members" in statement for statement in statements) == 1
    assert len(statements) <= 9
    assert "ORDER BY messages.sequence DESC" in statements[1]

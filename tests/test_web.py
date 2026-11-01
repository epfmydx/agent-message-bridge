"""Synthetic signed-in browser access, ordering and pagination."""
from contextlib import contextmanager
from html.parser import HTMLParser
import json
import shutil
import subprocess
from urllib.parse import parse_qs, urljoin, urlsplit

import pytest
from flask import template_rendered
from sqlalchemy import event

from bridge.auth import digest
from bridge.models import Artifact, Member, Message, MessageArtifact, Thread
from bridge.models_auth import User

BASE = "https://bridge.example.com"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


def get(client, path):
    return client.get(path, headers=HEADERS, base_url=BASE)


def sign_in(app, client, owner="agent-b"):
    with app.extensions["sessions"]() as db:
        credential = digest(db.get(User, owner).password_hash)
    with client.session_transaction(base_url=BASE) as session:
        session.update(owner=owner, credential=credential)


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


@pytest.fixture
def browser(bridge_app):
    with bridge_app.extensions["sessions"].begin() as db:
        db.add_all([Thread(id="shared"), Thread(id="private")])
        db.flush()
        db.add_all([Member(thread_id="shared", participant_id=p) for p in ("agent-b", "agent-a")])
        db.add_all([Member(thread_id="private", participant_id=p) for p in ("intruder", "agent-a")])
        for i in range(8):
            db.add(Message(id=f"message-{i}", thread_id="shared", sender_id="agent-b" if i % 2 else "agent-a",
                recipient_id="agent-a" if i % 2 else "agent-b", text=f"Synthetic message {i}",
                status="completed", needs_reply=False, sequence=i+1, fingerprint=f"synthetic-{i}",
                created_at=1704067200+i//2))
        db.add(Message(id="private-message", thread_id="private", sender_id="intruder", recipient_id="agent-a",
            text="Private synthetic content", status="received", needs_reply=True, sequence=1,
            fingerprint="private", created_at=1900000000))
    client = bridge_app.test_client()
    sign_in(bridge_app, client)
    return bridge_app, client


def page(app, client, path):
    with rendered(app) as contexts:
        response = get(client, path)
    assert response.status_code == 200, response.get_data(as_text=True)
    return contexts[-1]


def ids(context):
    return [m["message_id"] for m in context["messages"]]


def test_login_default_and_anonymous_routes(bridge_app):
    client = bridge_app.test_client()
    for path in ("/", "/message?message_id=unknown", "/files/unknown/download"):
        assert urlsplit(get(client, path).location).path == "/login"
    assert get(client, "/login").status_code == 200
    with client.session_transaction(base_url=BASE) as session:
        csrf = session["csrf"]
    response = client.post("/login", data={"csrf": csrf, "email": "agent-b@example.com",
        "password": "synthetic-password-agent-b"}, headers=HEADERS, base_url=BASE)
    assert response.status_code == 302 and response.location == "/"
    context = page(bridge_app, client, "/")
    assert context["account"] == {"id": "agent-b", "name": "Agent B", "email": "agent-b@example.com"}
    assert context["page_size"] == 25 and context["messages"] == []


def test_date_order_ties_keyset_next_previous_with_new_arrival(browser):
    app, client = browser
    first = page(app, client, "/?page_size=3")
    assert ids(first) == ["message-7", "message-6", "message-5"]
    assert first["pagination"]["newer_url"] is None
    assert all(message["created_at"].startswith("01 Jan 2024, 00:00:0")
               and message["created_at"].endswith(" UTC") for message in first["messages"])
    second = page(app, client, first["pagination"]["older_url"])
    assert ids(second) == ["message-4", "message-3", "message-2"]
    with app.extensions["sessions"].begin() as db:
        db.add(Message(id="new-arrival", thread_id="shared", sender_id="agent-a", recipient_id="agent-b",
            text="New arrival", status="received", needs_reply=True, sequence=9, fingerprint="new", created_at=1800000000))
    returned = page(app, client, second["pagination"]["newer_url"])
    assert ids(returned) == ids(first)
    assert returned["pagination"]["newer_url"]
    assert ids(page(app, client, returned["pagination"]["newer_url"])) == ["new-arrival"]
    last = page(app, client, second["pagination"]["older_url"])
    assert ids(last) == ["message-1", "message-0"]
    assert last["pagination"]["older_url"] is None
    assert not set(ids(second)) & set(ids(first))
    assert set(m["sender"] for m in first["messages"]) == {"agent-b", "agent-a"}


def test_thread_scope_detail_and_cursor_tampering(browser):
    app, client = browser
    context = page(app, client, "/?page_size=2")
    assert "private-message" not in ids(context)
    assert get(client, "/message?message_id=private-message").status_code == 404
    assert get(client, "/message?message_id=missing").status_code == 404
    detail = page(app, client, "/message?message_id=message-2")["message"]
    assert detail["thread_id"] == "shared" and detail["sender_name"] == "Agent A"
    link = context["pagination"]["older_url"]
    assert "Synthetic" not in link and "agent-b" not in link
    assert get(client, link+"x").status_code == 400
    other = app.test_client()
    sign_in(app, other, "intruder")
    assert get(other, link).status_code == 400
    assert get(other, "/message?message_id=message-2").status_code == 404
    assert get(client, link.replace("page_size=2", "page_size=3")).status_code == 400
    for value in ("0", "-1", "oops"):
        assert get(client, "/?page_size="+value).status_code == 400
    assert get(client, "/?cursor=invalid").status_code == 400
    assert get(client, "/?page_size=2&page_size=3").status_code == 400
    assert get(client, "/?page_size=100000000000000000000").status_code == 400


@pytest.fixture
def opaque_browser(browser):
    app, client = browser
    identifiers = ["plain/slash", "/leading", "a/../target", "../target", "/../target",
                   "reserved?query#fragment/%25/%2F", "dot/%2e%2e/target", "%?#/", "//other.example.com/path"]
    with app.extensions["sessions"].begin() as db:
        for i, ident in enumerate(identifiers):
            db.add(Message(id=ident, thread_id="shared", sender_id="agent-a", recipient_id="agent-b",
                text=f"Exact opaque message {i}", status="completed", needs_reply=False,
                sequence=20+i, fingerprint=f"opaque-{i}", created_at=1800000000+i))
    class Links(HTMLParser):
        def __init__(self, source):
            super().__init__()
            self.links = []
            self.feed(source)
        def handle_starttag(self, tag, attrs):
            href = dict(attrs).get("href")
            if tag == "a" and href and urlsplit(href).path == "/message":
                self.links.append(href)
    links = Links(get(client, "/").get_data(as_text=True)).links
    selected = {}
    for ident in identifiers:
        matches = [href for href in links if parse_qs(urlsplit(href).query) == {"message_id": [ident]}]
        assert len(matches) == 1
        selected[ident] = matches[0]
    return app, client, selected


def test_opaque_message_ids_use_exact_template_generated_query_links(opaque_browser):
    app, client, links = opaque_browser
    for ident, href in links.items():
        # Normal relative URL resolution keeps opaque IDs entirely out of the
        # path; slashes, dot segments, percent signs and fragments remain data.
        resolved = urljoin(BASE+"/some/browser/path", href)
        assert urlsplit(resolved).path == "/message"
        assert not urlsplit(resolved).fragment
        message = page(app, client, resolved)["message"]
        assert message["message_id"] == ident
        assert message["text"] == f"Exact opaque message {list(links).index(ident)}"
    for path in ("/message", "/message?message_id=", "/message?message_id=a&message_id=b",
                 "/message?message_id=a&extra=b"):
        assert get(client, path).status_code == 400
    assert get(client, "/messages/message-2").status_code == 404


@pytest.mark.skipif(not shutil.which("node"), reason="Node WHATWG URL parser is unavailable")
def test_opaque_message_links_survive_browser_standard_url_normalization(opaque_browser):
    app, client, links = opaque_browser
    # Node implements the browser-standard WHATWG URL parser. This explicitly
    # demonstrates the old path failure, then normalizes actual template links.
    script = """
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const oldPath = new URL('/messages/a/../target', input.base).pathname;
const links = input.links.map(link => new URL(link, input.base).href);
process.stdout.write(JSON.stringify({oldPath, links}));
"""
    result = subprocess.run([shutil.which("node"), "-e", script],
        input=json.dumps({"base": BASE, "links": list(links.values())}),
        text=True, capture_output=True, check=True)
    normalized = json.loads(result.stdout)
    assert normalized["oldPath"] == "/messages/target"
    for ident, href in zip(links, normalized["links"]):
        assert page(app, client, href)["message"]["message_id"] == ident


def test_escaped_text_and_bulk_attachments_and_download_scope(browser):
    app, client = browser
    with app.extensions["sessions"].begin() as db:
        db.get(Message, "message-7").text = '<script>alert("synthetic")</script> **plain text**'
        for i in range(8):
            db.add(Artifact(id=f"file-{i}", owner_id="agent-a", idempotency_key=f"file-{i}",
                object_key=f"synthetic/{i}", filename='<img src=x onerror=alert(1)>.txt',
                content_type="text/plain", size_bytes=10, sha256="0"*64, state="ready"))
        db.flush()
        db.add_all([MessageArtifact(message_id=f"message-{i}", artifact_id=f"file-{i}") for i in range(8)])
    queries = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        if "message_artifacts" in statement:
            queries.append(statement)
    event.listen(app.extensions["engine"], "before_cursor_execute", capture)
    try:
        response = get(client, "/")
    finally:
        event.remove(app.extensions["engine"], "before_cursor_execute", capture)
    assert response.status_code == 200 and len(queries) == 1
    for response in (response, get(client, "/message?message_id=message-7")):
        body = response.get_data(as_text=True)
        assert "<script>alert" not in body and "<img src=x" not in body
        assert "&lt;script&gt;" in body and "**plain text**" in body
    class Store:
        def presign_get(self, key, filename, content_type, expires):
            return "https://download.example.com/temporary-synthetic"
    app.extensions["object_store"] = Store()
    assert get(client, "/files/file-7/download").location == "https://download.example.com/temporary-synthetic"
    outsider = app.test_client()
    sign_in(app, outsider, "intruder")
    assert get(outsider, "/files/file-7/download").status_code == 404
    assert get(outsider, "/files/missing/download").status_code == 404


def test_disabled_account_and_password_rotation_remove_browser_access(browser):
    app, client = browser
    with app.extensions["sessions"].begin() as db:
        db.get(User, "agent-b").password_hash = "synthetic-rotated-password-hash"
    assert get(client, "/").location == "/login"
    assert get(client, "/message?message_id=message-1").location == "/login"
    assert get(client, "/files/file-1/download").location == "/login"

"""Neutral asset packaging and browser-template behavior."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[1]
PACKAGED_ASSETS = {"mark.svg", "logo.svg", "favicon.svg", "tokens.css"}
ACCOUNT = {"id": "agent-b", "name": "Agent B", "email": "agent-b@example.com"}
MESSAGE = {
    "message_id": "message-1", "thread_id": "thread-1", "sender": "agent_a",
    "sender_name": "Agent A", "recipient": "agent_b", "recipient_name": "Agent B",
    "reply_to": "message-0", "text": "A synthetic message.\nSecond line.",
    "status": "needs_input", "needs_reply": True, "created_at": "31 Oct 2026, 02:15 UTC",
    "attachments": [{"id": "file-1", "filename": "summary.txt", "size_bytes": 1024,
                     "content_type": "text/plain"}],
}


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.elements = []
        self.text = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)

    def find(self, tag, **attrs):
        return [item for name, item in self.elements if name == tag
                and all(item.get(key.replace("_", "-")) == value for key, value in attrs.items())]


@pytest.fixture
def template_app():
    app = Flask(__name__, template_folder=str(ROOT / "bridge/templates"),
                static_folder=str(ROOT / "bridge/static"), static_url_path="/static")
    for endpoint, path in {
        "inbox": "/", "login": "/login", "logout": "/logout",
        "connections": "/oauth/connections", "authorize": "/oauth/authorize",
        "browser_message": "/message",
        "browser_file": "/files/<artifact_id>/download",
    }.items():
        app.add_url_rule(path, endpoint, lambda **kwargs: "", methods=["GET", "POST"])
    app.config["TESTING"] = True
    return app


def page(app, template, **context):
    with app.test_request_context("/"):
        return render_template(template, account=ACCOUNT, csrf_token="synthetic-csrf", **context)


def test_neutral_assets_are_local_valid_and_structured():
    assets = ROOT / "bridge/static/brand"
    assert {path.name for path in assets.iterdir()} == PACKAGED_ASSETS
    for filename in ("logo.svg", "mark.svg", "favicon.svg"):
        source = (assets / filename).read_text()
        document = Document(source)
        assert document.find("svg") and document.find("title")
        assert not document.find("script")
        assert "https://" not in source
        assert source.replace('xmlns="http://www.w3.org/2000/svg"', "").find("http://") == -1
    tokens = (assets / "tokens.css").read_text()
    assert "--bridge-ink" in tokens and "--bridge-paper" in tokens
    assert "epf" not in tokens.lower() and "digitalx" not in tokens.lower()


@pytest.mark.parametrize(("template", "context"), [
    ("login.html", {"error": None}), ("connections.html", {"rows": []}),
    ("oauth-consent.html", {"client_name": "Test client", "callback": "https://client.example.com/cb",
                            "oauth_fields": {"client_id": "synthetic-client"}}),
    ("messages.html", {"messages": [MESSAGE], "pagination": {"older_url": None, "newer_url": None}, "page_size": 25}),
    ("message.html", {"message": MESSAGE}),
])
def test_pages_load_only_packaged_assets(template_app, template, context):
    document = Document(page(template_app, template, **context))
    assets = [item["href"] for item in document.find("link")] + [item["src"] for item in document.find("img")]
    assert assets
    client = template_app.test_client()
    for asset in assets:
        assert not urlsplit(asset).netloc
        assert asset.startswith("/static/")
        assert client.get(asset).status_code == 200
    assert document.find("main", id="main")
    assert document.find("a", href="#main")
    assert not document.find("script")
    assert "Agent Message Bridge" in "".join(document.text)
    for source in (ROOT / "bridge/static").rglob("*.css"):
        text = source.read_text()
        assert "@import" not in text and "@font-face" not in text and "url(" not in text


def test_login_preserves_email_and_associates_error_without_password(template_app):
    email = 'person+<test>@example.com'
    html = page(template_app, "login.html", email=email, error='Incorrect <script>alert(1)</script>')
    document = Document(html)
    assert not document.find("script")
    assert document.find("input", name="email")[0]["value"] == email
    assert "value" not in document.find("input", name="password")[0]
    assert document.find("label", **{"for": "email"}) and document.find("label", **{"for": "password"})
    for name in ("email", "password"):
        field = document.find("input", name=name)[0]
        assert field["aria-describedby"] == "login-error" and field["aria-invalid"] == "true"
    assert document.find("p", id="login-error", role="alert")
    assert document.find("form", method="post", action="/login")
    assert document.find("input", name="csrf", value="synthetic-csrf")


def test_consent_preserves_full_escaped_security_context_and_fields(template_app):
    name = 'Client <img src=x onerror=alert(1)> ' + "long-name" * 70
    callback = 'https://client.example.com/' + "long-path/" * 70 + '?x=<script>&y="value"'
    fields = {"client_id": 'client"<x>', "redirect_uri": callback, "state": 'a&b"<c>'}
    document = Document(page(template_app, "oauth-consent.html", client_name=name,
                             callback=callback, oauth_fields=fields))
    text = "".join(document.text)
    assert name in text and callback in text
    assert not document.find("script") and len(document.find("img")) == 2
    for key, value in fields.items():
        assert document.find("input", name=key, value=value)
    assert document.find("form", action="/oauth/authorize", method="post")
    assert document.find("button", name="approve", value="yes")
    assert document.find("button", name="approve", value="no")


def test_connection_identity_is_escaped_and_disconnect_keeps_csrf(template_app):
    name = 'Client <svg onload="alert(1)">'
    document = Document(page(template_app, "connections.html", rows=[({"id": "family-1"}, {"name": name})]))
    assert name in "".join(document.text) and not document.find("svg")
    assert document.find("button", aria_label="Disconnect " + name)
    assert document.find("input", name="family", value="family-1")
    assert document.find("form", action="/oauth/connections", method="post")
    assert len(document.find("input", name="csrf", value="synthetic-csrf")) == 2


def test_feed_previews_link_to_full_escaped_message_and_download(template_app):
    text = '<script>alert("private-body")</script>\n' + "full message content " * 80
    message = {**MESSAGE, "text": text, "sender_name": "<b>Sender</b>"}
    feed = Document(page(template_app, "messages.html", messages=[message],
                         pagination={"older_url": "/?before=cursor-2", "newer_url": "/?after=cursor-0"}, page_size=25))
    detail = Document(page(template_app, "message.html", message=message))
    assert not feed.find("script") and not detail.find("script") and not detail.find("b")
    assert text in "".join(detail.text)
    assert "…" in "".join(feed.text)
    assert feed.find("a", href="/message?message_id=message-1")
    assert feed.find("a", href="/?before=cursor-2") and feed.find("a", href="/?after=cursor-0")
    assert detail.find("a", href="/message?message_id=message-0")
    assert detail.find("a", href="/files/file-1/download")
    assert "Needs input" in "".join(detail.text)
    for document in (feed, detail):
        assert [form["action"] for form in document.find("form")] == ["/logout"]
        assert all("private-body" not in link.get("href", "") for link in document.find("a"))


def test_empty_feed_and_connections_have_clear_states(template_app):
    feed = page(template_app, "messages.html", messages=[],
                pagination={"older_url": None, "newer_url": None}, page_size=25)
    connections = page(template_app, "connections.html", rows=[])
    assert "No messages yet" in feed and 'aria-label="Message pages"' not in feed
    assert "No connected clients" in connections


@pytest.mark.parametrize("message_id", ["/leading/slash", "../dot/segment", "./message", "a?b#c&d=e", "space + 雪"])
def test_message_links_preserve_complete_identity_in_query(template_app, message_id):
    message = {**MESSAGE, "message_id": message_id, "reply_to": message_id}
    feed = Document(page(template_app, "messages.html", messages=[message],
                         pagination={"older_url": None, "newer_url": None}, page_size=25))
    detail = Document(page(template_app, "message.html", message=message))
    for document in (feed, detail):
        links = [urlsplit(link["href"]) for link in document.find("a")
                 if urlsplit(link["href"]).path == "/message"]
        assert len(links) == 1
        assert parse_qs(links[0].query) == {"message_id": [message_id]}
        assert not links[0].fragment

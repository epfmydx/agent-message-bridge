"""Cloudflare browser-origin requirements do not replace application authorization."""
import copy
import re

import pytest
from sqlalchemy import event

from bridge.cloudflare import TrustedSchemeProxy, proxy_networks
from bridge.config import validate_settings

BASE = "https://bridge.example.com"


def headers(app):
    return {"X-Bridge-Origin": app.config["CLOUDFLARE_ORIGIN_SECRET"], "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


@pytest.mark.parametrize("path,method", [("/", "get"), ("/login", "get"), ("/login", "post"), ("/logout", "post"),
    ("/oauth/authorize", "get"), ("/oauth/authorize", "post"), ("/oauth/connections", "get"), ("/oauth/connections", "post"),
    ("/message?message_id=synthetic-message", "get"), ("/files/synthetic-file/download", "get")])
def test_browser_guard_runs_before_database_and_session(bridge_app, path, method):
    queries = []
    def before(*args): queries.append(args[2])
    engine = bridge_app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", before)
    try: response = getattr(bridge_app.test_client(), method)(path, base_url=BASE)
    finally: event.remove(engine, "before_cursor_execute", before)
    assert response.status_code == 403 and response.json == {"error": "cloudflare_proxy_required"}
    assert queries == []
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize("header,value,status,error", [
    ("X-Bridge-Origin", "wrong", 403, "cloudflare_proxy_required"),
    ("X-Bridge-Origin", "one,two", 403, "cloudflare_proxy_required"),
    ("X-Forwarded-Proto", "http", 403, "cloudflare_https_required"),
    ("X-Forwarded-Proto", "https,https", 403, "cloudflare_https_required"),
    *[("CF-Connecting-IP", value, 400, "invalid_cloudflare_client_ip") for value in (
        "", "127.0.0.1", "10.0.0.1", "169.254.1.1", "::ffff:127.0.0.1", "64:ff9b::127.0.0.1", "2002:7f00:1::",
        "ff02::1", "fe80::1%en0", "8.8.8.8,1.1.1.1", "8.8.8.8:443", " 8.8.8.8", "2001:db8::1")],
])
def test_browser_rejects_invalid_origin_metadata(bridge_app, header, value, status, error):
    response = bridge_app.test_client().get("/login", base_url=BASE, headers={**headers(bridge_app), header: value})
    assert response.status_code == status and response.json == {"error": error}
    assert bridge_app.config["CLOUDFLARE_ORIGIN_SECRET"].encode() not in response.data


def test_untrusted_peer_and_missing_configuration_fail_closed(bridge_app):
    client = bridge_app.test_client()
    assert client.get("/login", base_url=BASE, headers=headers(bridge_app), environ_overrides={"REMOTE_ADDR": "8.8.4.4"}).status_code == 403
    valid = headers(bridge_app)
    for changes in ({"CLOUDFLARE_ORIGIN_SECRET": ""}, {"TRUSTED_PROXY_CIDRS": ()}):
        old = {k: bridge_app.config[k] for k in changes}
        bridge_app.config.update(changes)
        assert client.get("/login", base_url=BASE, headers=valid).status_code == 403
        bridge_app.config.update(old)


def test_origin_does_not_replace_password_or_csrf(bridge_app):
    client, origin = bridge_app.test_client(), headers(bridge_app)
    assert client.get("/", base_url=BASE, headers=origin).location == "/login"
    page = client.get("/login", base_url=BASE, headers=origin)
    csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
    assert client.post("/login", base_url=BASE, headers=origin, data={"email": "agent-b@example.com", "password": "synthetic-password-agent-b"}).status_code == 400
    login = client.post("/login", base_url=BASE, headers=origin, data={"csrf": csrf, "email": "agent-b@example.com", "password": "synthetic-password-agent-b"})
    assert login.status_code == 302 and login.location == "/"
    assert client.get("/", base_url=BASE).status_code == 403
    assert client.get("/", base_url=BASE, headers=origin).status_code == 200


@pytest.mark.parametrize("path,method,status", [("/healthz", "get", 200), ("/static/app.css", "get", 200),
    ("/static/brand/logo.svg", "get", 200), ("/.well-known/oauth-authorization-server", "get", 200),
    ("/.well-known/oauth-protected-resource/mcp", "get", 200), ("/mcp", "post", 401), ("/api/profile", "get", 401),
    ("/oauth/register", "post", 400), ("/oauth/token", "post", 400), ("/oauth/revoke", "post", 401)])
def test_machine_routes_and_public_assets_keep_existing_auth(bridge_app, path, method, status):
    response = getattr(bridge_app.test_client(), method)(path, base_url=BASE)
    assert response.status_code == status, response.data
    assert b"cloudflare_proxy_required" not in response.data


def test_only_trusted_socket_peer_can_supply_scheme():
    observed = []
    def app(environ, start): observed.append((environ["wsgi.url_scheme"], environ["REMOTE_ADDR"], environ.get("HTTP_HOST"))); return []
    proxy = TrustedSchemeProxy(app, ("10.20.0.5/32",))
    for address, scheme in (("10.20.0.5", "https"), ("8.8.4.4", "http")):
        proxy({"REMOTE_ADDR": address, "wsgi.url_scheme": "http", "HTTP_X_FORWARDED_PROTO": "https", "HTTP_X_FORWARDED_FOR": "10.20.0.5", "HTTP_HOST": "bridge.example.com"}, None)
        assert observed[-1] == (scheme, address, "bridge.example.com")


@pytest.mark.parametrize("value", ["*", "0.0.0.0/0", "::/0", "not-a-cidr", "127.0.0.1,", [""], 1])
def test_universal_or_invalid_proxy_trust_rejected(value):
    with pytest.raises((ValueError, TypeError)): proxy_networks(value)


def test_dedicated_origin_secret_and_credential_format(bridge_app):
    for value in ("short", "x"*257, bridge_app.config["ENCRYPTION_KEY"]):
        settings = dict(bridge_app.config)
        settings["CLOUDFLARE_ORIGIN_SECRET"] = value
        with pytest.raises(ValueError): validate_settings(settings)

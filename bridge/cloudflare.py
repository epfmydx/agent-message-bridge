"""Required origin verification for browser pages, independent of API authentication."""
import hmac
from ipaddress import ip_address, ip_network

from flask import jsonify, request

from .network import is_public_unicast

ORIGIN_HEADER = "X-Bridge-Origin"
BROWSER_ENDPOINTS = frozenset(("inbox", "browser_message", "browser_file", "login", "logout", "authorize", "connections",
                               "owner_conversation", "owner_conversation_messages", "profiles", "new_profile", "profile_notifications"))


def proxy_networks(value):
    if value is None or value == "" or value == [] or value == (): return ()
    parts = value.split(",") if isinstance(value, str) else value
    if not isinstance(parts, (list, tuple)) or any(not isinstance(p, str) or not p.strip() for p in parts):
        raise ValueError("TRUSTED_PROXY_CIDRS must contain explicit IP addresses or CIDRs")
    networks = tuple(ip_network(p.strip(), strict=False) for p in parts)
    if any(n.prefixlen == 0 for n in networks): raise ValueError("TRUSTED_PROXY_CIDRS must not trust every address")
    return tuple(str(n) for n in networks)


def single_ip(value):
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value: raise ValueError("Invalid address")
    address = ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def trusted_peer(value, networks):
    try:
        peer = single_ip(value)
        return any(peer in ip_network(n, strict=True) for n in networks)
    except (ValueError, TypeError): return False


def single_header(name):
    values = request.headers.getlist(name)
    if len(values) != 1 or any(c in values[0] for c in (",", "\r", "\n")): return ""
    return values[0]


class TrustedSchemeProxy:
    """Trust only scheme from verified socket peers; never replace REMOTE_ADDR/Host."""
    def __init__(self, application, networks):
        self.application, self.networks = application, networks

    def __call__(self, environ, start_response):
        if trusted_peer(environ.get("REMOTE_ADDR", ""), self.networks) and environ.get("HTTP_X_FORWARDED_PROTO") == "https":
            environ["wsgi.url_scheme"] = "https"
        return self.application(environ, start_response)


def install_admin_origin_guard(app):
    @app.before_request
    def verify_browser_origin():
        if request.endpoint not in BROWSER_ENDPOINTS and request.path != "/profiles" and not request.path.startswith("/profiles/"): return
        secret = app.config.get("CLOUDFLARE_ORIGIN_SECRET", "")
        supplied = single_header(ORIGIN_HEADER)
        if (not secret or not supplied or not trusted_peer(request.environ.get("REMOTE_ADDR", ""), app.config.get("TRUSTED_PROXY_CIDRS", ()))
                or not hmac.compare_digest(supplied.encode(), secret.encode())):
            return jsonify(error="cloudflare_proxy_required"), 403
        if single_header("X-Forwarded-Proto") != "https": return jsonify(error="cloudflare_https_required"), 403
        try:
            address = single_ip(single_header("CF-Connecting-IP"))
            if not is_public_unicast(str(address)): raise ValueError()
        except (ValueError, TypeError): return jsonify(error="invalid_cloudflare_client_ip"), 400
        request.environ["agent_message_bridge.cloudflare_client_ip"] = str(address)

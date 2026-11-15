"""Authlib authorization code/S256 PKCE server and durable connection revocation."""
import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import InvalidRequestError, OAuth2Error
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc7636 import CodeChallenge
from flask import abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import select, update
from werkzeug.security import check_password_hash, generate_password_hash

from .models import Participant, Subscription, now, uid
from .models_auth import APIKey, BrowserOwner, Client, Code, Family, Token, User

SCOPE = "bridge:messages"
AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def service_client(owner_id, key_id=None):
    return "service:"+owner_id + (":"+key_id if key_id else "")


def service_family(key_hash):
    return "service:"+digest(key_hash)


def deactivate_subscriptions(db, **filters):
    statement = update(Subscription)
    for field, value in filters.items():
        statement = statement.where(getattr(Subscription, field) == value)
    db.execute(statement.where(Subscription.active.is_(True))
               .values(active=False, generation=Subscription.generation+1))


def bootstrap_browser_admin(db, item):
    """Only the configured admin is synchronized; registered owners persist."""
    from .profiles import lock_profile_changes
    lock_profile_changes(db)
    owners = list(db.scalars(select(BrowserOwner).order_by(BrowserOwner.id).with_for_update()))
    if item:
        if (db.get(Participant, item["id"])
                or any(o.role != "admin" and (o.id == item["id"] or o.email == item["email"].strip().casefold()) for o in owners)):
            raise ValueError("Configured admin conflicts with an existing identity")
    for owner in owners:
        if owner.role == "admin":
            owner.active = False
    db.flush()
    if item:
        owner = next((o for o in owners if o.id == item["id"]), None)
        if owner is None:
            owner = BrowserOwner(id=item["id"], role="admin", name=item["name"])
            db.add(owner)
        owner.email = item["email"].strip().casefold()
        owner.password_hash, owner.active = item["password_hash"], True


def authenticated_user(db, owner_id):
    user = db.get(User, owner_id, populate_existing=True) if owner_id else None
    participant = db.get(Participant, owner_id, populate_existing=True) if owner_id else None
    return user if user and user.active and participant and participant.active else None


def authorized_user(db, owner_id):
    return authenticated_user(db, owner_id)


def browser_user(db):
    if "account_kind" in session and session["account_kind"] != "participant":
        return None
    user = authorized_user(db, session.get("owner"))
    credential = session.get("credential", "")
    if not user or not user.password_hash or not isinstance(credential, str) or not hmac.compare_digest(credential, digest(user.password_hash)):
        return None
    return user


def browser_owner(db):
    if session.get("account_kind") != "owner":
        return None
    owner_id = session.get("owner")
    owner = db.get(BrowserOwner, owner_id, populate_existing=True) if owner_id else None
    credential = session.get("credential", "")
    if (not owner or not owner.active or not isinstance(credential, str)
            or not hmac.compare_digest(credential, digest(owner.password_hash))):
        return None
    return owner


def browser_identity(db):
    return browser_owner(db) or browser_user(db)


def active_client(db, client_id, lock=False):
    stmt = select(Client).where(Client.client_id == client_id).execution_options(populate_existing=True)
    if lock:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    client = db.scalar(stmt)
    return client if client and client.active else None


def family_active(db, owner_id, client_id, family):
    """Check durable connection authority independently of access-token expiry."""
    user = authorized_user(db, owner_id)
    if not user:
        return False
    if client_id == service_client(owner_id):
        return bool(user.api_key_hash and hmac.compare_digest(family, service_family(user.api_key_hash)))
    prefix = service_client(owner_id) + ":"
    if client_id.startswith(prefix):
        key = db.get(APIKey, client_id[len(prefix):], populate_existing=True)
        return bool(key and key.owner_id == owner_id and key.active
                    and hmac.compare_digest(family, service_family(key.key_hash)))
    client = active_client(db, client_id)
    item = db.get(Family, family, populate_existing=True)
    return bool(client and item and item.active and item.owner_id == owner_id and item.client_id == client_id)


def revoke_family(db, family):
    # Changing active does not change the family key. NO KEY UPDATE still
    # serializes revocation, while allowing refresh INSERT foreign-key checks
    # to take KEY SHARE and finish before our token update waits on their row.
    item = db.scalar(select(Family).where(Family.id == family).with_for_update(key_share=True)
                     .execution_options(populate_existing=True))
    if not item or not item.active:
        return
    item.active = False
    db.execute(update(Token).where(Token.family == family).values(revoked=True))
    db.execute(update(Subscription).where(Subscription.family == family)
               .values(active=False, generation=Subscription.generation+1))


def bearer(db, *, lock_service=False):
    """Resolve sender identity from stored credentials, never from request data."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer ") or not header[7:]:
        abort(401)
    value_hash = digest(header[7:])
    item = db.scalar(select(Token).where(Token.access_hash == value_hash))
    if item:
        if not active_client(db, item.client_id, lock=True):
            abort(401)
        item = db.get(Token, item.id, populate_existing=True)
        if (item.revoked or item.is_expired() or item.resource != current_app.config["BASE_URL"]+"/mcp"
                or item.scope != SCOPE or not family_active(db, item.owner_id, item.client_id, item.family)):
            abort(401)
        return item
    user = db.scalar(select(User).where(User.api_key_hash == value_hash))
    key = db.scalar(select(APIKey).where(APIKey.key_hash == value_hash, APIKey.active.is_(True)))
    owner_id = user.id if user else key.owner_id if key else None
    if not owner_id:
        abort(401)
    # Only subscription revalidation needs to hold this authority through its
    # mutation. Ordinary operations own their participant lock order; taking a
    # sender lock here would invert send_message's sorted sender/recipient order.
    if lock_service:
        db.scalar(select(Participant).where(Participant.id == owner_id).with_for_update()
                  .execution_options(populate_existing=True))
    user = authorized_user(db, owner_id)
    valid = user and user.api_key_hash == value_hash
    if key:
        key = db.get(APIKey, key.id, populate_existing=True)
        valid = valid or bool(key and key.active and key.owner_id == owner_id)
    if not user or not valid:
        abort(401)
    # Token-shaped context; no service secret or synthetic DB token is created.
    from types import SimpleNamespace
    return SimpleNamespace(owner_id=user.id, client_id=service_client(user.id, key.id if key else None),
                           family=service_family(value_hash), scope=SCOPE)


def validate_redirect_uri(uri):
    if not isinstance(uri, str) or any(ord(ch) <= 32 or ord(ch) == 127 for ch in uri) or "\\" in uri or "*" in uri or "#" in uri:
        return False
    try:
        url = urlsplit(uri)
        url.port
        host = url.hostname or ""
        if ":" in host:
            ipaddress.IPv6Address(host)
        elif not re.fullmatch(r"[A-Za-z0-9.-]+", host.encode("idna").decode("ascii")):
            return False
        return bool(url.hostname and url.username is None and url.password is None and not url.fragment
                    and "*" not in url.netloc and (url.scheme == "https" or
                    (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))))
    except (ValueError, UnicodeError):
        return False


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(expected.encode(), request.form.get("csrf", "").encode()):
        abort(400, "Invalid form token")


class S256Challenge(CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant, redirect_uri):
        super().validate_code_challenge(grant, redirect_uri)
        payload = grant.request.payload.data
        if (payload.get("code_challenge_method") != "S256" or
                not re.fullmatch(r"[A-Za-z0-9_-]{43}", payload.get("code_challenge", ""))):
            raise InvalidRequestError("PKCE S256 required")

    def get_authorization_code_challenge(self, code): return code.challenge
    def get_authorization_code_challenge_method(self, code): return code.method


class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = AUTH_METHODS

    def save_authorization_code(self, code, req):
        # Consent may have passed browser_user before a concurrent password
        # reset. Serialize issuance with reset, then recheck that exact cookie
        # before adding authority the reset's family scan could otherwise miss.
        owner_id = req.user.id
        g.db.scalar(select(Participant).where(Participant.id == owner_id).with_for_update()
                     .execution_options(populate_existing=True))
        user = browser_user(g.db)
        if not user or user.id != owner_id:
            abort(401)
        family = uid()
        g.db.add(Family(id=family, owner_id=req.user.id, client_id=req.client.client_id))
        g.db.flush()
        g.db.add(Code(code_hash=digest(code), owner_id=req.user.id, client_id=req.client.client_id,
                      family=family, redirect_uri=req.payload.redirect_uri,
                      resource=req.payload.data["resource"], scope=SCOPE,
                      challenge=req.payload.data["code_challenge"], method="S256"))

    def query_authorization_code(self, code, client):
        item = g.db.scalar(select(Code).where(Code.code_hash == digest(code), Code.client_id == client.client_id)
                           .with_for_update().execution_options(populate_existing=True))
        if not item:
            return None
        if item.used:
            revoke_family(g.db, item.family)
            g.db.info["commit_security_changes"] = True
            return None
        if item.is_expired() or item.resource != request.form.get("resource"):
            return None
        g.oauth_family = item.family
        return item

    def delete_authorization_code(self, code):
        code.used = True

    def authenticate_user(self, code):
        return authorized_user(g.db, code.owner_id)


class RefreshGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = AUTH_METHODS
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, value):
        item = g.db.scalar(select(Token).where(Token.refresh_hash == digest(value))
                           .with_for_update().execution_options(populate_existing=True))
        if not item or item.client_id != self.request.client.client_id:
            return None
        if item.revoked:
            revoke_family(g.db, item.family)
            g.db.info["commit_security_changes"] = True
            return None
        if (item.refresh_expires_at <= now() or item.resource != request.form.get("resource")
                or not family_active(g.db, item.owner_id, item.client_id, item.family)):
            return None
        g.oauth_family = item.family
        return item

    def authenticate_user(self, token):
        return authorized_user(g.db, token.owner_id)

    def revoke_old_credential(self, token):
        token.revoked = True


def install_auth(app):
    configured_hashes = [(app.config.get("BROWSER_ADMIN") or {}).get("password_hash", "")]
    methods = {value.split("$", 1)[0] for value in configured_hashes if value}
    dummy_password_hashes = {method: generate_password_hash(secrets.token_urlsafe(32), method=method)
                             for method in methods}
    if not dummy_password_hashes:
        dummy = generate_password_hash(secrets.token_urlsafe(32))
        dummy_password_hashes[dummy.split("$", 1)[0]] = dummy
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=urlsplit(app.config["BASE_URL"]).scheme == "https",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                      OAUTH2_REFRESH_TOKEN_GENERATOR=True,
                      OAUTH2_TOKEN_EXPIRES_IN={"authorization_code": 900, "refresh_token": 900})

    def query_client(client_id):
        return active_client(g.db, client_id, lock=True)

    def save_token(data, req):
        family = g.oauth_family
        if not family_active(g.db, req.user.id, req.client.client_id, family):
            raise InvalidRequestError("Connection is inactive")
        g.db.add(Token(owner_id=req.user.id, client_id=req.client.client_id, family=family,
                       access_hash=digest(data["access_token"]),
                       refresh_hash=digest(data["refresh_token"]) if data.get("refresh_token") else None,
                       resource=app.config["BASE_URL"]+"/mcp", scope=SCOPE,
                       expires_at=now()+900, refresh_expires_at=now()+30*86400 if data.get("refresh_token") else 0))

    server = AuthorizationServer(app, query_client=query_client, save_token=save_token)
    server.register_grant(CodeGrant, [S256Challenge(required=True)])
    server.register_grant(RefreshGrant)
    app.extensions["oauth_server"] = server

    @app.after_request
    def auth_headers(response):
        if request.path.startswith(("/oauth/", "/login", "/logout")):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self'"+getattr(g, "oauth_callback_origin", "")+"; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.get("/.well-known/oauth-authorization-server")
    def oauth_metadata():
        base = app.config["BASE_URL"]
        return jsonify(issuer=base, authorization_endpoint=base+"/oauth/authorize", token_endpoint=base+"/oauth/token",
                       registration_endpoint=base+"/oauth/register", revocation_endpoint=base+"/oauth/revoke",
                       response_types_supported=["code"], grant_types_supported=["authorization_code", "refresh_token"],
                       code_challenge_methods_supported=["S256"], token_endpoint_auth_methods_supported=AUTH_METHODS,
                       revocation_endpoint_auth_methods_supported=AUTH_METHODS, scopes_supported=[SCOPE])

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    def protected_metadata():
        return jsonify(resource=app.config["BASE_URL"]+"/mcp", authorization_servers=[app.config["BASE_URL"]],
                       bearer_methods_supported=["header"], scopes_supported=[SCOPE])

    @app.post("/oauth/register")
    def register():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="invalid_client_metadata"), 400
        uris = data.get("redirect_uris")
        method = data.get("token_endpoint_auth_method", "client_secret_basic")
        name = data.get("client_name", "Agent Message Bridge connection")
        grant_types = data.get("grant_types", ["authorization_code"])
        if (not isinstance(uris, list) or not uris or not all(validate_redirect_uri(uri) for uri in uris)
                or method not in AUTH_METHODS or not isinstance(name, str) or not name.strip()
                or not isinstance(grant_types, list) or "authorization_code" not in grant_types
                or any(value not in ("authorization_code", "refresh_token") for value in grant_types)
                or data.get("response_types", ["code"]) != ["code"] or data.get("scope", SCOPE) != SCOPE):
            return jsonify(error="invalid_client_metadata"), 400
        secret = secrets.token_urlsafe(48) if method != "none" else None
        client = Client(client_id=uid(), name=name, redirect_uris=list(dict.fromkeys(uris)),
                        secret_hash=digest(secret) if secret else None, auth_method=method, grant_types=grant_types)
        g.db.add(client)
        result = dict(client_id=client.client_id, client_id_issued_at=int(now()), client_name=name,
                      redirect_uris=client.redirect_uris, token_endpoint_auth_method=method,
                      grant_types=grant_types, response_types=["code"], scope=SCOPE)
        if secret:
            result.update(client_secret=secret, client_secret_expires_at=0)
        return jsonify(result), 201

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        query_modes = request.args.getlist("mode")
        form_modes = request.form.getlist("mode") if request.method == "POST" else []
        modes = form_modes or query_modes or ["auto"]
        mode = modes[0] if len(modes) == 1 and (not form_modes or not query_modes or form_modes == query_modes) else "invalid"
        valid_mode = mode in ("auto", "owner", "bot")
        if request.method == "GET" and not valid_mode:
            abort(400)
        if request.method == "POST":
            check_csrf()
            identifier = request.form.get("email", "").strip()
            email = identifier.casefold()
            # Read the same active account sets for every email. If sync-config
            # added a hash method, dummy preparation must not depend on whether
            # the submitted email exists (including the first such login).
            owners = list(g.db.scalars(select(BrowserOwner).where(BrowserOwner.active.is_(True))))
            users = list(g.db.scalars(select(User).where(User.active.is_(True))))
            for account in owners + users:
                if account.password_hash:
                    method = account.password_hash.split("$", 1)[0]
                    if method not in dummy_password_hashes:
                        dummy_password_hashes[method] = generate_password_hash(secrets.token_urlsafe(32), method=method)
            # The explicit intent resolves legacy address/email collisions;
            # never choose an identity by trying a second password after failure.
            owner = next((account for account in owners if account.email == email), None) if valid_mode and mode != "bot" else None
            user = owner or (next((account for account in users if account.id == identifier), None) if valid_mode and mode != "owner" else None)
            actual_hash = user.password_hash if user and user.password_hash else ""
            actual_method = actual_hash.split("$", 1)[0]
            valid = False
            for method, dummy in tuple(dummy_password_hashes.items()):
                candidate = actual_hash if actual_hash and method == actual_method else dummy
                matched = check_password_hash(candidate, request.form.get("password", ""))
                valid = valid or (matched and bool(actual_hash) and method == actual_method)
            if (valid and (owner or authorized_user(g.db, user.id))
                    and hmac.compare_digest(user.password_hash, actual_hash)):
                # The return target is always constructed by our authorize route.
                target = "/" if owner else session.get("authorize_next", "/")
                if not target.startswith("/oauth/authorize?"):
                    target = "/"
                session.clear()
                session["owner"] = user.id
                # Bind only the immutable hash actually checked above. A reset
                # after the comparison yields an old cookie rejected on use.
                session["credential"] = digest(actual_hash)
                session["account_kind"] = "owner" if owner else "participant"
                session.permanent = True
                return redirect(target)
            error = "Sign-in details are incorrect."
        return render_template("login.html", csrf_token=csrf(), error=error, email=request.form.get("email", ""),
                               login_mode=mode if valid_mode else "auto", registration_complete=session.pop("registration_complete", False))

    @app.post("/logout")
    def logout():
        check_csrf()
        session.clear()
        return redirect("/login")

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        if browser_owner(g.db):
            abort(403)
        if request.method == "POST" and request.args:
            abort(400)
        payload = request.args if request.method == "GET" else request.form
        if any(len(payload.getlist(key)) != 1 for key in payload):
            abort(400)
        if payload.get("resource") != app.config["BASE_URL"]+"/mcp":
            return jsonify(error="invalid_target"), 400
        if payload.get("scope") != SCOPE or not payload.get("redirect_uri"):
            return jsonify(error="invalid_request"), 400
        user = browser_user(g.db)
        try:
            grant = server.get_consent_grant(end_user=user)
        except OAuth2Error as exc:
            return jsonify(error=exc.error), 400
        parsed_callback = urlsplit(grant.request.payload.redirect_uri)
        # Only a validated, registered callback may appear in CSP.
        callback_host = parsed_callback.hostname.encode("idna").decode("ascii")
        if ":" in callback_host:
            callback_host = "["+callback_host+"]"
        g.oauth_callback_origin = " "+parsed_callback.scheme+"://"+callback_host+(":"+str(parsed_callback.port) if parsed_callback.port else "")
        if not user:
            if request.method != "GET":
                abort(401)
            session["authorize_next"] = "/oauth/authorize?"+request.query_string.decode("ascii")
            return redirect(url_for("login", mode="bot"))
        if request.method == "POST":
            check_csrf()
            return server.create_authorization_response(grant=grant, grant_user=user if payload.get("approve") == "yes" else None)
        return render_template("oauth-consent.html", client_name=grant.request.client.name,
                               callback=payload["redirect_uri"], csrf_token=csrf(),
                               oauth_fields={key: value for key, value in payload.items() if key not in ("csrf", "approve")})

    @app.post("/oauth/token")
    def token():
        if request.args or any(len(request.form.getlist(key)) != 1 for key in request.form):
            return jsonify(error="invalid_request"), 400
        if request.form.get("resource") != app.config["BASE_URL"]+"/mcp":
            return jsonify(error="invalid_target"), 400
        if "scope" in request.form and request.form["scope"] != SCOPE:
            return jsonify(error="invalid_scope"), 400
        return server.create_token_response()

    @app.post("/oauth/revoke")
    def revoke():
        if request.args or any(len(request.form.getlist(key)) != 1 for key in request.form):
            return jsonify(error="invalid_request"), 400
        # Use the same Authlib client authentication as the token endpoint.
        oauth_req = server.create_oauth2_request(request)
        try:
            client = server.authenticate_client(oauth_req, AUTH_METHODS, "revocation")
        except OAuth2Error as exc:
            return jsonify(error=exc.error), 401
        if not client or not client.active:
            return jsonify(error="invalid_client"), 401
        value = request.form.get("token", "")
        item = g.db.scalar(select(Token).where((Token.access_hash == digest(value)) | (Token.refresh_hash == digest(value)),
                                               Token.client_id == client.client_id))
        if item:
            revoke_family(g.db, item.family)
        return "", 200

    @app.route("/oauth/connections", methods=["GET", "POST"])
    def connections():
        if browser_owner(g.db):
            abort(403)
        user = browser_user(g.db)
        if not user:
            return redirect("/login")
        if request.method == "POST":
            check_csrf()
            item = g.db.get(Family, request.form.get("family", ""))
            if item and item.owner_id == user.id:
                active_client(g.db, item.client_id, lock=True)
                revoke_family(g.db, item.id)
            return redirect("/oauth/connections")
        rows = g.db.execute(select(Family, Client).join(Client, Client.client_id == Family.client_id)
                            .where(Family.owner_id == user.id, Family.active.is_(True))).all()
        return render_template("connections.html", rows=rows, csrf_token=csrf())

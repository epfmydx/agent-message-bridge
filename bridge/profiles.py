"""Owner-managed participant provisioning; credentials remain outside sessions."""
import secrets
from datetime import datetime, timezone

from flask import abort, current_app, g, make_response, redirect, render_template, request, session, url_for
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from .auth import browser_owner, browser_user, check_csrf, csrf, digest
from .errors import Conflict, Invalid
from .models import Participant, uid
from .models_auth import APIKey, BrowserOwner, User
from .profile_webhooks import update_webhook, view_webhook


def lock_profile_changes(db):
    """Serialize cross-table identity checks with configuration synchronization."""
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                        "current_database() || ':' || current_schema() || :purpose, 0))"),
                        {"purpose": ":agent-message-bridge-profiles"})
    elif db.bind.dialect.name == "sqlite":
        # Browser POSTs already reserve their write transaction before any read.
        connection = db.connection()
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")


def validate_config_identities(db, settings):
    """Reject config takeover before modifying any profile or credential."""
    configured = settings["USERS"] + settings.get("BROWSER_OWNERS", [])
    ids = [item["id"] for item in configured]
    emails = [item["email"].casefold() for item in configured]
    if len(ids) != len(set(ids)) or len(emails) != len(set(emails)):
        raise ValueError("Configured identities must be unique")
    participants = {p.id: p for p in db.scalars(select(Participant))}
    users = list(db.scalars(select(User)))
    owners = list(db.scalars(select(BrowserOwner)))
    for item in settings["USERS"]:
        profile = participants.get(item["id"])
        if ((profile and profile.managed_source != "config")
                or any(u.id == item["id"] and u.managed_source != "config" for u in users)
                or any(o.id == item["id"] for o in owners)
                or any(u.id != item["id"] and u.email is not None
                       and u.email.casefold() == item["email"].casefold() for u in users)):
            raise ValueError("Configured identity conflicts with an existing profile")
    for item in settings.get("BROWSER_OWNERS", []):
        if item["id"] in participants or any(u.email is not None and
                u.email.casefold() == item["email"].casefold() for u in users):
            raise ValueError("Configured owner conflicts with an existing profile")


def _owner():
    owner = browser_owner(g.db)
    if owner:
        return owner
    if browser_user(g.db):
        abort(403)
    return None


def _form_signer():
    return URLSafeSerializer(current_app.secret_key, salt="agent-message-bridge-profile-creation-v1")


def _credential_signer():
    return URLSafeSerializer(current_app.secret_key, salt="agent-message-bridge-profile-credentials-v1")


def _credential_token(owner, profile_id, action, key_id=""):
    return _credential_signer().dumps(dict(owner=owner.id, profile=profile_id, action=action,
                                         key=key_id, nonce=secrets.token_urlsafe(32)))


def _credential_response(template, **context):
    response = make_response(render_template(template, **context))
    response.headers["Content-Security-Policy"] = ("default-src 'none'; img-src 'self'; style-src 'self'; "
        "script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    return response


def _webhook_enabled():
    """Accept only the checkbox's explicit boolean representation."""
    if "webhook_enabled" not in request.form:
        return False
    if request.form["webhook_enabled"] != "1":
        abort(400)
    return True


def install_profiles(app):
    @app.route("/profiles/credentials", methods=["GET", "POST"])
    def profile_credentials():
        from .credentials import credential_view, create_api_key, reset_password, revoke_api_key
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if set(request.args) != {"profile_id"} or len(request.args.getlist("profile_id")) != 1:
            abort(400)
        profile_id = request.args["profile_id"]
        error, status = None, 200
        if request.method == "POST":
            check_csrf()
            if any(len(request.form.getlist(key)) != 1 for key in request.form):
                abort(400)
            action = request.form.get("action", "")
            key_id = request.form.get("key_id", "")
            allowed = {"csrf", "operation_token", "expected_generation", "action"}
            if action == "reset_password":
                allowed |= {"password", "password_confirmation"}
            elif action == "revoke_key":
                allowed.add("key_id")
            elif action != "create_key":
                abort(400)
            if set(request.form) - allowed:
                abort(400)
            operation_token = request.form.get("operation_token", "")
            try:
                token = _credential_signer().loads(operation_token)
                if (not isinstance(token, dict) or token.get("owner") != owner.id
                        or token.get("profile") != profile_id or token.get("action") != action
                        or token.get("key") != key_id or not isinstance(token.get("nonce"), str)
                        or not token["nonce"]):
                    raise ValueError
                generation = request.form.get("expected_generation", "")
                if not generation.isascii() or not generation.isdecimal() or generation.startswith("0"):
                    raise ValueError
                generation = int(generation)
            except (BadData, ValueError, TypeError):
                abort(400)
            lock_profile_changes(g.db)
            if not _owner():
                return redirect(url_for("login"))
        participant = g.db.get(Participant, profile_id)
        user = g.db.get(User, profile_id)
        if not participant or not participant.active or not user or not user.active:
            abort(404)
        if request.method == "POST":
            try:
                with g.db.begin_nested():
                    if action == "reset_password":
                        password = request.form.get("password", "")
                        if not password or password != request.form.get("password_confirmation", ""):
                            raise Invalid("Enter matching passwords")
                        reset_password(g.db, user, password, generation, operation_token)
                    elif action == "create_key":
                        raw_key, key_id = create_api_key(g.db, user, generation, operation_token)
                    else:
                        revoke_api_key(g.db, user, key_id, generation, operation_token)
                g.db.commit()
            except Invalid:
                error = ("Enter matching new passwords. Email login requires an existing email address."
                         if action == "reset_password" else "This API key is no longer available. Review the current keys.")
                status = 400
            except Conflict:
                error = "Credentials changed or this form was already used. Review the current status before trying again. Keys cannot be shown again."
                status = 409
            else:
                if action == "create_key":
                    return _credential_response("profile-key-created.html", participant=participant,
                                                api_key=raw_key, key_id=key_id, csrf_token=csrf())
                session["profile_credential_notice"] = dict(profile=profile_id, action=action)
                return redirect(url_for("profile_credentials", profile_id=profile_id), code=303)
        view = credential_view(g.db, user)
        for key in view["keys"]:
            if key["created_at"] is not None:
                key["created_at"] = datetime.fromtimestamp(key["created_at"], timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
        notice = session.pop("profile_credential_notice", None) if request.method == "GET" else None
        if not isinstance(notice, dict) or notice.get("profile") != profile_id:
            notice = None
        tokens = {action: _credential_token(owner, profile_id, action)
                  for action in ("reset_password", "create_key")}
        revoke_tokens = {key["id"]: _credential_token(owner, profile_id, "revoke_key", key["id"])
                         for key in view["keys"] if key["active"]}
        response = _credential_response("profile-credentials.html", participant=participant, user=user,
            credential=view, tokens=tokens, revoke_tokens=revoke_tokens, error=error, notice=notice, csrf_token=csrf())
        response.status_code = status
        return response

    @app.get("/profiles")
    def profiles():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        from .web import _page_size, _signer
        if any(len(request.args.getlist(key)) != 1 for key in request.args):
            abort(400)
        size = _page_size()
        statement = select(Participant, User).join(User, Participant.id == User.id)
        if "cursor" in request.args:
            try:
                data = _signer().loads(request.args["cursor"])
                if (not isinstance(data, dict) or data.get("purpose") != "profiles"
                        or data.get("owner") != digest("owner:" + owner.id) or data.get("page_size") != size
                        or not isinstance(data.get("anchor"), str) or not data["anchor"]):
                    raise ValueError
                statement = statement.where(Participant.id > data["anchor"])
            except (BadData, ValueError, TypeError):
                abort(400)
        rows = g.db.execute(statement.order_by(Participant.id).limit(size + 1)).all()
        next_url = None
        if len(rows) > size:
            rows = rows[:size]
            cursor = _signer().dumps(dict(purpose="profiles", owner=digest("owner:" + owner.id),
                                         page_size=size, anchor=rows[-1][0].id))
            next_url = url_for("profiles", page_size=size, cursor=cursor)
        notifications = {participant.id: view_webhook(current_app.config, participant)
                         for participant, _ in rows}
        api_profiles = set(g.db.scalars(select(APIKey.owner_id).where(
            APIKey.owner_id.in_([participant.id for participant, _ in rows]), APIKey.active.is_(True)))) if rows else set()
        return render_template("profiles.html", rows=rows, next_url=next_url,
                               notifications=notifications, api_profiles=api_profiles)

    @app.route("/profiles/notifications", methods=["GET", "POST"])
    def profile_notifications():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if set(request.args) != {"profile_id"} or len(request.args.getlist("profile_id")) != 1:
            abort(400)
        profile_id = request.args["profile_id"]
        error = None
        status = 200
        if request.method == "POST":
            check_csrf()
            if any(len(request.form.getlist(key)) != 1 for key in request.form):
                abort(400)
            enabled = _webhook_enabled()
            generation = request.form.get("expected_generation", "")
            if not generation.isascii() or not generation.isdecimal() or generation.startswith("0"):
                abort(400)
            try:
                generation = int(generation)
            except ValueError:
                abort(400)
            lock_profile_changes(g.db)
            if not _owner():
                return redirect(url_for("login"))
        statement = select(Participant).where(Participant.id == profile_id)
        if request.method == "POST":
            statement = statement.with_for_update()
        participant = g.db.scalar(statement)
        user = g.db.get(User, profile_id)
        if not participant or not participant.active or not user or not user.active:
            abort(404)
        if request.method == "POST":
            try:
                with g.db.begin_nested():
                    update_webhook(g.db, current_app.config, participant, enabled=enabled,
                                   url=request.form.get("webhook_url", ""),
                                   token=request.form.get("webhook_token", ""),
                                   expected_generation=generation)
            except Invalid:
                error = "Enter a public HTTPS destination and a single-line bearer token using HTTP-compatible characters. A new destination requires a new token."
                status = 400
            except Conflict:
                error = "These settings changed since this form was opened. Review the current status before saving again."
                status = 409
            else:
                g.db.commit()
                return redirect(url_for("profile_notifications", profile_id=profile_id), code=303)
        return render_template("profile-notifications.html", participant=participant,
                               notification=view_webhook(current_app.config, participant),
                               error=error, csrf_token=csrf()), status

    @app.route("/profiles/new", methods=["GET", "POST"])
    def new_profile():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        error = None
        # Only nonsecret fields are ever passed back to a template.
        values = {key: request.form.get(key, "") for key in ("name", "profile_id", "email", "auth_mode")}
        if request.method == "GET":
            creation_token = _form_signer().dumps(dict(owner=owner.id, purpose="create-profile",
                                                       nonce=secrets.token_urlsafe(32)))
            values["auth_mode"] = "oauth"
            values["webhook_enabled"] = False
        else:
            check_csrf()
            creation_token = request.form.get("creation_token", "")
            try:
                token = _form_signer().loads(creation_token)
                if (not isinstance(token, dict) or token.get("owner") != owner.id
                        or token.get("purpose") != "create-profile"
                        or not isinstance(token.get("nonce"), str) or not token["nonce"]):
                    raise ValueError
            except (BadData, ValueError, TypeError):
                abort(400)
            if any(len(request.form.getlist(key)) != 1 for key in request.form):
                abort(400)
            values["webhook_enabled"] = _webhook_enabled()
            name, ident = values["name"].strip(), values["profile_id"].strip()
            email = values["email"].strip().casefold() or None
            mode = values["auth_mode"]
            password = request.form.get("password", "")
            if not name:
                error = "Enter a display name."
            elif mode not in ("oauth", "api_key"):
                error = "Choose an authentication method."
            elif mode == "oauth" and (not email or not password):
                error = "Email and password are required for OAuth / email login."
            if not error:
                lock_profile_changes(g.db)
                if not _owner():
                    return redirect(url_for("login"))
                token_hash = digest(creation_token)
                if g.db.scalar(select(User.id).where(User.creation_token_hash == token_hash)):
                    error = "This form has already created a profile. Open Profiles to continue."
                elif ident and (g.db.get(Participant, ident) or g.db.get(BrowserOwner, ident)
                                or any(item["id"] == ident for field in ("USERS", "BROWSER_OWNERS")
                                       for item in current_app.config.get(field, []))):
                    error = "That stable ID is already in use."
                elif email and (any(u.email and u.email.casefold() == email for u in g.db.scalars(select(User)))
                                or any(o.active and o.email.casefold() == email for o in g.db.scalars(select(BrowserOwner)))
                                or any(item["email"].casefold() == email for field in ("USERS", "BROWSER_OWNERS")
                                       for item in current_app.config.get(field, []))):
                    error = "That email is already in use."
                else:
                    ident = ident or uid()
                    raw_key = secrets.token_urlsafe(48) if mode == "api_key" else None
                    # The savepoint includes both records and the durable replay
                    # marker. A duplicate race cannot leave a partial profile.
                    try:
                        with g.db.begin_nested():
                            participant = Participant(id=ident, name=name, managed_source="database",
                                                      webhook_enabled=False)
                            g.db.add(participant)
                            g.db.flush()
                            g.db.add(User(id=ident, email=email, managed_source="database",
                                          password_hash=generate_password_hash(password) if mode == "oauth" else "",
                                          api_key_hash=digest(raw_key) if raw_key else None,
                                          creation_token_hash=token_hash))
                            g.db.flush()
                            if values["webhook_enabled"]:
                                update_webhook(g.db, current_app.config, participant, enabled=True,
                                               url=request.form.get("webhook_url", ""),
                                               token=request.form.get("webhook_token", ""),
                                               expected_generation=1)
                    except IntegrityError:
                        error = "That ID, email or form has already been used. Open a new form or choose different details."
                    except (Invalid, Conflict):
                        error = "Enter a public HTTPS destination and a single-line bearer token using HTTP-compatible characters to enable webhook notifications."
                    else:
                        # Commit before exposing the key. Failure cannot render
                        # success or persist a raw credential in a cookie.
                        g.db.commit()
                        return render_template("profiles-created.html", profile_id=ident, name=name, api_key=raw_key)
        return render_template("profiles-new.html", values=values, error=error,
                               creation_token=creation_token, csrf_token=csrf()), 400 if error else 200

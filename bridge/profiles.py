"""Owner-managed participant provisioning; credentials remain outside sessions."""
import secrets
from datetime import datetime

from flask import abort, current_app, g, make_response, redirect, render_template, request, session, url_for
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from .auth import browser_owner, browser_user, check_csrf, csrf, digest
from .errors import Conflict, Invalid
from .models import BotAllowlist, Participant, address_id, private_label, uid
from .models_auth import APIKey, BrowserOwner, User
from .profile_webhooks import update_webhook, view_webhook
from .profile_validation import display_name, contact_email


MAX_ALLOWLIST_ENTRIES = 500

def lock_profile_changes(db):
    """Serialize cross-table identity checks with registration/admin sync."""
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                        "current_database() || ':' || current_schema() || :purpose, 0))"),
                        {"purpose": ":agent-message-bridge-profiles"})
    elif db.bind.dialect.name == "sqlite":
        # Browser POSTs already reserve their write transaction before any read.
        connection = db.connection()
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")



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
    @app.route("/account", methods=["GET", "POST"])
    def owner_account():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if request.args:
            abort(400)
        error = None
        name = owner.name
        if request.method == "POST":
            check_csrf()
            if set(request.form) - {"csrf", "name"} or any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400)
            name = request.form.get("name", "")
            try:
                name = display_name(name)
            except Invalid as exc:
                error = str(exc)
            if not error:
                lock_profile_changes(g.db)
                owner = _owner()
                if not owner:
                    return redirect(url_for("login"))
                owner.name = name
                return redirect(url_for("owner_account"), code=303)
        return render_template("account.html", name=name, error=error, csrf_token=csrf()), 400 if error else 200

    def owned_profile(owner, *, lock=False):
        if set(request.args) != {"profile_id"} or len(request.args.getlist("profile_id")) != 1:
            abort(400)
        statement = select(Participant).where(Participant.id == request.args["profile_id"],
            Participant.owner_account_id == owner.id)
        if lock:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        participant = g.db.scalar(statement)
        if not participant:
            abort(404)
        return participant

    @app.route("/profiles/edit", methods=["GET", "POST"])
    def profile_edit():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if request.method == "POST":
            check_csrf()
            if set(request.form) - {"csrf", "name", "email"} or any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400)
            lock_profile_changes(g.db)
            if not _owner():
                return redirect(url_for("login"))
        participant = owned_profile(owner, lock=request.method == "POST")
        user = g.db.get(User, participant.id)
        if not participant.active or participant.deactivated_at is not None or not user or not user.active:
            abort(404)
        error = None
        values = dict(name=participant.name, email=user.email or "")
        if request.method == "POST":
            values = {key: request.form.get(key, "") for key in ("name", "email")}
            try:
                name, email = display_name(values["name"]), contact_email(values["email"])
            except Invalid as exc:
                error = str(exc)
            if not error:
                participant.name, user.email = name, email
                return redirect(url_for("profile_edit", profile_id=participant.id), code=303)
        return render_template("profile-edit.html", participant=participant, values=values,
                               error=error, csrf_token=csrf()), 400 if error else 200

    @app.route("/profiles/deactivate", methods=["GET", "POST"])
    def profile_deactivate():
        from .lifecycle import deactivate_bot, delivery_fence
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if request.method == "POST":
            check_csrf()
            if set(request.form) - {"csrf", "confirm"} or any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400)
        participant = owned_profile(owner)
        if not participant.active or participant.deactivated_at is not None:
            abort(404)
        error = None
        if request.method == "POST":
            if request.form.get("confirm") != "deactivate":
                error = "Confirm that you want to permanently deactivate this bot."
            else:
                # Fence before profile and participant locks, and retain it
                # through commit. No transport can start after retirement.
                with delivery_fence(g.db, participant.id):
                    lock_profile_changes(g.db)
                    if not _owner():
                        return redirect(url_for("login"))
                    deactivate_bot(g.db, owner.id, participant.id)
                    g.db.commit()
                return redirect(url_for("profiles"), code=303)
        return render_template("profile-deactivate.html", participant=participant,
                               error=error, csrf_token=csrf()), 400 if error else 200

    @app.route("/profiles/reachability", methods=["GET", "POST"])
    def profile_reachability():
        owner = _owner()
        if not owner:
            return redirect(url_for("login"))
        if set(request.args) != {"profile_id"} or len(request.args.getlist("profile_id")) != 1:
            abort(400)
        if request.method == "POST":
            check_csrf()
            if (set(request.form) - {"csrf", "policy", "sender_ids"}
                    or any(len(request.form.getlist(k)) != 1 for k in request.form)):
                abort(400)
            lock_profile_changes(g.db)
            if not _owner():
                return redirect(url_for("login"))
        query = select(Participant).where(Participant.id == request.args["profile_id"],
                                         Participant.owner_account_id == owner.id, Participant.active.is_(True))
        participant = g.db.scalar(query.with_for_update() if request.method == "POST" else query)
        if not participant:
            abort(404)
        error = None
        policy = participant.reachability_policy
        submitted_ids = None
        sender_ids = list(g.db.scalars(select(BotAllowlist.sender_id).where(
            BotAllowlist.receiver_id == participant.id).order_by(BotAllowlist.sender_id)))
        if request.method == "POST":
            policy = request.form.get("policy", "")
            submitted_ids = request.form.get("sender_ids", "\n".join(sender_ids))
            senders = {ident.strip(" ") for ident in submitted_ids.replace("\r\n", "\n").split("\n") if ident.strip(" ")} if policy == "allowlist" else set()
            if policy not in ("own_owner", "allowlist", "open"):
                error = "Choose who can message this bot."
            elif len(senders) > MAX_ALLOWLIST_ENTRIES:
                error = "Use at most 500 address IDs."
            elif any(not ident or ident != ident.strip() or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in ident) for ident in senders):
                error = "Enter one routing address per line, without control characters."
            else:
                owned = set(g.db.scalars(select(Participant.id).where(
                    Participant.owner_account_id == owner.id, Participant.id.in_(senders)))) if senders else set()
                if owned:
                    error = "Use address IDs of bots owned by someone else."
            if not error:
                participant.reachability_policy = policy
                if policy == "allowlist":
                    g.db.execute(delete(BotAllowlist).where(BotAllowlist.receiver_id == participant.id))
                    g.db.add_all([BotAllowlist(receiver_id=participant.id, sender_id=ident) for ident in sorted(senders)])
                return redirect(url_for("profile_reachability", profile_id=participant.id), code=303)
        return render_template("profile-reachability.html", participant=participant, policy=policy,
                               sender_text=submitted_ids if error else "\n".join(sender_ids),
                               error=error, csrf_token=csrf()), 400 if error else 200

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
        if not participant or participant.owner_account_id != owner.id or not participant.active or not user or not user.active:
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
                error = ("Enter matching new passwords."
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
        from .web import UTC
        for key in view["keys"]:
            if key["created_at"] is not None:
                key["created_at"] = datetime.fromtimestamp(key["created_at"], UTC).strftime("%d %b %Y, %H:%M:%S UTC")
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
        statement = select(Participant, User).join(User, Participant.id == User.id).where(Participant.owner_account_id == owner.id)
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
        return _credential_response("profiles.html", rows=rows, next_url=next_url,
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
        statement = select(Participant).where(Participant.id == profile_id, Participant.owner_account_id == owner.id)
        if request.method == "POST":
            statement = statement.with_for_update()
        participant = g.db.scalar(statement)
        user = g.db.get(User, profile_id)
        if not participant or participant.owner_account_id != owner.id or not participant.active or not user or not user.active:
            abort(404)
        if request.method == "POST":
            try:
                with g.db.begin_nested():
                    update_webhook(g.db, current_app.config, participant, enabled=enabled,
                                   url=request.form.get("webhook_url", ""),
                                   token=request.form.get("webhook_token", ""),
                                   expected_generation=generation)
            except Invalid:
                error = "Enter a public HTTPS destination and a single-line bearer token using HTTP-compatible characters. When changing the destination, enter that receiver’s bearer token."
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
            chosen_id = values["profile_id"].strip()
            try:
                name, email = display_name(values["name"]), contact_email(values["email"])
            except Invalid as exc:
                error = str(exc)
            mode = values["auth_mode"]
            password = request.form.get("password", "")
            if not error and mode not in ("oauth", "api_key"):
                error = "Choose an authentication method."
            elif not error and mode == "oauth" and not password:
                error = "Enter a password for address ID login."
            if not error:
                lock_profile_changes(g.db)
                if not _owner():
                    return redirect(url_for("login"))
                token_hash = digest(creation_token)
                if g.db.scalar(select(User.id).where(User.creation_token_hash == token_hash)):
                    error = "This form has already created a profile. Open Profiles to continue."
                elif chosen_id and g.db.scalar(select(Participant.id).where(
                        Participant.owner_account_id == owner.id, Participant.stable_id == chosen_id)):
                    error = "That chosen ID is already used by one of your bots."
                else:
                    ident = address_id()
                    chosen_id = chosen_id or private_label()
                    raw_key = secrets.token_urlsafe(48) if mode == "api_key" else None
                    # The savepoint includes both records and the durable replay
                    # marker. A duplicate race cannot leave a partial profile.
                    try:
                        with g.db.begin_nested():
                            participant = Participant(id=ident, stable_id=chosen_id, name=name, owner_account_id=owner.id, managed_source="database",
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
                        error = "This form or chosen ID has already been used. Open a new form."
                    except (Invalid, Conflict):
                        error = "Enter a public HTTPS destination and a single-line bearer token using HTTP-compatible characters to enable webhook notifications."
                    else:
                        # Commit before exposing the key. Failure cannot render
                        # success or persist a raw credential in a cookie.
                        g.db.commit()
                        return _credential_response("profiles-created.html", participant=participant, profile_id=ident, name=name, api_key=raw_key)
        return render_template("profiles-new.html", values=values, error=error,
                               creation_token=creation_token, csrf_token=csrf()), 400 if error else 200

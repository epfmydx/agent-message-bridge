"""Admin invitations and atomic, browser-only owner registration."""
import secrets
import math
from datetime import datetime

from flask import abort, current_app, g, redirect, render_template, request, session, url_for
from sqlalchemy import delete, select, tuple_, update
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError

from .auth import browser_identity, browser_owner, check_csrf, csrf, digest
from .models import now, uid
from .models_auth import BrowserOwner, InvitationReveal, OwnerInvitation
from .profiles import lock_profile_changes

LIFETIME = 7 * 86400
REVEAL_LIFETIME = 10 * 60
REGISTRATION_ERROR = "Registration failed. Check your details and invitation code."


def prune_reveals(db, timestamp):
    db.execute(delete(InvitationReveal).where(InvitationReveal.expires_at <= timestamp))


def create_invitation(db, admin):
    lock_profile_changes(db)
    current = db.get(BrowserOwner, admin.id, populate_existing=True)
    if not current or not current.active or current.role != "admin":
        abort(403)
    ident = uid()
    raw = secrets.token_urlsafe(32)
    issued = now()
    prune_reveals(db, issued)
    invitation = OwnerInvitation(id=ident, code_hash=digest(raw), creator_id=current.id,
                                 created_at=issued, expires_at=issued + LIFETIME)
    db.add(invitation)
    db.flush()
    db.add(InvitationReveal(invitation_id=ident, code=raw, expires_at=issued + REVEAL_LIFETIME))
    db.flush()
    return invitation, raw


def redeem_invitation(db, name, email, password, code):
    """CAS plus the account insert commit together, including on SQLite.

    The existing identity lock serializes owner email checks and admin
    synchronization. The conditional update remains the single-use authority.
    No raw code or password is retained in a session, receipt or invitation row.
    """
    from werkzeug.security import generate_password_hash
    # Reject C0/C1 controls before normalization, hashing or binding owner text.
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name + email):
        return None
    from .profile_validation import display_name
    from .errors import Invalid
    try:
        name = display_name(name)
    except Invalid:
        return None
    email, code = email.strip().casefold(), code.strip()
    if not name or not password or not code or email.count("@") != 1 or any(c.isspace() for c in email) or not all(email.split("@")):
        return None
    password_hash = generate_password_hash(password)
    lock_profile_changes(db)
    checked = now()
    invitation_id = db.scalar(select(OwnerInvitation.id).where(
        OwnerInvitation.code_hash == digest(code), OwnerInvitation.expires_at > checked,
        OwnerInvitation.redeemer_id.is_(None), OwnerInvitation.revoked_at.is_(None)))
    duplicate_email = db.scalar(select(BrowserOwner.id).where(
        BrowserOwner.email == email, BrowserOwner.active.is_(True)))
    # Valid-shaped failures all perform one KDF and these same indexed lookups.
    # Neither a duplicate owner email nor an invalid code consumes an invitation.
    if not invitation_id or duplicate_email:
        return None
    owner_id = uid()
    # The receipt and FK target must exist before the conditional update.
    with db.begin_nested():
        owner = BrowserOwner(id=owner_id, name=name, email=email,
                             password_hash=password_hash, role="owner")
        db.add(owner)
        db.flush()
        redeemed = now()
        changed = db.execute(update(OwnerInvitation).where(
            OwnerInvitation.code_hash == digest(code), OwnerInvitation.expires_at > redeemed,
            OwnerInvitation.redeemer_id.is_(None), OwnerInvitation.revoked_at.is_(None))
            .values(redeemer_id=owner_id, redeemed_at=redeemed))
        if changed.rowcount != 1:
            # Roll back the newly created identity as well as the redemption.
            raise InvalidInvitation
        db.execute(delete(InvitationReveal).where(InvitationReveal.invitation_id == invitation_id))
    return owner


class InvalidInvitation(Exception):
    pass


def install_invitations(app):
    @app.route("/register", methods=["GET", "POST"])
    def owner_register():
        error = None
        if request.method == "POST":
            check_csrf()
            allowed = {"csrf", "name", "email", "password", "code"}
            if set(request.form) - allowed or any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400)
            try:
                owner = redeem_invitation(g.db, *(request.form.get(k, "") for k in ("name", "email", "password", "code")))
            except (InvalidInvitation, IntegrityError):
                owner = None
            if owner:
                g.db.commit()
                session.clear()
                session["registration_complete"] = True
                return redirect(url_for("login"), code=303)
            error = REGISTRATION_ERROR
        return render_template("register.html", error=error, csrf_token=csrf(),
                               name=request.form.get("name", ""), email=request.form.get("email", "")), 400 if error else 200

    @app.get("/invitations/created")
    def invitation_created():
        admin = browser_owner(g.db)
        if not admin:
            if browser_identity(g.db):
                abort(403)
            return redirect(url_for("login"))
        if admin.role != "admin":
            abort(403)
        if set(request.args) != {"invitation_id"} or len(request.args.getlist("invitation_id")) != 1:
            abort(400)
        lock_profile_changes(g.db)
        admin = browser_owner(g.db)
        if not admin or admin.role != "admin":
            abort(403)
        ident = request.args["invitation_id"]
        shown = now()
        prune_reveals(g.db, shown)
        invitation = g.db.scalar(select(OwnerInvitation).where(
            OwnerInvitation.id == ident, OwnerInvitation.creator_id == admin.id).with_for_update())
        if (not invitation or invitation.displayed_at is not None or invitation.revoked_at is not None
                or invitation.redeemer_id is not None or invitation.expires_at <= shown):
            return redirect(url_for("invitations"), code=303)
        reveal = g.db.get(InvitationReveal, ident, with_for_update=True)
        if not reveal:
            return redirect(url_for("invitations"), code=303)
        raw = reveal.code
        g.db.delete(reveal)
        invitation.displayed_at = shown
        g.db.commit()
        return render_template("invitation-created.html", code=raw, invitation_id=ident,
                               register_url=current_app.config["BASE_URL"].rstrip("/") + "/register", csrf_token=csrf())

    @app.route("/invitations", methods=["GET", "POST"])
    def invitations():
        admin = browser_owner(g.db)
        if not admin:
            if browser_identity(g.db):
                abort(403)
            return redirect(url_for("login"))
        if admin.role != "admin":
            abort(403)
        if request.method == "POST":
            check_csrf()
            if any(len(request.form.getlist(k)) != 1 for k in request.form):
                abort(400)
            lock_profile_changes(g.db)
            admin = browser_owner(g.db)
            if not admin or admin.role != "admin":
                abort(403)
            action = request.form.get("action")
            if action == "create" and set(request.form) == {"csrf", "action"}:
                invitation, _ = create_invitation(g.db, admin)
                g.db.commit()
                return redirect(url_for("invitation_created", invitation_id=invitation.id), code=303)
            if action == "revoke" and set(request.form) == {"csrf", "action", "invitation_id"}:
                g.db.execute(update(OwnerInvitation).where(
                    OwnerInvitation.id == request.form["invitation_id"], OwnerInvitation.redeemer_id.is_(None),
                    OwnerInvitation.revoked_at.is_(None)).values(revoked_at=now()))
                g.db.execute(delete(InvitationReveal).where(InvitationReveal.invitation_id == request.form["invitation_id"]))
                return redirect(url_for("invitations"), code=303)
            abort(400)
        from .web import UTC, _page_size, _signer
        from itsdangerous import BadData
        if set(request.args) - {"page_size", "cursor"} or any(len(request.args.getlist(k)) != 1 for k in request.args):
            abort(400)
        size = _page_size()
        prune_reveals(g.db, now())
        redeemer = aliased(BrowserOwner)
        statement = select(OwnerInvitation, redeemer.name, redeemer.email).outerjoin(redeemer, redeemer.id == OwnerInvitation.redeemer_id)
        if "cursor" in request.args:
            try:
                data = _signer().loads(request.args["cursor"])
                if (data.get("purpose") != "invitations" or data.get("owner") != admin.id
                        or data.get("page_size") != size or not isinstance(data.get("anchor"), list)
                        or len(data["anchor"]) != 2 or type(data["anchor"][0]) not in (int, float)
                        or not math.isfinite(data["anchor"][0]) or not isinstance(data["anchor"][1], str)):
                    raise ValueError
                statement = statement.where(tuple_(OwnerInvitation.created_at, OwnerInvitation.id) < tuple(data["anchor"]))
            except (BadData, ValueError, TypeError, AttributeError):
                abort(400)
        rows = list(g.db.execute(statement.order_by(OwnerInvitation.created_at.desc(), OwnerInvitation.id.desc()).limit(size + 1)))
        next_url = None
        if len(rows) > size:
            rows = rows[:size]
            cursor = _signer().dumps(dict(purpose="invitations", owner=admin.id, page_size=size,
                                         anchor=[rows[-1][0].created_at, rows[-1][0].id]))
            next_url = url_for("invitations", page_size=size, cursor=cursor)
        current = now()
        items = [dict(id=r.id, creator=r.creator_id, redeemer_name=redeemer_name, redeemer_email=redeemer_email,
                      expires=datetime.fromtimestamp(r.expires_at, UTC).strftime("%d %b %Y, %H:%M UTC"),
                      state="Redeemed" if r.redeemer_id else "Revoked" if r.revoked_at is not None else "Expired" if r.expires_at <= current else "Available") for r, redeemer_name, redeemer_email in rows]
        return render_template("invitations.html", invitations=items, next_url=next_url, csrf_token=csrf())

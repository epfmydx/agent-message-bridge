"""Read-only browser views for a participant or the independent bridge owner."""
import json
import math
from datetime import datetime, timezone

from flask import abort, current_app, g, redirect, render_template, request, url_for
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import exists, select, true, tuple_
from sqlalchemy.orm import aliased

from . import auth, files
from .models import Artifact, Member, Message, MessageArtifact, Participant, Thread
from .models_auth import BrowserOwner

def _page_size():
    """Keep browser rendering and attachment bind lists bounded per request."""
    try:
        size = int(request.args.get("page_size", "25"))
        if not 1 <= size <= 100:
            raise ValueError
    except ValueError:
        abort(400, "Page size must be an integer from 1 to 100")
    return size


def _user():
    if not hasattr(g, "browser_account"):
        g.browser_account = auth.browser_identity(g.db)
    return g.browser_account


def _scope(owner):
    return exists(select(Member.thread_id).where(Member.thread_id == Message.thread_id,
                                                Member.participant_id == owner))


def _visibility(user):
    return true() if isinstance(user, BrowserOwner) else _scope(user.id)


def _cursor_identity(user):
    # Scope is part of the signed identity, even if an ID is reused after a
    # configured account is removed and replaced by a different account type.
    return json.dumps(["owner" if isinstance(user, BrowserOwner) else "participant", user.id], separators=(",", ":"))


def _signer():
    return URLSafeSerializer(current_app.secret_key, salt="agent-message-bridge-browser-pagination-v1")


def _cursor(owner, direction, row, page_size):
    return _signer().dumps({"owner": auth.digest(owner), "purpose": "inbox", "direction": direction,
                            "anchor": [row.created_at, row.id], "page_size": page_size})


def _read_cursor(value, owner, page_size):
    try:
        data = _signer().loads(value)
        if (not isinstance(data, dict) or data.get("owner") != auth.digest(owner)
                or data.get("purpose") != "inbox" or data.get("direction") not in ("older", "newer")
                or data.get("page_size") != page_size):
            raise ValueError
        anchor = data.get("anchor")
        if (not isinstance(anchor, list) or len(anchor) != 2 or type(anchor[0]) not in (int, float)
                or not math.isfinite(anchor[0]) or not isinstance(anchor[1], str) or not anchor[1]):
            raise ValueError
        return data["direction"], anchor
    except (BadData, ValueError, TypeError, OverflowError):
        abort(400, "Invalid page cursor")


def _rows(db, statement):
    sender, recipient = aliased(Participant), aliased(Participant)
    return db.execute(statement.add_columns(sender.name, recipient.name)
                      .join(sender, sender.id == Message.sender_id)
                      .join(recipient, recipient.id == Message.recipient_id)).all()


def _serialize(db, rows):
    attachments = {row.id: [] for row, _, _ in rows}
    if rows:
        # Fetch all attachment metadata once per page, including empty messages.
        for message_id, artifact in db.execute(select(MessageArtifact.message_id, Artifact)
                .join(Artifact, Artifact.id == MessageArtifact.artifact_id)
                .where(MessageArtifact.message_id.in_(attachments))
                .order_by(MessageArtifact.message_id, Artifact.id)):
            attachments[message_id].append({"id": artifact.id, "filename": artifact.filename,
                "size_bytes": artifact.size_bytes, "content_type": artifact.content_type})
    return [{"message_id": row.id, "thread_id": row.thread_id, "sender": row.sender_id,
             "sender_name": sender, "recipient": row.recipient_id, "recipient_name": recipient,
             "reply_to": row.reply_to, "text": row.text, "status": row.status,
             "needs_reply": row.needs_reply,
             "created_at": datetime.fromtimestamp(row.created_at, timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC"),
             "attachments": attachments[row.id]} for row, sender, recipient in rows]


def install_web(app):
    @app.context_processor
    def account_context():
        # Static/template rendering outside an application request must not open
        # a second session or disclose a participant from another request.
        user = _user() if hasattr(g, "db") and request.endpoint != "static" else None
        account = None
        if user:
            if isinstance(user, BrowserOwner):
                account = {"id": user.id, "name": user.name, "email": user.email, "is_owner": True}
            else:
                participant = g.db.get(Participant, user.id)
                account = {"id": user.id, "name": participant.name, "email": user.email}
        return {"account": account, "csrf_token": auth.csrf()}

    @app.get("/")
    def inbox():
        user = _user()
        if not user:
            return redirect(url_for("login"))
        if isinstance(user, BrowserOwner):
            from .owner_web import owner_inbox
            return owner_inbox(user)
        if "participant_a" in request.args or "participant_b" in request.args:
            abort(400, "Pair filtering is available in the owner overview")
        if any(len(request.args.getlist(key)) != 1 for key in ("page_size", "cursor") if key in request.args):
            abort(400)
        page_size = _page_size()
        direction, anchor = None, None
        cursor_identity = _cursor_identity(user)
        if "cursor" in request.args:
            direction, anchor = _read_cursor(request.args["cursor"], cursor_identity, page_size)
        statement = select(Message).where(_visibility(user))
        key = tuple_(Message.created_at, Message.id)
        if anchor:
            statement = statement.where(key < tuple(anchor) if direction == "older" else key > tuple(anchor))
        order = (Message.created_at.asc(), Message.id.asc()) if direction == "newer" else (Message.created_at.desc(), Message.id.desc())
        rows = _rows(g.db, statement.order_by(*order).limit(page_size))
        if direction == "newer":
            rows.reverse()
        pagination = {"older_url": None, "newer_url": None}
        if rows:
            for side, row, condition in (("older", rows[-1][0], key < (rows[-1][0].created_at, rows[-1][0].id)),
                                         ("newer", rows[0][0], key > (rows[0][0].created_at, rows[0][0].id))):
                if g.db.scalar(select(Message.id).where(_visibility(user), condition).limit(1)) is not None:
                    pagination[side+"_url"] = url_for("inbox", page_size=page_size,
                        cursor=_cursor(cursor_identity, side, row, page_size))
        return render_template("messages.html", messages=_serialize(g.db, rows), pagination=pagination, page_size=page_size)

    @app.get("/message")
    def browser_message():
        user = _user()
        if not user:
            return redirect(url_for("login"))
        # Message identities are opaque. Keeping them in the query string
        # prevents browser path normalization from changing slashes/dot segments.
        allowed = {"message_id", "participant_a", "participant_b"} if isinstance(user, BrowserOwner) else {"message_id"}
        if (not "message_id" in request.args or set(request.args) - allowed
                or any(len(request.args.getlist(key)) != 1 for key in request.args)
                or not request.args["message_id"]):
            abort(400, "One message ID is required")
        from .owner_web import _pair_args, _pair_condition, _selected_pair
        pair = _selected_pair() if isinstance(user, BrowserOwner) else None
        message_id = request.args["message_id"]
        rows = _rows(g.db, select(Message).where(Message.id == message_id, _visibility(user)))
        if not rows:
            abort(404)
        if pair and not g.db.scalar(select(Thread.id).where(Thread.id == rows[0][0].thread_id, _pair_condition(pair))):
            abort(404)
        back_url = (url_for("owner_conversation", thread_id=rows[0][0].thread_id, **_pair_args(pair))
                    if isinstance(user, BrowserOwner) else url_for("inbox"))
        reply_url = (url_for("browser_message", message_id=rows[0][0].reply_to, **_pair_args(pair))
                     if rows[0][0].reply_to else None)
        return render_template("message.html", message=_serialize(g.db, rows)[0], back_url=back_url, reply_url=reply_url)

    @app.get("/files/<artifact_id>/download")
    def browser_file(artifact_id):
        user = _user()
        if not user:
            return redirect(url_for("login"))
        read_file = files.get_overview_artifact if isinstance(user, BrowserOwner) else files.get_artifact
        result = read_file(g.db, app.config, user.id, artifact_id, store=app.extensions.get("object_store"))
        return redirect(result["download_url"])

    from .owner_web import install_owner_web
    install_owner_web(app)

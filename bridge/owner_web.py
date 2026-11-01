"""Read-only owner thread overview and sequence-ordered conversations."""
import math
from datetime import datetime, timezone

from flask import abort, current_app, g, jsonify, make_response, redirect, render_template, request, url_for
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import and_, case, exists, func, select, tuple_
from sqlalchemy.orm import aliased

from . import auth
from .models import Member, Message, Participant, Thread
from .models_auth import BrowserOwner


def _signer():
    return URLSafeSerializer(current_app.secret_key, salt="agent-message-bridge-owner-conversations-v1")


def _arguments(allowed, required=()):
    if (set(request.args) - set(allowed) or not set(required) <= set(request.args)
            or any(len(request.args.getlist(key)) != 1 for key in request.args)):
        abort(400, "Invalid conversation parameters")
    if any(not request.args[key] for key in required):
        abort(400, "A nonempty conversation parameter is required")
    from .web import _page_size
    return _page_size()


def _cursor(user, purpose, direction, anchor, size, thread_id=None, pair=None):
    from .web import _cursor_identity
    return _signer().dumps({"owner": auth.digest(_cursor_identity(user)), "purpose": purpose,
        "direction": direction, "anchor": anchor, "page_size": size, "thread_id": thread_id,
        "pair": list(pair) if pair else None})


def _read_cursor(value, user, purpose, size, thread_id=None, pair=None):
    from .web import _cursor_identity
    try:
        data = _signer().loads(value)
        if (not isinstance(data, dict) or data.get("owner") != auth.digest(_cursor_identity(user))
                or data.get("purpose") != purpose or type(data.get("page_size")) is not int
                or data.get("page_size") != size
                or data.get("thread_id") != thread_id or data.get("pair") != (list(pair) if pair else None)
                or data.get("direction") not in ("older", "newer")):
            raise ValueError
        anchor = data.get("anchor")
        if purpose == "owner-threads":
            if (not isinstance(anchor, list) or len(anchor) != 3 or type(anchor[0]) is not int
                    or anchor[0] not in (0, 1) or type(anchor[1]) not in (int, float)
                    or not math.isfinite(anchor[1]) or not isinstance(anchor[2], str) or not anchor[2]):
                raise ValueError
        elif type(anchor) is not int or not 0 <= anchor <= 2**63-1:
            raise ValueError
        return data["direction"], anchor
    except (BadData, ValueError, TypeError, OverflowError):
        abort(400, "Invalid page cursor")


def _html(template, **context):
    response = make_response(render_template(template, **context))
    response.headers["Content-Security-Policy"] = ("default-src 'none'; img-src 'self'; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    return response


def _participant_names(thread_ids):
    names = {ident: [] for ident in thread_ids}
    if names:
        for ident, name in g.db.execute(select(Member.thread_id, Participant.name)
                .join(Participant, Participant.id == Member.participant_id)
                .where(Member.thread_id.in_(names)).order_by(Member.thread_id, Participant.name, Participant.id)):
            names[ident].append(name)
    return names


def _selected_pair():
    """A pair is unordered; inactive profiles remain selectable for old history."""
    keys = ("participant_a", "participant_b")
    if not any(key in request.args for key in keys):
        return None
    if (not all(key in request.args for key in keys)
            or any(not request.args[key] for key in keys)
            or request.args[keys[0]] == request.args[keys[1]]):
        abort(400, "Choose two different profiles")
    pair = tuple(sorted(request.args[key] for key in keys))
    found = set(g.db.scalars(select(Participant.id).where(Participant.id.in_(pair))))
    if found != set(pair):
        abort(404)
    return pair


def _pair_args(pair):
    return dict(zip(("participant_a", "participant_b"), pair)) if pair else {}


def _pair_condition(pair):
    if pair is None:
        return True
    members = select(func.count()).select_from(Member).where(
        Member.thread_id == Thread.id).correlate(Thread).scalar_subquery()
    return and_(members == 2, *(exists(select(Member.thread_id).where(
        Member.thread_id == Thread.id, Member.participant_id == ident)).correlate(Thread) for ident in pair))


def _messages(rows, *, align=False, pair=None):
    from .web import _serialize
    serialized = _serialize(g.db, rows)
    first_sender = {}
    if align and rows:
        thread_ids = {row.thread_id for row, _, _ in rows}
        for thread_id, participant_id in g.db.execute(select(Member.thread_id, Member.participant_id)
                .where(Member.thread_id.in_(thread_ids))):
            first_sender[thread_id] = min(first_sender.get(thread_id, participant_id), participant_id)
    for message, (row, _, _) in zip(serialized, rows):
        message["sequence"] = row.sequence
        if align:
            message["alternate"] = row.sender_id != first_sender.get(row.thread_id, row.sender_id)
        message["detail_url"] = url_for("browser_message", message_id=row.id, **_pair_args(pair))
        for artifact in message["attachments"]:
            artifact["download_url"] = url_for("browser_file", artifact_id=artifact["id"])
    return serialized


def owner_inbox(user):
    """Page threads by their final sequence's date, then stable descending ID.

    Existing indexes support one final-message lookup per thread. Ordering and
    keyset predicates still scan the thread set: there is no persisted latest
    message date index. Only page messages, memberships and attachments are
    bulk-loaded, never complete message histories or per-row attachment queries.
    """
    from .web import _rows
    if not isinstance(user, BrowserOwner):
        abort(404)
    size = _arguments(("page_size", "cursor", "participant_a", "participant_b"))
    pair = _selected_pair()
    pair_args = _pair_args(pair)
    direction, anchor = None, None
    if "cursor" in request.args:
        direction, anchor = _read_cursor(request.args["cursor"], user, "owner-threads", size, pair=pair)
    final = aliased(Message)
    final_id = (select(Message.id).where(Message.thread_id == Thread.id)
        .order_by(Message.sequence.desc()).limit(1).correlate(Thread).scalar_subquery())
    active = case((final.id.is_not(None), 1), else_=0)
    date = case((final.id.is_not(None), final.created_at), else_=Thread.created_at)
    key = tuple_(active, date, Thread.id)
    statement = select(Thread, final.id, active.label("active"), date.label("sort_date")).outerjoin(
        final, final.id == final_id).where(_pair_condition(pair))
    if anchor is not None:
        statement = statement.where(key > tuple(anchor) if direction == "newer" else key < tuple(anchor))
    columns = (active, date, Thread.id)
    statement = statement.order_by(*(col.asc() if direction == "newer" else col.desc() for col in columns))
    # One extra key detects the next page without another full computed-key
    # scan. Clip before loading any bodies, memberships or attachment metadata.
    rows = g.db.execute(statement.limit(size + 1)).all()
    more_in_direction = len(rows) > size
    rows = rows[:size]
    if direction == "newer":
        rows.reverse()
    latest_ids = [row[1] for row in rows if row[1] is not None]
    latest = {message["message_id"]: message for message in _messages(
        _rows(g.db, select(Message).where(Message.id.in_(latest_ids))) if latest_ids else [])}
    thread_ids = [row[0].id for row in rows]
    names = _participant_names(thread_ids)
    first_id = (select(Message.id).where(Message.thread_id == Thread.id)
        .order_by(Message.sequence.asc()).limit(1).correlate(Thread).scalar_subquery())
    first_text = dict(g.db.execute(select(Thread.id, Message.text).join(Message, Message.id == first_id)
        .where(Thread.id.in_(thread_ids))).all()) if thread_ids else {}
    threads = [{"thread_id": row[0].id, "participant_names": names[row[0].id],
        "last_message": latest.get(row[1]), "first_message_text": first_text.get(row[0].id),
        "created_at": datetime.fromtimestamp(row[0].created_at, timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC"),
        "url": url_for("owner_conversation", thread_id=row[0].id, **pair_args)} for row in rows]
    pagination = {"older_url": None, "newer_url": None}
    if rows:
        for side, row in (("older", rows[-1]), ("newer", rows[0])):
            if direction is None and side == "newer":
                # This is the current first page, so a reverse existence scan
                # cannot reveal an earlier page in the selected result set.
                continue
            boundary = [row[2], row[3], row[0].id]
            if side == (direction or "older"):
                exists = more_in_direction
            else:
                condition = key < tuple(boundary) if side == "older" else key > tuple(boundary)
                exists = g.db.scalar(select(Thread.id).outerjoin(final, final.id == final_id)
                    .where(condition, _pair_condition(pair)).limit(1)) is not None
            if exists:
                pagination[side+"_url"] = url_for("inbox", page_size=size, **pair_args,
                    cursor=_cursor(user, "owner-threads", side, boundary, size, pair=pair))
    profiles = [dict(id=profile.id, name=profile.name, active=profile.active)
        for profile in g.db.scalars(select(Participant).order_by(Participant.name, Participant.id))]
    return _html("owner_threads.html", threads=threads, pagination=pagination, page_size=size,
        profiles=profiles, selected_pair=pair, refresh_url=url_for("inbox", page_size=size, **pair_args),
        all_pairs_url=url_for("inbox", page_size=size))


def _feed_url(user, thread_id, size, direction, anchor, pair=None):
    return url_for("owner_conversation_messages", thread_id=thread_id, page_size=size, **_pair_args(pair),
        cursor=_cursor(user, "owner-conversation", direction, anchor, size, thread_id, pair))


def _page_url(user, thread_id, size, direction, anchor, pair=None):
    return url_for("owner_conversation", thread_id=thread_id, page_size=size, **_pair_args(pair),
        cursor=_cursor(user, "owner-conversation", direction, anchor, size, thread_id, pair))


def _has_messages(thread_id, direction, anchor):
    condition = Message.sequence < anchor if direction == "older" else Message.sequence > anchor
    order = Message.sequence.desc() if direction == "older" else Message.sequence.asc()
    return g.db.scalar(select(Message.sequence).where(Message.thread_id == thread_id, condition)
        .order_by(order).limit(1)) is not None


def install_owner_web(app):
    @app.get("/conversation")
    def owner_conversation():
        from .web import _rows, _user
        user = _user()
        if not user:
            return redirect(url_for("login"))
        if not isinstance(user, BrowserOwner):
            abort(404)
        size = _arguments(("thread_id", "page_size", "cursor", "participant_a", "participant_b"), ("thread_id",))
        pair = _selected_pair()
        thread_id = request.args["thread_id"]
        history_page = "cursor" in request.args
        direction, anchor = None, 0
        if history_page:
            direction, anchor = _read_cursor(request.args["cursor"], user, "owner-conversation", size, thread_id, pair)
        thread = g.db.get(Thread, thread_id)
        if thread is None or (pair and not g.db.scalar(select(Thread.id)
                .where(Thread.id == thread_id, _pair_condition(pair)))):
            abort(404)
        statement = select(Message).where(Message.thread_id == thread_id)
        if history_page:
            statement = statement.where(Message.sequence < anchor if direction == "older" else Message.sequence > anchor)
        order = Message.sequence.asc() if direction == "newer" else Message.sequence.desc()
        rows = _rows(g.db, statement.order_by(order).limit(size))
        if direction != "newer":
            rows.reverse()
        oldest, newest = (rows[0][0].sequence, rows[-1][0].sequence) if rows else (anchor, anchor)
        older_exists = _has_messages(thread_id, "older", oldest)
        newer_exists = _has_messages(thread_id, "newer", newest)
        older_url = (_feed_url(user, thread_id, size, "older", oldest, pair)
            if older_exists else None)
        return _html("owner_conversation.html", thread={"id": thread_id, "thread_id": thread_id,
            "participant_names": _participant_names([thread_id])[thread_id]}, messages=_messages(rows, align=True, pair=pair),
            older_url=older_url, newer_url=_feed_url(user, thread_id, size, "newer", newest, pair), page_size=size,
            older_page_url=_page_url(user, thread_id, size, "older", oldest, pair) if older_exists else None,
            newer_page_url=_page_url(user, thread_id, size, "newer", newest, pair) if newer_exists else None,
            history_page=history_page, selected_pair=pair, list_url=url_for("inbox", **_pair_args(pair)))

    @app.get("/conversation/messages")
    def owner_conversation_messages():
        from .web import _rows, _user
        user = _user()
        if not user:
            return jsonify(error="Authentication required", login_url=url_for("login")), 401
        if not isinstance(user, BrowserOwner):
            abort(404)
        size = _arguments(("thread_id", "page_size", "cursor", "participant_a", "participant_b"), ("thread_id", "cursor"))
        pair = _selected_pair()
        thread_id = request.args["thread_id"]
        direction, anchor = _read_cursor(request.args["cursor"], user, "owner-conversation", size, thread_id, pair)
        if g.db.get(Thread, thread_id) is None or (pair and not g.db.scalar(select(Thread.id)
                .where(Thread.id == thread_id, _pair_condition(pair)))):
            abort(404)
        condition = Message.sequence < anchor if direction == "older" else Message.sequence > anchor
        order = Message.sequence.desc() if direction == "older" else Message.sequence.asc()
        rows = _rows(g.db, select(Message).where(Message.thread_id == thread_id, condition)
            .order_by(order).limit(size))
        if direction == "older":
            rows.reverse()
        oldest, newest = (rows[0][0].sequence, rows[-1][0].sequence) if rows else (anchor, anchor)
        older_exists = _has_messages(thread_id, "older", oldest)
        newer_exists = _has_messages(thread_id, "newer", newest)
        return jsonify(html=render_template("_owner_messages.html", messages=_messages(rows, align=True, pair=pair)),
            older_url=_feed_url(user, thread_id, size, "older", oldest, pair) if older_exists else None,
            newer_url=_feed_url(user, thread_id, size, "newer", newest, pair),
            has_more=older_exists if direction == "older" else newer_exists, message_count=len(rows))

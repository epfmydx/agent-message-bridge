"""Bridge-owned notification worker. Both webhook transports are at least once."""
import logging
import secrets

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import and_, or_, select

from . import events
from .messages import canonical
from .models import Delivery, Member, Message, Participant, Subscription, now
from .transport import CallbackError, post_callback, signed_headers

log = logging.getLogger(__name__)


def deliver_one(sessions, settings, post=None):
    from .auth import family_active
    post = post or post_callback
    with sessions() as db:
        candidate = db.scalar(select(Delivery).where(or_(and_(Delivery.state.in_(["pending", "retry"]), Delivery.available_at <= now()),
                              and_(Delivery.state == "sending", Delivery.lease_until <= now()))).order_by(Delivery.available_at, Delivery.id).limit(1))
        if candidate is None: return False
        ident = candidate.id
        message = db.get(Message, candidate.message_id)
        recipient = db.get(Participant, message.recipient_id, with_for_update=True, populate_existing=True)
        sub = db.get(Subscription, candidate.subscription_id, with_for_update=True, populate_existing=True) if candidate.kind == "mcp" else None
        item = db.get(Delivery, ident, with_for_update=True, populate_existing=True)
        if item.state not in ("pending", "retry", "sending") or item.available_at > now() or (item.state == "sending" and item.lease_until > now()): return True
        from .auth import authorized_user
        allowed = recipient.active and db.get(Member, (message.thread_id, recipient.id)) and authorized_user(db, recipient.id)
        generation = None
        if item.kind == "mcp":
            allowed = allowed and sub and sub.owner_id == recipient.id and sub.active and family_active(db, sub.owner_id, sub.client_id, sub.family)
            if allowed and sub.expires_at is not None and sub.expires_at <= now():
                item.state, item.lease, item.lease_until = "retry", None, None
                item.available_at = now()+30
                db.commit()
                return True
        elif item.kind == "webhook": allowed = allowed and recipient.id == settings["WEBHOOK_PARTICIPANT_ID"]
        else: allowed = False
        if not allowed:
            item.state, item.reason = "stopped", "access_or_subscription_revoked"
            db.commit()
            return True
        if item.kind == "mcp":
            generation = sub.generation
            preview = events.watermark(db, sub, including=item.id)
            body = canonical(events.payload(settings, db, sub, message, item, sequence=preview)).encode()
            cipher = Fernet(settings["ENCRYPTION_KEY"].encode())
            try:
                current = cipher.decrypt(sub.secret.encode()).decode()
            except InvalidToken:
                item.state, item.reason = "stopped", "secret_unreadable"
                item.lease, item.lease_until = None, None
                db.commit()
                log.warning("notification kind=mcp state=stopped reason=secret_unreadable")
                return True
            previous = None
            if sub.previous_secret and sub.rotation_until > now():
                try:
                    previous = cipher.decrypt(sub.previous_secret.encode()).decode()
                except InvalidToken:
                    # Current was verified at subscription; do not turn a broken
                    # overlap signature into a permanent delivery failure.
                    log.warning("notification kind=mcp reason=previous_secret_unreadable")
            headers = signed_headers(current, events.notification(message)["eventId"], body, sub.id, previous_secret=previous)
            callback = sub.callback
        else:
            callback = settings.get("WEBHOOK_URL")
            credential = settings.get("WEBHOOK_TOKEN")
            if not callback or not credential:
                item.state, item.reason, item.available_at = "retry", "webhook_not_configured", now()+30
                db.commit()
                return True
            body = canonical(events.notification(message)).encode()
            headers = {"Content-Type": "application/json", "Authorization": "Bearer "+credential}
        if len(body) > 262144:
            item.state, item.reason = "terminal", "protocol_payload_too_large"
            db.commit()
            return True
        lease, kind, sub_id = secrets.token_hex(16), item.kind, item.subscription_id
        # Never persist a bearer token or full callback URL in diagnostics.
        item.state, item.lease, item.lease_until = "sending", lease, now()+60
        item.attempts += 1
        db.commit()
    status, reason = None, None
    try: status, _ = post(callback, body, headers)
    except CallbackError as exc: reason = exc.reason
    except Exception: reason = "transport_error"
    with sessions() as db:
        sub = db.get(Subscription, sub_id, with_for_update=True, populate_existing=True) if sub_id else None
        item = db.get(Delivery, ident, with_for_update=True, populate_existing=True)
        if not item or item.state != "sending" or item.lease != lease: return True
        item.lease, item.lease_until = None, None
        if sub and (sub.generation != generation or not sub.active):
            item.state, item.reason, item.available_at = "retry" if sub.active else "stopped", "subscription_changed", now()
        elif status is not None and ((kind == "webhook" and status == 200) or (kind == "mcp" and 200 <= status < 300)):
            item.state, item.reason, item.status = "accepted", None, status
            if sub: events.checkpoint(sub, preview)
        elif status is None or status in (408, 425, 429) or status >= 500:
            item.state, item.reason, item.status = "retry", reason or "transient_http", status
            item.available_at = now()+min(2**min(item.attempts, 12), 3600)
        else:
            item.state, item.reason, item.status = "terminal", "callback_rejected", status
            if sub and status == 410: sub.active, sub.generation = False, sub.generation+1
        db.commit()
        log.info("notification kind=%s state=%s status=%s", kind, item.state, status)
    return True

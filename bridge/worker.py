"""Bridge-owned notification worker. Both webhook transports are at least once."""
import logging
import secrets

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import and_, or_, select

from . import events
from .messages import canonical
from .models import DELIVERY_ACTIVE_PREDICATE, Delivery, Member, Message, Participant, Subscription, now
from .transport import CallbackError, post_callback, signed_headers
from . import profile_webhooks

log = logging.getLogger(__name__)


def deliver_one(sessions, settings, post=None):
    from .auth import family_active
    post = post or post_callback
    with sessions() as db:
        candidate = db.scalar(select(Delivery).where(DELIVERY_ACTIVE_PREDICATE,
                              or_(and_(Delivery.state.in_(["pending", "retry"]), Delivery.available_at <= now()),
                              and_(Delivery.state == "sending", Delivery.lease_until <= now()))).order_by(Delivery.available_at, Delivery.id).limit(1))
        if candidate is None: return False
        ident = candidate.id
        message = db.get(Message, candidate.message_id)
        recipient = db.get(Participant, message.recipient_id, with_for_update=True, populate_existing=True)
        sub = db.get(Subscription, candidate.subscription_id, with_for_update=True, populate_existing=True) if candidate.kind == "mcp" else None
        item = db.get(Delivery, ident, with_for_update=True, populate_existing=True)
        if (item.state not in ("pending", "retry", "sending")
                or (item.state in ("pending", "retry") and item.available_at > now())
                or (item.state == "sending" and (item.lease_until is None or item.lease_until > now()))): return True
        from .auth import authorized_user
        allowed = recipient.active and db.get(Member, (message.thread_id, recipient.id)) and authorized_user(db, recipient.id)
        generation, webhook_changed = None, False
        if item.kind == "mcp":
            allowed = allowed and sub and sub.owner_id == recipient.id and sub.active and family_active(db, sub.owner_id, sub.client_id, sub.family)
            if allowed and sub.expires_at is not None and sub.expires_at <= now():
                item.state, item.lease, item.lease_until = "retry", None, None
                item.available_at = now()+30
                db.commit()
                return True
        elif item.kind == "webhook":
            webhook_changed = not profile_webhooks.current_delivery(settings, recipient, item)
            allowed = allowed and not webhook_changed
        else: allowed = False
        if not allowed:
            item.state, item.reason = "stopped", "webhook_changed" if webhook_changed else "access_or_subscription_revoked"
            if webhook_changed:
                item.lease, item.lease_until = None, None
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
            try:
                callback, credential = profile_webhooks.callback(settings, recipient)
            except (InvalidToken, UnicodeDecodeError, AttributeError):
                item.state, item.reason = "stopped", "secret_unreadable"
                item.lease, item.lease_until = None, None
                db.commit()
                return True
            generation = profile_webhooks.generation(recipient)
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
        recipient = db.get(Participant, message.recipient_id, with_for_update=True, populate_existing=True) if kind == "webhook" else None
        item = db.get(Delivery, ident, with_for_update=True, populate_existing=True)
        if not item or item.state != "sending" or item.lease != lease: return True
        item.lease, item.lease_until = None, None
        if recipient and (profile_webhooks.generation(recipient) != generation
                          or not profile_webhooks.current_delivery(settings, recipient, item)):
            item.state, item.reason, item.status = "stopped", "webhook_changed", status
        elif sub and (sub.generation != generation or not sub.active):
            item.state, item.reason, item.available_at = "retry" if sub.active else "stopped", "subscription_changed", now()
        elif status is not None and ((kind == "webhook" and status == 200) or (kind == "mcp" and 200 <= status < 300)):
            item.state, item.reason, item.status = "accepted", None, status
            if sub: events.checkpoint(sub, preview)
        elif kind == "webhook" and reason == "invalid_destination":
            item.state, item.reason, item.status = "terminal", "invalid_destination", None
        elif status is None or status in (408, 425, 429) or status >= 500:
            item.state, item.reason, item.status = "retry", reason or "transient_http", status
            item.available_at = now()+min(2**min(item.attempts, 12), 3600)
        else:
            item.state, item.reason, item.status = "terminal", "callback_rejected", status
            if sub and status == 410: sub.active, sub.generation = False, sub.generation+1
        db.commit()
        log.info("notification kind=%s state=%s status=%s", kind, item.state, status)
    return True

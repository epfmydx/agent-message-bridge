"""Recipient-scoped MCP Events, durable replay and signed cursors."""
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import case, select, update

from .errors import Invalid
from .messages import canonical, nonempty, participant, timestamp
from .models import Delivery, Message, Subscription, now
from .transport import secret_bytes

EVENT_NAME = "bridge.message.received"


def identity(token, callback):
    return hashlib.sha256(canonical([token.owner_id, token.client_id, callback, EVENT_NAME, {}]).encode()).hexdigest()


def cursor(settings, sub, sequence):
    body = canonical([sub.id, sequence]).encode()
    return base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + hmac.new(settings["SECRET_KEY"].encode(), body, hashlib.sha256).hexdigest()


def parse_cursor(settings, value, sub_id):
    try:
        encoded, signature = value.split(".")
        body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        ident, seq = json.loads(body)
        expected = hmac.new(settings["SECRET_KEY"].encode(), body, hashlib.sha256).hexdigest()
        if ident != sub_id or not hmac.compare_digest(signature, expected) or type(seq) is not int or seq < 0: raise ValueError()
        return seq
    except (TypeError, ValueError, AttributeError, UnicodeError): raise Invalid("Invalid replay cursor") from None


# Internal fetch batch, never a cursor/history or delivery limit.
WATERMARK_BATCH_SIZE = 256


def watermark(db, sub, including=None):
    # Older writers bump generation on replay but do not maintain these caches.
    sequence = (sub.acknowledged_sequence if sub.acknowledged_generation == sub.generation
                and sub.acknowledged_sequence is not None else sub.start_sequence)
    while True:
        # Bound the ordered message range before evaluating progress. A point
        # subquery uses the subscription/message index for each candidate; a
        # joined tail could still hash/sort the full history before its LIMIT.
        state = case((Delivery.id == including, "accepted"), else_=Delivery.state) if including is not None else Delivery.state
        progress = select(state).where(Delivery.subscription_id == sub.id, Delivery.message_id == Message.id)\
            .correlate(Message).limit(1).scalar_subquery()
        rows = list(db.execute(select(Message.recipient_sequence, progress)
                    .where(Message.recipient_id == sub.owner_id, Message.recipient_sequence > sequence)
                    .order_by(Message.recipient_sequence).limit(WATERMARK_BATCH_SIZE)))
        for seq, state in rows:
            if seq != sequence + 1 or state != "accepted": return sequence
            sequence = seq
        if len(rows) < WATERMARK_BATCH_SIZE: return sequence


def checkpoint(sub, sequence):
    """Confirm a computed preview after lease/generation-fenced acceptance.

    No second history query is needed: without a generation change, previously
    accepted rows cannot revert. Concurrent accepts can only extend the prefix.
    Keep an already-confirmed newer cache; a later watermark read catches up a
    concurrently accepted suffix. A replay resets the generation and cache in
    its own transaction, so an old preview must never reach this function.
    """
    if (sub.acknowledged_generation != sub.generation or sub.acknowledged_sequence is None
            or sequence > sub.acknowledged_sequence):
        sub.acknowledged_sequence = sequence
    sub.acknowledged_generation = sub.generation


def params_checked(params):
    if not isinstance(params, dict) or params.get("name") != EVENT_NAME or params.get("arguments", {}) != {}: raise Invalid("Expected bridge.message.received with empty arguments")
    delivery = params.get("delivery")
    if not isinstance(delivery, dict) or delivery.get("mode") != "webhook": raise Invalid("Webhook delivery is required")
    return nonempty(delivery.get("url")), delivery


def subscribe(db, settings, params, token, verify, revalidate):
    callback, delivery = params_checked(params)
    participant(db, token.owner_id)
    ident = identity(token, callback)
    seq = None if params.get("cursor") is None else parse_cursor(settings, params["cursor"], ident)
    ttl = params.get("ttlMs", 86_400_000)
    if ttl is not None and (type(ttl) is not int or ttl <= 0): raise Invalid("ttlMs must be positive or null")
    secret = delivery.get("secret")
    try: secret_bytes(secret)
    except ValueError: raise Invalid("Invalid webhook signing secret") from None
    # Callback verification owns no SQL transaction/lock. Recheck identity after it.
    db.rollback()
    verify(callback, secret, ident)
    token = revalidate()
    participant(db, token.owner_id, lock=True)
    sub = db.get(Subscription, ident, with_for_update=True, populate_existing=True)
    cipher = Fernet(settings["ENCRYPTION_KEY"].encode())
    encrypted = cipher.encrypt(secret.encode()).decode()
    if sub is None:
        if seq is not None: raise Invalid("Replay subscription is unavailable")
        # Sequenced inbox messages remain available before first connection.
        # Historical silent messages have NULL sequences and stay excluded.
        sub = Subscription(id=ident, owner_id=token.owner_id, client_id=token.client_id, family=token.family,
                           callback=callback, secret=encrypted, start_sequence=0, generation=1, active=True, rotation_until=0,
                           acknowledged_sequence=0, acknowledged_generation=1)
        db.add(sub)
        db.flush()
    else:
        confirmed = watermark(db, sub)
        if seq is not None and not sub.start_sequence <= seq <= confirmed: raise Invalid("Replay cursor is ahead of acknowledged delivery")
        if seq is not None:
            replay = select(Message.id).where(Message.recipient_id == sub.owner_id, Message.recipient_sequence > seq)
            db.execute(update(Delivery).where(Delivery.subscription_id == sub.id, Delivery.state == "accepted", Delivery.message_id.in_(replay))
                       .values(state="pending", reason="cursor_replay", available_at=now()))
        try:
            previous = cipher.decrypt(sub.secret.encode()).decode()
        except InvalidToken:
            previous = None
            sub.previous_secret, sub.rotation_until = None, 0
        if previous is not None and not hmac.compare_digest(previous, secret):
            sub.previous_secret, sub.rotation_until = sub.secret, now()+300
        elif sub.previous_secret:
            try:
                cipher.decrypt(sub.previous_secret.encode())
            except InvalidToken:
                sub.previous_secret, sub.rotation_until = None, 0
        sub.secret, sub.family, sub.active, sub.generation = encrypted, token.family, True, sub.generation+1
        sub.acknowledged_sequence = seq if seq is not None else confirmed
        sub.acknowledged_generation = sub.generation
        # A newly authorized reconnect revives queued work stopped by the old
        # connection. Permanent HTTP failures still require operator recovery.
        db.execute(update(Delivery).where(Delivery.subscription_id == sub.id, Delivery.state == "stopped")
                   .values(state="pending", reason="subscription_resumed", available_at=now()))
    queued = select(Delivery.message_id).where(Delivery.subscription_id == sub.id)
    for message in db.scalars(select(Message).where(Message.recipient_id == sub.owner_id,
                                                  Message.recipient_sequence > sub.start_sequence, Message.id.not_in(queued))):
        db.add(Delivery(message_id=message.id, kind="mcp", destination="mcp:"+sub.id, subscription_id=sub.id))
    sub.expires_at = None if ttl is None else now()+ttl/1000
    db.flush()
    return {"id": sub.id, "refreshBefore": None if sub.expires_at is None else timestamp(sub.expires_at),
            "cursor": cursor(settings, sub, watermark(db, sub)), "truncated": False}


def unsubscribe(db, params, token):
    callback, _ = params_checked(params)
    participant(db, token.owner_id, lock=True)
    sub = db.get(Subscription, identity(token, callback), with_for_update=True, populate_existing=True)
    if sub: sub.active, sub.generation = False, sub.generation+1
    return {}


def notification(message, checkpoint=None):
    return {"eventId": str(uuid.uuid5(uuid.NAMESPACE_URL, "agent-message-bridge:message:"+message.id)), "name": EVENT_NAME,
            "timestamp": timestamp(message.created_at), "data": {"message_id": message.id, "thread_id": message.thread_id,
            "sender": message.sender_id, "recipient": message.recipient_id, "status": message.status, "needs_reply": message.needs_reply}, "cursor": checkpoint}


def payload(settings, db, sub, message, delivery, sequence=None):
    if sequence is None: sequence = watermark(db, sub, including=delivery.id)
    return notification(message, cursor(settings, sub, sequence))

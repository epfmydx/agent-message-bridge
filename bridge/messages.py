"""Immutable shared messages with authenticated authors and recipient-only wakes."""
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import or_, select

from .errors import Conflict, Invalid, Unavailable
from .models import Artifact, Delivery, Member, Message, MessageArtifact, Participant, Subscription, Thread, WorkClaim, now, uid

STATUSES = ("received", "working", "completed", "needs_input")


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def timestamp(value): return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def nonempty(value):
    if not isinstance(value, str) or not value.strip(): raise Invalid("A nonempty identifier is required")
    return value


def participant(db, ident, lock=False):
    row = db.get(Participant, nonempty(ident), with_for_update=lock, populate_existing=True)
    if not row or not row.active: raise Unavailable("Participant is unavailable")
    return row


def thread_access(db, owner, thread_id, lock=False):
    participant(db, owner)
    thread = db.get(Thread, nonempty(thread_id), with_for_update=lock, populate_existing=True)
    if not thread or not db.get(Member, (thread.id, owner)): raise Unavailable("Thread is unavailable")
    return thread


def message_access(db, owner, ident):
    row = db.get(Message, nonempty(ident))
    if not row: raise Unavailable("Message is unavailable")
    thread_access(db, owner, row.thread_id)
    return row


def serialize(db, row, attachments=None):
    if attachments is None: attachments = list(db.scalars(select(MessageArtifact.artifact_id).where(MessageArtifact.message_id == row.id).order_by(MessageArtifact.artifact_id)))
    return {"message_id": row.id, "thread_id": row.thread_id, "sender": row.sender_id, "recipient": row.recipient_id,
            "reply_to": row.reply_to, "text": row.text, "status": row.status, "needs_reply": row.needs_reply,
            "attachment_ids": attachments, "sequence": row.sequence, "created_at": timestamp(row.created_at)}


def get_message(db, owner, ident): return serialize(db, message_access(db, owner, ident))


def send_message(db, settings, owner, params):
    if not isinstance(params, dict): raise Invalid("Expected a message object")
    fields = {"message_id", "thread_id", "recipient", "reply_to", "text", "status", "needs_reply", "attachment_ids"}
    if set(params) - fields: raise Invalid("Unknown message fields; sender comes from authentication")
    ident, recipient_id = nonempty(params.get("message_id")), nonempty(params.get("recipient"))
    if recipient_id == owner: raise Invalid("Address the other participant")
    if type(params.get("needs_reply")) is not bool: raise Invalid("needs_reply must be an explicit boolean")
    status = params.get("status")
    if status not in STATUSES: raise Invalid("Expected received, working, completed or needs_input status")
    text = params.get("text", "")
    attachments = params.get("attachment_ids", [])
    if not isinstance(text, str) or not isinstance(attachments, list) or any(not isinstance(a, str) or not a for a in attachments) or len(set(attachments)) != len(attachments):
        raise Invalid("Invalid text or attachment references")
    if not text.strip() and not attachments: raise Invalid("Message text or a file is required")
    thread_id, reply_to = params.get("thread_id"), params.get("reply_to")
    if thread_id is not None: nonempty(thread_id)
    if reply_to is not None: nonempty(reply_to)
    # Both sender idempotency and recipient event sequences are serialized.
    for p in sorted({owner, recipient_id}): participant(db, p, lock=True)
    fingerprint = hashlib.sha256(canonical([recipient_id, thread_id, reply_to, text, status, params["needs_reply"], sorted(attachments)]).encode()).hexdigest()
    prior = db.get(Message, ident)
    if prior:
        if prior.sender_id != owner or prior.fingerprint != fingerprint: raise Conflict("Message identity has conflicting content")
        return {**serialize(db, prior), "duplicate": True}
    if thread_id is None:
        if reply_to is not None: raise Invalid("A reply requires its thread_id")
        thread = Thread(id=uid(), sequence=0)
        db.add(thread)
        db.flush()
        db.add_all([Member(thread_id=thread.id, participant_id=p) for p in (owner, recipient_id)])
    else:
        thread = thread_access(db, owner, thread_id, lock=True)
        if not db.get(Member, (thread.id, recipient_id)): raise Unavailable("Recipient does not share this thread")
    if reply_to:
        reply = message_access(db, owner, reply_to)
        if reply.thread_id != thread.id: raise Invalid("Reply must belong to the same thread")
    for ident_file in attachments:
        artifact = db.get(Artifact, ident_file, with_for_update=True, populate_existing=True)
        if not artifact or artifact.state != "ready": raise Unavailable("Attachment is unavailable or not ready")
        if artifact.owner_id != owner:
            shared = db.scalar(select(MessageArtifact.message_id).join(Message, Message.id == MessageArtifact.message_id)
                               .where(MessageArtifact.artifact_id == artifact.id, Message.thread_id == thread.id))
            if not shared: raise Unavailable("Attachment is not shared in this thread")
    thread.sequence += 1
    recipient = participant(db, recipient_id)
    # Every new inbox message is eligible for MCP receipt notifications. Retain
    # NULL sequences on historical silent messages so catch-up cannot wake them.
    recipient.sequence += 1
    row = Message(id=ident, thread_id=thread.id, sender_id=owner, recipient_id=recipient_id, reply_to=reply_to, text=text,
                  status=status, needs_reply=params["needs_reply"], sequence=thread.sequence,
                  recipient_sequence=recipient.sequence, fingerprint=fingerprint, created_at=now())
    db.add(row)
    db.flush()
    db.add_all([MessageArtifact(message_id=row.id, artifact_id=a) for a in attachments])
    for sub in db.scalars(select(Subscription).where(Subscription.owner_id == recipient_id, Subscription.active.is_(True),
                         or_(Subscription.expires_at.is_(None), Subscription.expires_at > now()))):
        db.add(Delivery(message_id=row.id, kind="mcp", destination="mcp:"+sub.id, subscription_id=sub.id))
    # Profile bearer callbacks keep their existing actionable-only contract.
    if row.needs_reply:
        from .profile_webhooks import generation, should_notify
        if should_notify(settings, recipient):
            kind = "webhook"
            db.add(Delivery(message_id=row.id, kind=kind, destination=kind+":"+recipient_id,
                            webhook_generation=generation(recipient)))
    db.flush()
    return {**serialize(db, row), "duplicate": False}


def list_messages(db, owner, params):
    thread = thread_access(db, owner, params.get("thread_id"))
    after, batch = params.get("after_sequence", 0), params.get("page_size", 100)
    if type(after) is not int or after < 0 or type(batch) is not int or batch <= 0: raise Invalid("Invalid pagination")
    rows = list(db.scalars(select(Message).where(Message.thread_id == thread.id, Message.sequence > after).order_by(Message.sequence).limit(batch+1)))
    selected = rows[:batch]
    attachments = {row.id: [] for row in selected}
    if selected:
        for message_id, artifact_id in db.execute(select(MessageArtifact.message_id, MessageArtifact.artifact_id)
                .join(Message, Message.id == MessageArtifact.message_id)
                .where(Message.thread_id == thread.id, Message.sequence > after,
                       Message.sequence <= selected[-1].sequence).order_by(MessageArtifact.artifact_id)):
            attachments[message_id].append(artifact_id)
    return {"messages": [serialize(db, row, attachments[row.id]) for row in selected], "next_sequence": selected[-1].sequence if len(rows) > batch else None}


def list_threads(db, owner):
    participant(db, owner)
    return {"threads": [{"thread_id": t.id, "created_at": timestamp(t.created_at), "sequence": t.sequence}
                        for t in db.scalars(select(Thread).join(Member).where(Member.participant_id == owner).order_by(Thread.created_at, Thread.id))]}


def claim_message(db, owner, params):
    row = message_access(db, owner, params.get("message_id"))
    if row.recipient_id != owner: raise Invalid("Only the addressed recipient can claim actionable work")
    if not row.needs_reply: raise Invalid("This message is informational and cannot be claimed")
    participant(db, owner, lock=True)
    claim_id = nonempty(params.get("claim_id"))
    prior = db.get(WorkClaim, row.id, with_for_update=True, populate_existing=True)
    if prior is None:
        db.add(WorkClaim(message_id=row.id, claim_id=claim_id))
        return {"message_id": row.id, "acquired": True, "resumed": False}
    return {"message_id": row.id, "acquired": prior.claim_id == claim_id, "resumed": prior.claim_id == claim_id}

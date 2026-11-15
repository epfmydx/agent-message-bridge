"""Immutable shared messages with authenticated authors and recipient-only wakes."""
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import and_, exists, or_, select

from .errors import Conflict, Invalid, Unavailable
from .identities import load_identities, message_identity_fields, public_identity
from .models_auth import BrowserOwner
from .models import Artifact, BotAllowlist, Delivery, Member, Message, MessageArtifact, Participant, Subscription, Thread, WorkClaim, now, uid

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


def reachable(sender, recipient):
    return or_(recipient.owner_account_id == sender.owner_account_id,
               recipient.reachability_policy == "open",
               and_(recipient.reachability_policy == "allowlist", exists(select(BotAllowlist.sender_id).where(
                   BotAllowlist.receiver_id == recipient.id, BotAllowlist.sender_id == sender.id))))


def list_participants(db, owner):
    sender = participant(db, owner)
    return {"participants": [public_identity(ident, name, owner_name) for ident, name, owner_name in db.execute(
        select(Participant.id, Participant.name, BrowserOwner.name)
        .join(BrowserOwner, BrowserOwner.id == Participant.owner_account_id).where(
        Participant.active.is_(True), Participant.id != owner, reachable(sender, Participant)).order_by(Participant.id))]}


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


def serialize(db, row, attachments=None, identities=None):
    if identities is None: identities = load_identities(db, (row.sender_id, row.recipient_id))
    if attachments is None: attachments = list(db.scalars(select(MessageArtifact.artifact_id).where(MessageArtifact.message_id == row.id).order_by(MessageArtifact.artifact_id)))
    return {"message_id": row.id, "thread_id": row.thread_id, "sender": row.sender_id, "recipient": row.recipient_id,
            **message_identity_fields(identities[row.sender_id], identities[row.recipient_id]),
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
    fingerprint = hashlib.sha256(canonical([recipient_id, thread_id, reply_to, text, status, params["needs_reply"], sorted(attachments)]).encode()).hexdigest()
    sender = participant(db, owner)
    exact_retry = exists(select(Message.id).where(Message.id == ident, Message.sender_id == owner,
                                                 Message.fingerprint == fingerprint))
    prior_reply = False
    if thread_id is not None:
        # Membership and a message in this exact thread grant only reply access.
        prior_reply = and_(exists(select(Member.thread_id).where(Member.thread_id == thread_id, Member.participant_id == owner)),
            exists(select(Member.thread_id).where(Member.thread_id == thread_id, Member.participant_id == recipient_id)),
            exists(select(Message.id).where(Message.thread_id == thread_id, Message.sender_id == recipient_id)))
    eligible = db.scalar(select(Participant.id).where(Participant.id == recipient_id,
        Participant.active.is_(True), or_(reachable(sender, Participant), prior_reply, exact_retry)))
    if eligible is None:
        raise Unavailable("Recipient is unavailable")
    # Only eligible recipients enter the sorted lock path. Recheck policy below
    # after locks, so a concurrent revocation cannot authorize a new send.
    locked = {}
    for p in sorted({owner, recipient_id}):
        row = db.get(Participant, p, with_for_update=True, populate_existing=True)
        if not row or not row.active:
            raise Unavailable("Recipient is unavailable" if p == recipient_id else "Participant is unavailable")
        locked[p] = row
    prior = db.get(Message, ident)
    if prior and prior.sender_id == owner and prior.fingerprint == fingerprint:
        return {**serialize(db, prior), "duplicate": True}
    sender, receiver = locked[owner], locked[recipient_id]
    thread = None
    if thread_id is not None:
        try:
            thread = thread_access(db, owner, thread_id, lock=True)
        except Unavailable:
            raise Unavailable("Recipient is unavailable") from None
        if not db.get(Member, (thread.id, recipient_id)):
            raise Unavailable("Recipient is unavailable")
    accepts = db.scalar(select(Participant.id).where(Participant.id == receiver.id, reachable(sender, Participant)))
    wrote_here = not accepts and thread is not None and db.scalar(select(Message.id).where(
        Message.thread_id == thread.id, Message.sender_id == recipient_id).limit(1)) is not None
    if not accepts and not wrote_here:
        raise Unavailable("Recipient is unavailable")
    if prior:
        raise Conflict("Message identity has conflicting content")
    if thread is None:
        if reply_to is not None: raise Invalid("A reply requires its thread_id")
        thread = Thread(id=uid(), sequence=0)
        db.add(thread)
        db.flush()
        db.add_all([Member(thread_id=thread.id, participant_id=p) for p in (owner, recipient_id)])
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
            db.add(Delivery(message_id=row.id, kind="webhook", destination="webhook:"+recipient_id,
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
    identities = load_identities(db, {ident for row in selected for ident in (row.sender_id, row.recipient_id)})
    return {"messages": [serialize(db, row, attachments[row.id], identities) for row in selected], "next_sequence": selected[-1].sequence if len(rows) > batch else None}


def list_threads(db, owner):
    participant(db, owner)
    rows = list(db.scalars(select(Thread).join(Member).where(Member.participant_id == owner).order_by(Thread.created_at, Thread.id)))
    owned_threads = select(Member.thread_id).where(Member.participant_id == owner)
    members = {t.id: [] for t in rows}
    if rows:
        for thread_id, ident, name, owner_name, deactivated_at in db.execute(
                select(Member.thread_id, Participant.id, Participant.name, BrowserOwner.name, Participant.deactivated_at)
                .join(Participant, Participant.id == Member.participant_id)
                .join(BrowserOwner, BrowserOwner.id == Participant.owner_account_id)
                .where(Member.thread_id.in_(owned_threads)).order_by(Member.thread_id, Participant.id)):
            members[thread_id].append(public_identity(ident, name, owner_name, deactivated_at))
    return {"threads": [{"thread_id": t.id, "created_at": timestamp(t.created_at), "sequence": t.sequence,
                         "participants": members[t.id]} for t in rows]}


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

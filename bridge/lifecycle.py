"""Irreversible retirement and a cross-process outbound transport fence."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile

from sqlalchemy import select, text, update

from .auth import deactivate_subscriptions
from .credentials import revoke_password_connections, revoke_service_keys
from .errors import Unavailable
from .models import Delivery, Message, Participant, now
from .models_auth import User


@contextmanager
def delivery_fence(db, ident, *, shared=False):
    """Take this before profile/participant locks; retain through commit/transport.

    PostgreSQL transaction advisory locks coordinate API and worker processes.
    SQLite's local file locks serve the same purpose without holding a write
    transaction over transport. Lock files contain no account or message data.
    """
    if db.bind.dialect.name == "postgresql":
        function = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
        db.execute(text("SELECT " + function + "(hashtextextended("
            "current_database() || ':' || current_schema() || :purpose, 0))"),
            {"purpose": ":agent-message-bridge-dispatch:" + ident})
        yield
    else:
        import fcntl
        key = hashlib.sha256((str(db.bind.url) + ":" + ident).encode()).hexdigest()
        path = Path(tempfile.gettempdir()) / ("agent-message-bridge-dispatch-" + key + ".lock")
        with path.open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


def deactivate_bot(db, owner_id, ident):
    """Caller holds the exclusive dispatch fence and profile-change lock."""
    participant = db.scalar(select(Participant).where(Participant.id == ident,
        Participant.owner_account_id == owner_id).with_for_update().execution_options(populate_existing=True))
    if not participant or not participant.active or participant.deactivated_at is not None:
        raise Unavailable("Profile is unavailable")
    user = db.scalar(select(User).where(User.id == ident).with_for_update(key_share=True)
        .execution_options(populate_existing=True))
    if not user:
        raise Unavailable("Profile is unavailable")
    participant.active, participant.deactivated_at = False, now()
    participant.webhook_enabled = False
    participant.webhook_url, participant.webhook_token = None, None
    participant.webhook_generation += 1
    user.active, user.password_hash = False, ""
    user.credential_generation += 1
    revoke_service_keys(db, user)
    revoke_password_connections(db, user)
    deactivate_subscriptions(db, owner_id=ident)
    db.execute(update(Delivery).where(Delivery.message_id.in_(select(Message.id).where(
        Message.recipient_id == ident)), Delivery.state.in_(("pending", "retry", "sending")))
        .values(state="stopped", reason="participant_deactivated", lease=None, lease_until=None))
    db.flush()

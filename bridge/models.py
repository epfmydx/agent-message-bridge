"""Bridge-owned conversation, artifact and durable delivery records."""
import time
import uuid

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now(): return time.time()
def uid(): return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Participant(Base):
    __tablename__ = "participants"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    managed_source: Mapped[str] = mapped_column(String, default="config", server_default="config")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    # NULL retains the deployment-provided callback for its legacy recipient.
    # False is an explicit override and must never fall back to that callback.
    webhook_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    webhook_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    webhook_generation: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class Thread(Base):
    __tablename__ = "threads"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[float] = mapped_column(Float, default=now)


class Member(Base):
    __tablename__ = "thread_members"
    thread_id: Mapped[str] = mapped_column(ForeignKey("threads.id"), primary_key=True)
    participant_id: Mapped[str] = mapped_column(ForeignKey("participants.id"), primary_key=True)


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("thread_id", "sequence"), UniqueConstraint("recipient_id", "recipient_sequence"))
    id: Mapped[str] = mapped_column(String, primary_key=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("threads.id"), index=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("participants.id"))
    recipient_id: Mapped[str] = mapped_column(ForeignKey("participants.id"), index=True)
    reply_to: Mapped[str | None] = mapped_column(ForeignKey("messages.id"), nullable=True)
    text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String)
    needs_reply: Mapped[bool] = mapped_column(Boolean)
    sequence: Mapped[int] = mapped_column(Integer)
    recipient_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String)
    created_at: Mapped[float] = mapped_column(Float, default=now)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("owner_id", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("participants.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String)
    input_fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    object_key: Mapped[str] = mapped_column(String, unique=True)
    filename: Mapped[str] = mapped_column(Text)
    content_type: Mapped[str] = mapped_column(String)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String)
    state: Mapped[str] = mapped_column(String, default="pending")
    lease: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=now)


class MessageArtifact(Base):
    __tablename__ = "message_artifacts"
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), primary_key=True)


# Browser ordering is independent of the API's durable per-thread sequence.
BROWSER_INDEXES = (
    Index("ix_thread_members_participant_thread", Member.participant_id, Member.thread_id),
    Index("ix_messages_created_id", Message.created_at.desc(), Message.id.desc()),
    Index("ix_messages_thread_created_id", Message.thread_id, Message.created_at.desc(), Message.id.desc()),
)


class WorkClaim(Base):
    __tablename__ = "work_claims"
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String)
    claimed_at: Mapped[float] = mapped_column(Float, default=now)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("participants.id"), index=True)
    client_id: Mapped[str] = mapped_column(String)
    family: Mapped[str] = mapped_column(String)
    callback: Mapped[str] = mapped_column(Text)
    secret: Mapped[str] = mapped_column(Text)
    previous_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    rotation_until: Mapped[float] = mapped_column(Float, default=0)
    expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    start_sequence: Mapped[int] = mapped_column(Integer)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    # Nullable caches keep inserts by older versions compatible after upgrade.
    acknowledged_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    acknowledged_generation: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Delivery(Base):
    __tablename__ = "deliveries"
    __table_args__ = (UniqueConstraint("message_id", "destination"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    kind: Mapped[str] = mapped_column(String)
    destination: Mapped[str] = mapped_column(String)
    subscription_id: Mapped[str | None] = mapped_column(ForeignKey("subscriptions.id"), nullable=True)
    # NULL is generation 1 only for retained legacy bearer webhook deliveries.
    webhook_generation: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[float] = mapped_column(Float, default=now, index=True)
    lease: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)


# Keep this predicate literal in both the index and worker query so PostgreSQL
# can use the partial index with either custom or generic prepared plans.
DELIVERY_ACTIVE_PREDICATE = text("state IN ('pending', 'retry', 'sending')")

DELIVERY_INDEXES = (
    Index("ix_deliveries_subscription_message", Delivery.subscription_id, Delivery.message_id),
    Index("ix_deliveries_due", Delivery.available_at, Delivery.id,
          sqlite_where=DELIVERY_ACTIVE_PREDICATE, postgresql_where=DELIVERY_ACTIVE_PREDICATE),
)


def database(url):
    kwargs = {"pool_pre_ping": True, "hide_parameters": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        from sqlalchemy import event
        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _): connection.execute("PRAGMA foreign_keys=ON")
    return engine, sessionmaker(engine, expire_on_commit=False)

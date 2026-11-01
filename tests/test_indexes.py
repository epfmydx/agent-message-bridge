"""Fresh and existing-schema browser index upgrades on each test database."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import inspect, select, text, tuple_
from sqlalchemy.orm import aliased

from bridge.models import BROWSER_INDEXES, Member, Message, Participant, Thread
from bridge.schema import ensure_browser_indexes
from bridge.web import _scope


def index_names(engine, table):
    return {index["name"] for index in inspect(engine).get_indexes(table)}


def test_fresh_and_existing_table_index_upgrade(bridge_app):
    engine = bridge_app.extensions["engine"]
    for index in BROWSER_INDEXES:
        assert index.name in index_names(engine, index.table.name)
        index.drop(engine)
    # create_all intentionally skips existing tables; explicit upgrade repairs it.
    ensure_browser_indexes(engine)
    ensure_browser_indexes(engine)
    for index in BROWSER_INDEXES:
        assert index.name in index_names(engine, index.table.name)
    constraints = inspect(engine).get_unique_constraints(Message.__tablename__)
    assert any(c["column_names"] == ["thread_id", "sequence"] for c in constraints)
    reverse = next(i for i in inspect(engine).get_indexes(Member.__tablename__)
                   if i["name"] == "ix_thread_members_participant_thread")
    assert reverse["column_names"] == ["participant_id", "thread_id"]


def test_postgres_concurrent_init_and_invalid_index_recovery(bridge_app):
    engine = bridge_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires disposable PostgreSQL test database")
    for index in BROWSER_INDEXES:
        index.drop(engine)
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda _: ensure_browser_indexes(engine), range(2)))
    with bridge_app.extensions["sessions"].begin() as db:
        db.add(Thread(id="invalid-index-test"))
        db.flush()
        db.add_all([Message(id=f"invalid-index-message-{i}", thread_id="invalid-index-test", sender_id="agent-b",
            recipient_id="agent-a", text="Synthetic index retry", status="completed", needs_reply=False,
            sequence=i+1, fingerprint=f"invalid-index-{i}", created_at=1704067200) for i in range(2)])
    # Create a deliberately failed concurrent unique index, using our owned
    # name, to simulate an interrupted/failed build on an existing database.
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql("DROP INDEX CONCURRENTLY ix_messages_created_id")
        with pytest.raises(Exception):
            connection.exec_driver_sql("CREATE UNIQUE INDEX CONCURRENTLY ix_messages_created_id ON messages (created_at)")
        assert connection.scalar(text("SELECT indisvalid FROM pg_index WHERE indexrelid = 'ix_messages_created_id'::regclass")) is False
    ensure_browser_indexes(engine)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT indisvalid FROM pg_index WHERE indexrelid = 'ix_messages_created_id'::regclass")) is True


def test_postgres_representative_browser_explain(bridge_app):
    """Record real planner choices; no forced scan settings or timing promises."""
    engine = bridge_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires disposable PostgreSQL test database")
    with engine.begin() as connection:
        connection.execute(Thread.__table__.insert(), [{"id": f"explain-thread-{i}"} for i in range(2000)])
        connection.execute(Member.__table__.insert(), [
            {"thread_id": f"explain-thread-{i}", "participant_id": "agent-b" if i % 2 else "intruder"}
            for i in range(2000)])
        connection.execute(Message.__table__.insert(), [{
            "id": f"explain-message-{i:06d}", "thread_id": f"explain-thread-{i % 2000 if i < 20000 else 1}",
            "sender_id": "agent-a", "recipient_id": "agent-b" if i % 2 else "intruder",
            "text": "Synthetic planner sample", "status": "completed", "needs_reply": False,
            "sequence": i+1, "fingerprint": f"explain-{i}", "created_at": 1704067200+i//2}
            for i in range(24000)])
        connection.exec_driver_sql("ANALYZE messages")
        connection.exec_driver_sql("ANALYZE thread_members")
        sender, recipient = aliased(Participant), aliased(Participant)
        base = select(Message, sender.name, recipient.name).join(sender, sender.id == Message.sender_id)\
            .join(recipient, recipient.id == Message.recipient_id).where(_scope("agent-b"))
        statements = {
            "owner-inbox": select(Message).order_by(Message.created_at.desc(), Message.id.desc()).limit(25),
            "inbox-first": base.order_by(Message.created_at.desc(), Message.id.desc()).limit(25),
            "inbox-deep": base.where(tuple_(Message.created_at, Message.id) <
                (1704073200, "explain-message-012000")).order_by(Message.created_at.desc(), Message.id.desc()).limit(25),
            "thread-date": select(Message.id).where(Message.thread_id == "explain-thread-1")
                .order_by(Message.created_at.desc(), Message.id.desc()).limit(25),
            "membership": select(Member.thread_id).where(Member.participant_id == "agent-b"),
        }
        for name, statement in statements.items():
            sql = str(statement.compile(dialect=engine.dialect, compile_kwargs={"literal_binds": True}))
            plan = connection.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql).scalar_one()[0]
            nodes = []
            def walk(node):
                nodes.append(node)
                for child in node.get("Plans", []):
                    walk(child)
            walk(plan["Plan"])
            print(name, {"execution_ms": plan["Execution Time"], "rows": plan["Plan"]["Actual Rows"],
                         "indexes": [node["Index Name"] for node in nodes if "Index Name" in node],
                         "nodes": [node["Node Type"] for node in nodes],
                         "shared_hits": plan["Plan"]["Shared Hit Blocks"]})
            count = len(connection.execute(statement).all())
            assert count == (1000 if name == "membership" else 25)

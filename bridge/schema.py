"""Explicit schema upgrades for fresh and existing bridge databases."""
import time

from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateIndex

from .models import BROWSER_INDEXES, DELIVERY_INDEXES
from .models_auth import APIKey, CredentialOperation, LoginRate


def _ensure_indexes(engine, indexes, purpose):
    """Build owned indexes, without blocking PostgreSQL message writes.

    Call after metadata.create_all, outside a transaction. PostgreSQL concurrent
    builds use an autocommit connection and a session advisory lock scoped to
    the database/schema, serializing repeated init jobs. A failed concurrent
    build can leave an invalid index; only our named invalid indexes are dropped
    and rebuilt. SQLite uses ordinary check-first index creation.
    """
    if engine.dialect.name != "postgresql":
        with engine.begin() as connection:
            for index in indexes:
                connection.execute(CreateIndex(index, if_not_exists=True))
        return
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        schema = connection.scalar(text("SELECT current_schema()"))
        lock = connection.scalar(text("SELECT hashtextextended(current_database() || ':' || current_schema() || :purpose, 0)"),
                                 {"purpose": purpose})
        # A blocking SELECT pg_advisory_lock holds a transaction snapshot while
        # waiting. CREATE INDEX CONCURRENTLY can wait on that snapshot, causing
        # a deadlock with the lock waiter. Each try-lock ends immediately in
        # autocommit; wait between statements so no old snapshot stays open.
        while not connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": lock}):
            time.sleep(0.1)
        try:
            quote = engine.dialect.identifier_preparer.quote
            for index in indexes:
                valid = connection.scalar(text("""
                    SELECT i.indisvalid FROM pg_index i
                    JOIN pg_class c ON c.oid = i.indexrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = :schema AND c.relname = :name
                """), {"schema": schema, "name": index.name})
                if valid is False:
                    connection.exec_driver_sql("DROP INDEX CONCURRENTLY " + quote(schema) + "." + quote(index.name))
                if valid is not True:
                    sql = str(CreateIndex(index, if_not_exists=True).compile(dialect=engine.dialect))
                    connection.exec_driver_sql(sql.replace("CREATE INDEX ", "CREATE INDEX CONCURRENTLY ", 1))
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": lock})


def ensure_browser_indexes(engine):
    _ensure_indexes(engine, BROWSER_INDEXES, ":agent-message-bridge-browser-indexes")


def ensure_login_rate_schema(engine):
    """Serialize creation of the independent ephemeral counter table.

    No existing application table is altered. Retaining this additive table is
    safe when rolling back to older code, which simply does not consult it.
    """
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                "current_database() || ':' || current_schema() || :purpose, 0))"),
                {"purpose": ":agent-message-bridge-login-rate-schema"})
        elif engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        LoginRate.__table__.create(connection, checkfirst=True)
    _ensure_indexes(engine, tuple(LoginRate.__table__.indexes), ":agent-message-bridge-login-rate-indexes")


def ensure_delivery_schema(engine):
    """Add nullable generation-scoped caches, then build the delivery index.

    No data rewrite or destructive rollback is needed. NULL means recompute
    from retained deliveries. Older writers remain valid and their generation
    changes invalidate cached replay boundaries. New code requires init-db first.
    """
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                "current_database() || ':' || current_schema() || :purpose, 0))"),
                {"purpose": ":agent-message-bridge-delivery-columns"})
        elif engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        names = {column["name"] for column in inspect(connection).get_columns("subscriptions")}
        for name in ("acknowledged_sequence", "acknowledged_generation"):
            if name not in names:
                connection.exec_driver_sql("ALTER TABLE subscriptions ADD COLUMN " + name + " INTEGER")
    _ensure_indexes(engine, DELIVERY_INDEXES, ":agent-message-bridge-delivery-indexes")


def _profile_columns(connection):
    """Repeatable additions for profiles and their credential operations."""
    for table in ("participants", "oauth_users"):
        names = {c["name"] for c in inspect(connection).get_columns(table)}
        if "managed_source" not in names:
            connection.exec_driver_sql("ALTER TABLE " + table + " ADD COLUMN managed_source VARCHAR NOT NULL DEFAULT 'database'")
        if table == "oauth_users" and "creation_token_hash" not in names:
            connection.exec_driver_sql("ALTER TABLE oauth_users ADD COLUMN creation_token_hash VARCHAR")
    connection.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_users_creation_token_hash ON oauth_users (creation_token_hash)")
    names = {c["name"] for c in inspect(connection).get_columns("oauth_users")}
    for name, definition in (
            ("credential_generation", "INTEGER NOT NULL DEFAULT 1"),
            ("password_source", "VARCHAR"), ("api_key_source", "VARCHAR")):
        if name not in names:
            connection.exec_driver_sql("ALTER TABLE oauth_users ADD COLUMN " + name + " " + definition)
    APIKey.__table__.create(connection, checkfirst=True)
    CredentialOperation.__table__.create(connection, checkfirst=True)
    names = {c["name"] for c in inspect(connection).get_columns("participants")}
    for name, definition in (("webhook_enabled", "BOOLEAN"), ("webhook_url", "TEXT"),
                             ("webhook_token", "TEXT"), ("webhook_generation", "INTEGER NOT NULL DEFAULT 1")):
        if name not in names:
            connection.exec_driver_sql("ALTER TABLE participants ADD COLUMN " + name + " " + definition)
    if "deliveries" in inspect(connection).get_table_names():
        columns = {c["name"] for c in inspect(connection).get_columns("deliveries")}
        if "webhook_generation" not in columns:
            connection.exec_driver_sql("ALTER TABLE deliveries ADD COLUMN webhook_generation INTEGER")


def ensure_profile_schema(engine):
    """Repeatable additive profile upgrade, retaining nullable API-only emails.

    Legacy profile-column helpers remain independently testable. Version 0.2.0
    initialization first checks the fresh-database ownership requirement.
    """
    if engine.dialect.name == "sqlite":
        import re
        with engine.connect() as connection:
            prior_foreign_keys = int(connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one())
            prior_legacy_alter = int(connection.exec_driver_sql("PRAGMA legacy_alter_table").scalar_one())
            connection.commit()
            try:
                connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
                # Modern rename reparses external views/triggers while the old
                # table is temporarily absent. Legacy mode leaves references
                # intact until the replacement has its original name again.
                connection.exec_driver_sql("PRAGMA legacy_alter_table=ON")
                connection.commit()
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                nullable = next(c["nullable"] for c in inspect(connection).get_columns("oauth_users") if c["name"] == "email")
                if not nullable:
                    original = connection.scalar(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='oauth_users'"))
                    # Only this known column constraint changes; unexpected
                    # definitions fail closed instead of silently losing schema.
                    changed, count = re.subn(r'(?i)(\bemail\s+(?:VARCHAR(?:\(\d+\))?|TEXT))\s+NOT\s+NULL\b', r'\1', original)
                    if count != 1:
                        raise RuntimeError("Cannot safely upgrade the existing email column")
                    changed, count = re.subn(r'(?i)^(CREATE\s+TABLE\s+)(?:"oauth_users"|oauth_users)(?=\s*\()',
                                            r'\1oauth_users__profiles_upgrade', changed)
                    if count != 1:
                        raise RuntimeError("Cannot safely upgrade the existing user table")
                    retained = list(connection.scalars(text("SELECT sql FROM sqlite_master WHERE tbl_name='oauth_users' AND type IN ('index', 'trigger') AND sql IS NOT NULL")))
                    columns = [c["name"] for c in inspect(connection).get_columns("oauth_users")]
                    quote = engine.dialect.identifier_preparer.quote
                    column_sql = ", ".join(quote(name) for name in columns)
                    connection.exec_driver_sql(changed)
                    connection.exec_driver_sql("INSERT INTO oauth_users__profiles_upgrade (" + column_sql + ") SELECT " + column_sql + " FROM oauth_users")
                    connection.exec_driver_sql("DROP TABLE oauth_users")
                    connection.exec_driver_sql("ALTER TABLE oauth_users__profiles_upgrade RENAME TO oauth_users")
                    for sql in retained:
                        connection.exec_driver_sql(sql)
                _profile_columns(connection)
                if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
                    raise RuntimeError("Profile schema upgrade failed its foreign-key check")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.exec_driver_sql("PRAGMA legacy_alter_table=" + str(prior_legacy_alter))
                connection.exec_driver_sql("PRAGMA foreign_keys=" + str(prior_foreign_keys))
                connection.commit()
        return
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                "current_database() || ':' || current_schema() || :purpose, 0))"),
                        {"purpose": ":agent-message-bridge-profiles"})
            connection.exec_driver_sql("ALTER TABLE oauth_users ALTER COLUMN email DROP NOT NULL")
        _profile_columns(connection)


def ensure_multi_owner_schema(engine):
    """Add tenancy columns to an empty legacy schema; never guess ownership.

    The 0.2.0 revival uses a fresh database. Nonempty 0.1.x installations need
    a separately designed migration and fail closed here. Repeated init is safe.
    """
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                "current_database() || ':' || current_schema() || :purpose, 0))"),
                {"purpose": ":agent-message-bridge-profiles"})
        elif engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        inspector = inspect(connection)
        if "oauth_users" in inspector.get_table_names():
            email_unique = any(c["column_names"] == ["email"] for c in inspector.get_unique_constraints("oauth_users"))
            email_unique = email_unique or any(i.get("unique") and i["column_names"] == ["email"] for i in inspector.get_indexes("oauth_users"))
            if email_unique:
                raise RuntimeError("Version 0.2.0 requires a fresh database without legacy bot email uniqueness")
        columns = {c["name"] for c in inspect(connection).get_columns("participants")}
        if "owner_account_id" not in columns:
            if connection.scalar(text("SELECT count(*) FROM participants")):
                raise RuntimeError("Version 0.2.0 requires a fresh database; legacy ownership cannot be inferred")
            connection.exec_driver_sql("ALTER TABLE participants ADD COLUMN owner_account_id VARCHAR NOT NULL REFERENCES browser_owners(id)")
        if "stable_id" not in columns:
            if connection.scalar(text("SELECT count(*) FROM participants")):
                raise RuntimeError("Version 0.2.0 requires a fresh database; private bot IDs cannot be inferred")
            connection.exec_driver_sql("ALTER TABLE participants ADD COLUMN stable_id VARCHAR NOT NULL")
        inspector = inspect(connection)
        stable_keys = inspector.get_unique_constraints("participants") + [i for i in inspector.get_indexes("participants") if i.get("unique")]
        if not any(key["column_names"] == ["owner_account_id", "stable_id"] for key in stable_keys):
            connection.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS uq_participants_owner_stable ON participants (owner_account_id, stable_id)")
        if "reachability_policy" not in columns:
            connection.exec_driver_sql("ALTER TABLE participants ADD COLUMN reachability_policy VARCHAR NOT NULL DEFAULT 'own_owner' CHECK (reachability_policy IN ('own_owner','allowlist','open'))")
        columns = {c["name"] for c in inspect(connection).get_columns("browser_owners")}
        if "role" not in columns:
            if connection.scalar(text("SELECT count(*) FROM browser_owners")):
                raise RuntimeError("Version 0.2.0 requires a fresh database; legacy owner roles cannot be inferred")
            connection.exec_driver_sql("ALTER TABLE browser_owners ADD COLUMN role VARCHAR NOT NULL DEFAULT 'owner' CHECK (role IN ('admin','owner'))")
        from .models import BotAllowlist
        from .models_auth import InvitationReveal, OwnerInvitation
        BotAllowlist.__table__.create(connection, checkfirst=True)
        OwnerInvitation.__table__.create(connection, checkfirst=True)
        InvitationReveal.__table__.create(connection, checkfirst=True)
        invitation_columns = {c["name"] for c in inspect(connection).get_columns("owner_invitations")}
        if "displayed_at" not in invitation_columns:
            connection.exec_driver_sql("ALTER TABLE owner_invitations ADD COLUMN displayed_at FLOAT")
        connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_participants_owner_id ON participants (owner_account_id, id)")


def ensure_deactivation_schema(engine):
    """Add the nullable retirement marker without backfilling existing rows."""
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended("
                "current_database() || ':' || current_schema() || :purpose, 0))"),
                {"purpose": ":agent-message-bridge-profiles"})
        elif engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        if "deactivated_at" not in {c["name"] for c in inspect(connection).get_columns("participants")}:
            connection.exec_driver_sql("ALTER TABLE participants ADD COLUMN deactivated_at FLOAT")

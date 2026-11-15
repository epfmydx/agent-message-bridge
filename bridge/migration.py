"""Offline, explicit ownership migration for known public 0.1.x schemas.

The operator stops all old API/worker processes and backs up the database first.
Routing IDs, credentials, history and delivery receipts are never rewritten.
"""
import hashlib
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy import MetaData, inspect, select, text
from sqlalchemy.schema import CreateTable, CreateIndex

from .models import Base, Participant, now
from .models_auth import BrowserOwner, MigrationReceipt, User

NAME = "public-v01-ownership-v1"
P_BASE = {"id", "name", "managed_source", "active", "sequence"}
P_WEBHOOK = {"webhook_enabled", "webhook_url", "webhook_token", "webhook_generation"}
U_BASE = {"id", "email", "managed_source", "creation_token_hash", "password_hash", "api_key_hash", "active"}
U_CREDENTIAL = {"credential_generation", "credential_baseline_set", "configured_password_hash", "configured_api_key_hash", "password_source", "api_key_source"}
O_BASE = {"id", "name", "email", "password_hash", "active"}
LEGACY_TABLES = {"participants", "threads", "thread_members", "messages", "artifacts", "message_artifacts", "work_claims", "subscriptions", "deliveries", "browser_owners", "login_rate_limits", "oauth_users", "oauth_clients", "oauth_families", "oauth_codes", "oauth_tokens", "participant_api_keys", "credential_operations"}


def mapping_checked(value):
    if not isinstance(value, dict) or set(value) - {"version", "admin_owner_id", "participants", "bootstrap_admin"} or value.get("version") != 1:
        raise ValueError("Use a version 1 ownership mapping")
    if not isinstance(value.get("admin_owner_id"), str) or not value["admin_owner_id"] or not isinstance(value.get("participants"), list):
        raise ValueError("An explicit admin and participant ownership list are required")
    participants = []
    for item in value["participants"]:
        if (not isinstance(item, dict) or set(item) != {"id", "owner_id", "stable_id"}
                or any(not isinstance(v, str) or not v.strip() or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in v) for v in item.values())):
            raise ValueError("Each mapping requires an ID, owner ID and private stable ID without controls")
        participants.append(item)
    if len({p["id"] for p in participants}) != len(participants):
        raise ValueError("A participant appears more than once")
    if len({(p["owner_id"], p["stable_id"]) for p in participants}) != len(participants):
        raise ValueError("Private stable IDs must be unique within each owner")
    normalized = {**value, "participants": sorted(participants, key=lambda p: p["id"])}
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return normalized, digest


def _rows(connection, table):
    return list(connection.execute(text("SELECT * FROM " + table)).mappings())



def _plain_foreign_keys(inspector, table, *, legacy=True):
    """Known releases use plain, immediate FKs; rebuilding must not erase policy."""
    metadata = Base.metadata.tables[table]
    expected = set() if legacy and table == "participants" else {
        (tuple(element.parent.name for element in constraint.elements),
         next(iter(constraint.elements)).column.table.name,
         tuple(element.column.name for element in constraint.elements))
        for constraint in metadata.foreign_key_constraints}
    actual = inspector.get_foreign_keys(table)
    shapes = {(tuple(fk["constrained_columns"]), fk["referred_table"], tuple(fk["referred_columns"])) for fk in actual}
    if shapes != expected or len(actual) != len(expected):
        raise ValueError("Unsupported or missing required foreign-key constraint")
    for fk in actual:
        if fk.get("referred_schema") not in (None, inspector.default_schema_name):
            raise ValueError("Unsupported foreign-key target schema")
        for option, value in fk.get("options", {}).items():
            if value in (None, False):
                continue
            if option in ("ondelete", "onupdate") and str(value).upper() == "NO ACTION":
                continue
            if option == "initially" and str(value).upper() == "IMMEDIATE":
                continue
            if option == "match" and str(value).upper() in ("SIMPLE", "NONE"):
                continue
            raise ValueError("Unsupported foreign-key actions or deferrability")


def _credential_tables(inspector, tables):
    for table in {"participant_api_keys", "credential_operations"} & tables:
        metadata = Base.metadata.tables[table]
        if ({column["name"] for column in inspector.get_columns(table)} != set(metadata.columns.keys())
                or inspector.get_pk_constraint(table)["constrained_columns"] != [column.name for column in metadata.primary_key]
                or inspector.get_check_constraints(table)):
            raise ValueError("Unsupported legacy credential-table shape")
        for column in inspector.get_columns(table):
            known = metadata.c[column["name"]]
            if (column["type"]._type_affinity is not known.type._type_affinity
                    or getattr(column["type"], "length", None) != getattr(known.type, "length", None)
                    or column["nullable"] != known.nullable or column.get("default") is not None):
                raise ValueError("Unsupported legacy credential column type or nullability")
        unique = inspector.get_unique_constraints(table) + [i for i in inspector.get_indexes(table) if i.get("unique")]
        expected = {("key_hash",)} if table == "participant_api_keys" else set()
        if {tuple(index["column_names"]) for index in unique} != expected:
            raise ValueError("Unsupported legacy credential uniqueness")
        if any(index.get("dialect_options", {}).get(inspector.bind.dialect.name + "_where") is not None for index in unique):
            raise ValueError("Unsupported partial credential uniqueness")
        _plain_foreign_keys(inspector, table)

def _preflight(connection, mapping, digest, legacy_path, environ):
    inspector = inspect(connection)
    if connection.dialect.name == "sqlite":
        for table in ("participants", "oauth_users", "browser_owners", "participant_api_keys", "credential_operations"):
            if not inspector.has_table(table):
                continue
            for index in connection.exec_driver_sql("PRAGMA index_list(" + table + ")").mappings():
                if index["unique"]:
                    quoted = connection.dialect.identifier_preparer.quote(index["name"])
                    info = list(connection.exec_driver_sql("PRAGMA index_info(" + quoted + ")"))
                    if any(row[2] is None or row[1] == -2 for row in info):
                        raise ValueError("Unsupported expression-based unique index")
                    if table == "oauth_users" and index["origin"] == "c" and [row[2] for row in info] == ["email"]:
                        raise ValueError("Unsupported standalone email uniqueness index")
    tables = set(inspector.get_table_names())
    if MigrationReceipt.__tablename__ in tables:
        receipt = connection.execute(select(MigrationReceipt.__table__).where(MigrationReceipt.name == NAME)).mappings().first()
        if receipt:
            if not {"participant_api_keys", "credential_operations"} <= tables:
                raise ValueError("Migrated credential tables are incomplete")
            _credential_tables(inspector, tables)
            for table in ("participants", "oauth_users", "browser_owners"):
                _plain_foreign_keys(inspector, table, legacy=False)
            if receipt["mapping_hash"] != digest:
                raise ValueError("This database was migrated with a different ownership mapping")
            expected = {p["id"]: (p["owner_id"], p["stable_id"]) for p in mapping["participants"]}
            actual = {p["id"]: (p["owner_account_id"], p["stable_id"]) for p in _rows(connection, "participants") if p["id"] in expected}
            if actual != expected or any(p["managed_source"] != "database" for p in _rows(connection, "participants") if p["id"] in expected):
                raise ValueError("Migrated ownership no longer matches its receipt")
            if connection.scalar(text("SELECT role FROM browser_owners WHERE id=:id"), {"id": mapping["admin_owner_id"]}) != "admin":
                raise ValueError("Migrated admin no longer matches its receipt")
            unique = inspector.get_unique_constraints("oauth_users") + [i for i in inspector.get_indexes("oauth_users") if i.get("unique")]
            current_columns = {t: {c["name"] for c in inspector.get_columns(t)} for t in ("participants", "oauth_users", "browser_owners")}
            if any(not set(Base.metadata.tables[t].columns.keys()) <= current_columns[t] for t in current_columns):
                raise ValueError("Migrated schema is incomplete")
            owner_fk = inspector.get_foreign_keys("participants")
            if not any(f["constrained_columns"] == ["owner_account_id"] and f["referred_table"] == "browser_owners" and f["referred_columns"] == ["id"] for f in owner_fk):
                raise ValueError("Migrated ownership foreign key is missing")
            if connection.scalar(text("SELECT count(*) FROM participants p LEFT JOIN browser_owners o ON o.id=p.owner_account_id WHERE o.id IS NULL")):
                raise ValueError("Migrated ownership references are inconsistent")
            if any(c["column_names"] == ["email"] for c in unique):
                raise ValueError("Migrated schema is inconsistent")
            return None
    required = LEGACY_TABLES - {"participant_api_keys", "credential_operations"}
    if not required <= tables or tables & {"bot_allowlist", "owner_invitations", "invitation_reveals"}:
        raise ValueError("Unsupported or partially migrated database; expected a known public 0.1.x schema")
    if tables & {"participants__ownership_upgrade", "oauth_users__ownership_upgrade"}:
        raise ValueError("Unexpected migration temporary table")
    existing_indexes = {index["name"]: (table, index["column_names"], bool(index.get("unique")))
                        for table in tables for index in inspector.get_indexes(table)}
    if "uq_participants_owner_stable" in existing_indexes:
        raise ValueError("Reserved ownership index name already exists")
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            if index.name in existing_indexes:
                columns = [getattr(expression, "name", None) or expression.element.name for expression in index.expressions]
                if existing_indexes[index.name] != (table.name, columns, bool(index.unique)):
                    raise ValueError("A required index name collides with a different definition")
    columns = {name: {c["name"] for c in inspector.get_columns(name)} for name in ("participants", "oauth_users", "browser_owners")}
    if (columns["participants"] not in (P_BASE, P_BASE | P_WEBHOOK)
            or columns["oauth_users"] not in (U_BASE, U_BASE | U_CREDENTIAL)
            or columns["browser_owners"] != O_BASE):
        raise ValueError("Unsupported or partially migrated identity columns")
    optional = tables & {"participant_api_keys", "credential_operations"}
    delivery_columns = {c["name"] for c in inspector.get_columns("deliveries")}
    version_010 = columns["participants"] == P_BASE and columns["oauth_users"] == U_BASE and not optional and "webhook_generation" not in delivery_columns
    version_011 = columns["participants"] == P_BASE | P_WEBHOOK and columns["oauth_users"] == U_BASE | U_CREDENTIAL and optional == {"participant_api_keys", "credential_operations"} and "webhook_generation" in delivery_columns
    if not (version_010 or version_011):
        raise ValueError("Expected a complete public 0.1.0 or 0.1.1 schema")
    _credential_tables(inspector, tables)
    for table in (tables & LEGACY_TABLES) - {"participants", "oauth_users", "browser_owners"}:
        expected = set(Base.metadata.tables[table].columns.keys())
        actual = {c["name"] for c in inspector.get_columns(table)}
        acceptable = (expected, expected - {"webhook_generation"}) if table == "deliveries" else (expected,)
        if actual not in acceptable:
            raise ValueError("Unsupported legacy table columns")
    # Extra ordinary indexes/triggers/views are retained. Unknown uniqueness and
    # foreign-key contracts on rebuilt tables require a separate migration.
    for table, allowed in (("participants", set()), ("oauth_users", {("email",), ("api_key_hash",), ("creation_token_hash",)}), ("browser_owners", {("email",)})):
        if inspector.get_pk_constraint(table)["constrained_columns"] != ["id"] or inspector.get_check_constraints(table):
            raise ValueError("Unsupported identity primary-key or CHECK constraint")
        if connection.dialect.name == "sqlite":
            definition = connection.scalar(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"), {"name": table})
            import re
            if re.search(r"\b(COLLATE|WITHOUT\s+ROWID|STRICT|ON\s+CONFLICT)\b", definition, re.I):
                raise ValueError("Unsupported identity table options")
        known_defaults = {"managed_source": {"'config'"}, "credential_generation": {"1", "'1'"}, "credential_baseline_set": {"false", "0", "'false'"}, "webhook_generation": {"1", "'1'"}}
        for column in inspector.get_columns(table):
            default = column.get("default")
            if default is not None:
                normalized = str(default).replace("::character varying", "").strip("()")
                if normalized not in known_defaults.get(column["name"], set()):
                    raise ValueError("Unsupported identity column default")
        unique = inspector.get_unique_constraints(table) + [i for i in inspector.get_indexes(table) if i.get("unique")]
        if any(tuple(c["column_names"]) not in allowed for c in unique):
            raise ValueError("Unsupported identity uniqueness constraint")
    for table in tables & LEGACY_TABLES:
        _plain_foreign_keys(inspector, table)
    owners, participants, users = (_rows(connection, t) for t in ("browser_owners", "participants", "oauth_users"))
    by_id = {p["id"]: p for p in participants}
    assignments = {p["id"]: p for p in mapping["participants"]}
    if set(assignments) != set(by_id) or {u["id"] for u in users} != set(by_id):
        raise ValueError("Map every existing participant exactly once, including inactive profiles")
    owner_ids = {o["id"] for o in owners}
    admin = next((o for o in owners if o["id"] == mapping["admin_owner_id"]), None)
    if admin is None:
        candidate = mapping.get("bootstrap_admin")
        if owners or not isinstance(candidate, dict) or set(candidate) != {"id", "name", "email", "password_hash_env"}:
            raise ValueError("Select an existing active owner as admin, or explicitly bootstrap one when no owners exist")
        if candidate["id"] != mapping["admin_owner_id"] or candidate["id"] in by_id:
            raise ValueError("Bootstrap admin conflicts with an existing identity")
        from .profile_validation import display_name, contact_email
        from .errors import Invalid
        try:
            name, email = display_name(candidate["name"]), contact_email(candidate["email"])
        except (Invalid, TypeError):
            raise ValueError("Invalid bootstrap admin") from None
        password_hash = environ.get(candidate["password_hash_env"], "")
        if not email or not password_hash:
            raise ValueError("Bootstrap admin requires a valid email and password hash environment reference")
        admin = dict(id=candidate["id"], name=name, email=email, password_hash=password_hash, active=True)
        owner_ids.add(admin["id"])
    elif not admin["active"] or mapping.get("bootstrap_admin"):
        raise ValueError("Select an existing active admin without bootstrap credentials")
    if any(p["owner_id"] not in owner_ids for p in assignments.values()):
        raise ValueError("An ownership mapping refers to an unknown owner")
    if owner_ids & set(by_id):
        raise ValueError("Owner and participant identities must remain separate")
    # Explicit metadata identifies the former deployment callback. No secrets
    # enter the mapping, migration receipt, output, session or diagnostic.
    if legacy_path is None:
        raise ValueError("Supply the protected legacy config for the first migration")
    try:
        legacy = json.loads(Path(legacy_path).read_text())
    except (OSError, ValueError):
        raise ValueError("Cannot read protected legacy configuration") from None
    if not isinstance(legacy, dict) or set(legacy) - {"participants", "owners", "webhook_participant_id"} or not isinstance(legacy.get("participants"), list):
        raise ValueError("Expected a public 0.1.x legacy configuration")
    callback_id = legacy.get("webhook_participant_id")
    if callback_id not in by_id:
        raise ValueError("Legacy webhook recipient must be an existing participant")
    url, token = environ.get("WEBHOOK_URL", ""), environ.get("WEBHOOK_TOKEN", "")
    inherited = by_id[callback_id].get("webhook_enabled") is None
    encrypted = None
    if inherited and (url or token):
        from .network import _parse_destination, _InvalidDestination
        try:
            if not url or not token or any(ord(c) < 32 or ord(c) > 255 for c in token):
                raise ValueError()
            _parse_destination(url)
            encrypted = Fernet(environ["ENCRYPTION_KEY"].encode()).encrypt(token.encode()).decode()
        except (_InvalidDestination, ValueError, KeyError):
            raise ValueError("Legacy webhook transfer requires valid paired destination, token and encryption key") from None
    return dict(owners=owners, participants=participants, users=users, admin=admin,
                assignments=assignments, callback_id=callback_id, inherited=inherited,
                url=url if encrypted else None, encrypted=encrypted)


def _add(connection, table, name, definition):
    if name not in {c["name"] for c in inspect(connection).get_columns(table)}:
        connection.exec_driver_sql("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)


def _sqlite_replace(connection, model, rows):
    table = model.__table__
    temporary = table.name + "__ownership_upgrade"
    if inspect(connection).has_table(temporary):
        raise ValueError("Unexpected migration temporary table")
    retained = list(connection.scalars(text("SELECT sql FROM sqlite_master WHERE tbl_name=:name AND type IN ('index','trigger') AND sql IS NOT NULL"), {"name": table.name}))
    metadata = MetaData()
    for original in Base.metadata.sorted_tables:
        original.to_metadata(metadata)
    replacement = table.to_metadata(metadata, name=temporary)
    # Retain unused old credential-baseline columns, rather than erasing hashes.
    reflected = __import__('sqlalchemy').Table(table.name, MetaData(), autoload_with=connection)
    for column in reflected.columns:
        if column.name not in replacement.c:
            replacement.append_column(column._copy())
    connection.execute(CreateTable(replacement))
    if rows:
        # Untyped binds preserve old SQLite server-default representations,
        # including retained unused credential baseline fields, byte for byte.
        columns = list(rows[0])
        quote = connection.dialect.identifier_preparer.quote
        sql = "INSERT INTO " + temporary + " (" + ",".join(quote(c) for c in columns) + ") VALUES (" + ",".join(":" + c for c in columns) + ")"
        connection.execute(text(sql), [dict(row) for row in rows])
    connection.exec_driver_sql("DROP TABLE " + table.name)
    connection.exec_driver_sql("ALTER TABLE " + temporary + " RENAME TO " + table.name)
    for sql in retained:
        connection.exec_driver_sql(sql)


def _apply(connection, plan, mapping, digest):
    admin = plan["admin"]
    _add(connection, "browser_owners", "role", "VARCHAR NOT NULL DEFAULT 'owner' CHECK (role IN ('admin','owner'))")
    if not any(o["id"] == admin["id"] for o in plan["owners"]):
        connection.execute(BrowserOwner.__table__.insert().values(**admin, role="admin"))
    else:
        connection.execute(text("UPDATE browser_owners SET role='admin' WHERE id=:id"), {"id": admin["id"]})
    # Add the known 0.1.1 credential/webhook columns without syncing old config.
    from .schema import _profile_columns
    _profile_columns(connection)
    participants, users = _rows(connection, "participants"), _rows(connection, "oauth_users")
    migrated = []
    for row in participants:
        values = dict(row)
        assignment = plan["assignments"][row["id"]]
        values.update(owner_account_id=assignment["owner_id"], stable_id=assignment["stable_id"],
                      reachability_policy="own_owner", managed_source="database", deactivated_at=None,
                      legacy_webhook=row["id"] == plan["callback_id"])
        if row["webhook_enabled"] is None:
            values["webhook_enabled"] = row["id"] == plan["callback_id"]
            if values["webhook_enabled"]:
                values.update(webhook_url=plan["url"], webhook_token=plan["encrypted"])
        migrated.append(values)
    migrated_users = [dict(u, managed_source="database", password_source="database", api_key_source="database") for u in users]
    if connection.dialect.name == "sqlite":
        _sqlite_replace(connection, Participant, migrated)
        _sqlite_replace(connection, User, migrated_users)
    else:
        _add(connection, "participants", "owner_account_id", "VARCHAR REFERENCES browser_owners(id)")
        _add(connection, "participants", "stable_id", "VARCHAR")
        _add(connection, "participants", "reachability_policy", "VARCHAR NOT NULL DEFAULT 'own_owner' CHECK (reachability_policy IN ('own_owner','allowlist','open'))")
        _add(connection, "participants", "deactivated_at", "FLOAT")
        _add(connection, "participants", "legacy_webhook", "BOOLEAN NOT NULL DEFAULT false")
        for values in migrated:
            ident = values.pop("id")
            changed = {key: values[key] for key in ("owner_account_id", "stable_id", "reachability_policy", "managed_source", "deactivated_at", "legacy_webhook", "webhook_enabled", "webhook_url", "webhook_token")}
            connection.execute(Participant.__table__.update().where(Participant.id == ident).values(**changed))
        for values in migrated_users:
            connection.execute(text("UPDATE oauth_users SET managed_source='database',password_source='database',api_key_source='database' WHERE id=:id"), {"id": values["id"]})
        quote = connection.dialect.identifier_preparer.quote
        inspector = inspect(connection)
        unique = inspector.get_unique_constraints("oauth_users")
        names = set()
        for constraint in unique:
            if constraint["column_names"] == ["email"]:
                connection.exec_driver_sql("ALTER TABLE oauth_users DROP CONSTRAINT " + quote(constraint["name"]))
                names.add(constraint["name"])
        for index in inspector.get_indexes("oauth_users"):
            if index.get("unique") and index["column_names"] == ["email"] and index["name"] not in names:
                connection.exec_driver_sql("DROP INDEX " + quote(index["name"]))
        connection.exec_driver_sql("ALTER TABLE oauth_users ALTER COLUMN email DROP NOT NULL")
        connection.exec_driver_sql("ALTER TABLE participants ALTER COLUMN owner_account_id SET NOT NULL")
        connection.exec_driver_sql("ALTER TABLE participants ALTER COLUMN stable_id SET NOT NULL")
        connection.exec_driver_sql("CREATE UNIQUE INDEX uq_participants_owner_stable ON participants(owner_account_id,stable_id)")
    Base.metadata.create_all(connection)
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            connection.execute(CreateIndex(index, if_not_exists=True))
    connection.execute(MigrationReceipt.__table__.insert().values(name=NAME, mapping_hash=digest, applied_at=now()))
    if connection.dialect.name == "sqlite" and connection.exec_driver_sql("PRAGMA foreign_key_check").first():
        raise ValueError("Migration failed its foreign-key check")


def migrate_v01(engine, mapping, *, legacy_config=None, environ=None, apply=False):
    """Read-only check or one atomic migration; identical successful replay is inert."""
    mapping, digest = mapping_checked(mapping)
    environ = os.environ if environ is None else environ
    with engine.connect() as connection:
        sqlite = engine.dialect.name == "sqlite"
        prior = None
        try:
            if apply and sqlite:
                prior = (connection.exec_driver_sql("PRAGMA foreign_keys").scalar(), connection.exec_driver_sql("PRAGMA legacy_alter_table").scalar())
                connection.commit()
                connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
                connection.exec_driver_sql("PRAGMA legacy_alter_table=ON")
                connection.commit()
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            elif apply:
                connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
                connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':' || current_schema() || :purpose,0))"), {"purpose": ":agent-message-bridge-profiles"})
            plan = _preflight(connection, mapping, digest, legacy_config, environ)
            if plan is None:
                connection.rollback()
                return "already_applied"
            if not apply:
                connection.rollback()
                return "ready"
            _apply(connection, plan, mapping, digest)
            connection.commit()
            return "applied"
        except BaseException:
            connection.rollback()
            raise
        finally:
            if prior is not None:
                connection.exec_driver_sql("PRAGMA legacy_alter_table=" + str(prior[1]))
                connection.exec_driver_sql("PRAGMA foreign_keys=" + str(prior[0]))
                connection.commit()

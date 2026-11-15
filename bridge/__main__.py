"""Local bridge operations. Diagnostics deliberately omit content and credentials."""
import argparse
import json
import logging
import time

from sqlalchemy import func, select

from .app import bootstrap, create_app
from .models import Base, Delivery, Subscription, WorkClaim, now


def main():
    parser = argparse.ArgumentParser(description="Independent Agent Message Bridge service")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    commands.add_parser("init-db")
    commands.add_parser("sync-config")
    commands.add_parser("worker")
    commands.add_parser("status")
    commands.add_parser("failures")
    retry = commands.add_parser("retry-delivery")
    retry.add_argument("delivery_id")
    claim = commands.add_parser("release-claim", help="Release a stranded work claim after checking the prior worker outcome")
    claim.add_argument("message_id")
    claim.add_argument("--claim-id", required=True, help="Expected current claim identity; prevents releasing another run")
    migrate = commands.add_parser("migrate-v01", help="Offline ownership migration for existing public 0.1.x data")
    migrate.add_argument("--mapping", required=True, help="Protected JSON assigning every bot and selecting the admin")
    migrate.add_argument("--legacy-config", help="Protected old config; defaults to BRIDGE_CONFIG on first execution")
    mode = migrate.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only preflight; creates no schema or receipt")
    mode.add_argument("--apply", action="store_true", help="Apply atomically after stopping every old API/worker")
    args = parser.parse_args()
    if args.command == "migrate-v01":
        import os
        from pathlib import Path
        from .migration import migrate_v01
        from .models import database
        from sqlalchemy.engine import make_url
        try:
            url = make_url(os.environ["DATABASE_URL"])
            if url.get_backend_name() == "sqlite" and (not url.database or not Path(url.database).is_file()):
                raise ValueError("Select an existing SQLite database for migration")
            mapping = json.loads(Path(args.mapping).read_text())
            engine, _ = database(url.render_as_string(hide_password=False))
            try:
                result = migrate_v01(engine, mapping, legacy_config=args.legacy_config or os.environ.get("BRIDGE_CONFIG"), apply=args.apply)
            finally:
                engine.dispose()
        except (ValueError, KeyError, OSError) as exc:
            parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot read migration input or database settings")
        except Exception:
            parser.error("Migration failed; its transaction was rolled back. Check the supported schema and database availability.")
        print({"ready": "Migration preflight passed; database unchanged", "applied": "Ownership migration committed", "already_applied": "Ownership migration already applied; database unchanged"}[result])
        return
    if args.command == "serve":
        # Own Gunicorn image/runtime; preserve configured trusted proxy semantics.
        import os
        from gunicorn.app.wsgiapp import run
        import sys
        sys.argv = [sys.argv[0], "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "120", "--access-logfile", "/dev/null", "bridge.app:create_app()"]
        run()
        return
    app = create_app()
    sessions = app.extensions["sessions"]
    if args.command in ("init-db", "sync-config"):
        if args.command == "init-db":
            from sqlalchemy import inspect
            inspector = inspect(app.extensions["engine"])
            if inspector.has_table("participants") and "owner_account_id" not in {c["name"] for c in inspector.get_columns("participants")}:
                parser.error("Existing public 0.1.x database requires migrate-v01 with an explicit ownership mapping before init-db")
            from .models_auth import LoginRate
            # This new table has its own serialized, repeatable upgrade path.
            Base.metadata.create_all(app.extensions["engine"], tables=[
                table for table in Base.metadata.sorted_tables if table is not LoginRate.__table__])
            from .schema import ensure_multi_owner_schema, ensure_browser_indexes, ensure_delivery_schema, ensure_login_rate_schema, ensure_profile_schema, ensure_deactivation_schema
            ensure_multi_owner_schema(app.extensions["engine"])
            ensure_profile_schema(app.extensions["engine"])
            ensure_deactivation_schema(app.extensions["engine"])
            ensure_login_rate_schema(app.extensions["engine"])
            ensure_delivery_schema(app.extensions["engine"])
            ensure_browser_indexes(app.extensions["engine"])
        with sessions.begin() as db: bootstrap(db, app.config)
        print("Bridge configuration synchronized")
    elif args.command == "worker":
        from .worker import deliver_one
        logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
        try:
            while True:
                try:
                    if not deliver_one(sessions, app.config): time.sleep(1)
                except Exception:
                    # Dependency exceptions can contain credentials or source URLs.
                    # Context managers roll the transaction back; retry without
                    # formatting the exception or keeping a failed session alive.
                    logging.getLogger(__name__).error("worker_iteration_failed")
                    time.sleep(5)
        except KeyboardInterrupt: pass
    elif args.command == "status":
        with sessions() as db: counts = dict(db.execute(select(Delivery.state, func.count()).group_by(Delivery.state)).all())
        print(json.dumps(counts, sort_keys=True))
    elif args.command == "failures":
        with sessions() as db:
            for row in db.execute(select(Delivery.id, Delivery.kind, Delivery.state, Delivery.attempts, Delivery.status, Delivery.reason)
                                  .where(Delivery.state.in_(["retry", "terminal", "stopped"])).order_by(Delivery.available_at, Delivery.id)):
                print(json.dumps(dict(zip(("delivery_id", "kind", "state", "attempts", "status", "reason"), row)), sort_keys=True))
    elif args.command == "retry-delivery":
        with sessions.begin() as db:
            item = db.get(Delivery, args.delivery_id, with_for_update=True)
            if not item or item.state not in ("retry", "terminal", "stopped"): parser.error("No retained failed delivery with that ID")
            sub = db.get(Subscription, item.subscription_id) if item.subscription_id else None
            if sub and not sub.active: parser.error("Refresh the subscription before retrying")
            item.state, item.reason, item.available_at = "pending", None, now()
        print("Delivery queued; access will be checked again")
    elif args.command == "release-claim":
        with sessions.begin() as db:
            item = db.get(WorkClaim, args.message_id, with_for_update=True)
            if not item or item.claim_id != args.claim_id: parser.error("Work claim no longer matches")
            db.delete(item)
        print("Work claim released")


if __name__ == "__main__": main()

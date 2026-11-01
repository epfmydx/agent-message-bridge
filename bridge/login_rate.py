"""Short login burst limit; counters survive failed request rollbacks."""
import hashlib
import hmac
import math
from ipaddress import ip_address
from urllib.parse import urlsplit

import idna
from flask import jsonify, request
from sqlalchemy import delete, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from .cloudflare import single_ip
from .models_auth import LoginRate
from .network import is_public_unicast

REQUESTS, WINDOW, COOLDOWN = 10, 10, 10
CLEANUP_BATCH = 64  # Internal work size, not a limit on visitors or retained messages.


def client_key(secret, address):
    """Use only the origin guard's proven address; normalize equivalent spellings."""
    address = single_ip(address)
    if not is_public_unicast(str(address)):
        raise ValueError("Invalid verified client address")
    secret = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(secret, b"agent-message-bridge-login-rate-v1\0" + address.packed, hashlib.sha256).hexdigest()


def _clock(connection):
    # Read after acquiring the counter lock. Transaction-start time is stale
    # after waiting, and app-process clocks need not agree across replicas.
    sql = ("SELECT extract(epoch FROM clock_timestamp())" if connection.dialect.name == "postgresql"
           else "SELECT (julianday('now') - 2440587.5) * 86400.0")
    return float(connection.scalar(text(sql)))


def consume(engine, key):
    """Return retry seconds, or zero when admitted. Always commit the counter.

    One no-op upsert locks an existing row or creates it atomically, including
    when cleanup concurrently deletes an expired row. Each row contains at most
    ten admitted timestamps. Blocked requests never extend the cooldown.
    """
    table = LoginRate.__table__
    with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.begin()
            connection.exec_driver_sql("SET LOCAL lock_timeout = '1s'")
            connection.exec_driver_sql("SET LOCAL statement_timeout = '2s'")
        try:
            insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
            statement = insert(table).values(client_key=key, attempts=[], blocked_until=0, expires_at=0)
            row = connection.execute(statement.on_conflict_do_update(
                index_elements=[table.c.client_key], set_={"client_key": statement.excluded.client_key}
            ).returning(table.c.attempts, table.c.blocked_until)).one()
            now = _clock(connection)
            attempts, blocked_until = row
            if blocked_until > now:
                retry = math.ceil(blocked_until - now)
            else:
                attempts = [stamp for stamp in attempts if stamp > now - WINDOW]
                if len(attempts) >= REQUESTS:
                    blocked_until, retry = now + COOLDOWN, COOLDOWN
                    attempts = []
                else:
                    attempts.append(now)
                    blocked_until, retry = 0, 0
                connection.execute(update(table).where(table.c.client_key == key).values(
                    attempts=attempts, blocked_until=blocked_until,
                    expires_at=max(blocked_until, attempts[-1] + WINDOW if attempts else 0)))

            # Acquire our own row first, then skip other in-flight row locks.
            # A locked expired row cannot be deleted after another request has
            # refreshed it. The expiry index keeps this independent of history.
            expired = select(table.c.client_key).where(table.c.expires_at <= now,
                table.c.client_key != key).order_by(table.c.expires_at, table.c.client_key).limit(CLEANUP_BATCH)
            if connection.dialect.name == "postgresql":
                expired = expired.with_for_update(skip_locked=True)
            connection.execute(delete(table).where(table.c.client_key.in_(expired)))
            connection.commit()
            return retry
        except BaseException:
            connection.rollback()
            raise


def _canonical_hostname(host):
    """Compare IP literals or DNS names in their UTS46 nontransitional form."""
    host = host.rstrip(".")
    try:
        return str(ip_address(host)).lower()
    except ValueError:
        # Map case through IDNA rather than Unicode casefold: ß and ss are
        # different DNS names under modern browser nontransitional processing.
        return idna.encode(host, uts46=True, transitional=False).decode("ascii").lower().rstrip(".")


def install_login_limiter(app):
    # create_app validates BASE_URL before installing request hooks.
    canonical_host = _canonical_hostname(urlsplit(app.config["BASE_URL"]).hostname)

    @app.before_request
    def limit_login():
        if request.method != "POST" or request.path != "/login":
            return
        # Parse the port separately; normalize wire IDNA names and IP literals
        # exactly as the configured origin, including an absolute trailing dot.
        try:
            host = urlsplit("//" + request.host).hostname
            if not host or _canonical_hostname(host) != canonical_host:
                return
        except ValueError:
            return  # A malformed host cannot match the validated origin.
        try:
            key = client_key(app.secret_key, request.environ.get("agent_message_bridge.cloudflare_client_ip"))
        except (TypeError, ValueError):
            return jsonify(error="invalid_cloudflare_client_ip"), 400
        try:
            retry = consume(app.extensions["engine"], key)
        except SQLAlchemyError:
            # Database exceptions may embed values or credentials. Never fall
            # through to the expensive password checks on a counter failure.
            app.logger.error("login_rate_unavailable")
            return jsonify(error="login_temporarily_unavailable"), 503, {"Retry-After": "10"}
        if retry:
            return jsonify(error="login_rate_limited", message="Too many sign-in attempts. Try again shortly."), 429, {"Retry-After": str(retry)}

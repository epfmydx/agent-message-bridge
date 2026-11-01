"""OAuth credentials are opaque to clients and stored only as SHA-256 hashes."""
import hmac

from sqlalchemy import Boolean, Float, ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base, now, uid


class BrowserOwner(Base):
    """A browser viewer identity with no participant or OAuth authority."""
    __tablename__ = "browser_owners"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String)
    password_hash: Mapped[str] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (Index("uq_browser_owners_active_email", "email", unique=True,
                           postgresql_where=active.is_(True), sqlite_where=active.is_(True)),)


class LoginRate(Base):
    """Ephemeral pseudonymous per-IP login counters, separate from identities."""
    __tablename__ = "login_rate_limits"
    client_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[list] = mapped_column(JSON)
    blocked_until: Mapped[float] = mapped_column(Float)
    expires_at: Mapped[float] = mapped_column(Float)
    __table_args__ = (Index("ix_login_rate_expiry", expires_at, client_key),)


class User(Base):
    __tablename__ = "oauth_users"
    id: Mapped[str] = mapped_column(ForeignKey("participants.id"), primary_key=True)
    email: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    managed_source: Mapped[str] = mapped_column(String, default="config", server_default="config")
    creation_token_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    password_hash: Mapped[str] = mapped_column(String)
    api_key_hash: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (Index("uq_oauth_users_creation_token_hash", "creation_token_hash", unique=True),)

    def get_user_id(self):
        return self.id


class Client(Base):
    __tablename__ = "oauth_clients"
    client_id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    secret_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    redirect_uris: Mapped[list] = mapped_column(JSON)
    auth_method: Mapped[str] = mapped_column(String)
    grant_types: Mapped[list] = mapped_column(JSON, default=lambda: ["authorization_code", "refresh_token"])
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[float] = mapped_column(Float, default=now)

    def get_client_id(self): return self.client_id
    def get_default_redirect_uri(self): return self.redirect_uris[0]
    def check_redirect_uri(self, uri): return uri in self.redirect_uris
    def get_allowed_scope(self, scope): return scope if scope == "bridge:messages" else ""
    def check_client_secret(self, secret):
        from .auth import digest
        return bool(self.secret_hash and hmac.compare_digest(self.secret_hash, digest(secret)))
    def check_endpoint_auth_method(self, method, endpoint): return self.auth_method == method
    def check_response_type(self, response_type): return response_type == "code"
    def check_grant_type(self, grant_type): return grant_type in self.grant_types


class Family(Base):
    __tablename__ = "oauth_families"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("oauth_users.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Code(Base):
    __tablename__ = "oauth_codes"
    code_hash: Mapped[str] = mapped_column(String, primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("oauth_users.id"))
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id"), index=True)
    family: Mapped[str] = mapped_column(ForeignKey("oauth_families.id"))
    redirect_uri: Mapped[str] = mapped_column(String)
    resource: Mapped[str] = mapped_column(String)
    scope: Mapped[str] = mapped_column(String)
    challenge: Mapped[str] = mapped_column(String)
    method: Mapped[str] = mapped_column(String)
    expires_at: Mapped[float] = mapped_column(Float, default=lambda: now()+300)
    used: Mapped[bool] = mapped_column(Boolean, default=False)

    def is_expired(self): return self.expires_at <= now()
    def get_redirect_uri(self): return self.redirect_uri
    def get_scope(self): return self.scope
    def get_auth_time(self): return self.expires_at-300


class Token(Base):
    __tablename__ = "oauth_tokens"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("oauth_users.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id"), index=True)
    family: Mapped[str] = mapped_column(ForeignKey("oauth_families.id"), index=True)
    access_hash: Mapped[str] = mapped_column(String, unique=True)
    refresh_hash: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    resource: Mapped[str] = mapped_column(String)
    scope: Mapped[str] = mapped_column(String)
    expires_at: Mapped[float] = mapped_column(Float)
    refresh_expires_at: Mapped[float] = mapped_column(Float)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    def get_scope(self): return self.scope
    def check_client(self, client): return self.client_id == client.client_id
    def is_expired(self): return self.expires_at <= now()

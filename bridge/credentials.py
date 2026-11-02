"""Transactional participant credential changes, separate from profile provenance.

Callers verify the signed operation token and browser owner, and commit before
displaying a generated key. Only a digest of the opaque token is retained here.
"""
import secrets

from sqlalchemy import select, update
from werkzeug.security import generate_password_hash

from .auth import deactivate_subscriptions, digest, revoke_family, service_client, service_family
from .errors import Conflict, Invalid
from .models import Participant
from .models_auth import APIKey, CredentialOperation, Family, User


def credential_view(db, user):
    """Return display-safe metadata, never credential hashes or raw secrets."""
    keys = []
    if user.api_key_hash:
        keys.append(dict(id="legacy", source=user.api_key_source or user.managed_source,
                         created_at=None, active=True))
    keys.extend(dict(id=key.id, source=key.source, created_at=key.created_at, active=key.active)
                for key in db.scalars(select(APIKey).where(APIKey.owner_id == user.id)
                                      .order_by(APIKey.created_at, APIKey.id)))
    return dict(generation=user.credential_generation,
                password=dict(configured=bool(user.password_hash),
                              source=user.password_source or user.managed_source,
                              login_available=bool(user.email)), keys=keys)


def _change(db, user, expected_generation, operation_token):
    from .profiles import lock_profile_changes
    if (type(expected_generation) is not int or expected_generation < 1
            or not isinstance(operation_token, str) or not operation_token):
        raise Invalid("Invalid credential form")
    ident = user.id
    lock_profile_changes(db)
    participant = db.scalar(select(Participant).where(Participant.id == ident)
                            .with_for_update().execution_options(populate_existing=True))
    user = db.scalar(select(User).where(User.id == ident).with_for_update(key_share=True)
                     .execution_options(populate_existing=True))
    if not participant or not participant.active or not user or not user.active:
        raise Invalid("Profile is unavailable")
    token_hash = digest(operation_token)
    if db.get(CredentialOperation, token_hash) or user.credential_generation != expected_generation:
        raise Conflict("Credential form was already used or credentials changed")
    # Snapshot before the first UI mutation even when a fresh create_all fixture
    # or an owner-created profile has never run the additive schema upgrade.
    initialize_baseline(user)
    return user, token_hash


def initialize_baseline(user):
    if not user.credential_baseline_set:
        user.configured_password_hash = user.password_hash
        user.configured_api_key_hash = user.api_key_hash
        user.credential_baseline_set = True


def _receipt(db, user, token_hash, purpose, key_id=None):
    user.credential_generation += 1
    db.add(CredentialOperation(token_hash=token_hash, owner_id=user.id, purpose=purpose, key_id=key_id))
    db.flush()


def revoke_password_connections(db, user):
    for family in db.scalars(select(Family).where(Family.owner_id == user.id).order_by(Family.id)):
        revoke_family(db, family.id)


def revoke_service_keys(db, user):
    """Explicit config changes supersede all keys for the credential type."""
    user.api_key_hash = None
    for key_id in db.scalars(select(APIKey.id).where(APIKey.owner_id == user.id)):
        deactivate_subscriptions(db, owner_id=user.id, client_id=service_client(user.id, key_id))
    db.execute(update(APIKey).where(APIKey.owner_id == user.id, APIKey.active.is_(True)).values(active=False))
    deactivate_subscriptions(db, owner_id=user.id, client_id=service_client(user.id))


def reset_password(db, user, password, expected_generation, operation_token):
    if not isinstance(password, str) or not password:
        raise Invalid("Password is required")
    user, token_hash = _change(db, user, expected_generation, operation_token)
    if not user.email:
        raise Invalid("Password login requires an existing email")
    user.password_hash = generate_password_hash(password)
    user.password_source = "database"
    revoke_password_connections(db, user)
    _receipt(db, user, token_hash, "reset-password")


def create_api_key(db, user, expected_generation, operation_token):
    user, token_hash = _change(db, user, expected_generation, operation_token)
    raw_key = secrets.token_urlsafe(48)
    key_hash = digest(raw_key)
    # Both stores identify the same bearer namespace. The shared profile lock
    # serializes this cross-table uniqueness check with config synchronization.
    if (db.scalar(select(User.id).where(User.api_key_hash == key_hash))
            or db.scalar(select(APIKey.id).where(APIKey.key_hash == key_hash))):
        raise Conflict("Credential generation conflicted; open a new form")
    key = APIKey(owner_id=user.id, key_hash=key_hash, source="database")
    db.add(key)
    db.flush()
    _receipt(db, user, token_hash, "create-api-key", key.id)
    return raw_key, key.id


def revoke_api_key(db, user, key_id, expected_generation, operation_token):
    user, token_hash = _change(db, user, expected_generation, operation_token)
    if key_id == "legacy" and user.api_key_hash:
        key_hash = user.api_key_hash
        client_id = service_client(user.id)
        user.api_key_hash = None
        user.api_key_source = "database"
    else:
        key = db.get(APIKey, key_id, populate_existing=True) if isinstance(key_id, str) else None
        if not key or key.owner_id != user.id or not key.active:
            raise Invalid("API key is unavailable")
        key_hash, key.active = key.key_hash, False
        client_id = service_client(user.id, key.id)
    deactivate_subscriptions(db, owner_id=user.id, client_id=client_id,
                             family=service_family(key_hash))
    _receipt(db, user, token_hash, "revoke-api-key", key_id)

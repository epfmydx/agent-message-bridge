"""Durable, idempotent artifacts. Network I/O always occurs outside DB transactions."""
import hashlib
import json
import os
import re
import threading
import tempfile
import time
import uuid

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError

from .errors import Conflict, Invalid, Unavailable, StorageUnavailable
from .models import Artifact, Member, Message, MessageArtifact
from .object_store import S3Store, public_https_stream

# These are credential expiry and crash-recovery leases, not file/usage limits.
URL_TTL = 900
LEASE_SECONDS = 900
CHUNK_BYTES = 1024 * 1024


class _StoreState:
    def __init__(self):
        self.lock, self.store = threading.Lock(), None


class _ProcessStore:
    def __init__(self):
        self.states = {}

    def get(self, settings):
        # setdefault publishes one holder even when first post-fork calls race.
        # A new PID never uses an inherited client or possibly locked mutex.
        state = self.states.setdefault(os.getpid(), _StoreState())
        with state.lock:
            if state.store is None: state.store = S3Store(settings)
            return state.store


def _store(settings, store):
    if store is not None: return store
    from flask import current_app, has_app_context
    if has_app_context():
        cache = current_app.extensions.setdefault("s3_store_cache", _ProcessStore())
        return cache.get(settings)
    return S3Store(settings)


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise Invalid(label + ' is required')
    return value


def _metadata(params, imported=False):
    if not isinstance(params, dict):
        raise Invalid('File parameters must be an object')
    key = _text(params.get('idempotency_key'), 'idempotency_key')
    source = params.get('file', {}) if imported else {}
    if not isinstance(source, dict):
        raise Invalid('file must be an object')
    filename = _text(params.get('filename', source.get('file_name') or 'attachment'), 'filename')
    content_type = _text(params.get('content_type', source.get('mime_type') or 'application/octet-stream'), 'content_type')
    if any(c in content_type for c in '\r\n\x00'):
        raise Invalid('content_type is invalid')
    size = params.get('size_bytes', -1 if imported else None)
    digest = params.get('sha256', '' if imported else None)
    if isinstance(size, bool) or not isinstance(size, int) or size < (-1 if imported and 'size_bytes' not in params else 0):
        raise Invalid('size_bytes must be a nonnegative integer')
    if not isinstance(digest, str) or (digest and not re.fullmatch('[0-9a-fA-F]{64}', digest)) or (not imported and not digest):
        raise Invalid('sha256 must be a SHA-256 hex digest')
    digest = digest.lower()
    identity = {'kind': 'import' if imported else 'upload', 'filename': filename,
                'content_type': content_type, 'size_bytes': size, 'sha256': digest}
    if imported:
        identity['file_id'] = _text(source.get('file_id'), 'file.file_id')
        _text(source.get('download_url'), 'file.download_url')
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return key, filename, content_type, size, digest, fingerprint


def metadata(artifact):
    return {'id': artifact.id, 'filename': artifact.filename, 'content_type': artifact.content_type,
            'size_bytes': artifact.size_bytes if artifact.size_bytes >= 0 else None,
            'sha256': artifact.sha256 or None, 'state': artifact.state}


def _reserve(db, owner_id, values):
    key, filename, content_type, size, digest, fingerprint = values
    query = select(Artifact).where(Artifact.owner_id == owner_id, Artifact.idempotency_key == key).execution_options(populate_existing=True)
    existing = db.scalar(query)
    if existing is None:
        artifact_id = str(uuid.uuid4())
        existing = Artifact(id=artifact_id, owner_id=owner_id, idempotency_key=key,
            object_key='staging/' + artifact_id + '/' + str(uuid.uuid4()), filename=filename,
            content_type=content_type, size_bytes=size, sha256=digest, state='pending',
            input_fingerprint=fingerprint)
        db.add(existing)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.scalar(query)
            if existing is None:
                raise Conflict('File upload could not be reserved; retry') from None
    if existing.input_fingerprint != fingerprint:
        db.rollback()
        raise Conflict('idempotency_key was already used for a different file')
    db.commit()
    return existing


def _owned(db, owner_id, artifact_id):
    artifact = db.scalar(select(Artifact).where(Artifact.id == artifact_id, Artifact.owner_id == owner_id)
        .execution_options(populate_existing=True))
    if artifact is None:
        db.rollback()
        raise Unavailable('File not found')
    db.commit()
    return artifact


def create_upload(db, settings, owner_id, params, store=None):
    values = _metadata(params)
    storage = _store(settings, store)
    artifact = _reserve(db, owner_id, values)
    result = metadata(artifact)
    if artifact.state == 'ready':
        return result
    try:
        result.update(upload_url=storage.presign_put(artifact.object_key, artifact.content_type, URL_TTL),
                      upload_method='PUT', upload_headers={'Content-Type': artifact.content_type,
                          'x-amz-acl': 'private'}, expires_in=URL_TTL)
    except Exception:
        raise StorageUnavailable('File upload URL could not be created; retry') from None
    return result


def _claim(db, artifact):
    token = str(uuid.uuid4())
    changed = db.execute(update(Artifact).where(Artifact.id == artifact.id, Artifact.state != 'ready',
        or_(Artifact.lease.is_(None), Artifact.lease_until.is_(None), Artifact.lease_until < time.time()))
        .values(lease=token, lease_until=time.time() + LEASE_SECONDS))
    db.commit()
    if changed.rowcount != 1:
        db.refresh(artifact)
        db.commit()
        if artifact.state == 'ready':
            return None
        raise Conflict('File verification is in progress; retry')
    return token


def _release(db, artifact_id, token):
    db.rollback()
    db.execute(update(Artifact).where(Artifact.id == artifact_id, Artifact.lease == token)
        .values(lease=None, lease_until=None))
    db.commit()


def _copy_and_hash(source, destination=None):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
        if destination is not None:
            destination.write(chunk)
    return size, digest.hexdigest()


def _verify_expected(artifact, size, digest):
    if (artifact.size_bytes >= 0 and size != artifact.size_bytes) or (artifact.sha256 and digest != artifact.sha256):
        raise Invalid('File bytes do not match the declared size or SHA-256')


def _finalize(db, artifact, token, storage, source_context):
    final_key = 'artifacts/' + artifact.id + '/' + token
    try:
        # Spool on disk, with no file-size quota or full-file memory allocation.
        with tempfile.TemporaryFile() as spool:
            with source_context as source:
                size, digest = _copy_and_hash(source, spool)
            _verify_expected(artifact, size, digest)
            spool.seek(0)
            try:
                storage.write(final_key, spool, artifact.content_type)
            except Exception:
                # A timed-out write may have succeeded. Readback reconciles that outcome.
                pass
            with storage.open(final_key) as persisted:
                persisted_size, persisted_digest = _copy_and_hash(persisted)
            if (size, digest) != (persisted_size, persisted_digest):
                raise StorageUnavailable('Stored file could not be verified; retry')
        changed = db.execute(update(Artifact).where(Artifact.id == artifact.id, Artifact.lease == token,
            Artifact.state != 'ready').values(object_key=final_key, state='ready', size_bytes=size,
            sha256=digest, lease=None, lease_until=None))
        db.commit()
        db.refresh(artifact)
        db.commit()
        if changed.rowcount != 1 and artifact.state != 'ready':
            raise Conflict('File verification lease changed; retry')
        return metadata(artifact)
    except (Invalid, Conflict):
        _release(db, artifact.id, token)
        raise
    except Exception:
        _release(db, artifact.id, token)
        raise StorageUnavailable('File could not be verified and stored; retry') from None


def complete_upload(db, settings, owner_id, artifact_id, store=None):
    artifact = _owned(db, owner_id, artifact_id)
    if artifact.state == 'ready':
        return metadata(artifact)
    storage = _store(settings, store)
    token = _claim(db, artifact)
    if token is None:
        return metadata(artifact)
    return _finalize(db, artifact, token, storage, storage.open(artifact.object_key))


def import_file(db, settings, owner_id, params, store=None, fetcher=None):
    values = _metadata(params, imported=True)
    storage = _store(settings, store)
    artifact = _reserve(db, owner_id, values)
    if artifact.state == 'ready':
        return metadata(artifact)
    token = _claim(db, artifact)
    if token is None:
        return metadata(artifact)
    try:
        source = (fetcher or public_https_stream)(params['file']['download_url'])
    except Exception:
        _release(db, artifact.id, token)
        raise StorageUnavailable('File download failed; provide a fresh download URL and retry') from None
    return _finalize(db, artifact, token, storage, source)


def get_artifact(db, settings, owner_id, artifact_id, store=None):
    artifact = db.get(Artifact, artifact_id, populate_existing=True)
    allowed = artifact is not None and artifact.owner_id == owner_id
    if artifact is not None and not allowed:
        allowed = db.scalar(select(MessageArtifact.artifact_id).join(Message, Message.id == MessageArtifact.message_id)
            .join(Member, and_(Member.thread_id == Message.thread_id, Member.participant_id == owner_id))
            .where(MessageArtifact.artifact_id == artifact_id).limit(1)) is not None
    db.commit()
    if artifact is None or not allowed:
        raise Unavailable('File not found')
    return _download_artifact(settings, artifact, store)


def get_overview_artifact(db, settings, owner_id, artifact_id, store=None):
    """Browser-only owner read; this is never exposed as an MCP/API operation."""
    from .models_auth import BrowserOwner
    owner = db.get(BrowserOwner, owner_id, populate_existing=True)
    artifact = db.get(Artifact, artifact_id, populate_existing=True) if owner and owner.active else None
    db.commit()
    if artifact is None:
        raise Unavailable('File not found')
    return _download_artifact(settings, artifact, store)


def _download_artifact(settings, artifact, store):
    if artifact.state != 'ready':
        raise Conflict('File is not ready')
    storage = _store(settings, store)
    try:
        return dict(metadata(artifact), download_url=storage.presign_get(artifact.object_key,
            artifact.filename, artifact.content_type, URL_TTL), expires_in=URL_TTL)
    except Exception:
        raise StorageUnavailable('File download URL could not be created; retry') from None

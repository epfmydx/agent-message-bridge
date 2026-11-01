import contextlib
import hashlib
import io
import socket

import pytest

from bridge.errors import Conflict, Invalid, Unavailable
from bridge.files import complete_upload, create_upload, get_artifact, import_file
from bridge.models import Artifact, Base, Member, Message, MessageArtifact, Participant, Thread, database
from bridge.object_store import public_https_stream


class FakeStore:
    def __init__(self):
        self.objects = {}
        self.put_keys = {}
        self.fail_write = False
        self.corrupt_write = False
        self.ambiguous_write = False

    def presign_put(self, key, content_type, expires):
        self.put_keys['https://upload.example.com/' + key] = key
        return 'https://upload.example.com/' + key

    def presign_get(self, key, filename, content_type, expires):
        return 'https://download.example.com/' + key

    @contextlib.contextmanager
    def open(self, key):
        yield io.BytesIO(self.objects[key])

    def write(self, key, stream, content_type):
        if self.fail_write:
            raise OSError('sensitive storage error')
        self.objects[key] = b'corrupt' if self.corrupt_write else stream.read()
        if self.ambiguous_write:
            raise OSError('sensitive timeout')


@pytest.fixture
def files_db(tmp_path):
    engine, maker = database('sqlite:///' + str(tmp_path / 'files.db'))
    Base.metadata.create_all(engine)
    with maker() as db:
        db.add_all([Participant(id=p, name=p) for p in ['a', 'b', 'c']])
        db.commit()
        yield db
    engine.dispose()


def upload_params(data=b'hello', **overrides):
    return dict({'idempotency_key': 'upload-one', 'filename': 'hello.txt', 'content_type': 'text/plain',
                 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}, **overrides)


def import_params(**overrides):
    return dict({'idempotency_key': 'import-one', 'file': {'file_id': 'file-a', 'file_name': 'hello.txt',
                'mime_type': 'text/plain', 'download_url': 'https://files.example.com/signed?secret=value'}}, **overrides)


def fetch_bytes(data):
    @contextlib.contextmanager
    def fetch(url):
        yield io.BytesIO(data)
    return fetch


def ready_upload(db, store):
    pending = create_upload(db, {}, 'a', upload_params(), store)
    store.objects[store.put_keys[pending['upload_url']]] = b'hello'
    return pending, complete_upload(db, {}, 'a', pending['id'], store)


def test_upload_retry_integrity_and_immutable_final(files_db):
    store = FakeStore()
    pending, ready = ready_upload(files_db, store)
    assert ready['state'] == 'ready'
    assert ready['sha256'] == hashlib.sha256(b'hello').hexdigest()
    record = files_db.get(Artifact, ready['id'])
    final_key = record.object_key
    assert final_key != store.put_keys[pending['upload_url']]
    # A still-valid old upload URL writes only to staging.
    store.objects[store.put_keys[pending['upload_url']]] = b'altered bytes'
    assert complete_upload(files_db, {}, 'a', ready['id'], store) == ready
    assert create_upload(files_db, {}, 'a', upload_params(), store) == ready
    assert store.objects[final_key] == b'hello'
    with pytest.raises(Conflict):
        create_upload(files_db, {}, 'a', upload_params(filename='other.txt'), store)


def test_failure_stays_pending_and_safe_retry(files_db):
    store = FakeStore()
    pending = create_upload(files_db, {}, 'a', upload_params(), store)
    with pytest.raises(Unavailable, match='verified and stored'):
        complete_upload(files_db, {}, 'a', pending['id'], store)
    store.objects[store.put_keys[pending['upload_url']]] = b'wrong'
    with pytest.raises(Invalid, match='declared'):
        complete_upload(files_db, {}, 'a', pending['id'], store)
    assert files_db.get(Artifact, pending['id']).state == 'pending'
    store.objects[store.put_keys[pending['upload_url']]] = b'hello'
    store.fail_write = True
    with pytest.raises(Unavailable):
        complete_upload(files_db, {}, 'a', pending['id'], store)
    store.fail_write = False
    store.corrupt_write = True
    with pytest.raises(Unavailable):
        complete_upload(files_db, {}, 'a', pending['id'], store)
    store.corrupt_write = False
    store.ambiguous_write = True
    assert complete_upload(files_db, {}, 'a', pending['id'], store)['state'] == 'ready'


def test_import_idempotency_url_rotation_and_no_source_url_storage(files_db):
    store = FakeStore()
    params = import_params()
    ready = import_file(files_db, {}, 'a', params, store, fetch_bytes(b'hello'))
    assert ready['size_bytes'] == 5
    rotated = import_params(file=dict(params['file'], download_url='https://files.example.com/new?secret=rotated'))
    def should_not_fetch(url):
        raise AssertionError('ready retry must not fetch')
    assert import_file(files_db, {}, 'a', rotated, store, should_not_fetch) == ready
    record = files_db.get(Artifact, ready['id'])
    assert 'secret' not in str(record.__dict__)
    with pytest.raises(Conflict):
        import_file(files_db, {}, 'a', import_params(file=dict(params['file'], file_id='file-b')), store, fetch_bytes(b'hello'))
    with pytest.raises(Conflict):
        create_upload(files_db, {}, 'a', upload_params(idempotency_key='import-one'), store)


def test_import_bad_digest_and_fetch_failure_retry(files_db):
    store = FakeStore()
    params = import_params(size_bytes=5, sha256=hashlib.sha256(b'hello').hexdigest())
    with pytest.raises(Invalid):
        import_file(files_db, {}, 'a', params, store, fetch_bytes(b'wrong'))
    @contextlib.contextmanager
    def fail(url):
        raise OSError('https://private.example.com/?secret=bad')
        yield
    with pytest.raises(Unavailable) as caught:
        import_file(files_db, {}, 'a', params, store, fail)
    assert 'secret' not in str(caught.value)
    assert import_file(files_db, {}, 'a', params, store, fetch_bytes(b'hello'))['state'] == 'ready'


def test_thread_scoped_authorization(files_db):
    store = FakeStore()
    _, ready = ready_upload(files_db, store)
    assert get_artifact(files_db, {}, 'a', ready['id'], store)['download_url']
    for participant in ['b', 'c']:
        with pytest.raises(Unavailable, match='not found'):
            get_artifact(files_db, {}, participant, ready['id'], store)
        with pytest.raises(Unavailable, match='not found'):
            complete_upload(files_db, {}, participant, ready['id'], store)
    files_db.add(Thread(id='thread-one'))
    files_db.commit()
    files_db.add_all([Member(thread_id='thread-one', participant_id=p) for p in ['a', 'b']])
    files_db.add(Message(id='message-one', thread_id='thread-one', sender_id='a', recipient_id='b', text='',
        status='received', needs_reply=False, sequence=1, fingerprint='synthetic'))
    files_db.commit()
    files_db.add(MessageArtifact(message_id='message-one', artifact_id=ready['id']))
    files_db.commit()
    assert get_artifact(files_db, {}, 'b', ready['id'], store)['id'] == ready['id']
    with pytest.raises(Unavailable):
        get_artifact(files_db, {}, 'c', ready['id'], store)


def test_pending_and_concurrent_lease(files_db):
    import time
    store = FakeStore()
    pending = create_upload(files_db, {}, 'a', upload_params(), store)
    with pytest.raises(Conflict, match='not ready'):
        get_artifact(files_db, {}, 'a', pending['id'], store)
    record = files_db.get(Artifact, pending['id'])
    record.lease, record.lease_until = 'another-process', time.time() + 900
    files_db.commit()
    with pytest.raises(Conflict, match='in progress'):
        complete_upload(files_db, {}, 'a', pending['id'], store)
    record.lease_until = 0
    files_db.commit()
    store.objects[store.put_keys[pending['upload_url']]] = b'hello'
    assert complete_upload(files_db, {}, 'a', pending['id'], store)['state'] == 'ready'


def test_missing_storage_fails_clearly(files_db):
    with pytest.raises(Unavailable, match='not configured'):
        create_upload(files_db, {}, 'a', upload_params())


@pytest.mark.parametrize('url', ['http://files.example.com/a', 'https://user:pass@files.example.com/a',
    'https://127.0.0.1/a', 'https://169.254.169.254/a', 'https://[::1]/a',
    'https://files.example.com/a#fragment'])
def test_private_and_invalid_urls_rejected(url):
    with pytest.raises(Invalid):
        with public_https_stream(url):
            pytest.fail('must not return a private stream')


def test_all_dns_answers_checked_before_connect(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))])
    with pytest.raises(Invalid):
        with public_https_stream('https://files.example.com/a'):
            pytest.fail('mixed private DNS must be rejected')


def test_pinned_socket_keeps_tls_hostname(monkeypatch):
    from bridge.object_store import _PinnedHTTPSConnection
    calls = []
    class RawSocket:
        def settimeout(self, timeout):
            assert 0 < timeout <= 60
    raw = RawSocket()
    monkeypatch.setattr(socket, 'create_connection', lambda address, timeout: calls.append(address) or raw)
    class TLS:
        def wrap_socket(self, sock, server_hostname):
            calls.append((sock, server_hostname))
            return 'tls-socket'
    connection = _PinnedHTTPSConnection('files.example.com', 443, '8.8.8.8')
    connection._context = TLS()
    connection.connect()
    assert calls == [('8.8.8.8', 443), (raw, 'files.example.com')]
    assert connection.sock == 'tls-socket'


def test_https_no_redirect_and_incomplete_response(monkeypatch):
    import bridge.object_store as transport
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))])
    class Response(io.BytesIO):
        status = 302
        length = 10
    response = Response(b'hello')
    calls = []
    class Connection:
        def __init__(self, hostname, port, address, timeout):
            calls.append((hostname, port, address))
            self.sock = self
        def settimeout(self, timeout):
            pass
        def connect(self):
            pass
        def request(self, method, target, headers):
            calls.append((method, target, headers))
        def getresponse(self):
            return response
        def close(self):
            calls.append('closed')
    monkeypatch.setattr(transport, '_PinnedHTTPSConnection', Connection)
    with pytest.raises(Unavailable):
        with public_https_stream('https://files.example.com/a?signature=synthetic'):
            pytest.fail('must not follow redirect')
    assert calls[-1] == 'closed'
    assert len([c for c in calls if isinstance(c, tuple) and c[0] == 'GET']) == 1
    response.status = 200
    with pytest.raises(Unavailable, match='incomplete'):
        with public_https_stream('https://files.example.com/a') as stream:
            assert stream.read(1024) == b'hello'
            stream.read(1024)


def test_network_io_outside_database_transaction(files_db):
    class TransactionCheckingStore(FakeStore):
        @contextlib.contextmanager
        def open(self, key):
            assert not files_db.in_transaction()
            with super().open(key) as body:
                yield body
        def write(self, key, stream, content_type):
            assert not files_db.in_transaction()
            return super().write(key, stream, content_type)
        def presign_put(self, key, content_type, expires):
            assert not files_db.in_transaction()
            return super().presign_put(key, content_type, expires)
        def presign_get(self, key, filename, content_type, expires):
            assert not files_db.in_transaction()
            return super().presign_get(key, filename, content_type, expires)
    store = TransactionCheckingStore()
    _, ready = ready_upload(files_db, store)
    assert get_artifact(files_db, {}, 'a', ready['id'], store)['download_url']
    @contextlib.contextmanager
    def fetch(url):
        assert not files_db.in_transaction()
        yield io.BytesIO(b'hello')
    assert import_file(files_db, {}, 'a', import_params(), store, fetch)['state'] == 'ready'


def test_concurrent_upload_reservation_uses_one_identity(files_db):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session
    import threading
    barrier = threading.Barrier(4)
    store = FakeStore()
    engine = files_db.get_bind()
    def reserve(_):
        with Session(engine, expire_on_commit=False) as session:
            barrier.wait()
            return create_upload(session, {}, 'a', upload_params(), store)['id']
    with ThreadPoolExecutor(max_workers=4) as pool:
        identities = list(pool.map(reserve, range(4)))
    assert len(set(identities)) == 1
    assert files_db.scalar(select(func.count()).select_from(Artifact)) == 1
    files_db.commit()


@pytest.mark.parametrize('encoded_private', [
    '64:ff9b::127.0.0.1', '::ffff:127.0.0.1', '2002:7f00:1::',
    '2001:0000:0808:0808:0000:0000:80ff:fffe',
])
@pytest.mark.parametrize('mixed', [False, True])
def test_transition_ipv6_cannot_bypass_public_download_check(monkeypatch, encoded_private, mixed):
    records = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', (encoded_private, 443, 0, 0))]
    if mixed:
        records.insert(0, (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: records)
    monkeypatch.setattr(socket, 'create_connection', lambda *args, **kwargs: pytest.fail('must reject before connect'))
    with pytest.raises(Invalid, match='public HTTPS'):
        with public_https_stream('https://files.example.com/a'):
            pytest.fail('private embedded IPv4 must be rejected')


def test_s3_presigning_uses_sigv4_private_acl_and_explicit_checksum_compatibility(monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    from bridge.object_store import S3Store
    monkeypatch.setattr(socket, 'create_connection', lambda *args, **kwargs: pytest.fail('signing must stay offline'))
    store = S3Store({'S3_ENDPOINT': 'https://s3.example.com', 'S3_REGION': 'sgp1',
        'S3_BUCKET': 'synthetic-private', 'S3_ACCESS_KEY': 'synthetic-access',
        'S3_SECRET_KEY': 'synthetic-secret'})
    config = store.client.meta.config
    assert config.signature_version == 's3v4'
    assert config.request_checksum_calculation == 'when_required'
    assert config.response_checksum_validation == 'when_required'
    query = parse_qs(urlsplit(store.presign_put('staging/synthetic', 'text/plain', 900)).query)
    assert query['X-Amz-Algorithm'] == ['AWS4-HMAC-SHA256']
    assert query['X-Amz-Expires'] == ['900']
    assert query['X-Amz-SignedHeaders'] == ['content-type;host;x-amz-acl']
    assert 'AWSAccessKeyId' not in query
    download = parse_qs(urlsplit(store.presign_get('artifacts/synthetic', 'report.txt', 'text/plain', 900)).query)
    assert download['X-Amz-Algorithm'] == ['AWS4-HMAC-SHA256']
    assert download['response-content-type'] == ['text/plain']


def test_public_download_falls_back_before_http_and_sends_once(monkeypatch):
    import bridge.object_store as transport
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700:4700::1111', 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
    ])
    calls = []
    class Response(io.BytesIO):
        status = 200
        length = 5
    class Connection:
        def __init__(self, hostname, port, address, timeout):
            self.address = address
            self.sock = self
            assert hostname == 'files.example.com'
            assert 0 < timeout <= 60
        def connect(self):
            calls.append(('connect', self.address))
            if ':' in self.address:
                raise OSError('no IPv6 route')
        def settimeout(self, timeout):
            pass
        def request(self, method, target, headers):
            calls.append(('request', self.address))
        def getresponse(self):
            return Response(b'hello')
        def close(self):
            calls.append(('close', self.address))
    monkeypatch.setattr(transport, '_PinnedHTTPSConnection', Connection)
    with public_https_stream('https://files.example.com/a') as stream:
        assert stream.read(1024) == b'hello'
        assert stream.read(1024) == b''
    assert [c for c in calls if c[0] == 'connect'] == [
        ('connect', '2606:4700:4700::1111'), ('connect', '8.8.8.8')]
    assert [c for c in calls if c[0] == 'request'] == [('request', '8.8.8.8')]
    assert ('close', '2606:4700:4700::1111') in calls


def test_public_download_never_retries_after_possible_http_transmission(monkeypatch):
    import bridge.object_store as transport
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))
        for address in ['8.8.8.8', '1.1.1.1']])
    calls = []
    class Connection:
        def __init__(self, hostname, port, address, timeout):
            self.address = address
            self.sock = self
        def connect(self):
            calls.append(('connect', self.address))
        def settimeout(self, timeout):
            pass
        def request(self, *args, **kwargs):
            calls.append(('request', self.address))
            raise OSError('request may have been sent')
        def close(self):
            calls.append(('close', self.address))
    monkeypatch.setattr(transport, '_PinnedHTTPSConnection', Connection)
    with pytest.raises(Unavailable):
        with public_https_stream('https://files.example.com/a'):
            pytest.fail('request failed')
    assert [c for c in calls if c[0] == 'connect'] == [('connect', '8.8.8.8')]
    assert [c for c in calls if c[0] == 'request'] == [('request', '8.8.8.8')]


def test_public_connect_fallback_shares_one_deadline(monkeypatch):
    import bridge.object_store as transport
    clock = [0.0]
    attempts = []
    monkeypatch.setattr(transport.time, 'monotonic', lambda: clock[0])
    class Connection:
        def __init__(self, hostname, port, address, timeout):
            self.address = address
            self.timeout = timeout
            attempts.append((address, timeout))
        def connect(self):
            clock[0] += self.timeout
            raise TimeoutError
        def close(self):
            pass
    monkeypatch.setattr(transport, '_PinnedHTTPSConnection', Connection)
    with pytest.raises(Unavailable):
        transport._connect_public('files.example.com', 443, ['8.8.8.8', '1.1.1.1'], timeout=60)
    assert attempts == [('8.8.8.8', 30), ('1.1.1.1', 30)]
    assert clock[0] == 60

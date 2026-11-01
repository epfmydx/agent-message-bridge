"""Private S3 storage and a DNS-pinned, streaming HTTPS download transport."""
import contextlib
import http.client
import socket
import ssl
import time
from urllib.parse import urlsplit

from .errors import Invalid, Unavailable, StorageUnavailable
from .network import is_public_unicast


class S3Store:
    def __init__(self, settings):
        required = ('S3_ENDPOINT', 'S3_REGION', 'S3_BUCKET', 'S3_ACCESS_KEY', 'S3_SECRET_KEY')
        if not all(settings.get(key) for key in required):
            raise StorageUnavailable('Private file storage is not configured')
        try:
            import boto3
            from botocore.config import Config
            self.client = boto3.client('s3', endpoint_url=settings['S3_ENDPOINT'],
                region_name=settings['S3_REGION'], aws_access_key_id=settings['S3_ACCESS_KEY'],
                aws_secret_access_key=settings['S3_SECRET_KEY'], config=Config(
                    signature_version='s3v4', request_checksum_calculation='when_required',
                    response_checksum_validation='when_required'))
        except Exception:
            raise StorageUnavailable('Private file storage is unavailable') from None
        self.bucket = settings['S3_BUCKET']

    def presign_put(self, key, content_type, expires):
        return self.client.generate_presigned_url('put_object', Params={
            'Bucket': self.bucket, 'Key': key, 'ContentType': content_type,
            'ACL': 'private'}, ExpiresIn=expires)

    def presign_get(self, key, filename, content_type, expires):
        # RFC 5987 avoids injecting a caller-provided name into response headers.
        from urllib.parse import quote
        return self.client.generate_presigned_url('get_object', Params={
            'Bucket': self.bucket, 'Key': key,
            'ResponseContentType': content_type,
            'ResponseContentDisposition': "attachment; filename*=UTF-8''" + quote(filename, safe='')}, ExpiresIn=expires)

    @contextlib.contextmanager
    def open(self, key):
        body = self.client.get_object(Bucket=self.bucket, Key=key)['Body']
        try:
            yield body
        finally:
            body.close()

    def write(self, key, stream, content_type):
        self.client.upload_fileobj(stream, self.bucket, key,
            ExtraArgs={'ContentType': content_type, 'ACL': 'private'})


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, port, address, timeout=60):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        deadline = time.monotonic() + self.timeout
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            sock.settimeout(remaining)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class _DownloadBody:
    def __init__(self, response):
        self.response = response
        self.remaining = response.length

    def read(self, amount):
        chunk = self.response.read(amount)
        if self.remaining is not None:
            self.remaining -= len(chunk)
            if self.remaining < 0 or (not chunk and self.remaining != 0):
                raise Unavailable('File download was incomplete; retry')
        return chunk


def _public_address(value):
    return is_public_unicast(value)


def _connect_public(hostname, port, addresses, timeout=60):
    """Try validated addresses before sending HTTP, within one connect budget."""
    deadline = time.monotonic() + timeout
    for index, address in enumerate(addresses):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Reserve time for every remaining address, including IPv4 fallback.
        attempt_timeout = remaining / (len(addresses) - index)
        connection = _PinnedHTTPSConnection(hostname, port, address, timeout=attempt_timeout)
        connection.timeout = min(attempt_timeout, deadline - time.monotonic())
        if connection.timeout <= 0:
            connection.close()
            break
        try:
            connection.connect()
            # Connection attempts share a deadline; body reads retain the
            # ordinary idle timeout and do not impose a total file duration.
            connection.sock.settimeout(timeout)
            return connection
        except Exception:
            connection.close()
    raise Unavailable('File download connection failed; retry')


@contextlib.contextmanager
def public_https_stream(url):
    """Resolve once, validate every address, pin the socket, retain TLS hostname checks.

    Uses neither environment proxies nor redirects. Never includes URLs in errors.
    """
    connection = None
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            raise Invalid('File download must use a public HTTPS URL')
        hostname = parsed.hostname.encode('idna').decode('ascii')
        port = parsed.port or 443
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addresses or any(not _public_address(item[4][0]) for item in addresses):
            raise Invalid('File download must use a public HTTPS URL')
        numeric_addresses = list(dict.fromkeys(item[4][0] for item in addresses))
        connection = _connect_public(hostname, port, numeric_addresses)
        target = parsed.path or '/'
        if parsed.query:
            target += '?' + parsed.query
        connection.request('GET', target, headers={'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        if response.status != 200:
            raise Unavailable('File download failed; provide a fresh download URL and retry')
        yield _DownloadBody(response)
    except (Invalid, Unavailable):
        raise
    except Exception:
        raise Unavailable('File download failed; provide a fresh download URL and retry') from None
    finally:
        if connection is not None:
            connection.close()

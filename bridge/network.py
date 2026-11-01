"""Public HTTPS callback delivery with DNS pinning and a wall-clock deadline.

Only standard-library imports run in the parent process. DNS, TLS, request
writing, and response reading run in a disposable spawned process so a resolver
or peer that stalls cannot outlive the configured attempt deadline.
"""

import ipaddress
import multiprocessing
import socket
import time
from urllib.parse import urlsplit


REQUEST_DEADLINE_SECONDS = 10
# The verification response carries only a small challenge object. This bound
# limits transport memory and is enforced only for the subscription challenge.
CHALLENGE_RESPONSE_MAX_BYTES = 4096
# MCP Events' documented maximum event body size.
MCP_EVENT_BODY_MAX_BYTES = 256 * 1024
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


def is_public_unicast(value: str) -> bool:
    """Accept global unicast only, including addresses that encode IPv4."""
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        embedded = []
        if address.ipv4_mapped is not None:
            embedded.append(address.ipv4_mapped)
        elif address in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        elif address.sixtofour is not None:
            embedded.append(address.sixtofour)
        elif address.teredo is not None:
            embedded.extend(address.teredo)
        return all(item.is_global and not item.is_multicast for item in embedded)
    return True


class _InvalidDestination(Exception):
    pass


def _parse_destination(url: str):
    if not isinstance(url, str) or not url:
        raise _InvalidDestination
    try:
        parsed = urlsplit(url)
        port = parsed.port if parsed.port is not None else 443
        valid = (
            parsed.scheme.lower() == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and 1 <= port <= 65535
            and not any(char.isspace() for char in url)
        )
    except (TypeError, ValueError, UnicodeError):
        valid = False
        parsed = None
        port = 443
    if not valid or parsed is None:
        raise _InvalidDestination
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and not is_public_unicast(str(literal)):
        raise _InvalidDestination
    return parsed, port


def _resolve_public(hostname: str, port: int, resolver=None) -> list[str]:
    lookup = resolver or socket.getaddrinfo
    try:
        records = lookup(hostname, port, type=socket.SOCK_STREAM)
    except TimeoutError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise ConnectionError from exc
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses or any(not is_public_unicast(address) for address in addresses):
        raise _InvalidDestination
    return addresses


def _host_header(parsed, port: int) -> str:
    hostname = parsed.hostname
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        authority_host = hostname.encode("idna").decode("ascii")
    else:
        authority_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    return authority_host + (f":{port}" if parsed.port is not None else "")


def _pinned_post(url: str, ip: str, body: bytes, headers: dict[str, str], *, connect_timeout=5):
    """Send once to a validated numeric address while verifying the URL host."""
    parsed, port = _parse_destination(url)
    if not is_public_unicast(ip):
        raise _InvalidDestination

    import certifi
    import urllib3

    class ObservedConnection(urllib3.connection.HTTPSConnection):
        def connect(self):
            # urllib3 receives the numeric pool host. Explicit server_hostname
            # and assert_hostname keep SNI and certificate checks on URL host.
            super().connect()

    pool = urllib3.HTTPSConnectionPool(
        ip,
        port,
        assert_hostname=parsed.hostname,
        server_hostname=parsed.hostname,
        cert_reqs="CERT_REQUIRED",
        ca_certs=certifi.where(),
        maxsize=1,
    )
    pool.ConnectionCls = ObservedConnection
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    response = None
    try:
        response = pool.urlopen(
            "POST",
            path,
            body=body,
            headers={**headers, "Host": _host_header(parsed, port)},
            timeout=urllib3.Timeout(connect=connect_timeout, read=5),
            retries=False,
            redirect=False,
            preload_content=False,
        )
        try:
            challenge = __import__("json").loads(body).get("type") == "verification"
        except (ValueError, AttributeError):
            challenge = False
        # Event deliveries need only the status. Challenge verification reads
        # one beyond its protocol response bound to reject oversize replies.
        answer = response.read(CHALLENGE_RESPONSE_MAX_BYTES + 1) if challenge else b""
        return response.status, answer
    finally:
        if response is not None:
            response.close()
        pool.close()


def _child(connection, url: str, body: bytes, headers: dict[str, str], timeout=REQUEST_DEADLINE_SECONDS):
    try:
        deadline = time.monotonic()+timeout
        parsed, port = _parse_destination(url)
        addresses = _resolve_public(parsed.hostname, port)
        import urllib3
        # Try another validated address only when connection establishment
        # failed before any HTTP body could be sent. An ambiguous response or
        # write timeout is left to durable retry/consumer deduplication.
        result = None
        for index, address in enumerate(addresses):
            try:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise TimeoutError
                # Reserve a share for every remaining validated address, so
                # blackholed IPv6 answers cannot starve a reachable IPv4 one.
                budget = min(5, remaining/(len(addresses)-index))
                result = _pinned_post(url, address, body, headers, connect_timeout=budget)
                break
            except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError):
                if index == len(addresses)-1: raise
        connection.send(("ok", result))
    except _InvalidDestination:
        connection.send(("invalid_destination", None))
    except (TimeoutError, socket.timeout):
        connection.send(("timeout", None))
    except Exception as exc:
        # urllib3 uses its own timeout hierarchy; classify it without sending
        # exception details or type names across the process boundary.
        try:
            import urllib3

            outcome = "timeout" if isinstance(exc, urllib3.exceptions.TimeoutError) else "connection_failed"
        except Exception:
            outcome = "connection_failed"
        connection.send((outcome, None))
    finally:
        connection.close()


def _stop(process) -> None:
    if process.pid is None:
        process.close()
        return
    if process.is_alive():
        process.terminate()
        process.join(0.25)
        if process.is_alive():
            process.kill()
    process.join()
    process.close()


def _process_context():
    return multiprocessing.get_context("spawn")


def post_callback(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout: float = REQUEST_DEADLINE_SECONDS,
) -> tuple[int, bytes]:
    """POST once to a public HTTPS destination under an elapsed-time bound."""
    if not isinstance(body, bytes):
        raise TypeError("Callback body must be bytes")
    if len(body) > MCP_EVENT_BODY_MAX_BYTES:
        raise ValueError("MCP event body exceeds the protocol limit")
    try:
        _parse_destination(url)
    except _InvalidDestination as exc:
        from .transport import CallbackError

        raise CallbackError("invalid_destination") from exc
    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    context = _process_context()
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_child, args=(send, url, body, headers, timeout))
    deadline = time.monotonic() + timeout
    try:
        process.start()
        send.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receive.poll(remaining):
            raise TimeoutError
        try:
            outcome, result = receive.recv()
        except EOFError as exc:
            raise ConnectionError from exc
        if time.monotonic() > deadline:
            raise TimeoutError
        if outcome == "ok":
            status, response = result
            return int(status), bytes(response)
        if outcome == "invalid_destination":
            from .transport import CallbackError

            raise CallbackError("invalid_destination")
        if outcome == "timeout":
            raise TimeoutError
        raise ConnectionError
    except TimeoutError as exc:
        from .transport import CallbackError

        raise CallbackError("timeout") from exc
    except Exception as exc:
        from .transport import CallbackError

        if isinstance(exc, CallbackError):
            raise
        raise CallbackError("connection_failed") from exc
    finally:
        send.close()
        receive.close()
        _stop(process)


__all__ = (
    "CHALLENGE_RESPONSE_MAX_BYTES",
    "MCP_EVENT_BODY_MAX_BYTES",
    "REQUEST_DEADLINE_SECONDS",
    "is_public_unicast",
    "post_callback",
)

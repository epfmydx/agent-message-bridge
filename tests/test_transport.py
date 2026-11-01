import base64
import hashlib
import hmac
import json

import pytest
import urllib3

from bridge import network
from bridge.transport import CallbackError, signed_headers, verify_callback


def test_standard_webhooks_exact_bytes_and_rotation():
    secret = "whsec_"+base64.b64encode(b"x"*32).decode()
    previous = "whsec_"+base64.b64encode(b"y"*32).decode()
    body = b'{"message_id":"synthetic"}'
    headers = signed_headers(secret, "event-one", body, "sub-one", timestamp=123, previous_secret=previous)
    for value, key in zip(headers["webhook-signature"].split(), (b"x"*32, b"y"*32)):
        assert value == "v1,"+base64.b64encode(hmac.new(key, b"event-one.123."+body, hashlib.sha256).digest()).decode()
    assert headers["webhook-id"] == "event-one"


def test_callback_challenge_exact_echo_required():
    secret = "whsec_"+base64.b64encode(b"x"*32).decode()
    def echo(url, body, headers): return 200, body
    verify_callback("https://callback.example.com/hook", secret, "sub-one", post=echo)
    with pytest.raises(CallbackError, match="CallbackError"):
        verify_callback("https://callback.example.com/hook", secret, "sub-one", post=lambda *a: (200, b'{"challenge":"wrong"}'))


def test_callback_falls_back_only_before_request_transmission(monkeypatch):
    class Pipe:
        def send(self, value): self.value = value
        def close(self): pass
    pipe, attempts = Pipe(), []
    monkeypatch.setattr(network, "_resolve_public", lambda *a: ["2001:4860:4860::8888", "93.184.216.34"])
    def post(url, address, body, headers, **kwargs):
        attempts.append(address)
        if len(attempts) == 1: raise urllib3.exceptions.NewConnectionError(None, "synthetic no IPv6 route")
        return 200, b""
    monkeypatch.setattr(network, "_pinned_post", post)
    network._child(pipe, "https://callback.example.com/hook", b"{}", {})
    assert pipe.value == ("ok", (200, b"")) and len(attempts) == 2
    attempts.clear()
    def ambiguous(*args, **kwargs):
        attempts.append(args[1])
        raise urllib3.exceptions.ReadTimeoutError(None, "/", "synthetic outcome unknown")
    monkeypatch.setattr(network, "_pinned_post", ambiguous)
    network._child(pipe, "https://callback.example.com/hook", b"{}", {})
    assert pipe.value[0] == "timeout" and len(attempts) == 1


def test_blackholed_addresses_share_callback_deadline(monkeypatch):
    class Pipe:
        def send(self, value): self.value = value
        def close(self): pass
    clock, budgets, pipe = [0.0], [], Pipe()
    monkeypatch.setattr(network.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(network, "_resolve_public", lambda *a: ["2001:4860::1", "2001:4860::2", "93.184.216.34"])
    def post(url, address, body, headers, *, connect_timeout):
        budgets.append(connect_timeout)
        if ":" in address:
            clock[0] += connect_timeout
            raise urllib3.exceptions.ConnectTimeoutError("synthetic blackhole")
        return 200, b""
    monkeypatch.setattr(network, "_pinned_post", post)
    network._child(pipe, "https://callback.example.com/hook", b"{}", {}, timeout=10)
    assert pipe.value == ("ok", (200, b""))
    assert len(budgets) == 3 and all(3 < b < 3.34 for b in budgets)
    assert clock[0] < 10


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "::1", "64:ff9b::127.0.0.1", "2002:7f00:1::", "ff02::1"])
def test_callbacks_reject_private_and_embedded_destinations(address):
    assert not network.is_public_unicast(address)


def test_callback_checks_every_dns_answer():
    def resolver(*args, **kwargs):
        return [(None, None, None, None, ("93.184.216.34", 443)), (None, None, None, None, ("127.0.0.1", 443))]
    with pytest.raises(network._InvalidDestination): network._resolve_public("callback.example.com", 443, resolver=resolver)

"""Secure, bounded MCP Events callback transport."""

import base64
import hashlib
import hmac
import json
import secrets
import time

from .network import post_callback


class CallbackError(Exception):
    """Callback failure with a deliberately small, safe public reason set."""

    _REASONS = frozenset(
        ("timeout", "connection_failed", "challenge_failed", "invalid_destination")
    )

    def __init__(self, reason: str):
        if reason not in self._REASONS:
            raise ValueError("Invalid callback error reason")
        self.reason = reason
        super().__init__("CallbackError")


def secret_bytes(secret: str) -> bytes:
    """Decode a Standard Webhooks secret after enforcing the documented shape."""
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise ValueError("Invalid webhook secret")
    try:
        value = base64.b64decode(secret[6:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Invalid webhook secret") from exc
    if not 24 <= len(value) <= 64:
        raise ValueError("Invalid webhook secret")
    return value


def signed_headers(
    secret: str,
    event_id: str,
    body: bytes,
    subscription_id: str,
    timestamp: int | str | None = None,
    previous_secret: str | None = None,
) -> dict[str, str]:
    """Build Standard Webhooks v1 signatures over the exact transmitted bytes."""
    if not isinstance(body, bytes):
        raise TypeError("Webhook body must be bytes")
    timestamp_text = str(int(time.time()) if timestamp is None else timestamp)
    signing_input = event_id.encode("utf-8") + b"." + timestamp_text.encode("ascii") + b"." + body
    keys = [secret_bytes(secret)]
    if previous_secret is not None:
        keys.append(secret_bytes(previous_secret))
    signatures = [
        "v1," + base64.b64encode(hmac.new(key, signing_input, hashlib.sha256).digest()).decode("ascii")
        for key in keys
    ]
    return {
        "webhook-id": event_id,
        "webhook-timestamp": timestamp_text,
        "webhook-signature": " ".join(signatures),
        "X-MCP-Subscription-Id": subscription_id,
        "Content-Type": "application/json",
    }


def verify_callback(url: str, secret: str, subscription_id: str, post=post_callback) -> None:
    """Send a signed challenge and require an exact, constant-time echo."""
    challenge = secrets.token_urlsafe(32)
    body = json.dumps(
        {"type": "verification", "challenge": challenge},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    headers = signed_headers(
        secret,
        "verify_" + secrets.token_hex(16),
        body,
        subscription_id,
    )
    try:
        status, response = post(url, body, headers)
    except CallbackError:
        raise
    except TimeoutError as exc:
        raise CallbackError("timeout") from exc
    except Exception as exc:
        raise CallbackError("connection_failed") from exc

    try:
        if not 200 <= status < 300 or not isinstance(response, bytes) or len(response) > 4096:
            raise ValueError
        data = json.loads(response)
        echoed = data.get("challenge") if isinstance(data, dict) else None
        if not isinstance(echoed, str) or not hmac.compare_digest(echoed, challenge):
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise CallbackError("challenge_failed") from None


__all__ = ("CallbackError", "secret_bytes", "signed_headers", "verify_callback", "post_callback")

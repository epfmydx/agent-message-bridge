"""Private runtime configuration. No working credentials belong in this repo."""
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet


def load_settings():
    config = json.loads(Path(os.environ["BRIDGE_CONFIG"]).read_text())
    result = {"DATABASE_URL": os.environ["DATABASE_URL"], "BASE_URL": os.environ["BASE_URL"].rstrip("/"),
              "SECRET_KEY": os.environ["SESSION_SECRET"], "ENCRYPTION_KEY": os.environ["ENCRYPTION_KEY"],
              "USERS": config["participants"], "BROWSER_OWNERS": config.get("owners", []),
              "WEBHOOK_PARTICIPANT_ID": config["webhook_participant_id"]}
    for item in result["USERS"]:
        item["password_hash"] = os.environ[item["password_hash_env"]] if item.get("password_hash_env") else ""
        if item.get("api_key_env"):
            raw = os.environ[item["api_key_env"]]
            if not raw: raise ValueError("Participant API credential is required")
            item["api_key_hash"] = hashlib.sha256(raw.encode()).hexdigest()
    if not isinstance(result["BROWSER_OWNERS"], list):
        raise ValueError("BROWSER_OWNERS must be a list")
    for item in result["BROWSER_OWNERS"]:
        if not isinstance(item, dict) or not isinstance(item.get("password_hash_env"), str) or not item["password_hash_env"].strip():
            raise ValueError("Browser owner password_hash_env is required")
        item["password_hash"] = os.environ[item["password_hash_env"]]
    for key in ("WEBHOOK_URL", "WEBHOOK_TOKEN", "S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY", "CLOUDFLARE_ORIGIN_SECRET", "TRUSTED_PROXY_CIDRS"):
        result[key] = os.environ.get(key, "")
    validate_settings(result)
    return result


def https_origin(value, *, local=False):
    try:
        p = urlsplit(value)
        allowed = p.scheme == "https" or (local and p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1", "::1"))
        return bool(allowed and p.hostname and not p.username and not p.password and not p.query and not p.fragment and p.path in ("", "/"))
    except (ValueError, TypeError): return False


def validate_settings(settings):
    from .cloudflare import proxy_networks
    settings["TRUSTED_PROXY_CIDRS"] = proxy_networks(settings.get("TRUSTED_PROXY_CIDRS", ""))
    origin = settings.get("CLOUDFLARE_ORIGIN_SECRET", "")
    if not isinstance(origin, str) or (origin and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", origin)):
        raise ValueError("CLOUDFLARE_ORIGIN_SECRET must contain 32 to 256 URL-safe characters")
    settings["CLOUDFLARE_ORIGIN_SECRET"] = origin
    Fernet(settings["ENCRYPTION_KEY"].encode())
    if not settings.get("SECRET_KEY"): raise ValueError("SESSION_SECRET is required")
    if not https_origin(settings["BASE_URL"], local=True): raise ValueError("BASE_URL must be an HTTPS origin or localhost origin")
    users = settings["USERS"]
    ids = [u["id"] for u in users]
    emails = [u["email"].casefold() for u in users]
    keys = [u["api_key_hash"] for u in users if u.get("api_key_hash")]
    if origin and (origin in [settings.get(k) for k in ("SECRET_KEY", "ENCRYPTION_KEY", "WEBHOOK_TOKEN", "S3_SECRET_KEY")]
                   or hashlib.sha256(origin.encode()).hexdigest() in keys):
        raise ValueError("CLOUDFLARE_ORIGIN_SECRET must be a dedicated secret")
    if not ids or len(set(ids)) != len(ids) or len(set(emails)) != len(emails) or len(set(keys)) != len(keys):
        raise ValueError("Participant identities and credentials must be unique")
    for u in users:
        if not all(isinstance(u.get(k), str) and u[k] for k in ("id", "name", "email")) or not (u.get("password_hash") or u.get("api_key_hash")):
            raise ValueError("Participant identity and authentication are required")
    owners = settings.setdefault("BROWSER_OWNERS", [])
    if not isinstance(owners, list):
        raise ValueError("BROWSER_OWNERS must be a list")
    for owner in owners:
        if not isinstance(owner, dict) or set(owner)-{"id", "name", "email", "password_hash", "password_hash_env"}:
            raise ValueError("Browser owners accept only identity and password authentication")
        if not all(isinstance(owner.get(k), str) and owner[k].strip() for k in ("id", "name", "email", "password_hash")):
            raise ValueError("Browser owner identity and password authentication are required")
    owner_ids = [owner["id"] for owner in owners]
    owner_emails = [owner["email"].casefold() for owner in owners]
    if (len(set(ids+owner_ids)) != len(ids+owner_ids)
            or len(set(emails+owner_emails)) != len(emails+owner_emails)):
        raise ValueError("Browser owner and participant identities must be unique")
    if settings["WEBHOOK_PARTICIPANT_ID"] not in ids: raise ValueError("Unknown webhook participant")
    webhook = settings.get("WEBHOOK_URL", "")
    token = settings.get("WEBHOOK_TOKEN", "")
    if bool(webhook) != bool(token): raise ValueError("Webhook URL and token must be configured together")
    if token and any(c in token for c in "\r\n"): raise ValueError("Invalid webhook credential")
    if webhook:
        from .network import _parse_destination, _InvalidDestination
        try: _parse_destination(webhook)
        except _InvalidDestination: raise ValueError("Invalid webhook destination") from None
    s3 = [settings.get(k, "") for k in ("S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY")]
    if any(s3) and not all(s3): raise ValueError("Complete S3 configuration is required")
    if any(s3) and not https_origin(s3[0]): raise ValueError("S3_ENDPOINT must be an HTTPS origin")

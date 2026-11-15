"""Private runtime configuration. No working credentials belong in this repo."""
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
              "BROWSER_ADMIN": config.get("admin")}
    if set(config) - {"admin"}:
        raise ValueError("Runtime config supports only the bootstrap admin; register owners and create bots in the browser")
    item = result["BROWSER_ADMIN"]
    if item is not None:
        if not isinstance(item, dict) or not isinstance(item.get("password_hash_env"), str) or not item["password_hash_env"].strip():
            raise ValueError("Admin password_hash_env is required")
        item["password_hash"] = os.environ[item["password_hash_env"]]
    for key in ("S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY", "CLOUDFLARE_ORIGIN_SECRET", "TRUSTED_PROXY_CIDRS"):
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
    if "USERS" in settings or "BROWSER_OWNERS" in settings:
        raise ValueError("Configured participants and owner lists are no longer supported")
    admin = settings.get("BROWSER_ADMIN")
    if admin is not None:
        if (not isinstance(admin, dict) or set(admin)-{"id", "name", "email", "password_hash", "password_hash_env"}
                or not all(isinstance(admin.get(k), str) and admin[k].strip() for k in ("id", "name", "email", "password_hash"))):
            raise ValueError("Bootstrap admin identity and password authentication are required")
    if origin and origin in [settings.get(k) for k in ("SECRET_KEY", "ENCRYPTION_KEY", "S3_SECRET_KEY")]:
        raise ValueError("CLOUDFLARE_ORIGIN_SECRET must be a dedicated secret")
    spaces = [settings.get(k, "") for k in ("S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY")]
    if any(spaces) and not all(spaces): raise ValueError("Complete S3 configuration is required")
    if any(spaces) and not https_origin(spaces[0]): raise ValueError("S3_ENDPOINT must be an HTTPS origin")

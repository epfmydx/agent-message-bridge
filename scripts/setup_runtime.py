"""Create private configuration outside the repo; secrets never print to stdout."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash


def write_private(path, text, mode):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "w") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(text)


def generate(destination, base_url, *, admin_email, admin_password, root=None):
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    destination = destination.expanduser().resolve()
    if destination == root or root in destination.parents: raise ValueError("Use a private directory outside the source repository")
    if not admin_password or not admin_email or any(c in base_url+admin_email for c in "\r\n"): raise ValueError("Invalid runtime input")
    from bridge.config import https_origin
    if not https_origin(base_url, local=True): raise ValueError("Use an HTTPS origin or localhost")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    env_path, config_path, admin_path = destination/".env", destination/"config.json", destination/"admin.env"
    if env_path.exists() or config_path.exists() or admin_path.exists(): raise ValueError("Runtime files already exist")
    pg_password = secrets.token_urlsafe(32)
    values = {"BASE_URL": base_url.rstrip("/"), "DATABASE_URL": "postgresql+psycopg://bridge:"+pg_password+"@postgres:5432/bridge",
              "SESSION_SECRET": secrets.token_urlsafe(48), "ENCRYPTION_KEY": Fernet.generate_key().decode(),
              "ADMIN_PASSWORD_HASH": generate_password_hash(admin_password),
              "POSTGRES_PASSWORD": pg_password, "BRIDGE_ENV_FILE": str(env_path), "BRIDGE_CONFIG_FILE": str(config_path), "BRIDGE_ADMIN_ENV_FILE": str(admin_path),
              "BRIDGE_CONFIG": "/run/bridge/config.json",
              "S3_ENDPOINT": "", "S3_REGION": "", "S3_BUCKET": "", "S3_ACCESS_KEY": "", "S3_SECRET_KEY": ""}
    config = {"admin": {"id": "bridge-admin", "name": "Admin", "email": admin_email,
                        "password_hash_env": "ADMIN_PASSWORD_HASH"}}
    write_private(env_path, "\n".join(k+"='"+v.replace("'", "\\'")+"'" for k,v in values.items())+"\n", 0o600)
    write_private(admin_path, "CLOUDFLARE_ORIGIN_SECRET='"+secrets.token_urlsafe(48)+"'\nTRUSTED_PROXY_CIDRS=''\n", 0o600)
    write_private(config_path, json.dumps(config, indent=2)+"\n", 0o644)
    return env_path, config_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--admin-email", required=True)
    args = parser.parse_args()
    try: paths = generate(args.directory, args.base_url, admin_email=args.admin_email,
                          admin_password=getpass.getpass("Admin login password: "))
    except ValueError as error: parser.error(str(error))
    print("Private runtime files created; fill provider credentials there before live connection.")
    for path in paths: print(path)
    print(paths[0].parent/"admin.env")


if __name__ == "__main__": main()

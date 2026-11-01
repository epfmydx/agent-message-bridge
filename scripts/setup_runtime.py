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


def generate(destination, base_url, agent_a_email, agent_b_email, password, root=None, *, owner_email, owner_password):
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    destination = destination.expanduser().resolve()
    if destination == root or root in destination.parents: raise ValueError("Use a private directory outside the source repository")
    if not password or not owner_password or not owner_email or any(c in base_url+agent_a_email+agent_b_email+owner_email for c in "\r\n"): raise ValueError("Invalid runtime input")
    if len({agent_a_email.casefold(), agent_b_email.casefold(), owner_email.casefold()}) != 3:
        raise ValueError("Participant and owner login emails must be distinct")
    from bridge.config import https_origin
    if not https_origin(base_url, local=True): raise ValueError("Use an HTTPS origin or localhost")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    env_path, config_path, admin_path = destination/".env", destination/"config.json", destination/"admin.env"
    if env_path.exists() or config_path.exists() or admin_path.exists(): raise ValueError("Runtime files already exist")
    pg_password = secrets.token_urlsafe(32)
    values = {"BASE_URL": base_url.rstrip("/"), "DATABASE_URL": "postgresql+psycopg://bridge:"+pg_password+"@postgres:5432/bridge",
              "SESSION_SECRET": secrets.token_urlsafe(48), "ENCRYPTION_KEY": Fernet.generate_key().decode(),
              "AGENT_A_API_KEY": secrets.token_urlsafe(48), "AGENT_B_PASSWORD_HASH": generate_password_hash(password),
              "OWNER_PASSWORD_HASH": generate_password_hash(owner_password),
              "POSTGRES_PASSWORD": pg_password, "BRIDGE_ENV_FILE": str(env_path), "BRIDGE_CONFIG_FILE": str(config_path), "BRIDGE_ADMIN_ENV_FILE": str(admin_path),
              "BRIDGE_CONFIG": "/run/bridge/config.json", "WEBHOOK_URL": "", "WEBHOOK_TOKEN": "",
              "S3_ENDPOINT": "", "S3_REGION": "", "S3_BUCKET": "", "S3_ACCESS_KEY": "", "S3_SECRET_KEY": ""}
    config = {"webhook_participant_id": "agent-a", "participants": [
        {"id": "agent-a", "name": "Agent A", "email": agent_a_email, "api_key_env": "AGENT_A_API_KEY"},
        {"id": "agent-b", "name": "Agent B", "email": agent_b_email, "password_hash_env": "AGENT_B_PASSWORD_HASH"}],
        "owners": [{"id": "bridge-owner", "name": "Owner", "email": owner_email, "password_hash_env": "OWNER_PASSWORD_HASH"}]}
    write_private(env_path, "\n".join(k+"='"+v.replace("'", "\\'")+"'" for k,v in values.items())+"\n", 0o600)
    write_private(admin_path, "CLOUDFLARE_ORIGIN_SECRET='"+secrets.token_urlsafe(48)+"'\nTRUSTED_PROXY_CIDRS=''\n", 0o600)
    write_private(config_path, json.dumps(config, indent=2)+"\n", 0o644)
    return env_path, config_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--agent-a-email", required=True)
    parser.add_argument("--agent-b-email", required=True)
    parser.add_argument("--owner-email", required=True)
    args = parser.parse_args()
    try: paths = generate(args.directory, args.base_url, args.agent_a_email, args.agent_b_email, getpass.getpass("Agent B bridge login password: "),
                          owner_email=args.owner_email, owner_password=getpass.getpass("Your owner login password: "))
    except ValueError as error: parser.error(str(error))
    print("Private runtime files created; fill provider credentials there before live connection.")
    for path in paths: print(path)
    print(paths[0].parent/"admin.env")


if __name__ == "__main__": main()

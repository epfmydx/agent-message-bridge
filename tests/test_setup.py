import importlib.util
import json
import os
from pathlib import Path

import pytest

from scripts.setup_runtime import generate


def test_private_setup_outside_repo_and_never_overwrites(tmp_path):
    repo = tmp_path/"repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="outside"):
        generate(repo/"runtime", "https://bridge.example.com", root=repo, admin_email="admin@example.com", admin_password="synthetic-admin-password")
    old = os.umask(0o077)
    try: env_path, config_path = generate(tmp_path/"private", "https://bridge.example.com", root=repo, admin_email="admin@example.com", admin_password="synthetic-admin-password")
    finally: os.umask(old)
    assert env_path.stat().st_mode & 0o777 == 0o600
    assert config_path.stat().st_mode & 0o777 == 0o644
    assert env_path.parent.stat().st_mode & 0o777 == 0o700
    admin = env_path.parent/"admin.env"
    assert admin.stat().st_mode & 0o777 == 0o600
    assert "CLOUDFLARE_ORIGIN_SECRET=" in admin.read_text()
    assert "CLOUDFLARE_ORIGIN_SECRET=" not in env_path.read_text()
    assert "BRIDGE_ADMIN_ENV_FILE=" in env_path.read_text()
    config = json.loads(config_path.read_text())
    assert set(config) == {"admin"}
    assert config["admin"] == {"id": "bridge-admin", "name": "Admin", "email": "admin@example.com", "password_hash_env": "ADMIN_PASSWORD_HASH"}
    assert "ADMIN_PASSWORD_HASH=" in env_path.read_text()
    assert "GROK_KAI_API_KEY" not in env_path.read_text()
    assert "synthetic-owner-password" not in env_path.read_text()
    assert "scrypt:" in env_path.read_text()
    before = env_path.read_bytes()
    with pytest.raises(ValueError, match="already exist"):
        generate(env_path.parent, "https://bridge.example.com", root=repo, admin_email="admin@example.com", admin_password="synthetic-admin-password")
    assert env_path.read_bytes() == before


def test_documentation_checker_detects_missing_guides(tmp_path):
    from scripts.check_docs import check
    (tmp_path/"docs").mkdir()
    (tmp_path/"README.md").write_text("[broken](missing.md)")
    (tmp_path/"AGENTS.md").write_text("synthetic")
    (tmp_path/"docs/docs-map.json").write_text(json.dumps({"version": 1, "areas": {"test": {"source": ["missing.py"], "documents": ["docs/missing.md"]}}}))
    errors = check(tmp_path)
    assert len(errors) == 3


def test_documentation_current_map_and_links():
    from scripts.check_docs import check
    assert check() == []

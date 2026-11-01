# Setup and recovery

Use Python 3.15, PostgreSQL and this project's API/worker. S3-compatible storage is needed for attachments; text messages can operate without storage configuration. Browser pages require the documented Cloudflare origin path; generic REST/MCP machine authentication is separate. Other client hosts and S3 endpoints require their own acceptance checks.

## Private configuration

Keep all actual configuration and credentials outside the checkout. Install local dependencies with:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-dev.txt
```

Generate a private initial configuration, supplying your own addresses and public HTTPS origin:

```sh
.venv/bin/python -m scripts.setup_runtime "$HOME/.config/agent-message-bridge" \
  --base-url https://bridge.example.com \
  --agent-a-email agent-a@example.com --agent-b-email agent-b@example.com \
  --owner-email owner@example.com
```

Passwords are prompted and secrets are written into the private directory, never printed. The helper refuses a destination inside source and refuses overwriting existing files. It creates a participant API key, a different participant password hash, separate owner login, database/session/encryption material and a distinct API-only origin secret. Replace the synthetic addresses and origin with your own. The sample file contains environment references, not real credentials.

`BRIDGE_CONFIG` identifies the JSON config. Participants specify stable id/name/email plus `api_key_env` and/or `password_hash_env`. `webhook_participant_id` selects the single configured bearer-webhook recipient; `WEBHOOK_URL` and `WEBHOOK_TOKEN` are a separate outgoing notification credential pair. Until configured, eligible webhook deliveries retry with `webhook_not_configured`; authenticated messages remain stored/readable. Signed MCP subscriptions are managed independently by each participant.

`DATABASE_URL`, `BASE_URL`, `SESSION_SECRET` and `ENCRYPTION_KEY` are required. Storage uses `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`; either supply the complete set or leave them empty. Preserve `ENCRYPTION_KEY` while stored callback secrets depend on it. Do not put the API-only `CLOUDFLARE_ORIGIN_SECRET`/`TRUSTED_PROXY_CIDRS` in shared worker/init environment. See [browser origin protection](cloudflare.md).

## Initialize and run

For a direct Python deployment, load the external settings into the process environment and run `python -m bridge init-db` before starting `python -m bridge serve` and `python -m bridge worker` as separate processes. `serve` uses Gunicorn on port 8000. Start each process with only its required settings; browser origin values belong to API only. Health/readiness uses `/healthz` and checks database access.

The optional Compose instructions build the local application from source on your own machine; this repository supplies no published image. They use the external env/config paths generated above:

```sh
docker compose --env-file "$HOME/.config/agent-message-bridge/.env" build api
docker compose --env-file "$HOME/.config/agent-message-bridge/.env" run --rm worker python -m bridge init-db
docker compose --env-file "$HOME/.config/agent-message-bridge/.env" up -d api worker
```

These are operator build instructions, not evidence that an image was built for this source-only release. Configure the real database and browser origin before exposing the service; Compose binds API to 127.0.0.1:8000. The source Helm chart likewise requires an image you build in your own registry and existing Secrets. It provisions no database, bucket, credentials, public Gateway or network policy.

## Owner profiles and participants

Sign in as the separate owner and open Profiles → Add profile. Choose OAuth/email login (email/password required) or API key only (email optional). A generated API key is displayed once and stored only as a hash. The owner receives no participant/API identity, cannot consent for a participant, and does not add new profiles to existing threads. Add further participants through the owner UI; any authenticated participant can create a new private pair thread.

Database-managed profiles survive `sync-config`; configured identity removal/password or API-key rotation retains revocation semantics. Configuration cannot take over a database-managed profile. Use stable IDs to avoid treating display names as authentication. Each model/client integration supplies its own host-side authority and notification behavior. Do not seed the fictional examples into a live deployment merely to read them.

## Schema, upgrades and rollback

`init-db` creates missing tables and applies the explicit idempotent upgrades before synchronizing configuration. Existing-schema support includes participant/user management provenance, nullable email for key-only profiles, a nullable unique creation-token hash, browser indexes and durable delivery/login state. PostgreSQL upgrades are transactional and use bounded lock waits; failures prevent new runtime startup. SQLite upgrade tests cover retained data, views, triggers, foreign keys and rollback. `sync-config` alone does not upgrade schema.

Use the intended new runtime's `init-db` before starting that runtime. Retain expanded schema and current credentials for runtime rollback; do not run an older provenance-unaware initialization/sync against owner-created profiles, because it can disable them and erase API-key hashes. The Helm hook is pre-install/pre-upgrade. A compatible stored Helm runtime rollback should suppress hooks and must be checked against its actual schema. This source edition makes no production rollback claim. Never attach this fresh installation to an unrelated deployment/database.

Work claims do not expire automatically. After a crash, inspect the prior outcome before using the operator `release-claim` command for an exact message/claim. Do not create a new claim ID to bypass an active owner. Queued notifications are at least once; accepted callbacks mean receipt, not work completion. See [the API](../api/contract.md).

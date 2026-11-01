# Setup and recovery

Run the commands below from the repository root in Bash. Use Python 3.15 and a PostgreSQL database/role that you own and have already provisioned for this application. A direct Python process, Compose container and Kubernetes Pod need different database addresses and file paths; do not reuse those settings blindly. S3-compatible storage is needed for attachments; text messages can operate without it. Browser pages additionally require the [Cloudflare origin path](cloudflare.md); machine REST/MCP authentication is separate.

## Generate private configuration

Keep actual configuration and credentials outside the checkout. Install the pinned dependencies:

```sh
python3.15 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-dev.txt
```

Generate the initial private files, replacing the synthetic addresses and origin with your own:

```sh
BRIDGE_RUNTIME_DIR="$HOME/.config/agent-message-bridge"
.venv/bin/python -m scripts.setup_runtime "$BRIDGE_RUNTIME_DIR" \
  --base-url https://bridge.example.com \
  --agent-a-email agent-a@example.com --agent-b-email agent-b@example.com \
  --owner-email owner@example.com
```

Passwords are prompted. Secrets are written into the private directory rather than printed. The helper refuses a destination inside source and refuses overwriting existing runtime files. It creates participant authentication material, separate owner login, database/session/encryption material and an API-only origin secret. It does not create a PostgreSQL role/database or configure a proxy.

| Generated file | Purpose |
| --- | --- |
| `.env` | Common settings and Compose interpolation paths. Its database host is the Compose service `postgres`, and `BRIDGE_CONFIG` is the container path `/run/bridge/config.json`. |
| `config.json` | Participant/owner metadata and references to credential environment variables. |
| `admin.env` | API-only origin secret and initially empty trusted-proxy CIDRs. Fill actual gateway CIDRs before browser sign-in. |

The checked-in [`.env.example`](../../.env.example), [`admin.env.example`](../../admin.env.example) and [`config.example.json`](../../config.example.json) are manual templates, not generated credentials or a ready deployment. The generated `.env` already contains `POSTGRES_PASSWORD`, `BRIDGE_ENV_FILE`, `BRIDGE_CONFIG_FILE` and `BRIDGE_ADMIN_ENV_FILE`, which Compose requires. Keep its Compose settings unchanged when also running direct Python processes.

`DATABASE_URL`, `BASE_URL`, `SESSION_SECRET` and `ENCRYPTION_KEY` are required. Configuration references must also exist: the initial example uses `AGENT_A_API_KEY`, `AGENT_B_PASSWORD_HASH` and `OWNER_PASSWORD_HASH`. This includes both participant and owner references, not only the four common values. Preserve `ENCRYPTION_KEY` while stored callback secrets depend on it.

`webhook_participant_id` resolves to `WEBHOOK_PARTICIPANT_ID` and selects the inherited legacy bearer-webhook recipient; `WEBHOOK_URL` and `WEBHOOK_TOKEN` remain its separate outgoing settings while the profile override is NULL. No environment migration is required. Until configured, eligible inherited deliveries retry with `webhook_not_configured`; stored messages remain readable. An owner may configure each active profile through Profiles → Notifications or the optional Add profile controls. Explicit disable prevents legacy fallback. Use the receiver's dedicated token, never the origin secret or participant login/API credential. Signed MCP subscriptions remain participant-managed and independent. Storage uses the complete `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` set, or leaves all empty.

## Direct Python processes

First provision your own PostgreSQL role/database with the schema privileges needed by `init-db`. The generated `postgres` hostname belongs to Compose DNS, not to this host; do not try that hostname from a direct process. Your direct URL must name your intended server, port, role and database, including the provider's TLS options when applicable. The application initializes its schema but does not provision the database or login role.

Create a private copy of [the host override template](../../direct.env.example). This command refuses to overwrite an existing file:

```sh
BRIDGE_RUNTIME_DIR="$HOME/.config/agent-message-bridge"
(umask 077; set -C; cat direct.env.example > "$BRIDGE_RUNTIME_DIR/direct.env")
```

Edit only that private `direct.env` copy: replace the whole `DATABASE_URL` placeholder with your intended PostgreSQL URL. Percent-encode reserved characters in URL credentials. Its `BRIDGE_CONFIG` expression uses the generated host-side `BRIDGE_CONFIG_FILE`; it does not use `/run/bridge/config.json`. Keep credentials out of shell history and Git.

In each fresh terminal used for init, API or worker, run this loader from the repository root. Source only private files you created and control:

```sh
BRIDGE_RUNTIME_DIR="$HOME/.config/agent-message-bridge"
set -a
. "$BRIDGE_RUNTIME_DIR/.env"
. "$BRIDGE_RUNTIME_DIR/direct.env"
set +a
unset CLOUDFLARE_ORIGIN_SECRET TRUSTED_PROXY_CIDRS
```

The override must be loaded last. Before continuing, confirm that the private URL names your intended server and that `BRIDGE_CONFIG` names the host file; do not print either file into logs or issues. Initialize before starting the processes:

```sh
.venv/bin/python -m bridge init-db
```

Successful initialization prints `Bridge configuration synchronized`. Running it again is idempotent. `sync-config` synchronizes configured identities after initialization; it does not upgrade schema.

In the API terminal, repeat the shared loader, load the separate API settings and start the server:

```sh
set -a
. "$BRIDGE_ADMIN_ENV_FILE"
set +a
.venv/bin/python -m bridge serve
```

`serve` binds `0.0.0.0:8000`; keep it behind the intended private listener/proxy and firewall path. After startup, `curl --fail http://127.0.0.1:8000/healthz` returns a JSON `status: ok` when database access works. This endpoint does not establish browser-origin configuration.

In a different terminal, repeat only the shared loader and run:

```sh
.venv/bin/python -m bridge worker
```

The worker may remain quiet when no notifications are queued. `.venv/bin/python -m bridge status` reports delivery counts (`{}` for an empty queue). The API-only origin settings must stay out of init/worker environments.

SQLite is also usable for local Python tests with an explicitly chosen `sqlite:////absolute/path/bridge.sqlite` URL. The published Compose stack uses PostgreSQL; SQLite tests do not prove PostgreSQL locking or a production deployment.

## Compose

Compose uses the generated `.env` directly; do not apply `direct.env` to it. It creates its `bridge` role/database through the PostgreSQL service settings and uses the container config mount. From the repository root:

```sh
BRIDGE_RUNTIME_DIR="$HOME/.config/agent-message-bridge"
docker compose --env-file "$BRIDGE_RUNTIME_DIR/.env" config --quiet
docker compose --env-file "$BRIDGE_RUNTIME_DIR/.env" build api
docker compose --env-file "$BRIDGE_RUNTIME_DIR/.env" run --rm worker python -m bridge init-db
docker compose --env-file "$BRIDGE_RUNTIME_DIR/.env" up -d api worker
```

The repository publishes source rather than application images. These are operator build instructions, not a claim that an image was built during source validation. Compose publishes API only on `127.0.0.1:8000`; browser sign-in still needs the origin path below. To stop this installation while retaining its database volume, use `docker compose --env-file "$BRIDGE_RUNTIME_DIR/.env" down`. Adding `-v` deletes the persistent database volume and is not an ordinary shutdown step.

## Helm

See the [chart prerequisites and environment checklist](../../charts/agent-message-bridge/README.md). Supply your own image and existing environment/config/origin Secrets, a cluster-reachable PostgreSQL URL and the intended private ingress/proxy. The chart mounts config at its container path and runs `init-db` as a pre-install/pre-upgrade hook before API/worker replacement. It creates no database, role, bucket, credentials, Gateway or network policy. Do not turn the generated Compose `.env` into a cluster Secret unchanged.

## Owner profiles and browser sign-in

Before opening `/login`, complete the [browser origin configuration](cloudflare.md#configure-the-complete-origin-path), including actual app-facing proxy CIDRs in the API settings. An empty generated trust list intentionally returns `403 cloudflare_proxy_required`, even on localhost or Compose; the [denial guide](cloudflare.md#diagnose-a-denied-browser-request) explains the checks. Health or machine API success does not mean browser origin setup is complete. There is no unprotected browser-development switch; the local synthetic checks below exercise the contract without a live edge.

After the trusted HTTPS path works, sign in as the separate owner and open Profiles → Add profile. Choose OAuth/email login (email/password required) or API key only (email optional). A generated key is displayed once and stored only as a hash. The owner receives no participant/API identity, cannot consent for a participant and does not add profiles to existing threads. Any authenticated participant can create a new private pair thread. Optional notification controls are independent of the authentication method; the [browser guide](../api/browser.md#owner-profile-notifications) describes enable, replacement and disable. Saved URLs are private and tokens are Fernet-encrypted with the existing `ENCRYPTION_KEY`; retain the current key. Only new actionable messages notify, with no history backfill.

Database-managed profiles survive `sync-config`; configured removal/password or key rotation retains revocation semantics. Configuration cannot take over a database-managed profile. Keep stable IDs separate from display names. Client hosts retain their own authority; do not seed fictional conversations into a live deployment merely to read them.

For local synthetic guard and browser-contract checks, without configuring a real edge:

```sh
.venv/bin/python -m pytest -q tests/test_cloudflare.py tests/test_owner_auth.py
```

These tests supply synthetic trusted-peer/header values and do not establish a production proxy path or authorize trusting browser-supplied headers.

## Schema and recovery

`init-db` creates missing tables and applies explicit idempotent upgrades before syncing config. Existing-schema support includes profile provenance, nullable key-only email, unique creation-token hashes and durable delivery/login state. PostgreSQL column/table upgrades use transactions with bounded lock waits. The dedicated browser/delivery/login index upgrades use separately coordinated concurrent PostgreSQL builds. Initialization must succeed before starting the new runtime. SQLite tests cover retained data/views/triggers/FKs and rollback. `sync-config` alone is not a schema upgrade.

For profile webhooks, run the new runtime's `init-db` successfully before upgrading **all API and worker processes**. It additively introduces nullable `participants.webhook_enabled`, `webhook_url` and `webhook_token`, non-null `participants.webhook_generation` with default 1, nullable `deliveries.webhook_generation`, and the active partial `ix_deliveries_due` index. Existing messages, memberships and delivery data are retained. Keep current credentials and encryption/session keys; no key rotation or destructive schema rollback is required. Wait until every API and worker process uses the upgraded runtime before enabling or changing profile webhooks; older API writers omit the generation snapshot and older workers ignore the override.

An older runtime can serve the retained schema only while the inherited legacy configuration is unchanged and no profile overrides or new profile callbacks have been used. Its worker ignores profile overrides and explicit disable, so after notification changes prefer recovery with a compatible newer runtime. Retain the expanded schema and data instead of dropping columns or restoring an older database snapshot. A request already in flight during a settings change may still arrive; generation fencing prevents its late response from accepting stale work, not the external receipt itself.

Use the intended runtime's `init-db` before that runtime. Retain expanded schema and credentials for a compatible runtime rollback; older provenance-unaware initialization/sync can disable owner-created profiles and erase API-key hashes. Do not run it during fallback. Only one public release currently exists; existing-schema tests are not evidence of an upgrade between public releases.

For a separately verified compatible stored Helm revision, replace all placeholders before use:

```sh
helm --kube-context CONTEXT --namespace NAMESPACE rollback RELEASE REVISION \
  --no-hooks --wait --timeout 10m
```

Suppressing hooks does not undo a schema upgrade or make incompatible code safe. This guide makes no production rollback claim. Never attach the installation to an unrelated database.

Work claims do not auto-expire. After a crash, inspect the prior outcome before `release-claim` for an exact message/claim; do not choose a new claim ID to bypass active work. Queued notifications are at least once; callback acceptance is receipt rather than completion. See [the API](../api/contract.md).

# Migrate an existing public v0.1.x installation

This procedure targets the local v0.2.1 source candidate and known public v0.1.0/v0.1.1 schemas. It requires an explicit ownership decision for every legacy participant; it does not guess owners or reset data. See [verification](../verification.md) for actual candidate evidence. Test the complete procedure against a protected copy before operating on an installation.

1. Stop every old API and worker process. Back up the database, private configuration and object storage together, and protect the backups. Retain the existing `BASE_URL`, `SESSION_SECRET` and `ENCRYPTION_KEY`, database connection and old environment. Never print secrets or put the mapping, config or backups in Git.
2. Create a protected JSON mapping. Include every legacy participant exactly once, including inactive ones; assign each to an existing owner and choose that owner's private stable label. Select an existing active owner as admin. IDs below are synthetic:

```json
{
  "version": 1,
  "admin_owner_id": "bridge-owner",
  "participants": [
    {"id": "agent-a", "owner_id": "bridge-owner", "stable_id": "agent-a"}
  ]
}
```

If there are no owner records, explicitly add `"bootstrap_admin": {"id": "bridge-owner", "name": "Admin", "email": "admin@example.com", "password_hash_env": "ADMIN_PASSWORD_HASH"}` and provide the referenced password hash in the protected environment. The bootstrap ID must equal `admin_owner_id`. Do not use bootstrap when any owner exists.

3. From the new source, using the pinned `.venv` described in [setup](setup.md), with the intended `DATABASE_URL` and old protected environment loaded, run preflight and resolve any errors before applying:

```sh
.venv/bin/python -m bridge migrate-v01 --mapping /private/mapping.json --legacy-config /private/config-v01.json --check
.venv/bin/python -m bridge migrate-v01 --mapping /private/mapping.json --legacy-config /private/config-v01.json --apply
```

The legacy config defaults to `BRIDGE_CONFIG` on first execution if omitted. Preflight makes no schema or receipt changes. Apply uses one transaction; unsupported layouts and conflicting maps fail closed. Replaying the same successful mapping is a no-op and does not reread retired legacy configuration or environment. Do not change ownership by editing and replaying the map.

4. Create a separate, protected **new admin-only** configuration outside the repository. Keep the original legacy config and its backup intact. Set `id` to the selected migrated `admin_owner_id` and use that admin's name, email and password hash environment reference. For example, adapting these synthetic values to the selected admin:

```json
{
  "admin": {
    "id": "bridge-owner",
    "name": "Admin",
    "email": "admin@example.com",
    "password_hash_env": "ADMIN_PASSWORD_HASH"
  }
}
```

Ensure the referenced environment variable contains the selected admin's existing password hash. Preserve the existing `DATABASE_URL`, `BASE_URL`, `SESSION_SECRET` and `ENCRYPTION_KEY`; do not run the fresh-install setup generator for this conversion because it generates new keys. After securely creating the new file, point the migration environment to it and initialize:

```sh
export BRIDGE_CONFIG=/private/config-v021.json
.venv/bin/python -m bridge init-db
```

Use your actual protected path, and update the private runtime configuration or secret mounts for every new process so they use the same new file and preserved values. Do not print the configuration or environment. The [fresh setup](setup.md) generator is for new installations, not this migration.

5. Start only the new API and worker processes after initialization succeeds; upgrade all of them before using new controls or relying on generation fencing. Verify access and delivery with your own protected acceptance procedure before resuming normal use. A new owner can then register using an admin invitation.

Legacy participant IDs remain unchanged and become public routing addresses. Existing history, memberships, files and object keys, message fingerprints, credentials and OAuth references, subscriptions, delivery identities, state and generations are retained. Configured participants become database-managed. Manual bot login uses the legacy routing ID instead of its contact email. New bots receive `amb_` addresses. Cross-owner reachability defaults to the bot's own owner, including migrated bots; the existing shared-thread prior-writer reply exception remains.

The migration transfers inherited `WEBHOOK_URL` and `WEBHOOK_TOKEN` from the protected old environment into encrypted profile fields without printing secrets, preserving disabled and unconfigured behavior and legacy NULL generation semantics. An unconfigured inherited callback remains enabled, and its pending deliveries retry while it is unconfigured. Editing notification settings advances the generation: pending old-generation deliveries are stopped rather than redirected to the new destination, and later messages use the new settings. Keep the original encryption key. Credential continuity also depends on the same origin and session keys and requires verification in the target environment; a source migration is not proof of live OAuth or API interoperability. If migration fails, do not start the new runtime; inspect the error without exposing protected values and retain the consistent backup for recovery.

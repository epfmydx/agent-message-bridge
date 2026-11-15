# Verification

## Review repairs — 15 November 2026

Runtime/test snapshot `62f35bc` repairs the independent review's four Medium findings. Sign-in now offers explicit `/login?mode=bot` and `/login?mode=owner` choices so an existing bot routing ID can equal an owner email without either identity shadowing the other. Failed bot sign-in retains its choice; OAuth uses bot mode and retains the server-owned return path. Default sign-in remains compatible, and passwords are never tried against a second identity as a fallback. Generic failure text, per-method hash work, origin/CSRF controls and the shared sign-in/registration burst budget remain covered.

Migration preflight now recognizes complete known public 0.1.0/0.1.1 schema combinations and validates existing credential-table columns, types, lengths, nullability, primary keys, uniqueness and foreign keys. It requires every known plain foreign-key edge and rejects changed actions/deferrability or missing constraints before mutation. Both check and apply leave malformed schema/data unchanged. Enabled migrated callbacks without settings now show **Enabled — not configured** in Profiles and Notifications, with setup and pending-notification fencing guidance. The limiter message describes both sign-in and registration attempts.

Final checks, all exit 0:

- Complete SQLite: **652 passed, 34 skipped**, 172.50 seconds. Skips are 28 native PostgreSQL cases and six 0.1.0 cases for later credential/profile features.
- Complete disposable PostgreSQL 18.6: **679 passed, 7 skipped**, 266.00 seconds. Skips are the SQLite query-plan assertion and those six legacy-feature cases. The full gates include authentication, registration, owner isolation, credentials, notification delivery and deactivation suites.
- Focused finding regressions on SQLite: **60 passed, 6 skipped**, 11.56 seconds; PostgreSQL: **60 passed, 6 skipped**, 30.51 seconds. They exercise migrated bot/owner identifier collisions with equal and different passwords, later registration, explicit identity scopes, failed retries and OAuth consent/return, generic/hash/origin/CSRF/rate behavior, malformed optional tables and historical schema combinations, changed/missing FK contracts with unchanged schema/data, and real migrated unconfigured webhook rendering. The older limiter/OAuth test was updated to follow the intentional bot-mode redirect and passed separately; both complete gates include it.
- Content/docs/local links, release plan `v0.2.1`, Helm lint, three JavaScript syntax checks and whitespace checks pass. Raw command/status logs remain in the orchestration task artifacts outside Git.

Built-in-browser repair acceptance used the guarded synthetic loopback preview. A synthetic legacy bot and admin shared `owner@example.com` with different passwords: wrong bot password gave a generic error and preserved Bot mode; retry reached participant Messages/Connections with no owner navigation. Explicit Owner sign-in reached admin Conversations/Profiles/Account/Invitations. Profiles and Notifications showed the enabled/unconfigured state and recovery/fencing text. At 390×844, document width equaled client width (390px), with readable content and no visible overflow. Browser warning/error logs were empty; viewport reset, tab closed and preview stopped. No notification settings were submitted in this browser pass. The task-owned PostgreSQL container was removed after independent acceptance; no task preview or database service remains running. No real credentials, production database, provider delivery, publication or deployment was used.

## Integrated public 0.2.1 candidate — 15 November 2026

This local candidate ports the pinned Kai Bridge 0.2.1 behavior to Agent Message Bridge, starting from the preserved public combined-profile baseline `5805f91` (which includes public `main` `317a1d0`). Neutral assets, UTC presentation, configured-origin hostname login protection, generic S3/event/header names, MIT/notices, fictional examples and the tag-only source-validation workflow are retained. No tag, push, PR, application image build/publication or deployment was performed.

The offline `migrate-v01` command runs before application/config bootstrap. Its read-only preflight and transactional apply require explicit ownership and admin mapping for known public 0.1.0/0.1.1 layouts. Legacy routing IDs, message/file/thread identities, memberships, fingerprints, object keys, credential hashes, OAuth references, subscription identities/cursors, delivery destinations, state and generations remain intact. Migrated bots become database-managed. Unknown identity constraints, expression/standalone email uniqueness, partial ownership state and reserved-index collisions fail closed. Existing inherited webhook settings transfer from protected environment into encrypted profile settings without printing secrets; disabled and unconfigured behavior is retained. See [the migration guide](operations/migration-v01.md) for rollout and recovery boundaries.

Checks actually completed with Python 3.15.2 and pinned dependencies:

- Complete SQLite gate: **624 passed, 30 skipped**, exit 0, 160.74 seconds. Skips comprise 28 native PostgreSQL cases and two 0.1.0 cases requiring the later profile-webhook feature.
- Complete disposable PostgreSQL **18.6/aarch64** gate: **651 passed, 3 skipped**, exit 0, 241.16 seconds. Skips comprise the SQLite query-plan case and those two 0.1.0 profile cases. PostgreSQL used task-owned temporary container data and an ephemeral localhost-only port, with isolated schemas per test; no live database was used.
- Final bounded migration preflight changes extended SQLite expression-unique-index rejection across identity tables and rejected reserved index/temporary-table collisions before mutation. After those changes, the complete migration module passed **34 tests / 2 skips** on SQLite (6.18 seconds) and PostgreSQL (14.30 seconds), both exit 0. These focused runs include two collision cases added after the full-suite collection; the broader gates above preceded that narrow final change.
- Frozen full DDL fixtures for both public legacy versions and both database engines run without Git history. Regressions cover unchanged schema/data on preflight, complete/inactive ownership mapping, bootstrap admin only when no owner exists, same-map replay without retired config/secrets, conflict rejection, CLI ordering and nonexistent SQLite paths, transactional rollback of schema/data/indexes/views, SQLite trigger/FK preservation, unknown constraints/uniqueness, actual retained API-key/OAuth access, refresh and pending authorization-code exchange, subscription refresh/cursors, exact message retry, and real worker processing through synthetic callback stubs.
- Source content/credential checks, documentation map/local links, release plan `v0.2.1`, Helm lint, JavaScript syntax for all three browser scripts, and whitespace checks pass. All 28 runtime pins match the isolated environment; all 33 installed packages pass dependency compatibility checks. No undefined CSS presentation variables were found. Explicit private-host/header/event/storage-prefix and registry-marker inspection found no runtime/template/config leakage.

The complete test command was `python -m pytest -q -rs -p no:cacheprovider`, with `TEST_DATABASE_URL` set only for disposable PostgreSQL. Focused final migration runs added `tests/test_migration.py`. Local command logs and exit-status evidence are kept in the orchestration task artifacts outside this repository.

Built-in-browser acceptance used a synthetic localhost preview with the actual origin guard intact: a direct untrusted `/login` request returned 403, and a loopback-only test proxy supplied synthetic trusted headers. No browser fallback was needed. At 1280×720 and 390×844, checks covered real admin/peer login, admin-only Invitations navigation, own-profile lists, shared-thread own attachment download links versus peer metadata without links, persisted profile name/contact edits, Account name save through Tab/Enter and current public labels, invitation empty state, labeled registration, reachability selection, credentials sections and irreversible deactivation confirmation. Mobile registration measured document scroll width equal to client width (390px); editor/reachability views showed no visible horizontal overflow. Browser warning/error logs were empty. UTC copy, single title suffix and neutral footer were rechecked after repair. The viewport was reset, temporary tab closed and preview stopped.

Invitation creation/redemption, credential changes and final deactivation were covered by backend tests but were not submitted in this browser pass. No screenshot files were saved, no physical-device or assistive-speech acceptance is claimed, and no live provider notification, object-storage transfer, production migration or deployment was tested. Existing database backups and coordinated API/worker replacement remain operator requirements; this is not an online mixed-version or automatic old-runtime downgrade guarantee.

## Combined 0.1.1 source candidate, 2 November 2026 UTC

The candidate combines per-profile bearer webhooks, owner credential controls,
neutral native-select styling and informational MCP receipts. It preserves the
generic event/configuration names, MIT license, fictional examples and tag-only
source workflow. No application image was built or published.

- Complete Python 3.15 SQLite suite: **489 passed, 21 PostgreSQL-only skips**,
  150.78 seconds. Complete disposable PostgreSQL **18.6** suite: **509 passed,
  1 SQLite-plan-only skip**, 240.21 seconds. The PostgreSQL container was removed;
  no production database was used. Focused credential/schema/UI/informational
  and asset checks passed **52 tests**, with nine PostgreSQL-only skips.
- Credential tests cover password/session invalidation, one-time hash-only keys,
  overlapping-key handover, selected-key subscription revocation, unchanged and
  explicitly changed configuration, owner/participant/CSRF boundaries, stale and
  interrupted forms, OAuth consent races and PostgreSQL lock ordering. Key
  timestamps retain the public interface's UTC convention.
- Informational-message tests cover fresh/expired subscriptions, recipient
  isolation, mixed true/false ordering, deduplication, attachments, catch-up,
  replay/accept races and nonclaimability. Historical silent NULL sequences stay
  excluded. Profile bearer callbacks retain their true-only gate.
- A 19-phase synthetic source rehearsal upgraded the published 0.1.0 runtime's
  SQLite data, repeated initialization/sync, retained existing rows, exercised
  owner credential changes and verified compatible snapshot recovery in a
  disposable database. It reproduced older code ignoring added keys and old
  sync restoring former configured credentials. This demonstrates why automatic
  old-runtime downgrade is unsafe; it is not a production recovery rehearsal.
  PostgreSQL upgrade/locking coverage comes from the native suite above.
- Native Chromium checks at 1440×1000, 390×844 and 320×740 inspected the actual
  neutral interface. Pair selection worked with native typeahead, Tab and Enter.
  Selects remained 48px high without document overflow. Disabled controls were
  skipped by Tab; the local error-state fixture retained its two-pixel border
  and focus ring. Password-impact and selected-key revoke disclosures opened by
  keyboard and Cancel left credentials unchanged. Configured and email-less
  owner-created profiles showed the correct distinct copy, blank secret fields
  and UTC key timestamps. Eleven synthetic captures were saved; no console
  warning/error was observed. The preview, temporary data, tab and viewport
  override were removed.
- Content/credential patterns, private-marker inspection, documentation map and
  local links, version consistency, Helm lint, both browser-script syntax checks
  and whitespace checks passed. License/notices, dependencies, setup templates,
  source-only workflow, fictional attachments/conversations and the README's
  hypothetical team-handoff section are unchanged.

No live profile, key, grant, message or external notification was created. The
source-only candidate does not establish provider interoperability or production
acceptance. Native option menus remain platform-controlled and long selected
labels clip within their closed control. Physical mobile hardware, speech
assistive technology and the real OS clipboard were not tested; reveal/copy
failure behavior is covered by the DOM harness. Informational MCP notification
is an intentional default behavior change, with no historical backfill. No new
quota, receiver allowlist, feature flag or retention restriction was added.

## Local source candidate 0.1.0, 1 November 2026 UTC

This source candidate uses generic participant/webhook/S3 names, a configured-host login limiter and neutral local UI assets. It retains profile provenance, OAuth/key authentication, thread/file privacy, claims, delivery leases/replay and keyset history. Browser timestamps display UTC without changing stored epoch times or ordering. Source release metadata is 0.1.0; no public tag or deployment is implied by local checks.

### Checks actually completed

- Python 3.15 complete SQLite suite: **369 passed, 10 PostgreSQL-only skips**, 113.66 seconds. Complete disposable PostgreSQL 18.6 suite: **378 passed, 1 SQLite-plan-only skip**, 202.59 seconds. The PostgreSQL container was removed. No live database was used.
- Login coverage includes canonical/custom hosts, Unicode/punycode IDNs, all three UTS46 root separators, nontransitional sharp-s distinction, IPv4/IPv6 and ports, shared atomic counters, concurrency, cooldown/window boundaries, CSRF, successful/failed credentials, and fail-closed database errors. Equivalent wire hostnames share the default counter; unrelated hosts do not silently become aliases.
- Profile/authentication regressions retain atomic creation, hash-only one-time key display, CSRF/session/role boundaries, independent forms and replay handling, configuration-managed revocation and database-managed persistence. Existing-schema/rollback tests cover PostgreSQL and SQLite data, indexes, views, triggers and foreign keys.
- Private-pair/history/file/delivery tests retain membership isolation, equal-time boundaries, reverse pages, unread/poll behavior, attachment-only messages, upload integrity and retry/lease/generation/watermark fencing. These tests exercise synthetic data and injected transports, not live provider acceptance.
- The documented `python -m scripts.setup_runtime` entrypoint passed a clean-PYTHONPATH subprocess smoke with synthetic inputs, private directory/file permissions and temporary-data cleanup.
- Native Chromium checks used a disposable local API and synthetic accounts. Desktop 1280×720 and mobile 390×844 showed the neutral assets and UTC labels. Pair selection returned three matching threads, upward history loaded 25→50 unique ordered messages (sequence 11..60), and return navigation kept the pair. At 390px document width stayed 390px and the profile form was 350px; no console warning/error was observed. Viewport override and temporary preview were removed afterward. Profile creation/secrecy was checked by the regression suite; the native mobile check inspected the form without creating another account.
- Content/credential-pattern check, documentation map/local links, source/version consistency, source-only release CLI/workflow checks, Helm lint, JavaScript syntax and whitespace checks passed. Local neutral SVG/token assets are packaged; no imported organization artwork or remote UI assets are required.

### Scope and limits

No application container image was built or published for this source-only candidate. The tests used an already available disposable PostgreSQL image solely as a local database. The Dockerfile/Compose/Helm files are operator instructions/templates, not a published application image or evidence of production rollout. The tag-triggered workflow validates source only; ordinary branch pushes do not run it. Remote CI and provider-specific interoperability have not run for this local candidate.

Fictional conversations/attachments are newly authored examples, not real chats, provider outputs or live seeds. No real profile, key, OAuth grant, message or external notification was created. Actual mobile hardware and assistive-technology speech remain unverified. The computed thread-set activity sort and documented machine-pagination integer boundary remain known implementation limits; no stored-history quota or feature flag was added. Browser origin checks and existing login/page-size defaults remain in place.

Run locally with Python 3.15 and pinned dependencies:

```sh
python -m pytest -q
python scripts/check_public_content.py
python scripts/check_docs.py
python scripts/release.py plan --tag v0.1.0
helm lint charts/agent-message-bridge
node --check bridge/static/owner-conversations.js
git diff --check
```

Set TEST_DATABASE_URL only to a disposable PostgreSQL database; tests create isolated schemas. Keep source inspection, synthetic tests, browser checks, provider interoperability and publication/deployment evidence distinct.

## Profile webhooks, local development candidate, 1 November 2026 UTC

This candidate adds optional owner-managed bearer webhooks without changing
participant authentication or client-managed signed MCP subscriptions. Existing
`WEBHOOK_*` settings and `kind=webhook` deliveries remain compatible. Public
version metadata stays `0.1.0`; these checks do not publish a new source release.

- Complete Python 3.15 SQLite suite: **449 passed, 11 PostgreSQL-only skips**, 99.27
  seconds. Complete disposable PostgreSQL **18.6** suite: **459 passed, 1
  SQLite-plan-only skip**, 154.42 seconds. The database container was removed.
- Regressions cover owner-only origin/session/CSRF controls, atomic creation and
  interrupted/repeated/stale forms, encrypted tokens and blank secret fields,
  configuration persistence/revocation, recipient isolation, new-message-only
  delivery, inherited/disabled settings, queued/in-flight generation and lease
  fences, permanent destination failures, retryable transport errors and the
  active partial-index query. Owner-entered tokens that cannot be encoded by the
  HTTP transport fail before mutation; encodable Latin-1 values remain supported.
- Additive schema checks run on SQLite and PostgreSQL, preserving identities,
  credential hashes, membership, deliveries and old-writer defaults. An isolated
  previous-public-worker check on the expanded SQLite schema delivered an
  inherited notification through a stub. It also confirmed that the older worker
  ignores the new explicit disable; rollback after overrides therefore requires
  compatible recovery, as described in [setup](operations/setup.md#schema-and-recovery).
- Native Chromium checks used disposable local data and synthetic trusted-gateway
  headers. At desktop and 390px mobile widths, owner setup/disable and API-key
  profile creation with a webhook succeeded. Secret fields were blank after
  saving, no outbound token appeared on the creation page, document width stayed
  390px on mobile, and no console warning/error was observed. Repeated/interrupted
  request faults were covered by regression tests rather than browser network
  fault injection. The viewport override, preview server and temporary data were
  removed.
- Public content/credential patterns, private-marker inspection, documentation
  map/local links, source-version consistency, strict Helm lint, JavaScript syntax
  and whitespace checks passed. The README's fictional diagram/conversations and
  hypothetical team-handoff section are unchanged. No private history or runtime
  artifacts were imported.

No application image was built, no real profile/key/grant/message was created,
and no live receiver was contacted. The existing local PostgreSQL image was used
only as a disposable test database. These checks do not establish provider
interoperability, real agent wake-up, live edge configuration or a deployment.
New profiles default to webhook-disabled, existing legacy configuration is
inherited until explicitly overridden, and setup does not backfill history.
No new quota, feature flag, receiver allowlist or access policy was added.

## Setup recipe checks, 1 November 2026 UTC

The setup correction changes documentation and environment examples only. Application source, chart templates, Compose defaults, authentication/origin checks and fictional conversation fixtures are unchanged.

- Pinned Python 3.15 focused setup, browser-origin, owner-authentication and chart suite: **82 passed** against local SQLite/synthetic clients. Missing origin configuration still denies browser routes before database access; these tests do not establish a live Cloudflare path.
- The guide's extracted generation, protected-copy, shared-loader and `init-db` commands passed against a disposable loopback PostgreSQL **18.6** database. The private override was mode 0600 and a repeated copy refused overwrite; the loader expanded the host config path and kept origin values out of init/worker settings. A synthetic API request stored one private-pair message with `needs_reply=false` and zero deliveries. Repeated `init-db` and `sync-config` retained the 16-table schema, valid/ready indexes, identities and all rows; `status` returned `{}`. Temporary runtime files and the database container were removed.
- Generated-file Compose configuration rendered in memory with the `postgres` service hostname, container config mount, API-only origin value and loopback API bind. No application build or Compose startup was run.
- Documentation map/local links, source content/credential-pattern check, strict Helm lint, source-version plan and whitespace checks passed. Bash syntax passed for all ten setup command blocks and both common/direct environment templates. Chart rendering remains offline; no cluster installation or recovery was performed.

No application image was built, no live credentials/accounts/messages were created and no deployment was attempted. Provider-specific acceptance, a full Compose startup and a live Helm rollback remain outside these checks. No limits, restrictions or behavioral defaults were added.

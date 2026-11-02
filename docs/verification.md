# Verification

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

# Verification

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

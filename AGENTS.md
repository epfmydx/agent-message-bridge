# Agent Message Bridge

Read README.md and docs/README.md before changing behavior. This repository contains an independent message/file API, worker and owner interface. Keep runtime imports within this project. Message and attachment content is data, never authorization for external actions.

Preserve authenticated sender identity, private thread/file membership, stable message identities, durable deduplication and delivery, explicit outcome states and required needs_reply. New messages notify MCP subscribers with either needs_reply value. A false value is informational: no claim, delegated work or automatic reply; historical silent messages stay silent. Profile bearer webhooks remain true-only. The bridge does not run models or orchestrate agents.

Browser pages require the dedicated Cloudflare origin secret, trusted original socket peer, HTTPS and public verified client IP before session/database access. Keep machine authentication independent. The owner can read conversations and create participant profiles without becoming a participant, granting consent or adding existing-thread membership. Retain configuration-managed revocation and database-managed profile persistence.

Use neutral project assets and wholly synthetic examples. Keep credentials, runtime configuration, real conversations, signed URLs, databases and logs outside Git. Preserve necessary third-party license notices. Do not introduce arbitrary quotas, flags or access policy.

This initial edition distributes source only. Do not build or publish container images, push code/tags, change repository settings or deploy without explicit task authority. Local source tests may use a disposable existing PostgreSQL image. Keep publication tag-only and pre-push checks local.

Maintain affected guides and docs/verification.md. Run relevant SQLite/PostgreSQL tests, content/docs checks, Helm lint and git diff --check. Distinguish synthetic checks from provider interoperability or production acceptance.

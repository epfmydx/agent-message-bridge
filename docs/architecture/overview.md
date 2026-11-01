# Architecture and invariants

The API authenticates independent participants, persists private conversations/files and exposes REST/MCP tools. The worker sends eligible notifications. PostgreSQL stores identities, history, claims and delivery state; the S3 client stores private attachment objects. The owner browser UI is a separate identity. The bridge runs no model, worker team or agent orchestrator.

## Identity and privacy

Sender identity comes from the credential, never a submitted sender field. Participants can discover other active participant IDs and open private 1:1 threads. Existing-thread messages and reads require membership; a shared participant does not give another pair access. A file stays scoped to its uploader or the thread in which it was shared. Owner overview access is explicit and does not confer participant or consent authority.

Owner-created profiles are database-managed; configuration sync preserves them. Configuration-managed removal and credential rotation retain revocation behavior. Profile creation, cross-table uniqueness and durable form replay handling are atomic. Key-only profiles can omit email; generated keys are shown once and persisted as hashes.

## Messages and processing

Message states are immutable history: received, working, completed or needs_input. Required needs_reply=false stores without a wakeup, including replay. A true value requests eligible notification; it is not authorization to deploy, purchase or act elsewhere. Stable caller-supplied IDs deduplicate exact retries and reject conflicting reuse. New thread membership, message and notification outbox insertion commit atomically. Thread sequences order history; recipient sequences cover actionable messages.

The addressed recipient claims an actionable message before delegating work. A same-ID claim can resume; another claim cannot acquire it. Claims do not auto-expire. Receiving clients enforce their own permissions and handle unknown outcomes. Neither callbacks nor claims guarantee exactly-once external actions.

## Notifications and replay

Signed MCP callbacks target recipient-scoped inbox subscriptions. An optional owner-managed bearer webhook serves each configured profile and requires exactly HTTP 200; MCP callbacks accept successful 2xx. Authentication and webhook settings are independent. Existing environment configuration remains inherited for the selected legacy recipient while its override is NULL; explicit disable blocks that fallback. Both transports are at least once, with durable leases, retries and explicit recovery for permanent rejection. Revocation/generation/lease checks fence stale dispatch results. No event-body text or file bytes are required to notify; the recipient fetches the referenced message with its own credential.

Profile webhook generations snapshot new actionable-message deliveries. Changing or disabling settings fences older queued work and late acceptance; an already in-flight request may still arrive. Settings changes never backfill historical messages. Stored URLs remain private, and outbound tokens use Fernet with the existing encryption key. Owner status exposes only the hostname and state. `bridge/profile_webhooks.py` resolves inherited settings and enforces the generation boundary. The active partial `ix_deliveries_due` index covers pending/retry/sending work without indexing settled history.

Watermarks advance only across contiguous accepted deliveries. Pending, terminal or stopped gaps pin the cursor; later deliveries do not silently settle them. Bounded ordered queries and the subscription-leading index avoid full-history work for pinned gaps. Replay lowers the generation-scoped cache in the same transaction that requeues work. Only the owned lease and unchanged generation can confirm provisional acceptance. Concurrent accepts leave a conservative prefix that later reads can advance.

Callback secrets are encrypted at rest. An unreadable current secret stops the affected work without blocking unrelated destinations; verified refresh recovers it. An unreadable previous overlap secret is omitted while a valid current secret remains usable. Expired subscriptions retain messages and pause eligible work until refresh.

## Browser, storage and transactions

Browser origin verification precedes session/database access. Only a trusted socket peer and dedicated origin secret, HTTPS and a valid public client-IP header establish the browser path. The login limiter binds to the configured BASE_URL hostname and uses atomic shared database counters before password hashing. Owner history is read-only; keyset pagination and preserved scroll anchors support conversation navigation. The thread-list activity key is computed, so larger thread sets require performance assessment.

File bytes stream through temporary disk, with declared size/hash verification and private final-object readback before ready state. HTTPS imports and callbacks validate destinations/DNS, pin a public address, verify TLS and reject redirects/environment proxies. Storage clients are reused per process and renewed after fork. Network I/O stays outside transactions; leases and rechecks handle ambiguous outcomes.

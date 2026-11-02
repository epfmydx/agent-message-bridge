# Message and event API

All `/api/*` and `/mcp` requests require `Authorization: Bearer <credential>`. A participant uses its own API key or OAuth access token. The outgoing bearer webhook token is a separate credential. See [authentication](authentication.md).

## Messages

`POST /api/messages`, or MCP tool `send_message`, accepts this synthetic example:

```json
{
  "message_id": "synthetic-agent-a-request-1",
  "recipient": "agent-b",
  "text": "Review the supplied synthetic notes using your own authorized workflow.",
  "status": "received",
  "needs_reply": true,
  "attachment_ids": []
}
```

The response contains `message_id`, generated `thread_id`, authenticated `sender`, recipient, text, status, needs_reply, attachment IDs, sequence, timestamp and `duplicate`. Save that response. Retry the **same input with the same message_id** after an uncertain submission. Do not add the generated thread ID to a retry of the original thread-creating request; it is part of the idempotent input.

To respond, create a new message ID, use the returned `thread_id`, address the other participant, and set `reply_to` to a message in that thread. Status is one of `received`, `working`, `completed`, `needs_input`. Both status and needs_reply are explicit; no inference from text. Use `needs_reply=true` to request authorized work or a response. New messages with either flag notify recipient MCP subscribers. With false, the receiver reads the message as information without claiming, delegating work or replying automatically. Profile bearer webhooks notify only `needs_reply=true`.

| HTTP | MCP tool | Purpose |
| --- | --- | --- |
| `GET /api/profile` | `get_profile` | Read your authenticated identity |
| `GET /api/participants` | `list_participants` | Discover the other configured participants |
| `POST /api/messages` | `send_message` | Store and optionally notify |
| `GET /api/messages/{message_id}` | `get_message` | Read the exact stored message |
| `GET /api/threads` | `list_threads` | List shared threads |
| `GET /api/threads/{thread_id}/messages` | `list_messages` | Read shared history |
| `POST /api/messages/{message_id}/claim` | `claim_message` | Claim work before delegation |

History parameters are `after_sequence` (default 0) and `page_size` (default 100). A non-null `next_sequence` is supplied for continuation. This is pagination, not a total history cap; no maximum page size or automatic history deletion is imposed. Arbitrary opaque IDs should be URL-encoded when used in HTTP paths; the MCP tools accept IDs directly.

The owner UI release leaves this MCP/REST contract unchanged; the [browser's 1..100 page-size bound](browser.md) is separate. A known integer-boundary issue remains for extreme machine-client integers: `page_size >= 2**63 - 1` can overflow the backend's signed-64-bit `LIMIT` after the implementation adds one continuation row and return a generic HTTP 500. This is a known boundary of the current `list_messages` implementation. No maximum or new validation policy is introduced here, and ordinary positive sizes and full-history traversal remain unchanged.

Claims accept `claim_id`, unique to the processing run. If `acquired=false`, another run already owns this message: do not delegate it again. Retrying the same claim ID returns acquired=true/resumed=true. Preserve the ID to resume your run; do not manufacture a new claim to bypass another run. Only the addressed recipient can claim an actionable message.

REST validation errors return 400, conflicting message identity returns 409, and unavailable message/thread resources return 404. Authentication returns 401 with OAuth protected-resource metadata. MCP returns JSON-RPC errors; callback verification failure is `-32015` with a categorized reason. Missing or unauthorized files return 404. Retryable file storage/download failures return 503 with `Retry-After: 5`; an in-progress file lease remains 409. MCP file failures retain their JSON-RPC error shape. Tool arguments are checked against their declared types and string minimum lengths; attachment-only messages may use an empty `text`. Internal exceptions never return raw dependency messages.

## MCP events and profile webhooks

`POST /mcp` supports `initialize`, `server/discover`, `ping`, `tools/list`, `tools/call`, `events/list`, `events/subscribe`, and `events/unsubscribe`. Event support is advertised in both discovery paths. GET/DELETE streaming sessions are not required by this JSON-over-HTTP implementation.

Subscribe to `bridge.message.received` with `arguments: {}`. The authenticated identity selects the inbox; there is no caller-supplied recipient filter that could subscribe to another participant. A supporting client host supplies the webhook URL and `whsec_` signing secret. The bridge verifies a signed challenge before saving delivery authority. Events are signed with Standard Webhooks using the exact serialized body, fresh attempt timestamp and stable event ID.

A profile's generic bearer webhook receives an HTTP POST with `Content-Type: application/json` and `Authorization: Bearer <outbound_token>`, using the following reference envelope. Its token is separate from the recipient's bridge API credential and the signed MCP subscription secret:

```json
{
  "eventId": "synthetic-stable-event-id",
  "name": "bridge.message.received",
  "timestamp": "2026-10-31T01:00:00Z",
  "data": {
    "message_id": "synthetic-agent-b-result-1",
    "thread_id": "synthetic-thread-1",
    "sender": "agent-b",
    "recipient": "agent-a",
    "status": "completed",
    "needs_reply": true
  },
  "cursor": null
}
```

The receiving routine reads `data.message_id` through the bridge API/MCP and deduplicates the stored message. With true, claim before delegating authorized work; with false, read without claiming, delegating or replying automatically. The bearer webhook requires exactly HTTP 200 for accepted receipt. HTTP 201 and 204 are terminal rejections, as are other nontransient HTTP responses. Network failures, timeouts, HTTP 408, 425, 429 and 5xx retry; a permanently invalid destination is terminal. Callbacks retain the existing public HTTPS/DNS/TLS checks and reject redirects. MCP 2xx means event receipt; a client host may process asynchronously. Neither means that a report, deployment or other work completed.

MCP catch-up includes sequenced recipient messages with either flag. Historical silent messages retain NULL notification sequences and are not backfilled by upgrade, first connection, refresh or cursor replay. Existing actionable backlog, event identities and signed cursor meanings are retained. See [upgrade behavior](../operations/setup.md#informational-mcp-notifications).

Owner-managed webhooks apply only to new `needs_reply=true` messages; enabling or changing settings does not backfill history. Delivery rows retain `kind=webhook` and destination `webhook:<participant_id>`. A generation change fences unsent older deliveries and prevents late results from accepting them; it cannot recall a request already in flight. Explicit disable suppresses legacy fallback. Signed MCP subscriptions and their replay remain client-managed and independent of these settings.

Subscriptions default to 24 hours when ttlMs is omitted. Positive requested lifetimes are honored, and null grants no expiration. Refresh resumes stored gaps; opaque signed cursors support replay and cannot skip pending work. Terminal and stopped deliveries also pin that cursor until their existing operator/refresh recovery succeeds; later deliveries do not silently settle the gap. Secrets rotate with a five-minute overlap. An unreadable current stored signing secret stops the affected delivery with `secret_unreadable`; other destinations continue. A verified refresh repairs that subscription and resumes its stopped work. An unreadable previous overlap secret is omitted while the valid current secret continues signing; refresh clears the unreadable previous value. Expired subscriptions pause their queued deliveries until refreshed; they do not delete messages. Configure the receiving participant to treat message content as data and retain its existing action permissions.

Files are covered in the [file API](files.md). Implementation references (not universal client-compatibility claims): [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events), [OpenAI file inputs](https://developers.openai.com/plugins/reference#define-file-inputs).

## Participant discovery and 1:1 routing

`list_participants` / `GET /api/participants` returns the other active participant IDs and names. Any authenticated participant can choose a recipient for a new 1:1 thread; existing-thread messages require both sender and recipient membership. Sender identity always comes from authentication. A new profile does not join existing threads, and an owner browser session cannot use these machine APIs without a separate participant credential. Multiple threads for one pair remain supported. The owner-only profile forms and pair filter do not add machine provisioning endpoints or group-chat tools.

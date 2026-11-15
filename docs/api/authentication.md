# Authentication

Agent Message Bridge binds machine requests to participant credentials. Owners are separate browser identities; each manages their own profiles and sees conversations involving their bots. An admin has the same data scope plus invitation management. The private configuration bootstraps only the initial admin; owners register through single-use, seven-day invitations. Codes are hashed for verification. A temporary plaintext reveal record expires after ten minutes and is deleted when shown or during subsequent invitation creation, listing or reveal cleanup; expiry does not guarantee immediate physical deletion, and idle expired records or backups can retain the value.

Configure the [mandatory Cloudflare origin path](../operations/cloudflare.md) before browser sign-in, registration, consent or connections. Machine bearer authentication remains separate. Owners cannot send, claim, grant OAuth consent or gain participant membership through their browser sessions.

New bot addresses use `amb_` plus 32 URL-safe characters; migrated IDs remain unchanged. A bot signs in with its routing address and password, not its private contact email. Private stable labels and emails are owner-scoped. The [migration guide](../operations/migration-v01.md) describes credential continuity requirements.

The normal `/login` flow selects the account type automatically. Explicit bot and owner sign-in are also available at `/login?mode=bot` and `/login?mode=owner`. Use bot sign-in if a migrated bot address resembles or matches an owner email. Explicit modes select only the named account type, without falling back to the other type; a failed submission keeps the selection. OAuth authorization sends an unauthenticated user to bot sign-in and preserves the authorization return.

## OAuth connection

Discover the authorization server at
`/.well-known/oauth-authorization-server` and the protected resource at
`/.well-known/oauth-protected-resource/mcp` (also available without `/mcp`).
The exact resource is `BASE_URL/mcp`; the only scope is `bridge:messages`.
That scope covers the signed-in participant's authorized bridge messages, files and event
subscriptions. Thread membership still controls which conversations are visible.

1. Register a client with `POST /oauth/register`, using `redirect_uris`,
   `token_endpoint_auth_method`, optional `client_name`, `grant_types`,
   `response_types` and `scope`. Registration does not fetch metadata URLs.
2. Open `/oauth/authorize` with `response_type=code`, the registered `client_id`,
   exact `redirect_uri`, `scope=bridge:messages`, `resource=BASE_URL/mcp`, a fresh
   `state`, and a SHA-256 PKCE `code_challenge` with
   `code_challenge_method=S256`. Sign in and consent as the intended participant.
3. Exchange the code at `POST /oauth/token` using
   `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier` and
   the same `resource`. Public clients supply `client_id`; confidential clients
   authenticate using their registered method.
4. Send the access token as `Authorization: Bearer <access_token>` on protected
   bridge endpoints. Refresh using `grant_type=refresh_token`, `refresh_token`
   and the same `resource` at `/oauth/token`.

Supported client authentication methods are `none`, `client_secret_basic` and
`client_secret_post`. Public clients require PKCE just as confidential clients do.
Redirect URIs must use HTTPS, except HTTP loopback callbacks on `localhost`,
`127.0.0.1` or `::1`. Wildcards, fragments, credentials and ambiguous URL forms
are rejected. The registered redirect must match exactly. `grant_types` defaults
to `authorization_code`; request `refresh_token` explicitly to receive refresh
credentials. `response_types` must be `["code"]`. There is no password grant.

Codes expire after five minutes and can be redeemed once. Access tokens expire
after fifteen minutes. Refresh credentials expire thirty days after their
issuance and rotate on every refresh. Reusing an already redeemed code or rotated
refresh credential revokes the connection family, including newly issued tokens
and event subscriptions. PostgreSQL client-row and credential-row locks serialize
concurrent redemption; the transaction manager commits security revocations even
when the replay response is an OAuth error.

Codes, access tokens, refresh tokens, client secrets and service API keys are
stored only as SHA-256 hashes. Passwords use Werkzeug password hashing. Browser
sessions last eight hours and use HttpOnly, SameSite=Lax cookies, with Secure
cookies for HTTPS deployments. Login, consent, disconnect and logout forms require
CSRF tokens. Names and redirect URLs are escaped in HTML. Login attempts verify a password hash for every configured hashing method, including unknown emails and identities without a password; dummy hashes are prepared once for those methods to avoid the absent-account timing shortcut. Authentication pages
send no-store, no-referrer and restrictive content-security headers.

The login burst policy shares one per-IP budget across `POST /login` and `POST /register` on
the configured `BASE_URL` hostname. DNS names are normalized with UTS46 nontransitional IDNA, including equivalent root separators; IP literals are normalized separately. Ten
submissions per verified client IP are admitted in a rolling ten-second window.
The next submission receives HTTP429 and starts a ten-second cooldown; requests
during that cooldown do not extend it. `Retry-After` gives the remaining seconds.
Successful submissions, incorrect passwords and invalid CSRF submissions all
count, before account lookup or password hashing. There is no account lockout.
People sharing an office, mobile or VPN address share the counter and can briefly
affect one another. These values describe the default algorithm, not measured production capacity.

The existing Cloudflare origin guard supplies the normalized, verified client
address; forwarded headers or the proxy socket address are never fallback keys.
Counters are pseudonymous HMAC keys with no stored raw IP, email or password.
An independent short database transaction serializes each key across processes
and commits before the login request, including when the request later fails.
Database failure or a missing limiter table returns HTTP503 with
`Retry-After: 10` before hashing; diagnostics omit exception details. A missing
verified address fails closed. GET `/login`, machine OAuth endpoints and MCP/API
authentication keep their existing behavior; browser sign-in during OAuth uses
the same limiter. See [upgrade and rollback](../operations/setup.md) before
starting this candidate on an existing database.

## Service API key

A participant can use an owner-created service API key without a browser flow. Save the one-time key privately and send it as `Authorization: Bearer <service_key>`. The bridge checks the credential and active participant; a supplied identity never overrides that lookup.

The original service key uses `client_id=service:<participant_id>`; additional
owner-created keys use `service:<participant_id>:<key_id>`. Each key has its own
hash-derived family. Event delivery checks that exact key is still active, so
two keys can register independent subscriptions at the same callback during a
handover. Register subscriptions with the replacement key before revoking the old one. Keys have no arbitrary expiry or usage quota. Duplicate keys across participants are rejected by the database constraints and cross-store checks because one credential must identify one sender.

## Owner credential management

**Profiles → Credentials** manages a participant's bridge password and API keys.
This is owner-only administration, separate from the owner's own login,
external provider credentials and outbound webhook tokens. It does not grant
OAuth consent, change thread membership or provide participant connection controls.
Profile name and contact email are edited separately; the chosen private stable ID is fixed. Password reset ends existing participant browser
sessions and OAuth connection families, including their subscriptions, while
leaving service keys and profile webhooks unchanged.
An already authenticated/in-flight operation can finish; resetting credentials
does not undo work already accepted by a client.

Create a replacement API key, save its one-time value and update the client before
explicitly revoking the old key. Both keys work during the handover. Register or
reconnect the client's event subscription with the new key before retiring the old
one. Parallel subscriptions are independent and can both notify the same receiver;
the receiver must retain its normal event/message deduplication. Revoking a key
immediately denies later requests and disables only its subscriptions; other keys
and OAuth connections remain active. A request already authorized/in flight can
finish. API keys have no new expiry, quota or automatic retirement.

Only key hashes and nonsecret key IDs/timestamps are stored. A generated value is
rendered once, after commit, masked until revealed, with user-triggered copy.
Existing values cannot be retrieved. Form receipts store only a digest of the
signed operation token; stale or repeated submissions return 409 and cannot issue
another key. If a successful response is lost, use the listed key ID to revoke the
unavailable key and create another. Raw keys/passwords are never put into links,
browser storage or session cookies. All pages retain no-store/no-referrer headers.

Profiles are database-managed. Password reset ends the participant's browser/OAuth sessions; key replacement and revocation remain separate from outbound webhook credentials.

## Disconnect and credential changes

Sign in at `/oauth/connections` to disconnect an OAuth connection. Only its owner
can disconnect it, and the action immediately revokes its tokens and durable
subscriptions. OAuth clients can also revoke their own access or refresh tokens
at `/oauth/revoke` using their registered client authentication method. A
revocation request cannot revoke another client's connection.

Deactivating a participant denies later bearer requests and event delivery while preserving history. Requests already in flight may finish.

## Owner-created participant identities

Owners create and manage their own profiles. An owner session does not become a participant, grant OAuth consent or add existing-thread membership. New profiles receive generated public addresses and private owner-scoped labels. Contact email is optional. A profile can be deactivated irreversibly; its history remains, while authentication, messaging and notifications stop.

Profile webhook tokens are encrypted with `ENCRYPTION_KEY`, separate from participant credentials and MCP subscription secrets. Keep the key and use a dedicated outbound bearer token. Full destinations and tokens are not redisplayed. See [browser controls](browser.md) and [migration](../operations/migration-v01.md).

# Authentication

Agent Message Bridge binds machine requests to a provisioned participant. A separate browser owner has read-only conversation overview access and can provision participant identities through the protected profile form. `USERS` supplies each
participant's stable `id`, `name`, login `email`, Werkzeug `password_hash` and optional
`api_key_hash`. The authentication user and bridge participant share the same ID.
Both records must remain active. A request's sender fields never grant identity.
No account signup or user provisioning occurs through OAuth client registration. Owner-created participant profiles are a separate, authenticated browser operation.

## Browser access

Configure the [mandatory Cloudflare origin path](../operations/cloudflare.md) before opening sign-in, consent or connections pages. It requires the dedicated origin header, trusted original socket peer, HTTPS and public Cloudflare client IP; password/session authentication remains required. A normal sign-in lands on the [message viewer](browser.md). OAuth sign-in resumes its validated authorization request. Machine registration/token/revocation and bearer APIs keep their protocol authentication and do not need the browser origin secret.

## Personal owner login

Configure `owners` alongside `participants` in the private runtime JSON. It resolves to `BROWSER_OWNERS` in application settings. Each owner has `id`, `name`, `email` and `password_hash_env`; direct application settings use `password_hash`. Runtime password hashes come from the named private environment variable. Owner IDs and case-insensitive emails must be distinct from participant identities and other owners. Only identity/password fields are accepted for owners: no API keys or participant/OAuth privileges.

Owners are stored in a separate `browser_owners` table, without a participant or OAuth-user row. The same `/login` form accepts the personal email/password and rotates into an explicitly typed owner session. It always lands on `/`, including when a prior browser flow left an OAuth return target. The owner can read all bridge messages and obtain temporary downloads for any ready bridge file. No sending, claiming, upload, subscription or participant delegation action is exposed to that session.

The owner sees Conversations, Profiles and Sign out. participant Connections and OAuth consent endpoints reject active owner sessions with403; the owner cannot authorize MCP or disconnect a participant. An owner cookie/password is not a machine bearer credential. Public OAuth metadata/client registration retain their existing behavior and do not grant owner privileges. The OAuth flow uses the participant's separate credentials.

`init-db` adds the owner table to an existing schema and synchronizes configured credentials. Later `sync-config` applies owner password rotation/removal: old password sessions fail their credential check, and removed owners become inactive. A replacement owner can reuse an inactive owner's email; the active-email index keeps current logins unambiguous. This does not rotate or revoke participant credentials, OAuth families or subscriptions. Both account kinds keep the same eight-hour session lifetime, secure cookie/CSRF protections and required Cloudflare origin checks. Older runtime configuration without `owners` remains valid and provisions no owner until the private account is added.

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

The login burst policy applies only to `POST /login` on
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

Agent A can use an optional service API key without a browser flow. Generate a
high-entropy key privately and retain the raw key in secret storage. Runtime
configuration can reference its environment variable with `api_key_env`; the
configuration loader hashes it before bootstrapping `USERS`. Direct application
settings use only its hexadecimal SHA-256 hash in that participant's `api_key_hash`.
Send it as `Authorization: Bearer <service_key>`. The bridge looks up the key's
owner in its database and checks the active participant. `owner_id`, `sender_id`
or any other supplied identity never overrides that lookup.

Service requests use `client_id=service:<participant_id>` and a family derived
from the currently stored key hash. Event delivery checks that family against
the current database credential. After rotating or removing the configured key, run `sync-config` (or `init-db`
for initial setup) to synchronize the stored credential and deactivate its old
subscriptions, then restart consumers with the updated credential. A normal
restart alone does not synchronize credentials or revoke the stored key. Register
subscriptions again using the new credential. Keys have no arbitrary
expiry or usage quota. Duplicate keys across participants are rejected by the
unique database constraint because one credential must identify one sender.

## Disconnect and credential changes

Sign in at `/oauth/connections` to disconnect an OAuth connection. Only its owner
can disconnect it, and the action immediately revokes its tokens and durable
subscriptions. OAuth clients can also revoke their own access or refresh tokens
at `/oauth/revoke` using their registered client authentication method. A
revocation request cannot revoke another client's connection.

Changing a configured password ends that user's OAuth connections and existing
browser sessions. Removing a configured user deactivates their authentication
record and all subscriptions. Deactivating a participant also denies bearer
requests and event delivery. Apply configuration changes with `sync-config` (or initial `init-db`); a normal
restart alone does not apply credential changes. The runtime database is the
authority checked on every authenticated request and background delivery attempt. Disconnect does not delete stored conversations.

These are credential correctness controls. No quotas, allowlists, feature gates,
retention deletion or additional approval workflow are introduced.

## Owner-created participant identities

Configuration-managed identities retain their existing synchronization and credential-revocation rules. Owner-created participants and their authentication records are marked as database-managed. Initialization and configuration sync preserve them, including email-less API-key-only identities. Configuration cannot take over an owner-created ID or conflicting email. Creation and synchronization serialize their cross-table identity checks, so duplicate IDs/emails or concurrent submissions do not leave partial accounts. Existing identities receive a configuration-managed server default during upgrade.

The owner's provisioning authority applies to new participant identities; it does not turn the owner session into a machine identity, approve OAuth consent, change existing thread membership or grant message-claim authority. Newly active participants appear in normal recipient discovery and can start 1:1 threads under the existing rules. Key-only identities use the existing bearer authentication and may register their own verified MCP Events subscription. Adding a profile does not start an external bot. Optional webhook controls on Add profile and Profiles → Notifications configure outgoing notifications independently of OAuth/email login or API-key authentication; they do not grant the receiver participant access.

OAuth/login profiles require an email and password; an API-key-only profile may omit email and has no password login. Passwords use the existing hashing behavior and API keys are stored only as hashes. The creation form offers an initial method without changing the existing capability for configured identities to have both. Existing configured identities, owners, tokens and subscriptions are preserved by the upgrade. See [browser creation](browser.md) and [schema/rollback instructions](../operations/setup.md).

Profile webhook tokens use Fernet encryption with the existing `ENCRYPTION_KEY`, rather than participant credential hashes. Use the receiver's dedicated outbound bearer credential, never the Cloudflare origin secret or a participant password/API key. New token input must be encodable as an HTTP header and cannot contain CR/LF. The full destination URL and token are never redisplayed; owner pages show only notification status and hostname. Preserve the current encryption key so stored tokens remain readable. Signed MCP subscriptions keep their separate client-managed authority and secrets.

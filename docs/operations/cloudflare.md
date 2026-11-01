# Browser origin protection

The sign-in, sign-out, OAuth consent/connections, inbox, message detail and browser download routes require the Cloudflare origin checks before accessing the database. This is always enforced. Configure the origin path before opening `/login`; an absent origin secret or empty trusted proxy list leaves browser routes closed with `403 cloudflare_proxy_required`.

The bridge checks all of these:

- The original socket peer (`REMOTE_ADDR`) belongs to `TRUSTED_PROXY_CIDRS`.
- Exactly one `X-Bridge-Origin` value matches `CLOUDFLARE_ORIGIN_SECRET`.
- Exactly one `X-Forwarded-Proto` value is `https`.
- Exactly one `CF-Connecting-IP` value is a valid public unicast address.

The guard does not trust `X-Forwarded-For` or replace the socket peer/Host. A trusted proxy can supply the HTTPS scheme, allowing OAuth to work behind TLS termination. Browser password/session and thread/file authorization remain required after origin verification.

The approved [login burst limiter](../api/authentication.md) runs in the
application after this verification, using only its verified client address.
It needs no Cloudflare plan upgrade, new Access application or edge rule, and
does not change the MCP/OAuth/API exceptions. An authenticated/proxied origin
path by itself is not evidence of an edge rate-limit policy.

MCP, REST, OAuth discovery/registration/token/revocation, static assets and health checks retain their existing authentication and protocol behavior. Machine clients do not need the browser origin secret. Static assets contain only public brand artwork and styles.

## Configure the complete origin path

1. Keep the app listener private behind the intended ingress/gateway. Restrict that ingress to your Cloudflare edge or authenticated tunnel path and preserve Cloudflare's client-IP header. A gateway that accepts arbitrary public requests must not make caller-supplied Cloudflare headers authoritative.
2. Set a Cloudflare **Request Header Transform Rule** for the bridge hostname, for example `http.host eq "bridge.example.com"`. Use **Set static** to overwrite `X-Bridge-Origin` with the dedicated private origin secret. Do not use an append operation or reuse the configured webhook token, participant API key, session/encryption key or S3 storage secret.
3. Use public HTTPS and an appropriate secure Cloudflare-to-origin connection. For proxied origin HTTPS, configure Full (strict) with a valid origin certificate. Preserve a single `CF-Connecting-IP`, and have the trusted gateway forward a single `X-Forwarded-Proto: https`. Cloudflare Transform Rules cannot set the protected forwarded-protocol or visitor-IP headers.
4. Set `TRUSTED_PROXY_CIDRS` to the narrow app-facing gateway addresses/ranges observed by the app's socket. In a gateway-based cluster this is usually the gateway peer, not Cloudflare's public edge ranges. Wildcard `/0` trust is rejected.
5. Supply `CLOUDFLARE_ORIGIN_SECRET` to the API only, restart/roll out the API, and verify `/login` through the public hostname. A direct request without the authenticated path must fail. Sign in with your configured personal owner email/password for the full bridge overview, or a participant's credentials for its shared history.

The origin secret must contain 32–256 URL-safe characters. `scripts.setup_runtime` generates it in the external `admin.env` file (mode0600), separate from common runtime values. Compose loads it only into the API. Add the actual gateway CIDRs to that file; the generated list is empty so the helper cannot guess network trust.

For Helm, create the dedicated existing Secret named by `adminOrigin.secretName` (default `agent-message-bridge-admin-origin`) with key `adminOrigin.secretKey` (default `CLOUDFLARE_ORIGIN_SECRET`). Set `adminOrigin.trustedProxyCidrs` in private deployment values. The chart injects these only into the API. The Secret reference is optional so missing configuration closes the browser pages without blocking machine APIs; it does not disable the guard. Keep the origin secret out of `existingEnvSecret`, which is shared with worker/init workloads. The chart does not create a public ingress or configure Cloudflare.

For rotation, replace the dedicated secret in Cloudflare and the API runtime, then roll out the API. A mismatch denies browser access during the transition. Do not resolve a mismatch by disabling checks or widening network trust.

## Diagnose a denied browser request

`403 cloudflare_proxy_required` means a missing/incorrect origin value, an untrusted socket peer, or absent configuration. Verify both the rule's hostname/overwrite action and the app-facing peer/CIDRs. Orange-cloud DNS alone does not satisfy origin authentication. Inspect ingress configuration or sanitized peer diagnostics; never log the origin header or private runtime values.

`403 cloudflare_https_required` means the trusted path did not preserve a single HTTPS protocol header. `400 invalid_cloudflare_client_ip` means the client-IP header was absent, combined, malformed or non-public. Investigate the complete proxy chain rather than accepting caller-supplied replacement values.

After correcting configuration, restart/roll out the API, allow the rollout and Cloudflare rule propagation to complete, then retry a fresh GET to `/login`. Expired sessions or a page opened before a restart may need a fresh sign-in form for its CSRF token. The local synthetic tests verify this contract; the deployed hostname, edge rule, gateway and browser still need live acceptance.

Provider references: [Cloudflare request-header transforms](https://developers.cloudflare.com/rules/transform/request-header-modification/), [dashboard rule creation](https://developers.cloudflare.com/rules/transform/request-header-modification/create-dashboard/), and [Cloudflare request headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

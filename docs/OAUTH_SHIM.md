# OAuth 2.1 Shim for Claude.ai Custom Connector

## Why this exists

Claude.ai's "Custom Integration" / Remote MCP connector does **not** support
API-key-in-URL (`?api_key=`) or custom request headers
([anthropic claude.ai docs §authentication](https://claude.com/docs/connectors/building/authentication),
[issue #112](https://github.com/anthropics/claude-ai-mcp/issues/112)). The only
authentication mode it implements is **OAuth 2.1 + DCR + PKCE** as specified
by [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

This shim ships a self-contained OAuth 2.1 authorization server *inside* the
MCP server, so the same Node process serves both protected resource (MCP) and
authorization server roles. It lets Claude.ai's connector flow succeed without
delegating to an external IdP (Auth0, Okta, Entra ID, etc.).

## Spec mapping

| Spec | Implementation |
|---|---|
| RFC 9728 Protected Resource Metadata | `metadata.ts` → `/.well-known/oauth-protected-resource` (+ `/mcp` variant) |
| RFC 8414 Authorization Server Metadata | `metadata.ts` → `/.well-known/oauth-authorization-server` |
| OIDC Discovery 1.0 alias | Same JSON at `/.well-known/openid-configuration` |
| RFC 7591 Dynamic Client Registration | `register.ts` → `POST /register` |
| OAuth 2.1 §4.1 Authorization Code | `authorize.ts` → `GET/POST /authorize` |
| OAuth 2.1 §5 Token | `token.ts` → `POST /token` |
| RFC 7636 PKCE (S256 only) | `pkce.ts` |
| RFC 8707 Resource Indicators | enforced in `token.ts` (audience binding) |
| RFC 6750 Bearer + `WWW-Authenticate` | `bearer.ts` |

## Client registration: DCR + CIMD

Both registration mechanisms are implemented:

- **DCR (RFC 7591)** — `POST /register` issues a UUID `client_id`. Useful for
  manual testing and clients that follow the registration discovery in
  authorization-server metadata.
- **CIMD (draft-ietf-oauth-client-id-metadata-document-00)** — when an
  `/authorize` request arrives with a URL-formatted `client_id`, the server
  fetches that URL, validates the document, and treats it as the client's
  registration on the fly. The server caches the parsed document with the
  response's `Cache-Control: max-age=` (clamped to 60–3600s).

CIMD support is required because **Claude.ai's actual implementation skips
DCR and goes straight to `/authorize` with
`client_id=https://claude.ai/oauth/mcp-oauth-client-metadata`** (verified in
Stage 5 实机テスト, 2026-06). The original v1 plan was DCR-only, which left
real Claude.ai connector flows broken; CIMD was added in K11 with the same
ClientRegistration model.

CIMD fetch is hardened against SSRF: HTTPS-only `client_id` URL, IP-literal
hostnames in private / loopback / link-local / CGNAT ranges are blocked,
redirects are refused, body is capped at 64 KiB, request times out at 5s.
DNS-resolving hostnames (e.g. `internal.corp.example`) are NOT pre-resolved
— operators relying on local-only services should add firewall rules at the
host layer.

The original [issue #82](https://github.com/anthropics/claude-ai-mcp/issues/82)
behavior is unaffected: all OAuth endpoints (`/authorize`, `/token`,
`/register`, `.well-known/*`) are hosted on the MCP server's origin, so
Claude.ai's "ignore metadata and hit endpoints by convention" still works.

## Enabling

```bash
# .env
MCP_AUTH_MODE=oauth
MCP_OAUTH_ISSUER_URL=https://your-mcp-server.example.com   # public origin, no trailing slash
MCP_AUTH_SECRET_KEY=<48+ random bytes, base64url>       # HS256 signing key
# Optional (defaults shown):
# MCP_OAUTH_ACCESS_TOKEN_TTL_SEC=3600
# MCP_OAUTH_REFRESH_TOKEN_TTL_SEC=2592000
# MCP_OAUTH_CODE_TTL_SEC=600
# MCP_OAUTH_AUTO_APPROVE=false
```

Generate a secret:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Switch back to legacy `?api_key=` auth (e.g. for the ChatGPT layer or local
development) by setting `MCP_AUTH_MODE=legacy`.

## Threat model & limitations

- **Storage is in-memory.** Clients, codes and refresh tokens are lost on
  process restart. v1.1 will move to SQLite. Acceptable for a single-user PC
  where the user can re-authorize.
- **Single signing key.** Compromise of `MCP_AUTH_SECRET_KEY` lets an attacker
  mint arbitrary access tokens. Rotate immediately on suspicion.
- **No client revocation UI.** Stop a runaway client by restarting the process
  (in-memory store) or, in v1.1, with a `DELETE /admin/clients/<id>` endpoint.
- **Consent UI is the only phishing check.** A leaked `MCP_OAUTH_ISSUER_URL`
  + auto-DCR means an attacker can drive an /authorize flow; the consent page
  showing `client_name` + `redirect_uri` is what stops a human from blindly
  approving. **Do not set `MCP_OAUTH_AUTO_APPROVE=true` on a publicly-reachable
  origin.**
- **Tailscale Funnel ingress is NOT filtered by tailnet ACLs.** See
  `TAILSCALE_SECURITY.md` errata. The OAuth shim is the only application-layer
  defense for Funnel-exposed deployments.
- **Spec deviations.** AS metadata advertises endpoints under the issuer
  origin, but spec-compliant clients that *honor* `authorization_endpoint`
  will work; non-compliant clients (Claude.ai web) that ignore metadata also
  work because the endpoint paths happen to match.

## Manual test recipe

### DCR flow

```bash
# 1. Discovery
curl -s https://<issuer>/.well-known/oauth-protected-resource | jq
curl -s https://<issuer>/.well-known/oauth-authorization-server | jq

# 2. DCR
CID=$(curl -s -X POST https://<issuer>/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost:9000/cb"],"client_name":"Manual test"}' \
  | jq -r .client_id)
echo "client_id=$CID"

# 3. Authorize — open in browser, click Approve, capture ?code= from redirect
VERIFIER=$(node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))")
CHALLENGE=$(node -e "console.log(require('crypto').createHash('sha256').update('$VERIFIER').digest().toString('base64url'))")
open "https://<issuer>/authorize?response_type=code&client_id=$CID&redirect_uri=http://localhost:9000/cb&code_challenge=$CHALLENGE&code_challenge_method=S256&state=xyz&resource=https://<issuer>/mcp"

# 4. Token
curl -s -X POST https://<issuer>/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=<CODE>&redirect_uri=http://localhost:9000/cb&client_id=$CID&code_verifier=$VERIFIER&resource=https://<issuer>/mcp"

# 5. MCP request
curl -s https://<issuer>/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'
```

### CIMD flow (mimics Claude.ai)

```bash
# 1. (no /register call) — use a URL-formatted client_id pointing to a CIMD doc.
#    Claude.ai uses https://claude.ai/oauth/mcp-oauth-client-metadata which
#    points to https://claude.ai/api/mcp/auth_callback as the only redirect_uri.

# 2. Authorize — the server fetches the CIMD URL on this request,
#    validates the document, and shows the consent page (or 302s if auto-approve).
CIMD="https://claude.ai/oauth/mcp-oauth-client-metadata"
REDIRECT="https://claude.ai/api/mcp/auth_callback"
VERIFIER=$(node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))")
CHALLENGE=$(node -e "console.log(require('crypto').createHash('sha256').update('$VERIFIER').digest().toString('base64url'))")

# Encode for the URL
CIMD_ENC=$(node -e "console.log(encodeURIComponent('$CIMD'))")
REDIRECT_ENC=$(node -e "console.log(encodeURIComponent('$REDIRECT'))")
RESOURCE_ENC=$(node -e "console.log(encodeURIComponent('https://<issuer>/mcp'))")

# Expect HTTP 200 (consent HTML) on first call; the server fetches the CIMD doc.
curl -s -i "https://<issuer>/authorize?response_type=code&client_id=$CIMD_ENC&redirect_uri=$REDIRECT_ENC&code_challenge=$CHALLENGE&code_challenge_method=S256&state=xyz&scope=mcp&resource=$RESOURCE_ENC" | head -15

# To test programmatically against your OWN CIMD doc, host a JSON file with
# the shape:
#   {"client_id":"https://your-host/your-cimd.json","redirect_uris":["http://127.0.0.1:9000/cb"],"token_endpoint_auth_method":"none"}
# and substitute its URL for $CIMD above. Auto-approve the consent step
# (MCP_OAUTH_AUTO_APPROVE=true) so a curl-only loop captures the redirect.

# 3. Token exchange + Bearer use is identical to the DCR flow — the client_id
#    field in the /token request body is the URL string itself.
```

## Unit tests

```bash
npm run build
node --test dist/mcp-server/oauth/__tests__/oauth.test.js
```

## Future work

- v1.1: SQLite-backed stores (`better-sqlite3` already a candidate dep, or
  raw `node:sqlite` once stable in LTS)
- v1.2: CIMD endpoint + URL-formatted client_id support
- v1.3: scope splitting (`mcp:read`, `mcp:write`) + per-tool authorization
  gating
- v1.4: external IdP delegation mode (auth_server != resource_server) for
  multi-user enterprise deployments

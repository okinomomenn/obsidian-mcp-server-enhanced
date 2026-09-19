/**
 * @fileoverview OAuth 2.1 §5 token endpoint.
 *   POST /token (application/x-www-form-urlencoded)
 *     grant_type=authorization_code → exchange code+PKCE for tokens
 *     grant_type=refresh_token      → rotate refresh, issue new access
 *
 * Response is JSON per RFC 6749 §5.1.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { verifyClientAssertion } from "./clientAssertion.js";
import { resolveClient } from "./clientStore.js";
import { verifyS256Challenge } from "./pkce.js";
import {
  consumeCode,
  issueAccessToken,
  issueRefreshToken,
  peekCodeAuthMethod,
  peekRefreshAuthMethod,
  rotateRefreshToken,
} from "./tokenStore.js";
import {
  OAuthError,
  TokenAuthCodeRequestSchema,
  TokenRefreshRequestSchema,
  type TokenEndpointAuthMethod,
} from "./types.js";

export interface TokenDeps {
  jwtSecret: string;
  issuerUrl: string;
  /** Canonical MCP audience URI (issuer + mcp endpoint path). */
  audience: string;
  /** This server's own token endpoint URL — the only `aud` a client assertion may carry. */
  tokenEndpoint: string;
  accessTtlSec: number;
  refreshTtlSec: number;
}

/**
 * Enforce the client authentication that was bound to this grant at /authorize time.
 *
 * For "none" — every DCR client and every CIMD public client — this returns
 * immediately and the exchange is byte-for-byte what it was before private_key_jwt
 * existed: no client lookup, no network, no new failure mode. The CIMD document is
 * resolved only on the private_key_jwt branch (cached in cimd.ts), which preserves
 * the long-standing property that a refresh costs no round-trip.
 */
async function enforceClientAuth(
  method: TokenEndpointAuthMethod,
  form: { client_id: string; client_assertion?: string; client_assertion_type?: string },
  deps: TokenDeps,
): Promise<void> {
  if (method === "none") return;
  const client = await resolveClient(form.client_id);
  if (client.tokenEndpointAuthMethod !== "private_key_jwt") {
    // The client's published metadata no longer asks for private_key_jwt while a
    // live grant still requires it. Honour the stricter of the two.
    throw new OAuthError(
      "invalid_client",
      "grant requires private_key_jwt but the client no longer declares it",
      401,
    );
  }
  await verifyClientAssertion({
    client,
    assertion: form.client_assertion,
    assertionType: form.client_assertion_type,
    clientId: form.client_id,
    tokenEndpoint: deps.tokenEndpoint,
  });
}

interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

async function handleAuthCode(form: Record<string, string>, deps: TokenDeps): Promise<TokenResponse> {
  const parsed = TokenAuthCodeRequestSchema.safeParse(form);
  if (!parsed.success) {
    throw new OAuthError(
      "invalid_request",
      `token (authorization_code) invalid: ${JSON.stringify(parsed.error.flatten().fieldErrors)}`,
      400,
    );
  }
  const r = parsed.data;

  // Note: no client_id existence check here — the code → client binding below
  // is the authoritative proof that this client was approved at /authorize time.
  // For CIMD clients, re-fetching the metadata document on every /token call
  // would add an unnecessary network round-trip per refresh.
  //
  // Client authentication is checked first, and against a NON-destructive read of
  // the code: consuming it before a failed assertion would burn the grant (and, on
  // the client's retry, trip the reuse detector and revoke its refresh tokens).
  const boundAuthMethod = peekCodeAuthMethod(r.code);
  if (boundAuthMethod) {
    await enforceClientAuth(boundAuthMethod, r, deps);
  }
  const code = consumeCode(r.code);
  if (code.clientId !== r.client_id) {
    throw new OAuthError("invalid_grant", "code was issued to a different client", 400);
  }
  if (code.redirectUri !== r.redirect_uri) {
    throw new OAuthError("invalid_grant", "redirect_uri does not match authorize request", 400);
  }
  // RFC 8707 audience binding — when the client repeats `resource` it must match the
  // one bound at /authorize. When omitted (RFC 8707 §2.2 permits this, and claude.ai
  // does omit it) the code's bound resource is authoritative and is used below.
  if (r.resource !== undefined && code.resource !== r.resource) {
    throw new OAuthError("invalid_grant", "resource indicator does not match", 400);
  }
  if (!verifyS256Challenge(r.code_verifier, code.codeChallenge)) {
    throw new OAuthError("invalid_grant", "PKCE verifier does not match challenge", 400);
  }

  const access = await issueAccessToken({
    secret: deps.jwtSecret,
    issuer: deps.issuerUrl,
    audience: code.resource,
    clientId: r.client_id,
    scope: code.scope,
    ttlSec: deps.accessTtlSec,
  });
  const refresh = issueRefreshToken({
    clientId: r.client_id,
    resource: code.resource,
    scope: code.scope,
    ttlSec: deps.refreshTtlSec,
    clientAuthMethod: code.clientAuthMethod,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refresh.token,
    scope: code.scope,
  };
}

async function handleRefresh(form: Record<string, string>, deps: TokenDeps): Promise<TokenResponse> {
  const parsed = TokenRefreshRequestSchema.safeParse(form);
  if (!parsed.success) {
    throw new OAuthError(
      "invalid_request",
      `token (refresh_token) invalid: ${JSON.stringify(parsed.error.flatten().fieldErrors)}`,
      400,
    );
  }
  const r = parsed.data;

  // Same ordering rule as the authorization_code grant: authenticate the client
  // against a non-destructive read first, because rotateRefreshToken deletes the
  // presented token and a failure afterwards would log the connector out for good.
  const boundAuthMethod = peekRefreshAuthMethod(r.refresh_token);
  if (boundAuthMethod) {
    await enforceClientAuth(boundAuthMethod, r, deps);
  }

  // refresh token → client binding is verified by rotateRefreshToken.
  const old = rotateRefreshToken(r.refresh_token, r.client_id);
  // Same RFC 8707 §2.2 rule as the authorization_code grant: verify only when sent.
  if (r.resource !== undefined && old.resource !== r.resource) {
    throw new OAuthError("invalid_grant", "resource indicator does not match", 400);
  }

  // Optional scope down-scoping (RFC 6749 §6). v1: only honor "mcp" subset.
  const scope = r.scope
    ? r.scope.split(/\s+/).filter((s) => old.scope.split(/\s+/).includes(s)).join(" ") || old.scope
    : old.scope;

  const access = await issueAccessToken({
    secret: deps.jwtSecret,
    issuer: deps.issuerUrl,
    audience: old.resource,
    clientId: r.client_id,
    scope,
    ttlSec: deps.accessTtlSec,
  });
  const refresh = issueRefreshToken({
    clientId: r.client_id,
    resource: old.resource,
    scope,
    ttlSec: deps.refreshTtlSec,
    clientAuthMethod: old.clientAuthMethod,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refresh.token,
    scope,
  };
}

export async function handleToken(
  req: IncomingMessage,
  res: ServerResponse,
  parseFormBody: () => Promise<Record<string, string>>,
  deps: TokenDeps,
): Promise<void> {
  if (req.method !== "POST") {
    throw new OAuthError("invalid_request", "/token requires POST", 405);
  }
  const ct = (req.headers["content-type"] || "").toLowerCase();
  if (!ct.startsWith("application/x-www-form-urlencoded")) {
    throw new OAuthError(
      "invalid_request",
      "/token requires Content-Type: application/x-www-form-urlencoded",
      400,
    );
  }

  const form = await parseFormBody();
  let body: TokenResponse;
  switch (form.grant_type) {
    case "authorization_code":
      body = await handleAuthCode(form, deps);
      break;
    case "refresh_token":
      body = await handleRefresh(form, deps);
      break;
    default:
      throw new OAuthError(
        "unsupported_grant_type",
        `grant_type=${form.grant_type ?? "(missing)"} is not supported`,
        400,
      );
  }

  // OAuth 2.1 §5.1 — disable caching of bearer tokens.
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    Pragma: "no-cache",
  });
  res.end(JSON.stringify(body));
}

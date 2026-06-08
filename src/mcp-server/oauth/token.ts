/**
 * @fileoverview OAuth 2.1 §5 token endpoint.
 *   POST /token (application/x-www-form-urlencoded)
 *     grant_type=authorization_code → exchange code+PKCE for tokens
 *     grant_type=refresh_token      → rotate refresh, issue new access
 *
 * Response is JSON per RFC 6749 §5.1.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { getClient } from "./clientStore.js";
import { verifyS256Challenge } from "./pkce.js";
import {
  consumeCode,
  issueAccessToken,
  issueRefreshToken,
  rotateRefreshToken,
} from "./tokenStore.js";
import {
  OAuthError,
  TokenAuthCodeRequestSchema,
  TokenRefreshRequestSchema,
} from "./types.js";

export interface TokenDeps {
  jwtSecret: string;
  issuerUrl: string;
  /** Canonical MCP audience URI (issuer + mcp endpoint path). */
  audience: string;
  accessTtlSec: number;
  refreshTtlSec: number;
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

  const client = getClient(r.client_id);
  if (!client) throw new OAuthError("invalid_client", "unknown client_id", 401);

  const code = consumeCode(r.code);
  if (code.clientId !== r.client_id) {
    throw new OAuthError("invalid_grant", "code was issued to a different client", 400);
  }
  if (code.redirectUri !== r.redirect_uri) {
    throw new OAuthError("invalid_grant", "redirect_uri does not match authorize request", 400);
  }
  // RFC 8707 audience binding — the resource at /token must match the one at /authorize.
  if (code.resource !== r.resource) {
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

  const client = getClient(r.client_id);
  if (!client) throw new OAuthError("invalid_client", "unknown client_id", 401);

  const old = rotateRefreshToken(r.refresh_token, r.client_id);
  if (old.resource !== r.resource) {
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

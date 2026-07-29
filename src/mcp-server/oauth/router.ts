/**
 * @fileoverview OAuth router — dispatches well-known + DCR + authorize + token requests.
 * Returns true iff the request was handled (response was written).
 *
 * Wired into httpTransportNative.ts BEFORE the `/mcp`-only branch so that
 * OAuth endpoints are served without authentication.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { URL } from "url";
import { config } from "../../config/index.js";
import { logger, requestContextService } from "../../utils/index.js";
import { handleAuthorize } from "./authorize.js";
import { authorizationServerMetadata, protectedResourceMetadata } from "./metadata.js";
import { handleRegister } from "./register.js";
import { handleToken } from "./token.js";
import { OAuthError } from "./types.js";

export interface OAuthRouterDeps {
  /** Public canonical origin, e.g. https://your-mcp-server.example.com */
  issuerUrl: string;
  /** MCP endpoint path, e.g. /mcp */
  mcpEndpointPath: string;
  /** HS256 signing secret (≥32 bytes). */
  jwtSecret: string;
  accessTtlSec: number;
  refreshTtlSec: number;
  codeTtlSec: number;
  autoApprove: boolean;
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  // well-known metadata endpoints use writeJson exclusively (router.ts:61,65).
  // Force clients to re-fetch on every connection so server-side metadata changes
  // (e.g. capability advertisement) propagate immediately. See Stage 1.7 recon.
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
  });
  res.end(JSON.stringify(body));
}

function writeOAuthError(res: ServerResponse, err: OAuthError): void {
  if (!res.headersSent) {
    res.writeHead(err.httpStatus, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify(err.toJSON()));
  }
}

/** Returns true iff handled. Caller should `return` immediately when true. */
export async function routeOAuth(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  parseJsonBody: () => Promise<unknown>,
  parseFormBody: () => Promise<Record<string, string>>,
  deps: OAuthRouterDeps,
): Promise<boolean> {
  const path = url.pathname;
  const wellKnownPRM = "/.well-known/oauth-protected-resource";
  const wellKnownPRMSub = `/.well-known/oauth-protected-resource${deps.mcpEndpointPath}`;
  const wellKnownASM = "/.well-known/oauth-authorization-server";
  const wellKnownOIDC = "/.well-known/openid-configuration";

  // --- GET well-known metadata (no auth) ---
  if (req.method === "GET" && (path === wellKnownPRM || path === wellKnownPRMSub)) {
    writeJson(res, 200, protectedResourceMetadata(deps.issuerUrl, deps.mcpEndpointPath));
    return true;
  }
  if (req.method === "GET" && (path === wellKnownASM || path === wellKnownOIDC)) {
    writeJson(res, 200, authorizationServerMetadata(deps.issuerUrl));
    return true;
  }

  // --- DCR ---
  if (path === "/register") {
    try {
      await handleRegister(req, res, parseJsonBody);
    } catch (err) {
      handleErr(req, res, err, "register");
    }
    return true;
  }

  // --- Authorize ---
  if (path === "/authorize") {
    try {
      await handleAuthorize(req, res, url, parseFormBody, {
        autoApprove: deps.autoApprove,
        codeTtlSec: deps.codeTtlSec,
        issuerUrl: deps.issuerUrl,
      });
    } catch (err) {
      handleErr(req, res, err, "authorize");
    }
    return true;
  }

  // --- Token ---
  if (path === "/token") {
    try {
      await handleToken(req, res, parseFormBody, {
        jwtSecret: deps.jwtSecret,
        issuerUrl: deps.issuerUrl,
        audience: `${deps.issuerUrl.replace(/\/+$/, "")}${deps.mcpEndpointPath}`,
        accessTtlSec: deps.accessTtlSec,
        refreshTtlSec: deps.refreshTtlSec,
      });
    } catch (err) {
      handleErr(req, res, err, "token");
    }
    return true;
  }

  return false;
}

function handleErr(req: IncomingMessage, res: ServerResponse, err: unknown, op: string): void {
  const ctx = requestContextService.createRequestContext({
    operation: `oauth:${op}`,
    method: req.method ?? "unknown",
    url: req.url ?? "unknown",
  });
  if (err instanceof OAuthError) {
    logger.warning(`OAuth ${op} rejected: ${err.code} — ${err.description}`, ctx);
    writeOAuthError(res, err);
    return;
  }
  logger.error(`OAuth ${op} unexpected error`, {
    ...ctx,
    error: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined,
  });
  writeOAuthError(res, new OAuthError("server_error", "internal error", 500));
}

/**
 * Build OAuthRouterDeps from validated app config.
 * Throws at startup if MCP_AUTH_MODE=oauth but required secrets are absent.
 */
export function buildOAuthDepsFromConfig(mcpEndpointPath: string): OAuthRouterDeps {
  const issuer = config.mcpOauthIssuerUrl;
  if (!issuer) {
    throw new Error("MCP_OAUTH_ISSUER_URL is required when MCP_AUTH_MODE=oauth");
  }
  const secret = config.mcpAuthSecretKey;
  if (!secret) {
    throw new Error("MCP_AUTH_SECRET_KEY (≥32 chars) is required when MCP_AUTH_MODE=oauth");
  }
  return {
    issuerUrl: issuer.replace(/\/+$/, ""),
    mcpEndpointPath,
    jwtSecret: secret,
    accessTtlSec: config.mcpOauthAccessTokenTtlSec,
    refreshTtlSec: config.mcpOauthRefreshTokenTtlSec,
    codeTtlSec: config.mcpOauthCodeTtlSec,
    autoApprove: config.mcpOauthAutoApprove,
  };
}

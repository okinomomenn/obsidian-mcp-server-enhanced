/**
 * @fileoverview Bearer token middleware for the protected /mcp endpoint.
 * Returns {claims} on success, or writes a spec-compliant 401/403 response and returns null.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { verifyAccessToken } from "./tokenStore.js";
import { OAuthError } from "./types.js";
import type { AccessTokenClaims } from "./types.js";

export interface BearerDeps {
  jwtSecret: string;
  issuerUrl: string;
  audience: string;
  /** Absolute URL of the protected-resource-metadata document. */
  resourceMetadataUrl: string;
}

/** RFC 6750 §3 — emit a properly-quoted WWW-Authenticate challenge. */
function challengeHeader(deps: BearerDeps, error?: { code: string; description: string }, status: number = 401): string {
  const parts: string[] = [
    `Bearer realm="obsidian-mcp"`,
    `resource_metadata="${deps.resourceMetadataUrl}"`,
    `scope="mcp"`,
  ];
  if (error) {
    parts.push(`error="${error.code}"`);
    parts.push(`error_description="${error.description.replace(/"/g, "'")}"`);
  }
  void status;
  return parts.join(", ");
}

function reject(
  res: ServerResponse,
  deps: BearerDeps,
  status: 401 | 403,
  error: { code: string; description: string },
): null {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "WWW-Authenticate": challengeHeader(deps, error, status),
  });
  res.end(JSON.stringify({ error: error.code, error_description: error.description }));
  return null;
}

export async function verifyBearer(
  req: IncomingMessage,
  res: ServerResponse,
  deps: BearerDeps,
): Promise<AccessTokenClaims | null> {
  const header = req.headers.authorization;
  if (!header) {
    return reject(res, deps, 401, {
      code: "invalid_token",
      description: "Authorization header missing",
    });
  }
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return reject(res, deps, 401, {
      code: "invalid_token",
      description: "Authorization header must use Bearer scheme",
    });
  }
  const token = match[1].trim();
  try {
    return await verifyAccessToken({
      secret: deps.jwtSecret,
      issuer: deps.issuerUrl,
      audience: deps.audience,
      token,
    });
  } catch (err) {
    const e = err instanceof OAuthError ? err : new OAuthError("invalid_token", String(err), 401);
    return reject(res, deps, 401, { code: e.code, description: e.description });
  }
}

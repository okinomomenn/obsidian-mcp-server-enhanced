/**
 * @fileoverview Token issuance & verification.
 *   - Access tokens: self-contained HS256 JWTs (jose). No DB lookup at verify time.
 *   - Refresh tokens: opaque random strings stored in-memory, rotated on use (OAuth 2.1 MUST for public clients).
 *   - Authorization codes: in-memory, single-use, short-lived.
 */

import { randomBytes, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import type { AccessTokenClaims, AuthorizationCode, RefreshToken } from "./types.js";
import { OAuthError } from "./types.js";

const codes = new Map<string, AuthorizationCode>();
const refreshTokens = new Map<string, RefreshToken>();

function secretKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

/* ---------- Authorization codes ---------- */

export function issueCode(input: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  scope: string;
  ttlSec: number;
}): AuthorizationCode {
  const code: AuthorizationCode = {
    code: randomBytes(32).toString("base64url"),
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    resource: input.resource,
    scope: input.scope,
    expiresAt: Date.now() + input.ttlSec * 1000,
    consumed: false,
  };
  codes.set(code.code, code);
  return code;
}

/** Single-use: returns code only if unconsumed and unexpired, then marks consumed. */
export function consumeCode(value: string): AuthorizationCode {
  const code = codes.get(value);
  if (!code) throw new OAuthError("invalid_grant", "authorization code unknown", 400);
  if (code.consumed) {
    // Per RFC 6749 §10.5: detected reuse means earlier issuance was compromised.
    // Revoke all refresh tokens issued under this client_id to limit blast radius.
    revokeAllRefreshTokensForClient(code.clientId);
    throw new OAuthError("invalid_grant", "authorization code already used", 400);
  }
  if (Date.now() > code.expiresAt) {
    codes.delete(value);
    throw new OAuthError("invalid_grant", "authorization code expired", 400);
  }
  code.consumed = true;
  return code;
}

/* ---------- Access tokens (JWT) ---------- */

export async function issueAccessToken(input: {
  secret: string;
  issuer: string;
  audience: string;
  clientId: string;
  scope: string;
  ttlSec: number;
}): Promise<{ token: string; expiresIn: number }> {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    scope: input.scope,
    client_id: input.clientId,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(input.issuer)
    .setAudience(input.audience)
    .setSubject(input.clientId)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + input.ttlSec)
    .sign(secretKey(input.secret));
  return { token, expiresIn: input.ttlSec };
}

export async function verifyAccessToken(input: {
  secret: string;
  issuer: string;
  audience: string;
  token: string;
}): Promise<AccessTokenClaims> {
  try {
    const { payload } = await jwtVerify(input.token, secretKey(input.secret), {
      issuer: input.issuer,
      audience: input.audience,
      algorithms: ["HS256"],
    });
    return payload as unknown as AccessTokenClaims;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthError("invalid_token", `access token rejected: ${msg}`, 401);
  }
}

/* ---------- Refresh tokens ---------- */

export function issueRefreshToken(input: {
  clientId: string;
  resource: string;
  scope: string;
  ttlSec: number;
}): RefreshToken {
  const rt: RefreshToken = {
    token: randomBytes(48).toString("base64url"),
    clientId: input.clientId,
    resource: input.resource,
    scope: input.scope,
    expiresAt: Date.now() + input.ttlSec * 1000,
  };
  refreshTokens.set(rt.token, rt);
  return rt;
}

/** Rotation: invalidate the presented refresh token and return its metadata for re-issue. */
export function rotateRefreshToken(value: string, clientId: string): RefreshToken {
  const rt = refreshTokens.get(value);
  if (!rt) throw new OAuthError("invalid_grant", "refresh token unknown", 400);
  if (rt.clientId !== clientId) {
    refreshTokens.delete(value);
    throw new OAuthError("invalid_grant", "refresh token bound to different client", 400);
  }
  if (Date.now() > rt.expiresAt) {
    refreshTokens.delete(value);
    throw new OAuthError("invalid_grant", "refresh token expired", 400);
  }
  refreshTokens.delete(value);
  return rt;
}

function revokeAllRefreshTokensForClient(clientId: string): void {
  for (const [k, v] of refreshTokens) {
    if (v.clientId === clientId) refreshTokens.delete(k);
  }
}

/* ---------- Background GC ---------- */

export function startTokenStoreGc(intervalMs = 60_000): NodeJS.Timeout {
  return setInterval(() => {
    const now = Date.now();
    for (const [k, v] of codes) if (v.expiresAt < now) codes.delete(k);
    for (const [k, v] of refreshTokens) if (v.expiresAt < now) refreshTokens.delete(k);
  }, intervalMs);
}

/** Test-only helpers. */
export function _resetTokenStore(): void {
  codes.clear();
  refreshTokens.clear();
}
export function _peekCode(value: string): AuthorizationCode | undefined {
  return codes.get(value);
}

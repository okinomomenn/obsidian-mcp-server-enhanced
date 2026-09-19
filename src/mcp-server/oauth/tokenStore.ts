/**
 * @fileoverview Token issuance & verification.
 *   - Access tokens: self-contained HS256 JWTs (jose). No DB lookup at verify time,
 *     so they already survive a restart on their own — nothing is persisted here.
 *   - Refresh tokens: opaque random strings persisted in SQLite (v1.1), rotated on
 *     use (OAuth 2.1 MUST for public clients).
 *   - Authorization codes: persisted, single-use, short-lived.
 *
 * TIME UNITS: `expiresAt` / `expires_at` are epoch **milliseconds** (Date.now()).
 * The JWT layer is the only place that speaks seconds, and it converts locally in
 * issueAccessToken. Do not let seconds leak into the store.
 */

import { randomBytes, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { getDb } from "./db.js";
import type {
  AccessTokenClaims,
  AuthorizationCode,
  RefreshToken,
  TokenEndpointAuthMethod,
} from "./types.js";
import { OAuthError } from "./types.js";

interface CodeRow {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  resource: string;
  scope: string;
  expires_at: number;
  consumed: number;
  client_auth_method: string;
}

interface RefreshRow {
  token: string;
  client_id: string;
  resource: string;
  scope: string;
  expires_at: number;
  client_auth_method: string;
}

function toCode(row: CodeRow): AuthorizationCode {
  return {
    code: row.code,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    resource: row.resource,
    scope: row.scope,
    expiresAt: row.expires_at,
    // SQLite has no boolean type; the column is INTEGER 0/1.
    consumed: row.consumed !== 0,
    clientAuthMethod: toAuthMethod(row.client_auth_method),
  };
}

function toRefresh(row: RefreshRow): RefreshToken {
  return {
    token: row.token,
    clientId: row.client_id,
    resource: row.resource,
    scope: row.scope,
    expiresAt: row.expires_at,
    clientAuthMethod: toAuthMethod(row.client_auth_method),
  };
}

/**
 * Narrow the stored string. Anything unrecognised — a row written by a newer build
 * and read back by an older one — collapses to "private_key_jwt" rather than
 * "none": an unreadable requirement must not silently become no requirement.
 */
function toAuthMethod(value: string | null | undefined): TokenEndpointAuthMethod {
  if (value === "none" || value === undefined || value === null) return "none";
  return "private_key_jwt";
}

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
  /** How the client must authenticate at /token. Defaults to the public-client path. */
  clientAuthMethod?: TokenEndpointAuthMethod;
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
    clientAuthMethod: input.clientAuthMethod ?? "none",
  };
  getDb()
    .prepare(
      `INSERT INTO codes
         (code, client_id, redirect_uri, code_challenge, resource, scope, expires_at, consumed, client_auth_method)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    )
    .run(
      code.code,
      code.clientId,
      code.redirectUri,
      code.codeChallenge,
      code.resource,
      code.scope,
      code.expiresAt,
      code.clientAuthMethod,
    );
  return code;
}

/**
 * Non-destructive reads of the client authentication requirement bound to a grant.
 *
 * These exist so /token can verify a private_key_jwt assertion BEFORE consuming the
 * code or rotating the refresh token. Verifying afterwards would mean a transient
 * jwks_uri hiccup destroys the grant and logs the connector out permanently.
 * `undefined` means "no such grant" — the caller then falls through to
 * consumeCode / rotateRefreshToken, which raise the usual invalid_grant.
 */
export function peekCodeAuthMethod(value: string): TokenEndpointAuthMethod | undefined {
  const row = getDb()
    .prepare(`SELECT client_auth_method FROM codes WHERE code = ?`)
    .get(value) as { client_auth_method: string } | undefined;
  return row ? toAuthMethod(row.client_auth_method) : undefined;
}

export function peekRefreshAuthMethod(value: string): TokenEndpointAuthMethod | undefined {
  const row = getDb()
    .prepare(`SELECT client_auth_method FROM refresh_tokens WHERE token = ?`)
    .get(value) as { client_auth_method: string } | undefined;
  return row ? toAuthMethod(row.client_auth_method) : undefined;
}

/** Single-use: returns code only if unconsumed and unexpired, then marks consumed. */
export function consumeCode(value: string): AuthorizationCode {
  const db = getDb();
  const row = db.prepare(`SELECT * FROM codes WHERE code = ?`).get(value) as
    | CodeRow
    | undefined;
  if (!row) throw new OAuthError("invalid_grant", "authorization code unknown", 400);
  const code = toCode(row);
  if (code.consumed) {
    // Per RFC 6749 §10.5: detected reuse means earlier issuance was compromised.
    // Revoke all refresh tokens issued under this client_id to limit blast radius.
    revokeAllRefreshTokensForClient(code.clientId);
    throw new OAuthError("invalid_grant", "authorization code already used", 400);
  }
  if (Date.now() > code.expiresAt) {
    db.prepare(`DELETE FROM codes WHERE code = ?`).run(value);
    throw new OAuthError("invalid_grant", "authorization code expired", 400);
  }
  db.prepare(`UPDATE codes SET consumed = 1 WHERE code = ?`).run(value);
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
  /** Carried forward on every rotation so the requirement survives restarts. */
  clientAuthMethod?: TokenEndpointAuthMethod;
}): RefreshToken {
  const rt: RefreshToken = {
    token: randomBytes(48).toString("base64url"),
    clientId: input.clientId,
    resource: input.resource,
    scope: input.scope,
    expiresAt: Date.now() + input.ttlSec * 1000,
    clientAuthMethod: input.clientAuthMethod ?? "none",
  };
  getDb()
    .prepare(
      `INSERT INTO refresh_tokens (token, client_id, resource, scope, expires_at, client_auth_method)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(rt.token, rt.clientId, rt.resource, rt.scope, rt.expiresAt, rt.clientAuthMethod);
  return rt;
}

/** Rotation: invalidate the presented refresh token and return its metadata for re-issue. */
export function rotateRefreshToken(value: string, clientId: string): RefreshToken {
  const db = getDb();
  const row = db.prepare(`SELECT * FROM refresh_tokens WHERE token = ?`).get(value) as
    | RefreshRow
    | undefined;
  if (!row) throw new OAuthError("invalid_grant", "refresh token unknown", 400);
  const rt = toRefresh(row);
  const del = db.prepare(`DELETE FROM refresh_tokens WHERE token = ?`);
  if (rt.clientId !== clientId) {
    del.run(value);
    throw new OAuthError("invalid_grant", "refresh token bound to different client", 400);
  }
  if (Date.now() > rt.expiresAt) {
    del.run(value);
    throw new OAuthError("invalid_grant", "refresh token expired", 400);
  }
  del.run(value);
  return rt;
}

function revokeAllRefreshTokensForClient(clientId: string): void {
  getDb().prepare(`DELETE FROM refresh_tokens WHERE client_id = ?`).run(clientId);
}

/* ---------- Background GC ---------- */

export function startTokenStoreGc(intervalMs = 60_000): NodeJS.Timeout {
  return setInterval(() => {
    const now = Date.now();
    const db = getDb();
    db.prepare(`DELETE FROM codes WHERE expires_at < ?`).run(now);
    db.prepare(`DELETE FROM refresh_tokens WHERE expires_at < ?`).run(now);
  }, intervalMs);
}

/** Test-only helpers. */
export function _resetTokenStore(): void {
  const db = getDb();
  db.exec(`DELETE FROM codes`);
  db.exec(`DELETE FROM refresh_tokens`);
}
export function _peekCode(value: string): AuthorizationCode | undefined {
  const row = getDb().prepare(`SELECT * FROM codes WHERE code = ?`).get(value) as
    | CodeRow
    | undefined;
  return row ? toCode(row) : undefined;
}

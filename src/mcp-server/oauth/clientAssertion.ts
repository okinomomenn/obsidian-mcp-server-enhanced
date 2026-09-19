/**
 * @fileoverview RFC 7523 §2.2 / OIDC Core §9 `private_key_jwt` client authentication.
 *
 * Added 2026-09-18 so CIMD clients that refuse to act as public clients (ChatGPT
 * declares `token_endpoint_auth_method: "private_key_jwt"`) can be admitted without
 * touching the `"none"` path that every current connector uses.
 *
 * Scope discipline: this module is a leaf. It is called from token.ts and from
 * nowhere else, and it reads only the client's own CIMD-declared key material, so
 * the whole feature can be reverted by deleting this file and its single call site.
 *
 * Fail-closed by construction:
 *   - a jwks_uri that cannot be fetched, parsed, or shape-checked → assertion
 *     rejected; there is deliberately no stale-on-error fallback and no
 *     "allow when unknown" branch.
 *   - only asymmetric signature algorithms are accepted, so a published JWK Set
 *     cannot be replayed as an HMAC secret.
 */

import { createLocalJWKSet, importJWK, jwtVerify, type JWTPayload, type JWTVerifyOptions } from "jose";
import { assertFetchableHttpsUrl, assertJwkSet } from "./cimd.js";
import { OAuthError, type ClientRegistration, type JsonWebKeySet } from "./types.js";

/** RFC 7523 §2.2 — the only client_assertion_type this server accepts. */
export const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * Asymmetric only. `none` and the HS* family are excluded: with HS* anyone who can
 * read the (public) JWK Set could sign assertions with it.
 */
const ALLOWED_ALGS = [
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA",
] as const;

/**
 * jwks_uri fetch budget. Deliberately much tighter than the CIMD document fetch
 * (30s × 3): that one runs at /authorize where a human is already waiting on a
 * redirect, this one runs inside a token exchange. On timeout the assertion is
 * rejected.
 */
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const JWKS_MAX_BODY_BYTES = 64 * 1024;
/**
 * Cache TTL for a fetched JWK Set. Fixed rather than Cache-Control-driven: an
 * origin must not be able to pin its own keys in our memory indefinitely.
 */
const JWKS_TTL_MS = 300_000;

/** Longest assertion lifetime accepted, and therefore how long a jti is remembered. */
const MAX_ASSERTION_LIFETIME_SEC = 3600;

/** Clock skew tolerance for exp / nbf / iat, in seconds. */
const CLOCK_TOLERANCE_SEC = 60;

interface JwksCacheEntry {
  jwks: JsonWebKeySet;
  expiresAt: number;
}
const jwksCache = new Map<string, JwksCacheEntry>();

/** jti → epoch ms at which the assertion expires. Entries are pruned lazily. */
const seenJtis = new Map<string, number>();

/**
 * Hard cap on the replay table so a flood of assertions cannot exhaust memory.
 * Reaching it is not expected: a connector issues one assertion per token call.
 */
const MAX_SEEN_JTIS = 10_000;

function pruneJtis(now: number): void {
  for (const [jti, expiresAt] of seenJtis) {
    if (expiresAt <= now) seenJtis.delete(jti);
  }
}

/**
 * Record a jti, rejecting a repeat. Retained until the assertion's own `exp`, which
 * is all that is needed: past that point the `exp` check rejects it anyway.
 */
function claimJti(jti: string, expiresAtMs: number): void {
  const now = Date.now();
  pruneJtis(now);
  const seen = seenJtis.get(jti);
  if (seen !== undefined && seen > now) {
    throw new OAuthError("invalid_client", "client_assertion jti has already been used", 401);
  }
  if (seenJtis.size >= MAX_SEEN_JTIS) {
    // Every surviving entry is still within MAX_ASSERTION_LIFETIME_SEC, so nothing
    // can be evicted safely. Refusing is the fail-closed choice.
    throw new OAuthError("invalid_client", "client_assertion replay table is full", 503);
  }
  seenJtis.set(jti, expiresAtMs);
}

/**
 * Fetch a JWK Set over https under the same SSRF policy as the CIMD document fetch.
 * Throws OAuthError on any failure — callers must not fall back to accepting the
 * assertion.
 */
async function fetchJwks(jwksUri: string): Promise<JsonWebKeySet> {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) return cached.jwks;

  assertFetchableHttpsUrl(jwksUri, "CIMD jwks_uri");

  let response: Response;
  try {
    response = await fetch(jwksUri, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new OAuthError(
      "invalid_client",
      `jwks_uri fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      401,
    );
  }
  if (response.status !== 200) {
    throw new OAuthError("invalid_client", `jwks_uri fetch returned HTTP ${response.status}`, 401);
  }
  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new OAuthError(
      "invalid_client",
      `jwks_uri Content-Type must be application/json, got "${contentType}"`,
      401,
    );
  }
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > JWKS_MAX_BODY_BYTES) {
    throw new OAuthError("invalid_client", `jwks_uri body exceeds ${JWKS_MAX_BODY_BYTES} bytes`, 401);
  }
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
  } catch (err) {
    throw new OAuthError(
      "invalid_client",
      `jwks_uri body is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      401,
    );
  }
  const jwks = assertJwkSet(json, "jwks_uri document");
  jwksCache.set(jwksUri, { jwks, expiresAt: Date.now() + JWKS_TTL_MS });
  return jwks;
}

/** Resolve the key set a client's assertions must verify against. */
async function resolveClientJwks(client: ClientRegistration): Promise<JsonWebKeySet> {
  if (client.jwks) return client.jwks;
  if (client.jwksUri) return fetchJwks(client.jwksUri);
  // parseAndValidateCimdDocument guarantees one of the two, so reaching here means
  // the registration was built somewhere that skipped that check.
  throw new OAuthError(
    "invalid_client",
    `client ${client.clientId} declares private_key_jwt but publishes no key material`,
    401,
  );
}

/**
 * jose's key-set resolver picks exactly one key and refuses to guess: with an
 * unheadered `kid` and more than one candidate it raises
 * ERR_JWKS_MULTIPLE_MATCHING_KEYS, and a `kid` naming a key it filtered out raises
 * ERR_JWKS_NO_MATCHING_KEY. ChatGPT publishes two RS256 keys, so a kid-less
 * assertion from it would hit the first case and a perfectly valid signature would
 * be rejected — observed live against https://chatgpt.com/oauth/jwks.json.
 *
 * Only in those two ambiguity cases do we fall back to trying each published key in
 * turn. That is not a weakening: the requirement is "signed by a key this client's
 * own document publishes", and every candidate here is exactly that. Every other
 * failure (bad signature, wrong aud, expired) propagates from the strict pass.
 */
async function verifyAgainstJwks(
  assertion: string,
  jwks: JsonWebKeySet,
  options: JWTVerifyOptions,
): Promise<JWTPayload> {
  try {
    const keySet = createLocalJWKSet(jwks as unknown as Parameters<typeof createLocalJWKSet>[0]);
    const { payload } = await jwtVerify(assertion, keySet, options);
    return payload;
  } catch (err) {
    const code = (err as { code?: string } | null)?.code;
    if (code !== "ERR_JWKS_MULTIPLE_MATCHING_KEYS" && code !== "ERR_JWKS_NO_MATCHING_KEY") {
      throw err;
    }
    let lastErr: unknown = err;
    for (const jwk of jwks.keys) {
      try {
        const key = await importJWK(jwk as Parameters<typeof importJWK>[0]);
        const { payload } = await jwtVerify(assertion, key, options);
        return payload;
      } catch (perKeyErr) {
        lastErr = perKeyErr;
      }
    }
    throw lastErr;
  }
}

export interface VerifyClientAssertionInput {
  /** The resolved client, whose tokenEndpointAuthMethod is "private_key_jwt". */
  client: ClientRegistration;
  /** `client_assertion_type` exactly as posted. */
  assertionType: string | undefined;
  /** `client_assertion` exactly as posted. */
  assertion: string | undefined;
  /** `client_id` from the token request — must equal both iss and sub. */
  clientId: string;
  /** This server's own token endpoint URL — the only accepted `aud`. */
  tokenEndpoint: string;
}

/**
 * Verify a private_key_jwt client assertion. Resolves on success and throws
 * OAuthError("invalid_client") on every failure mode: signature not from a key the
 * client's own CIMD document publishes, iss/sub ≠ client_id, aud ≠ this token
 * endpoint, exp missing/expired/implausibly distant, jti missing or reused.
 */
export async function verifyClientAssertion(input: VerifyClientAssertionInput): Promise<void> {
  if (!input.assertion) {
    throw new OAuthError(
      "invalid_client",
      "client_assertion is required for a private_key_jwt client",
      401,
    );
  }
  if (input.assertionType !== CLIENT_ASSERTION_TYPE) {
    throw new OAuthError(
      "invalid_client",
      `client_assertion_type must be "${CLIENT_ASSERTION_TYPE}"`,
      401,
    );
  }

  const jwks = await resolveClientJwks(input.client);

  // Honour token_endpoint_auth_signing_alg when the client pins one, but never widen
  // past ALLOWED_ALGS — a document asking for HS256 must not be granted it.
  const pinned = input.client.tokenEndpointAuthSigningAlg;
  const algorithms: string[] =
    pinned && (ALLOWED_ALGS as readonly string[]).includes(pinned) ? [pinned] : [...ALLOWED_ALGS];

  const verifyOptions: JWTVerifyOptions = {
    algorithms,
    issuer: input.clientId,
    subject: input.clientId,
    audience: input.tokenEndpoint,
    clockTolerance: CLOCK_TOLERANCE_SEC,
    // jose treats a missing exp as "never expires"; requiredClaims makes it fatal.
    requiredClaims: ["exp", "jti", "iss", "sub", "aud"],
  };

  let payload: JWTPayload;
  try {
    payload = await verifyAgainstJwks(input.assertion, jwks, verifyOptions);
  } catch (err) {
    throw new OAuthError(
      "invalid_client",
      `client_assertion rejected: ${err instanceof Error ? err.message : String(err)}`,
      401,
    );
  }

  const exp = payload.exp;
  if (typeof exp !== "number") {
    throw new OAuthError("invalid_client", "client_assertion exp must be a number", 401);
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (exp > nowSec + MAX_ASSERTION_LIFETIME_SEC + CLOCK_TOLERANCE_SEC) {
    throw new OAuthError(
      "invalid_client",
      `client_assertion exp is more than ${MAX_ASSERTION_LIFETIME_SEC}s in the future`,
      401,
    );
  }

  const jti = payload.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    throw new OAuthError("invalid_client", "client_assertion jti must be a non-empty string", 401);
  }
  claimJti(jti, exp * 1000);
}

/** Test-only helper. */
export function _resetClientAssertionState(): void {
  jwksCache.clear();
  seenJtis.clear();
}

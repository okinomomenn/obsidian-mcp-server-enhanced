/**
 * @fileoverview OAuth Client ID Metadata Documents (CIMD).
 *
 * draft-ietf-oauth-client-id-metadata-document-00 + MCP 2025-11-25.
 *
 * When an /authorize request arrives with a URL-formatted client_id, the
 * authorization server fetches that URL and treats the returned JSON as the
 * client's registration metadata. This avoids a separate /register call —
 * the MCP client just hosts its metadata at a stable HTTPS URL.
 *
 * Security: CIMD lets unknown clients trigger an outbound HTTPS fetch from
 * this server. We MUST defend against SSRF (no private/loopback IPs, HTTPS
 * only, no redirects, body size cap, request timeout). See spec §6.
 */

import { OAuthError, type ClientRegistration } from "./types.js";

/** A fetched & validated client metadata document, normalized to ClientRegistration. */
// 2026-07-28: host egress observed at 4–19s TLS to the whole internet (not CIMD-host
// specific), so the previous 5_000ms aborted almost every fetch → invalid_client.
// Raised timeout, added bounded retries, and stale-on-error fallback below.
// Prior values (for rollback): FETCH_TIMEOUT_MS=5_000, no retry, MIN_TTL_SEC=60.
const FETCH_TIMEOUT_MS = 30_000;
const FETCH_RETRIES = 2; // total attempts = 1 + FETCH_RETRIES
const MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_TTL_SEC = 300;
const MIN_TTL_SEC = 300;
const MAX_TTL_SEC = 3600;

interface CacheEntry {
  client: ClientRegistration;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry>();

/** True if the value looks like an HTTPS URL eligible to be a CIMD client_id. */
export function isUrlClientId(clientId: string): boolean {
  return /^https:\/\//i.test(clientId);
}

/**
 * SSRF guard — block IP literals that target private / loopback / link-local
 * ranges. Hostnames that resolve via DNS are not pre-resolved; relying on the
 * outbound network being unable to reach internal services is an additional
 * layer of defence the operator can add (e.g. firewall rules on the host).
 */
export function isPrivateHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  // Literal hostnames that are always private.
  if (h === "localhost" || h === "ip6-localhost" || h === "ip6-loopback") return true;

  // IPv4 literal?
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10) return true;                  // 10/8
    if (a === 127) return true;                 // 127/8 loopback
    if (a === 0) return true;                   // 0.0.0.0/8
    if (a === 169 && b === 254) return true;    // 169.254/16 link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true;    // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
    return false;
  }

  // IPv6 literal?
  if (h.includes(":")) {
    if (h === "::1" || h === "::" ) return true;
    if (h.startsWith("fe80:")) return true;     // link-local
    if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique-local fc00::/7
    return false;
  }

  return false;
}

/**
 * Parse & validate a CIMD document per draft-ietf-oauth-client-id-metadata-document-00 §3.
 * Throws OAuthError(invalid_client) on any failure. Pure (no I/O) so it can be tested directly.
 */
export function parseAndValidateCimdDocument(raw: unknown, expectedClientIdUrl: string): ClientRegistration {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new OAuthError("invalid_client", "CIMD document must be a JSON object", 400);
  }
  const doc = raw as Record<string, unknown>;

  if (doc.client_id !== expectedClientIdUrl) {
    throw new OAuthError(
      "invalid_client",
      `CIMD client_id field "${String(doc.client_id)}" does not match the metadata URL "${expectedClientIdUrl}"`,
      400,
    );
  }

  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) {
    throw new OAuthError("invalid_client", "CIMD document must include non-empty redirect_uris array", 400);
  }
  const redirectUris: string[] = [];
  for (const uri of doc.redirect_uris) {
    if (typeof uri !== "string") {
      throw new OAuthError("invalid_client", "CIMD redirect_uris entries must be strings", 400);
    }
    try {
      const u = new URL(uri);
      if (u.protocol !== "https:" && u.protocol !== "http:") {
        throw new Error(`unsupported scheme ${u.protocol}`);
      }
      // For http://, allow only loopback (OAuth 2.1 §1.5).
      if (u.protocol === "http:" && !(u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]")) {
        throw new Error(`http:// redirect_uri must be loopback, got ${u.hostname}`);
      }
    } catch (err) {
      throw new OAuthError(
        "invalid_client",
        `CIMD redirect_uri "${uri}" is invalid: ${err instanceof Error ? err.message : String(err)}`,
        400,
      );
    }
    redirectUris.push(uri);
  }

  // token_endpoint_auth_method — v1 is public-client only.
  const authMethod = doc.token_endpoint_auth_method;
  if (authMethod !== undefined && authMethod !== "none") {
    throw new OAuthError(
      "invalid_client",
      `CIMD token_endpoint_auth_method must be "none" (public client); got "${String(authMethod)}"`,
      400,
    );
  }

  const clientName = typeof doc.client_name === "string" && doc.client_name.length > 0
    ? doc.client_name.slice(0, 200)
    : new URL(expectedClientIdUrl).hostname;

  return {
    clientId: expectedClientIdUrl,
    clientName,
    redirectUris,
    createdAt: Date.now(),
    tokenEndpointAuthMethod: "none",
    source: "cimd",
  };
}

function parseMaxAgeSec(cacheControl: string | null): number {
  if (!cacheControl) return DEFAULT_TTL_SEC;
  const m = /max-age\s*=\s*(\d+)/i.exec(cacheControl);
  if (!m) return DEFAULT_TTL_SEC;
  const v = Number(m[1]);
  if (!Number.isFinite(v) || v <= 0) return DEFAULT_TTL_SEC;
  return Math.min(MAX_TTL_SEC, Math.max(MIN_TTL_SEC, v));
}

/**
 * Fetch a CIMD document over HTTPS with SSRF + size + timeout + redirect guards.
 * Caches the parsed ClientRegistration with the response's Cache-Control max-age
 * (clamped to [60s, 3600s]). Throws OAuthError on any failure.
 */
export async function fetchCimdClient(clientIdUrl: string): Promise<ClientRegistration> {
  // Cache hit?
  const cached = cache.get(clientIdUrl);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.client;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(clientIdUrl);
  } catch {
    throw new OAuthError("invalid_client", `client_id is not a valid URL: ${clientIdUrl}`, 400);
  }
  if (parsedUrl.protocol !== "https:") {
    throw new OAuthError("invalid_client", `CIMD client_id URL must use https:// (got ${parsedUrl.protocol})`, 400);
  }
  if (!parsedUrl.pathname || parsedUrl.pathname === "/") {
    throw new OAuthError("invalid_client", `CIMD client_id URL must have a path component`, 400);
  }
  if (isPrivateHostname(parsedUrl.hostname)) {
    throw new OAuthError("invalid_client", `CIMD client_id URL hostname ${parsedUrl.hostname} is in a blocked range`, 400);
  }

  // Fetch + validate, retried on failure. Slow/flaky host egress (observed 4–19s
  // TLS) means a single 5s attempt aborted almost every time; retry with the full
  // timeout each attempt gives the handshake a chance to complete.
  let lastErr: unknown;
  for (let attempt = 0; attempt <= FETCH_RETRIES; attempt++) {
    try {
      const response = await fetch(clientIdUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (response.status !== 200) {
        throw new OAuthError("invalid_client", `CIMD fetch returned HTTP ${response.status}`, 400);
      }
      const contentType = (response.headers.get("content-type") || "").toLowerCase();
      if (!contentType.startsWith("application/json")) {
        throw new OAuthError("invalid_client", `CIMD response Content-Type must be application/json, got "${contentType}"`, 400);
      }

      // Bounded read.
      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > MAX_BODY_BYTES) {
        throw new OAuthError("invalid_client", `CIMD response body exceeds ${MAX_BODY_BYTES} bytes`, 400);
      }
      let json: unknown;
      try {
        json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
      } catch (err) {
        throw new OAuthError("invalid_client", `CIMD body is not valid JSON: ${err instanceof Error ? err.message : String(err)}`, 400);
      }

      const client = parseAndValidateCimdDocument(json, clientIdUrl);
      const ttlSec = parseMaxAgeSec(response.headers.get("cache-control"));
      cache.set(clientIdUrl, { client, expiresAt: Date.now() + ttlSec * 1000 });
      return client;
    } catch (err) {
      lastErr = err;
      // fall through to retry
    }
  }

  // All attempts failed. Serve a stale-but-previously-valid document if we have
  // one — a transient egress hiccup must not tear down an established client.
  if (cached) {
    return cached.client;
  }
  throw new OAuthError(
    "invalid_client",
    `CIMD fetch failed after ${FETCH_RETRIES + 1} attempts: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`,
    400,
  );
}

/** Test-only helper. */
export function _resetCimdCache(): void {
  cache.clear();
}

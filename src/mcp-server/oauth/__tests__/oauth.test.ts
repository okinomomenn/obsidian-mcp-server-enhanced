/**
 * @fileoverview OAuth shim unit tests. Run with:
 *   node --import=tsx --test src/mcp-server/oauth/__tests__/oauth.test.ts
 * or after `npm run build`:
 *   node --test dist/mcp-server/oauth/__tests__/oauth.test.js
 *
 * Focuses on pure logic (PKCE, token store, schemas). HTTP handler integration
 * is intentionally out of scope — those are covered by manual + Stage 5 E2E.
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { afterEach, describe, it } from "node:test";

import { verifyS256Challenge } from "../pkce.js";
import {
  _resetCimdCache,
  isPrivateHostname,
  isUrlClientId,
  parseAndValidateCimdDocument,
} from "../cimd.js";
import {
  _resetClientStore,
  createClient,
  getClient,
  isRegisteredRedirectUri,
  resolveClient,
} from "../clientStore.js";
import {
  _resetTokenStore,
  consumeCode,
  issueAccessToken,
  issueCode,
  issueRefreshToken,
  rotateRefreshToken,
  verifyAccessToken,
} from "../tokenStore.js";
import {
  AuthorizeRequestSchema,
  OAuthError,
  RegisterRequestSchema,
  TokenAuthCodeRequestSchema,
  TokenRefreshRequestSchema,
} from "../types.js";

const SECRET = "x".repeat(48);
const ISSUER = "https://example.test";
const AUDIENCE = "https://example.test/mcp";
const RESOURCE = AUDIENCE;

afterEach(() => {
  _resetClientStore();
  _resetTokenStore();
  _resetCimdCache();
});

describe("pkce.verifyS256Challenge", () => {
  it("accepts matching verifier+challenge pair", () => {
    const verifier = randomBytes(48).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest().toString("base64url");
    assert.equal(verifyS256Challenge(verifier, challenge), true);
  });

  it("rejects wrong verifier", () => {
    const verifier = randomBytes(48).toString("base64url");
    const challenge = createHash("sha256").update("different").digest().toString("base64url");
    assert.equal(verifyS256Challenge(verifier, challenge), false);
  });

  it("rejects length-mismatched challenge", () => {
    assert.equal(verifyS256Challenge("v", "short"), false);
  });
});

describe("clientStore", () => {
  it("issues a UUID client_id and stores metadata", () => {
    const c = createClient({ clientName: "Test", redirectUris: ["https://app.test/cb"] });
    assert.match(c.clientId, /^[0-9a-f-]{36}$/);
    assert.equal(c.tokenEndpointAuthMethod, "none");
    assert.equal(c.source, "dcr");
    assert.deepEqual(getClient(c.clientId)?.redirectUris, ["https://app.test/cb"]);
  });

  it("isRegisteredRedirectUri requires exact match", () => {
    const c = createClient({ redirectUris: ["https://app.test/cb"] });
    assert.equal(isRegisteredRedirectUri(c, "https://app.test/cb"), true);
    assert.equal(isRegisteredRedirectUri(c, "https://app.test/cb/"), false);
    assert.equal(isRegisteredRedirectUri(c, "https://APP.test/cb"), false);
  });

  it("resolveClient returns DCR client for UUID and throws for unknown", async () => {
    const c = createClient({ redirectUris: ["https://app.test/cb"] });
    const resolved = await resolveClient(c.clientId);
    assert.equal(resolved.clientId, c.clientId);
    await assert.rejects(resolveClient("not-registered"), (e: unknown) =>
      e instanceof OAuthError && e.code === "invalid_request",
    );
  });
});

describe("cimd — URL detection", () => {
  it("isUrlClientId matches https URLs", () => {
    assert.equal(isUrlClientId("https://claude.ai/oauth/mcp-oauth-client-metadata"), true);
    assert.equal(isUrlClientId("HTTPS://example.test/x.json"), true);
  });
  it("isUrlClientId rejects non-URL and http://", () => {
    assert.equal(isUrlClientId("7dc0fa8c-d028-453c-bf8a-10db41c0ce3c"), false);
    assert.equal(isUrlClientId("http://example.test/x.json"), false);
    assert.equal(isUrlClientId(""), false);
  });
});

describe("cimd — SSRF guard (isPrivateHostname)", () => {
  it("blocks loopback names and literals", () => {
    assert.equal(isPrivateHostname("localhost"), true);
    assert.equal(isPrivateHostname("127.0.0.1"), true);
    assert.equal(isPrivateHostname("127.250.99.7"), true);
    assert.equal(isPrivateHostname("::1"), true);
    assert.equal(isPrivateHostname("[::1]"), true);
  });
  it("blocks RFC1918 private ranges", () => {
    assert.equal(isPrivateHostname("10.0.0.1"), true);
    assert.equal(isPrivateHostname("172.16.5.5"), true);
    assert.equal(isPrivateHostname("172.31.255.255"), true);
    assert.equal(isPrivateHostname("192.168.1.1"), true);
  });
  it("blocks link-local + CGNAT + 0.x", () => {
    assert.equal(isPrivateHostname("169.254.169.254"), true); // AWS metadata
    assert.equal(isPrivateHostname("100.64.0.1"), true);
    assert.equal(isPrivateHostname("0.0.0.0"), true);
  });
  it("blocks IPv6 unique-local + link-local", () => {
    assert.equal(isPrivateHostname("fe80::1"), true);
    assert.equal(isPrivateHostname("fc00::1"), true);
    assert.equal(isPrivateHostname("fd12:3456:789a::1"), true);
  });
  it("allows public hostnames + public IPv4 literals", () => {
    assert.equal(isPrivateHostname("claude.ai"), false);
    assert.equal(isPrivateHostname("example.com"), false);
    assert.equal(isPrivateHostname("8.8.8.8"), false);
    assert.equal(isPrivateHostname("1.1.1.1"), false);
    assert.equal(isPrivateHostname("172.32.0.1"), false); // just outside 172.16/12
  });
});

describe("cimd — parseAndValidateCimdDocument", () => {
  const URL_OK = "https://claude.ai/oauth/mcp-oauth-client-metadata";

  it("accepts the real Claude.ai CIMD shape", () => {
    const doc = {
      client_id: URL_OK,
      client_name: "Claude",
      client_uri: "https://claude.ai",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    };
    const c = parseAndValidateCimdDocument(doc, URL_OK);
    assert.equal(c.clientId, URL_OK);
    assert.equal(c.clientName, "Claude");
    assert.equal(c.source, "cimd");
    assert.deepEqual(c.redirectUris, ["https://claude.ai/api/mcp/auth_callback"]);
  });

  it("rejects client_id mismatch", () => {
    assert.throws(
      () => parseAndValidateCimdDocument({ client_id: "https://other.example/x.json", redirect_uris: ["https://x/y"] }, URL_OK),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_client" && /does not match/.test(e.description),
    );
  });

  it("rejects missing or empty redirect_uris", () => {
    assert.throws(() => parseAndValidateCimdDocument({ client_id: URL_OK }, URL_OK));
    assert.throws(() => parseAndValidateCimdDocument({ client_id: URL_OK, redirect_uris: [] }, URL_OK));
  });

  it("rejects http:// redirect_uri to non-loopback", () => {
    assert.throws(
      () => parseAndValidateCimdDocument({ client_id: URL_OK, redirect_uris: ["http://evil.example/cb"] }, URL_OK),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_client",
    );
  });

  it("accepts http://localhost and http://127.0.0.1 redirect_uri", () => {
    assert.doesNotThrow(() => parseAndValidateCimdDocument({ client_id: URL_OK, redirect_uris: ["http://localhost:9000/cb"] }, URL_OK));
    assert.doesNotThrow(() => parseAndValidateCimdDocument({ client_id: URL_OK, redirect_uris: ["http://127.0.0.1:9000/cb"] }, URL_OK));
  });

  it("rejects non-none token_endpoint_auth_method", () => {
    assert.throws(
      () => parseAndValidateCimdDocument({
        client_id: URL_OK,
        redirect_uris: ["https://app/cb"],
        token_endpoint_auth_method: "client_secret_basic",
      }, URL_OK),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_client",
    );
  });

  it("rejects non-object / null / array input", () => {
    assert.throws(() => parseAndValidateCimdDocument(null, URL_OK));
    assert.throws(() => parseAndValidateCimdDocument([], URL_OK));
    assert.throws(() => parseAndValidateCimdDocument("string", URL_OK));
  });
});

describe("tokenStore — authorization codes", () => {
  it("issued code is single-use", () => {
    const c = issueCode({
      clientId: "c1",
      redirectUri: "https://app/cb",
      codeChallenge: "x",
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 60,
    });
    const first = consumeCode(c.code);
    assert.equal(first.consumed, true);
    assert.throws(() => consumeCode(c.code), (e: unknown) =>
      e instanceof OAuthError && e.code === "invalid_grant",
    );
  });

  it("expired code is rejected", () => {
    const c = issueCode({
      clientId: "c1",
      redirectUri: "https://app/cb",
      codeChallenge: "x",
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: -1,
    });
    assert.throws(() => consumeCode(c.code));
  });
});

describe("tokenStore — JWT access tokens", () => {
  it("round-trips access token with correct claims", async () => {
    const issued = await issueAccessToken({
      secret: SECRET,
      issuer: ISSUER,
      audience: AUDIENCE,
      clientId: "client-abc",
      scope: "mcp",
      ttlSec: 60,
    });
    const claims = await verifyAccessToken({
      secret: SECRET,
      issuer: ISSUER,
      audience: AUDIENCE,
      token: issued.token,
    });
    assert.equal(claims.sub, "client-abc");
    assert.equal(claims.client_id, "client-abc");
    assert.equal(claims.scope, "mcp");
    assert.equal(claims.iss, ISSUER);
    assert.equal(claims.aud, AUDIENCE);
  });

  it("rejects token signed with different secret", async () => {
    const issued = await issueAccessToken({
      secret: SECRET,
      issuer: ISSUER,
      audience: AUDIENCE,
      clientId: "c",
      scope: "mcp",
      ttlSec: 60,
    });
    await assert.rejects(
      verifyAccessToken({
        secret: "y".repeat(48),
        issuer: ISSUER,
        audience: AUDIENCE,
        token: issued.token,
      }),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_token",
    );
  });

  it("rejects token with wrong audience", async () => {
    const issued = await issueAccessToken({
      secret: SECRET,
      issuer: ISSUER,
      audience: AUDIENCE,
      clientId: "c",
      scope: "mcp",
      ttlSec: 60,
    });
    await assert.rejects(
      verifyAccessToken({
        secret: SECRET,
        issuer: ISSUER,
        audience: "https://other.example/mcp",
        token: issued.token,
      }),
    );
  });
});

describe("tokenStore — refresh rotation", () => {
  it("rotates refresh token and invalidates the old one", () => {
    const rt = issueRefreshToken({ clientId: "c1", resource: RESOURCE, scope: "mcp", ttlSec: 60 });
    const rotated = rotateRefreshToken(rt.token, "c1");
    assert.equal(rotated.clientId, "c1");
    assert.throws(() => rotateRefreshToken(rt.token, "c1"));
  });

  it("rejects rotation by a different client_id", () => {
    const rt = issueRefreshToken({ clientId: "c1", resource: RESOURCE, scope: "mcp", ttlSec: 60 });
    assert.throws(() => rotateRefreshToken(rt.token, "c2"));
  });
});

describe("schemas — request body validation", () => {
  it("RegisterRequestSchema requires at least one redirect_uri", () => {
    assert.equal(RegisterRequestSchema.safeParse({ redirect_uris: [] }).success, false);
    assert.equal(
      RegisterRequestSchema.safeParse({ redirect_uris: ["https://app.test/cb"] }).success,
      true,
    );
  });

  it("AuthorizeRequestSchema rejects non-S256 method", () => {
    const base = {
      response_type: "code",
      client_id: "c",
      redirect_uri: "https://app/cb",
      code_challenge: "x".repeat(43),
      code_challenge_method: "plain",
      state: "s",
      resource: "https://app/mcp",
    };
    assert.equal(AuthorizeRequestSchema.safeParse(base).success, false);
  });

  it("TokenAuthCodeRequestSchema requires code_verifier in length range", () => {
    assert.equal(
      TokenAuthCodeRequestSchema.safeParse({
        grant_type: "authorization_code",
        code: "abc",
        redirect_uri: "https://app/cb",
        client_id: "c",
        code_verifier: "short",
        resource: "https://app/mcp",
      }).success,
      false,
    );
  });

  it("TokenRefreshRequestSchema validates required fields", () => {
    assert.equal(
      TokenRefreshRequestSchema.safeParse({
        grant_type: "refresh_token",
        refresh_token: "rt",
        client_id: "c",
        resource: "https://app/mcp",
      }).success,
      true,
    );
  });
});

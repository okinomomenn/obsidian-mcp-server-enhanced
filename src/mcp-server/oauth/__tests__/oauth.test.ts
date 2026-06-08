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
  _resetClientStore,
  createClient,
  getClient,
  isRegisteredRedirectUri,
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
    assert.deepEqual(getClient(c.clientId)?.redirectUris, ["https://app.test/cb"]);
  });

  it("isRegisteredRedirectUri requires exact match", () => {
    const c = createClient({ redirectUris: ["https://app.test/cb"] });
    assert.equal(isRegisteredRedirectUri(c, "https://app.test/cb"), true);
    assert.equal(isRegisteredRedirectUri(c, "https://app.test/cb/"), false);
    assert.equal(isRegisteredRedirectUri(c, "https://APP.test/cb"), false);
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

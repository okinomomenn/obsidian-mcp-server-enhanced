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
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { after, afterEach, describe, it } from "node:test";

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
import { _closeDatabase, _useDatabaseAt, getDb } from "../db.js";
import { handleRegister } from "../register.js";
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

/**
 * The stores are SQLite-backed as of v1.1. Point them at a throwaway file before
 * any test runs — module-level so it happens at import time, ahead of the suites.
 */
const TMP_DIR = mkdtempSync(nodePath.join(tmpdir(), "obsmcp-oauth-test-"));
const DB_FILE = nodePath.join(TMP_DIR, "oauth.db");
_useDatabaseAt(DB_FILE);

after(() => {
  _closeDatabase();
  rmSync(TMP_DIR, { recursive: true, force: true });
});

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

  // Regression: claude.ai omits `resource` on /token. RFC 8707 §2.2 makes it
  // OPTIONAL there (the resource bound at /authorize is authoritative). Requiring
  // it produced invalid_request 400 and broke the connector handshake.
  it("TokenAuthCodeRequestSchema accepts a request with no resource", () => {
    assert.equal(
      TokenAuthCodeRequestSchema.safeParse({
        grant_type: "authorization_code",
        code: "abc",
        redirect_uri: "https://app/cb",
        client_id: "c",
        code_verifier: "a".repeat(43),
      }).success,
      true,
    );
  });

  it("TokenRefreshRequestSchema accepts a request with no resource", () => {
    assert.equal(
      TokenRefreshRequestSchema.safeParse({
        grant_type: "refresh_token",
        refresh_token: "rt",
        client_id: "c",
      }).success,
      true,
    );
  });

  it("TokenAuthCodeRequestSchema still rejects a malformed resource when present", () => {
    assert.equal(
      TokenAuthCodeRequestSchema.safeParse({
        grant_type: "authorization_code",
        code: "abc",
        redirect_uri: "https://app/cb",
        client_id: "c",
        code_verifier: "a".repeat(43),
        resource: "not-a-url",
      }).success,
      false,
    );
  });
});

/**
 * The reason this feature exists. Before v1.1 the stores were process-local Maps,
 * so a restart destroyed every registration and refresh token. Closing the handle
 * and reopening the same file is a faithful stand-in for a process restart: the
 * module state is rebuilt from disk exactly as it would be on boot.
 */
describe("persistence across a restart", () => {
  it("keeps a DCR client, and its client_id is unchanged", () => {
    const before = createClient({
      clientName: "Restart Survivor",
      redirectUris: ["https://app.test/cb"],
    });

    _closeDatabase();
    _useDatabaseAt(DB_FILE);

    const after_ = getClient(before.clientId);
    assert.ok(after_, "client vanished across restart");
    assert.equal(after_.clientId, before.clientId);
    assert.equal(after_.clientName, "Restart Survivor");
    assert.deepEqual(after_.redirectUris, ["https://app.test/cb"]);
    assert.equal(after_.createdAt, before.createdAt);
  });

  it("keeps a refresh token usable, so no re-consent is needed", () => {
    const c = createClient({ redirectUris: ["https://app.test/cb"] });
    const rt = issueRefreshToken({
      clientId: c.clientId,
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 3600,
    });

    _closeDatabase();
    _useDatabaseAt(DB_FILE);

    const rotated = rotateRefreshToken(rt.token, c.clientId);
    assert.equal(rotated.clientId, c.clientId);
    assert.equal(rotated.resource, RESOURCE);
    // Rotation is single-use: the same token must not survive a second exchange.
    assert.throws(
      () => rotateRefreshToken(rt.token, c.clientId),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
    );
  });

  it("keeps an authorization code, including its consumed flag", () => {
    const c = createClient({ redirectUris: ["https://app.test/cb"] });
    const code = issueCode({
      clientId: c.clientId,
      redirectUri: "https://app.test/cb",
      codeChallenge: "a".repeat(43),
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 600,
    });
    consumeCode(code.code);

    _closeDatabase();
    _useDatabaseAt(DB_FILE);

    // Replay protection must not be forgotten by a restart.
    assert.throws(
      () => consumeCode(code.code),
      (e: unknown) => e instanceof OAuthError && e.code === "invalid_grant",
    );
  });

  it("rejects a NULL primary key (TEXT PRIMARY KEY alone would not)", () => {
    const db = getDb();
    assert.throws(() =>
      db
        .prepare(
          `INSERT INTO clients
             (client_id, client_name, redirect_uris, created_at, token_endpoint_auth_method, source)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(null, "n", "[]", Date.now(), "none", "dcr"),
    );
  });
});

/** Minimal ServerResponse stand-in — handleRegister only needs writeHead/end. */
function mockRes() {
  const captured: { status?: number; body?: string } = {};
  return {
    res: {
      writeHead(status: number) {
        captured.status = status;
        return this;
      },
      end(body?: string) {
        captured.body = body;
        return this;
      },
    } as unknown as import("http").ServerResponse,
    captured,
  };
}

const postReq = { method: "POST" } as import("http").IncomingMessage;

describe("register — malformed body handling", () => {
  it("maps invalid JSON to 400 invalid_client_metadata, not 500", async () => {
    const { res } = mockRes();
    // parseJsonBody raises SyntaxError for a malformed body; previously this
    // escaped to the router's generic catch and surfaced as 500 server_error,
    // pointing the caller at the server when the fault was in the request.
    const parseJsonBody = () =>
      Promise.reject(new SyntaxError("Unexpected token } in JSON at position 4"));

    await assert.rejects(
      handleRegister(postReq, res, parseJsonBody),
      (e: unknown) =>
        e instanceof OAuthError &&
        e.code === "invalid_client_metadata" &&
        e.httpStatus === 400,
    );
  });

  it("still registers a well-formed body (no regression)", async () => {
    const { res, captured } = mockRes();
    const parseJsonBody = () =>
      Promise.resolve({
        redirect_uris: ["https://app.test/cb"],
        client_name: "Good Client",
      });

    await handleRegister(postReq, res, parseJsonBody);

    assert.equal(captured.status, 201);
    const payload = JSON.parse(captured.body ?? "{}");
    assert.match(payload.client_id, /^[0-9a-f-]{36}$/);
    assert.equal(payload.client_name, "Good Client");
    assert.deepEqual(payload.redirect_uris, ["https://app.test/cb"]);
    assert.equal(payload.token_endpoint_auth_method, "none");
    // And it is actually persisted, not just echoed back.
    assert.equal(getClient(payload.client_id)?.clientName, "Good Client");
  });
});

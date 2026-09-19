/**
 * @fileoverview private_key_jwt (RFC 7523 §2.2) client authentication tests.
 *   node --import=tsx --test src/mcp-server/oauth/__tests__/privateKeyJwt.test.ts
 *
 * Covers the four rejection modes the feature exists to enforce — wrong key, wrong
 * audience, expired assertion, replayed jti — plus a full /token exchange with a
 * valid assertion, driven through handleToken so the 200 is the real response.
 *
 * No network: the CIMD document is seeded into the cache with an inline JWK Set,
 * which is the same shape a successful fetch would have produced.
 */

import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { after, afterEach, before, describe, it } from "node:test";
import type { IncomingMessage, ServerResponse } from "node:http";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import { _primeCimdCache, _resetCimdCache, parseAndValidateCimdDocument } from "../cimd.js";
import { CLIENT_ASSERTION_TYPE, _resetClientAssertionState } from "../clientAssertion.js";
import { _resetClientStore } from "../clientStore.js";
import { _closeDatabase, _useDatabaseAt } from "../db.js";
import { handleToken, type TokenDeps } from "../token.js";
import { _resetTokenStore, issueCode, issueRefreshToken } from "../tokenStore.js";
import { OAuthError, type ClientRegistration, type JsonWebKeySet } from "../types.js";

/** jose does not re-export the key type; take it from generateKeyPair. */
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

const SECRET = "x".repeat(48);
const ISSUER = "https://example.test";
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const RESOURCE = `${ISSUER}/mcp`;
const CLIENT_ID = "https://client.test/oauth/client.json";
const REDIRECT_URI = "https://client.test/callback";

const DEPS: TokenDeps = {
  jwtSecret: SECRET,
  issuerUrl: ISSUER,
  audience: RESOURCE,
  tokenEndpoint: TOKEN_ENDPOINT,
  accessTtlSec: 3600,
  refreshTtlSec: 86_400,
};

const TMP_DIR = mkdtempSync(nodePath.join(tmpdir(), "obsmcp-pkjwt-test-"));
_useDatabaseAt(nodePath.join(TMP_DIR, "oauth.db"));

after(() => {
  _closeDatabase();
  rmSync(TMP_DIR, { recursive: true, force: true });
});

afterEach(() => {
  _resetClientStore();
  _resetTokenStore();
  _resetCimdCache();
  _resetClientAssertionState();
});

/* ---------- helpers ---------- */

let signingKey: SigningKey;
let publicJwk: Record<string, unknown>;
/** A structurally valid key that is NOT the one in the client's published JWK Set. */
let foreignKey: SigningKey;
/** The foreign key's public half — used to build an ambiguous two-key JWK Set. */
let foreignPublicJwk: Record<string, unknown>;

before(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  signingKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), alg: "RS256", use: "sig", kid: "test-1" };
  const other = await generateKeyPair("RS256", { extractable: true });
  foreignKey = other.privateKey;
  foreignPublicJwk = { ...(await exportJWK(other.publicKey)), alg: "RS256", use: "sig", kid: "test-2" };
});

function client(overrides: Partial<ClientRegistration> = {}): ClientRegistration {
  return {
    clientId: CLIENT_ID,
    clientName: "Test Client",
    redirectUris: [REDIRECT_URI],
    createdAt: Date.now(),
    tokenEndpointAuthMethod: "private_key_jwt",
    source: "cimd",
    jwks: { keys: [publicJwk] } as JsonWebKeySet,
    ...overrides,
  };
}

interface AssertionOverrides {
  key?: SigningKey;
  aud?: string;
  iss?: string;
  sub?: string;
  jti?: string;
  expSecondsFromNow?: number;
}

async function makeAssertion(o: AssertionOverrides = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid: "test-1" })
    .setIssuer(o.iss ?? CLIENT_ID)
    .setSubject(o.sub ?? CLIENT_ID)
    .setAudience(o.aud ?? TOKEN_ENDPOINT)
    .setJti(o.jti ?? randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + (o.expSecondsFromNow ?? 300))
    .sign(o.key ?? signingKey);
}

/** Minimal ServerResponse stand-in that records what handleToken wrote. */
function fakeRes() {
  const rec = { status: 0, headers: {} as Record<string, string>, body: "", headersSent: false };
  const res = {
    get headersSent() {
      return rec.headersSent;
    },
    writeHead(status: number, headers?: Record<string, string>) {
      rec.status = status;
      rec.headers = headers ?? {};
      rec.headersSent = true;
      return res;
    },
    end(chunk?: string) {
      if (chunk) rec.body = chunk;
      return res;
    },
  };
  return { res: res as unknown as ServerResponse, rec };
}

const POST_FORM = {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
} as unknown as IncomingMessage;

/** Issue a code bound to private_key_jwt and return {code, verifier}. */
function bindCode() {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest().toString("base64url");
  const code = issueCode({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeChallenge: challenge,
    resource: RESOURCE,
    scope: "mcp",
    ttlSec: 60,
    clientAuthMethod: "private_key_jwt",
  });
  return { code: code.code, verifier };
}

/**
 * Drive handleToken and record the response. handleToken throws OAuthError rather
 * than writing the error itself — router.ts owns that — so this mirrors what
 * router.ts's writeOAuthError does, making rec.status the status a client sees.
 */
async function postToken(form: Record<string, string>) {
  const { res, rec } = fakeRes();
  try {
    await handleToken(POST_FORM, res, async () => form, DEPS);
  } catch (err) {
    if (!(err instanceof OAuthError)) throw err;
    res.writeHead(err.httpStatus, { "Content-Type": "application/json" });
    res.end(JSON.stringify(err.toJSON()));
  }
  return rec;
}

/** Run a full authorization_code exchange, returning the recorded response. */
async function exchange(assertionOverrides: AssertionOverrides = {}, extra: Record<string, string> = {}) {
  _primeCimdCache(CLIENT_ID, client());
  const { code, verifier } = bindCode();
  return postToken({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await makeAssertion(assertionOverrides),
    ...extra,
  });
}

/* ---------- CIMD document parsing ---------- */

describe("cimd: private_key_jwt document validation", () => {
  const base = {
    client_id: CLIENT_ID,
    redirect_uris: [REDIRECT_URI],
    client_name: "Test Client",
  };

  it("accepts private_key_jwt with jwks_uri and records it", () => {
    const reg = parseAndValidateCimdDocument(
      { ...base, token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://client.test/jwks.json", token_endpoint_auth_signing_alg: "RS256" },
      CLIENT_ID,
    );
    assert.equal(reg.tokenEndpointAuthMethod, "private_key_jwt");
    assert.equal(reg.jwksUri, "https://client.test/jwks.json");
    assert.equal(reg.tokenEndpointAuthSigningAlg, "RS256");
  });

  it("rejects private_key_jwt with no key material", () => {
    assert.throws(
      () => parseAndValidateCimdDocument({ ...base, token_endpoint_auth_method: "private_key_jwt" }, CLIENT_ID),
      /requires "jwks" or "jwks_uri"/,
    );
  });

  it("rejects a jwks_uri pointing at a private address", () => {
    assert.throws(
      () =>
        parseAndValidateCimdDocument(
          { ...base, token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://127.0.0.1/jwks.json" },
          CLIENT_ID,
        ),
      /blocked range/,
    );
  });

  it("still rejects any other auth method", () => {
    assert.throws(
      () => parseAndValidateCimdDocument({ ...base, token_endpoint_auth_method: "client_secret_basic" }, CLIENT_ID),
      /must be "none" or "private_key_jwt"/,
    );
  });

  it("leaves the public-client path unchanged", () => {
    const reg = parseAndValidateCimdDocument({ ...base, token_endpoint_auth_method: "none" }, CLIENT_ID);
    assert.equal(reg.tokenEndpointAuthMethod, "none");
    assert.equal(reg.jwks, undefined);
    assert.equal(reg.jwksUri, undefined);
  });
});

/* ---------- the four rejection modes ---------- */

describe("private_key_jwt: /token rejects a bad assertion", () => {
  it("1. signature from a key the client does not publish → 401", async () => {
    const rec = await exchange({ key: foreignKey });
    assert.equal(rec.status, 401);
    assert.equal(JSON.parse(rec.body).error, "invalid_client");
  });

  it("2. aud is not this token endpoint → 401", async () => {
    const rec = await exchange({ aud: "https://evil.test/token" });
    assert.equal(rec.status, 401);
    assert.equal(JSON.parse(rec.body).error, "invalid_client");
  });

  it("3. expired assertion → 401", async () => {
    // Beyond the 60s clock tolerance.
    const rec = await exchange({ expSecondsFromNow: -120 });
    assert.equal(rec.status, 401);
    assert.equal(JSON.parse(rec.body).error, "invalid_client");
  });

  it("4. replayed jti → first 200, second 401", async () => {
    _primeCimdCache(CLIENT_ID, client());
    const jti = randomUUID();
    const assertion = await makeAssertion({ jti });

    const first = bindCode();
    const ok = await postToken({
      grant_type: "authorization_code",
      code: first.code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: first.verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
    });
    assert.equal(ok.status, 200);

    const second = bindCode();
    const replay = await postToken({
      grant_type: "authorization_code",
      code: second.code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: second.verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
    });
    assert.equal(replay.status, 401);
    assert.match(JSON.parse(replay.body).error_description, /jti has already been used/);
  });

  it("omitting the assertion entirely does not downgrade to the public path", async () => {
    _primeCimdCache(CLIENT_ID, client());
    const { code, verifier } = bindCode();
    const rec = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
    });
    assert.equal(rec.status, 401);
    assert.match(JSON.parse(rec.body).error_description, /client_assertion is required/);
  });

  it("iss/sub that are not the client_id → 401", async () => {
    const rec = await exchange({ iss: "https://someone.else/client.json" });
    assert.equal(rec.status, 401);
  });

  it("a failed assertion does not burn the authorization code", async () => {
    _primeCimdCache(CLIENT_ID, client());
    const { code, verifier } = bindCode();
    const bad = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await makeAssertion({ key: foreignKey }),
    });
    assert.equal(bad.status, 401);

    const good = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await makeAssertion(),
    });
    assert.equal(good.status, 200);
  });
});

/* ---------- the happy path ---------- */

describe("private_key_jwt: /token accepts a valid assertion", () => {
  it("authorization_code exchange returns 200 with a token set", async () => {
    const rec = await exchange();
    assert.equal(rec.status, 200);
    const body = JSON.parse(rec.body);
    assert.equal(body.token_type, "Bearer");
    assert.equal(body.scope, "mcp");
    assert.ok(body.access_token.length > 0);
    assert.ok(body.refresh_token.length > 0);
    assert.equal(rec.headers["Cache-Control"], "no-store");
  });

  it("the refresh token it issues still demands an assertion", async () => {
    _primeCimdCache(CLIENT_ID, client());
    const first = await exchange();
    const refreshToken = JSON.parse(first.body).refresh_token as string;

    const naked = await postToken({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });
    assert.equal(naked.status, 401);

    // ...and the rejected attempt did not destroy the refresh token.
    const ok = await postToken({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await makeAssertion(),
    });
    assert.equal(ok.status, 200);
  });

  it("rejects a wrong client_assertion_type", async () => {
    const rec = await exchange({}, { client_assertion_type: "urn:example:not-jwt-bearer" });
    assert.equal(rec.status, 401);
    assert.match(JSON.parse(rec.body).error_description, /client_assertion_type must be/);
  });
});

/* ---------- ambiguous key sets ---------- */

describe("private_key_jwt: a multi-key JWK Set", () => {
  /** Sign without a kid header, the case jose's resolver refuses to disambiguate. */
  async function kidlessAssertion(key: SigningKey, jti = randomUUID()): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(CLIENT_ID)
      .setSubject(CLIENT_ID)
      .setAudience(TOKEN_ENDPOINT)
      .setJti(jti)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(key);
  }

  /**
   * ChatGPT publishes two RS256 keys. Before the per-key fallback a kid-less
   * assertion failed with "multiple matching keys" even when the signature was
   * genuine — observed live against https://chatgpt.com/oauth/jwks.json.
   */
  it("accepts a kid-less assertion signed by any published key", async () => {
    _primeCimdCache(CLIENT_ID, client({ jwks: { keys: [publicJwk, foreignPublicJwk] } }));
    const { code, verifier } = bindCode();
    const rec = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await kidlessAssertion(signingKey),
    });
    assert.equal(rec.status, 200);
  });

  it("still rejects a kid-less assertion signed by an unpublished key", async () => {
    const stranger = (await generateKeyPair("RS256", { extractable: true })).privateKey;
    _primeCimdCache(CLIENT_ID, client({ jwks: { keys: [publicJwk, foreignPublicJwk] } }));
    const { code, verifier } = bindCode();
    const rec = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await kidlessAssertion(stranger),
    });
    assert.equal(rec.status, 401);
  });

  it("the per-key fallback does not bypass the aud check", async () => {
    _primeCimdCache(CLIENT_ID, client({ jwks: { keys: [publicJwk, foreignPublicJwk] } }));
    const { code, verifier } = bindCode();
    const now = Math.floor(Date.now() / 1000);
    const wrongAud = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(CLIENT_ID)
      .setSubject(CLIENT_ID)
      .setAudience("https://evil.test/token")
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signingKey);
    const rec = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: wrongAud,
    });
    assert.equal(rec.status, 401);
  });
});

/* ---------- the untouched public-client path ---------- */

describe('the "none" path is unchanged', () => {
  it("a public client exchanges a code with no assertion and no client lookup", async () => {
    const verifier = randomBytes(48).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest().toString("base64url");
    const code = issueCode({
      clientId: "dcr-client-uuid",
      redirectUri: REDIRECT_URI,
      codeChallenge: challenge,
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 60,
    });
    const rec = await postToken({
      grant_type: "authorization_code",
      code: code.code,
      redirect_uri: REDIRECT_URI,
      client_id: "dcr-client-uuid",
      code_verifier: verifier,
    });
    assert.equal(rec.status, 200);
  });

  it("a public client refreshes with no assertion", async () => {
    const rt = issueRefreshToken({
      clientId: "dcr-client-uuid",
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 3600,
    });
    const rec = await postToken({
      grant_type: "refresh_token",
      refresh_token: rt.token,
      client_id: "dcr-client-uuid",
    });
    assert.equal(rec.status, 200);
  });

  it("an unbound (pre-migration) grant defaults to the public path", async () => {
    // Simulates a row written before client_auth_method existed: the column default
    // is 'none', so the exchange must behave exactly as it did before.
    const rt = issueRefreshToken({
      clientId: "legacy-client",
      resource: RESOURCE,
      scope: "mcp",
      ttlSec: 3600,
    });
    assert.equal(rt.clientAuthMethod, "none");
    const rec = await postToken({
      grant_type: "refresh_token",
      refresh_token: rt.token,
      client_id: "legacy-client",
    });
    assert.equal(rec.status, 200);
  });
});

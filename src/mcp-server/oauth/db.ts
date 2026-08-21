/**
 * @fileoverview SQLite persistence for the OAuth shim (v1.1).
 *
 * Backs clientStore (DCR registrations) and tokenStore (authorization codes,
 * refresh tokens). Before v1.1 these lived in process-local `Map`s, so every
 * service restart destroyed them: the connector's client_id and refresh token
 * vanished and only the self-contained access token survived until its TTL
 * expired, after which no automatic recovery path existed.
 *
 * Uses Node's built-in `node:sqlite` (Node >= 22.5). Deliberately no native
 * dependency — nothing to rebuild when Node is upgraded.
 *
 * NOT persisted:
 *   - Access tokens: self-contained HS256 JWTs, verified statelessly against a
 *     secret that already survives restarts (.env). Nothing to store.
 *   - CIMD client cache (cimd.ts): re-fetchable from its source URL and has its
 *     own TTL/stale handling. Persisting it would cache remote state we do not own.
 *
 * TIME UNIT: every `*_at` column is an INTEGER epoch in **milliseconds**,
 * matching `Date.now()` as used throughout the OAuth layer. Do not mix seconds
 * in — the JWT layer speaks seconds, this layer speaks milliseconds, and the
 * conversion belongs at the JWT boundary (tokenStore.issueAccessToken).
 */

import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * Schema. TEXT primary keys carry an explicit NOT NULL: SQLite permits NULL in a
 * TEXT PRIMARY KEY (a long-standing quirk retained for backwards compatibility),
 * so `PRIMARY KEY` alone would not reject a NULL client_id / token / code.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id                  TEXT PRIMARY KEY NOT NULL,
  client_name                TEXT NOT NULL,
  redirect_uris              TEXT NOT NULL,
  created_at                 INTEGER NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  source                     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token      TEXT PRIMARY KEY NOT NULL,
  client_id  TEXT NOT NULL,
  resource   TEXT NOT NULL,
  scope      TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS codes (
  code           TEXT PRIMARY KEY NOT NULL,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource       TEXT NOT NULL,
  scope          TEXT NOT NULL,
  expires_at     INTEGER NOT NULL,
  consumed       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id  ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_codes_expires_at          ON codes(expires_at);
`;

let db: DatabaseSync | null = null;
let configDbPath: string | undefined;

/**
 * Injected from the composition root rather than read from `src/config` directly:
 * that module has import-time side effects (it can `process.exit` on an invalid
 * logs dir), and db.ts must stay importable from unit tests.
 */
export function configureDatabasePath(dbPath: string): void {
  configDbPath = dbPath;
}

/** Resolved lazily so importing this module never touches the filesystem. */
function resolveDbPath(): string {
  return configDbPath ?? process.env.MCP_OAUTH_DB_PATH ?? "";
}

function open(dbPath: string): DatabaseSync {
  // The DB deliberately lives outside the project tree in production
  // (D:\SYRINX-Data\...), so it is NOT routed through config's ensureDirectory,
  // which confines paths to the project root.
  mkdirSync(path.dirname(dbPath), { recursive: true });
  const handle = new DatabaseSync(dbPath);
  // WAL survives an abrupt process kill (NSSM stop) far better than the default
  // rollback journal, which is the exact failure mode this feature exists to fix.
  handle.exec("PRAGMA journal_mode = WAL");
  handle.exec("PRAGMA foreign_keys = ON");
  handle.exec(SCHEMA);
  return handle;
}

/** Lazily opens (and migrates) the database on first use. */
export function getDb(): DatabaseSync {
  if (db) return db;
  const dbPath = resolveDbPath();
  if (!dbPath) {
    throw new Error(
      "OAuth database path is not configured. Set MCP_OAUTH_DB_PATH or call configureDatabasePath().",
    );
  }
  db = open(dbPath);
  return db;
}

/* ---------- Test-only helpers ---------- */

/**
 * Point the store at a specific file and reopen. Combined with `_closeDatabase()`
 * this simulates a process restart within a single test run: close the handle,
 * reopen the same path, and assert the rows are still there.
 */
export function _useDatabaseAt(dbPath: string): void {
  _closeDatabase();
  configDbPath = dbPath;
  db = open(dbPath);
}

export function _closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

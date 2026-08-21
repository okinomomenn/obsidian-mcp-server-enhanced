/**
 * @fileoverview Registry for OAuth clients.
 *
 *   - DCR (RFC 7591) clients: created on POST /register, persisted in SQLite
 *     (v1.1). Before v1.1 these lived in a process-local Map and every restart
 *     forced the connector to re-register and the user to re-consent.
 *
 *   - CIMD clients: fetched on demand from the URL given as client_id
 *     (draft-ietf-oauth-client-id-metadata-document-00). Validation + caching
 *     lives in cimd.ts and stays in-memory: it is a cache of state we do not own.
 *
 * resolveClient() is the unified entry point for handlers and dispatches
 * based on whether the client_id is a URL.
 */

import { randomUUID } from "node:crypto";
import { fetchCimdClient, isUrlClientId } from "./cimd.js";
import { getDb } from "./db.js";
import { OAuthError, type ClientRegistration } from "./types.js";

/** Row shape as stored; redirect_uris is a JSON array, created_at epoch ms. */
interface ClientRow {
  client_id: string;
  client_name: string;
  redirect_uris: string;
  created_at: number;
  token_endpoint_auth_method: string;
  source: string;
}

function toRegistration(row: ClientRow): ClientRegistration {
  return {
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUris: JSON.parse(row.redirect_uris) as string[],
    createdAt: row.created_at,
    tokenEndpointAuthMethod: row.token_endpoint_auth_method as "none",
    source: row.source as "dcr" | "cimd",
  };
}

export function createClient(input: {
  clientName?: string;
  redirectUris: string[];
}): ClientRegistration {
  const client: ClientRegistration = {
    clientId: randomUUID(),
    clientName: input.clientName ?? "Unnamed MCP Client",
    redirectUris: [...input.redirectUris],
    createdAt: Date.now(),
    tokenEndpointAuthMethod: "none",
    source: "dcr",
  };
  getDb()
    .prepare(
      `INSERT INTO clients
         (client_id, client_name, redirect_uris, created_at, token_endpoint_auth_method, source)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      client.clientId,
      client.clientName,
      JSON.stringify(client.redirectUris),
      client.createdAt,
      client.tokenEndpointAuthMethod,
      client.source,
    );
  return client;
}

/** DCR-only lookup. Returns undefined for unknown UUIDs; never fetches. */
export function getClient(clientId: string): ClientRegistration | undefined {
  const row = getDb()
    .prepare(`SELECT * FROM clients WHERE client_id = ?`)
    .get(clientId) as ClientRow | undefined;
  return row ? toRegistration(row) : undefined;
}

/**
 * Unified async resolution.
 *   - URL-formatted client_id → CIMD fetch (may hit the network).
 *   - UUID / opaque client_id → persisted DCR lookup.
 * Throws OAuthError("invalid_request" / "invalid_client") on failure.
 */
export async function resolveClient(clientId: string): Promise<ClientRegistration> {
  if (isUrlClientId(clientId)) {
    return fetchCimdClient(clientId);
  }
  const c = getClient(clientId);
  if (!c) {
    throw new OAuthError("invalid_request", `unknown client_id ${clientId}`, 400);
  }
  return c;
}

/** Strict equality check — no prefix match, no scheme normalization. */
export function isRegisteredRedirectUri(client: ClientRegistration, uri: string): boolean {
  return client.redirectUris.includes(uri);
}

/** Test-only helper. */
export function _resetClientStore(): void {
  getDb().exec(`DELETE FROM clients`);
}

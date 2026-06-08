/**
 * @fileoverview Registry for OAuth clients.
 *
 *   - DCR (RFC 7591) clients: created on POST /register, stored in-memory.
 *     v1 ephemeral — re-register after process restart. v1.1 → SQLite-backed.
 *
 *   - CIMD clients: fetched on demand from the URL given as client_id
 *     (draft-ietf-oauth-client-id-metadata-document-00). Validation + caching
 *     lives in cimd.ts.
 *
 * resolveClient() is the unified entry point for handlers and dispatches
 * based on whether the client_id is a URL.
 */

import { randomUUID } from "node:crypto";
import { fetchCimdClient, isUrlClientId } from "./cimd.js";
import { OAuthError, type ClientRegistration } from "./types.js";

const clients = new Map<string, ClientRegistration>();

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
  clients.set(client.clientId, client);
  return client;
}

/** DCR-only lookup. Returns undefined for unknown UUIDs; never fetches. */
export function getClient(clientId: string): ClientRegistration | undefined {
  return clients.get(clientId);
}

/**
 * Unified async resolution.
 *   - URL-formatted client_id → CIMD fetch (may hit the network).
 *   - UUID / opaque client_id → in-memory DCR lookup.
 * Throws OAuthError("invalid_request" / "invalid_client") on failure.
 */
export async function resolveClient(clientId: string): Promise<ClientRegistration> {
  if (isUrlClientId(clientId)) {
    return fetchCimdClient(clientId);
  }
  const c = clients.get(clientId);
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
  clients.clear();
}

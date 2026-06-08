/**
 * @fileoverview In-memory store for dynamically-registered OAuth clients (RFC 7591).
 * v1: ephemeral — re-register after process restart. v1.1 → SQLite-backed.
 */

import { randomUUID } from "node:crypto";
import type { ClientRegistration } from "./types.js";

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
  };
  clients.set(client.clientId, client);
  return client;
}

export function getClient(clientId: string): ClientRegistration | undefined {
  return clients.get(clientId);
}

/** Strict equality check — no prefix match, no scheme normalization. */
export function isRegisteredRedirectUri(client: ClientRegistration, uri: string): boolean {
  return client.redirectUris.includes(uri);
}

/** Test-only helper. */
export function _resetClientStore(): void {
  clients.clear();
}

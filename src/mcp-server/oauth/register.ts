/**
 * @fileoverview RFC 7591 §3 Dynamic Client Registration endpoint.
 * POST /register — accepts public-client metadata, returns issued client_id.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { createClient } from "./clientStore.js";
import { OAuthError, RegisterRequestSchema } from "./types.js";

/** Reject redirect URIs that violate OAuth 2.1 §1.5: HTTPS or loopback only. */
function isAllowedRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]")) return true;
    return false;
  } catch {
    return false;
  }
}

export async function handleRegister(
  req: IncomingMessage,
  res: ServerResponse,
  parseJsonBody: () => Promise<unknown>,
): Promise<void> {
  if (req.method !== "POST") {
    throw new OAuthError("invalid_request", "register requires POST", 405);
  }

  const body = await parseJsonBody();
  const parsed = RegisterRequestSchema.safeParse(body);
  if (!parsed.success) {
    throw new OAuthError(
      "invalid_request",
      `register payload invalid: ${JSON.stringify(parsed.error.flatten().fieldErrors)}`,
      400,
    );
  }

  for (const uri of parsed.data.redirect_uris) {
    if (!isAllowedRedirectUri(uri)) {
      throw new OAuthError(
        "invalid_request",
        `redirect_uri ${uri} is not allowed (must be https:// or http://localhost)`,
        400,
      );
    }
  }

  const client = createClient({
    clientName: parsed.data.client_name,
    redirectUris: parsed.data.redirect_uris,
  });

  res.writeHead(201, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
      client_name: client.clientName,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  );
}

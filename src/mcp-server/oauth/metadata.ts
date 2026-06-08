/**
 * @fileoverview OAuth discovery metadata documents.
 *   - RFC 9728 Protected Resource Metadata
 *   - RFC 8414 Authorization Server Metadata
 *   - OpenID Connect Discovery 1.0 (alias of AS metadata to satisfy MCP client fallback)
 */

import { SCOPES } from "./types.js";

/** Strip trailing slash so URIs match the MCP spec's canonical form. */
function canonical(url: string): string {
  return url.replace(/\/+$/, "");
}

/** RFC 9728 §2 Protected Resource Metadata. */
export function protectedResourceMetadata(issuerUrl: string, mcpEndpoint: string) {
  const issuer = canonical(issuerUrl);
  return {
    resource: `${issuer}${mcpEndpoint}`,
    authorization_servers: [issuer],
    scopes_supported: [...SCOPES],
    bearer_methods_supported: ["header"],
    resource_documentation: `${issuer}/docs/oauth`,
  };
}

/** RFC 8414 §2 Authorization Server Metadata. */
export function authorizationServerMetadata(issuerUrl: string) {
  const issuer = canonical(issuerUrl);
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...SCOPES],
    /** MCP 2025-11-25 §Discovery — advertise CIMD support for forward-compatibility. */
    client_id_metadata_document_supported: true,
    /** RFC 8707 resource indicator support. */
    authorization_response_iss_parameter_supported: true,
    service_documentation: `${issuer}/docs/oauth`,
  };
}

/**
 * @fileoverview OAuth 2.1 shim — shared types and Zod schemas.
 * Implements MCP Authorization 2025-11-25 + RFC 9728 + RFC 8414 + RFC 7591 + OAuth 2.1 (PKCE S256).
 */

import { z } from "zod";

/** OAuth scope vocabulary for this server. v1 ships a single coarse-grained scope. */
export const SCOPES = ["mcp"] as const;
export type Scope = (typeof SCOPES)[number];

/** A registered or fetched OAuth client. Unified view over DCR + CIMD. */
export interface ClientRegistration {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  createdAt: number;
  /** Token endpoint auth method — always "none" in v1 (public clients only). */
  tokenEndpointAuthMethod: "none";
  /** Where the registration came from. "dcr" = POST /register, "cimd" = fetched from URL client_id. */
  source: "dcr" | "cimd";
}

/** A short-lived authorization code, single-use, PKCE-bound. */
export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  /** PKCE S256 challenge — verifier hashed by client, verified at /token. */
  codeChallenge: string;
  /** RFC 8707 resource indicator (canonical MCP server URI). */
  resource: string;
  scope: string;
  expiresAt: number;
  /** Flipped to true on first /token exchange to prevent replay. */
  consumed: boolean;
}

/** An issued refresh token, rotated on every use (OAuth 2.1 requirement for public clients). */
export interface RefreshToken {
  token: string;
  clientId: string;
  resource: string;
  scope: string;
  expiresAt: number;
}

/** Decoded access token claims (HS256 JWT). */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  client_id: string;
  iat: number;
  exp: number;
  jti: string;
}

/** RFC 7591 §3.1 client registration request (minimal subset). */
export const RegisterRequestSchema = z.object({
  redirect_uris: z.array(z.string().url()).min(1),
  client_name: z.string().min(1).max(200).optional(),
  token_endpoint_auth_method: z.literal("none").optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  scope: z.string().optional(),
});
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

/** OAuth 2.1 §4.1 authorization request (query string). */
export const AuthorizeRequestSchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.literal("S256"),
  state: z.string().min(1),
  resource: z.string().url(),
  scope: z.string().optional(),
});
export type AuthorizeRequest = z.infer<typeof AuthorizeRequestSchema>;

/** OAuth 2.1 §5 token request — authorization_code grant. */
export const TokenAuthCodeRequestSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  code_verifier: z.string().min(43).max(128),
  /**
   * RFC 8707 §2.2 — OPTIONAL at the token endpoint. When omitted the AS uses the
   * resource bound at authorization time. claude.ai omits it; requiring it here
   * made /token fail closed with invalid_request and broke the connector.
   */
  resource: z.string().url().optional(),
});
export type TokenAuthCodeRequest = z.infer<typeof TokenAuthCodeRequestSchema>;

/** OAuth 2.1 §5 token request — refresh_token grant. */
export const TokenRefreshRequestSchema = z.object({
  grant_type: z.literal("refresh_token"),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  /** RFC 8707 §2.2 — OPTIONAL; falls back to the resource bound to the refresh token. */
  resource: z.string().url().optional(),
  scope: z.string().optional(),
});
export type TokenRefreshRequest = z.infer<typeof TokenRefreshRequestSchema>;

/** RFC 6749 §5.2 standard error codes used by this server, plus RFC 7591 §3.2.2. */
export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "access_denied"
  | "server_error"
  | "invalid_token"
  | "insufficient_scope"
  /** RFC 7591 §3.2.2 — registration-specific; the submitted metadata is unusable. */
  | "invalid_client_metadata";

export class OAuthError extends Error {
  constructor(
    public readonly code: OAuthErrorCode,
    public readonly description: string,
    public readonly httpStatus: number = 400,
  ) {
    super(`${code}: ${description}`);
    this.name = "OAuthError";
  }

  toJSON() {
    return { error: this.code, error_description: this.description };
  }
}

/**
 * @fileoverview OAuth 2.1 §4.1 authorization endpoint.
 *   GET  /authorize?... → consent HTML (or auto-approve → immediate redirect with code)
 *   POST /authorize     → form submission from consent page → redirect with code
 *
 * All authorize-request parameters are echoed via signed-state in the consent form,
 * so the server holds no per-request session.
 */

import type { IncomingMessage, ServerResponse } from "http";
import sanitizeHtml from "sanitize-html";
import { URL } from "url";
import { getClient, isRegisteredRedirectUri } from "./clientStore.js";
import { issueCode } from "./tokenStore.js";
import { AuthorizeRequestSchema, OAuthError, SCOPES } from "./types.js";
import type { AuthorizeRequest } from "./types.js";

export interface AuthorizeDeps {
  autoApprove: boolean;
  codeTtlSec: number;
}

/** Render a minimal consent page. All dynamic values are escaped. */
function renderConsent(params: AuthorizeRequest, clientName: string): string {
  const safe = (s: string) => sanitizeHtml(s, { allowedTags: [], allowedAttributes: {} });
  const fields = Object.entries(params)
    .map(([k, v]) => `<input type="hidden" name="${safe(k)}" value="${safe(String(v))}">`)
    .join("\n        ");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize ${safe(clientName)}</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 480px; margin: 4em auto; padding: 0 1em; color: #222; }
  h1 { font-size: 1.4em; }
  .meta { background: #f5f5f7; padding: 1em; border-radius: 6px; font-size: 0.9em; }
  .meta div { margin: 0.3em 0; word-break: break-all; }
  .meta b { display: inline-block; min-width: 6em; color: #555; }
  .actions { margin-top: 1.5em; display: flex; gap: 0.5em; }
  button { padding: 0.6em 1.2em; border-radius: 6px; border: 0; cursor: pointer; font-size: 1em; }
  button.allow { background: #0a7; color: white; }
  button.deny { background: #eee; color: #333; }
</style></head>
<body>
  <h1>Authorize <em>${safe(clientName)}</em>?</h1>
  <p>This client is requesting access to your Obsidian MCP server.</p>
  <div class="meta">
    <div><b>Client</b> ${safe(clientName)}</div>
    <div><b>Redirect</b> ${safe(params.redirect_uri)}</div>
    <div><b>Scope</b> ${safe(params.scope ?? "mcp")}</div>
    <div><b>Resource</b> ${safe(params.resource)}</div>
  </div>
  <form method="POST" action="/authorize">
    ${fields}
    <div class="actions">
      <button class="allow" name="decision" value="approve" type="submit">Approve</button>
      <button class="deny" name="decision" value="deny" type="submit" formnovalidate>Deny</button>
    </div>
  </form>
</body></html>`;
}

function redirectWithCode(res: ServerResponse, redirectUri: string, code: string, state: string): void {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  res.writeHead(302, { Location: url.toString() });
  res.end();
}

function redirectWithError(res: ServerResponse, redirectUri: string, error: string, description: string, state: string): void {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  url.searchParams.set("state", state);
  res.writeHead(302, { Location: url.toString() });
  res.end();
}

async function parseAuthorizeParams(
  req: IncomingMessage,
  url: URL,
  parseFormBody: () => Promise<Record<string, string>>,
): Promise<{ params: AuthorizeRequest; decision: "approve" | "deny" | "auto" }> {
  let raw: Record<string, string>;
  let decision: "approve" | "deny" | "auto";
  if (req.method === "GET") {
    raw = Object.fromEntries(url.searchParams.entries());
    decision = "auto";
  } else if (req.method === "POST") {
    raw = await parseFormBody();
    decision = raw.decision === "deny" ? "deny" : "approve";
    delete raw.decision;
  } else {
    throw new OAuthError("invalid_request", "/authorize accepts GET or POST", 405);
  }

  const parsed = AuthorizeRequestSchema.safeParse(raw);
  if (!parsed.success) {
    throw new OAuthError(
      "invalid_request",
      `authorize params invalid: ${JSON.stringify(parsed.error.flatten().fieldErrors)}`,
      400,
    );
  }
  return { params: parsed.data, decision };
}

export async function handleAuthorize(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  parseFormBody: () => Promise<Record<string, string>>,
  deps: AuthorizeDeps,
): Promise<void> {
  const { params, decision } = await parseAuthorizeParams(req, url, parseFormBody);

  // Validate client + redirect_uri BEFORE rendering anything user-facing.
  // Per OAuth 2.1, redirect_uri must NEVER be inferred — only exact-match against registered URIs.
  const client = getClient(params.client_id);
  if (!client) {
    // No safe redirect target — render plain error.
    throw new OAuthError("invalid_request", `unknown client_id ${params.client_id}`, 400);
  }
  if (!isRegisteredRedirectUri(client, params.redirect_uri)) {
    throw new OAuthError(
      "invalid_request",
      `redirect_uri ${params.redirect_uri} not registered for client`,
      400,
    );
  }

  // Scope normalization — v1 only honors "mcp"; absent/empty defaults to "mcp".
  const requestedScopes = (params.scope ?? "mcp").split(/\s+/).filter(Boolean);
  const grantedScopes = requestedScopes.filter((s) => (SCOPES as readonly string[]).includes(s));
  if (grantedScopes.length === 0) grantedScopes.push("mcp");

  if (decision === "deny") {
    redirectWithError(res, params.redirect_uri, "access_denied", "user denied consent", params.state);
    return;
  }

  if (decision === "auto" && !deps.autoApprove) {
    const html = renderConsent(params, client.clientName);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  // approve OR (auto && autoApprove)
  const code = issueCode({
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    codeChallenge: params.code_challenge,
    resource: params.resource,
    scope: grantedScopes.join(" "),
    ttlSec: deps.codeTtlSec,
  });
  redirectWithCode(res, params.redirect_uri, code.code, params.state);
}

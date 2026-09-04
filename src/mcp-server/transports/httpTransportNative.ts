/**
 * @fileoverview Pure Node.js HTTP implementation for MCP Streamable HTTP transport.
 * Removes Hono dependency to eliminate response handling conflicts with MCP SDK.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import http from "http";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { URL } from "url";
import winston from "winston";
import { config } from "../../config/index.js";
import {
  logger,
  RequestContext,
  requestContextService,
} from "../../utils/index.js";
import { VaultManager } from "../../services/vaultManager/index.js";
import { handleChatGptLayerRequest } from "../../chatgpt/layer.js";
import { verifyBearer } from "../oauth/bearer.js";
import { buildOAuthDepsFromConfig, routeOAuth, type OAuthRouterDeps } from "../oauth/router.js";
import { startTokenStoreGc } from "../oauth/tokenStore.js";

const HTTP_PORT = config.mcpHttpPort;
const HTTP_HOST = config.mcpHttpHost;
const MCP_ENDPOINT_PATH = "/mcp";

/**
 * Stores active `StreamableHTTPServerTransport` instances, keyed by session ID.
 */
const httpTransports: Record<string, StreamableHTTPServerTransport> = {};

/**
 * Stores the last activity timestamp for each session.
 */
const sessionActivity: Record<string, number> = {};

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const SESSION_GC_INTERVAL_MS = 60 * 1000; // 1 minute
const MAX_PORT_RETRIES = 15;

/**
 * Monotonic counter for the response-leg log (see `McpResponseClosed`).
 * Resets on process start; pair it with the process uptime when reading logs.
 */
let httpRequestSeq = 0;

/**
 * Argument keys that name the vault object a tool call acts on, in the order
 * they are preferred. Only path-like keys are read: free text (`query`,
 * `content`, `text`) never reaches the evidence log.
 */
const TARGET_ARG_KEYS = [
  "targetIdentifier",
  "filePath",
  "dirPath",
  "path",
  "templatePath",
  "targetPath",
] as const;

/** Longer targets are truncated; a vault path never legitimately runs this far. */
const TARGET_MAX_LENGTH = 300;

/**
 * Pulls the target out of a JSON-RPC body so a cut return leg can be matched
 * back to the request that was lost. `tool` alone says which tool ran; this
 * says what it ran on, which is what turns a guess into a comparison.
 *
 * Returns `null` when the body names no target — a non-`tools/call` method, a
 * tool that takes no path, or a body that never parsed.
 */
function extractTargetIdentifier(body: unknown): string | null {
  const args = (body as { params?: { arguments?: unknown } } | undefined)
    ?.params?.arguments;
  if (!args || typeof args !== "object") return null;
  const record = args as Record<string, unknown>;
  for (const key of TARGET_ARG_KEYS) {
    const value = record[key];
    // An empty string is a real argument (list_files uses "" for the vault
    // root), so presence and type decide — not truthiness.
    if (typeof value === "string") {
      return value.length > TARGET_MAX_LENGTH
        ? `${value.slice(0, TARGET_MAX_LENGTH)}…`
        : value;
    }
  }
  return null;
}

/** Dedicated sink for return-leg evidence. See `attachEvidenceChannel`. */
const EVIDENCE_FILENAME = "funnel-evidence.log";
const EVIDENCE_MAX_SIZE = 5 * 1024 * 1024; // 5MB
const EVIDENCE_MAX_FILES = 10;

/**
 * Reads the git HEAD SHA of the checkout this build came from, walking up from
 * `startDir`. Best effort: returns "unknown" when there is no .git nearby (a
 * copied tree, an npm install), which is itself worth recording.
 */
function readGitHeadSha(startDir: string): string {
  try {
    let dir = startDir;
    for (let i = 0; i < 5; i++) {
      const gitDir = path.join(dir, ".git");
      if (fs.existsSync(gitDir)) {
        const head = fs.readFileSync(path.join(gitDir, "HEAD"), "utf8").trim();
        if (!head.startsWith("ref: ")) {
          return head; // detached HEAD holds the SHA directly
        }
        const ref = head.slice(5).trim();
        const looseRef = path.join(gitDir, ref);
        if (fs.existsSync(looseRef)) {
          return fs.readFileSync(looseRef, "utf8").trim();
        }
        const packedRefs = path.join(gitDir, "packed-refs");
        if (fs.existsSync(packedRefs)) {
          for (const line of fs
            .readFileSync(packedRefs, "utf8")
            .split("\n")) {
            const [sha, name] = line.trim().split(" ");
            if (name === ref && sha) return sha;
          }
        }
        return "unknown";
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // A missing or unreadable .git is not worth failing a server start over.
  }
  return "unknown";
}

/**
 * Opens the funnel evidence channel: a second file transport on the shared
 * logger that keeps only two kinds of record.
 *
 *   1. `McpResponseClosed` where the response was a POST that closed before it
 *      was written out — the machine-side proof that the return leg was cut.
 *   2. One `McpTransportStarted` marker per process start.
 *
 * The marker is what makes an empty file readable. Without it, "no evidence
 * lines" and "the process restarted and lost its history" look identical.
 *
 * The main log is untouched: same rotation, same lines, same volume. This file
 * only ever receives what the filter below admits, which under healthy
 * operation is one line per restart.
 */
function attachEvidenceChannel(): string | null {
  if (!config.logsPath) return null;

  const evidenceFilter = winston.format((info) => {
    if (info.operation === "McpTransportStarted") return info;
    if (
      info.operation === "McpResponseClosed" &&
      info.httpMethod === "POST" &&
      info.clientAborted === true
    ) {
      return info;
    }
    return false;
  });

  const filename = path.join(config.logsPath, EVIDENCE_FILENAME);
  const attached = logger.addTransport(
    new winston.transports.File({
      filename,
      format: winston.format.combine(
        evidenceFilter(),
        winston.format.timestamp(),
        winston.format.json(),
      ),
      maxsize: EVIDENCE_MAX_SIZE,
      maxFiles: EVIDENCE_MAX_FILES,
      tailable: true,
    }),
  );
  return attached ? filename : null;
}

/**
 * Checks if a port is in use.
 */
async function isPortInUse(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const tempServer = http.createServer();
    tempServer
      .once("error", (err: NodeJS.ErrnoException) => {
        resolve(err.code === "EADDRINUSE");
      })
      .once("listening", () => {
        tempServer.close(() => resolve(false));
      })
      .listen(port, host);
  });
}

/**
 * Sets CORS headers on the response.
 */
function setCorsHeaders(res: http.ServerResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Last-Event-ID, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}

/**
 * Validates the API key from URL query parameter.
 * Claude.ai will connect with: http://127.0.0.1:3010/mcp?api_key=YOUR_MCP_AUTH_KEY
 */
function validateApiKey(req: http.IncomingMessage, url: URL): boolean {
  // Use the MCP authentication key for MCP authentication
  // If no MCP auth key is configured, skip authentication
  if (!config.mcpAuthKey || config.mcpAuthKey === "dummy") {
    logger.debug("API key validation skipped - no MCP auth key configured");
    return true;
  }

  // Check for API key in query parameter
  const apiKeyFromQuery = url.searchParams.get('api_key');
  
  const validationContext = requestContextService.createRequestContext({
    operation: "ApiKeyValidation",
    hasApiKeyInQuery: !!apiKeyFromQuery,
    apiKeyMatches: apiKeyFromQuery === config.mcpAuthKey,
    queryParams: Array.from(url.searchParams.keys()),
    apiKeyLength: apiKeyFromQuery?.length || 0,
    configKeyLength: config.mcpAuthKey.length,
    // Show first/last 4 chars of keys for debugging
    apiKeyPreview: apiKeyFromQuery ? `${apiKeyFromQuery.substring(0, 4)}...${apiKeyFromQuery.substring(apiKeyFromQuery.length - 4)}` : "none",
    configKeyPreview: `${config.mcpAuthKey.substring(0, 4)}...${config.mcpAuthKey.substring(config.mcpAuthKey.length - 4)}`,
  });
  logger.debug("API key validation", validationContext);
  
  if (apiKeyFromQuery && apiKeyFromQuery === config.mcpAuthKey) {
    return true;
  }

  return false;
}

/**
 * Handles OPTIONS requests for CORS preflight.
 */
function handleOptions(res: http.ServerResponse) {
  setCorsHeaders(res);
  res.writeHead(200);
  res.end();
}

/**
 * Parses request body as JSON.
 */
async function parseJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Parses request body as application/x-www-form-urlencoded.
 */
async function parseFormBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      try {
        const params = new URLSearchParams(body);
        const out: Record<string, string> = {};
        for (const [k, v] of params) out[k] = v;
        resolve(out);
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Starts the pure Node.js HTTP server for MCP transport.
 */
export async function startHttpTransport(
  createServerInstanceFn: () => Promise<McpServer>,
  parentContext: RequestContext,
  vaultManager: VaultManager,
): Promise<http.Server> {
  const transportContext = requestContextService.createRequestContext({
    ...parentContext,
    transportType: "HTTP",
    component: "HttpTransportSetup",
  });

  const evidenceFile = attachEvidenceChannel();

  // --- OAuth shim setup (only when MCP_AUTH_MODE=oauth) ---
  let oauthDeps: OAuthRouterDeps | undefined;
  if (config.mcpAuthMode === "oauth") {
    oauthDeps = buildOAuthDepsFromConfig(MCP_ENDPOINT_PATH);
    startTokenStoreGc();
    logger.info(`OAuth shim active (issuer=${oauthDeps.issuerUrl}, audience=${oauthDeps.issuerUrl}${MCP_ENDPOINT_PATH})`, transportContext);
  } else {
    logger.info("OAuth shim disabled (MCP_AUTH_MODE=legacy) — using ?api_key= auth", transportContext);
  }

  // Start session garbage collector
  setInterval(() => {
    const now = Date.now();
    for (const sessionId in sessionActivity) {
      if (now - sessionActivity[sessionId] > SESSION_TIMEOUT_MS) {
        const gcContext = requestContextService.createRequestContext({
          operation: "SessionGarbageCollector",
          sessionId,
        });
        logger.info(`Session ${sessionId} timed out due to inactivity. Cleaning up.`, gcContext);
        const transport = httpTransports[sessionId];
        if (transport) {
          transport.close();
        }
        delete sessionActivity[sessionId];
      }
    }
  }, SESSION_GC_INTERVAL_MS);

  const server = http.createServer(async (req, res) => {
    // --- Response-leg instrumentation (log-only; adds no behaviour) ---
    // Records how each /mcp response ended: status, latency, whether the body was
    // handed to the OS in full (`finished`), and whether the socket closed before
    // that (`clientAborted`). A `clientAborted: true` line is the machine-side
    // evidence that the return leg was cut before the response was delivered.
    // `targetIdentifier` carries what the call acted on, so a cut line can be
    // compared against the request that was lost instead of merely guessed at.
    // Listeners are attached before anything else so no request can escape them.
    const respRec: {
      seq: number;
      start: number;
      path: string;
      rpcMethod?: string;
      tool?: string;
      targetIdentifier: string | null;
      finishMs?: number;
      logged: boolean;
    } = {
      seq: ++httpRequestSeq,
      start: Date.now(),
      path: "",
      targetIdentifier: null,
      logged: false,
    };
    res.on("finish", () => {
      respRec.finishMs = Date.now() - respRec.start;
    });
    res.on("close", () => {
      if (respRec.logged) return;
      respRec.logged = true;
      // Only the MCP endpoint is logged; health pollers on other paths would
      // otherwise add thousands of lines a day to a fixed-size rotation.
      if (respRec.path !== MCP_ENDPOINT_PATH) return;
      const finished = res.writableFinished === true;
      logger.info(
        `MCP response closed: ${req.method} ${respRec.path} ${res.statusCode}`,
        requestContextService.createRequestContext({
          operation: "McpResponseClosed",
          reqSeq: respRec.seq,
          path: respRec.path,
          httpMethod: req.method || "unknown",
          rpcMethod: respRec.rpcMethod,
          tool: respRec.tool,
          targetIdentifier: respRec.targetIdentifier,
          status: res.statusCode,
          ms: Date.now() - respRec.start,
          finishMs: respRec.finishMs ?? null,
          finished,
          clientAborted: !finished,
        }),
      );
    });

    try {
      setCorsHeaders(res);

      const url = new URL(req.url!, `http://${req.headers.host}`);
      respRec.path = url.pathname;

      // Log all incoming requests for debugging
      const requestContext = requestContextService.createRequestContext({
        operation: "IncomingHTTPRequest",
        method: req.method || "unknown",
        url: req.url || "unknown",
        headers: JSON.stringify({
          host: req.headers.host,
          "user-agent": req.headers["user-agent"],
          "mcp-session-id": req.headers["mcp-session-id"],
          authorization: req.headers.authorization ? "[REDACTED]" : undefined,
        }),
        query: url.search,
      });
      logger.info(`Incoming HTTP request: ${req.method} ${req.url}`, requestContext);
      
      if (
        await handleChatGptLayerRequest({
          req,
          res,
          url,
          parentContext: requestContext,
          parseJsonBody: () => parseJsonBody(req),
          ensureAuthenticated: () => validateApiKey(req, url),
          vaultManager,
          mcpEndpointPath: MCP_ENDPOINT_PATH,
        })
      ) {
        return;
      }

      // OAuth discovery + DCR + authorize + token (no Bearer required on these paths).
      if (oauthDeps && (await routeOAuth(
        req,
        res,
        url,
        () => parseJsonBody(req),
        () => parseFormBody(req),
        oauthDeps,
      ))) {
        return;
      }

      // Only handle our MCP endpoint
      if (url.pathname !== MCP_ENDPOINT_PATH) {
        res.writeHead(404);
        res.end("Not Found");
        return;
      }

      // Handle OPTIONS for CORS
      if (req.method === "OPTIONS") {
        handleOptions(res);
        return;
      }

      // Authentication: OAuth Bearer (mode=oauth) or legacy ?api_key= (mode=legacy)
      if (oauthDeps) {
        const claims = await verifyBearer(req, res, {
          jwtSecret: oauthDeps.jwtSecret,
          issuerUrl: oauthDeps.issuerUrl,
          audience: `${oauthDeps.issuerUrl}${MCP_ENDPOINT_PATH}`,
          resourceMetadataUrl: `${oauthDeps.issuerUrl}/.well-known/oauth-protected-resource`,
        });
        if (!claims) return; // verifyBearer already wrote the 401 response
      } else if (!validateApiKey(req, url)) {
        logger.warning(`Authentication failed for request: ${req.method} ${req.url}`, {
          ...requestContext,
          authFailure: true,
          hasApiKeyInQuery: url.searchParams.has('api_key'),
          configuredApiKey: config.obsidianApiKey ? "[SET]" : "[NOT SET]",
        });
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32001, message: "Unauthorized: Invalid or missing API key" },
          id: null,
        }));
        return;
      }

      const sessionId = req.headers["mcp-session-id"] as string;
      let transport: StreamableHTTPServerTransport | undefined;
      
      if (config.mcpHttpStateless) {
        // In stateless mode, use a single shared transport
        transport = httpTransports["stateless"] || undefined;
      } else {
        // In session mode, use session-based transport lookup
        transport = sessionId ? httpTransports[sessionId] : undefined;
        if (transport && sessionId) {
          sessionActivity[sessionId] = Date.now();
        }
      }

      if (req.method === "POST") {
        const body = await parseJsonBody(req);
        respRec.rpcMethod =
          typeof body?.method === "string" ? body.method : undefined;
        respRec.tool =
          typeof body?.params?.name === "string" ? body.params.name : undefined;
        respRec.targetIdentifier = extractTargetIdentifier(body);

        // Log POST body for debugging (without sensitive data)
        logger.debug(`POST request body`, {
          ...requestContext,
          bodyKeys: Object.keys(body || {}),
          method: body?.method,
          hasId: !!body?.id,
          hasParams: !!body?.params,
        });
        const isInitReq = isInitializeRequest(body);
        const requestId = body?.id || null;

        if (isInitReq) {
          logger.info(`Received InitializeRequest`, {
            ...requestContext,
            isInitReq: true,
            hasExistingTransport: !!transport,
            sessionId: sessionId || "none",
            statelessMode: config.mcpHttpStateless,
          });
          
          if (transport) {
            logger.warning("Received InitializeRequest on existing session. Closing old session.");
            await transport.close();
          }

          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: config.mcpHttpStateless ? undefined : () => randomUUID(),
            onsessioninitialized: (newId) => {
              if (config.mcpHttpStateless) {
                // In stateless mode, store under "stateless" key
                httpTransports["stateless"] = transport!;
                logger.info(`HTTP Stateless transport initialized`, transportContext);
              } else {
                // In session mode, store under session ID
                httpTransports[newId] = transport!;
                sessionActivity[newId] = Date.now();
                const sessionContext = requestContextService.createRequestContext({
                  operation: "sessionCreated",
                  newSessionId: newId,
                });
                logger.info(`HTTP Session created: ${newId}`, sessionContext);
              }
            },
          });

          transport.onclose = () => {
            const closedSessionId = transport!.sessionId;
            if (closedSessionId) {
              delete httpTransports[closedSessionId];
              delete sessionActivity[closedSessionId];
              const closeContext = requestContextService.createRequestContext({
                operation: "sessionClosed",
                closedSessionId,
              });
              logger.info(`HTTP Session closed: ${closedSessionId}`, closeContext);
            }
          };

          const mcpServer = await createServerInstanceFn();
          await mcpServer.connect(transport);
        } else if (!transport && !config.mcpHttpStateless) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32004, message: "Invalid or expired session ID" },
            id: requestId,
          }));
          return;
        } else if (!transport && config.mcpHttpStateless) {
          // In stateless mode, create transport if it doesn't exist
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            onsessioninitialized: (newId) => {
              httpTransports["stateless"] = transport!;
              logger.info(`HTTP Stateless transport initialized for non-init request`, transportContext);
            },
          });
          const mcpServer = await createServerInstanceFn();
          await mcpServer.connect(transport);
        }

        // Let MCP transport handle the request completely
        await transport!.handleRequest(req, res, body);
        
      } else if (req.method === "GET" || req.method === "DELETE") {
        if (!transport && !config.mcpHttpStateless) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32004, message: "Session not found or expired" },
            id: null,
          }));
          return;
        } else if (!transport && config.mcpHttpStateless) {
          // In stateless mode, create transport if it doesn't exist
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            onsessioninitialized: (newId) => {
              httpTransports["stateless"] = transport!;
              logger.info(`HTTP Stateless transport initialized for non-init request`, transportContext);
            },
          });
          const mcpServer = await createServerInstanceFn();
          await mcpServer.connect(transport);
        }

        // Let MCP transport handle the request completely
        await transport!.handleRequest(req, res);
        
      } else {
        res.writeHead(405);
        res.end("Method Not Allowed");
      }

    } catch (err) {
      const errorContext = requestContextService.createRequestContext({
        operation: "httpRequestError",
        method: req.method || "unknown",
        url: req.url || "unknown",
      });
      logger.error("Error handling HTTP request", {
        ...errorContext,
        error: err instanceof Error ? err.message : String(err),
      });
      
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        }));
      }
    }
  });

  // Find available port
  let currentPort = HTTP_PORT;
  for (let i = 0; i <= MAX_PORT_RETRIES; i++) {
    currentPort = HTTP_PORT + i;
    
    if (await isPortInUse(currentPort, HTTP_HOST)) {
      logger.warning(`Port ${currentPort} is in use, trying next port...`);
      continue;
    }

    try {
      await new Promise<void>((resolve, reject) => {
        server.listen(currentPort, HTTP_HOST, () => {
          const serverAddress = `http://${HTTP_HOST}:${currentPort}${MCP_ENDPOINT_PATH}`;
          logger.info(`HTTP transport successfully listening at ${serverAddress}`);
          
          // Unconditional. Only the HTTP transport reaches this line, so stdout is
          // never the JSON-RPC channel here (that belongs to the stdio transport).
          // Under a service manager this line is the proof-of-life that the capture
          // file lacked for this service's entire history.
          console.log(`\n🚀 MCP Server running in HTTP mode at: ${serverAddress}\n   (MCP Spec: 2025-03-26 Streamable HTTP Transport)\n`);

          // Marker on the evidence channel. An evidence file holding only these
          // is proof of health; a gap in them dates a restart, which is the one
          // thing that can silently erase the counter and the session state.
          logger.info(
            `MCP HTTP transport started (pid ${process.pid})`,
            requestContextService.createRequestContext({
              operation: "McpTransportStarted",
              pid: process.pid,
              startedAt: new Date().toISOString(),
              gitHead: readGitHeadSha(path.dirname(config.logsPath)),
              port: currentPort,
              evidenceFile: evidenceFile ?? "disabled",
            }),
          );
          resolve();
        });
        server.on("error", reject);
      });
      
      return server;
    } catch (err: any) {
      if (err.code !== "EADDRINUSE") {
        throw err;
      }
    }
  }

  throw new Error(`Failed to bind to any port after ${MAX_PORT_RETRIES + 1} attempts`);
}

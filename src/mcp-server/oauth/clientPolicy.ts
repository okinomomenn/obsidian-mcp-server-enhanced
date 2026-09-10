/**
 * @fileoverview Per-client tool authorization for the /mcp endpoint.
 *
 * WHY THIS LIVES AT THE TRANSPORT LAYER, NOT IN THE TOOLS
 *
 * The HTTP transport runs in stateless mode (`MCP_HTTP_STATELESS=true`), which
 * means a single `StreamableHTTPServerTransport` — and therefore a single
 * `McpServer` instance with one tool registry — serves every client. There is
 * no per-client server instance to register a different tool set on, so the
 * "hand out different tools per client" shape is not available. Authorization
 * has to be decided per request, from the verified access-token claims, before
 * the call reaches the shared server.
 *
 * FAIL CLOSED
 *
 * `TOOL_CLASS` is an explicit table over every registered tool. A tool that is
 * missing from it is classified as `write`, not as `read`: adding a tool must
 * never silently widen a restricted client's reach. `classifyTool` is exported
 * so a test can assert the table covers the live registry exactly.
 *
 * SCOPE OF THE RESTRICTION
 *
 * Only clients listed in `restrictedClientIds` are affected. Everyone else —
 * Claude (a CIMD client whose client_id is a URL), Open WebUI, and any future
 * client — takes the `allow` path on the first branch and behaves exactly as
 * before this module existed.
 */

/** What a tool does to the vault. Drives the decision in `decide`. */
export type ToolClass = "read" | "write" | "delete";

/**
 * Every tool registered by `createMcpServerInstance`, classified.
 *
 * Keep this in sync with server.ts. `clientPolicy.test.ts` asserts the two
 * agree, so an unclassified tool fails the build's test step rather than
 * quietly defaulting to something permissive at runtime.
 */
export const TOOL_CLASS: Readonly<Record<string, ToolClass>> = Object.freeze({
  // --- read: no vault mutation, allowed vault-wide ---
  obsidian_read_file: "read",
  obsidian_list_files: "read",
  obsidian_global_search: "read",
  obsidian_dataview_query: "read",
  obsidian_task_query: "read",
  obsidian_tasks_query_builder: "read",
  obsidian_graph_analysis: "read",
  // --- write: mutates a target path, allowed only inside the client's区画 ---
  obsidian_update_file: "write",
  obsidian_search_replace: "write",
  obsidian_manage_frontmatter: "write",
  obsidian_manage_tags: "write",
  obsidian_create_task: "write",
  obsidian_update_task: "write",
  obsidian_periodic_notes: "write",
  obsidian_block_reference: "write",
  obsidian_template_system: "write",
  obsidian_smart_linking: "write",
  // --- delete: refused outright, inside the区画 as well ---
  obsidian_delete_file: "delete",
});

/**
 * Unknown tools are `write`, which is the most restricted class that still has
 * a legitimate path (a delete-by-default would be indistinguishable from a
 * broken registry). A tool nobody classified is a tool nobody vouched for.
 */
export function classifyTool(tool: string): ToolClass {
  return TOOL_CLASS[tool] ?? "write";
}

export interface ClientPolicy {
  /** Token `client_id` values this policy applies to. Everyone else is unrestricted. */
  restrictedClientIds: readonly string[];
  /** Vault-relative directory the restricted clients may write into, e.g. `_inbox/astra`. */
  writeRoot: string;
}

export type PolicyDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

const ALLOW: PolicyDecision = { allowed: true };

/**
 * Normalize a vault-relative path for prefix comparison.
 *
 * Returns `null` for anything that cannot be compared safely — a traversal
 * segment, a drive letter, a UNC or absolute path — so the caller refuses
 * rather than guessing. Backslashes are folded to `/` because the vault runs on
 * Windows and both separators reach us; case is folded for the same reason.
 */
export function normalizeVaultPath(raw: string): string | null {
  let p = raw.trim().replace(/\\/g, "/");
  if (p === "") return "";
  // Absolute, UNC, or drive-qualified paths are not vault-relative.
  if (p.startsWith("/") || p.startsWith("//") || /^[A-Za-z]:/.test(p)) return null;
  // Strip a leading "./" (possibly repeated) before inspecting segments.
  while (p.startsWith("./")) p = p.slice(2);
  const segments = p.split("/").filter((s) => s !== "");
  // "." is harmless; ".." can escape the write root and is never accepted.
  if (segments.some((s) => s === "..")) return null;
  return segments
    .filter((s) => s !== ".")
    .join("/")
    .toLowerCase();
}

/**
 * True when `target` is the write root itself or something beneath it.
 *
 * The boundary is a path separator, so `_inbox/astra-notes/x.md` does NOT match
 * a write root of `_inbox/astra` — a plain `startsWith` would have let it in.
 */
export function isInsideWriteRoot(target: string, writeRoot: string): boolean {
  const root = normalizeVaultPath(writeRoot);
  if (root === null || root === "") return false;
  return target === root || target.startsWith(root + "/");
}

/**
 * Decide whether `clientId` may run `tool` against `targetPath`.
 *
 * `targetPath` is what the transport already extracts for logging
 * (`extractTargetIdentifier`); `null` means the request carried no recognizable
 * path argument.
 */
export function decide(input: {
  policy: ClientPolicy;
  clientId: string | undefined;
  tool: string;
  targetPath: string | null;
}): PolicyDecision {
  const { policy, clientId, tool, targetPath } = input;

  // 1. Unrestricted clients (Claude, Open WebUI, …) are untouched.
  if (!clientId || !policy.restrictedClientIds.includes(clientId)) return ALLOW;

  const cls = classifyTool(tool);

  // 2. Deletion is refused everywhere, including inside the client's own 区画:
  //    removing notes is the cleanup lane's job, never an agent's.
  if (cls === "delete") {
    return {
      allowed: false,
      reason:
        `このクライアントは削除できない（${policy.writeRoot}/ の中も不可）。` +
        `削除は清掃便の管轄。書き換えたい場合は ${policy.writeRoot}/ 配下の更新で行うこと。`,
    };
  }

  // 3. Reading is allowed vault-wide.
  if (cls === "read") return ALLOW;

  // 4. Writing (and anything unclassified) is confined to the write root.
  if (targetPath === null) {
    return {
      allowed: false,
      reason:
        `書込先のパスを読み取れなかったため拒否した。` +
        `このクライアントの書込は ${policy.writeRoot}/ 配下のみ許可されている。`,
    };
  }
  const normalized = normalizeVaultPath(targetPath);
  if (normalized === null) {
    return {
      allowed: false,
      reason:
        `書込先 '${targetPath}' は Vault 相対パスとして解釈できない（'..' や絶対パスは不可）。` +
        `このクライアントの書込は ${policy.writeRoot}/ 配下のみ許可されている。`,
    };
  }
  if (isInsideWriteRoot(normalized, policy.writeRoot)) return ALLOW;

  return {
    allowed: false,
    reason:
      `書込先 '${targetPath}' は許可範囲の外。` +
      `このクライアントの書込は ${policy.writeRoot}/ 配下のみ。読み取りは Vault 全域が許可されている。`,
  };
}

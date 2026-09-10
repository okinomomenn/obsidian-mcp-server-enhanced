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
 * SCOPE OF THE RESTRICTION — AN ALLOW LIST, NOT A DENY LIST
 *
 * Clients named in `unrestrictedClientIds` keep full access; everyone else is
 * restricted, including a client_id nobody has seen before. The reverse shape
 * was tried first and fails open exactly when it matters: a connector
 * re-registers, DCR mints a new client_id, the configured id matches nobody,
 * and the gate quietly stops applying. Reversed, that same event lands the
 * newcomer in the restricted class.
 *
 * The cost is the mirror hazard — if a trusted client's id changes it loses
 * vault-wide access until the list is updated. That failure is loud (a refusal
 * with a reason) rather than silent, and `enabled: false` restores the old
 * behaviour without touching code.
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
  /**
   * Master switch. `false` short-circuits every decision to allow, which is
   * both the default and the rollback: clear the env line, restart, done.
   *
   * It exists because the list below is an ALLOW list, so an empty list plus
   * an enabled gate would restrict everyone. Enabling and listing have to be
   * two separate acts.
   */
  enabled: boolean;
  /**
   * Clients that keep full vault-wide access. Everyone else — including a
   * client_id nobody has seen before — gets the restricted treatment.
   *
   * DELIBERATELY AN ALLOW LIST. The first version keyed on the restricted ids
   * instead, which failed open in the one situation most likely to arise: a
   * connector re-registers (after a key rotation, say), DCR mints a fresh
   * client_id, the configured id now matches nobody, and the gate silently
   * stops applying. Reversed, that same event lands the newcomer in the
   * restricted class, which is loud and safe.
   *
   * An entry ending in `*` matches by prefix. That is what keeps a CIMD client
   * covered: its client_id is a URL under a stable origin, while DCR ids are
   * volatile UUIDs.
   */
  unrestrictedClientIds: readonly string[];
  /** Vault-relative directory the restricted clients may write into, e.g. `_inbox/astra`. */
  writeRoot: string;
}

/** Exact match, or prefix match for an entry written with a trailing `*`. */
export function isUnrestricted(clientId: string, patterns: readonly string[]): boolean {
  for (const p of patterns) {
    if (p.endsWith("*")) {
      if (clientId.startsWith(p.slice(0, -1))) return true;
    } else if (clientId === p) {
      return true;
    }
  }
  return false;
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

  // 1. Gate off: behave exactly as if this module did not exist.
  if (!policy.enabled) return ALLOW;

  // 2. Listed clients keep full access. An absent client_id is NOT one of them:
  //    no identity means the caller cannot be vouched for, so it is restricted.
  if (clientId && isUnrestricted(clientId, policy.unrestrictedClientIds)) return ALLOW;

  const cls = classifyTool(tool);

  // 3. Deletion is refused everywhere, including inside the client's own 区画:
  //    removing notes is the cleanup lane's job, never an agent's.
  if (cls === "delete") {
    return {
      allowed: false,
      reason:
        `このクライアントは削除できない（${policy.writeRoot}/ の中も不可）。` +
        `削除は清掃便の管轄。書き換えたい場合は ${policy.writeRoot}/ 配下の更新で行うこと。`,
    };
  }

  // 4. Reading is allowed vault-wide.
  if (cls === "read") return ALLOW;

  // 5. Writing (and anything unclassified) is confined to the write root.
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

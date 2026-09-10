/**
 * @fileoverview Per-client tool authorization tests. Run with:
 *   node --import=tsx --test src/mcp-server/oauth/__tests__/clientPolicy.test.ts
 * or after `npm run build`:
 *   node --test dist/mcp-server/oauth/__tests__/clientPolicy.test.js
 *
 * Two things are pinned here:
 *
 *   1. COVERAGE. The classification table is checked against the live tool
 *      registry, read off `registration.ts` at test time rather than copied
 *      into the test. Adding a tool without classifying it fails this suite —
 *      which is the point: the runtime default is `write`, and a default is a
 *      safety net, not a decision.
 *
 *   2. THE MATRIX. Every tool is exercised through `decide` for the restricted
 *      client, in and out of the write root, so the table below is the
 *      authorization surface in one readable place.
 *
 * These are pure-function tests: no server, no transport, no network.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import {
  TOOL_CLASS,
  classifyTool,
  decide,
  isInsideWriteRoot,
  normalizeVaultPath,
  type ClientPolicy,
  type ToolClass,
} from "../clientPolicy.js";

const ASTRA = "f8f2a3fa-9bde-4cb6-afc9-a66412a43789";
const CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const OPENWEBUI = "53281724-cd37-408d-a3e0-71f071077d7b";

const POLICY: ClientPolicy = {
  restrictedClientIds: [ASTRA],
  writeRoot: "_inbox/astra",
};

const INSIDE = "_inbox/astra/note.md";
const OUTSIDE = "00-meta/handoff/x.md";

/**
 * Reads the tool names the server actually registers, from their source.
 *
 * The name is not declared in one consistent place: some tools put
 * `const toolName = "…"` in `registration`, others in `index`, and some pass
 * `name: "…"` to the SDK. So every file in the tool's directory is scanned for
 * a quoted `obsidian_*` literal and the directory must yield exactly one
 * distinct name — which also catches a tool that starts answering to two.
 */
function liveToolNames(): string[] {
  const here = nodePath.dirname(fileURLToPath(import.meta.url));
  // src/mcp-server/oauth/__tests__ and dist/mcp-server/oauth/__tests__ sit at
  // the same depth relative to the tools directory.
  const toolsDir = nodePath.resolve(here, "..", "..", "tools");
  const names: string[] = [];
  for (const entry of readdirSync(toolsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = nodePath.join(toolsDir, entry.name);
    const found = new Set<string>();
    for (const file of readdirSync(dir, { withFileTypes: true })) {
      if (!file.isFile()) continue;
      if (!/\.(ts|js)$/.test(file.name) || file.name.endsWith(".d.ts")) continue;
      const source = readFileSync(nodePath.join(dir, file.name), "utf8");
      for (const m of source.matchAll(/["'](obsidian_[a-z_]+)["']/g)) found.add(m[1]);
    }
    assert.equal(
      found.size,
      1,
      `${entry.name}: expected exactly one obsidian_* tool name, found ${[...found].join(", ") || "none"}`,
    );
    names.push([...found][0]);
  }
  return names.sort();
}

describe("clientPolicy — coverage of the live tool registry", () => {
  it("classifies every registered tool, and classifies nothing that is not registered", () => {
    const live = liveToolNames();
    const table = Object.keys(TOOL_CLASS).sort();
    assert.deepEqual(
      table,
      live,
      "TOOL_CLASS and the tool registry disagree. Classify the new tool in clientPolicy.ts.",
    );
    assert.equal(live.length, 18, "tool count changed; review the classification");
  });

  it("defaults an unknown tool to write, never to read", () => {
    assert.equal(classifyTool("obsidian_brand_new_tool"), "write");
    assert.equal(classifyTool(""), "write");
  });

  it("refuses an unclassified tool outside the write root (fail closed)", () => {
    const d = decide({
      policy: POLICY,
      clientId: ASTRA,
      tool: "obsidian_brand_new_tool",
      targetPath: OUTSIDE,
    });
    assert.equal(d.allowed, false);
  });
});

describe("clientPolicy — the authorization matrix", () => {
  const expected: Record<ToolClass, { inside: boolean; outside: boolean }> = {
    read: { inside: true, outside: true },
    write: { inside: true, outside: false },
    delete: { inside: false, outside: false },
  };

  for (const [tool, cls] of Object.entries(TOOL_CLASS)) {
    it(`${tool} (${cls}): inside=${expected[cls].inside} outside=${expected[cls].outside}`, () => {
      const inside = decide({ policy: POLICY, clientId: ASTRA, tool, targetPath: INSIDE });
      const outside = decide({ policy: POLICY, clientId: ASTRA, tool, targetPath: OUTSIDE });
      assert.equal(inside.allowed, expected[cls].inside, `${tool} inside the write root`);
      assert.equal(outside.allowed, expected[cls].outside, `${tool} outside the write root`);
      if (!inside.allowed) assert.ok(inside.reason.length > 0, "a refusal must explain itself");
      if (!outside.allowed) assert.ok(outside.reason.length > 0, "a refusal must explain itself");
    });
  }
});

describe("clientPolicy — unrestricted clients are untouched", () => {
  for (const [label, id] of [
    ["Claude (CIMD)", CLAUDE],
    ["Open WebUI", OPENWEBUI],
    ["no client_id", undefined],
  ] as const) {
    it(`${label}: every tool allowed everywhere, delete included`, () => {
      for (const tool of Object.keys(TOOL_CLASS)) {
        for (const target of [INSIDE, OUTSIDE, null]) {
          const d = decide({ policy: POLICY, clientId: id, tool, targetPath: target });
          assert.equal(d.allowed, true, `${label} / ${tool} / ${target}`);
        }
      }
    });
  }

  it("an empty restricted list disables the gate entirely", () => {
    const off: ClientPolicy = { restrictedClientIds: [], writeRoot: "_inbox/astra" };
    const d = decide({ policy: off, clientId: ASTRA, tool: "obsidian_delete_file", targetPath: OUTSIDE });
    assert.equal(d.allowed, true);
  });
});

describe("clientPolicy — path normalization", () => {
  it("folds separators and case", () => {
    assert.equal(normalizeVaultPath("_inbox\\Astra\\Note.md"), "_inbox/astra/note.md");
  });

  it("strips leading ./ and empty segments", () => {
    assert.equal(normalizeVaultPath("./_inbox//astra/a.md"), "_inbox/astra/a.md");
  });

  it("rejects traversal", () => {
    assert.equal(normalizeVaultPath("_inbox/astra/../../00-meta/x.md"), null);
    assert.equal(normalizeVaultPath(".."), null);
  });

  it("rejects absolute, UNC and drive-qualified paths", () => {
    assert.equal(normalizeVaultPath("/00-meta/x.md"), null);
    assert.equal(normalizeVaultPath("//server/share/x.md"), null);
    assert.equal(normalizeVaultPath("D:\\SYRINX-Vault\\00-meta\\x.md"), null);
  });

  it("treats the root itself as inside, and a same-prefix sibling as outside", () => {
    assert.equal(isInsideWriteRoot("_inbox/astra", "_inbox/astra"), true);
    assert.equal(isInsideWriteRoot("_inbox/astra/deep/a.md", "_inbox/astra"), true);
    assert.equal(isInsideWriteRoot("_inbox/astra-notes/a.md", "_inbox/astra"), false);
    assert.equal(isInsideWriteRoot("_inbox/astrax", "_inbox/astra"), false);
  });
});

describe("clientPolicy — refusals for the restricted client", () => {
  it("refuses a write with no readable target path", () => {
    const d = decide({ policy: POLICY, clientId: ASTRA, tool: "obsidian_update_file", targetPath: null });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.match(d.reason, /_inbox\/astra/);
  });

  it("refuses a traversal that would land inside the write root textually", () => {
    const d = decide({
      policy: POLICY,
      clientId: ASTRA,
      tool: "obsidian_update_file",
      targetPath: "_inbox/astra/../../CLAUDE.md",
    });
    assert.equal(d.allowed, false);
  });

  it("refuses delete inside the write root", () => {
    const d = decide({ policy: POLICY, clientId: ASTRA, tool: "obsidian_delete_file", targetPath: INSIDE });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.match(d.reason, /削除/);
  });

  it("allows a read anywhere in the vault", () => {
    for (const p of ["CLAUDE.md", "00-meta/ops/log/2026-09.md", "_queue/log/x.md", null]) {
      const d = decide({ policy: POLICY, clientId: ASTRA, tool: "obsidian_read_file", targetPath: p });
      assert.equal(d.allowed, true, String(p));
    }
  });
});

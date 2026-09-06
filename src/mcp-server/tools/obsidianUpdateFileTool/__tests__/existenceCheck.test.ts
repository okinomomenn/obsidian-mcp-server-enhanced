/**
 * @fileoverview Unit tests for the pre-operation existence check in
 * `processObsidianUpdateFile`. Run after `npm run build` with:
 *   OBSIDIAN_API_KEY=test-key-not-used \
 *     node --test dist/mcp-server/tools/obsidianUpdateFileTool/__tests__/existenceCheck.test.js
 *
 * The key is never used — no request leaves the process — but importing this
 * module pulls in `config`, which refuses to load without one. "Logger not
 * initialized; message dropped." lines are expected: the logger is never
 * started in a unit-test process.
 *
 * These pin the two behaviours that matter when the check answers "not found":
 *   1. a new file is still created (the check is informational, not a gate), and
 *   2. an unreachable vault is NEVER mistaken for an absent file.
 *
 * The Obsidian REST service is injected, so it is stubbed here — no HTTP, no
 * vault. Only pure control flow is exercised.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ObsidianUpdateFileInputSchema,
  processObsidianUpdateFile,
} from "../logic.js";
import type { ObsidianRestApiService } from "../../../../services/obsidianRestAPI/index.js";
import { BaseErrorCode, McpError } from "../../../../types-global/errors.js";
import { requestContextService } from "../../../../utils/index.js";

const TARGET = "notes/example.md";

type ExistenceOutcome = "found" | "notFound" | "unavailable";

/**
 * Builds a stub service plus a call log.
 *
 * `getFileContent` is used twice by the logic under test: once for the Step 1
 * existence check and once for the Step 4 final-state read. Only the first call
 * is scripted; later calls always throw so that `getFinalState` takes its own
 * catch path and returns null. That keeps stat formatting out of these tests.
 */
function makeService(existence: ExistenceOutcome) {
  const calls: string[] = [];
  let getFileContentCalls = 0;

  const service = {
    async getFileContent(): Promise<unknown> {
      getFileContentCalls += 1;
      calls.push("getFileContent");
      if (getFileContentCalls > 1) {
        // Step 4 final-state read; getFinalState swallows this and returns null.
        throw new McpError(BaseErrorCode.NOT_FOUND, "stub: no final state");
      }
      if (existence === "found") {
        return { content: "old", frontmatter: {}, path: TARGET, tags: [] };
      }
      throw new McpError(
        existence === "notFound"
          ? BaseErrorCode.NOT_FOUND
          : BaseErrorCode.SERVICE_UNAVAILABLE,
        existence === "notFound"
          ? "Obsidian API Not Found: /vault/" + TARGET
          : "Obsidian API Network Error: No response received from /vault/",
      );
    },
    async updateFileContent(): Promise<void> {
      calls.push("updateFileContent");
    },
    async getActiveFile(): Promise<unknown> {
      calls.push("getActiveFile");
      throw new McpError(BaseErrorCode.NOT_FOUND, "stub");
    },
    async updateActiveFile(): Promise<void> {
      calls.push("updateActiveFile");
    },
    async getPeriodicNote(): Promise<unknown> {
      calls.push("getPeriodicNote");
      throw new McpError(BaseErrorCode.NOT_FOUND, "stub");
    },
    async updatePeriodicNote(): Promise<void> {
      calls.push("updatePeriodicNote");
    },
  };

  return {
    service: service as unknown as ObsidianRestApiService,
    calls,
    existenceCheckCalls: () => Math.min(getFileContentCalls, 1),
    getFileContentCalls: () => getFileContentCalls,
  };
}

function makeParams(overrides: Record<string, unknown> = {}) {
  return ObsidianUpdateFileInputSchema.parse({
    targetType: "filePath",
    targetIdentifier: TARGET,
    modificationType: "wholeFile",
    wholeFileMode: "overwrite",
    content: "new content",
    createIfNeeded: true,
    overwriteIfExists: false,
    returnContent: false,
    ...overrides,
  });
}

function makeContext() {
  return requestContextService.createRequestContext({
    operation: "existenceCheckTest",
  });
}

describe("update_file — existence check: creation path", () => {
  it("creates the file when the check answers NOT_FOUND", async () => {
    const { service, calls } = makeService("notFound");

    const response = await processObsidianUpdateFile(
      makeParams(),
      makeContext(),
      service,
      undefined,
    );

    assert.equal(response.success, true);
    assert.ok(
      calls.includes("updateFileContent"),
      "the write must still happen after a NOT_FOUND existence check",
    );
    assert.match(
      response.message,
      /successfully created/,
      "a NOT_FOUND check means this was a creation, not an overwrite",
    );
  });

  it("asks exactly once — a 404 is not retried", async () => {
    const { service, getFileContentCalls } = makeService("notFound");

    await processObsidianUpdateFile(
      makeParams(),
      makeContext(),
      service,
      undefined,
    );

    // Call 1 = existence check, call 2 = final-state read. A retried existence
    // check would push this to 4. Asking again cannot turn a 404 into a 200.
    assert.equal(getFileContentCalls(), 2);
  });

  it("refuses to create when createIfNeeded is false", async () => {
    const { service, calls } = makeService("notFound");

    await assert.rejects(
      processObsidianUpdateFile(
        makeParams({ createIfNeeded: false }),
        makeContext(),
        service,
        undefined,
      ),
      (error: unknown) =>
        error instanceof McpError && error.code === BaseErrorCode.NOT_FOUND,
    );

    assert.ok(
      !calls.includes("updateFileContent"),
      "nothing may be written when creation is disabled",
    );
  });
});

describe("update_file — existence check: existing-file path", () => {
  it("overwrites an existing file without claiming it was created", async () => {
    const { service, calls } = makeService("found");

    const response = await processObsidianUpdateFile(
      makeParams({ overwriteIfExists: true }),
      makeContext(),
      service,
      undefined,
    );

    assert.equal(response.success, true);
    assert.ok(calls.includes("updateFileContent"));
    assert.match(response.message, /successfully overwritten/);
    assert.doesNotMatch(response.message, /created/);
  });

  it("honours overwriteIfExists=false on an existing file", async () => {
    const { service, calls } = makeService("found");

    await assert.rejects(
      processObsidianUpdateFile(
        makeParams({ overwriteIfExists: false }),
        makeContext(),
        service,
        undefined,
      ),
      (error: unknown) =>
        error instanceof McpError && error.code === BaseErrorCode.CONFLICT,
    );

    assert.ok(
      !calls.includes("updateFileContent"),
      "the overwrite guard must block the write",
    );
  });
});

describe("update_file — existence check: unreachable vault", () => {
  it("aborts instead of treating SERVICE_UNAVAILABLE as absence", async () => {
    const { service, calls } = makeService("unavailable");

    await assert.rejects(
      processObsidianUpdateFile(
        makeParams(),
        makeContext(),
        service,
        undefined,
      ),
      (error: unknown) =>
        error instanceof McpError &&
        error.code === BaseErrorCode.SERVICE_UNAVAILABLE,
    );

    // The regression this guards: if an unreachable vault were folded into the
    // NOT_FOUND branch, existsBefore would go false and the tool would create
    // (or overwrite) a file it never actually looked at.
    assert.ok(
      !calls.includes("updateFileContent"),
      "an unreachable vault must never reach the write",
    );
  });

  it("does not retry an unreachable vault either", async () => {
    const { service, getFileContentCalls } = makeService("unavailable");

    await assert.rejects(
      processObsidianUpdateFile(
        makeParams(),
        makeContext(),
        service,
        undefined,
      ),
    );

    assert.equal(getFileContentCalls(), 1);
  });
});

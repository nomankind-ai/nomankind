/**
 * The worked example, checked the way a stranger would check it.
 *
 * Decision D-041: the demo checkpoint's own export is the repository's worked
 * example, and it lives at schema/examples/checkpoint/entry.json and
 * schema/examples/checkpoint/log.json. Those two files are written by a real
 * checkpoint run and committed as they came out; nothing here authors them, and
 * nothing here invents a stand-in when they are absent.
 *
 * Goals and non-goals, goal 4: "anyone can check the proof offline with two
 * files and one script". This test is that stranger, standing on the example
 * the README points at rather than on a generated fixture: it reads the two
 * files off disk, hands them to verifyOffline, and asks for a clean verdict.
 *
 * Before the checkpoint has run, the files do not exist and the test skips
 * under a name that says so. A skip is the honest answer to "the example is not
 * committed yet"; a failure would be the suite complaining about work that has
 * not been asked for, and a fabricated fixture would be worse than either.
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { verifyOffline } from "../src/verify.js";

const EXAMPLE_DIR = join(
  import.meta.dirname,
  "..",
  "schema",
  "examples",
  "checkpoint",
);
const ENTRY_PATH = join(EXAMPLE_DIR, "entry.json");
const LOG_PATH = join(EXAMPLE_DIR, "log.json");

/**
 * Read once, at collection time: `skipIf` wants a boolean before any test body
 * runs, and either file missing means there is no example to check.
 */
const MISSING = !existsSync(ENTRY_PATH) || !existsSync(LOG_PATH);

async function example(): Promise<{ entry: unknown; bundle: unknown }> {
  return {
    entry: JSON.parse(await readFile(ENTRY_PATH, "utf8")) as unknown,
    bundle: JSON.parse(await readFile(LOG_PATH, "utf8")) as unknown,
  };
}

describe("the committed checkpoint example (D-041)", () => {
  test.skipIf(MISSING)(
    "verifies entry.json against log.json with no diffs, or skips until schema/examples/checkpoint/ is committed",
    async () => {
      const { entry, bundle } = await example();
      const report = await verifyOffline(entry, bundle);

      // diffs first: a named diff says what is wrong, where `ok` only says that
      // something is.
      expect(report.diffs).toEqual([]);
      expect(report.ok).toBe(true);
    },
  );

  test.skipIf(MISSING)(
    "shows an entry the log has carried all the way to verified, or skips until schema/examples/checkpoint/ is committed",
    async () => {
      const { entry } = await example();

      expect((entry as Record<string, unknown>)["status"]).toBe("verified");
    },
  );
});

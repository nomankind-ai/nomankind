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
 *
 * The generator at the top writes the two files from a checkpoint run in
 * process, guarded exactly as the verify fixtures' generator is
 * (test/verify-fixtures.test.ts), so no derived field is ever authored by hand
 * and the keys are throwaways nobody keeps:
 *
 *   NOMANKIND_WRITE_CHECKPOINT_EXAMPLE=1 npm test -- checkpoint-example
 *
 * The demo's own export replaces what it writes at the next real checkpoint.
 */

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildExport } from "../src/cli/export.js";
import { CHECKPOINT_DOMAINS, runCheckpoint } from "../src/cli/checkpoint.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import { txtRecordName } from "../src/registry.js";
import { verifyOffline } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  makeAgent,
  type TestAgent,
} from "./helpers/registry.js";
import { FixtureFetcher, SUBMIT_NOW, type FixturePage } from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
} from "./helpers/witness.js";

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

/** The page the seeded entry cites, the same one M14's walk serves. */
const SEED_PAGE: FixturePage = {
  body: [
    "<!doctype html><html><head><title>example/demo-model</title></head>",
    "<body><main><h1>example/demo-model</h1>",
    "<p>90 requests per minute</p></main></body></html>",
  ].join(""),
  contentType: "text/html; charset=utf-8",
};

describe("the checkpoint example (generation)", () => {
  test.skipIf(!process.env["NOMANKIND_WRITE_CHECKPOINT_EXAMPLE"])(
    "writes entry.json and log.json from a checkpoint run in process",
    async () => {
      const { CHECKPOINT_CITATION } = await import("../src/cli/checkpoint.js");
      const pages: Record<string, FixturePage> = {
        [CHECKPOINT_CITATION]: SEED_PAGE,
      };
      const lines: string[] = [];
      const io: ValidatorIo = {
        stdout: (line: string) => lines.push(line),
        stderr: (line: string) => lines.push(`stderr ${line}`),
      };

      const store = await openTestDatabase();
      try {
        const maintainer: TestAgent = await makeAgent();
        const fixtures: TestAgent[] = [
          await makeAgent(),
          await makeAgent(),
          await makeAgent(),
        ];
        const records: Record<string, string[]> = {};
        CHECKPOINT_DOMAINS.forEach((domain, index) => {
          records[txtRecordName(domain)] = [fixtures[index]!.agentId];
        });

        const env: Env = {
          DB: store.db,
          CAPTURES: store.captures,
          ENVIRONMENT: "local",
          MAINTAINER_AGENT_ID: maintainer.agentId,
        };
        const deps: RequestDeps = {
          now: SUBMIT_NOW,
          dns: new FixtureResolver(records),
          payout: new MockPayoutAdapter(),
          fetcher: new FixtureFetcher(pages),
        };
        const http: HttpClient = {
          fetch: (request: Request) => handleRequest(request, env, deps),
        };

        const result = await runCheckpoint({
          baseUrl: TEST_ORIGIN,
          keys: { maintainer, fixtures },
          deps: {
            http,
            fetcher: new FixtureFetcher(pages),
            now: SUBMIT_NOW,
            io,
            outDir: null,
          },
        });
        expect(result.steps.filter((step) => !step.ok)).toEqual([]);

        // The seal is the sweep's, so the export is taken after it: the walk's
        // own bundle was built before any seal existed.
        const witness = await makeWitness("checkpoint-witness.example");
        const beacon = new FixtureBeacon("checkpoint-example");
        await beacon.advance(SUBMIT_NOW.toISOString());
        await runSweep(env, {
          now: SUBMIT_NOW,
          beacon,
          witness: new FakeWitnessAdapter({ signers: [witness] }),
          pinned: pinnedSet([witness]),
          ineligibleAgents: new Set([maintainer.agentId]),
          anchor: new FakeAnchorAdapter(null),
        });
        const sealed = await buildExport({
          baseUrl: TEST_ORIGIN,
          entryId: result.entryId as string,
          http,
          now: SUBMIT_NOW,
        });

        await writeFile(
          ENTRY_PATH,
          `${JSON.stringify(sealed.entry, null, 2)}\n`,
          "utf8",
        );
        await writeFile(
          LOG_PATH,
          `${JSON.stringify(sealed.bundle, null, 2)}\n`,
          "utf8",
        );

        // What was just written has to verify, or it is not a worked example.
        const report = await verifyOffline(sealed.entry, sealed.bundle);
        expect(report.diffs).toEqual([]);
        expect(report.ok).toBe(true);
      } finally {
        await store.dispose();
      }
    },
    180_000,
  );
});

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

/**
 * The M14 demo checkpoint, walked in process.
 *
 * Whitepaper, Conclusion: "The first falsifiable milestone is small and public:
 * three verified operators, none of them the maintainer's, promoting a seeded
 * entry to verified under the rules above." This file walks exactly that with
 * the real code: three fixture operators join through the real registry door and
 * are named by the real genesis power, the maintainer submits one seeded entry
 * with a bare key, the three fixture validators fetch the citation for
 * themselves and sign real nomankind-record-v1 decisions, the entry comes back
 * verified under the small-pool rule, the two files are exported from the
 * Worker's own routes, and the offline verifier answers ok on them with no
 * diffs.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with the migrations applied, the archive is miniflare's R2, the
 * keys are generated through WebCrypto and every signature is made by them, and
 * the http client is nothing but a call into the real router. Only the DNS
 * resolver, the payment provider and the page fetch are injected, because only
 * those are not ours to run in a test.
 *
 * Beside the walk are the unit tests for the two judgments the fixture validator
 * makes: the allowlist of predicate forms (D-031), and the snapshot rule.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  CHECKPOINT_CITATION,
  CHECKPOINT_DOMAINS,
  CHECKPOINT_SUBJECT,
  runCheckpoint,
  type CheckpointResult,
} from "../src/cli/checkpoint.js";
import {
  decidePredicate,
  decideSnapshot,
  fetchAndHash,
  judgeTest,
  parsePredicate,
  runValidator,
  SNAPSHOT_MISMATCH,
  type CaptureFacts,
  type HttpClient,
  type ValidatorIo,
} from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import { APPROVALS_TO_VERIFY_SMALL_POOL, NORM_VERSION } from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { verifyOffline } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  makeAgent,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

// ---------------------------------------------------------------------------
// The page the seeded entry cites
// ---------------------------------------------------------------------------

/** The seed page, served to the submit route and to every validator alike. */
const SEED_PAGE: FixturePage = {
  body: [
    "<!doctype html><html><head><title>example/demo-model</title></head>",
    "<body><main><h1>example/demo-model</h1>",
    "<p>90 requests per minute</p></main></body></html>",
  ].join(""),
  contentType: "text/html; charset=utf-8",
};

/** The same URL, saying something else: a source that moved under the entry. */
const CHANGED_PAGE: FixturePage = {
  body: [
    "<!doctype html><html><head><title>example/demo-model</title></head>",
    "<body><main><h1>example/demo-model</h1>",
    "<p>30 requests per minute</p></main></body></html>",
  ].join(""),
  contentType: "text/html; charset=utf-8",
};

const PAGES: Record<string, FixturePage> = { [CHECKPOINT_CITATION]: SEED_PAGE };
const CHANGED_PAGES: Record<string, FixturePage> = {
  [CHECKPOINT_CITATION]: CHANGED_PAGE,
};

/** Lines the checkpoint printed, kept so the walk can be read back. */
const lines: string[] = [];
const io: ValidatorIo = {
  stdout: (line: string) => lines.push(line),
  stderr: (line: string) => lines.push(`stderr ${line}`),
};

// ---------------------------------------------------------------------------
// The allowlist of predicate forms (D-031)
// ---------------------------------------------------------------------------

/** One capture, as a predicate sees it. */
const CAPTURE: CaptureFacts = {
  text: "example/demo-model\n\n90 requests per minute",
  status: 200,
};

/** A core with the seventeen keys, for the two pure judgments. */
function coreOf(overrides: Record<string, unknown> = {}): Core {
  return {
    id: "nmk_0123456789abcdef0123456789abcdef",
    subject: CHECKPOINT_SUBJECT,
    category: "limit",
    claim: "the cited page documents the request limit",
    before: "no documented request limit",
    after: "90 requests per minute",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CHECKPOINT_CITATION,
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "1F916:aaaa",
    author_operator: null,
    submitted_at: AT,
    ...overrides,
  } as Core;
}

/** An observed core carrying one proposed test. */
function observedCore(test: string, category = "limit"): Core {
  return coreOf({
    category,
    evidence_tier: "observed",
    observation: {
      method: "other",
      test,
      receipt_hash: `sha256:${"b".repeat(64)}`,
      observed_at: "2026-09-01",
      notes: "the fixture's own test",
    },
  });
}

describe("the allowlist of predicate forms", () => {
  it("reads each allowed form and decides it against a capture", () => {
    const contains = parsePredicate("contains:90 requests per minute");
    const absent = parsePredicate("absent:30 requests per minute");
    const status = parsePredicate("status:200");

    expect(contains).toEqual({ form: "contains", value: "90 requests per minute" });
    expect(absent).toEqual({ form: "absent", value: "30 requests per minute" });
    expect(status).toEqual({ form: "status", value: "200" });

    expect(decidePredicate(contains!, CAPTURE)).toBe(true);
    expect(decidePredicate(absent!, CAPTURE)).toBe(true);
    expect(decidePredicate(status!, CAPTURE)).toBe(true);
  });

  it("decides each allowed form false when it does not hold", () => {
    expect(
      decidePredicate(parsePredicate("contains:30 requests")!, CAPTURE),
    ).toBe(false);
    expect(
      decidePredicate(parsePredicate("absent:90 requests")!, CAPTURE),
    ).toBe(false);
    expect(decidePredicate(parsePredicate("status:404")!, CAPTURE)).toBe(false);
  });

  it("decides no text predicate against a capture with no extracted text", () => {
    const binary: CaptureFacts = { text: null, status: 200 };

    expect(decidePredicate(parsePredicate("contains:x")!, binary)).toBe(false);
    // Not "absent held": a predicate that could not be decided did not hold.
    expect(decidePredicate(parsePredicate("absent:x")!, binary)).toBe(false);
  });

  for (const unknown of [
    "matches:/90/",
    "the page should say 90 requests per minute",
    "contains:",
    ":90",
    "status:20",
    "status:abc",
  ]) {
    it(`refuses a predicate outside the allowlist: ${unknown}`, () => {
      expect(parsePredicate(unknown)).toBeNull();
    });
  }

  it("judges a stated entry as having no test at all", () => {
    expect(judgeTest(coreOf())).toEqual({ test_accepted: null, predicate: null });
  });

  it("accepts an observed test in the allowlist", () => {
    const judged = judgeTest(observedCore("contains:90 requests per minute"));

    expect(judged.test_accepted).toBe(true);
    expect(judged.predicate).toEqual({
      form: "contains",
      value: "90 requests per minute",
    });
  });

  it("does not accept an observed test outside the allowlist", () => {
    const judged = judgeTest(observedCore("ask the model and see what it says"));

    expect(judged.test_accepted).toBe(false);
    expect(judged.predicate).toBeNull();
  });

  for (const category of ["behavior", "misbehavior"]) {
    it(`never accepts a ${category} test: the fixture cannot run a model`, () => {
      const core = coreOf({
        category,
        evidence_tier: "observed",
        evidence: {
          model: "example/demo-model",
          prompt: "say ninety",
          parameters: null,
          predicate: "contains:90 requests per minute",
          observed_at: "2026-09-01",
          provider_statement: null,
        },
      });

      expect(judgeTest(core)).toEqual({ test_accepted: false, predicate: null });
    });
  }
});

describe("the snapshot rule", () => {
  it("approves when the validator's own hash is the entry's", () => {
    const core = coreOf();

    expect(decideSnapshot(core, core["snapshot_hash"] as string)).toEqual({
      decision: "approve",
      reason: null,
    });
  });

  it("rejects with snapshot_mismatch when the page has changed", () => {
    expect(decideSnapshot(coreOf(), `sha256:${"c".repeat(64)}`)).toEqual({
      decision: "reject",
      reason: SNAPSHOT_MISMATCH,
    });
  });

  it("hashes a fetched page exactly as the norm rule does", async () => {
    const fetched = await fetchAndHash(
      new FixtureFetcher(PAGES),
      CHECKPOINT_CITATION,
    );

    expect(fetched.ok).toBe(true);
    if (!fetched.ok) return;
    expect(fetched.snapshot.hash).toBe(await pageHash(SEED_PAGE));
    expect(fetched.snapshot.status).toBe(200);
    expect(fetched.snapshot.text).toContain("90 requests per minute");
  });
});

// ---------------------------------------------------------------------------
// The checkpoint itself
// ---------------------------------------------------------------------------

describe("the demo checkpoint, end to end", () => {
  let store: TestDatabase;
  let maintainer: TestAgent;
  let fixtures: TestAgent[];
  let env: Env;
  let deps: RequestDeps;
  let http: HttpClient;
  let result: CheckpointResult;

  beforeAll(async () => {
    store = await openTestDatabase();
    maintainer = await makeAgent();
    fixtures = [await makeAgent(), await makeAgent(), await makeAgent()];

    const records: Record<string, string[]> = {};
    CHECKPOINT_DOMAINS.forEach((domain, index) => {
      records[txtRecordName(domain)] = [fixtures[index]!.agentId];
    });

    env = {
      DB: store.db,
      CAPTURES: store.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: maintainer.agentId,
    };
    deps = {
      now: NOW,
      dns: new FixtureResolver(records),
      payout: new MockPayoutAdapter(),
      fetcher: new FixtureFetcher(PAGES),
    };
    http = { fetch: (request: Request) => handleRequest(request, env, deps) };

    result = await runCheckpoint({
      baseUrl: TEST_ORIGIN,
      keys: { maintainer, fixtures },
      deps: {
        http,
        fetcher: new FixtureFetcher(PAGES),
        now: NOW,
        io,
        outDir: null,
      },
    });
  }, 180_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("walks every step, and every step holds", () => {
    expect(result.steps.filter((step) => !step.ok)).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.entryId).toMatch(/^nmk_[A-Za-z0-9]+$/);
  });

  it("prints the TXT record each fixture operator needs, before it joins", () => {
    for (let index = 0; index < CHECKPOINT_DOMAINS.length; index += 1) {
      expect(lines).toContain(
        `txt _nomankind.${CHECKPOINT_DOMAINS[index]} TXT ${fixtures[index]!.agentId}`,
      );
    }
    // Printed before the first door is knocked on.
    expect(lines.indexOf(`txt _nomankind.${CHECKPOINT_DOMAINS[0]} TXT ${fixtures[0]!.agentId}`)).toBeLessThan(
      lines.findIndex((line) => line.includes("register ")),
    );
  });

  it("verifies the entry on two approvals, none of them the maintainer's", () => {
    const entry = result.entry as Record<string, unknown>;

    expect(validateEntry(entry).errors).toEqual([]);
    expect(entry["status"]).toBe("verified");
    const approvers = entry["approvers"] as { operator: string }[];
    expect(approvers).toHaveLength(APPROVALS_TO_VERIFY_SMALL_POOL);
    expect(approvers.map((record) => record.operator)).toEqual([
      CHECKPOINT_DOMAINS[0],
      CHECKPOINT_DOMAINS[1],
    ]);
    // The submitter is a bare key: it names no operator at all, so no approver
    // can be under the submitter's own.
    expect(entry["author_operator"]).toBeNull();
    expect(entry["author"]).toBe(maintainer.agentId);
  });

  it("treats the third validator's entry_closed as the rule working", () => {
    const third = result.steps.find((step) =>
      step.name === `validate ${CHECKPOINT_DOMAINS[2]}`,
    );

    expect(third?.ok).toBe(true);
    expect(third?.detail).toContain("entry_closed");
  });

  it("exports a bundle carrying the log, the registry and the capture", () => {
    const bundle = result.bundle!;
    const entry = result.entry as Record<string, unknown>;

    expect(bundle.as_of).toBe(AT);
    expect(bundle.events.length).toBeGreaterThan(0);
    // Seq order, from the start of the log, with the chain intact.
    expect(bundle.events[0]!.seq).toBe(0);
    expect(bundle.events[0]!.prev_hash).toBeNull();
    expect(Object.keys(bundle.registry.operators).sort()).toEqual(
      [...CHECKPOINT_DOMAINS].sort(),
    );
    expect(Object.keys(bundle.registry.agents)).toHaveLength(
      CHECKPOINT_DOMAINS.length,
    );
    expect(bundle.seals).toEqual([]);
    expect(bundle.captures[entry["snapshot_hash"] as string]).toBeDefined();
  });

  it("answers ok with zero diffs from the offline verifier", async () => {
    const report = await verifyOffline(result.entry, result.bundle);

    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(result.entryId);
    expect(result.report?.ok).toBe(true);
  });

  // -------------------------------------------------------------------------
  // The --assigned flag, and a page that moved, against a second seeded entry
  // -------------------------------------------------------------------------

  describe("a second entry, still open", () => {
    let secondId: string;

    beforeAll(async () => {
      const core = await submittedCore(maintainer, {
        subject: CHECKPOINT_SUBJECT,
        category: "limit",
        claim: "demo checkpoint seed: a second entry, for the assigned flag",
        before: "demo checkpoint seed: no documented request limit",
        after: "demo checkpoint seed: the cited page documents the limit",
        effective_at: "2026-09-02",
        citation: CHECKPOINT_CITATION,
        snapshot_hash: await pageHash(SEED_PAGE),
      });
      const response = await http.fetch(await submission(maintainer, { core }));
      expect(response.status).toBe(201);
      secondId = core["id"] as string;
    }, 60_000);

    it("refuses a claimed draw the operator does not hold", async () => {
      const run = await runValidator({
        baseUrl: TEST_ORIGIN,
        entryId: secondId,
        assigned: true,
        deps: {
          http,
          fetcher: new FixtureFetcher(PAGES),
          now: NOW,
          key: fixtures[0]!,
        },
        io,
      });

      // The flag is the operator's own claim, and the Worker refuses a wrong one.
      expect(run.record?.assigned_random).toBe(true);
      expect([run.status, run.error]).toEqual([
        422,
        "assigned_random_without_assignment",
      ]);
      expect(run.ok).toBe(false);
    });

    it("takes the same decision as a volunteer, with the flag false", async () => {
      const run = await runValidator({
        baseUrl: TEST_ORIGIN,
        entryId: secondId,
        deps: {
          http,
          fetcher: new FixtureFetcher(PAGES),
          now: NOW,
          key: fixtures[0]!,
        },
        io,
      });

      expect(run.record?.assigned_random).toBe(false);
      expect(run.record?.test_accepted).toBeNull();
      expect([run.status, run.decision]).toEqual([201, "approve"]);
      expect(run.ok).toBe(true);
    });

    it("rejects with snapshot_mismatch when the page has moved under it", async () => {
      const run = await runValidator({
        baseUrl: TEST_ORIGIN,
        entryId: secondId,
        deps: {
          http,
          // The same URL, saying something else.
          fetcher: new FixtureFetcher(CHANGED_PAGES),
          now: NOW,
          key: fixtures[1]!,
        },
        io,
      });

      expect([run.status, run.decision, run.reason]).toEqual([
        201,
        "reject",
        SNAPSHOT_MISMATCH,
      ]);
      expect(run.record?.snapshot_hash).toBe(await pageHash(CHANGED_PAGE));
      expect(run.ok).toBe(true);
    });
  });
});

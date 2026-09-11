/**
 * M24a end to end: the same fact filed twice, refused at the door (D-085).
 *
 * Whitepaper Section 6, "Submit". The rule under test is mechanical and small:
 * an entry whose domain, subject, category and normalized `after` value are
 * already held by a live entry — draft or verified — never enters the log. It
 * is refused before the citation is fetched, which is the point of putting the
 * check where it is: a duplicate that costs the log a capture has already cost
 * it something.
 *
 * Everything here is real except the network and the clock. Real Ed25519 keys,
 * the real router, miniflare's D1 with the migrations applied and miniflare's
 * R2, the real norm rule over real fixture bytes. Every refusal below asserts
 * that nothing moved: the head of the log, the entries row, the capture row,
 * the object in the archive, and the fixture fetcher's own request log.
 *
 * The dispute door asks the same question in its own order: it holds the check
 * back out of `prepareSubmission` and runs it after its filing refusals, so a
 * second challenge against one entry is still `dispute_open` (D-066). Reaching
 * the duplicate answer from outside therefore needs two separately verified
 * targets on one subject, which the last case below builds; the kernel's own
 * correction case is pinned in test/duplicate.test.ts.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import type { ApproverRecord } from "../src/events.js";
import { archiveAddress } from "../src/normalize.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { signCore } from "../src/sign.js";
import type { SubmissionProposal } from "../src/submit.js";
import {
  captureForHash,
  getEntry,
  headSeq,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  bytesOf,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m24a";

/** The three operators that validate here; the submitter stays a bare key. */
const OPERATORS = ["v1.example", "v2.example", "v3.example"];

// ---------------------------------------------------------------------------
// The page every citation points at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Merlin pricing</h1><p>$30 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://merlin.example/pricing";
const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

let PRICING_HASH = "";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;
let maintainer: TestAgent;
let alice: TestAgent;
let parties: Party[];

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);
  store = await openTestDatabase();
  maintainer = await makeAgent();
  alice = await makeAgent();

  parties = [];
  for (const operator of OPERATORS) {
    parties.push({ operator, agent: await makeAgent() });
  }

  const records: Record<string, string[]> = {};
  for (const party of parties) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  fetcher = new FixtureFetcher(PAGES);
  deps = {
    now: NOW,
    fetcher,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
  };

  for (const party of parties) {
    const joined = await send(
      await signedPost(party.agent, {
        path: "/operators",
        body: {
          operator: party.operator,
          attestation: await attestFor(party.agent, party.operator, AT),
          payout: { reference: VERIFIED_REFERENCE },
        },
        timestamp: AT,
      }),
    );
    expect([joined.status, party.operator]).toEqual([201, party.operator]);

    const named = await send(
      await signedPost(maintainer, {
        path: "/genesis",
        body: { operator: party.operator },
        timestamp: AT,
      }),
    );
    expect([named.status, party.operator]).toEqual([200, party.operator]);
  }
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function send(request: Request): Promise<Response> {
  return handleRequest(request, env, deps);
}

/**
 * A stated pricing proposal for one subject. `after` is the claim's value and
 * so the part of the duplicate key a test moves; `claim` moves with it only to
 * keep two entries' ids apart.
 */
function pricing(
  subject: string,
  overrides: Partial<Omit<SubmissionProposal, "author">> = {},
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing rose to $30 per seat per month`,
    before: "$25 per seat per month",
    after: "$30 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    ...overrides,
  };
}

/** Submit one entry through the door; it must be accepted as a draft. */
async function submit(
  proposal: Omit<SubmissionProposal, "author">,
): Promise<Core> {
  const core = await submittedCore(alice, proposal);
  const response = await send(await submission(alice, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  return core;
}

/** The schema's approvers[] item, signed by one validating party. */
function decision(
  party: Party,
  overrides: Partial<ApproverRecord> = {},
): ApproverRecord {
  return {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: PRICING_HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
    ...overrides,
  };
}

/** One signed decision, through the validate door. */
async function decide(
  entryId: string,
  party: Party,
  overrides: Partial<ApproverRecord> = {},
): Promise<Record<string, unknown>> {
  const record = decision(party, overrides);
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  const response = await send(
    await signedPost(party.agent, {
      path: `/entries/${entryId}/validate`,
      body: { record, signature },
      timestamp: AT,
    }),
  );
  const body = (await response.json()) as Record<string, unknown>;
  expect([response.status, body]).toEqual([201, expect.anything()]);
  return body;
}

/** Take an entry to verified on two approvals, under the small-pool rule. */
async function verify(core: Core): Promise<void> {
  const id = core["id"] as string;
  await decide(id, parties[0]!);
  const body = await decide(id, parties[1]!);
  expect(validateEntry(body).errors).toEqual([]);
  expect(body["status"]).toBe("verified");
}

/** Take an entry to rejected on two rejections. */
async function reject(core: Core): Promise<void> {
  const id = core["id"] as string;
  await decide(id, parties[0]!, {
    decision: "reject",
    reason: "the cited page does not carry this price",
    snapshot_hash: null,
  });
  const body = await decide(id, parties[1]!, {
    decision: "reject",
    reason: "the page says $30 for a different plan",
    snapshot_hash: null,
  });
  expect(validateEntry(body).errors).toEqual([]);
  expect(body["status"]).toBe("rejected");
}

/** The whole record a refusal must leave exactly where it found it. */
interface Trace {
  readonly head: number | null;
  readonly entry: boolean;
  readonly capture: boolean;
  readonly archived: boolean;
  readonly fetches: number;
}

async function trace(core: Core): Promise<Trace> {
  return {
    head: await headSeq(store.db),
    entry: (await getEntry(store.db, core["id"] as string)) !== null,
    capture:
      (await captureForHash(store.db, core["snapshot_hash"] as string)) !== null,
    archived:
      (await store.captures.head(await archiveAddress(bytesOf(PRICING)))) !==
      null,
    fetches: fetcher.requests.length,
  };
}

/**
 * Send a submission that must be refused as a duplicate, and prove it cost the
 * log nothing: no event, no row, no capture, and not even a fetch.
 */
async function refused(core: Core, duplicateOf: string): Promise<void> {
  const before = await trace(core);
  const response = await send(await submission(alice, { core }));
  const body = (await response.json()) as Record<string, unknown>;

  expect([response.status, body["error"], body["duplicate_of"]]).toEqual([
    422,
    "duplicate_claim",
    duplicateOf,
  ]);
  expect(await trace(core)).toEqual(before);
}

// ---------------------------------------------------------------------------

describe("a duplicate of a draft entry", () => {
  let first: Core;

  beforeAll(async () => {
    first = await submit(pricing("example/merlin-1"));
  }, 60_000);

  it("is refused, naming the entry that already holds the claim", async () => {
    const again = await submittedCore(
      alice,
      pricing("example/merlin-1", {
        claim: "example/merlin-1 is listed at $30 per seat per month",
      }),
    );
    // A different claim, so a different id: what repeats is the value.
    expect(again["id"]).not.toBe(first["id"]);
    await refused(again, first["id"] as string);
  }, 60_000);

  it("is refused even when the value differs only by whitespace", async () => {
    const spaced = await submittedCore(
      alice,
      pricing("example/merlin-1", {
        claim: "example/merlin-1 costs $30 per seat per month",
        after: "$30  per seat per month ",
      }),
    );
    await refused(spaced, first["id"] as string);
  }, 60_000);

  it("accepts a different value for the same subject", async () => {
    const other = await submit(
      pricing("example/merlin-1", {
        claim: "example/merlin-1 seat pricing rose to $35 per seat per month",
        after: "$35 per seat per month",
      }),
    );
    expect(other["id"]).not.toBe(first["id"]);
  }, 60_000);
});

describe("a duplicate of a verified entry", () => {
  let first: Core;

  beforeAll(async () => {
    first = await submit(pricing("example/merlin-2"));
    await verify(first);
  }, 120_000);

  it("is refused, naming the verified entry", async () => {
    const again = await submittedCore(
      alice,
      pricing("example/merlin-2", {
        claim: "example/merlin-2 is listed at $30 per seat per month",
      }),
    );
    await refused(again, first["id"] as string);
  }, 60_000);
});

describe("the same claim, filed as a supersession", () => {
  it("is accepted: superseding is the sanctioned way to refile", async () => {
    const first = await submit(pricing("example/merlin-3"));
    const again = await submittedCore(
      alice,
      pricing("example/merlin-3", {
        claim: "example/merlin-3 is still $30 per seat per month",
        supersedes: first["id"] as string,
      }),
    );
    const response = await send(await submission(alice, { core: again }));
    const body = (await response.json()) as Record<string, unknown>;
    expect([response.status, body["id"], body["status"]]).toEqual([
      201,
      again["id"],
      "draft",
    ]);
    expect(validateEntry(body).errors).toEqual([]);
  }, 120_000);
});

describe("a duplicate of a rejected entry", () => {
  it("is accepted: a fact may be refiled once its entry stops standing", async () => {
    const first = await submit(pricing("example/merlin-4"));
    await reject(first);

    const again = await submittedCore(
      alice,
      pricing("example/merlin-4", {
        claim: "example/merlin-4 is listed at $30 per seat per month",
      }),
    );
    const response = await send(await submission(alice, { core: again }));
    const body = (await response.json()) as Record<string, unknown>;
    expect([response.status, body["id"], body["status"]]).toEqual([
      201,
      again["id"],
      "draft",
    ]);
  }, 120_000);
});

describe("the dispute door, which asks the same question in its own order", () => {
  /** One correction of a target entry on this subject, carrying `after`. */
  function correction(
    subject: string,
    claim: string,
    after: string,
  ): Omit<SubmissionProposal, "author"> {
    return {
      subject,
      category: "correction",
      domain: DEFAULT_DOMAIN,
      claim,
      before: "$30 per seat per month",
      after,
      effective_at: "2026-09-02",
      citation: PRICING_URL,
      snapshot_hash: PRICING_HASH,
    };
  }

  /** File one signed correction against one target, as the bare key alice. */
  async function file(targetId: string, core: Core): Promise<Response> {
    const signature = await signCore(core, alice.privateKey);
    return send(
      await signedPost(alice, {
        path: `/entries/${targetId}/dispute`,
        body: { entry: { ...core, signature } },
        timestamp: AT,
      }),
    );
  }

  it("refuses a correction that duplicates a live correction", async () => {
    // Two verified entries on one subject, so two targets that can each take a
    // challenge of their own: a second challenge against one target is refused
    // `dispute_open` first (D-066), and that order is what this door keeps by
    // asking the duplicate question after its filing refusals rather than
    // inside the submission pipeline.
    const target = await submit(pricing("example/merlin-5"));
    await verify(target);
    const other = await submit(
      pricing("example/merlin-5", {
        claim: "example/merlin-5 seat pricing rose to $35 per seat per month",
        after: "$35 per seat per month",
      }),
    );
    await verify(other);

    const first = await submittedCore(
      alice,
      correction(
        "example/merlin-5",
        "example/merlin-5 is $40 per seat per month, not $30",
        "$40 per seat per month",
      ),
    );
    const filed = await file(target["id"] as string, first);
    expect([filed.status, await filed.json()]).toEqual([
      201,
      expect.anything(),
    ]);

    // The same value, a different claim, and a target with no open dispute of
    // its own: the filing refusals pass, and the duplicate rule answers.
    const again = await submittedCore(
      alice,
      correction(
        "example/merlin-5",
        "example/merlin-5 is really $40 per seat per month",
        "$40 per seat per month",
      ),
    );
    const response = await file(other["id"] as string, again);
    const body = (await response.json()) as Record<string, unknown>;
    expect([response.status, body["error"], body["duplicate_of"]]).toEqual([
      422,
      "duplicate_claim",
      first["id"],
    ]);
    expect(await getEntry(store.db, again["id"] as string)).toBeNull();
  }, 240_000);
});

describe("a subject holding more entries than one page", () => {
  // The defect this pins: the door used to read its candidates forward, oldest
  // first, and reverse one page of LIST_PAGE_LIMIT rows. Past a full page on
  // one domain, subject and category the newest live entries were never in the
  // page at all, so a duplicate of the newest one walked straight through. The
  // read is newest first now, and paged, so the newest is the first thing seen.
  const SUBJECT = "example/merlin-6";

  /** The claim's value at step n, distinct at every step. */
  function priced(n: number): string {
    return `$${40 + n} per seat per month`;
  }

  let newest: Core;

  beforeAll(async () => {
    // One more than a full page, all live drafts on one subject and category.
    // The real LIST_PAGE_LIMIT, not a smaller one passed in: the door takes no
    // page size of its own, and a number a test chose would not be the bound
    // the defect was about.
    for (let n = 0; n <= LIST_PAGE_LIMIT + 1; n += 1) {
      newest = await submit(
        pricing(SUBJECT, {
          claim: `${SUBJECT} seat pricing rose to ${priced(n)}`,
          after: priced(n),
        }),
      );
    }
  }, 600_000);

  it("refuses a duplicate of the newest, naming it", async () => {
    const value = priced(LIST_PAGE_LIMIT + 1);
    const again = await submittedCore(
      alice,
      pricing(SUBJECT, {
        claim: `${SUBJECT} is listed at ${value}`,
        after: value,
      }),
    );
    expect(again["id"]).not.toBe(newest["id"]);
    await refused(again, newest["id"] as string);
  }, 120_000);

  it("still refuses a duplicate of the oldest, a whole page down", async () => {
    // The other end of the same read: paging down reaches the first entry
    // filed, so a duplicate of it is refused too, naming it.
    const value = priced(0);
    const again = await submittedCore(
      alice,
      pricing(SUBJECT, {
        claim: `${SUBJECT} was listed at ${value}`,
        after: value,
      }),
    );
    const first = await submittedCore(
      alice,
      pricing(SUBJECT, {
        claim: `${SUBJECT} seat pricing rose to ${value}`,
        after: value,
      }),
    );
    await refused(again, first["id"] as string);
  }, 120_000);
});

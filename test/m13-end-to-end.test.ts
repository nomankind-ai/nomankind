/**
 * M13 end to end: submitting, from the outside, through the Worker.
 *
 * Whitepaper Section 6, "Submit": "An agent signs and submits an entry with a
 * citation. The source is snapshotted and hashed at that moment. The entry
 * appears immediately, marked draft." Section 5: "Anyone can submit with a bare
 * agent key." Both sentences are walked here by real keys against a real
 * migrated database and a real R2 bucket.
 *
 * Everything is real except the network. The requests are signed with generated
 * Ed25519 keys and verified by the Worker, the snapshot hashes are computed by
 * the real norm rule over real fixture bytes, the archive is miniflare's R2, the
 * database is miniflare's D1 with the migrations applied, and the entry that
 * comes back is checked against the published schema. Only the fetch is
 * injected, because only the network is not ours to run in a test, and the clock
 * is injected because nothing under src/ is allowed to read one.
 *
 * Every refusal below asserts that nothing was written: the head of the log, the
 * entries row, the capture row, and the object in the archive. That is the
 * property that matters most in this milestone. A refused submission that left a
 * capture behind would be a source pinned to an entry that does not exist.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  buildTranscriptArtifact,
  receiptArtifactHash,
  transcriptArtifactHash,
} from "../src/artifact.js";
import type { Core } from "../src/core.js";
import { canonicalize } from "../src/hash.js";
import { archiveAddress } from "../src/normalize.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import type { SubmissionProposal } from "../src/submit.js";
import { captureForHash, getEntry, headSeq } from "../src/storage/repository.js";
import type { R2Like } from "../src/storage/r2.js";
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
import { DEFAULT_DOMAIN } from "../src/policy.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** The operator a registered agent joins as, and a reference the mock passes. */
const OPERATOR = "kestrel-watch.example";
const VERIFIED_REFERENCE = "mock-verified-m13";

// ---------------------------------------------------------------------------
// The pages the citations point at
// ---------------------------------------------------------------------------

const HTML: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel-2 pricing</h1><p>$25 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const JSON_PAGE: FixturePage = {
  body: '{"model":"kestrel-2","seat_month_usd":25}',
  contentType: "application/json",
};
const MOVED: FixturePage = { body: "", location: "/pricing-final" };
const FINAL: FixturePage = {
  body: "<!doctype html><html><body><main><p>Kestrel-2 is $25 per seat per month</p></main></body></html>",
  contentType: "text/html",
};
/** A page whose content only a browser could show: the rule cannot pin it. */
const SCRIPT_ONLY: FixturePage = {
  body: '<!doctype html><html><body><script>document.write("$25")</script></body></html>',
  contentType: "text/html",
};
const LIMITS: FixturePage = {
  body: "<!doctype html><html><body><main><p>Kestrel-2 allows 60 requests per minute</p></main></body></html>",
  contentType: "text/html",
};

const HTML_URL = "https://kestrel.example/pricing";
const JSON_URL = "https://kestrel.example/pricing.json";
const MOVED_URL = "https://kestrel.example/moved";
const FINAL_URL = "https://kestrel.example/pricing-final";
const SCRIPT_URL = "https://kestrel.example/spa";
const LIMITS_URL = "https://kestrel.example/limits";

const PAGES: Record<string, FixturePage> = {
  [HTML_URL]: HTML,
  [JSON_URL]: JSON_PAGE,
  [MOVED_URL]: MOVED,
  [FINAL_URL]: FINAL,
  [SCRIPT_URL]: SCRIPT_ONLY,
  [LIMITS_URL]: LIMITS,
};

let store: TestDatabase;
let alice: TestAgent;
let bob: TestAgent;
let carol: TestAgent;
let maintainer: TestAgent;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;

let htmlHash: string;
let jsonHash: string;
let finalHash: string;
let limitsHash: string;

beforeAll(async () => {
  store = await openTestDatabase();
  [alice, bob, carol, maintainer] = await Promise.all([
    makeAgent(),
    makeAgent(),
    makeAgent(),
    makeAgent(),
  ]);

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
    dns: new FixtureResolver({ [txtRecordName(OPERATOR)]: [carol.agentId] }),
    payout: new MockPayoutAdapter(),
  };

  htmlHash = await pageHash(HTML);
  jsonHash = await pageHash(JSON_PAGE);
  finalHash = await pageHash(FINAL);
  limitsHash = await pageHash(LIMITS);
}, 60_000);

// getPlatformProxy runs a child process; vitest would hold the run open
// without this.
afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

async function send(
  request: Request,
  override: Partial<RequestDeps> = {},
): Promise<Response> {
  return handleRequest(request, env, { ...deps, ...override });
}

/** A stated pricing entry citing the HTML page: the plainest submission. */
function pricing(
  overrides: Partial<Omit<SubmissionProposal, "author">> = {},
): Omit<SubmissionProposal, "author"> {
  return {
    subject: "kestrel/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-2 seat pricing rose to $25 per seat per month",
    before: "$20 per seat per month",
    after: "$25 per seat per month",
    effective_at: "2026-09-01",
    citation: HTML_URL,
    snapshot_hash: htmlHash,
    ...overrides,
  };
}

/** The whole record, as a refusal must leave it. */
interface Trace {
  readonly head: number | null;
  readonly entry: boolean;
  readonly capture: boolean;
  readonly archived: boolean;
}

async function trace(core: Core, page: FixturePage): Promise<Trace> {
  // The hash the entry claims, and the address its capture would be stored at:
  // a refusal must leave neither behind.
  return {
    head: await headSeq(store.db),
    entry: (await getEntry(store.db, core["id"] as string)) !== null,
    capture:
      (await captureForHash(store.db, core["snapshot_hash"] as string)) !== null,
    archived:
      (await store.captures.head(await archiveAddress(bytesOf(page)))) !== null,
  };
}

/** Send a request that must be refused, and prove it wrote nothing at all. */
async function refused(
  input: { core: Core; receipt?: unknown; signer?: TestAgent; page: FixturePage },
  status: number,
  error: string,
  author: TestAgent = alice,
): Promise<unknown> {
  const before = await trace(input.core, input.page);
  const response = await send(
    await submission(author, {
      core: input.core,
      receipt: input.receipt,
      signer: input.signer,
    }),
  );
  const body = await response.json();

  expect(response.status).toBe(status);
  expect((body as { error: string }).error).toBe(error);
  expect(await trace(input.core, input.page)).toEqual(before);
  return body;
}

// ---------------------------------------------------------------------------

describe("a stated entry citing an HTML page", () => {
  let core: Core;
  let created: Record<string, unknown>;

  beforeAll(async () => {
    core = await submittedCore(alice, pricing());
    const response = await send(await submission(alice, { core }));
    expect(response.status).toBe(201);
    expect(response.headers.get("location")).toBe(`/entries/${core["id"]}`);
    expect(response.headers.get("cache-control")).toBe("no-store");
    created = (await response.json()) as Record<string, unknown>;
  });

  it("answers with a valid entry, marked draft", () => {
    const validation = validateEntry(created);
    expect(validation.errors).toEqual([]);
    expect(validation.ok).toBe(true);
    expect(created["id"]).toBe(core["id"]);
    expect(created["status"]).toBe("draft");
    expect(created["seal"]).toBeNull();
    expect(created["approvers"]).toEqual([]);
    // Derived, not sent: the submitter proposed neither of these.
    expect(created["last_confirmed"]).toBe("2026-09-08");
    expect(created["staleness_window_days"]).toBe(90);
  });

  it("submitted with a bare agent key, so the entry names no operator", () => {
    expect(created["author"]).toBe(alice.agentId);
    expect(created["author_operator"]).toBeNull();
  });

  it("serves the entry back at its own URL", async () => {
    const response = await send(get(`/entries/${core["id"] as string}`));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(created);
  });

  it("serves the capture at the entry's snapshot hash", async () => {
    const response = await send(get(`/captures/${htmlHash}`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-nomankind-archive-hash")).toBe(
      await archiveAddress(bytesOf(HTML)),
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytesOf(HTML));
  });

  it("serves that capture inert, so an archived page cannot run at our origin", async () => {
    // Anyone can submit with a bare key, and what they cite is archived raw:
    // this HTML is a stranger's bytes served from demo.nomankind.ai.
    const response = await send(get(`/captures/${htmlHash}`));
    const archiveHash = await archiveAddress(bytesOf(HTML));

    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="${archiveHash.slice("sha256:".length)}"`,
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toBe(
      "default-src 'none'; sandbox",
    );
  });

  it("records the fetch in the sidecar beside it", async () => {
    const response = await send(get(`/captures/${htmlHash}/sidecar`));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      final_url: HTML_URL,
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
      fetched_at: AT,
      fetcher: maintainer.agentId,
    });
  });

  it("refuses the very same entry a second time", async () => {
    const response = await send(await submission(alice, { core }));
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "duplicate_entry" });
  });
});

describe("other citations", () => {
  it("pins a JSON citation and archives it under its own media type", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 seat pricing is published as $25 per seat per month",
        citation: JSON_URL,
        snapshot_hash: jsonHash,
      }),
    );
    expect((await send(await submission(alice, { core }))).status).toBe(201);

    const response = await send(get(`/captures/${jsonHash}`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.text()).toBe(JSON_PAGE.body);
  });

  it("follows a redirect and records where the bytes actually came from", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 pricing moved to a new page and says $25 per seat",
        citation: MOVED_URL,
        snapshot_hash: finalHash,
      }),
    );
    expect((await send(await submission(alice, { core }))).status).toBe(201);

    const response = await send(get(`/captures/${finalHash}/sidecar`));
    expect(await response.json()).toMatchObject({
      final_url: FINAL_URL,
      status: 200,
      fetcher: maintainer.agentId,
    });
  });
});

describe("the door refuses before it writes", () => {
  it("refuses a page that needs JavaScript, with the norm rule's own reason", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 pricing is rendered in the browser and says $25",
        citation: SCRIPT_URL,
        snapshot_hash: `sha256:${"5c".repeat(32)}`,
      }),
    );
    await refused({ core, page: SCRIPT_ONLY }, 422, "needs_javascript");
  });

  it("refuses a hash that is not the hash of the cited page", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, cited with the wrong hash",
        citation: LIMITS_URL,
        snapshot_hash: `sha256:${"7d".repeat(32)}`,
      }),
    );
    await refused({ core, page: LIMITS }, 422, "snapshot_mismatch");
  });

  it("refuses a citation that is not an http URL", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, cited from a file",
        citation: "file:///etc/prices",
      }),
    );
    await refused({ core, page: HTML }, 422, "unsupported_citation");
  });

  it("refuses an entry the schema rejects, and names the field", async () => {
    // Not the category: since v0.7 the submission gate refuses a category
    // outside the entry's domain (`category_not_in_domain`) before the schema
    // is consulted at all, and today's one registered domain admits exactly the
    // schema's enum -- so a bad category never reaches the schema. A malformed
    // date does, and the refusal still names the field it failed on.
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, dated in no calendar at all",
        effective_at: "the first of September",
        citation: LIMITS_URL,
        snapshot_hash: limitsHash,
      }),
    );
    const body = (await refused(
      { core, page: LIMITS },
      422,
      "schema_invalid",
    )) as { errors: { path: string }[] };
    expect(body.errors.map((error) => error.path)).toContain("/effective_at");
  });

  it("refuses a category the entry's domain does not admit", async () => {
    // Decision D-071: which categories a domain admits is the registry
    // document's table, application-enforced, and the refusal comes before any
    // fetch or write.
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, filed under no category at all",
        category: "gossip",
        citation: LIMITS_URL,
        snapshot_hash: limitsHash,
      }),
    );
    await refused({ core, page: LIMITS }, 422, "category_not_in_domain");
  });

  it("refuses an unsigned request", async () => {
    const core = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 costs $25 per seat, sent by nobody" }),
    );
    const before = await headSeq(store.db);
    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, {
        method: "POST",
        body: JSON.stringify({ entry: { ...core, signature: "x" } }),
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "missing_header" });
    expect(await headSeq(store.db)).toBe(before);
  });

  it("refuses a request signed by a key other than the author", async () => {
    const core = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 costs $25 per seat, submitted by someone else" }),
    );
    await refused({ core, page: HTML, signer: bob }, 403, "author_mismatch");
  });

  it("refuses a body whose entry is not exactly the core and its signature", async () => {
    const core = await submittedCore(alice, pricing());
    const request = await signedPost(alice, {
      path: "/entries",
      body: { entry: { ...core, signature: "x", status: "verified" } },
      timestamp: AT,
    });

    const response = await send(request);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_body" });
  });

  it("spends the nonce even on a refusal, so no refused write can be replayed", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, cited with a hash from nowhere",
        snapshot_hash: `sha256:${"4b".repeat(32)}`,
      }),
    );
    const nonce = "m13-refused-once";

    const first = await send(await submission(alice, { core, nonce }));
    expect([first.status, await first.json()]).toEqual([
      422,
      { error: "snapshot_mismatch" },
    ]);

    // The very same signed request again: the nonce was spent by the request
    // that was refused on its contents, so the replay never reaches them.
    const replay = await send(await submission(alice, { core, nonce }));
    expect([replay.status, await replay.json()]).toEqual([
      401,
      { error: "replay" },
    ]);
  });

  it("refuses a receipt on an entry that receipts nothing", async () => {
    const core = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 costs $25 per seat, with a receipt nobody asked for" }),
    );
    await refused(
      { core, page: HTML, receipt: { method: "metered_call" } },
      400,
      "bad_body",
    );
  });
});

describe("supersession", () => {
  let target: Core;

  beforeAll(async () => {
    target = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 seat pricing was $22 per seat per month" }),
    );
    expect((await send(await submission(alice, { core: target }))).status).toBe(201);
  });

  it("refuses a supersession of an entry that does not exist", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, replacing an entry nobody wrote",
        supersedes: "nmk_00000000000000000000000000000000",
      }),
    );
    await refused({ core, page: HTML }, 422, "target_missing");
  });

  it("refuses a supersession across categories", async () => {
    const limit = await submittedCore(
      alice,
      pricing({
        category: "limit",
        claim: "Kestrel-2 allows 60 requests per minute",
        before: "30 requests per minute",
        after: "60 requests per minute",
        citation: LIMITS_URL,
        snapshot_hash: limitsHash,
      }),
    );
    expect((await send(await submission(alice, { core: limit }))).status).toBe(201);

    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, replacing a rate limit",
        supersedes: limit["id"] as string,
      }),
    );
    await refused({ core, page: HTML }, 422, "category_mismatch");
  });

  it("accepts a supersession that shares its target's subject and category", async () => {
    const core = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 seat pricing rose again, to $25 per seat per month",
        supersedes: target["id"] as string,
      }),
    );
    const response = await send(await submission(alice, { core }));

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["supersedes"]).toBe(target["id"]);
    // The old entry is not touched: a superseder flips it only once it has
    // verified, and that is derivation's answer, not this route's.
    const stored = await getEntry(store.db, target["id"] as string);
    expect(stored!.entry["superseded_by"]).toBeNull();
  });
});

describe("the operator behind the key", () => {
  beforeAll(async () => {
    const registration = await signedPost(carol, {
      path: "/operators",
      body: {
        operator: OPERATOR,
        attestation: await attestFor(carol, OPERATOR, AT),
        payout: { reference: VERIFIED_REFERENCE },
      },
      timestamp: AT,
    });
    expect((await send(registration)).status).toBe(201);
  });

  it("snapshots the operator into the signed core of a registered agent", async () => {
    const core = await submittedCore(
      carol,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, submitted under an operator",
        author_operator: OPERATOR,
      }),
    );
    const response = await send(await submission(carol, { core }));

    expect(response.status).toBe(201);
    expect((await response.json() as Record<string, unknown>)["author_operator"]).toBe(
      OPERATOR,
    );
  });

  it("refuses an operator the registry does not put behind the key", async () => {
    const core = await submittedCore(
      bob,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, claimed under someone else's operator",
        author_operator: OPERATOR,
      }),
    );
    await refused({ core, page: HTML }, 422, "author_operator_mismatch", bob);
  });

  it("lets a bare agent key submit, and names no operator", async () => {
    const core = await submittedCore(
      bob,
      pricing({ claim: "Kestrel-2 costs $25 per seat, submitted with a bare key" }),
    );
    const response = await send(await submission(bob, { core }));

    expect(response.status).toBe(201);
    expect((await response.json() as Record<string, unknown>)["author_operator"]).toBeNull();
  });
});

describe("a behavior entry, whose snapshot is its frozen transcript", () => {
  const evidence = {
    model: "kestrel/kestrel-2",
    prompt: "What is the capital of France?",
    parameters: { temperature: 0 },
    output: "I cannot help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
  };
  const artifact = buildTranscriptArtifact(
    evidence,
    evidence.output,
    evidence.observed_at,
  );

  let core: Core;

  beforeAll(async () => {
    const hashed = await transcriptArtifactHash(artifact);
    if (!hashed.ok) throw new Error("m13: the fixture transcript is refused");
    core = await submittedCore(alice, {
      subject: "kestrel/kestrel-2",
      category: "behavior",
      claim: "Kestrel-2 refuses a plain factual question",
      before: "answered the question",
      after: "refuses the question",
      effective_at: "2026-09-01",
      evidence,
      citation: "https://kestrel.example/transcripts/1",
      snapshot_hash: hashed.hash,
    });
  });

  it("accepts it without fetching the citation at all", async () => {
    const asked = fetcher.requests.length;
    const response = await send(await submission(alice, { core }));

    expect(response.status).toBe(201);
    expect(fetcher.requests.length).toBe(asked);
    const body = (await response.json()) as Record<string, unknown>;
    expect(validateEntry(body).ok).toBe(true);
    expect(body["evidence_tier"]).toBe("observed");
  });

  it("archives the canonical artifact at the entry's snapshot hash", async () => {
    const response = await send(
      get(`/captures/${core["snapshot_hash"] as string}`),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.text()).toBe(canonicalize(artifact));
  });

  it("says nobody fetched it, rather than inventing a provenance", async () => {
    const response = await send(
      get(`/captures/${core["snapshot_hash"] as string}/sidecar`),
    );
    expect(await response.json()).toEqual({
      final_url: null,
      status: null,
      headers: {},
      fetched_at: AT,
      fetcher: maintainer.agentId,
    });
  });
});

describe("an observed entry, whose measurement is receipted", () => {
  const receipt = {
    method: "probe_to_limit",
    subject: "kestrel/kestrel-2",
    test: "POST /v1/messages until a 429 comes back; holds if the limit is 60 per minute",
    request: {
      url: "https://api.kestrel.example/v1/messages",
      headers: { authorization: "[REDACTED]" },
    },
    response: { status: 429, body: { error: "rate_limit", limit: 60 } },
    billing: null,
    observed_at: "2026-09-07",
    observer: "1F916:probe",
  };

  let core: Core;

  beforeAll(async () => {
    const hashed = await receiptArtifactHash(receipt);
    if (!hashed.ok) throw new Error("m13: the fixture receipt is refused");
    core = await submittedCore(alice, {
      subject: "kestrel/kestrel-2",
      category: "limit",
      claim: "Kestrel-2 allows 60 requests per minute, measured by probing",
      before: "30 requests per minute",
      after: "60 requests per minute",
      effective_at: "2026-09-01",
      evidence_tier: "observed",
      observation: {
        method: "probe_to_limit",
        test: receipt.test,
        receipt_hash: hashed.hash,
        observed_at: "2026-09-07",
        notes: null,
      },
      citation: LIMITS_URL,
      snapshot_hash: limitsHash,
    });
  });

  it("refuses the submission when the receipt itself is not sent", async () => {
    await refused({ core, page: LIMITS }, 422, "missing_receipt");
  });

  it("accepts it with the receipt, and archives both captures", async () => {
    const response = await send(await submission(alice, { core, receipt }));
    expect(response.status).toBe(201);
    expect(validateEntry(await response.json()).ok).toBe(true);

    const page = await send(get(`/captures/${limitsHash}`));
    expect(page.status).toBe(200);
    expect(new Uint8Array(await page.arrayBuffer())).toEqual(bytesOf(LIMITS));

    const observation = core["observation"] as { receipt_hash: string };
    const stored = await send(get(`/captures/${observation.receipt_hash}`));
    expect(stored.status).toBe(200);
    expect(await stored.text()).toBe(canonicalize(receipt));
  });

  it("refuses a receipt that is not the one the core names", async () => {
    const other = await submittedCore(
      alice,
      pricing({
        claim: "Kestrel-2 costs $25 per seat, measured against another receipt",
        evidence_tier: "observed",
        observation: {
          method: "metered_call",
          test: "buy one seat and read the invoice line",
          receipt_hash: `sha256:${"3e".repeat(32)}`,
          observed_at: "2026-09-07",
          notes: null,
        },
      }),
    );
    await refused({ core: other, receipt, page: HTML }, 422, "receipt_mismatch");
  });
});

describe("the reads", () => {
  it("refuses an id that is not an entry id, before it asks the database", async () => {
    const response = await send(get("/entries/not-an-id"));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_id" });
  });

  it("answers 404 for an entry that was never submitted", async () => {
    const response = await send(get("/entries/nmk_11111111111111111111111111111111"));
    expect(response.status).toBe(404);
  });

  it("refuses a capture address that is not a hash", async () => {
    const response = await send(get("/captures/sha256:nope"));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_hash" });
  });

  it("answers 404 for a hash nothing was captured under", async () => {
    const response = await send(get(`/captures/sha256:${"0f".repeat(32)}`));
    expect(response.status).toBe(404);
    const sidecar = await send(get(`/captures/sha256:${"0f".repeat(32)}/sidecar`));
    expect(sidecar.status).toBe(404);
  });

  it("names the methods each route takes", async () => {
    const post = await send(
      new Request(`${TEST_ORIGIN}/captures/${htmlHash}`, { method: "POST" }),
    );
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");

    const wrong = await send(new Request(`${TEST_ORIGIN}/entries`, { method: "DELETE" }));
    expect(wrong.status).toBe(405);
    expect(wrong.headers.get("allow")).toBe("POST");
  });
});

describe("an environment shaped like production", () => {
  it("takes no capture at all when no fetcher identity is configured", async () => {
    const unconfigured: Env = { ...env, MAINTAINER_AGENT_ID: "" };
    const quiet = new FixtureFetcher(PAGES);
    const core = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 costs $25 per seat, filed at an unconfigured deployment" }),
    );

    const before = await headSeq(store.db);
    const response = await handleRequest(
      await submission(alice, { core }),
      unconfigured,
      { ...deps, fetcher: quiet },
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "fetcher_not_configured" });
    // Before any fetch: an unconfigured maintainer cannot stand behind a
    // capture, so none is taken.
    expect(quiet.requests).toEqual([]);
    expect(await headSeq(store.db)).toBe(before);
  });

  it("answers 503 rather than a raw 500 when the archive does not answer", async () => {
    const broken = (): Promise<never> =>
      Promise.reject(new Error("R2 is unreachable"));
    const unreachable: Env = {
      ...env,
      CAPTURES: { put: broken, get: broken, head: broken } as unknown as R2Like,
    };
    const core = await submittedCore(
      alice,
      pricing({ claim: "Kestrel-2 costs $25 per seat, filed against a broken archive" }),
    );

    const before = await headSeq(store.db);
    const response = await handleRequest(
      await submission(alice, { core }),
      unreachable,
      deps,
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "archive_unreachable" });
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
    expect(await headSeq(store.db)).toBe(before);
  });
});

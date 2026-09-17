/**
 * The ceilings on what a signed core may carry, and the capture ceiling at the
 * door.
 *
 * The QA of 2026-09-12: the signed core's text had no length ceiling at all — a
 * one-megabyte claim and four hundred levels of nesting were accepted and sealed
 * — and `CAPTURE_MAX_BYTES` was enforced inside the HTTP adapter and nowhere
 * else, so the rule held for the one fetcher that obeys it and for no other.
 * Both are the log's rules rather than an adapter's, so both are checked here:
 * the ceilings as a pure function of a core (src/submit.ts), applied at the door
 * before anything is fetched, and the capture ceiling on the bytes that actually
 * came back.
 *
 * No schema change: every entry already in the log stays valid and readable
 * exactly as it is. No policy number lives here either — the ceilings are
 * CORE_TEXT_MAX_CHARS's, EVIDENCE_MAX_BYTES's and CAPTURE_MAX_BYTES's.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { canonicalize } from "../src/hash.js";
import {
  CAPTURE_MAX_BYTES,
  CORE_TEXT_MAX_CHARS,
  DEFAULT_DOMAIN,
  EVIDENCE_MAX_BYTES,
} from "../src/policy.js";
import { getEntry } from "../src/storage/repository.js";
import {
  CORE_OBJECT_FIELDS,
  CORE_TEXT_FIELDS,
  buildSubmittedCore,
  checkCoreSize,
  type SubmissionProposal,
} from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { FixtureResolver, makeAgent, type TestAgent } from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_CLOCK,
  SUBMIT_NOW,
  pageHash,
  submittedCore,
  submission,
  type FixturePage,
} from "./helpers/submit.js";

const NOW = SUBMIT_NOW;

const PRICING_URL = "https://kestrel.example/pricing";
const HUGE_URL = "https://kestrel.example/huge";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Pricing</h1></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

/**
 * A page one byte over the capture ceiling, which is what the fixture fetcher
 * hands back untouched: the adapter's own check is not in the way here, which
 * is the point — the door has to make it too.
 */
const HUGE_PAGE: FixturePage = {
  body: new Uint8Array(CAPTURE_MAX_BYTES + 1).fill(0x61),
  contentType: "text/plain; charset=utf-8",
};

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;
let author: TestAgent;
let snapshot: string;

/** The proposal every case below starts from: the plainest valid submission. */
function proposal(
  overrides: Partial<SubmissionProposal> = {},
): Omit<SubmissionProposal, "author" | "domain"> & { domain?: string } {
  return {
    subject: "example/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-2 seat pricing rose to $25 per seat per month",
    before: "$20 per seat per month",
    after: "$25 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: snapshot,
    ...overrides,
  };
}

beforeAll(async () => {
  store = await openTestDatabase();
  author = await makeAgent();
  fetcher = new FixtureFetcher({
    [PRICING_URL]: PAGE,
    [HUGE_URL]: HUGE_PAGE,
  });
  snapshot = await pageHash(PAGE);
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: (await makeAgent()).agentId,
    SEALING_AGENT_KEY: "",
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver({}),
    fetcher,
  };
});

afterAll(async () => {
  await store.dispose();
});

describe("checkCoreSize", () => {
  it("accepts a core at the ceilings exactly", async () => {
    const core = await buildSubmittedCore(
      {
        ...proposal({ claim: "c".repeat(CORE_TEXT_MAX_CHARS) }),
        domain: DEFAULT_DOMAIN,
        author: author.agentId,
      },
      SUBMIT_CLOCK,
    );

    expect(checkCoreSize(core)).toEqual({ ok: true });
  });

  it("names the field that is too long, one field at a time", async () => {
    for (const field of CORE_TEXT_FIELDS) {
      const core = await buildSubmittedCore(
        {
          ...proposal({ [field]: "c".repeat(CORE_TEXT_MAX_CHARS + 1) }),
          domain: DEFAULT_DOMAIN,
          author: author.agentId,
        },
        SUBMIT_CLOCK,
      );

      expect(checkCoreSize(core)).toEqual({
        ok: false,
        reason: "core_too_large",
        field,
      });
    }
  });

  it("measures evidence and observation over their canonical bytes", async () => {
    for (const field of CORE_OBJECT_FIELDS) {
      const fat = { note: "n".repeat(EVIDENCE_MAX_BYTES) };
      expect(canonicalize(fat).length).toBeGreaterThan(EVIDENCE_MAX_BYTES);

      const core = await buildSubmittedCore(
        {
          ...proposal({ [field]: fat }),
          domain: DEFAULT_DOMAIN,
          author: author.agentId,
        },
        SUBMIT_CLOCK,
      );

      expect(checkCoreSize(core)).toEqual({
        ok: false,
        reason: "core_too_large",
        field,
      });
    }
  });

  it("passes a core whose nullable objects are null", async () => {
    const core = await buildSubmittedCore(
      { ...proposal(), domain: DEFAULT_DOMAIN, author: author.agentId },
      SUBMIT_CLOCK,
    );

    expect(core["evidence"]).toBeNull();
    expect(core["observation"]).toBeNull();
    expect(checkCoreSize(core)).toEqual({ ok: true });
  });
});

describe("POST /entries applies the ceilings before it fetches anything", () => {
  it("refuses a 5,000-character claim core_too_large, naming the field", async () => {
    const core = await submittedCore(author, {
      ...proposal({ claim: "c".repeat(5000) }),
    });
    const seenBefore = fetcher.requests.length;

    const response = await handleRequest(
      await submission(author, { core }),
      env,
      deps,
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({
      error: "core_too_large",
      field: "claim",
    });
    // Before the fetch, which is the whole point: an entry too big to keep
    // forever costs the log no outbound request, no capture and no row.
    expect(fetcher.requests.length).toBe(seenBefore);
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
  });

  it("refuses an oversized evidence object the same way", async () => {
    const core = await submittedCore(author, {
      ...proposal({
        evidence: { note: "n".repeat(EVIDENCE_MAX_BYTES) },
        evidence_tier: "stated",
      }),
    });
    const seenBefore = fetcher.requests.length;

    const response = await handleRequest(
      await submission(author, { core }),
      env,
      deps,
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({
      error: "core_too_large",
      field: "evidence",
    });
    expect(fetcher.requests.length).toBe(seenBefore);
  });

  it("accepts a claim at the ceiling", async () => {
    const core = await submittedCore(author, {
      ...proposal({ claim: "c".repeat(CORE_TEXT_MAX_CHARS) }),
    });

    const response = await handleRequest(
      await submission(author, { core }),
      env,
      deps,
    );

    expect(response.status).toBe(201);
  });
});

describe("the capture ceiling is the log's, not the adapter's", () => {
  it("refuses a capture one byte over CAPTURE_MAX_BYTES, writing nothing", async () => {
    const core = await submittedCore(author, {
      ...proposal({
        citation: HUGE_URL,
        after: "$26 per seat per month",
        // The hash is never reached: the bytes are refused before they are
        // hashed, which is what stops a gigabyte being hashed to find out.
        snapshot_hash: `sha256:${"a1".repeat(32)}`,
      }),
    });

    const response = await handleRequest(
      await submission(author, { core }),
      env,
      deps,
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "too_large" });
    expect(fetcher.requests).toContain(HUGE_URL);
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
  });
});

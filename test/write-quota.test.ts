/**
 * The write quota, through the real Worker on a real miniflare D1.
 *
 * The QA of 2026-09-12: `POST /entries` was uncapped for any self-generated
 * key, and every call was a fetch of a caller-chosen URL of up to ten
 * mebibytes, two R2 writes and a draft row forever. Section 5 says anyone may
 * submit with a bare agent key and Section 9 prices spam through the paid loop,
 * and both are still true — what was missing is the ceiling that makes a free
 * key finite. Two buckets: one keyed by the agent that signed, one keyed by the
 * client that called, because a key costs nothing to mint and the first bucket
 * alone bounds nobody who can mint a fresh one per request.
 *
 * Charged after the signature verifies and before any fetch, DNS lookup,
 * archive write or derivation — which is what the counting fetcher here is for:
 * a refused write must reach the network no more than a refused signature does.
 *
 * Every key here is a bare one, and decision D-130 charges a bare key at the
 * probationary per-agent cap: it is nobody's operator, so it is nobody's
 * established one. The per-agent numbers below are that cap's, and
 * test/standing-tiers.test.ts is where the three tiers are told apart.
 *
 * No policy number lives here: the caps are WRITES_PER_AGENT_PER_DAY_PROBATION's
 * and WRITES_PER_CLIENT_PER_DAY's, and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { utcDay } from "../src/anchor.js";
import {
  DEFAULT_DOMAIN,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_CLIENT_PER_DAY,
} from "../src/policy.js";
import { addQuota, quotaOn } from "../src/storage/keys.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import {
  writeScopeForAgent,
  writeScopeForClient,
} from "../src/worker/registry.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submittedCore,
  submission,
  type FixturePage,
} from "./helpers/submit.js";

const NOW = SUBMIT_NOW;
const DAY = utcDay(NOW.toISOString());

const PRICING_URL = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Pricing</h1></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;
let author: TestAgent;
let other: TestAgent;
let third: TestAgent;
let maintainer: TestAgent;
let snapshot: string;

/** Both scopes one call from `author` with no client address is counted under. */
let agentScope: string;
let clientScope: string;

beforeAll(async () => {
  store = await openTestDatabase();
  author = await makeAgent();
  other = await makeAgent();
  third = await makeAgent();
  maintainer = await makeAgent();
  fetcher = new FixtureFetcher({ [PRICING_URL]: PAGE });
  snapshot = await pageHash(PAGE);
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: "",
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver({}),
    fetcher,
  };
  agentScope = writeScopeForAgent(author.agentId);
  clientScope = await writeScopeForClient(
    new Request(`${TEST_ORIGIN}/entries`, { method: "POST" }),
  );
});

afterAll(async () => {
  await store.dispose();
});

function send(request: Request): Promise<Response> {
  return handleRequest(request, env, deps);
}

/**
 * One signed submission, distinct from every other by the value it claims, so
 * nothing here is refused as a duplicate of the one before it (D-085): the
 * duplicate key is the normalized value and not the prose around it.
 */
let filings = 0;

async function submit(
  claim: string,
  signer: TestAgent = author,
): Promise<Response> {
  filings += 1;
  const core = await submittedCore(signer, {
    subject: "example/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$20 per seat per month",
    after: `$${20 + filings} per seat per month`,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: snapshot,
  });
  return send(await submission(signer, { core }));
}

/** What each bucket has spent today. */
async function spent(): Promise<{ agent: number; client: number }> {
  return {
    agent: await quotaOn(store.db, agentScope, DAY),
    client: await quotaOn(store.db, clientScope, DAY),
  };
}

describe("every authenticated write is charged once, to both buckets", () => {
  it("charges a write that is accepted and a write that is refused afterwards", async () => {
    const before = await spent();

    const accepted = await submit("Kestrel-2 seat pricing rose, filing one");
    expect(accepted.status).toBe(201);

    // Authenticated and then refused on its own merits: this one repeats a live
    // claim's own subject and category under a value already filed, so the
    // duplicate rule answers it. It still spent its nonce, as it always did,
    // and it spends its write too — a caller who could make a hundred doomed
    // submissions for free would have found the hole this closes.
    filings -= 1;
    const repeated = await submit("Kestrel-2 seat pricing rose, filed twice");
    expect(repeated.status).toBe(422);
    expect(await repeated.json()).toMatchObject({ error: "duplicate_claim" });

    const after = await spent();
    expect(after.agent).toBe(before.agent + 2);
    expect(after.client).toBe(before.client + 2);
  });

  it("charges nothing for a request that never authenticated", async () => {
    const before = await spent();

    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, { method: "POST", body: "{}" }),
    );
    expect(response.status).toBe(401);

    expect(await spent()).toEqual(before);
  });
});

describe("the per-agent cap", () => {
  it("refuses the write past the cap 429 write_quota, before any fetch", async () => {
    // The day taken to one below the cap, so the next write is the last one
    // allowed and the one after it is the hundred-and-first.
    const used = (await spent()).agent;
    await addQuota(
      store.db,
      agentScope,
      DAY,
      WRITES_PER_AGENT_PER_DAY_PROBATION - used - 1,
    );

    const last = await submit("Kestrel-2 seat pricing rose, the last allowed");
    expect(last.status).toBe(201);

    const seenBefore = fetcher.requests.length;
    const over = await submit("Kestrel-2 seat pricing rose, one too many");

    expect(over.status).toBe(429);
    expect(await over.json()).toMatchObject({
      error: "write_quota",
      bucket: "agent",
      limit: WRITES_PER_AGENT_PER_DAY_PROBATION,
    });
    expect(over.headers.get("x-nomankind-write-limit")).toBe(
      String(WRITES_PER_AGENT_PER_DAY_PROBATION),
    );
    expect(over.headers.get("x-nomankind-write-remaining")).toBe("0");

    // The whole point of charging before the expensive part: the citation was
    // never fetched, so the refusal cost the log no outbound request at all.
    expect(fetcher.requests.length).toBe(seenBefore);
  });

  it("does not charge the refused write again", async () => {
    const before = await spent();
    const over = await submit("Kestrel-2 seat pricing rose, refused twice");
    expect(over.status).toBe(429);
    expect((await spent()).agent).toBe(before.agent);
  });

  it("leaves another agent on the same client its own cap", async () => {
    // The second agent's own bucket is empty, so it is the client bucket alone
    // that could refuse it — and that one still has room.
    const response = await submit(
      "Kestrel-2 seat pricing rose, from a second key",
      other,
    );
    expect(response.status).toBe(201);
  });
});

describe("the per-client cap", () => {
  it("refuses a write past the cap whichever agent signs it", async () => {
    await addQuota(
      store.db,
      clientScope,
      DAY,
      WRITES_PER_CLIENT_PER_DAY - (await spent()).client,
    );

    for (const [name, signer] of [
      // Two keys whose own agent buckets have room, so it is the client bucket
      // and nothing else that refuses them.
      ["the second key", other],
      ["the third key", third],
    ] as const) {
      const seenBefore = fetcher.requests.length;
      const response = await submit(`Kestrel-2 pricing, ${name} over the cap`, signer);

      expect(response.status).toBe(429);
      expect(await response.json()).toMatchObject({
        error: "write_quota",
        bucket: "client",
        limit: WRITES_PER_CLIENT_PER_DAY,
      });
      expect(fetcher.requests.length).toBe(seenBefore);
    }
  });

  it("refuses every other write door the same way, before its own work", async () => {
    // The registry door's DNS lookup is the expensive step the QA named, and a
    // resolver holding no records would refuse this registration anyway — the
    // 429 is proof the quota was charged before the lookup, not after it.
    const response = await send(
      await signedPost(third, {
        path: "/operators",
        body: {
          operator: "over.example",
          domain: DEFAULT_DOMAIN,
          attestation: {},
          payout: { reference: "acct_x" },
        },
        timestamp: NOW.toISOString(),
      }),
    );

    expect(response.status).toBe(429);
    expect(await response.json()).toMatchObject({ error: "write_quota" });
  });

  it("exempts the genesis door, which is the maintainer's own key", async () => {
    // Both buckets are spent and the maintainer's is not even counted, so the
    // answer is the door's own rule about the operator it was asked to name.
    const response = await send(
      await signedPost(maintainer, {
        path: "/genesis",
        body: { operator: "nobody.example" },
        timestamp: NOW.toISOString(),
      }),
    );

    expect(response.status).not.toBe(429);
    expect(await response.json()).toEqual({ error: "unregistered_operator" });
  });
});

/**
 * The read side's three caps (M25, whitepaper Section 9).
 *
 * "The log is free to read at low volume, forever. Revenue comes from
 * high-rate API access, structured feeds and webhooks, change alerts." The QA
 * of 2026-09-12 found three ways that sentence was not enforced, and this file
 * is where each of them is made falsifiable.
 *
 * The free tier was counted per client address and nowhere else, so a hundred
 * addresses each inside the per-client cap were the whole account's daily
 * budget: there was a cap on one reader and no ceiling on all of them. A
 * registered operator's signed read was metered in the anonymous bucket of
 * whatever address it came from, so a validator walking the log for the entries
 * it has to reproduce exhausted the free tier for every stranger behind that
 * address. And `GET /events` — the door a trainer pages the whole log through —
 * was charged nothing at all.
 *
 * miniflare's D1 with the real migrations applied, because the quota row is an
 * UPSERT the database does the arithmetic of and a hand-written fake would
 * answer for none of it. Every instant is injected, and each block reads on a
 * UTC day of its own, because a day is what a counter is keyed by and two
 * blocks sharing one would be two tests sharing a bucket.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  OPERATOR_TIER,
  QUOTA_SCOPE_FREE_GLOBAL,
  mintKey,
  quotaScopeForClient,
  quotaScopeForOperator,
} from "../src/keys.js";
import {
  FREE_READS_PER_DAY_GLOBAL,
  FREE_TIER,
  OPERATOR_READS_PER_DAY,
  RATE_TIERS,
} from "../src/policy.js";
import { signRequest } from "../src/request.js";
import type { D1Like } from "../src/storage/d1.js";
import { addQuota, putKey, quotaOn } from "../src/storage/keys.js";
import { putAgent, putOperator } from "../src/storage/repository.js";
import {
  accessHeaders,
  chargeReads,
  readerAccess,
  resolveAccess,
} from "../src/worker/access.js";
import type { Env } from "../src/worker/env.js";
import { handleEvents } from "../src/worker/events.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { makeAgent, type TestAgent } from "./helpers/registry.js";

let store: TestDatabase;
let db: D1Like;

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

/** An env with nothing in it but the database, which is all these doors read. */
function envOf(): Env {
  return { DB: db } as unknown as Env;
}

/** A free read from one client address. */
function fromClient(ip: string, path = "/read/nmk_1"): Request {
  return new Request(`https://nomankind.ai${path}`, {
    headers: { "cf-connecting-ip": ip },
  });
}

/** An agent bound to a registered operator. */
async function bound(operator: string): Promise<TestAgent> {
  const agent = await makeAgent();
  await putOperator(db, {
    id: operator,
    kind: "domain",
    maintainer: false,
    provider: false,
    registeredSeq: 0,
    details: {},
  });
  await putAgent(db, {
    agentId: agent.agentId,
    operatorId: operator,
    registeredSeq: 0,
  });
  return agent;
}

/** One signed GET, exactly as the disclosure gate verifies one. */
async function signedGet(
  agent: TestAgent,
  at: Date,
  path: string,
  headers: Record<string, string> = {},
): Promise<Request> {
  const signed = await signRequest({
    method: "GET",
    path,
    body: null,
    agentId: agent.agentId,
    privateKey: agent.privateKey,
    timestamp: at.toISOString(),
  });
  return new Request(`https://nomankind.ai${path}`, {
    headers: { ...signed, ...headers },
  });
}

// ---------------------------------------------------------------------------
// The ceiling over every free client together
// ---------------------------------------------------------------------------

describe("the free tier's global ceiling", () => {
  const NOW = new Date("2026-09-11T12:00:00.000Z");
  const DAY = "2026-09-11";

  it("refuses the next free read once the day's ceiling is spent, across clients", async () => {
    // One read left in the whole log's free tier, and two clients who have each
    // read nothing: the per-client cap cannot be what refuses either of them.
    await addQuota(db, QUOTA_SCOPE_FREE_GLOBAL, DAY, FREE_READS_PER_DAY_GLOBAL - 1);

    const first = await resolveAccess(db, fromClient("198.51.100.7"), NOW);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.access.used).toBe(0);
    await chargeReads(db, first.access, 1);

    // The charge landed in both counters, which is what makes the ceiling a
    // number rather than a hope.
    expect(await quotaOn(db, QUOTA_SCOPE_FREE_GLOBAL, DAY)).toBe(
      FREE_READS_PER_DAY_GLOBAL,
    );
    expect(
      await quotaOn(db, await quotaScopeForClient("198.51.100.7"), DAY),
    ).toBe(1);

    // A different address, nothing read, well inside its own cap, refused.
    const second = await resolveAccess(db, fromClient("203.0.113.9"), NOW);
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.refusal.status).toBe(429);
    expect(second.refusal.reason).toBe("rate_limited");
    expect(second.refusal.body).toMatchObject({
      error: "rate_limited",
      tier: FREE_TIER,
      limit: FREE_READS_PER_DAY_GLOBAL,
      used: FREE_READS_PER_DAY_GLOBAL,
      scope: "global",
      resets_at: "2026-09-12T00:00:00.000Z",
    });
    // It is the ceiling and not the per-client cap: that client's own counter
    // is still zero, far under RATE_TIERS.free.
    expect(await quotaOn(db, await quotaScopeForClient("203.0.113.9"), DAY)).toBe(
      0,
    );
    expect(RATE_TIERS[FREE_TIER]!.reads_per_day).toBeGreaterThan(0);
  });

  it("does not refuse a paid key because strangers were reading", async () => {
    // The same day, the same spent ceiling: a key buys throughput, and a cap on
    // the free tier is not the paid tier's to meet.
    expect(await quotaOn(db, QUOTA_SCOPE_FREE_GLOBAL, DAY)).toBe(
      FREE_READS_PER_DAY_GLOBAL,
    );
    const minted = mintKey();
    await putKey(db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier: "standard",
      status: "active",
      clientDay: "cs_ceiling",
      createdAt: NOW.toISOString(),
    });

    const resolved = await resolveAccess(
      db,
      new Request("https://nomankind.ai/read/nmk_1", {
        headers: {
          authorization: `Bearer ${minted.secret}`,
          "cf-connecting-ip": "203.0.113.9",
        },
      }),
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.access.tier).toBe("standard");
    // A paid read is counted under its key and never against the ceiling.
    expect(resolved.access.globalScope).toBeNull();
    await chargeReads(db, resolved.access, 1);
    expect(await quotaOn(db, QUOTA_SCOPE_FREE_GLOBAL, DAY)).toBe(
      FREE_READS_PER_DAY_GLOBAL,
    );
  });
});

// ---------------------------------------------------------------------------
// The operator's own bucket
// ---------------------------------------------------------------------------

describe("a registered operator's signed reads", () => {
  const NOW = new Date("2026-09-13T12:00:00.000Z");
  const DAY = "2026-09-13";
  const PATH = "/read/nmk_1";

  it("are metered under the operator and not in the client's bucket", async () => {
    const agent = await bound("metered.example");
    const request = await signedGet(agent, NOW, PATH, {
      "cf-connecting-ip": "198.51.100.20",
    });
    const granted = await readerAccess(request, envOf(), db, NOW);
    expect(granted.ok).toBe(true);
    if (!granted.ok || granted.reader.kind !== "operator") {
      expect.unreachable("a signed read did not read as an operator");
      return;
    }
    const access = granted.reader.access;
    expect(access.tier).toBe(OPERATOR_TIER);
    expect(access.limit).toBe(OPERATOR_READS_PER_DAY);
    expect(access.scope).toBe(quotaScopeForOperator("metered.example"));
    expect(access.globalScope).toBeNull();

    // The three headers, in the operator's own tier.
    expect(accessHeaders(access, access.limit - access.used - 1)).toEqual({
      "x-nomankind-tier": OPERATOR_TIER,
      "x-nomankind-limit": String(OPERATOR_READS_PER_DAY),
      "x-nomankind-remaining": String(OPERATOR_READS_PER_DAY - 1),
    });

    await chargeReads(db, access, 1);
    expect(await quotaOn(db, quotaScopeForOperator("metered.example"), DAY)).toBe(
      1,
    );
    // Neither the address's bucket nor the whole log's free tier moved.
    expect(
      await quotaOn(db, await quotaScopeForClient("198.51.100.20"), DAY),
    ).toBe(0);
    expect(await quotaOn(db, QUOTA_SCOPE_FREE_GLOBAL, DAY)).toBe(0);
  });

  it("are served even when the address's free bucket is spent", async () => {
    // The QA's own case: a trainer walking the log used to exhaust the free
    // tier of whatever address it came from, and then be refused by it.
    const agent = await bound("walker.example");
    const ip = "198.51.100.21";
    await addQuota(
      db,
      await quotaScopeForClient(ip),
      DAY,
      RATE_TIERS[FREE_TIER]!.reads_per_day,
    );

    const granted = await readerAccess(
      await signedGet(agent, NOW, PATH, { "cf-connecting-ip": ip }),
      envOf(),
      db,
      NOW,
    );
    expect(granted.ok).toBe(true);
    if (!granted.ok) return;
    expect(granted.reader.kind).toBe("operator");
  });

  it("are refused when the operator's own day is spent", async () => {
    const agent = await bound("spent.example");
    await addQuota(
      db,
      quotaScopeForOperator("spent.example"),
      DAY,
      OPERATOR_READS_PER_DAY,
    );

    const granted = await readerAccess(
      await signedGet(agent, NOW, PATH),
      envOf(),
      db,
      NOW,
    );
    expect(granted.ok).toBe(false);
    if (granted.ok) return;
    expect(granted.refusal.status).toBe(429);
    expect(granted.refusal.reason).toBe("rate_limited");
    expect(granted.refusal.body).toMatchObject({
      error: "rate_limited",
      tier: OPERATOR_TIER,
      limit: OPERATOR_READS_PER_DAY,
      used: OPERATOR_READS_PER_DAY,
    });
  });
});

// ---------------------------------------------------------------------------
// GET /events is a read
// ---------------------------------------------------------------------------

describe("GET /events", () => {
  const NOW = new Date("2026-09-14T12:00:00.000Z");
  const DAY = "2026-09-14";

  it("charges one unit per page against the caller's bucket", async () => {
    const ip = "203.0.113.40";
    const answer = await handleEvents(fromClient(ip, "/events"), envOf(), {
      now: NOW,
    });
    expect(answer).not.toBeNull();
    expect(answer!.status).toBe(200);
    expect(answer!.headers.get("x-nomankind-tier")).toBe(FREE_TIER);
    expect(answer!.headers.get("x-nomankind-limit")).toBe(
      String(RATE_TIERS[FREE_TIER]!.reads_per_day),
    );
    expect(answer!.headers.get("x-nomankind-remaining")).toBe(
      String(RATE_TIERS[FREE_TIER]!.reads_per_day - 1),
    );

    // One unit for the page, in the client's bucket and the ceiling's.
    expect(await quotaOn(db, await quotaScopeForClient(ip), DAY)).toBe(1);
    expect(await quotaOn(db, QUOTA_SCOPE_FREE_GLOBAL, DAY)).toBe(1);

    // A second page is a second read.
    await handleEvents(fromClient(ip, "/events"), envOf(), { now: NOW });
    expect(await quotaOn(db, await quotaScopeForClient(ip), DAY)).toBe(2);
  });

  it("is refused like every other door when the bucket is spent", async () => {
    const ip = "203.0.113.41";
    await addQuota(
      db,
      await quotaScopeForClient(ip),
      DAY,
      RATE_TIERS[FREE_TIER]!.reads_per_day,
    );

    const answer = await handleEvents(fromClient(ip, "/events"), envOf(), {
      now: NOW,
    });
    expect(answer).not.toBeNull();
    expect(answer!.status).toBe(429);
    const body = (await answer!.json()) as Record<string, unknown>;
    expect(body["error"]).toBe("rate_limited");
    expect(body["tier"]).toBe(FREE_TIER);
    // A refusal costs nothing: the counter is exactly where it was.
    expect(await quotaOn(db, await quotaScopeForClient(ip), DAY)).toBe(
      RATE_TIERS[FREE_TIER]!.reads_per_day,
    );
  });

  it("leaves the proof route uncharged", async () => {
    // Proof is public from the first minute, whoever is asking: the inclusion
    // proof beside the page is not this door and is not charged.
    const ip = "203.0.113.42";
    const answer = await handleEvents(
      fromClient(ip, "/events/0/proof"),
      envOf(),
      { now: NOW },
    );
    // Not this route's path at all, so it answers null and charges nothing.
    expect(answer).toBeNull();
    expect(await quotaOn(db, await quotaScopeForClient(ip), DAY)).toBe(0);
  });
});

/**
 * The key, the store behind it, and the gate in front of it.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." Three things have to hold for that sentence to mean anything.
 * A key must be a credential and not an identity: minted from real randomness,
 * stored as a hash, and never recoverable from anything the system keeps. A
 * quota must be the database's arithmetic and not an isolate's, or two readers
 * served at the same instant cost one read between them. And the gate must say
 * no in the right word — a mistyped key, an unknown key and a used-up day are
 * three different answers and a reader owed one of them is owed that one.
 *
 * miniflare's D1 with the real migrations applied, because the UPSERT, the
 * partial unique index and `UPDATE ... RETURNING` are the things under test and
 * a hand-written fake would answer for none of them. The clock is injected
 * everywhere.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { sha256Hex } from "../src/hash.js";
import {
  KEY_ID_PREFIX,
  KEY_PREFIX,
  KEY_REFUSALS,
  keyHash,
  looksLikeKey,
  mintKey,
  quotaScopeForClient,
  quotaScopeForKey,
  tierLimit,
} from "../src/keys.js";
import { FREE_TIER, RATE_TIERS, isPaidTier } from "../src/policy.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  KeyDayConflictError,
  addQuota,
  keyByClientDay,
  keyByHash,
  keyById,
  putKey,
  quotaDays,
  quotaOn,
  readCountEventOn,
  receiptsForKey,
} from "../src/storage/keys.js";
import { signRequest } from "../src/request.js";
import { putAgent, putOperator } from "../src/storage/repository.js";
import {
  accessHeaders,
  chargeReads,
  nextKeyCounter,
  readerAccess,
  resolveAccess,
} from "../src/worker/access.js";
import type { Env } from "../src/worker/env.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { makeAgent, type TestAgent } from "./helpers/registry.js";

const NOW = new Date("2026-09-11T12:00:00.000Z");
const DAY = "2026-09-11";
const TOMORROW = "2026-09-12T00:00:00.000Z";

let store: TestDatabase;
let db: D1Like;

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

/** A request with whatever headers a case needs. */
function ask(headers: Record<string, string> = {}): Request {
  return new Request("https://nomankind.ai/read/nmk_1", { headers });
}

/** One claimed key, with the secret its holder was shown once. */
async function claim(input: {
  tier?: string;
  suffix: string;
}): Promise<{ id: string; secret: string }> {
  const minted = mintKey();
  await putKey(db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: input.tier ?? "standard",
    status: "active",
    clientDay: `cs_${input.suffix}`,
    createdAt: NOW.toISOString(),
  });
  return { id: minted.id, secret: minted.secret };
}

// ---------------------------------------------------------------------------
// The kernel
// ---------------------------------------------------------------------------

describe("mintKey", () => {
  it("mints an id and a secret of the published shapes", async () => {
    const minted = mintKey();
    expect(minted.id).toMatch(/^key_[0-9a-f]{16}$/);
    expect(minted.id.startsWith(KEY_ID_PREFIX)).toBe(true);
    expect(minted.secret).toMatch(/^nmk_[A-Za-z0-9_-]{43}$/);
    expect(minted.secret.startsWith(KEY_PREFIX)).toBe(true);
    // The stored form is the hash of the secret's UTF-8 bytes and nothing else,
    // so a copy of the table cannot be used to read as anybody.
    expect(await minted.hash).toBe(await sha256Hex(minted.secret));
    expect(await minted.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("draws the id and the secret separately", () => {
    // The id is public — it is in every receipt and in the published per-key
    // counts — so knowing it must say nothing about the secret.
    const random = (n: number): Uint8Array => new Uint8Array(n).fill(7);
    const minted = mintKey(random);
    expect(minted.id).toBe("key_0707070707070707");
    expect(minted.secret).not.toContain("0707");
  });

  it("mints a different key every time", () => {
    const seen = new Set<string>();
    for (let index = 0; index < 50; index += 1) seen.add(mintKey().secret);
    expect(seen.size).toBe(50);
  });
});

describe("looksLikeKey", () => {
  it("accepts a minted secret and nothing else", () => {
    expect(looksLikeKey(mintKey().secret)).toBe(true);
    for (const value of [
      null,
      undefined,
      42,
      "",
      "nmk_",
      "nmk_tooshort",
      `nmk_${"a".repeat(44)}`,
      `nmk_${"a".repeat(42)}+`,
      `key_${"a".repeat(43)}`,
      "Bearer nmk_x",
    ]) {
      expect([value, looksLikeKey(value)]).toEqual([value, false]);
    }
  });
});

describe("quota scopes", () => {
  it("names a key by its id and a client by a hash of its address", async () => {
    expect(quotaScopeForKey("key_abc")).toBe("key:key_abc");
    const scope = await quotaScopeForClient("203.0.113.7");
    expect(scope).toBe(`client:${await sha256Hex("203.0.113.7")}`);
    // A rate counter that stored addresses would be a record of who read what.
    expect(scope).not.toContain("203.0.113.7");
    expect(await quotaScopeForClient(null)).toBe("client:anonymous");
    expect(await quotaScopeForClient("")).toBe("client:anonymous");
  });
});

describe("tierLimit", () => {
  it("reads the cap out of policy, and refuses a tier policy retired", () => {
    expect(tierLimit(FREE_TIER)).toBe(RATE_TIERS[FREE_TIER]!.reads_per_day);
    expect(tierLimit("standard")).toBe(RATE_TIERS["standard"]!.reads_per_day);
    // A cap of zero refuses, which is the right answer for a key whose tier is
    // no longer published.
    expect(tierLimit("retired")).toBe(0);
  });
});

describe("the published tiers", () => {
  it("publishes a cap and a name, and no price or share at all", () => {
    // Decision D-127, "the record is free, no money anywhere": a tier is a cap
    // and a name. There is no contributor share to hold above a floor and no
    // split to check it against, so a tier row must carry nothing else.
    for (const slug of Object.keys(RATE_TIERS)) {
      expect([slug, Object.keys(RATE_TIERS[slug]!).sort()]).toEqual([
        slug,
        ["key", "name", "reads_per_day"],
      ]);
    }
  });

  it("gives every tier a positive daily cap", () => {
    const slugs = Object.keys(RATE_TIERS);
    expect(slugs.length).toBeGreaterThan(0);
    for (const slug of slugs) {
      const tier = RATE_TIERS[slug]!;
      expect([slug, Number.isInteger(tier.reads_per_day)]).toEqual([slug, true]);
      expect(tier.reads_per_day).toBeGreaterThan(0);
      expect(typeof tier.name).toBe("string");
    }
    // The free tier is the one served without a key, and it is the only one.
    expect(RATE_TIERS[FREE_TIER]!.key).toBe(false);
    expect(isPaidTier(FREE_TIER)).toBe(false);
    expect(isPaidTier("standard")).toBe(true);
    expect(isPaidTier("retired")).toBe(false);
    expect(isPaidTier(7)).toBe(false);
    for (const slug of slugs) {
      if (slug === FREE_TIER) continue;
      expect([slug, isPaidTier(slug)]).toEqual([slug, true]);
    }
  });

  it("names every refusal the gate can answer with", () => {
    expect([...KEY_REFUSALS]).toEqual([
      "missing_key",
      "bad_key",
      "unknown_key",
      "rate_limited",
    ]);
    // The two the bill was about went with it (D-127 item 2).
    expect([...KEY_REFUSALS]).not.toContain("key_canceled");
    expect([...KEY_REFUSALS]).not.toContain("key_past_due");
  });
});

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

describe("the key store", () => {
  it("stores a key and finds it three ways, never returning the hash", async () => {
    const minted = mintKey();
    const hash = await minted.hash;
    const stored = await putKey(db, {
      id: minted.id,
      keyHash: hash,
      tier: "standard",
      status: "active",
      clientDay: "client_store:2026-09-12",
      createdAt: NOW.toISOString(),
    });
    expect(stored.counter).toBe(0);
    expect(JSON.stringify(stored)).not.toContain(hash);
    expect(JSON.stringify(stored)).not.toContain(minted.secret);

    for (const found of [
      await keyByHash(db, hash),
      await keyById(db, minted.id),
      await keyByClientDay(db, "client_store:2026-09-12"),
    ]) {
      expect(found).toEqual(stored);
    }
    expect(await keyByHash(db, await keyHash("nmk_nobody"))).toBeNull();
    expect(await keyByClientDay(db, "client_nobody:2026-09-12")).toBeNull();
  });

  it("refuses a second key for one client on one day", async () => {
    const minted = mintKey();
    await expect(
      putKey(db, {
        id: minted.id,
        keyHash: await minted.hash,
        tier: "standard",
        status: "active",
        clientDay: "client_store:2026-09-12",
        createdAt: NOW.toISOString(),
      }),
    ).rejects.toBeInstanceOf(KeyDayConflictError);
  });

  it("adds to a day inside the database rather than in an isolate", async () => {
    const scope = "key:key_quota";
    expect(await quotaOn(db, scope, DAY)).toBe(0);
    // Ten concurrent charges: if the count were read into an isolate and written
    // back, most of these would be lost.
    await Promise.all(
      Array.from({ length: 10 }, () => addQuota(db, scope, DAY, 1)),
    );
    expect(await quotaOn(db, scope, DAY)).toBe(10);
    // Zero charges nothing, and never creates a row.
    await addQuota(db, "key:key_zero", DAY, 0);
    expect(await quotaOn(db, "key:key_zero", DAY)).toBe(0);
  });

  it("reads a scope's days as a bounded range, oldest first", async () => {
    const scope = "key:key_days";
    await addQuota(db, scope, "2026-09-09", 3);
    await addQuota(db, scope, "2026-09-10", 5);
    await addQuota(db, scope, "2026-09-11", 7);
    expect(await quotaDays(db, scope, "2026-09-09", "2026-09-10")).toEqual([
      { day: "2026-09-09", reads: 3 },
      { day: "2026-09-10", reads: 5 },
    ]);
    expect(await quotaDays(db, scope, "2026-09-12", "2026-09-13")).toEqual([]);
  });

  it("finds the read_count event for one date by its payload", async () => {
    expect(await readCountEventOn(db, DAY)).toBeNull();
    await db
      .prepare(
        `INSERT INTO events (seq, "at", type, entry_id, payload, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        1,
        `${DAY}T23:59:00.000Z`,
        "read_count",
        null,
        JSON.stringify({
          date: DAY,
          reads: [],
          total: 0,
          counter_first: null,
          counter_last: null,
          paid: { reads: [], total: 4, keys: { key_seen: 4 } },
        }),
        null,
        `sha256:${"a".repeat(64)}`,
      )
      .run();
    const event = await readCountEventOn(db, DAY);
    expect(event?.seq).toBe(1);
    expect(
      (event?.payload as unknown as { paid: { keys: Record<string, number> } })
        .paid.keys,
    ).toEqual({ key_seen: 4 });
    expect(await readCountEventOn(db, "2026-09-10")).toBeNull();
  });

  it("pages one key's receipts by the key's own counter", async () => {
    const claimed = await claim({ suffix: "receipts" });
    for (let counter = 1; counter <= 3; counter += 1) {
      await db
        .prepare(
          `INSERT INTO receipts (id, kind, entry_id, seq, created_at, payload_json, key_id, key_counter)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          `rcpt_${100 + counter}`,
          "read",
          "nmk_00000000000000000000000000000001",
          100 + counter,
          `${DAY}T0${counter}:00:00.000Z`,
          JSON.stringify({ counter: 100 + counter, key: claimed.id }),
          claimed.id,
          counter,
        )
        .run();
    }

    const first = await receiptsForKey(db, claimed.id, 0, 2);
    expect(first.map((row) => row.key_counter)).toEqual([1, 2]);
    expect(first[0]).toEqual({
      kind: "read",
      key_counter: 1,
      counter: 101,
      created_at: `${DAY}T01:00:00.000Z`,
      receipt: { counter: 101, key: claimed.id },
    });
    const second = await receiptsForKey(db, claimed.id, 2, 2);
    expect(second.map((row) => row.key_counter)).toEqual([3]);
    // Somebody else's key sees nothing of this one's.
    expect(await receiptsForKey(db, "key_nobody", 0, 10)).toEqual([]);
  });

  it("refuses two receipts at one key counter", async () => {
    const claimed = await claim({ suffix: "dupcounter" });
    const insert = (id: string): Promise<unknown> =>
      db
        .prepare(
          `INSERT INTO receipts (id, kind, entry_id, seq, created_at, payload_json, key_id, key_counter)
           VALUES (?, 'read', NULL, ?, ?, '{}', ?, 1)`,
        )
        .bind(id, Number(id.slice(5)), NOW.toISOString(), claimed.id)
        .run();
    await insert("rcpt_9001");
    await expect(insert("rcpt_9002")).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

describe("resolveAccess", () => {
  it("serves a request with no key on the free tier", async () => {
    const resolved = await resolveAccess(db, ask(), NOW);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.access.tier).toBe(FREE_TIER);
    expect(resolved.access.key).toBeNull();
    expect(resolved.access.scope).toBe("client:anonymous");
    expect(resolved.access.day).toBe(DAY);
    expect(resolved.access.limit).toBe(RATE_TIERS[FREE_TIER]!.reads_per_day);
  });

  it("counts a keyless reader by a hash of its address", async () => {
    const resolved = await resolveAccess(
      db,
      ask({ "cf-connecting-ip": "198.51.100.4" }),
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.access.scope).toBe(
      `client:${await sha256Hex("198.51.100.4")}`,
    );
  });

  it("refuses a header that is not a well-formed key, before any query", async () => {
    const resolved = await resolveAccess(
      db,
      ask({ authorization: "Bearer not-a-key" }),
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect(resolved.refusal.status).toBe(401);
    expect(resolved.refusal.reason).toBe("bad_key");
    expect(resolved.refusal.body).toEqual({ error: "bad_key" });
  });

  it("refuses a well-formed key nobody holds", async () => {
    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${mintKey().secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      401,
      "unknown_key",
    ]);
  });

  it("serves a key whose row still says a pre-D-127 word", async () => {
    // A deployment that sold keys can hold a row whose `status` reads
    // `canceled` or `past_due`. Nothing writes either any more and no door
    // refuses on one (D-127 item 2), so the gate reads the row and serves it;
    // the parser hands the word back rather than throwing on it.
    const claimed = await claim({ suffix: "legacystatus" });
    await db
      .prepare(`UPDATE api_keys SET status = 'canceled' WHERE id = ?`)
      .bind(claimed.id)
      .run();

    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${claimed.secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.access.key?.id).toBe(claimed.id);
    expect((await keyById(db, claimed.id))?.status).toBe("canceled");
  });

  it("serves the last read of the day and refuses the next", async () => {
    const claimed = await claim({ suffix: "atcap" });
    const limit = RATE_TIERS["standard"]!.reads_per_day;
    await addQuota(db, quotaScopeForKey(claimed.id), DAY, limit - 1);

    const request = ask({ authorization: `Bearer ${claimed.secret}` });
    const served = await resolveAccess(db, request, NOW);
    expect(served.ok).toBe(true);
    if (!served.ok) return;
    expect(served.access.used).toBe(limit - 1);
    expect(served.access.limit).toBe(limit);
    expect(accessHeaders(served.access, limit - served.access.used - 1)).toEqual(
      {
        "x-nomankind-tier": "standard",
        "x-nomankind-limit": String(limit),
        "x-nomankind-remaining": "0",
      },
    );

    // The door charges what it served, and only then is the day used up.
    await chargeReads(db, served.access, 1);
    expect(await quotaOn(db, quotaScopeForKey(claimed.id), DAY)).toBe(limit);

    const refused = await resolveAccess(db, request, NOW);
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect(refused.refusal.status).toBe(429);
    expect(refused.refusal.reason).toBe("rate_limited");
    expect(refused.refusal.body).toEqual({
      error: "rate_limited",
      tier: "standard",
      limit,
      used: limit,
      resets_at: TOMORROW,
    });
    // The retry is the seconds to midnight, so a client waiting it out asks
    // again on the day the cap actually reset.
    expect(refused.refusal.retryAfter).toBe(12 * 60 * 60);
  });

  it("charges nothing for a request that served nothing", async () => {
    const claimed = await claim({ suffix: "zerocharge" });
    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${claimed.secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    await chargeReads(db, resolved.access, 0);
    expect(await quotaOn(db, quotaScopeForKey(claimed.id), DAY)).toBe(0);
  });

  it("charges the day the gate let the request in on", async () => {
    const claimed = await claim({ suffix: "midnight" });
    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${claimed.secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    await chargeReads(db, resolved.access, 4);
    // Even though the charge happened later, it lands on the access's own day.
    expect(await quotaOn(db, quotaScopeForKey(claimed.id), DAY)).toBe(4);
    expect(await quotaOn(db, quotaScopeForKey(claimed.id), "2026-09-12")).toBe(
      0,
    );
  });
});

describe("nextKeyCounter", () => {
  it("hands out 1, then 2, and never the same number twice", async () => {
    const claimed = await claim({ suffix: "counter" });
    expect(await nextKeyCounter(db, claimed.id)).toBe(1);
    expect(await nextKeyCounter(db, claimed.id)).toBe(2);

    const drawn = await Promise.all(
      Array.from({ length: 8 }, () => nextKeyCounter(db, claimed.id)),
    );
    expect(new Set(drawn).size).toBe(8);
    expect((await keyById(db, claimed.id))?.counter).toBe(10);
  });

  it("throws rather than guessing for a key that is not there", async () => {
    await expect(nextKeyCounter(db, "key_nobody")).rejects.toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------
// The release window's reader (decision D-100)
// ---------------------------------------------------------------------------

/**
 * `readerAccess`: which of the three readers is asking.
 *
 * The one question the release window puts to every door — a paid key, an agent
 * bound to a registered operator, or everybody else — and the three answers it
 * has. What is pinned here is that the two credentials are the ones the rest of
 * the system already uses (`resolveAccess`'s key gate and M2's signed request,
 * in the form the M24c disclosure gate verifies: GET, the path with no query
 * string, a null body), and that neither a bad key nor a bad signature is ever
 * quietly served as free.
 */
describe("readerAccess", () => {
  const PATH = "/read/nmk_1";
  const URL_ = `https://nomankind.ai${PATH}`;

  /** An env with nothing in it but the database, which is all this gate reads. */
  function envOf(): Env {
    return { DB: db } as unknown as Env;
  }

  /** One signed GET, exactly as the disclosure gate verifies one. */
  async function signedGet(
    agent: TestAgent,
    at: Date = NOW,
    path: string = PATH,
  ): Promise<Request> {
    const headers = await signRequest({
      method: "GET",
      path,
      body: null,
      agentId: agent.agentId,
      privateKey: agent.privateKey,
      timestamp: at.toISOString(),
    });
    return new Request(`https://nomankind.ai${path}`, { headers });
  }

  /** An agent bound to a registered operator, and one bound to nobody. */
  async function bound(operator: string): Promise<TestAgent> {
    const agent = await makeAgent();
    await putOperator(db, {
      id: operator,
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

  it("answers free for a request that presents nothing", async () => {
    const resolved = await readerAccess(new Request(URL_), envOf(), db, NOW);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.reader.kind).toBe("free");
  });

  it("answers key for a valid active key, through the M24 resolver", async () => {
    const claimed = await claim({ suffix: "reader" });
    const resolved = await readerAccess(
      new Request(URL_, { headers: { authorization: `Bearer ${claimed.secret}` } }),
      envOf(),
      db,
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok || resolved.reader.kind !== "key") {
      expect.unreachable("a valid key did not read as a key");
      return;
    }
    expect(resolved.reader.key.key?.id).toBe(claimed.id);
    expect(resolved.reader.key.tier).toBe("standard");
  });

  it("refuses a bad key rather than serving it free", async () => {
    const resolved = await readerAccess(
      new Request(URL_, { headers: { authorization: "Bearer not-a-key" } }),
      envOf(),
      db,
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      401,
      "bad_key",
    ]);
  });

  it("answers operator for a signed GET from a bound agent", async () => {
    const agent = await bound("reader.example");
    const resolved = await readerAccess(
      await signedGet(agent),
      envOf(),
      db,
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok || resolved.reader.kind !== "operator") {
      expect.unreachable("a signed read did not read as an operator");
      return;
    }
    expect(resolved.reader.operator).toBe("reader.example");
    expect(resolved.reader.agent).toBe(agent.agentId);
  });

  it("refuses a signature that does not verify, rather than downgrading it", async () => {
    const agent = await bound("skew.example");
    // The same request an hour late: the timestamp is signed, so the verdict is
    // clock_skew and the reader asked for something they did not get.
    const stale = await signedGet(agent, new Date(NOW.getTime() - 3_600_000));
    const resolved = await readerAccess(stale, envOf(), db, NOW);
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      401,
      "bad_signature",
    ]);
  });

  it("refuses a signature over another path", async () => {
    const agent = await bound("path.example");
    const elsewhere = await signedGet(agent, NOW, "/entries/nmk_1");
    const moved = new Request(URL_, { headers: elsewhere.headers });
    const resolved = await readerAccess(moved, envOf(), db, NOW);
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect(resolved.refusal.reason).toBe("bad_signature");
  });

  it("reads an agent bound to nobody as free", async () => {
    // The signature verifies and proves who they are; they are simply not
    // entitled to anything, which is what the free tier is.
    const stranger = await makeAgent();
    const resolved = await readerAccess(
      await signedGet(stranger),
      envOf(),
      db,
      NOW,
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.reader.kind).toBe("free");
  });

  it("spends the nonce, so the same signed read cannot be replayed", async () => {
    const agent = await bound("replay.example");
    const request = await signedGet(agent);
    const first = await readerAccess(request.clone(), envOf(), db, NOW);
    expect(first.ok).toBe(true);
    const again = await readerAccess(request, envOf(), db, NOW);
    expect(again.ok).toBe(false);
    if (again.ok) return;
    expect(again.refusal.reason).toBe("bad_signature");
  });
});

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
 * no in the right word — a mistyped key, an unknown key, a canceled
 * subscription and a used-up day are four different answers and a reader owed
 * one of them is owed that one.
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
  keyStatusFromSubscription,
  looksLikeKey,
  mintKey,
  quotaScopeForClient,
  quotaScopeForKey,
  tierLimit,
} from "../src/keys.js";
import {
  CONTRIBUTOR_SHARE_FLOOR_PERCENT,
  CONTRIBUTOR_SHARE_PERCENT,
  FREE_TIER,
  RATE_TIERS,
  READ_SHARE_SPLIT,
  SLOT_COUNT,
  isPaidTier,
} from "../src/policy.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  KeyClaimConflictError,
  addQuota,
  keyByCheckoutSession,
  keyByHash,
  keyById,
  keyBySubscription,
  putKey,
  putStripeEvent,
  quotaDays,
  quotaOn,
  readCountEventOn,
  receiptsForKey,
  setKeyStatus,
  stripeEventSeen,
} from "../src/storage/keys.js";
import {
  accessHeaders,
  chargeReads,
  nextKeyCounter,
  resolveAccess,
} from "../src/worker/access.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

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
  status?: "active" | "past_due" | "canceled";
  suffix: string;
}): Promise<{ id: string; secret: string }> {
  const minted = mintKey();
  await putKey(db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: input.tier ?? "standard",
    status: input.status ?? "active",
    customer: `cus_${input.suffix}`,
    subscription: `sub_${input.suffix}`,
    checkoutSession: `cs_${input.suffix}`,
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

describe("keyStatusFromSubscription", () => {
  it("maps the provider's vocabulary onto our three words", () => {
    expect(keyStatusFromSubscription("active")).toBe("active");
    expect(keyStatusFromSubscription("trialing")).toBe("active");
    expect(keyStatusFromSubscription("past_due")).toBe("past_due");
    expect(keyStatusFromSubscription("unpaid")).toBe("past_due");
    expect(keyStatusFromSubscription("canceled")).toBe("canceled");
    expect(keyStatusFromSubscription("incomplete")).toBe("canceled");
    expect(keyStatusFromSubscription("paused")).toBe("canceled");
    // A word nobody anticipated refuses rather than serving: the safe reading
    // of an unknown status is the one that says no.
    expect(keyStatusFromSubscription("something_new")).toBe("canceled");
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
  it("keeps the contributor share at or above its floor", () => {
    // Section 9: "The contributor share is a floor that only rises."
    expect(CONTRIBUTOR_SHARE_PERCENT).toBeGreaterThanOrEqual(
      CONTRIBUTOR_SHARE_FLOOR_PERCENT,
    );
  });

  it("makes the share exactly the split it is made of", () => {
    expect(
      READ_SHARE_SPLIT.submitter + SLOT_COUNT * READ_SHARE_SPLIT.validator,
    ).toBe(CONTRIBUTOR_SHARE_PERCENT);
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
      "key_canceled",
      "key_past_due",
      "rate_limited",
    ]);
  });
});

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

describe("the key store", () => {
  it("stores a key and finds it four ways, never returning the hash", async () => {
    const minted = mintKey();
    const hash = await minted.hash;
    const stored = await putKey(db, {
      id: minted.id,
      keyHash: hash,
      tier: "standard",
      status: "active",
      customer: "cus_store",
      subscription: "sub_store",
      checkoutSession: "cs_store",
      createdAt: NOW.toISOString(),
    });
    expect(stored.counter).toBe(0);
    expect(JSON.stringify(stored)).not.toContain(hash);
    expect(JSON.stringify(stored)).not.toContain(minted.secret);

    for (const found of [
      await keyByHash(db, hash),
      await keyById(db, minted.id),
      await keyBySubscription(db, "sub_store"),
      await keyByCheckoutSession(db, "cs_store"),
    ]) {
      expect(found).toEqual(stored);
    }
    expect(await keyByHash(db, await keyHash("nmk_nobody"))).toBeNull();
    expect(await keyBySubscription(db, "sub_nobody")).toBeNull();
  });

  it("refuses a second key for one checkout session", async () => {
    const minted = mintKey();
    await expect(
      putKey(db, {
        id: minted.id,
        keyHash: await minted.hash,
        tier: "standard",
        status: "active",
        customer: "cus_store2",
        subscription: "sub_store2",
        checkoutSession: "cs_store",
        createdAt: NOW.toISOString(),
      }),
    ).rejects.toBeInstanceOf(KeyClaimConflictError);
  });

  it("moves a status and nothing else", async () => {
    const claimed = await claim({ suffix: "status" });
    const before = await keyById(db, claimed.id);
    await setKeyStatus(db, claimed.id, "past_due", "2026-09-12T00:00:00.000Z");
    const after = await keyById(db, claimed.id);
    expect(after).toEqual({
      ...before!,
      status: "past_due",
      updated_at: "2026-09-12T00:00:00.000Z",
    });
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

  it("records a provider event once", async () => {
    expect(await stripeEventSeen(db, "evt_one")).toBe(false);
    await putStripeEvent(db, {
      id: "evt_one",
      type: "invoice.paid",
      receivedAt: NOW.toISOString(),
      outcome: "applied",
    });
    expect(await stripeEventSeen(db, "evt_one")).toBe(true);
    // A retry of a message already acted on must not throw and must not change
    // what was recorded.
    await putStripeEvent(db, {
      id: "evt_one",
      type: "invoice.paid",
      receivedAt: "2027-01-01T00:00:00.000Z",
      outcome: "ignored",
    });
    const row = await db
      .prepare(`SELECT outcome FROM stripe_events WHERE id = ?`)
      .bind("evt_one")
      .first<{ outcome: string }>();
    expect(row?.outcome).toBe("applied");
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

  it("refuses a canceled subscription's key with 402", async () => {
    const claimed = await claim({ suffix: "canceled", status: "canceled" });
    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${claimed.secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      402,
      "key_canceled",
    ]);
  });

  it("refuses a key whose bill did not clear with 402", async () => {
    const claimed = await claim({ suffix: "pastdue", status: "past_due" });
    const resolved = await resolveAccess(
      db,
      ask({ authorization: `Bearer ${claimed.secret}` }),
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      402,
      "key_past_due",
    ]);
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

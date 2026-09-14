/**
 * `GET /entries/{id}/events`: one entry's own events, with their proofs
 * (decision D-120).
 *
 * The log is public and pageable, and until this door existed that was the only
 * way to gather one entry's story: page `GET /events` to its head and keep the
 * lines bearing the id, because a reader who stopped early could not know they
 * had them all. That made a bounded export of a single entry cost a walk of
 * everything, which is the thing a bounded export exists not to do. So the log
 * answers the sub-sequence directly, with each event's covering seal and
 * inclusion proof beside it in exactly the shape `GET /events/{seq}/proof`
 * answers.
 *
 * The log here is seeded through the kernel's own `appendEvent` and `buildSeal`
 * into a real migrated D1: every hash is the hash the kernel computes and every
 * root is over the real leaves, so a proof this door serves is checked below
 * against the root the seal really committed to rather than against a fixture.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  appendEvent,
  buildSeal,
  type ApproverRecord,
  type Core,
  type Event,
  type Seal,
} from "../src/index.js";
import { mintKey } from "../src/keys.js";
import { decodeProof, verifyInclusion } from "../src/merkle.js";
import { RELEASE_WINDOW_DAYS } from "../src/policy.js";
import { appendEvents, putSeal } from "../src/storage/repository.js";
import { putKey } from "../src/storage/keys.js";
import type { Env } from "../src/worker/env.js";
import { cacheablePath, handleRequest } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ORIGIN = "https://app.nomankind.ai";
const NOW = new Date("2026-09-12T00:00:00.000Z");

/** The entry this door is asked about, and one beside it that must not appear. */
const ENTRY = "nmk_00112233445566778899aabbccddeeff";
const OTHER = "nmk_ffeeddccbbaa99887766554433221100";
/** Well formed, and the log has never heard of it. */
const UNKNOWN = "nmk_0123456789abcdef0123456789abcdef";

/** A day inside the release window, and one long past it. */
const AT_RECENT = new Date(NOW.getTime() - 24 * 60 * 60 * 1000).toISOString();
const AT_OLD = new Date(
  NOW.getTime() - (RELEASE_WINDOW_DAYS + 10) * 24 * 60 * 60 * 1000,
).toISOString();

interface Answer {
  entry_id: string;
  head: number | null;
  events: Record<string, unknown>[];
  proofs: {
    seq: number;
    hash: string;
    seal: { seq: number; root: string; hash: string; sealed_at: string };
    inclusion_proof: string;
    witnesses: unknown[];
  }[];
}

let store: TestDatabase;
let env: Env;
let keySecret: string;
let events: Event[] = [];
let seal: Seal;

/**
 * The least a core and a decision record can be.
 *
 * Cast on purpose and said out loud: this door never reads inside a payload —
 * it selects events by entry id, proves them against their seal, and withholds
 * or serves them whole. A full signed core here would be a fixture about
 * validation in a test about routing, and the chain, the seal and the proofs
 * below are all real whatever the payload holds.
 */
function core(id: string): Core {
  return { id, claim: `the claim of ${id}` } as unknown as Core;
}

function record(): ApproverRecord {
  return { operator: "op_one" } as unknown as ApproverRecord;
}

beforeAll(async () => {
  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;

  const minted = mintKey();
  keySecret = minted.secret;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer: "cus_door",
    subscription: "sub_door",
    checkoutSession: "cs_door",
    createdAt: AT_OLD,
  });

  // A log with two entries interleaved, so "this entry's own events" is a claim
  // with something to be wrong about, and one of this entry's events left after
  // the seal, so "sealed events carry a proof and unsealed ones do not" is too.
  events = await appendEvent([], {
    at: AT_OLD,
    type: "operator_registered",
    entry_id: null,
    payload: { operator: "op_one", maintainer: false },
  });
  events = await appendEvent(events, {
    at: AT_OLD,
    type: "entry_submitted",
    entry_id: ENTRY,
    payload: { core: core(ENTRY), signature: "sig_entry" },
  });
  events = await appendEvent(events, {
    at: AT_OLD,
    type: "entry_submitted",
    entry_id: OTHER,
    payload: { core: core(OTHER), signature: "sig_other" },
  });
  events = await appendEvent(events, {
    at: AT_OLD,
    type: "validation",
    entry_id: ENTRY,
    payload: { record: record(), signature: "sig_validation" },
  });
  const sealed = await buildSeal(events, null, { now: AT_RECENT });
  if (!sealed.ok) throw new Error(`seed: buildSeal ${sealed.reason}`);
  seal = sealed.seal;

  // After the seal, so nothing covers it.
  events = await appendEvent(events, {
    at: AT_RECENT,
    type: "reconfirmation",
    entry_id: ENTRY,
    payload: { record: record(), signature: "sig_reconfirm" },
  });

  await appendEvents(store.db, events);
  await putSeal(store.db, seal);
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

function get(
  path: string,
  init?: { key?: string; method?: string },
): Promise<Response> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (init?.key !== undefined) headers["authorization"] = `Bearer ${init.key}`;
  return handleRequest(
    new Request(`${ORIGIN}${path}`, { method: init?.method ?? "GET", headers }),
    env,
    { now: NOW },
  );
}

async function answered(path: string, key?: string): Promise<Answer> {
  const response = await get(path, key === undefined ? undefined : { key });
  expect(response.status).toBe(200);
  return (await response.json()) as Answer;
}

describe("the entry's own events", () => {
  it("answers them in seq order and nothing else's", async () => {
    const body = await answered(`/entries/${ENTRY}/events`, keySecret);

    expect(body.entry_id).toBe(ENTRY);
    expect(body.head).toBe(events[events.length - 1]!.seq);
    // The entry's four: its submission, its validation, its reconfirmation —
    // and never the other entry's submission that sits between them, nor the
    // registration that belongs to no entry.
    expect(body.events.map((event) => event["seq"])).toEqual([1, 3, 4]);
    for (const event of body.events) {
      expect(event["entry_id"]).toBe(ENTRY);
    }
  }, 120_000);

  it("carries one proof per sealed event, and it verifies against the root", async () => {
    const body = await answered(`/entries/${ENTRY}/events`, keySecret);

    // Two of the three are under the seal; the reconfirmation came after it and
    // is here without a proof rather than with a null nobody can check.
    expect(body.proofs.map((proof) => proof.seq)).toEqual([1, 3]);

    for (const proof of body.proofs) {
      expect(proof.seal.seq).toBe(seal.seq);
      expect(proof.seal.root).toBe(seal.root);
      expect(proof.seal.hash).toBe(seal.hash);
      expect(proof.seal.sealed_at).toBe(seal.sealed_at);
      expect(proof.hash).toBe(events[proof.seq]!.hash);

      const decoded = decodeProof(proof.inclusion_proof);
      expect(decoded).not.toBeNull();
      expect(await verifyInclusion(proof.hash, decoded!, seal.root)).toBe(true);
    }
  }, 120_000);

  it("charges one read and says so in the same three headers every door does", async () => {
    const first = await get(`/entries/${ENTRY}/events`);
    expect(first.status).toBe(200);
    const limit = Number(first.headers.get("x-nomankind-limit"));
    const after = Number(first.headers.get("x-nomankind-remaining"));
    expect(first.headers.get("x-nomankind-tier")).toBe("free");
    expect(limit).toBeGreaterThan(0);

    // One call is one read: the next one's remaining is one lower, which is the
    // same arithmetic `GET /events` does for a page.
    const second = await get(`/entries/${ENTRY}/events`);
    expect(Number(second.headers.get("x-nomankind-remaining"))).toBe(after - 1);
  }, 120_000);
});

describe("the release window, on this door as on the paged one", () => {
  it("hands a free reader hash lines, with the proofs beside them", async () => {
    const body = await answered(`/entries/${ENTRY}/events`);

    // The seal is a day old and the window is thirty, so nothing has released.
    for (const event of body.events) {
      expect(event["payload"]).toBeNull();
      expect(event["withheld"]).toBe(true);
      // Everything that is proof stays: the position, the links and the hash.
      expect(typeof event["hash"]).toBe("string");
      expect(event["entry_id"]).toBe(ENTRY);
    }

    // Proof is public from the first minute, whoever is asking.
    expect(body.proofs.map((proof) => proof.seq)).toEqual([1, 3]);
    for (const proof of body.proofs) {
      const decoded = decodeProof(proof.inclusion_proof);
      expect(await verifyInclusion(proof.hash, decoded!, seal.root)).toBe(true);
    }
  }, 120_000);

  it("serves a key the payloads whole", async () => {
    const body = await answered(`/entries/${ENTRY}/events`, keySecret);
    for (const event of body.events) {
      expect(event["payload"]).not.toBeNull();
      expect(event["withheld"]).toBeUndefined();
    }
    const submitted = body.events.find((event) => event["seq"] === 1)!;
    expect(
      (submitted["payload"] as Record<string, unknown>)["signature"],
    ).toBe("sig_entry");
  }, 120_000);
});

describe("what the door refuses", () => {
  it("names a malformed id and an unknown one apart", async () => {
    const bad = await get("/entries/not-an-id/events");
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "bad_id" });

    const missing = await get(`/entries/${UNKNOWN}/events`);
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "not_found" });
  }, 120_000);

  it("refuses a write to a read door, with Allow", async () => {
    const posted = await get(`/entries/${ENTRY}/events`, { method: "POST" });
    expect(posted.status).toBe(405);
    expect(posted.headers.get("allow")).toContain("GET");
    expect(await posted.json()).toEqual({ error: "method_not_allowed" });
  }, 120_000);

  it("is never held at the edge", () => {
    // What it answers depends on who is asking, so it must not be looked for in
    // a shared cache at all — and the entry's own page, under the same prefix,
    // still is.
    expect(cacheablePath(`/entries/${ENTRY}/events`)).toBe(false);
    expect(cacheablePath(`/entries/${ENTRY}`)).toBe(true);
  });
});

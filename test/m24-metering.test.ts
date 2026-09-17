/**
 * M25d: the day's read counts, still published, and billed to nobody.
 *
 * Decision D-127, "the record is free, no money anywhere": the metering step and
 * the payout step are retired. What was the bill's side of Section 9 is gone —
 * the `meter_reports` table is dropped with the step that wrote it (migration
 * 0023) — and what stays is the sentence underneath it: "Read counts are
 * published to the sealed log daily, so nomankind cannot quietly change the
 * numbers later." The daily `read_count` event goes on being published, with its
 * per-key counts, as evidence of use that nobody prices.
 *
 * The world here is deliberately small — receipts, a seal, and two keys — so
 * that what is under test is the sweep and not a milestone's worth of
 * scaffolding around it. Everything it touches is real: miniflare's D1 with the
 * migrations applied, real signed receipts, and the real publish, seal and
 * ledger steps of the sweep the alarm runs. No payment provider is constructed
 * anywhere, because there is no door and no step left to construct one for.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { mintKey } from "../src/keys.js";
import { LIST_PAGE_LIMIT } from "../src/policy.js";
import { signReadReceipt } from "../src/receipt.js";
import { putKey } from "../src/storage/keys.js";
import {
  eventsAfter,
  ledgerCursor,
  nextReadCounter,
  putReadReceipt,
  reconciliationRows,
  sweepSteps,
} from "../src/storage/repository.js";
import type { EventPayloads, Event } from "../src/events.js";
import type { Env } from "../src/worker/env.js";
import {
  LEDGER_CURSOR,
  SWEEP_STEPS,
  runSweep,
  type SweepReport,
} from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

const NOW = new Date("2026-09-10T12:00:00.000Z");
const DAY_MS = 86_400_000;

function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

function date(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

const ENVIRONMENT = "local";
const ENTRY = "nmk_0123456789abcdef0123456789abcdef";
const ENTRY_HASH = `sha256:${"a".repeat(64)}`;

let store: TestDatabase;
let env: Env;
let issuerKey: CryptoKey;
let issuerId = "";

/** Two keys, so "one meter event per key per day" is a claim with two sides. */
let one = { id: "", secret: "", customer: "cus_one" };
let two = { id: "", secret: "", customer: "cus_two" };

/** One signed read receipt on a day, served to a key or to nobody. */
async function receipt(at: Date, keyId: string | null): Promise<void> {
  const counter = await nextReadCounter(store.db);
  const keyCounter = keyId === null ? null : counter;
  const readAt = at.toISOString();
  const signed = await signReadReceipt(
    {
      entry_id: ENTRY,
      entry_hash: ENTRY_HASH,
      read_at: readAt,
      counter,
      issuer: issuerId,
      key: keyId,
      key_counter: keyCounter,
    },
    issuerKey,
  );
  await putReadReceipt(store.db, {
    entryId: ENTRY,
    createdAt: readAt,
    receipt: signed,
    keyId,
    keyCounter,
  });
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m24-metering");
  await beacon.advance(at.toISOString());
  return runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

/** The `read_count` event of one day, once the sweep has published it. */
async function publishedOn(date: string): Promise<Event<"read_count">> {
  const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 4);
  const found = events.find(
    (event) =>
      event.type === "read_count" &&
      (event.payload as EventPayloads["read_count"]).date === date,
  );
  if (found === undefined) throw new Error(`no read_count for ${date}`);
  return found as Event<"read_count">;
}

beforeAll(async () => {
  const pair = await generateKeypair();
  issuerKey = pair.privateKey;
  issuerId = agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));

  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT,
    MAINTAINER_AGENT_ID: "",
    SEALING_AGENT_KEY: base64urlEncode(
      await exportPrivateKeyPkcs8(pair.privateKey),
    ),
  };
  for (const holder of [one, two]) {
    const minted = mintKey();
    holder.id = minted.id;
    holder.secret = minted.secret;
    await putKey(store.db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier: "standard",
      status: "active",
      clientDay: `cs_${minted.id}`,
      createdAt: NOW.toISOString(),
    });
  }

  // Day 0: two reads on one key, one on the other, and one on nobody's.
  await receipt(NOW, one.id);
  await receipt(NOW, one.id);
  await receipt(NOW, two.id);
  await receipt(NOW, null);
}, 600_000);

afterAll(async () => {
  await store?.dispose();
}, 600_000);

// ---------------------------------------------------------------------------
// (a) The count is published; nobody is billed for it
// ---------------------------------------------------------------------------

describe("a published day, under D-127", () => {
  let report: SweepReport;
  let published: Event<"read_count">;

  beforeAll(async () => {
    report = await sweep(day(1));
    published = await publishedOn(date(0));
  }, 600_000);

  it("still publishes the day's counts, per key, as evidence of use", () => {
    const payload = published.payload as EventPayloads["read_count"];
    expect(payload.total).toBe(4);
    expect(payload.paid!.keys).toEqual({ [one.id]: 2, [two.id]: 1 });
    expect(payload.paid!.total).toBe(3);
  });

  it("bills nobody: there is no table left to write a report into", async () => {
    await expect(
      store.db.prepare(`SELECT COUNT(*) AS n FROM meter_reports`).first(),
    ).rejects.toThrow();
  }, 600_000);

  it("has no metering step and no payout step to run", () => {
    expect(SWEEP_STEPS).not.toContain("metering");
    expect(SWEEP_STEPS).not.toContain("payout");
    expect(report).not.toHaveProperty("metered");
    expect(report).not.toHaveProperty("payouts");
  });

  it("writes no row for either retired step, and one for the alerts", async () => {
    const rows = await sweepSteps(store.db);
    const byStep = new Map(rows.map((row) => [row.step, row]));
    expect(byStep.has("metering")).toBe(false);
    expect(byStep.has("payout")).toBe(false);
    expect(byStep.get("alerts")!.detail).toEqual({
      created: 0,
      delivered: 0,
      failed: 0,
      retried: 0,
    });
  }, 600_000);

  it("prices nothing: the ledger step reports ok with a zero count", async () => {
    expect(report.ledger).toEqual({
      through: report.sealed!.last_seq,
      read_shares: 0,
      clawbacks: 0,
      bounties: 0,
      reconciliations: 0,
      entries: 0,
      day: null,
      ok: true,
    });
    // No row of any kind followed from a day of reads.
    expect(await reconciliationRows(store.db, LIST_PAGE_LIMIT)).toEqual([]);
  }, 600_000);

  it("keeps the cursor a fork restarts from", async () => {
    // `npm run import-mirror` sets this, and the step has to go on moving it or
    // a fork would resume at a position nothing ever advances.
    expect(await ledgerCursor(store.db, LEDGER_CURSOR)).toBe(
      report.sealed!.last_seq,
    );
  }, 600_000);

  it("keeps publishing on the days after, unpriced", async () => {
    await receipt(day(1), one.id);
    const again = await sweep(day(2));
    const second = await publishedOn(date(1));
    const payload = second.payload as EventPayloads["read_count"];
    expect(payload.paid!.keys).toEqual({ [one.id]: 1 });
    expect(again.ledger!.read_shares).toBe(0);
    expect(await reconciliationRows(store.db, LIST_PAGE_LIMIT)).toEqual([]);
  }, 600_000);
});

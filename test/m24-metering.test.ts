/**
 * M24: the day's paid reads, reported to the payment provider exactly once.
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily, so nomankind cannot quietly change the numbers later, and any operator
 * can reconcile their payout against the log." The bill has to follow that
 * published number, and this is the step that sends it: one meter event per key
 * per day, drawn from the sealed `read_count` event's own `paid.keys`, with the
 * day and the key inside the identifier so the provider itself refuses a
 * duplicate.
 *
 * The world here is deliberately small — receipts, a seal, and two keys — so
 * that what is under test is the step and not a milestone's worth of scaffolding
 * around it. Everything it touches is real: miniflare's D1 with the migrations
 * applied, real signed receipts, the real publish, seal and ledger steps, and
 * the sweep the alarm runs. The provider is the mock, because the one thing a
 * test of a paid loop must never do is reach a payment provider.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  MockPaymentsAdapter,
  UnavailablePaymentsAdapter,
} from "../src/adapters/stripe.js";
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
  countMeterReports,
  eventsAfter,
  ledgerCursor,
  nextReadCounter,
  putReadReceipt,
  sweepSteps,
} from "../src/storage/repository.js";
import type { EventPayloads, Event } from "../src/events.js";
import type { Env } from "../src/worker/env.js";
import { METERING_CURSOR, runSweep, type SweepReport } from "../src/worker/sweep.js";
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
let payments: MockPaymentsAdapter;
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
async function sweep(
  at: Date,
  provider: MockPaymentsAdapter | UnavailablePaymentsAdapter = payments,
): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m24-metering");
  await beacon.advance(at.toISOString());
  return runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payments: provider,
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
  payments = new MockPaymentsAdapter();

  for (const holder of [one, two]) {
    const minted = mintKey();
    holder.id = minted.id;
    holder.secret = minted.secret;
    await putKey(store.db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier: "standard",
      status: "active",
      customer: holder.customer,
      subscription: `sub_${minted.id}`,
      checkoutSession: `cs_${minted.id}`,
      createdAt: NOW.toISOString(),
    });
  }

  // Day 0: two reads on one key, one on the other, and one on nobody's.
  await receipt(NOW, one.id);
  await receipt(NOW, one.id);
  await receipt(NOW, two.id);
  await receipt(NOW, null);
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) One meter event per key per day
// ---------------------------------------------------------------------------

describe("the metering step over a published day", () => {
  let report: SweepReport;
  let published: Event<"read_count">;

  beforeAll(async () => {
    report = await sweep(day(1));
    published = await publishedOn(date(0));
  }, 120_000);

  it("publishes the day's paid half before it bills anyone", () => {
    const payload = published.payload as EventPayloads["read_count"];
    expect(payload.total).toBe(4);
    expect(payload.paid!.keys).toEqual({ [one.id]: 2, [two.id]: 1 });
    expect(payload.paid!.total).toBe(3);
  });

  it("sends one event per key, with the day inside the identifier", () => {
    // The identifier is the provider's own idempotency key, and it names the
    // environment, the day and the key: three things that cannot collide.
    expect(
      [...payments.reported].sort((left, right) =>
        left.identifier < right.identifier ? -1 : 1,
      ),
    ).toEqual(
      [
        {
          customer: one.customer,
          value: 2,
          identifier: `${ENVIRONMENT}:${date(0)}:${one.id}`,
          timestamp: Math.floor(Date.parse(`${date(0)}T23:59:59Z`) / 1000),
        },
        {
          customer: two.customer,
          value: 1,
          identifier: `${ENVIRONMENT}:${date(0)}:${two.id}`,
          timestamp: Math.floor(Date.parse(`${date(0)}T23:59:59Z`) / 1000),
        },
      ].sort((left, right) => (left.identifier < right.identifier ? -1 : 1)),
    );
  });

  it("reports what it did, and moves its own cursor", async () => {
    expect(report.metered).toEqual({ keys: 2, reads: 3 });
    expect(await countMeterReports(store.db)).toBe(2);
    expect(await ledgerCursor(store.db, METERING_CURSOR)).toBeGreaterThanOrEqual(
      published.seq,
    );
  });

  it("writes a row for its own step and for the alert step beside it", async () => {
    const rows = await sweepSteps(store.db);
    const byStep = new Map(rows.map((row) => [row.step, row]));
    expect(byStep.has("metering")).toBe(true);
    expect(byStep.has("alerts")).toBe(true);
    expect(byStep.get("metering")!.detail).toEqual({ keys: 2, reads: 3 });
    expect(byStep.get("alerts")!.detail).toEqual({
      created: 0,
      delivered: 0,
      failed: 0,
      retried: 0,
    });
  });

  it("never bills the same key-day twice, however often the sweep runs", async () => {
    const again = await sweep(day(1));
    expect(again.metered).toEqual({ keys: 0, reads: 0 });
    expect(payments.reported).toHaveLength(2);
    expect(await countMeterReports(store.db)).toBe(2);
    // The second run's own row says it did nothing, which is the truth about a
    // day already billed rather than a step that failed to bill it.
    const rows = await sweepSteps(store.db);
    const metering = rows.find((row) => row.step === "metering")!;
    expect(metering.detail).toEqual({ keys: 0, reads: 0 });
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (b) A deployment that cannot bill at all
// ---------------------------------------------------------------------------

describe("the metering step where there is no provider", () => {
  it("says so once and reports nothing, leaving the day still owed", async () => {
    // A second day of reads on the first key, published by the run below.
    await receipt(day(1), one.id);

    const report = await sweep(day(2), new UnavailablePaymentsAdapter());
    expect(report.metered).toEqual({ keys: 0, reads: 0 });
    expect(report.skipped["metering_unavailable"]).toBe(1);
    // Nothing was sent and nothing was written down as sent.
    expect(payments.reported).toHaveLength(2);
    expect(await countMeterReports(store.db)).toBe(2);

    // And the next run with the provider back picks the day up.
    const after = await sweep(day(2));
    expect(after.metered).toEqual({ keys: 1, reads: 1 });
    expect(payments.reported[2]).toEqual({
      customer: one.customer,
      value: 1,
      identifier: `${ENVIRONMENT}:${date(1)}:${one.id}`,
      timestamp: Math.floor(Date.parse(`${date(1)}T23:59:59Z`) / 1000),
    });
  }, 120_000);
});

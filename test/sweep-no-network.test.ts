/**
 * A sweep that owes the network nothing must not wait on it, and a sweep that
 * does owe it something must not wait longer than the window says.
 *
 * The demo deployment's alarm took 30,398 milliseconds of wall time against 46
 * milliseconds of CPU on a run whose report said nothing was wrong: nothing
 * sealed, nothing witnessed, nothing mirrored, nothing alerted, no draw due —
 * and thirty seconds is FETCH_TIMEOUT_MS. Two things were behind it, and this
 * file pins both.
 *
 * The first is the draws step, which read the drand chain once a run whether or
 * not a draw was owed. A log whose trusted pool is below the switch owes no draw
 * at all, so that call was made on the strength of nothing and the whole sweep
 * stood behind it.
 *
 * The second is the shape of every timeout. `AbortSignal.timeout(ms)` schedules
 * a timer that cannot be cancelled, and on workerd a pending timer keeps the
 * invocation alive until it fires — so a call that came back in fifty
 * milliseconds still held the alarm open for the rest of the window. Every
 * outbound call now runs under src/adapters/timeout.ts's `withDeadline`, whose
 * timer is cleared the moment the call is done.
 *
 * So the world here is a working one: sealed events to seal and witness, an
 * anchor still waiting for its receipt, a published day with a paid key on it
 * for the metering step to report, a due alert delivery, a mirror that has not
 * exported today, and released rows above the floor for the payout step to pay.
 * Every step has work, and every adapter that reaches the network is the class
 * the deployment runs, wired to a fetch that accepts every call and answers
 * none. The windows are the tests' own small ones — the hook the adapters carry
 * so a test need not wait out thirty real seconds — and what is measured is that
 * each step spends its own window and not a moment more, that the steps that
 * need nothing spend nothing, and that the run finishes.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { LocalAnchorAdapter } from "../src/adapters/anchor.js";
import { DrandReader } from "../src/adapters/beacon.js";
import { GitHubMirrorAdapter } from "../src/adapters/mirror.js";
import { MockPayoutAdapter, MOCK_VERIFIED_PREFIX } from "../src/adapters/payout.js";
import { StripeAdapter } from "../src/adapters/stripe.js";
import { withDeadline } from "../src/adapters/timeout.js";
import { MockWitnessAdapter, MOCK_WITNESSES } from "../src/adapters/witness.js";
import { utcDay } from "../src/anchor.js";
import type { Core } from "../src/core.js";
import { appendEvent, type Event } from "../src/events.js";
import { keyHash } from "../src/keys.js";
import type { LedgerRow } from "../src/ledger.js";
import {
  DEFAULT_DOMAIN,
  FETCH_TIMEOUT_MS,
  NORM_VERSION,
  PAYOUT_MINIMUM_MICROS,
} from "../src/policy.js";
import {
  putAlertDeliveries,
  putAlertEndpoint,
  recentAttempts,
} from "../src/storage/alerts.js";
import { putKey } from "../src/storage/keys.js";
import {
  appendEvents,
  putAnchor,
  putLedgerRows,
  putOperator,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { runSweep, SWEEP_STEPS, type SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock: nothing here reads a wall clock but the durations. */
const NOW = new Date("2026-09-12T00:05:00.000Z");
const AT = NOW.toISOString();

/** A unit constant: a day, in milliseconds. */
const DAY_MS = 86_400_000;

/** The day the published count is about, and the day the anchor is waiting on. */
const YESTERDAY = utcDay(new Date(NOW.getTime() - DAY_MS).toISOString());

/**
 * The window every network call in this test is made under.
 *
 * Small on purpose: what is being measured is that a call that never answers
 * costs its window and nothing more, and thirty real seconds would measure the
 * same thing in thirty seconds. The adapters take it the way `DrandReader` and
 * the capture fetcher always have.
 */
const WINDOW_MS = 60;

/** How long the test gives a whole sweep before it calls it hung. */
const PATIENCE_MS = 5_000;

/** The most any one step may spend: its own window, and room for D1 beside it. */
const STEP_BUDGET_MS = 1_500;

const KEY_ID = "key_sweep_demo";
const OPERATOR = "kestrel";
const ENDPOINT = "hook_sweep_demo";
const ENTRY_ID = "nmk_sweep_demo_00001";

/** A fetch that accepts every call and answers none of them. */
function neverAnswers(asked: string[]): typeof fetch {
  return (async (input: unknown, init?: RequestInit): Promise<Response> => {
    asked.push(String(input));
    return new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;
      if (signal === undefined || signal === null) return;
      // Exactly what a real fetch does when its caller gives up: reject with
      // the reason the signal was aborted with, which is how a caller tells a
      // window that ran out from a host that refused the connection.
      signal.addEventListener("abort", () =>
        reject(signal.reason ?? new Error("aborted")),
      );
    });
  }) as unknown as typeof fetch;
}

/** The run, or a failure saying it was still waiting when patience ran out. */
async function withinPatience(run: Promise<SweepReport>): Promise<SweepReport> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const patience = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error("the sweep was still waiting on the network")),
      PATIENCE_MS,
    );
  });
  try {
    return await Promise.race([run, patience]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * One entry's signed core, as the log carries it: all eighteen keys, because
 * the alert step extracts the core off the event and a missing key is a throw.
 * Nothing here is signed — no door is asked to accept it, and every step that
 * reads it reads the fields rather than the signature.
 */
function core(): Core {
  return {
    id: ENTRY_ID,
    subject: "kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-1 lists $40 per seat per month",
    before: null,
    after: "$40 per seat per month",
    effective_at: AT,
    evidence_tier: "stated",
    evidence: { kind: "document" },
    observation: null,
    citation: "https://kestrel.example.com/pricing",
    snapshot_hash: "0".repeat(64),
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "1F916:YXV0aG9yQWdlbnRJZGVudGl0eUFBQUFBQUE",
    author_operator: OPERATOR,
    submitted_at: AT,
  } as unknown as Core;
}

describe("a sweep with work in every step and a network that never answers", () => {
  let store: TestDatabase;
  const asked: string[] = [];
  let report: SweepReport;

  beforeAll(async () => {
    store = await openTestDatabase();
    const fetchFn = neverAnswers(asked);

    // The log: one submitted entry, and yesterday's published count with a paid
    // key on it. Both are unsealed, so this run's seal step has a batch to seal
    // and its witness step a seal to countersign.
    let events: Event[] = [];
    events = await appendEvent(events, {
      at: AT,
      type: "entry_submitted",
      entry_id: ENTRY_ID,
      payload: { core: core(), signature: "c2lnbmF0dXJl" },
    });
    events = await appendEvent(events, {
      at: AT,
      type: "read_count",
      entry_id: null,
      payload: {
        date: YESTERDAY,
        reads: [{ entry_id: ENTRY_ID, count: 4 }],
        total: 4,
        counter_first: 1,
        counter_last: 4,
        receipts: 4,
        // The paid half, which is what the metering step owes the provider a
        // report for.
        paid: { reads: [{ entry_id: ENTRY_ID, count: 4 }], total: 4, keys: { [KEY_ID]: 4 } },
      },
    });
    await appendEvents(store.db, events);

    // The key that paid for them, so the metering step has a customer to bill.
    await putKey(store.db, {
      id: KEY_ID,
      keyHash: await keyHash("nmk_live_sweep_demo_secret"),
      tier: "startup",
      status: "active",
      customer: "cus_sweep_demo",
      subscription: "sub_sweep_demo",
      checkoutSession: "cs_sweep_demo",
      createdAt: AT,
    });

    // An endpoint with a delivery already due, so the alerts step posts one.
    await putAlertEndpoint(store.db, {
      id: ENDPOINT,
      keyId: KEY_ID,
      url: "https://hook.example.com/alerts",
      secret: "c2VjcmV0LWZvci1zaWduaW5nLWFsZXJ0cy1vbmx5",
      domain: null,
      subject: null,
      category: null,
      kinds: null,
      createdAt: AT,
    });
    await putAlertDeliveries(store.db, [
      {
        id: "alert_sweep_demo",
        endpointId: ENDPOINT,
        eventSeq: 0,
        kind: "verified",
        entryId: ENTRY_ID,
        body: { id: "alert_sweep_demo", kind: "verified" },
        nextAt: AT,
        createdAt: AT,
      },
    ]);

    // The operator that is owed money, onboarded, with a released accrual at
    // the floor: the payout step has a transfer to make.
    await putOperator(store.db, {
      id: OPERATOR,
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: { payout_reference: `${MOCK_VERIFIED_PREFIX}${OPERATOR}` },
    });
    await putLedgerRows(store.db, [
      {
        id: `read_share:${OPERATOR}:sweep-demo`,
        kind: "read_share",
        entry_id: null,
        operator: OPERATOR,
        role: "validator",
        date: "2026-08-01",
        reads: 1,
        unit: "micros",
        amount: PAYOUT_MINIMUM_MICROS,
        available_at: "2026-09-01T00:00:00.000Z",
        seq: 0,
        at: AT,
        ref: {},
      } as unknown as LedgerRow,
    ]);

    // Yesterday's anchor, written and still without its receipt: the anchor
    // step retries it, through an adapter that posts nothing anywhere.
    await putAnchor(store.db, {
      date: YESTERDAY,
      first_seal_seq: null,
      last_seal_seq: null,
      roots: [],
      hash: "0".repeat(64),
      external: null,
    });

    const env = {
      DB: store.db,
      ENVIRONMENT: "demo",
    } as unknown as Env;

    report = await withinPatience(
      runSweep(env, {
        now: NOW,
        // Every one of these is the class the deployment runs, over a fetch
        // that never answers, under a window small enough to watch.
        beacon: new DrandReader(fetchFn, WINDOW_MS),
        witness: new MockWitnessAdapter(),
        pinned: { witnesses: [...MOCK_WITNESSES], registry: null },
        ineligibleAgents: new Set<string>(),
        anchor: new LocalAnchorAdapter(),
        payout: new MockPayoutAdapter(),
        mirror: new GitHubMirrorAdapter({
          token: "not-a-real-token",
          fetch: fetchFn,
          timeoutMs: WINDOW_MS,
        }),
        payments: new StripeAdapter({
          secretKey: "sk_test_not_a_real_key",
          fetch: fetchFn,
          timeoutMs: WINDOW_MS,
        }),
        alertFetch: fetchFn,
        alertTimeoutMs: WINDOW_MS,
      }),
    );
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("gets through every step, with work in each", () => {
    // The steps that need nobody did their work: the batch is sealed, the seal
    // is countersigned by the mock witnesses, and the operator was paid.
    expect(report.sealed).not.toBeNull();
    expect(report.witnessed).toHaveLength(1);
    expect(report.payouts).toEqual([
      {
        operator: OPERATOR,
        amount: PAYOUT_MINIMUM_MICROS,
        transfer: expect.any(String),
      },
    ]);
    expect(report.ledger?.ok).toBe(true);
  });

  it("asks the network only where the step had a call to make", () => {
    // The mirror push, the metering report and the alert delivery: three steps
    // with outside work, and no fourth. The chain is not among them — no draft
    // is owed a validator, and the draws step no longer asks for nothing.
    expect(asked.filter((url) => url.includes("drand"))).toEqual([]);
    expect(asked.some((url) => url.includes("github"))).toBe(true);
    expect(asked.some((url) => url.includes("stripe"))).toBe(true);
    expect(asked.some((url) => url.includes("hook.example.com"))).toBe(true);
  });

  it("counts the unavailable steps rather than pretending they worked", () => {
    // Each of the three says so in its own word, and none of them claims to
    // have done the thing the network never answered.
    expect(report.metered).toEqual({ keys: 0, reads: 0 });
    expect(report.mirror).toBeNull();
    // Two deliveries were posted and neither answered: the one that was already
    // due, and the one this run created from the entry it sealed. Both are on
    // the retry ladder rather than marked delivered or failed.
    expect(report.alerts).toEqual({
      created: 1,
      delivered: 0,
      failed: 0,
      retried: 2,
    });
    // The whole account of the run, exactly: the two steps whose calls never
    // answered say so, the day's counts are current, and the anchor is still
    // waiting for a receipt its local adapter never posts for. Nothing else
    // refused, and nothing pretended to have got through.
    expect(report.skipped).toEqual({
      metering_failed: 1,
      mirror_failed: 1,
      read_counts_current: 1,
      anchor_pending: 1,
    });
  });

  it("records a delivery that timed out as a timeout", async () => {
    // The word matters: the endpoint-silencing rule counts consecutive
    // timeouts, and a deadline of ours that reported something else would
    // leave a dead host being posted to forever.
    const [attempt] = await recentAttempts(store.db, ENDPOINT, 1);
    expect(attempt?.last_status).toBeNull();
    expect(attempt?.last_error).toBe("TimeoutError");
  });

  it("spends its own window per step and no more", () => {
    // Every step the run reached is named, and every one of them is inside the
    // budget: a step that waited out a real thirty-second window — which is
    // what an uncancellable timer did to every step behind it — could not be.
    const measured = Object.keys(report.durations).sort();
    expect(measured).toEqual([...SWEEP_STEPS].sort());
    for (const [step, spent] of Object.entries(report.durations)) {
      expect([step, spent >= 0 && spent < STEP_BUDGET_MS]).toEqual([step, true]);
    }
    const total = Object.values(report.durations).reduce((a, b) => a + b, 0);
    expect(total).toBeLessThan(PATIENCE_MS);
    expect(total).toBeLessThan(FETCH_TIMEOUT_MS);
  });
});

describe("the deadline every outbound call is made under", () => {
  it("clears its timer when the call comes back", async () => {
    vi.useFakeTimers();
    try {
      const answered = await withDeadline(FETCH_TIMEOUT_MS, async (signal) => {
        expect(signal.aborted).toBe(false);
        return "answered";
      });
      expect(answered).toBe("answered");
      // The whole regression in one assertion: a timer still pending after the
      // call it was watching is what held the alarm open for thirty seconds.
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("clears its timer when the call throws", async () => {
    vi.useFakeTimers();
    try {
      await expect(
        withDeadline(FETCH_TIMEOUT_MS, async () => {
          throw new Error("network");
        }),
      ).rejects.toThrow("network");
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts the call with a timeout when the window runs out", async () => {
    vi.useFakeTimers();
    try {
      let reason: unknown = null;
      const call = withDeadline(
        FETCH_TIMEOUT_MS,
        (signal) =>
          new Promise<string>((_resolve, reject) => {
            signal.addEventListener("abort", () => {
              reason = signal.reason;
              reject(signal.reason);
            });
          }),
      );
      // The assertion is attached before the clock moves, because the rejection
      // arrives inside the tick that advances it.
      const refused = expect(call).rejects.toThrow(/deadline/);
      await vi.advanceTimersByTimeAsync(FETCH_TIMEOUT_MS);
      await refused;
      // Named the way `AbortSignal.timeout` named it, because the records that
      // count a silent endpoint read the name.
      expect((reason as { name?: string } | null)?.name).toBe("TimeoutError");
    } finally {
      vi.useRealTimers();
    }
  });
});

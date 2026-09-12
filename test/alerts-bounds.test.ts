/**
 * What one run of the alert step may do, and what it does about a host that
 * never answers.
 *
 * Whitepaper Section 9: change alerts are a paid feature, and M24 built them
 * (decision D-091). The step walks the sealed log, derives the alerts its events
 * call for, and posts what is due — and every one of those three is unbounded
 * unless something bounds it. Deriving one event's alerts rebuilds an entry's
 * world; a page of events with several endpoints subscribed writes events times
 * alerts times endpoints rows; and a delivery may take ALERT_TIMEOUT_MS, so a
 * run that posted a page of them could be held for a quarter of an hour by hosts
 * that never answer, with the backlog behind them only growing.
 *
 * So a run reads ALERT_EVENTS_PER_RUN events past its cursor, posts
 * ALERT_DELIVERIES_PER_RUN due deliveries oldest first, and turns off an
 * endpoint whose last ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE deliveries all timed
 * out — its pending deliveries closed with `endpoint_disabled` rather than
 * posted, and `enabled: false` on its holder's own listing. These tests measure
 * exactly that, against miniflare's D1 with every migration applied, an injected
 * clock, and a `fetch` that answers or times out because the test said so.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { appendEvent, type Event } from "../src/events.js";
import { KEY_PREFIX, keyHash } from "../src/keys.js";
import {
  ALERT_DELIVERIES_PER_RUN,
  ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE,
  ALERT_EVENTS_PER_RUN,
  ALERT_RETRY_MINUTES,
} from "../src/policy.js";
import {
  alertCursor,
  deliveriesForEndpoint,
  putAlertDeliveries,
  putAlertEndpoint,
  setAlertCursor,
  type AlertDeliveryInput,
} from "../src/storage/alerts.js";
import type { D1Like } from "../src/storage/d1.js";
import { putKey } from "../src/storage/keys.js";
import { appendEvents } from "../src/storage/repository.js";
import { handleAlerts, runAlertStep } from "../src/worker/alerts.js";
import type { Env } from "../src/worker/env.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock: nothing here reads a wall clock. */
const NOW = new Date("2026-09-12T00:05:00.000Z");
const AT = NOW.toISOString();

/** The instant plus so many minutes, as the retry ladder counts them. */
function later(minutes: number): Date {
  return new Date(NOW.getTime() + minutes * 60_000);
}

/** A fetch that answers every request, recording what it was asked. */
interface FakeFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** The URL and delivery id of every call, in order. */
  readonly calls: { url: string; delivery: string }[];
}

/**
 * A fetch whose answer depends on the host.
 *
 * `timeOutFor` is the URL that never answers: the call rejects with the same
 * `TimeoutError` `AbortSignal.timeout` raises, which is what a host that does
 * not answer inside ALERT_TIMEOUT_MS looks like from here.
 */
function fakeFetch(timeOutFor?: string): FakeFetch {
  const calls: { url: string; delivery: string }[] = [];
  const call = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    calls.push({ url, delivery: headers.get("x-nomankind-alert") ?? "" });
    if (url === timeOutFor) {
      const error = new Error("The operation was aborted due to timeout");
      error.name = "TimeoutError";
      throw error;
    }
    return new Response(null, { status: 200 });
  }) as FakeFetch;
  Object.defineProperty(call, "calls", { value: calls });
  return call;
}

/** One endpoint row, straight into the store: no door, no secret to show. */
async function endpoint(
  db: D1Like,
  id: string,
  keyId: string,
  url: string,
): Promise<void> {
  await putAlertEndpoint(db, {
    id,
    keyId,
    url,
    secret: "c2VjcmV0LWZvci1zaWduaW5nLWFsZXJ0cy1vbmx5",
    domain: null,
    subject: null,
    category: null,
    kinds: null,
    createdAt: AT,
  });
}

/** One pending delivery, as the step's own writer shapes it. */
function delivery(
  id: string,
  endpointId: string,
  nextAt: string,
): AlertDeliveryInput {
  return {
    id,
    endpointId,
    eventSeq: 1,
    kind: "verified",
    entryId: "nmk_bounds_00001",
    body: { id, kind: "verified" },
    nextAt,
    createdAt: AT,
  };
}

describe("createDeliveries: ALERT_EVENTS_PER_RUN events a run", () => {
  let store: TestDatabase;
  let head = 0;

  beforeAll(async () => {
    store = await openTestDatabase();
    await endpoint(store.db, "hook_reader", "key_reader", "https://ok.example.com/hook");

    // Fifty sealed events nobody is alerted about: a `read_count` is about a
    // day and not about an entry, so the step reads it, derives nothing, and
    // moves its cursor — which is the bound this test is measuring.
    let events: Event[] = [];
    for (let day = 1; day <= 50; day += 1) {
      events = await appendEvent(events, {
        at: AT,
        type: "read_count",
        entry_id: null,
        payload: {
          date: `2026-07-${String(day).padStart(2, "0")}`,
          reads: [],
          total: 0,
          counter_first: null,
          counter_last: null,
          receipts: 0,
        },
      });
    }
    await appendEvents(store.db, events);
    head = events[events.length - 1]!.seq;
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("reads the first twenty and leaves the cursor there", async () => {
    const report = await runAlertStep(
      store.db,
      { now: NOW, sealedHead: head, fetch: fakeFetch(), origin: "" },
      () => {},
    );

    expect(report.created).toBe(0);
    expect(await alertCursor(store.db)).toBe(ALERT_EVENTS_PER_RUN - 1);
  }, 600_000);

  it("reads the next twenty on the run after it", async () => {
    await runAlertStep(
      store.db,
      { now: NOW, sealedHead: head, fetch: fakeFetch(), origin: "" },
      () => {},
    );
    expect(await alertCursor(store.db)).toBe(ALERT_EVENTS_PER_RUN * 2 - 1);

    // And the backlog is caught up rather than dropped: the third run takes the
    // last ten and the cursor reaches the head.
    await runAlertStep(
      store.db,
      { now: NOW, sealedHead: head, fetch: fakeFetch(), origin: "" },
      () => {},
    );
    expect(await alertCursor(store.db)).toBe(head);
  }, 600_000);
});

describe("the delivery loop: ALERT_DELIVERIES_PER_RUN a run, oldest first", () => {
  let store: TestDatabase;
  const DUE = 30;
  const HOOK = "hook_backlog";
  const URL_ = "https://backlog.example.com/hook";

  /** The delivery ids in the order the step owes them: oldest `next_at` first. */
  const owed = Array.from({ length: DUE }, (_, index) => `del_${index}`);

  beforeAll(async () => {
    store = await openTestDatabase();
    await endpoint(store.db, HOOK, "key_backlog", URL_);
    // A backlog built up while nothing ran: every one of them is due, and each
    // is a second older than the next.
    await putAlertDeliveries(
      store.db,
      owed.map((id, index) =>
        delivery(
          id,
          HOOK,
          new Date(NOW.getTime() - (DUE - index) * 1000).toISOString(),
        ),
      ),
    );
    // Nothing to derive: the cursor is already at the head this run is given.
    await setAlertCursor(store.db, 0);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("drains eight a run, in the order the backlog built up", async () => {
    for (let run = 0; run < 4; run += 1) {
      const call = fakeFetch();
      const report = await runAlertStep(
        store.db,
        { now: NOW, sealedHead: 0, fetch: call, origin: "" },
        () => {},
      );

      const expected = owed.slice(
        run * ALERT_DELIVERIES_PER_RUN,
        (run + 1) * ALERT_DELIVERIES_PER_RUN,
      );
      expect(call.calls.map((made) => made.delivery)).toEqual(expected);
      expect(report.delivered).toBe(expected.length);
      expect(report.failed).toBe(0);
      expect(report.retried).toBe(0);
    }

    // Thirty of them, eight at a time: four runs, and the last one short.
    const rows = await deliveriesForEndpoint(store.db, HOOK, null, 100);
    expect(rows).toHaveLength(DUE);
    expect(rows.every((row) => row.status === "delivered")).toBe(true);
  }, 600_000);
});

describe("an endpoint that stops answering", () => {
  let store: TestDatabase;
  const DEAD = "hook_dead";
  const LIVE = "hook_live";
  const DEAD_URL = "https://dead.example.com/hook";
  const LIVE_URL = "https://live.example.com/hook";
  const KEY_ID = "key_owner";
  const SECRET = `${KEY_PREFIX}${"a".repeat(43)}`;

  /** The five deliveries the dead endpoint never answers. */
  const deadIds = Array.from(
    { length: ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE },
    (_, index) => `del_dead_${index}`,
  );

  beforeAll(async () => {
    store = await openTestDatabase();
    await putKey(store.db, {
      id: KEY_ID,
      keyHash: await keyHash(SECRET),
      tier: "startup",
      status: "active",
      customer: "cus_test",
      subscription: "sub_test",
      checkoutSession: "cs_test",
      createdAt: AT,
    });
    await endpoint(store.db, DEAD, KEY_ID, DEAD_URL);
    await endpoint(store.db, LIVE, KEY_ID, LIVE_URL);
    await putAlertDeliveries(store.db, [
      ...deadIds.map((id) => delivery(id, DEAD, AT)),
      delivery("del_live_0", LIVE, AT),
      delivery("del_live_1", LIVE, AT),
      delivery("del_live_2", LIVE, AT),
    ]);
    await setAlertCursor(store.db, 0);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  /** The holder's own listing, through the door they would ask at. */
  async function listing(): Promise<Record<string, unknown>[]> {
    const response = await handleAlerts(
      new Request("https://nomankind.ai/keys/me/webhooks", {
        headers: { authorization: `Bearer ${SECRET}` },
      }),
      { DB: store.db } as unknown as Env,
      { now: NOW },
    );
    expect(response?.status).toBe(200);
    const body = (await response!.json()) as {
      endpoints: Record<string, unknown>[];
    };
    return body.endpoints;
  }

  it("retries the first timeouts like any other failure", async () => {
    const call = fakeFetch(DEAD_URL);
    const report = await runAlertStep(
      store.db,
      { now: NOW, sealedHead: 0, fetch: call, origin: "" },
      () => {},
    );

    // Eight due, eight posted: five that never answered and three that did.
    expect(call.calls).toHaveLength(ALERT_DELIVERIES_PER_RUN);
    expect(report.delivered).toBe(3);
    expect(report.retried).toBe(ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE);
    expect(report.failed).toBe(0);

    // Nothing is off yet on this run: the rule is about the last five, and the
    // fifth had not timed out when the first was posted.
    const rows = await deliveriesForEndpoint(store.db, DEAD, null, 10);
    for (const row of rows) {
      expect(row.status).toBe("pending");
      expect(row.last_error).toBe("TimeoutError");
      expect(row.attempts).toBe(1);
    }
  }, 600_000);

  it("turns the endpoint off, and tells its holder so", async () => {
    const shown = await listing();
    const byId = new Map(shown.map((row) => [row["id"], row["enabled"]]));
    expect(byId.get(DEAD)).toBe(false);
    // The healthy one is untouched: this is a rule about one endpoint's own
    // record and never about the key that holds it.
    expect(byId.get(LIVE)).toBe(true);
  }, 600_000);

  it("fails its pending deliveries endpoint_disabled and keeps the other going", async () => {
    // Two more alerts for the healthy endpoint, and the ladder's first rung has
    // passed, so the dead endpoint's five are due again.
    await putAlertDeliveries(store.db, [
      delivery("del_live_3", LIVE, AT),
      delivery("del_live_4", LIVE, AT),
    ]);
    const at = later(ALERT_RETRY_MINUTES[0]! + 1);

    const call = fakeFetch(DEAD_URL);
    const report = await runAlertStep(
      store.db,
      { now: at, sealedHead: 0, fetch: call, origin: "" },
      () => {},
    );

    // Seven due, and not one of them was posted to the dead host.
    expect(call.calls.map((made) => made.url)).toEqual([LIVE_URL, LIVE_URL]);
    expect(report.delivered).toBe(2);
    expect(report.failed).toBe(ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE);
    expect(report.retried).toBe(0);

    const dead = await deliveriesForEndpoint(store.db, DEAD, null, 10);
    expect(dead).toHaveLength(ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE);
    for (const row of dead) {
      expect(row.status).toBe("failed");
      expect(row.last_error).toBe("endpoint_disabled");
    }

    const live = await deliveriesForEndpoint(store.db, LIVE, null, 10);
    expect(live.filter((row) => row.status === "delivered")).toHaveLength(5);

    // And it stays off: the rows the rule wrote are the silence continuing, not
    // evidence against it.
    const shown = await listing();
    expect(shown.find((row) => row["id"] === DEAD)?.["enabled"]).toBe(false);
    expect(shown.find((row) => row["id"] === LIVE)?.["enabled"]).toBe(true);
  }, 600_000);
});

/**
 * `stale` at the read door, derived rather than remembered.
 *
 * The schema says of `stale` that it is "true when expires_at is in the past",
 * and of every derived field that it is "computed from append-only events or
 * from the core, never written directly". It is the one derived field whose
 * answer depends on when it is asked, and the stored `entries` row carries the
 * answer its last writer's clock gave.
 *
 * The QA of 2026-09-12 found the read door handing that stored answer out: an
 * entry whose ninety-day window closed overnight was served `"stale": false`
 * until the sweep's staleness step got round to rewriting the row, so the door
 * served a fact the entry itself says is out of date without saying so — and
 * the same entry, read again a few minutes later after a sweep that appended no
 * event and changed nothing about the log, read differently. A derived field
 * that changes when a background job runs is not derived.
 *
 * So the door reads it against the request's own clock (src/worker/read.ts,
 * `clocked`), by `expiredByClock` — the same function `GET /sync` and the
 * mirror already apply to a row they serve from storage, so the three doors
 * cannot disagree about a calendar. The column stays: the sweep goes on
 * rewriting it, the ledger's half shares and the counters are counted off it,
 * and the index on it is what makes "which entries went stale overnight" a
 * seek. What this file pins is that the JSON a reader is handed is the same
 * before and after that rewrite.
 *
 * The sync door's half of the same rule has its own file
 * (test/sync-fast-path.test.ts, "a row the page cannot answer from"), where a
 * page served under a seal past every window is checked against a full
 * re-derivation at that clock.
 *
 * miniflare's D1 with the real migrations, the real kernel derivation, the real
 * read route, and an injected clock: nothing here reads a wall clock.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import { deriveEntry } from "../src/derive.js";
import { appendEvent, type Event, type EventType } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { DEFAULT_DOMAIN, RELEASE_WINDOW_DAYS } from "../src/policy.js";
import { buildSeal } from "../src/seal.js";
import {
  appendEvents,
  getEntry,
  putEntry,
  putSeal,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRead } from "../src/worker/read.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ORIGIN = "https://api.test";
const ENTRY_ID = "nmk_0123456789abcdef0123456789abcdef";
const DAY0 = new Date("2026-09-01T00:00:00.000Z");
const DAY_MS = 86_400_000;
/** The pricing window, and the first day past it. */
const WINDOW_DAYS = 90;

function day(days: number): Date {
  return new Date(DAY0.getTime() + days * DAY_MS);
}

let store: TestDatabase;
let env: Env;
let events: Event[] = [];

/** A submitted core, complete to the schema's eighteen keys. */
function core(): Core {
  return {
    id: ENTRY_ID,
    subject: "example/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-2 seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://kestrel.example/pricing",
    snapshot_hash: `sha256:${"0".repeat(64)}`,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: `1F916:${"a".repeat(32)}`,
    author_operator: null,
    submitted_at: DAY0.toISOString(),
  } as unknown as Core;
}

async function add<T extends EventType>(
  type: T,
  entryId: string | null,
  payload: Event<T>["payload"],
): Promise<void> {
  events = await appendEvent(events, {
    at: DAY0.toISOString(),
    type,
    entry_id: entryId,
    payload,
  });
}

/** The entry as `GET /read/{id}` answers it, at one instant. */
async function read(now: Date): Promise<Record<string, unknown>> {
  const response = await handleRead(
    new Request(`${ORIGIN}/read/${ENTRY_ID}`),
    env,
    { now },
  );
  expect(response).not.toBeNull();
  expect(response!.status).toBe(200);
  const body = (await response!.json()) as Record<string, unknown>;
  return body["entry"] as Record<string, unknown>;
}

/** The `stale` column and the JSON's own field, as the row holds them. */
async function row(): Promise<{ stale: unknown; column: unknown }> {
  const stored = await getEntry(store.db, ENTRY_ID);
  const column = await store.db
    .prepare(`SELECT stale FROM entries WHERE id = ?`)
    .bind(ENTRY_ID)
    .first<{ stale: number }>();
  return {
    stale: (stored!.entry as unknown as Record<string, unknown>)["stale"],
    column: column!.stale,
  };
}

beforeAll(async () => {
  store = await openTestDatabase();
  const pair = await generateKeypair();

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "1F916:maintainer",
    SEALING_AGENT_KEY: base64urlEncode(
      await exportPrivateKeyPkcs8(pair.privateKey),
    ),
  };

  // The registry: a maintainer and three outside operators, two of which judge
  // the entry. Three, because verification's precondition is three operators
  // outside the submitter's own that could actually sign it.
  await add("operator_registered", null, {
    operator: "maintainer.example",
    maintainer: true,
  });
  for (const operator of ["k1.example", "k2.example", "k3.example"]) {
    await add("operator_registered", null, { operator, maintainer: false });
    await add("operator_trusted", null, { operator });
  }
  await add("entry_submitted", ENTRY_ID, { core: core(), signature: "sig" });
  for (const [index, operator] of ["k1.example", "k2.example"].entries()) {
    await add("validation", ENTRY_ID, {
      record: {
        agent: `1F916:agent-${operator}`,
        operator,
        decision: "approve",
        reason: null,
        snapshot_hash: `sha256:${"0".repeat(64)}`,
        assigned_random: false,
        test_accepted: null,
        reproduction: null,
        observation: null,
        signed_at: day(index).toISOString(),
      },
      signature: "sig",
    } as never);
  }
  await appendEvents(store.db, events);

  // The seal, at day 0: the release window runs from it, so the entry's content
  // is public from day RELEASE_WINDOW_DAYS and a free reader is served after.
  const built = await buildSeal(events, null, { now: DAY0.toISOString() });
  if (!built.ok) throw new Error(`seal: ${built.reason}`);
  await putSeal(store.db, built.seal);

  // The row exactly as the door that verified it left it: derived on day 0,
  // inside the window, so its `stale` is the answer day 0 gave.
  const derived = deriveEntry(events, ENTRY_ID, { now: DAY0.toISOString() });
  expect(derived.derived.status).toBe("verified");
  expect(derived.derived.expires_at).toBe("2026-11-30");
  await putEntry(
    store.db,
    derived.entry,
    derived.sidecar,
    events[events.length - 1]!.seq,
  );
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the read door's `stale`", () => {
  it("says false while the window is open", async () => {
    const served = await read(day(RELEASE_WINDOW_DAYS + 1));
    expect(served["status"]).toBe("verified");
    expect(served["stale"]).toBe(false);
    expect(served["expires_at"]).toBe("2026-11-30");
  }, 600_000);

  it("says true past the window, before any sweep has touched the row", async () => {
    // Nothing has been written since the approvals: the stored copy still says
    // what day 0 said, and the reader is told what today says.
    expect(await row()).toEqual({ stale: false, column: 0 });

    const served = await read(day(WINDOW_DAYS + 1));
    expect(served["stale"]).toBe(true);
    // Section 7: past its window an entry stays verified but shows as stale.
    expect(served["status"]).toBe("verified");
    // And the row is untouched: the door derived an answer, it did not write one.
    expect(await row()).toEqual({ stale: false, column: 0 });
  }, 600_000);

  it("is still fresh on the expiry day itself", async () => {
    // `expires_at` is a calendar date and the comparison is of UTC days, so the
    // expiry day is the last fresh one -- the rule `freshnessOf` applies, and
    // the door must not read it a second way.
    expect((await read(day(WINDOW_DAYS)))["stale"]).toBe(false);
  }, 600_000);

  it("reads the same before and after the sweep rewrites the row", async () => {
    const at = day(WINDOW_DAYS + 5);
    const before = await read(at);

    // What the sweep's staleness step writes: the entry rederived at its own
    // clock, stored, no event appended.
    const swept = deriveEntry(events, ENTRY_ID, { now: at.toISOString() });
    expect(swept.derived.stale).toBe(true);
    await putEntry(
      store.db,
      swept.entry,
      swept.sidecar,
      events[events.length - 1]!.seq,
    );
    expect(await row()).toEqual({ stale: true, column: 1 });

    const after = await read(at);
    expect(JSON.stringify(after)).toBe(JSON.stringify(before));
    expect(after["stale"]).toBe(true);
  }, 600_000);

  it("leaves a stored `true` alone whatever the calendar says", async () => {
    // D-096's version staleness is a fact about the log and not about the
    // clock: an observation of a model version another version has replaced is
    // stale permanently, with `expires_at` exactly where the window put it. The
    // door adds the calendar's answer to the row's and never replaces it, so a
    // row that came in stale stays stale.
    const swept = deriveEntry(events, ENTRY_ID, { now: DAY0.toISOString() });
    await putEntry(
      store.db,
      { ...swept.entry, stale: true },
      swept.sidecar,
      events[events.length - 1]!.seq,
    );
    // Read inside the freshness window, so the calendar's own answer is false.
    expect((await read(day(RELEASE_WINDOW_DAYS + 2)))["stale"]).toBe(true);
  }, 600_000);
});

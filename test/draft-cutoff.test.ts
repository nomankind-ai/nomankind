/**
 * The draws step's queue, bounded (M25, migration 0019, DRAW_DRAFT_MAX_AGE_DAYS).
 *
 * The QA of 2026-09-12: the sweep's draws step paged every draft in the table
 * on every run, so a draft nobody ever validated stayed in the working set
 * forever and every run paid for it again — a cost that grows with the log and
 * is spent on entries the log has already given up drawing for.
 *
 * What is pinned here is the bound and what it does not touch. A draft
 * submitted within DRAW_DRAFT_MAX_AGE_DAYS of the run's own clock is paged; one
 * submitted before it is not, and never is again, because the cutoff is on
 * `submitted_at` and nothing moves that — so a validation does not put an older
 * draft back in the queue. The entry itself is untouched: it is still a draft,
 * still in the table, still readable, and still open to a volunteer.
 *
 * miniflare's D1 with the real migrations applied, because the bound is a
 * predicate the database applies and an index (0019) serves. The clock is
 * injected: every instant below is measured from one `NOW` that never moves.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
import { appendEvent, type Event } from "../src/events.js";
import { DEFAULT_DOMAIN, DRAW_DRAFT_MAX_AGE_DAYS, NORM_VERSION } from "../src/policy.js";
import type { D1Like } from "../src/storage/d1.js";
import { appendEvents, listEntries, putEntry } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The instant every run below is made at. */
const NOW = new Date("2026-09-12T12:00:00.000Z");
const DAY_MS = 86_400_000;

/** How old each of the two drafts is, either side of the cutoff. */
const YOUNG_DAYS = 1;
const OLD_DAYS = DRAW_DRAFT_MAX_AGE_DAYS + 1;

const YOUNG_ID = `nmk_${"1".repeat(32)}`;
const OLD_ID = `nmk_${"2".repeat(32)}`;

let store: TestDatabase;
let db: D1Like;

/** An instant that many days before the run's clock. */
function daysAgo(days: number): string {
  return new Date(NOW.getTime() - days * DAY_MS).toISOString();
}

/** A core with exactly the schema's signed keys. */
function coreOf(id: string, submittedAt: string): Core {
  const core: Record<string, unknown> = {
    id,
    subject: "example.com",
    category: "fact",
    domain: DEFAULT_DOMAIN,
    claim: "The sky is blue.",
    before: null,
    after: `blue ${id}`,
    effective_at: submittedAt,
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://example.com/sky",
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "nmk_agent_test",
    author_operator: null,
    submitted_at: submittedAt,
  };
  expect(Object.keys(core).sort()).toEqual([...CORE_KEYS].sort());
  return core as Core;
}

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;

  // Two drafts and nothing else: one submitted yesterday, one submitted a day
  // past the cutoff. No trusted pool, so no draw is owed on either — what is
  // measured is which of them the step reads at all.
  let events: Event[] = [];
  for (const [id, days] of [
    [OLD_ID, OLD_DAYS],
    [YOUNG_ID, YOUNG_DAYS],
  ] as const) {
    const at = daysAgo(days);
    events = await appendEvent(events, {
      at,
      type: "entry_submitted",
      entry_id: id,
      payload: { core: coreOf(id, at), signature: "sig" },
    } as never);
  }
  await appendEvents(db, events);
  for (const id of [OLD_ID, YOUNG_ID]) {
    const derived = deriveEntry(events, id, { now: NOW.toISOString() });
    expect(derived.entry["status"]).toBe("draft");
    await putEntry(db, derived.entry, derived.sidecar, events[events.length - 1]!.seq);
  }
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

function envOf(): Env {
  return {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}

describe("the drafts a listing bounded by submitted_at pages", () => {
  it("pages the draft inside the window and not the one outside it", async () => {
    const cutoff = new Date(
      NOW.getTime() - DRAW_DRAFT_MAX_AGE_DAYS * DAY_MS,
    ).toISOString();
    const page = await listEntries(db, {
      status: "draft",
      limit: 100,
      submittedAtOrAfter: cutoff,
    });
    expect(page.map((stored) => stored.entry["id"])).toEqual([YOUNG_ID]);
  });

  it("pages both when nothing bounds it, so the row is there either way", async () => {
    // The bound is on the queue and not on the entry: the abandoned draft is
    // still a draft and still in the table, and a listing that does not ask for
    // the bound still sees it.
    const page = await listEntries(db, { status: "draft", limit: 100 });
    expect(page.map((stored) => stored.entry["id"]).sort()).toEqual(
      [OLD_ID, YOUNG_ID].sort(),
    );
  });

  it("takes the bound and the keyset together", async () => {
    const cutoff = daysAgo(DRAW_DRAFT_MAX_AGE_DAYS);
    const first = await listEntries(db, {
      status: "draft",
      limit: 1,
      submittedAtOrAfter: cutoff,
    });
    expect(first).toHaveLength(1);
    const next = await listEntries(db, {
      status: "draft",
      limit: 1,
      submittedAtOrAfter: cutoff,
      afterSubmittedSeq: first[0]!.submittedSeq,
    });
    // Only one draft is inside the window, so the page after it is empty —
    // and the older draft is not waiting behind the cursor.
    expect(next).toEqual([]);
  });
});

describe("the sweep's draws step", () => {
  /**
   * Every draft the step pages is asked `drawDue` and, with no trusted pool,
   * answers `pool_below_switch` — one skip per draft read. So the count is
   * exactly how many drafts the step put in its working set, which is the thing
   * the bound changes.
   */
  it("reads only the drafts inside the window", async () => {
    const beacon = new FixtureBeacon("draft-cutoff");
    await beacon.advance(new Date(NOW.getTime() - 60_000).toISOString());
    const report = await runSweep(envOf(), { now: NOW, beacon });
    expect(report.skipped["pool_below_switch"]).toBe(1);
    expect(report.drawn).toEqual([]);
  });

  it("leaves the abandoned draft in the log, a draft and readable", async () => {
    const page = await listEntries(db, { status: "draft", limit: 100 });
    const old = page.find((stored) => stored.entry["id"] === OLD_ID);
    expect(old).toBeDefined();
    expect(old!.entry["status"]).toBe("draft");
  });
});

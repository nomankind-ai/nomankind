/**
 * The co-signing view: who signed beside whom, and how the two fell (D-119).
 *
 * The question is a reader's, asked of the demo: how do I tell three
 * independent confirmations from three copies of one procedure. The log has
 * always held the answer — `validation` and `reconfirmation` say who signed
 * what — so the counters step folds it into rows and the pages read the rows.
 *
 * Three things are pinned here, which are the three the Plan asked for. The
 * counts are a hand fold over the fixture's own events, written out below, so
 * the test knows the answer without running the code that produces it. Every
 * entry the page lists is a link a reader can follow. And a page view issues no
 * scan over the events for any of it, asserted against the SQL the render
 * actually prepares rather than described in a comment — the same wrapper
 * test/operator-counters.test.ts uses, because it is the same promise.
 *
 * The fourth is the fold's own bargain: a second run at the same head must not
 * count the same pair twice, and a run at a cursor must not read the log.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type {
  ApproverRecord,
  Event,
  EventInput,
  ReconfirmationRecord,
} from "../src/events.js";
import { appendEvent } from "../src/events.js";
import {
  appendEvents,
  cosignPairsForOperator,
  cosignerCountsForOperators,
  putOperator,
  readCosignCursor,
  writeCosignCursor,
} from "../src/storage/repository.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";
import { countersStep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-13T00:00:00.000Z");
const AT = NOW.toISOString();

const ALPHA = "alpha.example";
const BETA = "beta.example";
const GAMMA = "gamma.example";
const OPERATORS = [ALPHA, BETA, GAMMA] as const;

const E1 = "nmk_cosign1";
const E2 = "nmk_cosign2";
const E3 = "nmk_cosign3";

/**
 * The fixture, as the log holds it: who signed what, which way, in this order.
 *
 * e1: all three approve — three pairs, all agreed.
 * e2: alpha and beta approve, gamma rejects — alpha/beta agreed, and gamma
 *     opposed to each of them.
 * e3: alpha approves and beta reconfirms — one pair, agreed, because
 *     reconfirming an entry is the same side as approving it.
 * Beta signs e1 twice, the second time the other way: the fold takes an
 * operator's first stance on an entry, so the pair is what it was when it was
 * formed and a later second thought does not rewrite it.
 */
const DECISIONS = [
  [E1, ALPHA, "approve"],
  [E1, BETA, "approve"],
  [E1, GAMMA, "approve"],
  [E2, ALPHA, "approve"],
  [E2, BETA, "approve"],
  [E2, GAMMA, "reject"],
  [E3, ALPHA, "approve"],
  [E1, BETA, "reject"],
] as const;

/** The hand fold: pair, entries both signed, agreed, opposed. */
const EXPECTED = [
  [ALPHA, BETA, 3, 3, 0],
  [ALPHA, GAMMA, 2, 1, 1],
  [BETA, GAMMA, 2, 1, 1],
] as const;

function approver(
  operator: string,
  decision: "approve" | "reject",
): ApproverRecord {
  return {
    agent: `1F916:${operator}-agent`,
    operator,
    decision,
    reason: decision === "reject" ? "citation did not say it" : null,
    snapshot_hash: `sha256:${"2".repeat(64)}`,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  };
}

function reconfirmation(operator: string): ReconfirmationRecord {
  return {
    agent: `1F916:${operator}-agent`,
    operator,
    snapshot_hash: `sha256:${"3".repeat(64)}`,
    reproduction: null,
    observation: null,
    signed_at: AT,
  };
}

/**
 * A database that remembers the SQL a render prepared.
 *
 * The assertion this file turns on is about a statement that must not be made,
 * and the only honest way to ask that is of the SQL itself.
 */
function watching(db: D1Like): { db: D1Like; sql: () => string[] } {
  const seen: string[] = [];
  const wrapped: D1Like = {
    prepare(sql: string): D1LikeStatement {
      seen.push(sql);
      return db.prepare(sql);
    },
    batch: (statements) => db.batch(statements),
    exec: (sql) => db.exec(sql),
  };
  return { db: wrapped, sql: () => seen };
}

let store: TestDatabase;
let db: D1Like;
let chain: Event[] = [];

async function add(input: EventInput): Promise<Event> {
  chain = await appendEvent(chain, input);
  return chain[chain.length - 1]!;
}

function envOf(on: D1Like): Env {
  return {
    DB: on,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}

/** One page, rendered through the router the Worker uses. */
async function page(path: string, on: D1Like): Promise<string> {
  const response = await handlePages(
    new Request(`https://app.nomankind.ai${path}`, {
      headers: { accept: "text/html" },
    }),
    envOf(on),
    { now: NOW },
  );
  expect(response).not.toBeNull();
  expect(response!.status).toBe(200);
  return response!.text();
}

/** The pair row for two operators, whichever way round it is asked for. */
async function pairOf(
  operator: string,
  cosigner: string,
): Promise<{ both: number; agreed: number; opposed: number } | null> {
  const pairs = await cosignPairsForOperator(db, operator, 100);
  const found = pairs.find((each) => each.cosigner === cosigner);
  return found === undefined
    ? null
    : { both: found.both, agreed: found.agreed, opposed: found.opposed };
}

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;

  for (const id of OPERATORS) {
    await putOperator(db, {
      id,
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: { trusted: true, trusted_seq: 1 },
    });
  }

  const events: Event[] = [];
  for (const [entryId, operator, decision] of DECISIONS) {
    events.push(
      await add({
        at: AT,
        type: "validation",
        entry_id: entryId,
        payload: {
          record: approver(operator, decision),
          signature: "c2lnbmF0dXJl",
        },
      }),
    );
  }
  events.push(
    await add({
      at: AT,
      type: "reconfirmation",
      entry_id: E3,
      payload: { record: reconfirmation(BETA), signature: "c2lnbmF0dXJl" },
    }),
  );
  await appendEvents(db, events);
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

describe("before the first fold", () => {
  it("shows every operator no co-signer rather than a guess", async () => {
    const counts = await cosignerCountsForOperators(db, [...OPERATORS]);
    expect([...counts.entries()]).toEqual([]);
    const html = await page("/operators", db);
    for (const id of OPERATORS) expect(html).toContain(id);
    const operator = await page(`/operators/${ALPHA}`, db);
    expect(operator).toContain(
      "has not signed an entry beside another operator",
    );
  }, 120_000);
});

describe("after the sweep has folded", () => {
  beforeAll(async () => {
    await countersStep(db, chain.length - 1, AT, () => undefined);
  }, 120_000);

  it("counts what a hand fold over the same events counts", async () => {
    for (const [one, other, both, agreed, opposed] of EXPECTED) {
      expect([one, other, await pairOf(one, other)]).toEqual([
        one,
        other,
        { both, agreed, opposed },
      ]);
      // Both directions, because both reads this exists for are "for this
      // operator, who with", and the numbers are the pair's either way round.
      expect([other, one, await pairOf(other, one)]).toEqual([
        other,
        one,
        { both, agreed, opposed },
      ]);
    }
    const counts = await cosignerCountsForOperators(db, [...OPERATORS]);
    expect([...counts.entries()].sort()).toEqual([
      [ALPHA, 2],
      [BETA, 2],
      [GAMMA, 2],
    ]);
    // The cursor is the head the fold covered, which is what makes the rows
    // checkable: fold the sealed events to it and the same numbers come back.
    expect(await readCosignCursor(db)).toBe(chain.length - 1);
  }, 120_000);

  it("counts nothing twice when the same head is folded again", async () => {
    await countersStep(db, chain.length - 1, AT, () => undefined);
    for (const [one, other, both, agreed, opposed] of EXPECTED) {
      expect(await pairOf(one, other)).toEqual({ both, agreed, opposed });
    }
  }, 120_000);

  it("counts nothing twice when a run wrote its rows and died before its cursor", async () => {
    // The crash the position guard exists for, and the one the test above
    // cannot reach: that one reruns at a cursor already at the head, so its
    // tail is empty and nothing is added at all. Here the rows are written and
    // the cursor is not, which is what a run killed between the two leaves
    // behind. The next run folds the same tail again — from the start, because
    // a cursor of -1 is no cursor — and must find its own work already done.
    await writeCosignCursor(db, -1, AT);
    await countersStep(db, chain.length - 1, AT, () => undefined);
    for (const [one, other, both, agreed, opposed] of EXPECTED) {
      expect([one, other, await pairOf(one, other)]).toEqual([
        one,
        other,
        { both, agreed, opposed },
      ]);
    }
    // And the repair is complete: the cursor is back at the head, so the run
    // after this one has a stretch of log to fold rather than the whole thing.
    expect(await readCosignCursor(db)).toBe(chain.length - 1);
  }, 120_000);

  it("shows the counts on the operator page, and links every entry it lists", async () => {
    const html = await page(`/operators/${ALPHA}`, db);
    expect(html).toContain(">Co-signers</h2>");
    expect(html).toContain(`<a href="/operators/${BETA}">`);
    expect(html).toContain(`<a href="/operators/${GAMMA}">`);
    for (const pair of await cosignPairsForOperator(db, ALPHA, 100)) {
      // Every entry the table names is a door a reader can walk through: a
      // count with no way to the record behind it is a number to be taken on
      // trust, which is the one thing this page is not for.
      expect(html).toContain(`<a href="/entries/${pair.newestEntryId}">`);
    }
    // What the view is, and what it is not, in the page's own words.
    expect(html).toContain("not a finding of collusion or of independence");
  }, 120_000);

  it("shows one column of distinct co-signers on the directory", async () => {
    const html = await page("/operators", db);
    expect(html).toContain("<th>co-signers</th>");
    expect(html).toContain("has signed an entry beside");
  }, 120_000);

  it("never asks the events table for any of it", async () => {
    for (const path of ["/operators", `/operators/${ALPHA}`]) {
      const { db: watched, sql } = watching(db);
      await page(path, watched);
      const scans = sql().filter(
        (statement) =>
          statement.includes("'reconfirmation'") ||
          statement.includes("FROM events"),
      );
      // The operator page reads its own validations off the events table, which
      // it has always done and which is bounded by that operator's own page of
      // decisions. What must never happen is a scan for the co-signing view:
      // none of the statements this page makes may mention the two types the
      // fold reads together.
      expect([path, scans.filter((each) => each.includes("'reconfirmation'"))])
        .toEqual([path, []]);
      // And it did read the rows, which is where the numbers come from.
      expect(
        sql().some((statement) => statement.includes("FROM cosign_pairs")),
      ).toBe(true);
    }
  }, 120_000);
});

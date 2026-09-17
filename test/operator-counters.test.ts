/**
 * The operators directory and the genesis page, off the sweep's counters.
 *
 * Whitepaper Section 3: every number a page shows is a view of the log. The QA
 * of 2026-09-12 found this particular view being taken once per reader — both
 * pages grouped over every `validation` event in the log on every load, which
 * is a cost that grows with the record and is paid by whoever happens to be
 * looking. So the counters step takes it once a run, into one counter pair per
 * operator, and the pages read exactly the operators they show.
 *
 * What is pinned here is both halves of that. The numbers on the page are the
 * ones the sweep counted — the same numbers `validationCountsByOperator` gives,
 * because that is what they are counted from — and the pages never ask the
 * events table for them again, which is asserted against the SQL the render
 * actually prepares rather than described in a comment.
 *
 * And the state before the first run, which is a real state on every fresh
 * deployment: an operator with no counter yet shows the zero it showed before
 * any of this existed, rather than a blank or a broken page.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { ApproverRecord, Event, EventInput } from "../src/events.js";
import { appendEvent } from "../src/events.js";
import {
  appendEvents,
  putOperator,
  validationCountsByOperator,
} from "../src/storage/repository.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";
import { countersStep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-11T00:00:00.000Z");
const AT = NOW.toISOString();

/** Who signed what, and when: two decisions for alpha, one for beta, none for gamma. */
const DECISIONS = [
  ["op-alpha", "approve", "nmk_e1", "2026-09-01T00:00:00.000Z"],
  ["op-beta", "approve", "nmk_e1", "2026-09-02T00:00:00.000Z"],
  ["op-alpha", "reject", "nmk_e2", "2026-09-03T00:00:00.000Z"],
] as const;

const OPERATORS = ["op-alpha", "op-beta", "op-gamma"] as const;

function approver(
  operator: string,
  decision: "approve" | "reject",
  signedAt: string,
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
    signed_at: signedAt,
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

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;

  for (const id of OPERATORS) {
    await putOperator(db, {
      id,
      kind: "domain",
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: { trusted: true, trusted_seq: 1 },
    });
  }

  const events: Event[] = [];
  for (const [operator, decision, entryId, signedAt] of DECISIONS) {
    events.push(
      await add({
        at: signedAt,
        type: "validation",
        entry_id: entryId,
        payload: {
          record: approver(operator, decision, signedAt),
          signature: "c2lnbmF0dXJl",
        },
      }),
    );
  }
  await appendEvents(db, events);
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

describe("before the first counters step", () => {
  it("shows every operator the zero it showed before any of this existed", async () => {
    const html = await page("/operators", db);
    for (const id of OPERATORS) expect(html).toContain(id);
    // Every row's validations cell reads zero and no row reads two, because no
    // run has counted yet. A missing counter has always been a zero on these
    // pages — that is how an operator absent from the old grouping read — so a
    // deployment between its deploy and its first sweep shows what it always
    // showed and never a blank.
    expect(html).not.toContain("<td>2</td>");

    const genesis = await page("/genesis", db);
    expect(genesis).not.toContain(`<td class="mono">2</td>`);
  }, 120_000);
});

describe("after the sweep has counted", () => {
  beforeAll(async () => {
    await countersStep(db, chain.length - 1, AT, () => undefined);
  }, 120_000);

  it("shows the counts the log itself gives, because that is what they are counted from", async () => {
    const counted = await validationCountsByOperator(db, 100);
    expect(counted).toEqual([
      { operator: "op-alpha", count: 2, lastSignedAt: "2026-09-03T00:00:00.000Z" },
      { operator: "op-beta", count: 1, lastSignedAt: "2026-09-02T00:00:00.000Z" },
    ]);

    const operators = await page("/operators", db);
    expect(operators).toContain("<td>2</td>");
    expect(operators).toContain("<td>1</td>");

    const genesis = await page("/genesis", db);
    expect(genesis).toContain(`<td class="mono">2</td>`);
    // The count, and the instant it was last signed at, rendered exactly as the
    // page rendered it when it read the grouping directly: the counter holds
    // the instant as epoch milliseconds because the table holds integers, and
    // the page turns it back into the instant the row carried.
    expect(genesis).toContain("2026-09-03 00:00:00Z");
    expect(genesis).toContain("2026-09-02 00:00:00Z");
  }, 120_000);

  it("never asks the events table for them again", async () => {
    for (const path of ["/operators", "/genesis"]) {
      const { db: watched, sql } = watching(db);
      await page(path, watched);
      const scans = sql().filter((statement) =>
        statement.includes(`type = 'validation'`),
      );
      // Not "fewer than before" and not "one instead of many": none. The page's
      // cost must not grow with the number of decisions the record holds.
      expect([path, scans]).toEqual([path, []]);
      // And it did read the counters, which is where the numbers come from now.
      expect(
        sql().some((statement) => statement.includes("FROM counters")),
      ).toBe(true);
    }
  }, 120_000);
});

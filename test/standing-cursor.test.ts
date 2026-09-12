/**
 * Standing behind a cursor.
 *
 * Whitepaper Section 9: standing "is derived from the sealed public events by a
 * published formula, so anyone can recompute anyone's standing from the log and
 * get the same number." A cursor is allowed to make that cheaper and is not
 * allowed to make it different, so everything here is one assertion said twice:
 * what the fold continued from a position equals what the fold over the whole
 * log says at that position, and the sweep that continues it reads the events
 * after the cursor rather than the log.
 *
 * The world is the offline verifier's own (test/helpers/verify-world.ts) with a
 * dispute, a reconfirmation and an attestation on it, plus a missed assignment
 * and a trust change appended here, so the fold's branches that carry state
 * across positions — a submission credit that is spent once, an upheld dispute's
 * signers burned once — are all exercised across a cursor rather than inside one
 * run of the loop.
 */

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { appendEvent } from "../src/index.js";
import { registeredOperatorsAt } from "../src/derive.js";
import type { Event } from "../src/events.js";
import { standingAfter, standingAt, type Standing } from "../src/standing.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import {
  appendEvents,
  putOperator,
  putSeal,
  storedStandings,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleStanding } from "../src/worker/standing.js";
import { standingStep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  CHALLENGER_OPERATOR,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

/** The instant every appended event and every step below runs at. */
const AT = "2026-09-12T00:00:00.000Z";

let world: VerifyWorld;
/** The whole log: the world's events, a missed assignment and a trust change. */
let log: Event[];

beforeAll(async () => {
  world = await buildVerifyWorld({
    withDispute: "outsider",
    withReconfirmation: true,
    withAttestation: true,
  });
  const ordered = [...world.bundle.events].sort((left, right) => left.seq - right.seq);
  // A missed assignment: the one burn nothing else in this world produces.
  const withMiss = await appendEvent(ordered, {
    at: AT,
    type: "assignment_missed",
    entry_id: world.entryId,
    payload: { agent: "agent_absent", operator: CHALLENGER_OPERATOR },
  });
  // A trust change, so the log the fold walks carries the events the trust step
  // appends as well as the ones that move a number.
  log = await appendEvent(withMiss, {
    at: AT,
    type: "operator_trusted",
    entry_id: null,
    payload: { operator: CHALLENGER_OPERATOR },
  });
}, 120_000);

/** Three heads: a third of the way in, two thirds, and the end. */
function heads(): [number, number, number] {
  const last = log[log.length - 1]!.seq;
  return [Math.floor(last / 3), Math.floor((last * 2) / 3), last];
}

describe("the incremental fold is the whole fold", () => {
  it("agrees at three heads, continuing from the one before", () => {
    const [one, two, three] = heads();

    const first = standingAfter(log, new Map(), -1, one);
    expect(first).toEqual(standingAt(log, one));

    const second = standingAfter(log, first, one, two);
    expect(second).toEqual(standingAt(log, two));

    const third = standingAfter(log, second, two, three);
    expect(third).toEqual(standingAt(log, three));
  });

  it("does not pay a submission credit twice across a cursor", () => {
    const [, , last] = heads();
    // Every position in turn, one event at a time: if any branch of the fold
    // double-counted across a cursor, some step of this walk would disagree.
    let carried = new Map<string, Standing>();
    for (let position = 0; position <= last; position += 1) {
      carried = standingAfter(log, carried, position - 1, position);
      expect(carried).toEqual(standingAt(log, position));
    }
  });
});

// ---------------------------------------------------------------------------
// The sweep's own step, over a real database
// ---------------------------------------------------------------------------

/** Every statement a step prepared, with what it was bound to. */
interface Counted {
  readonly db: D1Like;
  readonly statements: { sql: string; values: unknown[] }[];
}

/**
 * A D1Like that records what is asked of it and asks the real one.
 *
 * Statements and not rows, because the cost the cursor exists to remove is a
 * read of the whole log per run and the shape of that read is a statement bound
 * to a range starting at zero.
 */
function counting(db: D1Like): Counted {
  const statements: { sql: string; values: unknown[] }[] = [];
  // miniflare's own statement objects are the only thing its `batch` will take,
  // so every wrapper keeps the real one and `batch` hands those back.
  const real = new WeakMap<D1LikeStatement, D1LikeStatement>();
  const wrap = (sql: string, statement: D1LikeStatement): D1LikeStatement => {
    const wrapped: D1LikeStatement = {
      bind: (...values: unknown[]) => {
        statements.push({ sql, values });
        return wrap(sql, statement.bind(...values));
      },
      first: <Row,>() => statement.first<Row>(),
      all: <Row,>() => statement.all<Row>(),
      run: <Row,>() => statement.run<Row>(),
    };
    real.set(wrapped, statement);
    return wrapped;
  };
  return {
    statements,
    db: {
      prepare: (sql: string) => {
        statements.push({ sql, values: [] });
        return wrap(sql, db.prepare(sql));
      },
      batch: (batched: D1LikeStatement[]) =>
        db.batch(batched.map((one) => real.get(one) ?? one)),
      exec: (sql: string) => db.exec(sql),
    },
  };
}

const opened: TestDatabase[] = [];

afterEach(async () => {
  while (opened.length > 0) await opened.pop()?.dispose();
});

/** A migrated database holding the whole log, its operators and its seals. */
async function seeded(): Promise<TestDatabase> {
  const store = await openTestDatabase();
  opened.push(store);
  await appendEvents(store.db, log);
  const last = log[log.length - 1]!.seq;
  const registered = registeredOperatorsAt(log, last);
  for (const id of registered.operators) {
    await putOperator(store.db, {
      id,
      maintainer: registered.maintainers.has(id),
      provider: false,
      registeredSeq: 0,
      details: {},
    });
  }
  for (const seal of world.bundle.seals) await putSeal(store.db, seal);
  return store;
}

describe("the sweep's standing step", () => {
  it("stores the whole fold's answer, then continues from it", async () => {
    const store = await seeded();
    const [one, , three] = heads();

    const first = await standingStep(store.db, one, AT, () => {});
    expect(first?.position).toBe(one);
    const afterFirst = await storedStandings(store.db);
    expect(afterFirst.position).toBe(one);
    expect(afterFirst.standings).toEqual(standingAt(log, one));

    const measured = counting(store.db);
    const second = await standingStep(measured.db, three, AT, () => {});
    expect(second?.position).toBe(three);

    const afterSecond = await storedStandings(store.db);
    expect(afterSecond.position).toBe(three);
    expect(afterSecond.standings).toEqual(standingAt(log, three));
  }, 120_000);

  it("reads only the events after the cursor", async () => {
    const store = await seeded();
    const [one, , three] = heads();
    await standingStep(store.db, one, AT, () => {});

    const measured = counting(store.db);
    await standingStep(measured.db, three, AT, () => {});

    // Every ranged read of the log starts after the cursor. A run that folded
    // the log again would bind a range starting at zero, which is exactly the
    // 3,306 rows a run the QA measured read at 3,305 events.
    const ranged = measured.statements.filter(
      (statement) =>
        statement.sql.includes("FROM events") &&
        statement.sql.includes("seq >= ?") &&
        statement.values.length > 0,
    );
    expect(ranged.length).toBeGreaterThan(0);
    for (const statement of ranged) {
      expect(statement.values[0] as number).toBeGreaterThan(one);
    }

    // And the whole step is a handful of statements rather than a page walk of
    // the log: the tail, the registry, the entries the tail names, the rows.
    // Pinned at the measured cost with a little headroom, so a regression that
    // doubled the work fails here rather than on the platform's row budget.
    const prepared = measured.statements.filter(
      (statement) => statement.values.length === 0,
    );
    expect(prepared.length).toBeLessThanOrEqual(30);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// What the door serves
// ---------------------------------------------------------------------------

describe("GET /standing", () => {
  it("names every registered operator, folded or not", async () => {
    const store = await seeded();
    const [one] = heads();
    await standingStep(store.db, one, AT, () => {});

    // An operator registered after the fold, which is every operator for the
    // five minutes between its registration and the next sweep. It has a
    // standing of zero at the fold's position — which is a different thing to
    // say than nothing at all, and the only one of the two the reader can check.
    const newcomer = "op_after_the_fold";
    await putOperator(store.db, {
      id: newcomer,
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: {},
    });

    const response = await handleStanding(
      new Request("https://api.test/standing"),
      { DB: store.db, CAPTURES: store.captures, ENVIRONMENT: "local" } as Env,
      { now: new Date(AT) },
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    const body = (await response!.json()) as {
      position: number;
      operators: { operator: string; standing: number; position: number }[];
    };

    expect(body.position).toBe(one);
    const named = new Map(body.operators.map((row) => [row.operator, row]));
    // Everything the fold knew, plus the newcomer at zero, and the position on
    // every row is the position the sweep folded to.
    for (const operator of standingAt(log, one).keys()) {
      expect(named.has(operator)).toBe(true);
    }
    expect(named.get(newcomer)).toMatchObject({
      standing: 0,
      earned: 0,
      burned: 0,
      locked: 0,
      available: 0,
      position: one,
    });
    expect(body.operators.every((row) => row.position === one)).toBe(true);
  }, 120_000);
});

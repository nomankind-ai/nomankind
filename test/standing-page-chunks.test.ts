/**
 * The directory's standing read, asked for more ids than D1 will bind.
 *
 * `standingForOperators` bound one parameter per id in one statement, and D1
 * takes a hundred bound values: a caller with more operators on the page than
 * that got a refusal from the database rather than a map. Nothing in the Worker
 * asks for more than a page today, which is exactly why it would have been
 * found by the first caller who did.
 *
 * A real miniflare D1, because the bound is the database's and a hand-written
 * fake would hold whatever the fake felt like holding.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  putOperator,
  setOperatorStanding,
  standingForOperators,
} from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** More than D1 binds in one statement, and not a multiple of the chunk. */
const IDS = 120;

/** The position every standing here was computed at. */
const SEQ = 41;

let store: TestDatabase;

function id(index: number): string {
  return `op-${String(index).padStart(3, "0")}.example`;
}

beforeAll(async () => {
  store = await openTestDatabase();
  for (let index = 0; index < IDS; index += 1) {
    await putOperator(store.db, {
      id: id(index),
      kind: "domain",
      maintainer: false,
      provider: false,
      registeredSeq: index + 1,
      details: { registered_by: `1F916:agent-${index}`, trusted: false },
    });
    // Every operator but the last: one id with no cached standing keeps the
    // "absent is not computed yet" promise honest across the chunk boundary.
    if (index < IDS - 1) {
      await setOperatorStanding(store.db, id(index), index + 1, SEQ);
    }
  }
}, 240_000);

afterAll(async () => {
  await store.dispose();
});

describe("a page of ids past D1's bound", () => {
  it("answers every one of them, in chunks", async () => {
    const page = Array.from({ length: IDS }, (_, index) => id(index));
    const standings = await standingForOperators(store.db, page);

    // One short: the operator whose standing was never computed.
    expect(standings.size).toBe(IDS - 1);
    expect(standings.get(id(0))).toEqual({ standing: 1, seq: SEQ });
    // Either side of the fiftieth id, which is where one statement ends and the
    // next begins.
    expect(standings.get(id(49))).toEqual({ standing: 50, seq: SEQ });
    expect(standings.get(id(50))).toEqual({ standing: 51, seq: SEQ });
    expect(standings.get(id(IDS - 2))).toEqual({ standing: IDS - 1, seq: SEQ });
    // Absent rather than zero, on the last chunk as on the first.
    expect(standings.has(id(IDS - 1))).toBe(false);
  }, 240_000);

  it("still asks nothing at all for an empty page", async () => {
    expect(await standingForOperators(store.db, [])).toEqual(new Map());
  }, 240_000);
});

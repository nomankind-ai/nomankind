/**
 * The mirror carries what an operator did, not only what it is worth (D-140
 * item 7).
 *
 * The gap this closes is small and the consequence was not. `standing.json` is
 * the body of `GET /standing` at the sealed head, and the import replayed it
 * into the cached `standing` column alone: a fresh fork's `/operators` agreed
 * with the source about every number and showed nulls where the source showed
 * the validations, the reproductions, the submissions and the marks the number
 * was folded from. The numbers matched and the work behind them was missing,
 * which is exactly the thing this record says a score should never be.
 *
 * Three claims are held here. The export carries each operator's counts in the
 * row beside its number, from the fold the leaderboard's own counts are a cache
 * of. The replay is lossless: what `putStandings` writes from that fold is what
 * `storedStandings` reads back, counts included, at the imported head. And a
 * clone written before the counts existed still reads — `standingRowCounts`
 * answers null rather than refusing, which is what keeps an older copy
 * somebody's exit.
 *
 * The events are built by hand rather than through the doors. What is under test
 * is a fold and a round trip, both of which read an event's payload and neither
 * of which reads a signature, so a whole signed world would be several hundred
 * events to check a JSON shape. The end-to-end proof that the two sides agree
 * over a real log is test/import-mirror-end-to-end.test.ts, which now compares
 * the counts along with everything else.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Event } from "../src/events.js";
import {
  mirrorStanding,
  standingRowCounts,
  type MirrorStandingRow,
} from "../src/mirror.js";
import {
  STANDING_ASSIGNMENT_MISSED,
  STANDING_ATTESTATION_SCORED,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_VALIDATION_VOLUNTEERED,
} from "../src/policy.js";
import { standingAt, type StandingCounts } from "../src/standing.js";
import {
  putStandings,
  storedStandingOf,
  storedStandings,
} from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const VOLUNTEER = "volunteer.example";
const SCORER = "scorer.example";

/** One event of the fold's own shape. Nothing here is signed or chained. */
function event(
  seq: number,
  type: string,
  payload: unknown,
  entryId: string | null = null,
): Event {
  return {
    seq,
    at: "2026-09-18T00:00:00.000Z",
    type,
    entry_id: entryId,
    payload,
    prev_hash: seq === 0 ? null : `sha256:${"0".repeat(64)}`,
    hash: `sha256:${"0".repeat(64)}`,
  } as unknown as Event;
}

/**
 * A log with two operators who did different things.
 *
 * The validations carry no `entry_id`, so the fold pays the validator and never
 * looks for a submission to credit: the submitter's side of the formula is
 * derived from a whole entry and is not what this file is about.
 */
const EVENTS: readonly Event[] = [
  event(0, "operator_registered", { operator: VOLUNTEER, maintainer: false }),
  event(1, "operator_registered", { operator: SCORER, maintainer: false }),
  event(2, "validation", {
    record: { operator: VOLUNTEER, assigned_random: false },
  }),
  event(3, "validation", {
    record: { operator: VOLUNTEER, assigned_random: true },
  }),
  event(4, "attestation_scored", { record: { operator: SCORER } }),
  event(5, "assignment_missed", { operator: SCORER, agent: "1F916:scorer" }),
];

const HEAD = EVENTS.length - 1;

describe("the export carries the counts beside the number", () => {
  const exported = mirrorStanding(EVENTS, HEAD);

  it("is the same fold the leaderboard's counts are a cache of", () => {
    const folded = standingAt(EVENTS, HEAD);
    expect(exported.position).toBe(HEAD);
    expect(exported.operators.map((each) => each.operator)).toEqual([
      SCORER,
      VOLUNTEER,
    ]);
    for (const row of exported.operators) {
      expect([row.operator, row]).toEqual([row.operator, folded.get(row.operator)]);
    }
  });

  it("names every count on every row, through a JSON round trip", () => {
    const written = JSON.parse(JSON.stringify(exported)) as {
      operators: unknown[];
    };
    expect(written.operators).toHaveLength(2);
    for (const row of written.operators) {
      expect(standingRowCounts(row)).not.toBeNull();
    }

    const volunteer = written.operators.find(
      (row) => (row as MirrorStandingRow).operator === VOLUNTEER,
    );
    expect(standingRowCounts(volunteer)).toEqual({
      validations_volunteered: 1,
      validations_assigned: 1,
      validations_reproduced: 0,
      attestations_scored: 0,
      submissions_verified: 0,
      disputes_upheld: 0,
      revalidations_changed: 0,
      overturned: 0,
      missed: 0,
      forfeits: 0,
    } satisfies StandingCounts);

    // And the number beside them is the published formula over the same two
    // moves, so the row is checkable by a reader who adds it up.
    expect((volunteer as MirrorStandingRow).standing).toBe(
      STANDING_VALIDATION_VOLUNTEERED + STANDING_VALIDATION_ASSIGNED,
    );

    const scorer = written.operators.find(
      (row) => (row as MirrorStandingRow).operator === SCORER,
    );
    expect(standingRowCounts(scorer)).toEqual({
      validations_volunteered: 0,
      validations_assigned: 0,
      validations_reproduced: 0,
      attestations_scored: 1,
      submissions_verified: 0,
      disputes_upheld: 0,
      revalidations_changed: 0,
      overturned: 0,
      missed: 1,
      forfeits: 0,
    } satisfies StandingCounts);
    expect((scorer as MirrorStandingRow).standing).toBe(
      STANDING_ATTESTATION_SCORED - STANDING_ASSIGNMENT_MISSED,
    );
  });
});

describe("a standing file written before the counts existed", () => {
  const exported = mirrorStanding(EVENTS, HEAD);

  /** The same document as a v1, v2 or v3 clone pushed before D-140 wrote it. */
  function withoutCounts(): { operators: Record<string, unknown>[] } {
    const written = JSON.parse(JSON.stringify(exported)) as {
      operators: Record<string, unknown>[];
    };
    for (const row of written.operators) delete row["counts"];
    return written;
  }

  it("reads as null counts rather than as a malformed row", () => {
    const written = withoutCounts();
    for (const row of written.operators) {
      expect(standingRowCounts(row)).toBeNull();
      // Everything else the older layout does carry is still there to check.
      expect(typeof row["standing"]).toBe("number");
      expect(row["position"]).toBe(HEAD);
    }
  });

  it("reads as null for a row that is not a row at all", () => {
    for (const row of [null, undefined, 3, "counts", [], {}]) {
      expect([row, standingRowCounts(row)]).toEqual([row, null]);
    }
  });

  it("reads as null for a half-written counts object", () => {
    const one = JSON.parse(
      JSON.stringify(exported.operators[0]),
    ) as Record<string, unknown>;
    const counts = one["counts"] as Record<string, unknown>;

    // A key missing.
    const missing = { ...one, counts: { ...counts } };
    delete (missing["counts"] as Record<string, unknown>)["forfeits"];
    expect(standingRowCounts(missing)).toBeNull();

    // A key that is not a whole number.
    expect(
      standingRowCounts({ ...one, counts: { ...counts, missed: "1" } }),
    ).toBeNull();
    expect(
      standingRowCounts({ ...one, counts: { ...counts, missed: 1.5 } }),
    ).toBeNull();

    // A key nothing puts there.
    expect(
      standingRowCounts({ ...one, counts: { ...counts, bonus: 1 } }),
    ).toBeNull();
  });
});

describe("the replay puts the counts back in the fork's own table", () => {
  let fork: TestDatabase;

  beforeAll(async () => {
    fork = await openTestDatabase();
    // Exactly what src/cli/import-mirror.ts writes: the whole accumulator the
    // export's own fold produced, at the imported head.
    await putStandings(fork.db, mirrorStanding(EVENTS, HEAD).operators);
  }, 600_000);

  afterAll(async () => {
    await fork?.dispose();
  });

  it("reads back every row the export carried, counts and all", async () => {
    const stored = await storedStandings(fork.db);
    expect(stored.position).toBe(HEAD);
    const folded = standingAt(EVENTS, HEAD);
    expect([...stored.standings.keys()].sort()).toEqual(
      [...folded.keys()].sort(),
    );
    for (const [operator, expected] of folded) {
      expect([operator, stored.standings.get(operator)]).toEqual([
        operator,
        expected,
      ]);
    }
  }, 600_000);

  it("answers one operator's counts, which is what the directory reads", async () => {
    const one = await storedStandingOf(fork.db, VOLUNTEER);
    expect(one).not.toBeNull();
    expect(one!.counts).toEqual(standingAt(EVENTS, HEAD).get(VOLUNTEER)!.counts);
    // Null is still "never folded" and not a row of zeroes: an operator this
    // log never mentioned has no row at all.
    expect(await storedStandingOf(fork.db, "stranger.example")).toBeNull();
  }, 600_000);
});

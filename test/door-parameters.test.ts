/**
 * One query rule, on every door (the QA of 2026-09-12).
 *
 * The QA sent the same four malformed queries at each read door and got four
 * different answers. `GET /read/{id}` dropped every parameter while its query
 * twin refused an unknown one, so a reader who put `min_tier=observed` on the
 * path form was handed an entry below their demand that looked like it had met
 * it. The read door took the first of a repeated parameter where the delta
 * stream refuses two values outright. `GET /events` accepted both, where
 * `/sync` and the entries listing refuse both. `/anchors?after=2026-13-45`
 * passed a shape test — four digits, two digits, two digits — and answered an
 * empty page about a day that does not exist. And the four reads that take no
 * query at all dropped whatever they were sent.
 *
 * So: one reader (src/params.ts), and each door's own words for it. The
 * listings say `bad_query`; the frozen reader and the entries listing say
 * `unknown_parameter` and `repeated_parameter`, which is what they already
 * said.
 *
 * A real migrated D1 with nothing in it: a refusal about the shape of a
 * question is answered before anything is read, so an empty log is the right
 * fixture and the answers below are about the door and never about a record.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { isCalendarDate } from "../src/params.js";
import { LIST_PAGE_LIMIT } from "../src/policy.js";
import { parseReadQuery } from "../src/read.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { parseEntriesQuery } from "../src/ui/query.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-12T00:00:00.000Z");
const ORIGIN = "https://app.nomankind.ai";

/** A well-formed entry id the empty log does not hold. */
const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";

let store: TestDatabase;
let env: Env;

beforeAll(async () => {
  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

function get(path: string): Promise<Response> {
  return handleRequest(
    new Request(`${ORIGIN}${path}`, {
      headers: { accept: "application/json" },
    }),
    env,
    { now: NOW },
  );
}

/** The door's answer, as the status and the reason it named. */
async function refusal(path: string): Promise<[number, unknown]> {
  const response = await get(path);
  const body = (await response.json()) as { error?: unknown };
  return [response.status, body.error ?? null];
}

describe("the listings refuse a query they cannot read, in one word", () => {
  const OVER = LIST_PAGE_LIMIT + 1;

  const cases: readonly [string, string][] = [
    // A parameter the door does not take.
    ["/events?limt=5", "unknown parameter"],
    ["/seals?cursor=3", "unknown parameter"],
    ["/anchors?page=2", "unknown parameter"],
    // The same parameter twice: two questions, and picking one is guessing.
    ["/events?after=1&after=900", "repeated parameter"],
    ["/seals?limit=5&limit=50", "repeated parameter"],
    ["/anchors?after=2026-09-01&after=2026-09-02", "repeated parameter"],
    // A limit outside the published page size, refused and never clamped.
    [`/events?limit=${OVER}`, "limit over the page size"],
    [`/seals?limit=${OVER}`, "limit over the page size"],
    [`/anchors?limit=${OVER}`, "limit over the page size"],
    ["/events?limit=0", "limit below one"],
    // A position that is not one.
    ["/events?after=1e9", "after in exponent form"],
    ["/seals?after=-1", "negative after"],
    // A day the calendar does not have.
    ["/anchors?after=2026-13-45", "month 13, day 45"],
    ["/anchors?after=2026-02-30", "the 30th of February"],
    // The registry listing, which read its own limit and ignored the rest of
    // the query until the QA of 2026-09-13 put it on the shared reader.
    ["/operators?limt=5", "unknown parameter"],
    ["/operators?limit=5&limit=50", "repeated parameter"],
    [`/operators?limit=${OVER}`, "limit over the page size"],
    ["/operators?limit=0", "limit below one"],
    ["/operators?limit=1e9", "limit in exponent form"],
  ];

  for (const [path, why] of cases) {
    it(`refuses ${path} — ${why}`, async () => {
      expect([path, ...(await refusal(path))]).toEqual([path, 400, "bad_query"]);
    }, 60_000);
  }

  it("still serves the two parameters each listing does take", async () => {
    for (const path of [
      "/events?after=0&limit=5",
      "/seals?after=0&limit=5",
      `/anchors?after=2024-02-29&limit=${LIST_PAGE_LIMIT}`,
      `/operators?limit=${LIST_PAGE_LIMIT}`,
      "/operators",
    ]) {
      const response = await get(path);
      expect([path, response.status]).toEqual([path, 200]);
    }
  }, 60_000);

  it("refuses a day the calendar does not have in the path too", async () => {
    expect(await refusal("/anchors/2026-13-45")).toEqual([400, "bad_id"]);
    expect(await refusal("/anchors/2026-02-30")).toEqual([400, "bad_id"]);
    // A leap day is a day, and the empty log simply does not hold it.
    expect(await refusal("/anchors/2024-02-29")).toEqual([404, "not_found"]);
  }, 60_000);
});

describe("2026 is not a leap year and 2024 is", () => {
  it("knows the Gregorian rule", () => {
    expect(isCalendarDate("2024-02-29")).toBe(true);
    expect(isCalendarDate("2026-02-29")).toBe(false);
    expect(isCalendarDate("2000-02-29")).toBe(true);
    expect(isCalendarDate("1900-02-29")).toBe(false);
    expect(isCalendarDate("2026-04-31")).toBe(false);
    expect(isCalendarDate("2026-00-10")).toBe(false);
    expect(isCalendarDate("2026-09-00")).toBe(false);
    expect(isCalendarDate("2026-9-1")).toBe(false);
  });
});

describe("the doors that name their subject in the path take no query", () => {
  const NONE: readonly string[] = [
    "/standing",
    "/ledger",
    "/operators/example.com/standing",
    "/operators/example.com/ledger",
  ];

  for (const path of NONE) {
    it(`refuses a parameter on ${path}`, async () => {
      expect(await refusal(`${path}?limit=5`)).toEqual([400, "bad_query"]);
    }, 60_000);
  }

  it("refuses one on /read/{id} in the frozen reader's own words", async () => {
    expect(await refusal(`/read/${ENTRY_ID}?min_tier=observed`)).toEqual([
      400,
      "unknown_parameter",
    ]);
    expect(await refusal(`/read/${ENTRY_ID}?entry_id=${ENTRY_ID}`)).toEqual([
      400,
      "unknown_parameter",
    ]);
  }, 60_000);
});

describe("the frozen reader refuses a parameter given twice", () => {
  it("names it rather than taking the first value", () => {
    const twice = new URLSearchParams([
      ["subject", "a"],
      ["category", "pricing"],
      ["min_tier", "stated"],
      ["min_tier", "observed"],
    ]);
    expect(parseReadQuery(twice)).toEqual({
      ok: false,
      reason: "repeated_parameter",
    });
  });

  it("still names an unknown one first", () => {
    const both = new URLSearchParams([
      ["catagory", "pricing"],
      ["subject", "a"],
      ["subject", "b"],
    ]);
    expect(parseReadQuery(both)).toEqual({
      ok: false,
      reason: "unknown_parameter",
    });
  });
});

describe("the entries listing reads its cursor by the same rule", () => {
  it("refuses a position that is not one and takes one that is", () => {
    // `0099` is the one this narrowed (the QA of 2026-09-13): the old test was
    // `/^\d+$/` and read it as 99, so one page had two URLs. A position is
    // spelt one way here, as it is at every other door, and the README says so.
    for (const bad of ["1e9", "", "-1", "0099", "007", " 5"]) {
      expect([
        bad,
        parseEntriesQuery(new URLSearchParams({ before: bad })),
      ]).toEqual([bad, { ok: false, reason: "bad_before" }]);
    }
    const ok = parseEntriesQuery(new URLSearchParams({ before: "99999" }));
    expect(ok.ok && ok.before).toBe(99999);
    // Zero is a real sealed position, so the bound is non-negative.
    const zero = parseEntriesQuery(new URLSearchParams({ before: "0" }));
    expect(zero.ok && zero.before).toBe(0);
    // And a listing that names no cursor still starts at the head.
    const none = parseEntriesQuery(new URLSearchParams());
    expect(none.ok && none.before).toBeNull();
  });
});

describe("an id is exactly the length it is documented at", () => {
  const SHORT = `nmk_${"a".repeat(31)}`;
  const LONG = `nmk_${"a".repeat(33)}`;

  it("refuses a 31- and a 33-hex entry id at both entry doors", async () => {
    for (const id of [SHORT, LONG]) {
      expect([id, ...(await refusal(`/entries/${id}`))]).toEqual([
        id,
        400,
        "bad_id",
      ]);
      expect([id, ...(await refusal(`/read/${id}`))]).toEqual([
        id,
        400,
        "bad_id",
      ]);
      expect([id, ...(await refusal(`/read?entry_id=${id}`))]).toEqual([
        id,
        400,
        "bad_entry_id",
      ]);
    }
  }, 60_000);
});

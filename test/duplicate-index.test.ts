/**
 * The duplicate rule, as a column and an index (M25, Section 6 "Submit",
 * decision D-085, migration 0019).
 *
 * "Two entries are the same claim when they name the same domain, the same
 * subject and the same category and assert the same value" as of the same
 * `effective_at` -- the fifth field the QA of 2026-09-12 added, and the reason
 * migration 0020 empties the column so every key is computed again. That rule lived
 * only in src/duplicate.ts, so the door had to bring it the rows: the QA of
 * 2026-09-12 found it reading a subject's whole live history on every
 * submission — 669 rows at 667 live entries, about 130 MB of JSON at a hundred
 * thousand — to answer a question an index can answer in one seek.
 *
 * What is pinned here is that the two copies of the rule cannot drift. The key
 * the index holds is `duplicateKeyHash`'s, computed over `duplicateKey`'s own
 * normalization, so a claim filed with different whitespace or in a different
 * Unicode normal form lands on the same row; the lookup is one statement
 * whatever the subject's history; a row written by the store carries its key;
 * and a row written before 0019 is given exactly the key it would have had.
 *
 * miniflare's D1 with the real migrations applied, because the index, the
 * `IN` and the query planner are what is under test.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { appendEvent, type Event } from "../src/events.js";
import type { Core } from "../src/core.js";
import type { Sidecar } from "../src/derive.js";
import {
  LIVE_STATUSES,
  duplicateKey,
  duplicateKeyHash,
} from "../src/duplicate.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import {
  appendEvents,
  backfillDuplicateKeys,
  liveDuplicateOf,
  putEntry,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

let store: TestDatabase;
let db: D1Like;

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

const SUBJECT = "openai/gpt-5";
const CATEGORY = "pricing";
const AT = "2026-09-11T12:00:00.000Z";
const EFFECTIVE_AT = "2026-09-01";

/** A core carrying the five fields the duplicate key is made of. */
function coreOf(id: string, after: string, effectiveAt = EFFECTIVE_AT): Core {
  return {
    id,
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    after,
    effective_at: effectiveAt,
  } as unknown as Core;
}

/** The entry row's shape, as the store writes one. */
function entryOf(
  id: string,
  after: string,
  status: string,
  effectiveAt = EFFECTIVE_AT,
): Entry {
  return {
    id,
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    after,
    effective_at: effectiveAt,
    status,
    submitted_at: AT,
    author: "nmk_agent_test",
    stale: false,
    expires_at: null,
    supersedes: null,
  } as unknown as Entry;
}

const SIDECAR = {} as unknown as Sidecar;

/** Insert one entries row straight, with the key a caller names. */
function rawEntry(
  id: string,
  after: string,
  status: string,
  submittedSeq: number,
  duplicateKeyValue: string | null,
  effectiveAt = EFFECTIVE_AT,
): D1LikeStatement {
  return rawEntryOn(
    db,
    id,
    after,
    status,
    submittedSeq,
    duplicateKeyValue,
    effectiveAt,
  );
}

/** The same insert, against a database the caller names. */
function rawEntryOn(
  target: D1Like,
  id: string,
  after: string,
  status: string,
  submittedSeq: number,
  duplicateKeyValue: string | null,
  effectiveAt = EFFECTIVE_AT,
): D1LikeStatement {
  return target
    .prepare(
      `INSERT INTO entries (
         id, subject, category, domain, status, submitted_at, submitted_seq,
         author, stale, expires_at, supersedes,
         entry_json, sidecar_json, derived_through_seq, duplicate_key
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, '{}', ?, ?)`,
    )
    .bind(
      id,
      SUBJECT,
      CATEGORY,
      DEFAULT_DOMAIN,
      status,
      AT,
      submittedSeq,
      "nmk_agent_test",
      JSON.stringify(entryOf(id, after, status, effectiveAt)),
      submittedSeq,
      duplicateKeyValue,
    );
}

// ---------------------------------------------------------------------------
// The key the store writes
// ---------------------------------------------------------------------------

describe("the duplicate_key column", () => {
  it("is written by the store's own entry write, over the entry's own core", async () => {
    // The one write path every entry goes through: a submission event, so the
    // row knows its position, and then the derived entry.
    const id = `nmk_${"a".repeat(32)}`;
    const events: Event[] = await appendEvent([], {
      at: AT,
      type: "entry_submitted",
      entry_id: id,
      payload: { core: coreOf(id, "30 per million"), signature: "sig" },
    } as never);
    await appendEvents(db, events);
    await putEntry(db, entryOf(id, "30 per million", "draft"), SIDECAR, 0);

    const row = await db
      .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
      .bind(id)
      .first<{ duplicate_key: string | null }>();
    expect(row!.duplicate_key).toBe(
      await duplicateKeyHash(coreOf(id, "30 per million")),
    );

    // And the index answers with it.
    expect(
      await liveDuplicateOf(db, await duplicateKeyHash(coreOf("other", "30 per million"))),
    ).toBe(id);
  });
});

// ---------------------------------------------------------------------------
// The same key for the same claim
// ---------------------------------------------------------------------------

describe("liveDuplicateOf", () => {
  const HELD = `nmk_${"b".repeat(32)}`;
  const VALUE = "USD 30.00 per million tokens";

  beforeAll(async () => {
    await db.batch([
      // The live entry holding the claim.
      rawEntry(HELD, VALUE, "draft", 100, await duplicateKeyHash(coreOf(HELD, VALUE))),
    ]);
  });

  it("finds the row through a whitespace variant of the same value", async () => {
    // Step 4 of norm-v1.2 folds runs of line-internal whitespace and trims the
    // ends, so this is the same claim and must be the same key. The rule keeps
    // line breaks, which is why this variant has none: a claim written over two
    // lines is a different string and the rule says so.
    const variant = "  USD 30.00\tper   million tokens  ";
    expect(duplicateKey(coreOf("x", variant)).value).toBe(
      duplicateKey(coreOf("y", VALUE)).value,
    );
    expect(await liveDuplicateOf(db, await duplicateKeyHash(coreOf("x", variant)))).toBe(
      HELD,
    );
  });

  it("finds the row through an NFD variant of the same value", async () => {
    const nfc = "Café pricing";
    const nfd = nfc.normalize("NFD");
    expect(nfd).not.toBe(nfc);

    const id = `nmk_${"c".repeat(32)}`;
    await db.batch([
      rawEntry(id, nfc, "verified", 101, await duplicateKeyHash(coreOf(id, nfc))),
    ]);
    expect(await liveDuplicateOf(db, await duplicateKeyHash(coreOf("z", nfd)))).toBe(
      id,
    );
  });

  it("does not find the row through the same value at a different date", async () => {
    // The QA of 2026-09-12: `effective_at` is the fifth field of the key, so
    // the same value as of another date is another claim and the index says so.
    // The door then lets it through to the validators, which is where the
    // registry document and whitepaper Section 6 put that judgment.
    expect(
      await liveDuplicateOf(db, await duplicateKeyHash(coreOf("x", VALUE, "2026-12-01"))),
    ).toBeNull();
    // And the date's own row is found by its own key, so the two coexist.
    const later = `nmk_${"9".repeat(32)}`;
    await db.batch([
      rawEntry(later, VALUE, "draft", 103, await duplicateKeyHash(coreOf(later, VALUE, "2026-12-01")), "2026-12-01"),
    ]);
    expect(
      await liveDuplicateOf(db, await duplicateKeyHash(coreOf("x", VALUE, "2026-12-01"))),
    ).toBe(later);
    // The original date is untouched: narrowing the key did not weaken it.
    expect(await liveDuplicateOf(db, await duplicateKeyHash(coreOf("x", VALUE)))).toBe(
      HELD,
    );
  });

  it("answers null for a claim nothing live holds", async () => {
    expect(
      await liveDuplicateOf(db, await duplicateKeyHash(coreOf("q", "never filed"))),
    ).toBeNull();
  });

  it("ignores an entry that no longer stands, and names the newest that does", async () => {
    const value = "20 per million";
    const key = await duplicateKeyHash(coreOf("k", value));
    const rejected = `nmk_${"d".repeat(32)}`;
    const older = `nmk_${"e".repeat(32)}`;
    const newer = `nmk_${"f".repeat(32)}`;
    await db.batch([
      rawEntry(rejected, value, "rejected", 200, key),
      rawEntry(older, value, "draft", 201, key),
      rawEntry(newer, value, "verified", 202, key),
    ]);
    // `rejected`, `superseded` and `overturned` release a claim; the two live
    // ones hold it, and the newest submission is the one a submitter is told
    // to look at.
    expect(LIVE_STATUSES).not.toContain("rejected");
    expect(await liveDuplicateOf(db, key)).toBe(newer);
  });
});

// ---------------------------------------------------------------------------
// One statement, whatever the history
// ---------------------------------------------------------------------------

describe("a subject with two thousand live entries", () => {
  const ROWS = 2_000;
  const BUSY = "busy/subject";

  /** A D1Like that counts the statements the code under test asks for. */
  function counting(inner: D1Like): { db: D1Like; statements: () => number } {
    let count = 0;
    const wrapped: D1Like = {
      prepare(sql: string) {
        count += 1;
        return inner.prepare(sql);
      },
      batch(statements) {
        count += 1;
        return inner.batch(statements);
      },
      exec(sql: string) {
        count += 1;
        return inner.exec(sql);
      },
    };
    return { db: wrapped, statements: () => count };
  }

  beforeAll(async () => {
    // Two thousand live entries on one subject and category, each its own
    // claim: exactly the history the old paged scan read whole.
    const PAGE = 250;
    for (let from = 0; from < ROWS; from += PAGE) {
      const statements: D1LikeStatement[] = [];
      for (let index = from; index < from + PAGE; index += 1) {
        const id = `nmk_${String(index).padStart(32, "0")}`;
        const value = `busy value ${index}`;
        const core = {
          id,
          subject: BUSY,
          category: CATEGORY,
          domain: DEFAULT_DOMAIN,
          after: value,
        } as unknown as Core;
        statements.push(
          db
            .prepare(
              `INSERT INTO entries (
                 id, subject, category, domain, status, submitted_at,
                 submitted_seq, author, stale, expires_at, supersedes,
                 entry_json, sidecar_json, derived_through_seq, duplicate_key
               ) VALUES (?, ?, ?, ?, 'draft', ?, ?, 'nmk_agent_test', 0, NULL,
                         NULL, '{}', '{}', ?, ?)`,
            )
            .bind(
              id,
              BUSY,
              CATEGORY,
              DEFAULT_DOMAIN,
              AT,
              1_000 + index,
              1_000 + index,
              await duplicateKeyHash(core),
            ),
        );
      }
      await db.batch(statements);
    }
  }, 600_000);

  it("answers the duplicate lookup in one statement", async () => {
    const counted = counting(db);
    const wanted = {
      id: "asking",
      subject: BUSY,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
      after: "busy value 1999",
    } as unknown as Core;

    const found = await liveDuplicateOf(counted.db, await duplicateKeyHash(wanted));
    expect(found).toBe(`nmk_${String(1_999).padStart(32, "0")}`);
    // One seek on `entries_duplicate_key`, whatever the subject's history: not
    // a page, not a scan, and no entry_json read at all.
    expect(counted.statements()).toBe(1);
  });

  it("answers a claim nobody holds in one statement too", async () => {
    const counted = counting(db);
    const unheld = {
      id: "asking",
      subject: BUSY,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
      after: "a value nobody filed",
    } as unknown as Core;
    expect(await liveDuplicateOf(counted.db, await duplicateKeyHash(unheld))).toBeNull();
    expect(counted.statements()).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The backfill
// ---------------------------------------------------------------------------

describe("backfillDuplicateKeys", () => {
  const PRE = `nmk_${"1".repeat(32)}`;
  const PRE_VALUE = "  pre-0019   value ";

  beforeAll(async () => {
    // A row as a Worker before 0019 wrote one: the entry_json is there and the
    // column is not, because the migration cannot run the norm rule in SQL.
    await db.batch([rawEntry(PRE, PRE_VALUE, "draft", 300, null)]);
  });

  it("gives a pre-0019 row exactly the key it would have been written with", async () => {
    expect(await liveDuplicateOf(db, await duplicateKeyHash(coreOf("q", PRE_VALUE)))).toBeNull();

    const filled = await backfillDuplicateKeys(db, 100);
    expect(filled).toBeGreaterThan(0);

    const row = await db
      .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
      .bind(PRE)
      .first<{ duplicate_key: string | null }>();
    expect(row!.duplicate_key).toBe(await duplicateKeyHash(coreOf(PRE, PRE_VALUE)));

    // And the same claim, filed with different whitespace, now finds it.
    expect(
      await liveDuplicateOf(db, await duplicateKeyHash(coreOf("q", "pre-0019 value"))),
    ).toBe(PRE);
  });

  it("leaves a row that already carries a key alone, and stops when there is nothing left", async () => {
    const before = await db
      .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
      .bind(PRE)
      .first<{ duplicate_key: string | null }>();
    expect(await backfillDuplicateKeys(db, 100)).toBe(0);
    const after = await db
      .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
      .bind(PRE)
      .first<{ duplicate_key: string | null }>();
    expect(after!.duplicate_key).toBe(before!.duplicate_key);
    expect(
      await db
        .prepare(`SELECT count(*) AS n FROM entries WHERE duplicate_key IS NULL`)
        .first<{ n: number }>(),
    ).toEqual({ n: 0 });
  });
});


// ---------------------------------------------------------------------------
// The sweep step that calls it
// ---------------------------------------------------------------------------

describe("the sweep's duplicates step", () => {
  it("fills a pre-0019 row, and the door's own lookup then finds it", async () => {
    // A database of its own: this runs a whole sweep, and the rest of this file
    // is about one table.
    const world = await openTestDatabase();
    try {
      const env: Env = {
        DB: world.db,
        CAPTURES: world.captures,
        ENVIRONMENT: "local",
        MAINTAINER_AGENT_ID: "1F916:maintainer",
      };
      const id = `nmk_${"2".repeat(32)}`;
      const value = "  swept   value ";
      const key = await duplicateKeyHash(coreOf(id, value));

      // The row as a Worker before 0019 left it: the submission event in the
      // log, the entry row beside it, and no duplicate key, because the column
      // did not exist when it was written.
      const events: Event[] = await appendEvent([], {
        at: AT,
        type: "entry_submitted",
        entry_id: id,
        payload: { core: coreOf(id, value), signature: "sig" },
      } as never);
      await appendEvents(world.db, events);
      await world.db.batch([
        rawEntryOn(world.db, id, value, "draft", events[0]!.seq, null),
      ]);

      // The state the fix is about: the claim is live and the index cannot see
      // it, so the door would take a second copy of it.
      expect(await liveDuplicateOf(world.db, key)).toBeNull();

      const report = await runSweep(env, {
        now: new Date("2026-09-11T13:00:00.000Z"),
        beacon: new FixtureBeacon("duplicates"),
      });
      expect(report.duplicates).toEqual({ filled: 1 });

      // Exactly the key the store would have written, so a backfilled row and a
      // row written today are indistinguishable.
      const row = await world.db
        .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
        .bind(id)
        .first<{ duplicate_key: string | null }>();
      expect(row!.duplicate_key).toBe(key);

      // And the door's question, asked the way the door asks it: the same claim
      // filed with different whitespace now finds the entry already holding it.
      expect(
        await liveDuplicateOf(
          world.db,
          await duplicateKeyHash(coreOf("other", "swept value")),
        ),
      ).toBe(id);

      // Idle once there is nothing left: the next run fills nothing.
      const again = await runSweep(env, {
        now: new Date("2026-09-11T14:00:00.000Z"),
        beacon: new FixtureBeacon("duplicates"),
      });
      expect(again.duplicates).toEqual({ filled: 0 });
    } finally {
      await world.dispose();
    }
  }, 600_000);

  it("refills a row migration 0020 nulled, with the key that carries effective_at", async () => {
    // 0020 is one statement -- `UPDATE entries SET duplicate_key = NULL` --
    // because the key is a SHA-256 over RFC 8785 canonical JSON of normalized
    // text and SQL cannot compute it. What it leaves behind is exactly the
    // state 0019's backfill already knows how to close, which is the whole
    // reason the migration is allowed to be that short.
    const world = await openTestDatabase();
    try {
      const env: Env = {
        DB: world.db,
        CAPTURES: world.captures,
        ENVIRONMENT: "local",
        MAINTAINER_AGENT_ID: "1F916:maintainer",
      };
      const id = `nmk_${"3".repeat(32)}`;
      const value = "40 per million";

      const events: Event[] = await appendEvent([], {
        at: AT,
        type: "entry_submitted",
        entry_id: id,
        payload: { core: coreOf(id, value), signature: "sig" },
      } as never);
      await appendEvents(world.db, events);
      await putEntry(world.db, entryOf(id, value, "draft"), SIDECAR, events[0]!.seq);

      // The store wrote the current key. 0020 then empties the column for every
      // row, which is what a deployment sees the moment the migration runs.
      expect(
        await world.db
          .prepare(`SELECT duplicate_key FROM entries WHERE id = ?`)
          .bind(id)
          .first<{ duplicate_key: string | null }>(),
      ).toEqual({ duplicate_key: await duplicateKeyHash(coreOf(id, value)) });
      await world.db.prepare(`UPDATE entries SET duplicate_key = NULL`).run();
      expect(await liveDuplicateOf(world.db, await duplicateKeyHash(coreOf(id, value)))).toBeNull();

      const report = await runSweep(env, {
        now: new Date("2026-09-11T13:00:00.000Z"),
        beacon: new FixtureBeacon("duplicates"),
      });
      expect(report.duplicates).toEqual({ filled: 1 });

      // The key it comes back with is the five-field one: the same claim at
      // another date does not find it, and its own date does.
      expect(await liveDuplicateOf(world.db, await duplicateKeyHash(coreOf(id, value)))).toBe(
        id,
      );
      expect(
        await liveDuplicateOf(
          world.db,
          await duplicateKeyHash(coreOf(id, value, "2027-01-01")),
        ),
      ).toBeNull();
    } finally {
      await world.dispose();
    }
  }, 600_000);
});

/**
 * The counters the public pages read, against a real D1.
 *
 * Whitepaper Section 3: the log is the record, and every number a page shows is
 * a view of it. The QA of 2026-09-12 found the pages taking that view per
 * reader, by scanning whole tables — twice over for two conditions no index
 * could serve. M25 takes it once per sweep instead, so the thing these tests
 * have to prove is that the cheap answer and the expensive one are the same
 * answer.
 *
 * So every count below is checked against the scan it replaces, over a world
 * with entries in every status across three domains, five operators of whom two
 * are trusted, twelve seals of which nine are countersigned, and two
 * attestations. The fixtures go in through the repository's own writers,
 * because a row written any other way would not prove the shape the Worker
 * stores — and one test deliberately writes a row the other way, to show that
 * the comparison would catch it.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getPlatformProxy } from "wrangler";
import { extractCore, type Core } from "../src/core.js";
import type { DerivedAttestation } from "../src/attest.js";
import type { Sidecar } from "../src/derive.js";
import {
  appendEvent,
  type Attestation,
  type Event,
  type EventInput,
} from "../src/events.js";
import { FixtureBeacon } from "../src/adapters/beacon.js";
import { DOMAIN_SLUGS } from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import type { Seal } from "../src/seal.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import type { R2Like } from "../src/storage/r2.js";
import { applyMigrations } from "../src/storage/migrate.js";
import {
  appendEvents,
  countAttestations,
  countEntries,
  countOperators,
  countSeals,
  countTrustedOperators,
  countWitnessedSeals,
  eventBySeq,
  headSeq,
  putAttestation,
  putEntry,
  putSeal,
  readCounters,
  setSealRegistry,
  registerOperator,
  setSealWitnesses,
  trustOperator,
  trustedOperatorIds,
  unwitnessedSeals,
  type OperatorRecord,
  type StoredEntryInput,
} from "../src/storage/repository.js";
import { countersStep, runSweep } from "../src/worker/sweep.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";
import { statusInput } from "../src/worker/status.js";
import {
  CONFIG_PATH,
  loadMigrations,
  openTestDatabase,
  type TestDatabase,
} from "./helpers/d1.js";

const AT = "2026-09-12T00:00:00.000Z";

const ATTESTATION: Attestation = {
  version: "attest-v1",
  signed_at: "2026-08-01T00:00:00.000Z",
  signature: "c2lnbmF0dXJl",
};

/** The three registered domains, named by the registry rather than by hand. */
const [ECOSYSTEM, GOVERNANCE, SAFETY] = DOMAIN_SLUGS as readonly [
  string,
  string,
  string,
];

/** A fixture entry: what derivation would have left behind, spelled out. */
interface Fixture {
  readonly id: string;
  readonly domain: string;
  readonly status: string;
  readonly stale: boolean;
}

/**
 * Every status, spread over the three domains, with staleness on three of them.
 *
 * Five statuses and three domains on purpose: a count that quietly grouped by
 * the wrong column, or that took the default domain for every row, would come
 * back different from the scan it is checked against.
 */
const FIXTURES: readonly Fixture[] = [
  { id: "nmk_c01", domain: ECOSYSTEM, status: "verified", stale: false },
  { id: "nmk_c02", domain: ECOSYSTEM, status: "verified", stale: true },
  { id: "nmk_c03", domain: ECOSYSTEM, status: "draft", stale: false },
  { id: "nmk_c04", domain: ECOSYSTEM, status: "rejected", stale: false },
  { id: "nmk_c05", domain: GOVERNANCE, status: "verified", stale: true },
  { id: "nmk_c06", domain: GOVERNANCE, status: "superseded", stale: false },
  { id: "nmk_c07", domain: GOVERNANCE, status: "overturned", stale: false },
  { id: "nmk_c08", domain: SAFETY, status: "verified", stale: true },
  { id: "nmk_c09", domain: SAFETY, status: "draft", stale: false },
  { id: "nmk_c10", domain: SAFETY, status: "rejected", stale: false },
];

function entryOf(fixture: Fixture): Entry {
  return {
    id: fixture.id,
    subject: "openai/gpt-5",
    category: "pricing",
    domain: fixture.domain,
    claim: `${fixture.id} changed`,
    before: "old",
    after: "new",
    effective_at: "2026-04-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://example.test/changelog",
    snapshot_hash: `sha256:${"1".repeat(64)}`,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: "1F916:author",
    author_operator: "op-alpha",
    submitted_at: "2026-04-02T00:00:00.000Z",
    status: fixture.status,
    staleness_window_days: null,
    verified_at: fixture.status === "verified" ? "2026-04-03T00:00:00.000Z" : null,
    last_confirmed: "2026-04-03",
    expires_at: null,
    stale: fixture.stale,
    superseded_by: null,
    overturned_by: null,
    confidence: null,
  };
}

const SIDECAR: Sidecar = {
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: null,
  source: { class: "other", matched_host: null, authority: null },
  trusted_count_at_decision: null,
  read_share_slots: null,
  revalidations: [],
};

/** The five operators, and which domain each attested in at registration. */
const OPERATORS: readonly { id: string; domain: string; trusted: boolean }[] = [
  { id: "op-alpha", domain: ECOSYSTEM, trusted: true },
  { id: "op-beta", domain: ECOSYSTEM, trusted: true },
  { id: "op-gamma", domain: GOVERNANCE, trusted: false },
  { id: "op-delta", domain: SAFETY, trusted: false },
  { id: "op-epsilon", domain: SAFETY, trusted: false },
];

const SEAL_COUNT = 12;
const WITNESSED_SEALS = 9;

/**
 * The first event a seal covers. The ten submissions are at 0..9, so the seals
 * are put over the registration events above them: `setSealWitnesses` rewrites
 * every entry a seal covers, and these fixtures are about the seals themselves.
 */
const SEAL_BASE = 10;

/** A distinct 64-character digest per seal: the hash column is unique. */
function digest(seq: number): string {
  return `sha256:${String(seq).padStart(2, "0").repeat(32)}`;
}

function sealAt(seq: number): Seal {
  return {
    seq,
    first_seq: SEAL_BASE + seq,
    last_seq: SEAL_BASE + seq,
    size: 1,
    root: digest(seq),
    sealed_at: `2026-04-${String(seq + 1).padStart(2, "0")}T00:00:00.000Z`,
    prev_hash: seq === 0 ? null : digest(seq - 1),
    hash: digest(seq),
    witnesses: [],
    registry: null,
  };
}

function attestationAt(id: string, seq: number): DerivedAttestation {
  return {
    id,
    domain: ECOSYSTEM,
    model: "openai/gpt-5",
    model_operator: null,
    probes: [],
    probe_hash: `sha256:${"3".repeat(64)}`,
    probe_count: 0,
    pool_snapshot_seq: 0,
    beacon_round: 1,
    scorers: [],
    requested_seq: seq,
    requested_at: "2026-09-01T00:00:00.000Z",
    deadline: "2026-09-08T00:00:00.000Z",
    answers_hash: null,
    answered_at: null,
    scores: [],
    score: null,
    status: "open",
    scored_at: null,
    date: null,
  };
}

/** Every count the step writes, taken the expensive way: by scanning. */
async function byScanning(db: D1Like): Promise<Record<string, number>> {
  const scan = async (sql: string, ...bindings: unknown[]): Promise<number> => {
    const row = await db
      .prepare(sql)
      .bind(...bindings)
      .first<Record<string, unknown>>();
    return row === null ? 0 : (row["n"] as number);
  };
  const counts: Record<string, number> = {
    entries_total: await scan(`SELECT COUNT(*) AS n FROM entries`),
    entries_verified: await scan(
      `SELECT COUNT(*) AS n FROM entries WHERE json_extract(entry_json, '$.status') = 'verified'`,
    ),
    entries_stale: await scan(
      `SELECT COUNT(*) AS n FROM entries WHERE json_extract(entry_json, '$.stale')`,
    ),
    operators_registered: await scan(`SELECT COUNT(*) AS n FROM operators`),
    operators_trusted: await scan(
      `SELECT COUNT(*) AS n FROM operators WHERE json_extract(operator_json, '$.trusted')`,
    ),
    seals: await scan(`SELECT COUNT(*) AS n FROM seals`),
    seals_witnessed: await scan(
      `SELECT COUNT(*) AS n FROM seals WHERE witnesses_json <> '[]'`,
    ),
    attestations: await scan(`SELECT COUNT(*) AS n FROM attestations`),
  };
  for (const slug of DOMAIN_SLUGS) {
    counts[`${slug}:entries`] = await scan(
      `SELECT COUNT(*) AS n FROM entries WHERE json_extract(entry_json, '$.domain') = ?`,
      slug,
    );
    counts[`${slug}:trusted`] = await scan(
      `SELECT COUNT(*) AS n FROM operators
        WHERE json_extract(operator_json, '$.trusted')
          AND id IN (SELECT operator FROM operator_domains WHERE domain = ?)`,
      slug,
    );
  }
  return counts;
}

/** A D1 handle that counts the statements prepared through it. */
function counting(db: D1Like): { db: D1Like; statements: () => number } {
  let prepared = 0;
  const wrapped: D1Like = {
    prepare(sql: string): D1LikeStatement {
      prepared += 1;
      return db.prepare(sql);
    },
    batch: (statements) => db.batch(statements),
    exec: (sql) => db.exec(sql),
  };
  return { db: wrapped, statements: () => prepared };
}

describe("the counters step", () => {
  let world: TestDatabase;
  let db: D1Like;
  let env: Env;
  let chain: Event[] = [];
  let sealedHead = -1;

  async function add(input: EventInput): Promise<Event> {
    chain = await appendEvent(chain, input);
    return chain[chain.length - 1]!;
  }

  function operatorRecord(
    id: string,
    registeredSeq: number,
    trustedSeq: number | null,
  ): OperatorRecord {
    return {
      id,
      maintainer: false,
      provider: false,
      registeredSeq,
      details: {
        registered_by: `1F916:${id}-agent`,
        attestation: ATTESTATION,
        trusted: trustedSeq !== null,
        trusted_seq: trustedSeq,
      },
    };
  }

  beforeAll(async () => {
    world = await openTestDatabase();
    db = world.db;
    env = {
      DB: db,
      CAPTURES: world.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "1F916:maintainer",
    };

    const submissions: Event[] = [];
    for (const fixture of FIXTURES) {
      const core: Core = extractCore(entryOf(fixture));
      submissions.push(
        await add({
          at: "2026-04-02T00:00:00.000Z",
          type: "entry_submitted",
          entry_id: fixture.id,
          payload: { core, signature: "c2lnbmF0dXJl" },
        }),
      );
    }
    await appendEvents(db, submissions);
    for (const [index, fixture] of FIXTURES.entries()) {
      await putEntry(db, entryOf(fixture), SIDECAR, submissions[index]!.seq);
    }

    for (const operator of OPERATORS) {
      const registered = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "operator_registered",
        entry_id: null,
        payload: { operator: operator.id, maintainer: false },
      });
      const bound = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "agent_bound",
        entry_id: null,
        payload: {
          operator: operator.id,
          agent: `1F916:${operator.id}-agent`,
          attestation: ATTESTATION,
        },
      });
      await registerOperator(db, {
        events: [registered, bound],
        operator: operatorRecord(operator.id, registered.seq, null),
        agent: {
          agentId: `1F916:${operator.id}-agent`,
          operatorId: operator.id,
          registeredSeq: bound.seq,
        },
        domain: { domain: operator.domain, attestation: ATTESTATION },
      });
    }
    for (const operator of OPERATORS.filter((one) => one.trusted)) {
      const event = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "operator_trusted",
        entry_id: null,
        payload: { operator: operator.id },
      });
      await trustOperator(db, {
        event,
        operator: operatorRecord(operator.id, event.seq - 1, event.seq),
      });
    }

    // Twelve seals, nine of them countersigned through the writer that attaches
    // countersignatures, so the column is written by the path the sweep uses.
    const rewrite = async (
      entryId: string,
    ): Promise<StoredEntryInput> => {
      throw new Error(`no entry should be covered: ${entryId}`);
    };
    for (let seq = 0; seq < SEAL_COUNT; seq += 1) {
      await putSeal(db, sealAt(seq));
    }
    for (let seq = 0; seq < WITNESSED_SEALS; seq += 1) {
      await setSealWitnesses(
        db,
        sealAt(seq),
        [
          { agent: "1F916:witness", signature: "c2lnbmF0dXJl" },
        ],
        new Date(AT),
        rewrite,
      );
      // And the registry receipt with it, so the sweep's queue is the three
      // seals that are actually still waiting rather than every seal at once.
      await setSealRegistry(db, seq, {
        registry: "mock",
        handle: "nomankind",
        label: `seal-${seq}`,
        event_id: seq,
        event_hash: `sha256:${"4".repeat(64)}`,
        receipt: null,
        sealed_at: AT,
      });
    }

    for (const [index, id] of ["att_one", "att_two"].entries()) {
      await putAttestation(db, {
        attestation: attestationAt(id, index),
        answers: null,
      });
    }

    sealedHead = chain.length - 1;
  }, 120_000);

  afterAll(async () => {
    await world?.dispose();
  });

  it("counts exactly what a scan of the same world counts", async () => {
    const skipped: string[] = [];
    const report = await countersStep(db, sealedHead, AT, (reason) =>
      skipped.push(reason),
    );
    expect(skipped).toEqual([]);

    const scanned = await byScanning(db);
    const counters = await readCounters(db);
    expect(counters).not.toBeNull();

    expect({
      entries_total: counters!.entries_total,
      entries_verified: counters!.entries_verified,
      entries_stale: counters!.entries_stale,
      operators_registered: counters!.operators_registered,
      operators_trusted: counters!.operators_trusted,
      seals: counters!.seals,
      seals_witnessed: counters!.seals_witnessed,
      attestations: counters!.attestations,
    }).toEqual({
      entries_total: scanned["entries_total"],
      entries_verified: scanned["entries_verified"],
      entries_stale: scanned["entries_stale"],
      operators_registered: scanned["operators_registered"],
      operators_trusted: scanned["operators_trusted"],
      seals: scanned["seals"],
      seals_witnessed: scanned["seals_witnessed"],
      attestations: scanned["attestations"],
    });

    // The fixtures themselves, so a scan that agreed with a broken count on an
    // empty world would still be caught.
    expect(counters!.entries_total).toBe(FIXTURES.length);
    expect(counters!.operators_registered).toBe(OPERATORS.length);
    expect(counters!.operators_trusted).toBe(2);
    expect(counters!.seals).toBe(SEAL_COUNT);
    expect(counters!.seals_witnessed).toBe(WITNESSED_SEALS);
    expect(counters!.attestations).toBe(2);

    // Every registered domain has a pair, including one the scan and the step
    // both count from the same rows.
    for (const slug of DOMAIN_SLUGS) {
      expect(counters!.entries_by_domain[slug]).toEqual({
        entries: scanned[`${slug}:entries`],
        trusted_operators: scanned[`${slug}:trusted`],
      });
    }

    // The position and the instant are the run's, on every row at once.
    expect(counters!.position).toBe(sealedHead);
    expect(counters!.sealed_head).toBe(sealedHead);
    expect(counters!.updated_at).toBe(AT);
    expect(report).toEqual({
      position: sealedHead,
      entries: FIXTURES.length,
      operators: OPERATORS.length,
      seals: SEAL_COUNT,
      attestations: 2,
    });
  });

  it("rewrites the row whole, so a domain that empties out does not linger", async () => {
    await countersStep(db, sealedHead, AT, () => undefined);
    const rows = await db
      .prepare(`SELECT COUNT(*) AS n FROM counters`)
      .first<Record<string, unknown>>();
    // Nine named counters plus a pair per registered domain, and no second run
    // of the same step doubles them.
    expect(rows!["n"]).toBe(9 + DOMAIN_SLUGS.length * 2);
  });

  it("answers a status gather from the row instead of scanning for it", async () => {
    const { db: watched, statements } = counting(db);
    const input = await statusInput(watched, { ...env, DB: watched }, AT);

    expect(input.seals).toEqual({
      total: SEAL_COUNT,
      witnessed: WITNESSED_SEALS,
    });
    expect(input.entries).toBe(FIXTURES.length);
    expect(input.pool.registered).toBe(OPERATORS.length);
    expect(input.attestations.total).toBe(2);

    // The whole point of the milestone: not one statement in the gather counts
    // a table any more. Five of the thirty-three reads this door used to make
    // were whole-table counts — the seals, the countersigned seals, the
    // operators, the entries and the attestations — and they are one lookup by
    // primary key now, which is why the ceiling is thirty rather than the
    // thirty-four it would otherwise be. Asserted rather than described, so a
    // read added to this path has to be argued for.
    expect(statements()).toBeLessThan(30);
  });

  it("still answers before the first sweep has written the row", async () => {
    const fresh = await openTestDatabase();
    try {
      expect(await readCounters(fresh.db)).toBeNull();
      const input = await statusInput(
        fresh.db,
        { ...env, DB: fresh.db, CAPTURES: fresh.captures },
        AT,
      );
      expect(input.seals).toEqual({ total: 0, witnessed: 0 });
      expect(input.entries).toBe(0);
      expect(input.pool.registered).toBe(0);
      expect(input.attestations.total).toBe(0);
    } finally {
      await fresh.dispose();
    }
  }, 60_000);

  it("answers every recount from an index, and the queue from the partial one", async () => {
    // The rule the milestone turns on, asked of the planner rather than
    // described: a count that fell back to a table scan, or to json_extract,
    // would be the thing the QA found, quietly restored.
    for (const [sql, index] of [
      [`SELECT COUNT(*) AS n FROM entries WHERE stale = 1`, "entries_stale"],
      [
        `SELECT COUNT(*) AS n FROM operators WHERE trusted = 1`,
        "operators_trusted",
      ],
      [`SELECT COUNT(*) AS n FROM seals WHERE witnessed = 1`, "seals_witnessed"],
      [
        `SELECT id FROM operators WHERE trusted = 1 ORDER BY id LIMIT 10`,
        "operators_trusted",
      ],
      [
        `SELECT seq FROM seals WHERE witnessed = 0 OR registry_json IS NULL ORDER BY seq LIMIT 10`,
        // The partial index holds only the seals still waiting, so walking all
        // of it is walking the queue and not the table.
        "seals_unfinished",
      ],
      [
        `SELECT domain, COUNT(*) AS n FROM entries GROUP BY domain`,
        "entries_domain_status_seq",
      ],
    ] as const) {
      const rows = await db
        .prepare(`EXPLAIN QUERY PLAN ${sql}`)
        .all<Record<string, unknown>>();
      const detail = rows.results.map((row) => String(row["detail"])).join(" | ");
      expect([sql, detail.includes(index)]).toEqual([sql, true]);
      expect([sql, detail.includes("json_extract")]).toEqual([sql, false]);
    }
  });

  it("keeps the columns and the JSON beside them saying the same thing", async () => {
    // The writers named in 0018's comment are the only ones that touch these
    // columns, and every one of them went through the fixtures above.
    expect(await countTrustedOperators(db)).toBe(2);
    expect(await trustedOperatorIds(db, 10)).toEqual(["op-alpha", "op-beta"]);
    expect(await countWitnessedSeals(db)).toBe(WITNESSED_SEALS);
    expect((await unwitnessedSeals(db, 20)).map((seal) => seal.seq)).toEqual([
      9, 10, 11,
    ]);

    // And the mutation: trust flipped in the JSON and nowhere else — which is
    // what a write that bypassed `operatorStatement` would leave behind — is
    // caught, because the column no longer says what the JSON says.
    await db
      .prepare(
        `UPDATE operators
            SET operator_json = json_set(operator_json, '$.trusted', json('true'))
          WHERE id = 'op-gamma'`,
      )
      .run();
    try {
      const scanned = await byScanning(db);
      expect(scanned["operators_trusted"]).toBe(3);
      expect(await countTrustedOperators(db)).toBe(2);
      expect(scanned["operators_trusted"]).not.toBe(
        await countTrustedOperators(db),
      );
    } finally {
      await db
        .prepare(
          `UPDATE operators
              SET operator_json = json_set(operator_json, '$.trusted', json('false'))
            WHERE id = 'op-gamma'`,
        )
        .run();
    }
  });
});

/**
 * A database migrated up to but not including 0018, so the backfill can be
 * given rows that were written before the columns existed.
 */
async function through0017(): Promise<{
  db: D1Like;
  rest: () => Promise<string[]>;
  dispose: () => Promise<void>;
}> {
  const platform = await getPlatformProxy<{ DB: D1Like; CAPTURES: R2Like }>({
    configPath: CONFIG_PATH,
    persist: false,
  });
  const all = loadMigrations();
  const upTo = all.slice(
    0,
    all.findIndex((one) => one.name === "0018_counters.sql"),
  );
  expect(upTo[upTo.length - 1]?.name).toBe("0017_standing_cursor.sql");
  await applyMigrations(platform.env.DB, upTo);
  return {
    db: platform.env.DB,
    rest: () => applyMigrations(platform.env.DB, all),
    dispose: () => platform.dispose(),
  };
}

describe("the 0018 backfill on a database written before it", () => {
  it("gives every existing row the trust and the countersignature it already had", async () => {
    const old = await through0017();
    try {
      // Operators as the pre-0018 writer left them: trust inside the JSON only,
      // including a row that never carried the field at all.
      for (const [id, trusted] of [
        ["op-one", "true"],
        ["op-two", "true"],
        ["op-three", "false"],
        ["op-four", null],
      ] as const) {
        await old.db
          .prepare(
            `INSERT INTO operators (id, maintainer, provider, registered_seq, operator_json)
             VALUES (?, 0, 0, 0, ?)`,
          )
          .bind(
            id,
            trusted === null ? "{}" : `{"trusted":${trusted}}`,
          )
          .run();
      }

      // Seals as the pre-0018 writer left them: the countersignatures in JSON.
      for (let seq = 0; seq < 5; seq += 1) {
        await old.db
          .prepare(
            `INSERT INTO seals (seq, first_seq, last_seq, size, root, sealed_at, prev_hash, hash, witnesses_json, registry_json)
             VALUES (?, ?, ?, 1, ?, ?, NULL, ?, ?, NULL)`,
          )
          .bind(
            seq,
            seq,
            seq,
            `sha256:${String(seq).repeat(64)}`,
            `2026-04-0${seq + 1}T00:00:00.000Z`,
            `sha256:${String(seq).repeat(64)}`,
            seq < 3 ? `[{"witness":"mock"}]` : "[]",
          )
          .run();
      }

      expect(await old.rest()).toEqual(["0018_counters.sql"]);

      // The column says exactly what the JSON beside it has always said.
      expect(await countTrustedOperators(old.db)).toBe(2);
      expect(await trustedOperatorIds(old.db, 10)).toEqual(["op-one", "op-two"]);
      expect(await countOperators(old.db)).toBe(4);
      expect(await countWitnessedSeals(old.db)).toBe(3);
      expect(await countSeals(old.db)).toBe(5);
      expect((await unwitnessedSeals(old.db, 10)).map((seal) => seal.seq)).toEqual(
        [0, 1, 2, 3, 4],
      );

      // And the entries index the migration adds serves the count it was added
      // for, on a table that was there before it.
      expect(await countEntries(old.db, { stale: true })).toBe(0);
      expect(await countAttestations(old.db)).toBe(0);

      // Nothing is counted before the first sweep writes the row.
      expect(await readCounters(old.db)).toBeNull();
    } finally {
      await old.dispose();
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// A populated log between the migration and its first sweep, and the run that
// ends it
// ---------------------------------------------------------------------------

/**
 * The window every upgrade opens: the 0018 migration is applied, the counters
 * table is there and empty, and the sweep has not run yet.
 *
 * A missing row must never read as zeros. Zeros are a statement about the log —
 * no entries, no operators, no seals, no attestations — and the status rules
 * turn stages idle on them, so a populated production would report itself
 * stopped for as long as it took the next sweep to come round. What a missing
 * row means is "nobody has folded these", and the answer to that is to count
 * them, which is what every one of these pages did before the row existed
 * (`logCounters`, src/worker/status.ts).
 *
 * And the run itself: nothing in the suite bound `countersStep` to `runSweep`
 * until this file did, so deleting the call from the sweep passed everything.
 * Here the sweep is run for real, and the row it leaves is the assertion.
 */
describe("a populated log before its first sweep", () => {
  let world: TestDatabase;
  let db: D1Like;
  let env: Env;
  let chain: Event[] = [];

  /**
   * Put `count` entries in, through the writers the Worker itself uses.
   *
   * The chain is re-read from the store each time rather than kept in hand: a
   * sweep writes events of its own, so the head this test appends after is
   * whatever the log holds now.
   */
  async function seed(count: number, from = 0): Promise<void> {
    const head = await headSeq(db);
    const last = head === null || head < 0 ? null : await eventBySeq(db, head);
    chain = last === null ? [] : [last];
    const submissions: Event[] = [];
    const fixtures = FIXTURES.slice(from, from + count);
    for (const fixture of fixtures) {
      chain = await appendEvent(chain, {
        at: "2026-04-02T00:00:00.000Z",
        type: "entry_submitted",
        entry_id: fixture.id,
        payload: { core: extractCore(entryOf(fixture)), signature: "c2lnbmF0dXJl" },
      });
      submissions.push(chain[chain.length - 1]!);
    }
    await appendEvents(db, submissions);
    for (const [index, fixture] of fixtures.entries()) {
      await putEntry(db, entryOf(fixture), SIDECAR, submissions[index]!.seq);
    }
  }

  beforeAll(async () => {
    world = await openTestDatabase();
    db = world.db;
    env = {
      DB: db,
      CAPTURES: world.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "1F916:maintainer",
    };
    await seed(4);
  }, 120_000);

  afterAll(async () => {
    await world?.dispose();
  });

  it("counts the log rather than reporting it empty", async () => {
    // The state under test, stated: the table is there and nothing has folded.
    expect(await readCounters(db)).toBeNull();

    const input = await statusInput(db, env, AT);
    expect(input.entries).toBe(4);
    expect(input.entries).toBe(await countEntries(db, {}));
    expect(input.seals).toEqual({
      total: await countSeals(db),
      witnessed: await countWitnessedSeals(db),
    });
    expect(input.pool.registered).toBe(await countOperators(db));
    expect(input.attestations.total).toBe(await countAttestations(db));
  }, 60_000);

  it("shows the same counts on the pages that read them", async () => {
    const home = await handlePages(
      new Request("https://app.nomankind.ai/", {
        headers: { accept: "text/html" },
      }),
      env,
      { now: new Date(AT) },
    );
    expect(home!.status).toBe(200);
    const verified = await countEntries(db, { status: "verified" });
    expect(await home!.text()).toContain(`>${verified}<`);

    const domains = await handlePages(
      new Request("https://app.nomankind.ai/domains", {
        headers: { accept: "text/html" },
      }),
      env,
      { now: new Date(AT) },
    );
    const page = await domains!.text();
    for (const slug of DOMAIN_SLUGS) {
      const counted = await countEntries(db, { domain: slug });
      expect(page).toContain(`${counted} entries`);
    }
  }, 60_000);

  it("is ended by a sweep, which leaves the row at the run's own position and clock", async () => {
    const at = new Date("2026-09-12T01:00:00.000Z");
    const report = await runSweep(env, {
      now: at,
      beacon: new FixtureBeacon("counters"),
    });

    const written = await readCounters(db);
    expect(written).not.toBeNull();
    expect(written!.updated_at).toBe(at.toISOString());
    // The position is the run's sealed head, which is what the report says the
    // step folded to, and the same number the row carries.
    expect(written!.position).toBe(written!.sealed_head);
    expect(report.counters).not.toBeNull();
    expect(report.counters!.position).toBe(written!.position);
    expect(report.counters!.entries).toBe(written!.entries_total);
    expect(written!.entries_total).toBe(await countEntries(db, {}));
  }, 600_000);

  it("folds the new entries in when the sweep runs again", async () => {
    const before = await readCounters(db);
    expect(before).not.toBeNull();

    await seed(3, 4);
    // Until the next run, the row is the last run's answer: the counters are a
    // view of the log folded at a position, not a live count.
    expect((await readCounters(db))!.entries_total).toBe(before!.entries_total);

    const at = new Date("2026-09-12T02:00:00.000Z");
    await runSweep(env, { now: at, beacon: new FixtureBeacon("counters") });

    const after = await readCounters(db);
    expect(after!.entries_total).toBe(before!.entries_total + 3);
    expect(after!.entries_total).toBe(await countEntries(db, {}));
    expect(after!.updated_at).toBe(at.toISOString());
  }, 600_000);
});

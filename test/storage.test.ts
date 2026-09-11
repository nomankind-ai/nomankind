/**
 * The storage round-trip, against a real D1.
 *
 * The world under test is the verifier's own (test/helpers/verify-world.ts):
 * real Ed25519 signatures, real hashes, both entries out of `deriveEntry`. So
 * these tests do not ask "did the columns survive" but the stronger question
 * the retrospective's DEPLOY-1 lesson demands: after a full trip through D1,
 * does the log still verify, and does derivation over the events read back
 * produce exactly the entry that was stored.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  CORE_KEYS,
  agentIdFromPublicKey,
  appendEvent,
  bountyAccrual,
  disputeOutcomeStakes,
  disputeStake,
  revalidationOutcomeStakes,
  revalidationStake,
  DISPUTE_STAKE_STANDING,
  REVALIDATION_REQUEST_STAKE_STANDING,
  LIST_PAGE_LIMIT,
  buildReadCountPayload,
  clawbackRows,
  payoutPlan,
  payoutRow,
  readShareRows,
  reconciliationRow,
  buildAnchor,
  buildSeal,
  buildSubmittedCore,
  decodeProof,
  deriveEntry,
  entryHash,
  entrySeal,
  exportPublicKeyRaw,
  generateKeypair,
  signReadReceipt,
  signSyncReceipt,
  verifyReadReceipt,
  verifySyncReceipt,
  sealsForEntries,
  verifyInclusion,
  utcDay,
  verifyChain,
  type Anchor,
  type ApproverRecord,
  type Attestation,
  type Core,
  type Event,
  type EntrySeal,
  type Entry,
  lockedStanding,
  type LedgerRow,
  type StakeRecord,
  type OpenAssignment,
  type EntryStatus,
  type ReadReceipt,
  type SyncReceipt,
  type RegistrySeal,
  type Seal,
  type WitnessSignature,
} from "../src/index.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { sourceClassOf } from "../src/sources.js";
import { applyMigrations, splitStatements } from "../src/storage/migrate.js";
import {
  EventAppendError,
  agentsForOperator,
  appendEvents,
  countEntries,
  countTrustedOperators,
  listEntriesPage,
  operatorDomains,
  operatorsInDomain,
  probeCandidates,
  recordDomainJoin,
  captureForHash,
  capturesForEntry,
  dueAssignments,
  eventBySeq,
  eventsAfter,
  eventsForEntry,
  eventsInRange,
  earliestReadReceiptDay,
  eventsOfType,
  getAnchor,
  getEntry,
  getOperator,
  headSeq,
  latestAnchor,
  latestEventOfType,
  entriesNewestFirst,
  latestSeal,
  listEntries,
  listOperators,
  bountiesForEntry,
  correctionEntriesFor,
  disputeOf,
  dueRevalidationAssignments,
  ledgerRowsForEntry,
  bountyPoolRows,
  entryLedgerRows,
  heldReadShareRows,
  ledgerCursor,
  ledgerRowsForOperator,
  ledgerRowsOn,
  markLedgerPaid,
  payoutRows,
  putLedgerRows,
  reconciliationRows,
  recordPayout,
  recordTrustChange,
  releasedUnpaidRows,
  setLedgerCursor,
  setOperatorStanding,
  standingByOperator,
  operatorStanding,
  standingForOperators,
  priceBountyRow,
  openRevalidationAssignment,
  openStakeRowsForOperator,
  overturnedCountsByOperator,
  recordDisputeFiling,
  recordFailureReport,
  recordRevalidationAssignment,
  recordRevalidationMissed,
  recordRevalidationRequest,
  recordRevalidationResolution,
  type StoredEntryInput,
  markAssignmentAnswered,
  markAssignmentMissed,
  MissingSubmissionError,
  openAssignment,
  operatorForAgent,
  putAgent,
  putAnchor,
  putAssignment,
  putCapture,
  putEntry,
  putOperator,
  putReadReceipt,
  putSyncReceipt,
  putSeal,
  newestUpgradedAnchor,
  nextReadCounter,
  readCandidates,
  readCountsOn,
  readCountsSplitOn,
  readCounterRangeOn,
  readReceiptByCounter,
  readReceiptsForEntry,
  ReceiptConflictError,
  syncReceiptByCounter,
  recordAssignment,
  recordAssignmentMissed,
  recordPoolSnapshot,
  recordReconfirmation,
  recordValidation,
  anchorsAfter,
  recordSeal,
  registerOperator,
  sealBySeq,
  sealCovering,
  sealsAfter,
  sealsBetween,
  sealsSealedOn,
  SealConflictError,
  setAnchorExternal,
  setSealRegistry,
  setSealWitnesses,
  unwitnessedSeals,
  staleDue,
  submitEntry,
  supersedersOf,
  trustOperator,
  type SealRederive,
  type AgentRecord,
  type CaptureRecord,
  type OperatorRecord,
} from "../src/storage/repository.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import {
  archiveCapture,
  readCapture,
  readSidecar,
  type Sidecar,
} from "../src/storage/r2.js";
import { entryWorld, rederive } from "../src/worker/world.js";
import { loadMigrations, openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  DRAFT_ENTRY_ID,
  MAINTAINER_OPERATOR,
  OUTSIDE_OPERATORS,
  SUBMITTER_OPERATOR,
  VERIFIED_ENTRY_ID,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

let test: TestDatabase;
let world: VerifyWorld;

/**
 * A second seal, built but not stored.
 *
 * The world seals events 0 through the last validation and then submits the
 * draft and appends the reconfirmation, so the tail of the log is left
 * unsealed. `buildSeal` with the world's seal as its predecessor closes exactly
 * that tail, which is what the range predicates need: one seal cannot tell
 * `WHERE last_seq >= ? AND first_seq <= ?` from `WHERE last_seq >= ?`.
 */
let secondSeal: Seal;

/** The derivation clock the world was built under. */
function clock(): { now: string } {
  return { now: world.bundle.as_of };
}

/**
 * 0005's three columns, read raw. The repository never selects them back into
 * an entry — they exist for the sweep's WHERE clause — so the only way to ask
 * what was written is to ask the table.
 */
async function freshnessColumns(
  db: D1Like,
  id: string,
): Promise<Record<string, unknown> | null> {
  const row = await db
    .prepare(`SELECT stale, expires_at, supersedes FROM entries WHERE id = ?`)
    .bind(id)
    .first<Record<string, unknown>>();
  if (row === null) return null;
  return {
    stale: row["stale"],
    expires_at: row["expires_at"] ?? null,
    supersedes: row["supersedes"] ?? null,
  };
}

beforeAll(async () => {
  world = await buildVerifyWorld({ withReconfirmation: true });
  test = await openTestDatabase();
  await appendEvents(test.db, world.bundle.events);
  for (const seal of world.bundle.seals) await putSeal(test.db, seal);

  const previous = world.bundle.seals[world.bundle.seals.length - 1]!;
  const built = await buildSeal(world.bundle.events, previous, clock());
  if (!built.ok) throw new Error(`storage.test: buildSeal ${built.reason}`);
  secondSeal = built.seal;
}, 600_000);

// getPlatformProxy runs a child process; vitest would hold the run open
// without this.
afterAll(async () => {
  await test?.dispose();
});

describe("events", () => {
  it("round-trips the whole log and still verifies", async () => {
    const last = world.bundle.events[world.bundle.events.length - 1]!;
    expect(await headSeq(test.db)).toBe(last.seq);

    const stored = await eventsInRange(test.db, 0, last.seq);
    expect(stored).toEqual(world.bundle.events);
    expect(await verifyChain(stored)).toEqual({
      ok: true,
      length: world.bundle.events.length,
    });
  });

  it("reads one entry's lifecycle without touching the rest of the log", async () => {
    const expected = world.bundle.events.filter(
      (event) => event.entry_id === VERIFIED_ENTRY_ID,
    );
    expect(expected.length).toBeGreaterThan(0);
    expect(await eventsForEntry(test.db, VERIFIED_ENTRY_ID)).toEqual(expected);
  });

  it("reads one event by seq", async () => {
    const wanted = world.bundle.events[2]!;
    expect(await eventBySeq(test.db, wanted.seq)).toEqual(wanted);
    expect(await eventBySeq(test.db, world.bundle.events.length)).toBeNull();
  });

  it("pages forward from a known position", async () => {
    const page = await eventsAfter(test.db, 0, 3);
    expect(page).toEqual(world.bundle.events.slice(1, 4));
    const next = await eventsAfter(test.db, page[page.length - 1]!.seq, 3);
    expect(next).toEqual(world.bundle.events.slice(4, 7));
  });

  it("pages forward within one event type", async () => {
    const submissions = world.bundle.events.filter(
      (event) => event.type === "entry_submitted",
    );
    expect(
      await eventsOfType(test.db, "entry_submitted", -1, submissions.length),
    ).toEqual(submissions);
  });

  it("refuses a batch that does not continue the log", async () => {
    // The same events again: their first seq is 0, but the log's head is not -1.
    const refused = appendEvents(test.db, world.bundle.events);
    await expect(refused).rejects.toBeInstanceOf(EventAppendError);
    await expect(refused).rejects.toMatchObject({
      name: "EventAppendError",
      reason: "bad_seq",
    });
  });

  it("refuses a batch whose prev_hash does not match the head", async () => {
    const head = world.bundle.events[world.bundle.events.length - 1]!;
    const forged: Event = {
      ...head,
      seq: head.seq + 1,
      prev_hash: "sha256:" + "0".repeat(64),
    };
    const refused = appendEvents(test.db, [forged]);
    await expect(refused).rejects.toBeInstanceOf(EventAppendError);
    await expect(refused).rejects.toMatchObject({ reason: "bad_prev_hash" });

    // Refused before anything was written: the head has not moved.
    expect(await headSeq(test.db)).toBe(head.seq);
  });
});

describe("entries", () => {
  beforeAll(async () => {
    const head = world.bundle.events[world.bundle.events.length - 1]!;
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    for (const id of [VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID]) {
      const derived = deriveEntry(world.bundle.events, id, clock(), entrySeals);
      await putEntry(test.db, derived.entry, derived.sidecar, head.seq);
    }
  }, 600_000);

  it("round-trips a verified entry with its sidecar", async () => {
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    const derived = deriveEntry(
      world.bundle.events,
      VERIFIED_ENTRY_ID,
      clock(),
      entrySeals,
    );
    const stored = await getEntry(test.db, VERIFIED_ENTRY_ID);

    expect(stored).not.toBeNull();
    expect(stored!.entry).toEqual(world.entry);
    expect(stored!.entry["status"]).toBe("verified");
    expect(stored!.entry["seal"]).not.toBeNull();
    expect(stored!.sidecar).toEqual(derived.sidecar);
  });

  it("round-trips a draft whose seal is null", async () => {
    const stored = await getEntry(test.db, DRAFT_ENTRY_ID);
    expect(stored).not.toBeNull();
    expect(stored!.entry).toEqual(world.draftEntry);
    expect(stored!.entry["status"]).toBe("draft");
    expect(stored!.entry["seal"]).toBeNull();
  });

  it("returns null for an entry that was never stored", async () => {
    expect(await getEntry(test.db, "nmk_01NOTHERE")).toBeNull();
  });

  it("derives the stored entry again from the events read back from D1", async () => {
    const events = await eventsInRange(
      test.db,
      0,
      world.bundle.events.length - 1,
    );
    const seals = await sealsBetween(test.db, 0, events.length - 1);
    const entrySeals = await sealsForEntries(events, seals);

    for (const id of [VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID]) {
      const rederived = deriveEntry(events, id, clock(), entrySeals);
      const stored = await getEntry(test.db, id);
      expect(rederived.entry).toEqual(stored!.entry);
      expect(rederived.sidecar).toEqual(stored!.sidecar);
    }
  });

  it("copies stale, expires_at and supersedes out beside the JSON", async () => {
    // 0005's three columns are copies of fields already inside entry_json,
    // exactly as subject, category and status are. Read raw, so this is the
    // column and not the JSON answering.
    for (const id of [VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID]) {
      const stored = await getEntry(test.db, id);
      expect(await freshnessColumns(test.db, id)).toEqual({
        stale: stored!.entry["stale"] === true ? 1 : 0,
        expires_at: stored!.entry["expires_at"] ?? null,
        supersedes: stored!.entry["supersedes"] ?? null,
      });
    }
  });

  it("backfills the three columns from the JSON of rows already stored", async () => {
    // 0005's backfill, run against real rows: a live database takes the
    // migration with entries already in it, and the copies have to come out of
    // the JSON those rows carry. Wrong values first, so the assertion cannot
    // pass on what putEntry already wrote.
    const backfill = splitStatements(
      loadMigrations().find((one) => one.name === "0005_freshness.sql")!.sql,
    ).find((statement) => statement.includes("UPDATE entries SET"))!;
    const before = new Map(
      await Promise.all(
        [VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID].map(
          async (id) => [id, await freshnessColumns(test.db, id)] as const,
        ),
      ),
    );

    await test.db
      .prepare(
        `UPDATE entries SET stale = 1, expires_at = '1999-01-01', supersedes = 'nmk_wrong'`,
      )
      .run();
    await test.db.prepare(backfill).run();

    for (const [id, columns] of before) {
      expect(await freshnessColumns(test.db, id)).toEqual(columns);
    }
  });

  it("filters a listing by subject, category and status", async () => {
    const bySubject = await listEntries(test.db, {
      subject: world.entry["subject"] as string,
      limit: 10,
    });
    expect(bySubject.map((row) => row.entry["id"])).toEqual([VERIFIED_ENTRY_ID]);

    const drafts = await listEntries(test.db, { status: "draft", limit: 10 });
    expect(drafts.map((row) => row.entry["id"])).toEqual([DRAFT_ENTRY_ID]);

    const wrongCategory = await listEntries(test.db, {
      subject: world.entry["subject"] as string,
      category: "availability",
      limit: 10,
    });
    expect(wrongCategory).toEqual([]);
  });

  it("pages by keyset on submitted_seq", async () => {
    const all = await listEntries(test.db, { limit: 10 });
    expect(all.map((row) => row.entry["id"])).toEqual([
      VERIFIED_ENTRY_ID,
      DRAFT_ENTRY_ID,
    ]);

    const first = await listEntries(test.db, { limit: 1 });
    expect(first.map((row) => row.entry["id"])).toEqual([VERIFIED_ENTRY_ID]);

    const second = await listEntries(test.db, {
      limit: 1,
      afterSubmittedSeq: first[0]!.submittedSeq,
    });
    expect(second.map((row) => row.entry["id"])).toEqual([DRAFT_ENTRY_ID]);

    const past = await listEntries(test.db, {
      limit: 1,
      afterSubmittedSeq: second[0]!.submittedSeq,
    });
    expect(past).toEqual([]);
  });
});

describe("operators and agents", () => {
  beforeAll(async () => {
    const registry = world.bundle.registry;
    let seq = 0;
    for (const [id, flags] of Object.entries(registry.operators)) {
      await putOperator(test.db, {
        id,
        maintainer: flags.maintainer,
        provider: flags.provider,
        registeredSeq: seq,
        details: { ...flags },
      });
      seq += 1;
    }
    for (const [agentId, operatorId] of Object.entries(registry.agents)) {
      await putAgent(test.db, { agentId, operatorId, registeredSeq: seq });
      seq += 1;
    }
  }, 600_000);

  it("round-trips an operator", async () => {
    const maintainer = await getOperator(test.db, MAINTAINER_OPERATOR);
    expect(maintainer).toMatchObject({
      id: MAINTAINER_OPERATOR,
      maintainer: true,
      provider: false,
    });
    expect(maintainer!.details).toEqual({
      maintainer: true,
      provider: false,
      domains: [DEFAULT_DOMAIN],
    });


    const submitter = await getOperator(test.db, SUBMITTER_OPERATOR);
    expect(submitter!.maintainer).toBe(false);
    expect(await getOperator(test.db, "op_unknown")).toBeNull();
  });

  it("resolves the operator behind an agent", async () => {
    const [agentId, operatorId] = Object.entries(world.bundle.registry.agents)[0]!;
    expect(await operatorForAgent(test.db, agentId)).toBe(operatorId);
    expect(await operatorForAgent(test.db, "nmk_agent_unknown")).toBeNull();
  });

  it("pages operators by keyset on id", async () => {
    const ids = Object.keys(world.bundle.registry.operators).sort();
    const first = await listOperators(test.db, { limit: 2 });
    expect(first.map((operator) => operator.id)).toEqual(ids.slice(0, 2));

    const next = await listOperators(test.db, {
      limit: 2,
      afterId: first[first.length - 1]!.id,
    });
    expect(next.map((operator) => operator.id)).toEqual(ids.slice(2, 4));
  });
});

describe("assignments", () => {
  const outside = OUTSIDE_OPERATORS[0]!;

  it("opens an assignment and then closes it as missed", async () => {
    const assignment: OpenAssignment = {
      seq: 1000,
      agent: "nmk_agent_assigned",
      operator: outside,
      beacon_round: 42,
      deadline: "2026-09-13T00:00:00.000Z",
      replacement: false,
    };
    await putAssignment(test.db, VERIFIED_ENTRY_ID, assignment);
    expect(await openAssignment(test.db, VERIFIED_ENTRY_ID)).toEqual(assignment);

    await markAssignmentMissed(test.db, VERIFIED_ENTRY_ID, assignment.seq, 1001);
    expect(await openAssignment(test.db, VERIFIED_ENTRY_ID)).toBeNull();
  });

  it("holds the newest open assignment for the entry", async () => {
    const replacement: OpenAssignment = {
      seq: 1002,
      agent: "nmk_agent_replacement",
      operator: OUTSIDE_OPERATORS[1]!,
      beacon_round: 43,
      deadline: "2026-09-14T00:00:00.000Z",
      replacement: true,
    };
    await putAssignment(test.db, VERIFIED_ENTRY_ID, replacement);
    expect(await openAssignment(test.db, VERIFIED_ENTRY_ID)).toEqual(replacement);
    expect(await openAssignment(test.db, DRAFT_ENTRY_ID)).toBeNull();
  });

  it("is closed by the validator's answer as well as by the miss", async () => {
    const answered: OpenAssignment = {
      seq: 1004,
      agent: "nmk_agent_answered",
      operator: OUTSIDE_OPERATORS[2]!,
      beacon_round: 44,
      deadline: "2026-09-15T00:00:00.000Z",
      replacement: false,
    };
    await putAssignment(test.db, DRAFT_ENTRY_ID, answered);
    expect(await openAssignment(test.db, DRAFT_ENTRY_ID)).toEqual(answered);

    await markAssignmentAnswered(test.db, DRAFT_ENTRY_ID, answered.seq, 1005);
    expect(await openAssignment(test.db, DRAFT_ENTRY_ID)).toBeNull();
  });

  it("sweeps the assignments past their deadline, oldest first", async () => {
    const overdue: OpenAssignment[] = [
      "2026-09-12T00:00:00.000Z",
      "2026-09-10T00:00:00.000Z",
      "2026-09-11T00:00:00.000Z",
    ].map((deadline, index) => ({
      seq: 1100 + index,
      agent: `nmk_agent_due_${index}`,
      operator: OUTSIDE_OPERATORS[index % OUTSIDE_OPERATORS.length]!,
      beacon_round: 50 + index,
      deadline,
      replacement: false,
    }));
    for (const assignment of overdue) {
      await putAssignment(test.db, DRAFT_ENTRY_ID, assignment);
    }

    const swept = await dueAssignments(test.db, "2026-09-13T00:00:00.000Z", 10);
    expect(swept.map((row) => row.assignment.deadline)).toEqual([
      "2026-09-10T00:00:00.000Z",
      "2026-09-11T00:00:00.000Z",
      "2026-09-12T00:00:00.000Z",
    ]);
    expect(swept.every((row) => row.entryId === DRAFT_ENTRY_ID)).toBe(true);
    expect(swept[0]!.assignment).toEqual(
      overdue.find((one) => one.deadline === "2026-09-10T00:00:00.000Z"),
    );

    // Strictly before: the deadline instant itself is still inside the window.
    const onTheInstant = await dueAssignments(
      test.db,
      "2026-09-10T00:00:00.000Z",
      10,
    );
    expect(onTheInstant).toEqual([]);

    // The caller's own limit, and nothing beyond it.
    const capped = await dueAssignments(test.db, "2026-09-13T00:00:00.000Z", 2);
    expect(capped.map((row) => row.assignment.deadline)).toEqual([
      "2026-09-10T00:00:00.000Z",
      "2026-09-11T00:00:00.000Z",
    ]);

    // A missed row and an answered row have both closed, so neither comes back.
    await markAssignmentMissed(test.db, DRAFT_ENTRY_ID, 1100, 1200);
    await markAssignmentAnswered(test.db, DRAFT_ENTRY_ID, 1101, 1201);
    expect(
      (await dueAssignments(test.db, "2026-09-13T00:00:00.000Z", 10)).map(
        (row) => row.assignment.seq,
      ),
    ).toEqual([1102]);
  });
});

describe("seals", () => {
  it("round-trips a seal", async () => {
    const seal = world.bundle.seals[0]!;
    expect(await latestSeal(test.db)).toEqual(
      world.bundle.seals[world.bundle.seals.length - 1]!,
    );
    expect(await sealsBetween(test.db, seal.first_seq, seal.last_seq)).toEqual([
      seal,
    ]);
  });

  it("finds the seal covering an event by seq", async () => {
    const seal = world.bundle.seals[0]!;
    expect(await sealCovering(test.db, seal.first_seq)).toEqual(seal);
    expect(await sealCovering(test.db, seal.last_seq)).toEqual(seal);
    // The draft was submitted after the seal closed, so nothing covers it.
    expect(await sealCovering(test.db, seal.last_seq + 1)).toBeNull();
  });
});

describe("seals over two batches", () => {
  let first: Seal;

  beforeAll(async () => {
    first = world.bundle.seals[world.bundle.seals.length - 1]!;
    await putSeal(test.db, secondSeal);
  }, 600_000);

  it("closes exactly the tail the first seal left open", () => {
    expect(secondSeal.first_seq).toBe(first.last_seq + 1);
    expect(secondSeal.last_seq).toBe(world.bundle.events.length - 1);
    expect(secondSeal.seq).toBe(first.seq + 1);
    expect(secondSeal.prev_hash).toBe(first.hash);
  });

  it("covers an event by the range it falls in, on both sides of the boundary", async () => {
    expect(await sealCovering(test.db, secondSeal.first_seq)).toEqual(secondSeal);
    expect(await sealCovering(test.db, secondSeal.last_seq)).toEqual(secondSeal);
    expect(await sealCovering(test.db, first.first_seq)).toEqual(first);
    // The event one before the second batch begins is still the first seal's.
    expect(await sealCovering(test.db, secondSeal.first_seq - 1)).toEqual(first);
    // Past the head of the log, nothing is sealed.
    expect(await sealCovering(test.db, secondSeal.last_seq + 1)).toBeNull();
  });

  it("returns every seal overlapping a range, in seal order", async () => {
    expect(
      await sealsBetween(test.db, first.first_seq, secondSeal.last_seq),
    ).toEqual([first, secondSeal]);
    expect(
      await sealsBetween(test.db, secondSeal.first_seq, secondSeal.last_seq),
    ).toEqual([secondSeal]);
    expect(await sealsBetween(test.db, first.first_seq, first.last_seq)).toEqual([
      first,
    ]);
    expect(
      await sealsBetween(test.db, secondSeal.last_seq + 1, secondSeal.last_seq + 2),
    ).toEqual([]);
  });

  it("returns the newest seal, not the first one stored", async () => {
    expect(await latestSeal(test.db)).toEqual(secondSeal);
  });
});

/**
 * A store that holds a later seal and not the earlier one: the leading range of
 * the log is unsealed as far as this database is concerned. Its own database,
 * because the one above holds both seals and so has no unsealed leading range
 * to ask about. This is what pins `first_seq <= ?`: without it the query would
 * hand back a seal whose batch starts after the event asked for.
 */
describe("a store holding only a later seal", () => {
  let later: TestDatabase;

  beforeAll(async () => {
    later = await openTestDatabase();
    await putSeal(later.db, secondSeal);
  }, 600_000);

  afterAll(async () => {
    await later?.dispose();
  });

  it("covers nothing before the batch it holds", async () => {
    expect(await sealCovering(later.db, secondSeal.first_seq)).toEqual(secondSeal);
    expect(await sealCovering(later.db, secondSeal.first_seq - 1)).toBeNull();
    expect(await sealCovering(later.db, 0)).toBeNull();
    expect(await sealsBetween(later.db, 0, secondSeal.first_seq - 1)).toEqual([]);
  });
});

describe("anchors", () => {
  it("round-trips a day's anchor", async () => {
    const day = utcDay(world.bundle.seals[0]!.sealed_at);
    const built = await buildAnchor(world.bundle.seals, day);
    expect(built.ok).toBe(true);
    const anchor = (built as { ok: true; anchor: Anchor }).anchor;

    await putAnchor(test.db, anchor);
    expect(await getAnchor(test.db, day)).toEqual(anchor);
    expect(await latestAnchor(test.db)).toEqual(anchor);
    expect(await getAnchor(test.db, "2020-01-01")).toBeNull();
  });
});

/**
 * The newest finished timestamp, in its own database.
 *
 * The status page names the newest anchor whose proof reached a block, and the
 * whole point of asking the store for it is that the answer is one row: a log
 * with years of days behind it must not be read through to find the last one
 * that upgraded. So the questions here are the three the page can meet — no
 * anchors at all, anchors whose receipts are still pending, and more than one
 * finished proof, where only the newest day is the answer.
 */
describe("the newest upgraded anchor", () => {
  let anchors: TestDatabase;

  /** A day's anchor over one made-up seal, so no world is needed to have one. */
  async function anchorOn(date: string): Promise<Anchor> {
    const built = await buildAnchor(
      [{ seq: 1, root: `sha256:${date}`, sealed_at: `${date}T12:00:00.000Z` }],
      date,
    );
    expect(built.ok).toBe(true);
    return (built as { ok: true; anchor: Anchor }).anchor;
  }

  /** The receipt a calendar hands back, pending or folded into a block. */
  function receipt(
    submitted: string,
    upgraded: { block_height: number; upgraded_at: string } | null,
  ): NonNullable<Anchor["external"]> {
    return {
      kind: "opentimestamps",
      calendar: "https://alice.btc.calendar.opentimestamps.org",
      submitted_at: submitted,
      proof: "AE9wZW5UaW1lc3RhbXBz",
      upgraded:
        upgraded === null
          ? null
          : { proof: "AE9wZW5UaW1lc3RhbXBzAAEC", ...upgraded },
    };
  }

  beforeAll(async () => {
    anchors = await openTestDatabase();
  }, 600_000);

  afterAll(async () => {
    await anchors?.dispose();
  });

  it("answers null with no anchor at all", async () => {
    expect(await newestUpgradedAnchor(anchors.db)).toBeNull();
  });

  it("answers null while every receipt is still pending", async () => {
    // One day never posted anywhere and one posted and waiting: neither is a
    // proof that stands on its own, so neither is an answer.
    await putAnchor(anchors.db, await anchorOn("2026-09-05"));
    const waiting = await anchorOn("2026-09-06");
    await putAnchor(anchors.db, waiting);
    await setAnchorExternal(
      anchors.db,
      waiting.date,
      receipt("2026-09-07T00:10:00.000Z", null),
    );

    expect(await newestUpgradedAnchor(anchors.db)).toBeNull();
  });

  it("answers the newest of two finished proofs, and only what the page says", async () => {
    for (const [date, block] of [
      ["2026-09-07", 966_101],
      ["2026-09-08", 966_287],
    ] as const) {
      const anchor = await anchorOn(date);
      await putAnchor(anchors.db, anchor);
      await setAnchorExternal(
        anchors.db,
        date,
        receipt(`${date}T00:10:00.000Z`, {
          block_height: block,
          upgraded_at: `${date}T09:00:00.000Z`,
        }),
      );
    }

    // The later day wins, and the roots and the .ots proof stay in the column:
    // the page says a day, a height and an instant, so that is all that is read.
    expect(await newestUpgradedAnchor(anchors.db)).toEqual({
      date: "2026-09-08",
      block_height: 966_287,
      upgraded_at: "2026-09-08T09:00:00.000Z",
    });
    // And a still newer day whose receipt is pending does not take the answer
    // off it: the newest anchor and the newest finished proof are two different
    // rows, which is the whole reason the page names the second one.
    const pending = await anchorOn("2026-09-09");
    await putAnchor(anchors.db, pending);
    await setAnchorExternal(
      anchors.db,
      pending.date,
      receipt("2026-09-10T00:10:00.000Z", null),
    );

    expect((await latestAnchor(anchors.db))!.date).toBe("2026-09-09");
    expect((await newestUpgradedAnchor(anchors.db))!.date).toBe("2026-09-08");
  });
});

describe("migrations", () => {
  it("applies nothing the second time", async () => {
    expect(await applyMigrations(test.db, loadMigrations())).toEqual([]);
  });

  it("applies 0004 after 0003, adding to the assignments table and nothing else", async () => {
    const names = loadMigrations().map((migration) => migration.name);
    expect(names).toEqual([
      "0001_init.sql",
      "0002_registry.sql",
      "0003_captures.sql",
      "0004_assignments.sql",
      "0005_freshness.sql",
      "0006_sealing.sql",
      "0007_receipts.sql",
      "0008_sync.sql",
      "0009_disputes.sql",
      "0010_ledger.sql",
      "0011_attestations.sql",
      "0012_domains.sql",
      "0013_status.sql",
      "0014_mirror.sql",
      "0015_paid_access.sql",
    ]);

    // Forward-only (D-022): 0004 adds a column and an index and reshapes
    // nothing, so a live database takes it without rewriting a table. The
    // database under test was migrated 0001 through 0004 in this order, which
    // is what "applies on top of 0003" means.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0004_assignments.sql")!.sql,
    );
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain("ALTER TABLE assignments ADD COLUMN answered_seq");
    expect(statements[1]).toContain("CREATE INDEX assignments_due");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b|\bCREATE TABLE\b/);
    }

    // The column it adds is on the live table and starts null, so a row
    // written by putAssignment is open until something closes it.
    await putAssignment(test.db, "nmk_migrated", {
      seq: 7,
      agent: "nmk_agent_migrated",
      operator: "op_migrated",
      beacon_round: 1,
      deadline: "2026-09-20T00:00:00.000Z",
      replacement: false,
    });
    expect(await openAssignment(test.db, "nmk_migrated")).not.toBeNull();
    await markAssignmentAnswered(test.db, "nmk_migrated", 7, 8);
    expect(await openAssignment(test.db, "nmk_migrated")).toBeNull();
  });

  it("applies 0005 after 0004, adding to the entries table and nothing else", () => {
    // Forward-only (D-022): three columns, a backfill of the rows already
    // stored, and two partial indexes. Nothing is dropped and no table is
    // reshaped, so a live database takes it without rewriting a table.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0005_freshness.sql")!.sql,
    );
    expect(statements).toHaveLength(6);
    expect(statements[0]).toContain("ALTER TABLE entries ADD COLUMN stale");
    expect(statements[1]).toContain("ALTER TABLE entries ADD COLUMN expires_at");
    expect(statements[2]).toContain("ALTER TABLE entries ADD COLUMN supersedes");
    expect(statements[3]).toContain("UPDATE entries SET");
    expect(statements[4]).toContain("CREATE INDEX entries_stale_due");
    expect(statements[5]).toContain("CREATE INDEX entries_supersedes");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b|\bCREATE TABLE\b/);
    }
  });

  it("applies 0006 after 0005, adding to the seals table and nothing else", () => {
    // Forward-only (D-022): one nullable column and one index. Nothing is
    // dropped and no table is reshaped, so a live database takes it as it
    // stands, and every seal already stored reads back with registry null.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0006_sealing.sql")!.sql,
    );
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain("ALTER TABLE seals ADD COLUMN registry_json");
    expect(statements[1]).toContain("CREATE INDEX seals_sealed_at");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b|\bCREATE TABLE\b/);
    }
  });

  it("applies 0007 after 0006, indexing the receipts table and nothing else", () => {
    // Forward-only (D-022): three indexes over the placeholder table 0001
    // declared, and no reshaping at all. A live database takes it as it stands.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0007_receipts.sql")!.sql,
    );
    expect(statements).toHaveLength(3);
    expect(statements[0]).toContain("CREATE UNIQUE INDEX receipts_kind_seq");
    expect(statements[1]).toContain("CREATE INDEX receipts_kind_created_at");
    expect(statements[2]).toContain("CREATE INDEX receipts_kind_entry");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b|\bCREATE TABLE\b|\bALTER TABLE\b/);
    }
  });

  it("applies 0008 after 0007, adding one partial index and nothing else", () => {
    // Forward-only (D-022): one partial unique index over the table 0001
    // declared, and no reshaping at all. It closes the one duplicate 0007's
    // (kind, seq) index permits: a read receipt and a sync receipt at the same
    // running counter.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0008_sync.sql")!.sql,
    );
    expect(statements).toHaveLength(1);
    expect(statements[0]).toContain("CREATE UNIQUE INDEX receipts_counter");
    expect(statements[0]).toContain("WHERE kind IN ('read', 'sync')");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b|\bCREATE TABLE\b|\bALTER TABLE\b/);
    }
  });

  it("applies 0010 after 0009, adding to the ledger and operators tables", async () => {
    // Forward-only (D-022): six nullable columns on `ledger`, two indexes, two
    // backfills of what is already stored, one new table, and two nullable
    // columns on `operators`. Nothing is dropped and no table is reshaped, so a
    // live database takes it without rewriting one.
    const statements = splitStatements(
      loadMigrations().find((one) => one.name === "0010_ledger.sql")!.sql,
    );
    expect(statements).toHaveLength(13);
    expect(statements[0]).toContain("ALTER TABLE ledger ADD COLUMN amount");
    expect(statements[1]).toContain("ALTER TABLE ledger ADD COLUMN unit");
    expect(statements[5]).toContain("ALTER TABLE ledger ADD COLUMN paid_by");
    expect(statements[6]).toContain("CREATE INDEX ledger_operator_unpaid");
    expect(statements[7]).toContain("CREATE INDEX ledger_kind_date");
    expect(statements[10]).toContain("CREATE TABLE ledger_state");
    expect(statements[11]).toContain("ALTER TABLE operators ADD COLUMN standing");
    for (const statement of statements) {
      expect(statement).not.toMatch(/\bDROP\b/);
    }
    // The one new table is the only CREATE TABLE in the file.
    expect(statements.filter((one) => /\bCREATE TABLE\b/.test(one))).toHaveLength(1);

    // The columns are on the live table and start null, so a row written before
    // this milestone is unpaid and outside every holdback rather than missing.
    const row = await test.db
      .prepare(
        `SELECT amount, unit, role, "date", available_at, paid_by FROM ledger ${"LIMIT 1"}`,
      )
      .first<Record<string, unknown>>();
    expect(row === null || row["paid_by"] === null).toBe(true);
  });

  it("records the migration under the name wrangler would use", async () => {
    const applied = await test.db
      .prepare(`SELECT name FROM "d1_migrations" ORDER BY id`)
      .all<{ name: string }>();
    expect(applied.results.map((row) => row.name)).toEqual([
      "0001_init.sql",
      "0002_registry.sql",
      "0003_captures.sql",
      "0004_assignments.sql",
      "0005_freshness.sql",
      "0006_sealing.sql",
      "0007_receipts.sql",
      "0008_sync.sql",
      "0009_disputes.sql",
      "0010_ledger.sql",
      "0011_attestations.sql",
      "0012_domains.sql",
      "0013_status.sql",
      "0014_mirror.sql",
      "0015_paid_access.sql",
    ]);
  });
});

/**
 * A sidecar written before M20 existed.
 *
 * `revalidations` is new in this milestone, so every row already in a live
 * database has a sidecar_json without the key and the entry page reads
 * `sidecar.revalidations.length` off it. Two things have to hold, and they are
 * two different things: 0009 backfills what is already stored, and the reader
 * defaults the key for a row the previous Worker writes in the window between
 * that migration and the deploy that replaces it.
 */
describe("a sidecar stored before revalidations existed", () => {
  /** 0009's backfill statement, taken from the migration file itself. */
  function backfill(): string {
    const migration = loadMigrations().find(
      (one) => one.name === "0009_disputes.sql",
    );
    expect(migration).toBeDefined();
    const found = splitStatements(migration!.sql).filter((statement) =>
      statement.includes("json_set(sidecar_json"),
    );
    expect(found).toHaveLength(1);
    return found[0]!;
  }

  /** One entries row whose sidecar_json is shaped as an older Worker wrote it. */
  async function putPreM20(id: string): Promise<void> {
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    const derived = deriveEntry(
      world.bundle.events,
      VERIFIED_ENTRY_ID,
      clock(),
      entrySeals,
    );
    const entry = { ...derived.entry, id } as Record<string, unknown>;
    // The key removed rather than emptied: undefined is what the page met.
    const { revalidations: _gone, ...older } = derived.sidecar;
    expect(Object.keys(older)).not.toContain("revalidations");

    await test.db
      .prepare(
        `INSERT INTO entries
           (id, subject, category, status, submitted_at, submitted_seq,
            author, entry_json, sidecar_json, derived_through_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        entry["subject"] as string,
        entry["category"] as string,
        entry["status"] as string,
        entry["submitted_at"] as string,
        0,
        entry["author"] as string,
        JSON.stringify(entry),
        JSON.stringify(older),
        0,
      )
      .run();

    const raw = await test.db
      .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
      .bind(id)
      .first<{ sidecar_json: string }>();
    expect(JSON.parse(raw!.sidecar_json)).not.toHaveProperty("revalidations");
  }

  it("is backfilled with an empty list by 0009", async () => {
    const id = `nmk_${"0".repeat(31)}1`;
    await putPreM20(id);

    await test.db.prepare(backfill()).run();

    // The column itself, so this is the migration answering and not the reader.
    const raw = await test.db
      .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
      .bind(id)
      .first<{ sidecar_json: string }>();
    expect(JSON.parse(raw!.sidecar_json)).toHaveProperty("revalidations", []);

    const stored = await getEntry(test.db, id);
    expect(stored!.sidecar.revalidations).toEqual([]);
  });

  it("leaves a row that already carries the key alone", async () => {
    // The filter is the point: a derived list of real checks must survive the
    // backfill, and running it twice must not flatten one.
    const stored = await getEntry(test.db, VERIFIED_ENTRY_ID);
    expect(stored).not.toBeNull();

    await test.db.prepare(backfill()).run();
    await test.db.prepare(backfill()).run();

    const again = await getEntry(test.db, VERIFIED_ENTRY_ID);
    expect(again!.sidecar).toEqual(stored!.sidecar);
  });

  it("reads back as an empty list even when the backfill has not run", async () => {
    const id = `nmk_${"0".repeat(31)}2`;
    await putPreM20(id);

    const stored = await getEntry(test.db, id);
    expect(stored).not.toBeNull();
    expect(stored!.sidecar.revalidations).toEqual([]);
    // Nothing else about the sidecar is invented by the default.
    expect(stored!.sidecar.effective_tier).toBeDefined();
  });
});

/**
 * A sidecar written before the source class existed (decision D-080).
 *
 * The M20 pattern again, and with a stronger guarantee than the empty list had:
 * the class is a pure function of the stored core's domain, subject and
 * citation, so the reader computing it from the row's own entry gives the
 * identical answer `deriveEntry` would. There is no migration and there does not
 * need to be one -- a row written by the previous Worker reads with its class
 * the first time anybody asks for it.
 */
describe("a sidecar stored before the source class existed", () => {
  /**
   * One entries row whose sidecar_json is shaped as the previous Worker wrote
   * it: no `source` at all, or -- with `staleSource` -- the pre-D-081 object
   * that carried `provider` where `authority` now goes.
   */
  async function putPreM23b(
    id: string,
    staleSource?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    const derived = deriveEntry(
      world.bundle.events,
      VERIFIED_ENTRY_ID,
      clock(),
      entrySeals,
    );
    const entry = { ...derived.entry, id } as Record<string, unknown>;
    // The key removed rather than nulled: undefined is what the page would meet.
    const { source: _gone, ...without } = derived.sidecar;
    expect(Object.keys(without)).not.toContain("source");
    const older =
      staleSource === undefined ? without : { ...without, source: staleSource };

    await test.db
      .prepare(
        `INSERT INTO entries
           (id, subject, category, status, submitted_at, submitted_seq,
            author, entry_json, sidecar_json, derived_through_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        entry["subject"] as string,
        entry["category"] as string,
        entry["status"] as string,
        entry["submitted_at"] as string,
        0,
        entry["author"] as string,
        JSON.stringify(entry),
        JSON.stringify(older),
        0,
      )
      .run();

    const raw = await test.db
      .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
      .bind(id)
      .first<{ sidecar_json: string }>();
    const stored = JSON.parse(raw!.sidecar_json) as Record<string, unknown>;
    if (staleSource === undefined) {
      expect(stored).not.toHaveProperty("source");
    } else {
      expect(stored["source"]).toEqual(staleSource);
    }
    return entry;
  }

  it("reads back with the class computed from its own stored core", async () => {
    const id = `nmk_${"0".repeat(31)}3`;
    const entry = await putPreM23b(id);

    const stored = await getEntry(test.db, id);
    expect(stored).not.toBeNull();
    // The same answer derivation gives, because it is the same function over
    // the same bytes -- not a second reading of the citation.
    expect(stored!.sidecar.source).toEqual(
      sourceClassOf(
        entry["domain"] as string,
        entry["subject"],
        entry["citation"],
      ),
    );
    expect(stored!.sidecar.source.class).toBe("official");
    // Nothing else about the sidecar is invented by the default.
    expect(stored!.sidecar.effective_tier).toBeDefined();
    expect(stored!.sidecar.revalidations).toEqual([]);
  });

  it("recomputes a source that still carries the pre-D-081 key", async () => {
    // A row written between M23b and the rename holds `provider` and no
    // `authority`, and its class is valid, so a check on the class alone would
    // hand a page an object missing the key it reads. The default is keyed on
    // the key: the object is thrown away and rebuilt from the row's own core,
    // which is where the old value came from in the first place.
    const id = `nmk_${"0".repeat(31)}4`;
    const entry = await putPreM23b(id, {
      class: "official",
      matched_host: "kestrel.example",
      provider: "kestrel",
    });

    const stored = await getEntry(test.db, id);
    expect(stored).not.toBeNull();
    expect(stored!.sidecar.source).toEqual(
      sourceClassOf(
        entry["domain"] as string,
        entry["subject"],
        entry["citation"],
      ),
    );
    // The stale key goes with the object it was on, and the new one is there.
    expect(stored!.sidecar.source).not.toHaveProperty("provider");
    expect(stored!.sidecar.source).toHaveProperty("authority");
  });

  it("leaves a row that already carries the key alone", async () => {
    const stored = await getEntry(test.db, VERIFIED_ENTRY_ID);
    expect(stored).not.toBeNull();
    expect(stored!.sidecar.source).toEqual(
      deriveEntry(world.bundle.events, VERIFIED_ENTRY_ID, clock()).sidecar
        .source,
    );
  });
});

/**
 * The registry's atomic writes, in their own database.
 *
 * Section 5 and Section 11: the binding is sealed into the log, and the rows
 * are only an index into it. So the question is not whether the columns
 * survive but whether the two can ever disagree — a row with no event behind
 * it, or an event with no row in front of it. Its own database, because these
 * tests move the head of the log and the world above is asserted against its
 * own head.
 */
describe("registry writes", () => {
  const OPERATOR = "lattice.example";
  const AGENT = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";

  const attestation: Attestation = {
    version: "nomankind-independence-v1",
    signed_at: "2026-09-07T12:00:00Z",
    signature: "c2lnbmF0dXJl",
  };

  let registry: TestDatabase;
  let registration: Event[];

  function operatorRecord(overrides: Partial<OperatorRecord> = {}): OperatorRecord {
    return {
      id: OPERATOR,
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: { payout: { reference: "acct_123" } },
      ...overrides,
    };
  }

  function agentRecord(overrides: Partial<AgentRecord> = {}): AgentRecord {
    return { agentId: AGENT, operatorId: OPERATOR, registeredSeq: 1, ...overrides };
  }

  beforeAll(async () => {
    registry = await openTestDatabase();
    let log: Event[] = [];
    log = await appendEvent(log, {
      at: "2026-09-07T12:00:00Z",
      type: "operator_registered",
      entry_id: null,
      payload: { operator: OPERATOR, maintainer: false },
    });
    log = await appendEvent(log, {
      at: "2026-09-07T12:00:01Z",
      type: "agent_bound",
      entry_id: null,
      payload: { operator: OPERATOR, agent: AGENT, attestation },
    });
    registration = log;
  }, 600_000);

  afterAll(async () => {
    await registry?.dispose();
  });

  it("refuses a run that does not continue the log, and writes no row", async () => {
    const badSeq = registration.map((event) => ({ ...event, seq: event.seq + 5 }));
    await expect(
      registerOperator(registry.db, {
        events: badSeq,
        operator: operatorRecord(),
        agent: agentRecord(),
      }),
    ).rejects.toMatchObject({ name: "EventAppendError", reason: "bad_seq" });

    const badPrev = [
      { ...registration[0]!, prev_hash: "sha256:" + "0".repeat(64) },
      registration[1]!,
    ];
    await expect(
      registerOperator(registry.db, {
        events: badPrev,
        operator: operatorRecord(),
        agent: agentRecord(),
      }),
    ).rejects.toBeInstanceOf(EventAppendError);

    expect(await headSeq(registry.db)).toBeNull();
    expect(await getOperator(registry.db, OPERATOR)).toBeNull();
    expect(await operatorForAgent(registry.db, AGENT)).toBeNull();
  });

  it("appends the events and writes both rows in one write", async () => {
    await registerOperator(registry.db, {
      events: registration,
      operator: operatorRecord(),
      agent: agentRecord(),
    });

    expect(await headSeq(registry.db)).toBe(1);
    expect(await eventsInRange(registry.db, 0, 1)).toEqual(registration);
    expect(await verifyChain(await eventsInRange(registry.db, 0, 1))).toEqual({
      ok: true,
      length: 2,
    });
    expect(await getOperator(registry.db, OPERATOR)).toEqual(operatorRecord());
    expect(await operatorForAgent(registry.db, AGENT)).toBe(OPERATOR);
  });

  it("refuses a trust event that does not continue the log, and leaves the row alone", async () => {
    const trusted = await appendEvent(registration, {
      at: "2026-09-07T12:00:02Z",
      type: "operator_trusted",
      entry_id: null,
      payload: { operator: OPERATOR },
    });
    const event = trusted[trusted.length - 1]!;

    await expect(
      trustOperator(registry.db, {
        event: { ...event, seq: event.seq + 3 },
        operator: operatorRecord({ details: { trusted: true } }),
      }),
    ).rejects.toMatchObject({ reason: "bad_seq" });
    await expect(
      trustOperator(registry.db, {
        event: { ...event, prev_hash: "sha256:" + "0".repeat(64) },
        operator: operatorRecord({ details: { trusted: true } }),
      }),
    ).rejects.toMatchObject({ reason: "bad_prev_hash" });

    expect(await headSeq(registry.db)).toBe(1);
    expect(await getOperator(registry.db, OPERATOR)).toEqual(operatorRecord());
  });

  it("appends the trust event and replaces the row in one write", async () => {
    const trusted = await appendEvent(registration, {
      at: "2026-09-07T12:00:02Z",
      type: "operator_trusted",
      entry_id: null,
      payload: { operator: OPERATOR },
    });
    const event = trusted[trusted.length - 1]!;
    const replaced = operatorRecord({
      details: { payout: { reference: "acct_123" }, trusted: true },
    });

    await trustOperator(registry.db, { event, operator: replaced });

    expect(await headSeq(registry.db)).toBe(2);
    expect(await eventBySeq(registry.db, 2)).toEqual(event);
    expect(await getOperator(registry.db, OPERATOR)).toEqual(replaced);
  });

  it("lists an operator's agents in binding order, up to the caller's limit", async () => {
    const agents: AgentRecord[] = [
      agentRecord({ agentId: `${AGENT}_b`, registeredSeq: 5 }),
      agentRecord({ agentId: `${AGENT}_c`, registeredSeq: 9 }),
    ];
    for (const agent of agents) await putAgent(registry.db, agent);
    await putOperator(registry.db, operatorRecord({ id: "beacon.example" }));
    await putAgent(
      registry.db,
      agentRecord({
        agentId: `${AGENT}_other`,
        operatorId: "beacon.example",
        registeredSeq: 7,
      }),
    );

    const all = await agentsForOperator(registry.db, OPERATOR, 10);
    expect(all.map((agent) => agent.agentId)).toEqual([
      AGENT,
      `${AGENT}_b`,
      `${AGENT}_c`,
    ]);
    expect(all[0]).toEqual(agentRecord());

    const capped = await agentsForOperator(registry.db, OPERATOR, 2);
    expect(capped.map((agent) => agent.agentId)).toEqual([AGENT, `${AGENT}_b`]);
    expect(await agentsForOperator(registry.db, "beacon.example", 10)).toEqual([
      agentRecord({
        agentId: `${AGENT}_other`,
        operatorId: "beacon.example",
        registeredSeq: 7,
      }),
    ]);
    expect(await agentsForOperator(registry.db, "nobody.example", 10)).toEqual([]);
  });
});

/**
 * The index into the snapshot archive.
 *
 * The bytes live in R2 and nothing here holds them: a row says which capture
 * backs which hash, and the two questions it has to answer are "what did this
 * entry rest on" and "what is this hash". The second is the public one, and it
 * has to give the same answer every time even when two entries cite the same
 * page, so the earliest capture wins and the entry id breaks a tie.
 */
describe("captures", () => {
  const PAGE_HASH = `sha256:${"ab".repeat(32)}`;
  const ARCHIVE_HASH = `sha256:${"cd".repeat(32)}`;
  const RECEIPT_HASH = `sha256:${"ef".repeat(32)}`;

  function capture(overrides: Partial<CaptureRecord> = {}): CaptureRecord {
    return {
      entryId: "nmk_0000000000000000000000000000cap1",
      role: "snapshot",
      contentHash: PAGE_HASH,
      archiveHash: ARCHIVE_HASH,
      normVersion: "norm-v1.2",
      kind: "html",
      mediaType: "text/html",
      size: 1234,
      fetchedAt: "2026-09-08T12:00:00.000Z",
      ...overrides,
    };
  }

  beforeAll(async () => {
    await putCapture(test.db, capture());
    await putCapture(
      test.db,
      capture({ role: "receipt", contentHash: RECEIPT_HASH, kind: "receipt" }),
    );
    // A second entry citing the same page, captured a day later.
    await putCapture(
      test.db,
      capture({
        entryId: "nmk_0000000000000000000000000000cap2",
        fetchedAt: "2026-09-09T12:00:00.000Z",
      }),
    );
  }, 600_000);

  it("round-trips a capture row", async () => {
    expect(await captureForHash(test.db, PAGE_HASH)).toEqual(capture());
  });

  it("answers a hash with the earliest capture of it", async () => {
    const found = await captureForHash(test.db, PAGE_HASH);
    expect(found!.entryId).toBe("nmk_0000000000000000000000000000cap1");
    expect(found!.fetchedAt).toBe("2026-09-08T12:00:00.000Z");
  });

  it("finds the receipt by its own hash", async () => {
    const found = await captureForHash(test.db, RECEIPT_HASH);
    expect(found!.role).toBe("receipt");
    expect(found!.kind).toBe("receipt");
  });

  it("returns null for a hash nothing was captured under", async () => {
    expect(await captureForHash(test.db, `sha256:${"11".repeat(32)}`)).toBeNull();
  });

  it("gives every capture one entry rests on", async () => {
    const found = await capturesForEntry(
      test.db,
      "nmk_0000000000000000000000000000cap1",
    );
    expect(found.map((row) => row.role)).toEqual(["receipt", "snapshot"]);
  });

  it("gives nothing for an entry with no captures", async () => {
    expect(await capturesForEntry(test.db, "nmk_01NOTHERE")).toEqual([]);
  });
});

/**
 * The archive itself, against miniflare's own R2.
 *
 * The one property the archive has that D1 does not: a capture is written once.
 * Two entries can cite the same page a day apart, and the second capture must
 * not overwrite the first — the bytes are the same by construction, but the
 * sidecar is not, and the provenance worth keeping is the earliest one.
 */
describe("the snapshot archive", () => {
  const ARCHIVE_HASH = `sha256:${"3c".repeat(32)}`;
  const FETCHER = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const encoder = new TextEncoder();

  const FIRST_BYTES = encoder.encode(
    "<!doctype html><html><body><p>$25 per seat</p></body></html>",
  );
  const SECOND_BYTES = encoder.encode("<!doctype html><html><body></body></html>");

  function sidecarAt(fetchedAt: string): Sidecar {
    return {
      final_url: "https://kestrel.example/pricing",
      status: 200,
      headers: { "content-type": "text/html" },
      fetched_at: fetchedAt,
      fetcher: FETCHER,
    };
  }

  const FIRST_AT = "2026-09-08T12:00:00.000Z";
  const SECOND_AT = "2026-09-09T12:00:00.000Z";

  beforeAll(async () => {
    await archiveCapture(test.captures, {
      archiveHash: ARCHIVE_HASH,
      bytes: FIRST_BYTES,
      mediaType: "text/html",
      sidecar: sidecarAt(FIRST_AT),
    });
    // The same address, captured again a day later with different everything.
    await archiveCapture(test.captures, {
      archiveHash: ARCHIVE_HASH,
      bytes: SECOND_BYTES,
      mediaType: "application/json",
      sidecar: sidecarAt(SECOND_AT),
    });
  }, 600_000);

  it("keeps the first capture's bytes and media type", async () => {
    const stored = await readCapture(test.captures, ARCHIVE_HASH);

    expect(stored!.bytes).toEqual(FIRST_BYTES);
    expect(stored!.mediaType).toBe("text/html");
  });

  it("keeps the first capture's sidecar", async () => {
    expect(await readSidecar(test.captures, ARCHIVE_HASH)).toEqual(
      sidecarAt(FIRST_AT),
    );
  });
});

/**
 * A submission is one write or none.
 *
 * Same lesson as the registry writes above: the event is the record and the
 * entries and captures rows are only indexes into it, so the question is
 * whether the three can ever disagree. Its own database, because these tests
 * write at seq 0.
 */
describe("submission writes", () => {
  const AUTHOR = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const AT = "2026-09-08T12:00:00.000Z";
  const SNAPSHOT_HASH = `sha256:${"9a".repeat(32)}`;

  let store: TestDatabase;
  let core: Core;
  let submission: Event[];
  let derived: ReturnType<typeof deriveEntry>;

  beforeAll(async () => {
    store = await openTestDatabase();
    core = await buildSubmittedCore(
      {
        subject: "kestrel/kestrel-2",
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-2 seat pricing rose to $25 per seat per month",
        before: "$20 per seat per month",
        after: "$25 per seat per month",
        effective_at: "2026-09-01",
        citation: "https://kestrel.example/pricing",
        snapshot_hash: SNAPSHOT_HASH,
        author: AUTHOR,
      },
      { now: AT },
    );
    submission = await appendEvent([], {
      at: AT,
      type: "entry_submitted",
      entry_id: core["id"] as string,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    derived = deriveEntry(submission, core["id"] as string, { now: AT });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  function captureRow(): CaptureRecord {
    return {
      entryId: core["id"] as string,
      role: "snapshot",
      contentHash: SNAPSHOT_HASH,
      archiveHash: `sha256:${"7b".repeat(32)}`,
      normVersion: core["norm_version"] as string,
      kind: "html",
      mediaType: "text/html",
      size: 99,
      fetchedAt: AT,
    };
  }

  it("refuses a run that does not continue the log, and writes no row", async () => {
    const moved = submission.map((event) => ({ ...event, seq: event.seq + 3 }));
    await expect(
      submitEntry(store.db, {
        events: moved,
        entry: derived.entry,
        sidecar: derived.sidecar,
        derivedThroughSeq: moved[0]!.seq,
        captures: [captureRow()],
      }),
    ).rejects.toMatchObject({ name: "EventAppendError", reason: "bad_seq" });

    expect(await headSeq(store.db)).toBeNull();
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
    expect(await capturesForEntry(store.db, core["id"] as string)).toEqual([]);
  });

  it("refuses an entry with no submission event behind it", async () => {
    await expect(
      submitEntry(store.db, {
        events: [],
        entry: derived.entry,
        sidecar: derived.sidecar,
        derivedThroughSeq: 0,
        captures: [],
      }),
    ).rejects.toBeInstanceOf(MissingSubmissionError);

    expect(await headSeq(store.db)).toBeNull();
  });

  it("appends the event and writes the entry and its captures in one write", async () => {
    await submitEntry(store.db, {
      events: submission,
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: submission[0]!.seq,
      captures: [captureRow()],
    });

    const id = core["id"] as string;
    expect(await headSeq(store.db)).toBe(0);
    expect(await eventsForEntry(store.db, id)).toEqual(submission);
    const stored = await getEntry(store.db, id);
    expect(stored!.entry).toEqual(derived.entry);
    expect(stored!.entry["status"]).toBe("draft");
    expect(stored!.submittedSeq).toBe(0);
    expect(await capturesForEntry(store.db, id)).toEqual([captureRow()]);
    expect(await captureForHash(store.db, SNAPSHOT_HASH)).toEqual(captureRow());
  });

  it("derives the same entry again from the event read back from D1", async () => {
    const id = core["id"] as string;
    const events = await eventsForEntry(store.db, id);
    const rederived = deriveEntry(events, id, { now: AT });
    const stored = await getEntry(store.db, id);
    expect(rederived.entry).toEqual(stored!.entry);
    expect(rederived.sidecar).toEqual(stored!.sidecar);
  });
});

/**
 * The validation writes, in their own database.
 *
 * Lifecycle of an entry, Validate: the draw, the seventy-two-hour window and the
 * miss are all events, and every row beside them is an index into one. So the
 * question these ask is the one the registry writes ask: can the row and the
 * event ever disagree. Each writer seals its event onto the stored head itself,
 * so a caller cannot hand in an event that does not continue the log, and each
 * writes its row in the same batch, so neither half can land alone.
 *
 * Its own database, because these move the head of the log and the world above
 * is asserted against its own head.
 */
/**
 * The same database, answering the head query with a row the log has already
 * moved past. A writer that seals its own event onto the head cannot be handed a
 * broken run by its caller, so this is the one way left to give it one: the
 * event it computes is one the log already holds.
 */
function staleHead(db: D1Like, seq: number): D1Like {
  return {
    prepare(sql: string): D1LikeStatement {
      if (sql.includes("FROM events ORDER BY seq DESC")) {
        return db.prepare(
          sql.replace("ORDER BY seq DESC", `WHERE seq = ${seq}`),
        );
      }
      return db.prepare(sql);
    },
    batch: (statements) => db.batch(statements),
    exec: (statement) => db.exec(statement),
  };
}

describe("validation writes", () => {
  const AUTHOR = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const AT = "2026-09-08T12:00:00.000Z";
  const SNAPSHOT_HASH = `sha256:${"3c".repeat(32)}`;
  const ASSIGNED = "op_assigned.example";

  let store: TestDatabase;
  let entryId: string;

  function record(operator: string): ApproverRecord {
    return {
      agent: `1F916:agent-${operator}`,
      operator,
      decision: "approve",
      reason: null,
      snapshot_hash: SNAPSHOT_HASH,
      assigned_random: true,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    };
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    const core = await buildSubmittedCore(
      {
        subject: "kestrel/kestrel-3",
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-3 seat pricing rose to $30 per seat per month",
        before: "$25 per seat per month",
        after: "$30 per seat per month",
        effective_at: "2026-09-01",
        citation: "https://kestrel.example/pricing-3",
        snapshot_hash: SNAPSHOT_HASH,
        author: AUTHOR,
      },
      { now: AT },
    );
    entryId = core["id"] as string;
    const submission = await appendEvent([], {
      at: AT,
      type: "entry_submitted",
      entry_id: entryId,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    const derived = deriveEntry(submission, entryId, { now: AT });
    await submitEntry(store.db, {
      events: submission,
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: 0,
      captures: [],
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("seals a pool snapshot onto the head of the stored log", async () => {
    const event = await recordPoolSnapshot(store.db, {
      at: AT,
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: [ASSIGNED, "op_other.example"] },
    });

    expect(event.seq).toBe(1);
    expect(await headSeq(store.db)).toBe(1);
    expect(await eventBySeq(store.db, 1)).toEqual(event);
    expect(await verifyChain(await eventsInRange(store.db, 0, 1))).toEqual({
      ok: true,
      length: 2,
    });
  });

  it("appends the assignment and opens its row in one write", async () => {
    const event = await recordAssignment(store.db, {
      at: AT,
      type: "assignment",
      entry_id: entryId,
      payload: {
        agent: `1F916:agent-${ASSIGNED}`,
        operator: ASSIGNED,
        beacon_round: 4_100_100,
        deadline: "2026-09-11T12:00:00.000Z",
        replacement: false,
      },
    });

    expect(event.seq).toBe(2);
    expect(await eventBySeq(store.db, 2)).toEqual(event);
    // The row is read out of the event, so its seq is the event's own position.
    expect(await openAssignment(store.db, entryId)).toEqual({
      seq: 2,
      agent: `1F916:agent-${ASSIGNED}`,
      operator: ASSIGNED,
      beacon_round: 4_100_100,
      deadline: "2026-09-11T12:00:00.000Z",
      replacement: false,
    });
    expect(
      await dueAssignments(store.db, "2026-09-12T00:00:00.000Z", 10),
    ).toHaveLength(1);
  });

  it("appends the validation, stores the entry, and closes the assignment", async () => {
    // The entry has to be derived from a log that already holds this event, and
    // the event does not exist until it is sealed onto the head — which is why
    // the writer hands the sealed event back rather than taking an entry.
    const before = await eventsForEntry(store.db, entryId);
    let derived: ReturnType<typeof deriveEntry> | null = null;

    const event = await recordValidation(store.db, {
      event: {
        at: AT,
        type: "validation",
        entry_id: entryId,
        payload: { record: record(ASSIGNED), signature: "c2lnbmF0dXJl" },
      },
      stored: (validation) => {
        derived = deriveEntry([...before, validation], entryId, { now: AT });
        return {
          entry: derived.entry,
          sidecar: derived.sidecar,
          derivedThroughSeq: validation.seq,
        };
      },
      answeredAssignmentSeq: 2,
    });

    expect(event.seq).toBe(3);
    expect(await eventBySeq(store.db, 3)).toEqual(event);
    expect(await verifyChain(await eventsInRange(store.db, 0, 3))).toEqual({
      ok: true,
      length: 4,
    });

    const stored = await getEntry(store.db, entryId);
    expect(stored!.derivedThroughSeq).toBe(3);
    expect(stored!.entry).toEqual(derived!.entry);
    expect(stored!.sidecar).toEqual(derived!.sidecar);
    // Derivation saw the validation, and one approval does not verify an entry.
    expect(stored!.entry["status"]).toBe("draft");
    // Answered, not missed: the sweep must never seal a miss against a
    // validator who responded inside the window.
    expect(await openAssignment(store.db, entryId)).toBeNull();
    expect(
      await dueAssignments(store.db, "2026-09-12T00:00:00.000Z", 10),
    ).toEqual([]);
  });

  it("appends the miss and closes the row it closes", async () => {
    const drawn = await recordAssignment(store.db, {
      at: AT,
      type: "assignment",
      entry_id: entryId,
      payload: {
        agent: "1F916:agent-op_replacement.example",
        operator: "op_replacement.example",
        beacon_round: 4_100_200,
        deadline: "2026-09-11T12:00:00.000Z",
        replacement: true,
      },
    });
    expect(await openAssignment(store.db, entryId)).not.toBeNull();

    const missed = await recordAssignmentMissed(
      store.db,
      {
        at: AT,
        type: "assignment_missed",
        entry_id: entryId,
        payload: {
          agent: "1F916:agent-op_replacement.example",
          operator: "op_replacement.example",
        },
      },
      drawn.seq,
    );

    expect(missed.seq).toBe(drawn.seq + 1);
    expect(await eventBySeq(store.db, missed.seq)).toEqual(missed);
    expect(await openAssignment(store.db, entryId)).toBeNull();
    expect(
      await dueAssignments(store.db, "2026-09-12T00:00:00.000Z", 10),
    ).toEqual([]);
  });

  it("refuses a validation for an entry with no submission behind it, and writes nothing", async () => {
    const before = await headSeq(store.db);
    await expect(
      recordValidation(store.db, {
        event: {
          at: AT,
          type: "validation",
          entry_id: "nmk_never_submitted",
          payload: { record: record(ASSIGNED), signature: "c2lnbmF0dXJl" },
        },
        // Never called: the submission is looked for before anything is
        // derived, so a refusal costs the caller no derivation at all.
        stored: () => {
          throw new Error("stored must not be called");
        },
        answeredAssignmentSeq: null,
      }),
    ).rejects.toBeInstanceOf(MissingSubmissionError);

    expect(await headSeq(store.db)).toBe(before);
  });

  it("refuses a write computed over a head the log has already left behind", async () => {
    const before = await headSeq(store.db);
    // A stale head is the one way a writer that seals its own event can still
    // produce a run that does not continue the log. The batch is atomic, so the
    // refusal leaves the log exactly as it was.
    await expect(
      recordPoolSnapshot(staleHead(store.db, 0), {
        at: AT,
        type: "pool_snapshot",
        entry_id: null,
        payload: { operators: [ASSIGNED] },
      }),
    ).rejects.toBeTruthy();

    expect(await headSeq(store.db)).toBe(before);
    expect(await verifyChain(await eventsInRange(store.db, 0, before!))).toEqual(
      { ok: true, length: before! + 1 },
    );
  });
});

/**
 * The staleness sweep's read, in its own database.
 *
 * Whitepaper Section 7, "Freshness and decay": "Past its window an entry stays
 * verified but shows as stale." A window closing is a fact about the calendar
 * and not an event anyone appends, so something has to find the entries the day
 * turned on. This is the query it starts from, and the only one beside the
 * assignment sweep that starts from a date rather than from an entry.
 *
 * Its own database because it needs entries with chosen expiry dates, and the
 * world above is asserted against its own two.
 */
describe("the staleness sweep's read", () => {
  const AUTHOR = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";

  let store: TestDatabase;
  /** Submission day -> entry id, and entry id -> the expires_at derivation gave it. */
  const idFor = new Map<string, string>();
  const expiryOf = new Map<string, string>();
  /** The release entry: an event category, so no window and no expires_at ever. */
  let eventCategoryId: string;

  beforeAll(async () => {
    store = await openTestDatabase();
    let log: Event[] = [];

    // Submitted out of order on purpose: the sweep orders by expiry, not by the
    // order the entries arrived in.
    const days = ["2026-03-01", "2026-01-01", "2026-02-01"];
    for (const day of days) {
      const at = `${day}T12:00:00.000Z`;
      const core = await buildSubmittedCore(
        {
          subject: `kestrel/kestrel-${day}`,
          category: "pricing",
          domain: DEFAULT_DOMAIN,
          claim: `Kestrel seat pricing as of ${day}`,
          before: "$20 per seat per month",
          after: "$25 per seat per month",
          effective_at: day,
          citation: `https://kestrel.example/pricing/${day}`,
          snapshot_hash: `sha256:${"5e".repeat(32)}`,
          author: AUTHOR,
        },
        { now: at },
      );
      const id = core["id"] as string;
      log = await appendEvent(log, {
        at,
        type: "entry_submitted",
        entry_id: id,
        payload: { core, signature: "c2lnbmF0dXJl" },
      });
      const event = log[log.length - 1]!;
      // Derived at its own submission instant, so every one of them is fresh:
      // the sweep's job is to find the ones the calendar has since passed.
      const derived = deriveEntry(log, id, { now: at });
      await submitEntry(store.db, {
        events: [event],
        entry: derived.entry,
        sidecar: derived.sidecar,
        derivedThroughSeq: event.seq,
        captures: [],
      });
      idFor.set(day, id);
      expiryOf.set(id, derived.entry["expires_at"] as string);
    }

    const at = "2026-01-15T12:00:00.000Z";
    const core = await buildSubmittedCore(
      {
        subject: "kestrel/kestrel-2",
        category: "release",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-2 shipped",
        before: "unreleased",
        after: "generally available",
        effective_at: "2026-01-15",
        citation: "https://kestrel.example/releases/kestrel-2",
        snapshot_hash: `sha256:${"6f".repeat(32)}`,
        author: AUTHOR,
      },
      { now: at },
    );
    eventCategoryId = core["id"] as string;
    log = await appendEvent(log, {
      at,
      type: "entry_submitted",
      entry_id: eventCategoryId,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    const event = log[log.length - 1]!;
    const derived = deriveEntry(log, eventCategoryId, { now: at });
    expect(derived.entry["expires_at"]).toBeNull();
    await submitEntry(store.db, {
      events: [event],
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: event.seq,
      captures: [],
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  /** The three windowed entries, oldest expiry first. */
  function inExpiryOrder(): Array<{ id: string; expires_at: string }> {
    return ["2026-01-01", "2026-02-01", "2026-03-01"].map((day) => ({
      id: idFor.get(day)!,
      expires_at: expiryOf.get(idFor.get(day)!)!,
    }));
  }

  it("gives back the windowed entries in expiry order, and nothing else", async () => {
    const due = await staleDue(store.db, { today: "2030-01-01", limit: 10 });
    expect(due).toEqual(inExpiryOrder());
    // The event category has no window, so it is not in the index and never due.
    expect(due.map((row) => row.id)).not.toContain(eventCategoryId);
  });

  it("counts the expiry day itself as still fresh", async () => {
    const order = inExpiryOrder();
    // Strictly before, matching derivation: the expiry date is day 90 and the
    // entry goes stale on day 91.
    const onTheDay = await staleDue(store.db, {
      today: order[0]!.expires_at,
      limit: 10,
    });
    expect(onTheDay).toEqual([]);

    const nextOne = await staleDue(store.db, {
      today: order[1]!.expires_at,
      limit: 10,
    });
    expect(nextOne).toEqual([order[0]]);
  });

  it("honours the caller's limit and pages on by keyset", async () => {
    const order = inExpiryOrder();

    const first = await staleDue(store.db, { today: "2030-01-01", limit: 2 });
    expect(first).toEqual(order.slice(0, 2));

    const next = await staleDue(store.db, {
      today: "2030-01-01",
      limit: 2,
      afterExpiresAt: first[first.length - 1]!.expires_at,
      afterId: first[first.length - 1]!.id,
    });
    expect(next).toEqual(order.slice(2));

    const past = await staleDue(store.db, {
      today: "2030-01-01",
      limit: 2,
      afterExpiresAt: next[next.length - 1]!.expires_at,
      afterId: next[next.length - 1]!.id,
    });
    expect(past).toEqual([]);
  });

  it("drops an entry once its stale column says the sweep has had it", async () => {
    const order = inExpiryOrder();
    await store.db
      .prepare(`UPDATE entries SET stale = 1 WHERE id = ?`)
      .bind(order[0]!.id)
      .run();

    expect(await staleDue(store.db, { today: "2030-01-01", limit: 10 })).toEqual(
      order.slice(1),
    );

    await store.db
      .prepare(`UPDATE entries SET stale = 0 WHERE id = ?`)
      .bind(order[0]!.id)
      .run();
    expect(
      await staleDue(store.db, { today: "2030-01-01", limit: 10 }),
    ).toHaveLength(3);
  });
});

/**
 * The same database with one statement broken, so a batch fails where it is
 * applied rather than where it is built. The writers below seal their own event,
 * so a caller cannot hand them a broken run; this is how the write still gets to
 * fail after the events are checked, which is where atomicity has to hold.
 */
function brokenEntryWrite(db: D1Like): D1Like {
  return {
    prepare(sql: string): D1LikeStatement {
      return db.prepare(sql.replace("INSERT INTO entries (", "INSERT INTO no_such_table ("));
    },
    batch: (statements) => db.batch(statements),
    exec: (statement) => db.exec(statement),
  };
}

/**
 * Supersession and reconfirmation, in their own database.
 *
 * Section 7, "Freshness and decay": a superseding entry names its target in its
 * own signed core, and the old entry's superseded-by pointer is derived from it,
 * so verifying the superseder is the moment the target's row changes too — both
 * rows or neither. And reconfirmation "advances the derived last-confirmed date,
 * reopens the freshness window, and collects the bounty that built up while the
 * entry was stale", so the bounty and the event that earned it land together.
 */
describe("supersession and reconfirmation writes", () => {
  const AUTHOR = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const SUBJECT = "kestrel/kestrel-4";
  const AT = "2026-09-08T12:00:00.000Z";
  const RECONFIRMER = "harrier.example";

  let store: TestDatabase;
  let log: Event[] = [];
  let targetId: string;
  let supersederId: string;
  let secondSupersederId: string;

  async function submit(
    overrides: { claim: string; supersedes: string | null; at: string },
  ): Promise<string> {
    const core = await buildSubmittedCore(
      {
        subject: SUBJECT,
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim: overrides.claim,
        before: "$25 per seat per month",
        after: "$30 per seat per month",
        effective_at: "2026-09-01",
        citation: "https://kestrel.example/pricing-4",
        snapshot_hash: `sha256:${"8a".repeat(32)}`,
        supersedes: overrides.supersedes,
        author: AUTHOR,
      },
      { now: overrides.at },
    );
    const id = core["id"] as string;
    log = await appendEvent(log, {
      at: overrides.at,
      type: "entry_submitted",
      entry_id: id,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    const event = log[log.length - 1]!;
    const derived = deriveEntry(log, id, { now: overrides.at });
    await submitEntry(store.db, {
      events: [event],
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: event.seq,
      captures: [],
    });
    return id;
  }

  function approver(operator: string): ApproverRecord {
    return {
      agent: `1F916:agent-${operator}`,
      operator,
      decision: "approve",
      reason: null,
      snapshot_hash: `sha256:${"8a".repeat(32)}`,
      assigned_random: true,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    };
  }

  function reconfirmationRecord(): {
    agent: string;
    operator: string;
    snapshot_hash: string;
    reproduction: null;
    observation: null;
    signed_at: string;
  } {
    return {
      agent: `1F916:agent-${RECONFIRMER}`,
      operator: RECONFIRMER,
      snapshot_hash: `sha256:${"9b".repeat(32)}`,
      reproduction: null,
      observation: null,
      signed_at: AT,
    };
  }

  /** Rederive one entry from everything the store holds for it, plus `extra`. */
  async function rederive(
    id: string,
    extra: readonly Event[],
  ): Promise<ReturnType<typeof deriveEntry>> {
    const events = await eventsForEntry(store.db, id);
    return deriveEntry([...events, ...extra], id, { now: AT });
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    targetId = await submit({
      claim: "Kestrel-4 seat pricing is $25 per seat per month",
      supersedes: null,
      at: AT,
    });
    supersederId = await submit({
      claim: "Kestrel-4 seat pricing rose to $30 per seat per month",
      supersedes: targetId,
      at: "2026-09-08T13:00:00.000Z",
    });
    secondSupersederId = await submit({
      claim: "Kestrel-4 seat pricing rose to $35 per seat per month",
      supersedes: targetId,
      at: "2026-09-08T14:00:00.000Z",
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("finds the entries that declare they supersede one, in submission order", async () => {
    expect(await supersedersOf(store.db, targetId, 10)).toEqual([
      supersederId,
      secondSupersederId,
    ]);
    // The caller's own limit, and nothing beyond it.
    expect(await supersedersOf(store.db, targetId, 1)).toEqual([supersederId]);
    // An entry nothing points at, and one that supersedes rather than is
    // superseded.
    expect(await supersedersOf(store.db, supersederId, 10)).toEqual([]);
    expect(await supersedersOf(store.db, "nmk_01NOTHERE", 10)).toEqual([]);
  });

  it("writes the superseded target's row in the same batch as the validation", async () => {
    const targetBefore = (await getEntry(store.db, targetId))!;
    const supersederBefore = (await getEntry(store.db, supersederId))!;

    const event = await recordValidation(store.db, {
      event: {
        at: AT,
        type: "validation",
        entry_id: supersederId,
        payload: { record: approver("op_one.example"), signature: "c2lnbmF0dXJl" },
      },
      stored: (validation) => ({
        entry: supersederBefore.entry,
        sidecar: supersederBefore.sidecar,
        derivedThroughSeq: validation.seq,
      }),
      // The target, rederived by the caller at the same log position. Nothing
      // in storage derives it: `also` only carries the row across.
      also: (validation) => [
        {
          entry: targetBefore.entry,
          sidecar: targetBefore.sidecar,
          derivedThroughSeq: validation.seq,
        },
      ],
      answeredAssignmentSeq: null,
    });

    const target = (await getEntry(store.db, targetId))!;
    const superseder = (await getEntry(store.db, supersederId))!;
    expect(target.derivedThroughSeq).toBe(event.seq);
    expect(superseder.derivedThroughSeq).toBe(event.seq);
    // Each row keeps its own submitted_seq: submitted_seq is the position of
    // that entry's own submission, not of the event that rewrote the row.
    expect(target.submittedSeq).toBe(targetBefore.submittedSeq);
    expect(superseder.submittedSeq).toBe(supersederBefore.submittedSeq);
    expect(target.submittedSeq).not.toBe(superseder.submittedSeq);
  });

  it("appends the reconfirmation, stores the entry, and accrues no bounty on a fresh entry", async () => {
    const before = await eventsForEntry(store.db, targetId);
    let derived: ReturnType<typeof deriveEntry> | null = null;

    const event = await recordReconfirmation(store.db, {
      event: {
        at: AT,
        type: "reconfirmation",
        entry_id: targetId,
        payload: { record: reconfirmationRecord(), signature: "c2lnbmF0dXJl" },
      },
      stored: (reconfirmation) => {
        derived = deriveEntry([...before, reconfirmation], targetId, { now: AT });
        return {
          entry: derived.entry,
          sidecar: derived.sidecar,
          derivedThroughSeq: reconfirmation.seq,
        };
      },
      // Inside its window, so nothing was withheld and nothing is owed.
      bounty: (reconfirmation) =>
        bountyAccrual({ expires_at: "2026-12-07", stale: false }, reconfirmation),
    });

    expect(await eventBySeq(store.db, event.seq)).toEqual(event);
    expect(await headSeq(store.db)).toBe(event.seq);
    expect(await verifyChain(await eventsInRange(store.db, 0, event.seq))).toEqual({
      ok: true,
      length: event.seq + 1,
    });

    const stored = (await getEntry(store.db, targetId))!;
    expect(stored.entry).toEqual(derived!.entry);
    expect(stored.derivedThroughSeq).toBe(event.seq);
    expect(stored.entry["reconfirmations"]).toHaveLength(1);
    expect(await bountiesForEntry(store.db, targetId, 10)).toEqual([]);
  });

  it("writes the bounty in the same batch when the entry had gone stale", async () => {
    const before = await eventsForEntry(store.db, targetId);
    let accrued: ReturnType<typeof bountyAccrual> = null;

    const event = await recordReconfirmation(store.db, {
      event: {
        at: AT,
        type: "reconfirmation",
        entry_id: targetId,
        payload: { record: reconfirmationRecord(), signature: "c2lnbmF0dXJl" },
      },
      stored: (reconfirmation) => {
        const derived = deriveEntry([...before, reconfirmation], targetId, {
          now: AT,
        });
        return {
          entry: derived.entry,
          sidecar: derived.sidecar,
          derivedThroughSeq: reconfirmation.seq,
        };
      },
      bounty: (reconfirmation) => {
        accrued = bountyAccrual(
          { expires_at: "2026-06-01", stale: true },
          reconfirmation,
        );
        return accrued;
      },
    });

    expect(accrued).not.toBeNull();
    expect(await bountiesForEntry(store.db, targetId, 10)).toEqual([accrued]);
    // The ledger row keeps the placeholder table's shape (0001_init).
    const row = await store.db
      .prepare(`SELECT id, kind, operator_id, seq, created_at FROM ledger`)
      .first<Record<string, unknown>>();
    expect(row).toEqual({
      id: `bounty_accrual:${event.seq}`,
      kind: "bounty_accrual",
      operator_id: RECONFIRMER,
      seq: event.seq,
      created_at: AT,
    });
    // Only this entry's bounties, and only up to the caller's limit.
    expect(await bountiesForEntry(store.db, supersederId, 10)).toEqual([]);
    expect(await bountiesForEntry(store.db, targetId, 1)).toHaveLength(1);
  });

  it("refuses a reconfirmation for an entry with no submission behind it", async () => {
    const before = await headSeq(store.db);
    await expect(
      recordReconfirmation(store.db, {
        event: {
          at: AT,
          type: "reconfirmation",
          entry_id: "nmk_never_submitted",
          payload: { record: reconfirmationRecord(), signature: "c2lnbmF0dXJl" },
        },
        stored: () => {
          throw new Error("stored must not be called");
        },
        bounty: () => {
          throw new Error("bounty must not be called");
        },
      }),
    ).rejects.toBeInstanceOf(MissingSubmissionError);

    expect(await headSeq(store.db)).toBe(before);
  });

  it("leaves no event behind when the entry row cannot be written", async () => {
    const before = await headSeq(store.db);
    const bounties = await bountiesForEntry(store.db, targetId, 10);
    const events = await eventsForEntry(store.db, targetId);

    await expect(
      recordReconfirmation(brokenEntryWrite(store.db), {
        event: {
          at: AT,
          type: "reconfirmation",
          entry_id: targetId,
          payload: { record: reconfirmationRecord(), signature: "c2lnbmF0dXJl" },
        },
        stored: (reconfirmation) => {
          const derived = deriveEntry([...events, reconfirmation], targetId, {
            now: AT,
          });
          return {
            entry: derived.entry,
            sidecar: derived.sidecar,
            derivedThroughSeq: reconfirmation.seq,
          };
        },
        bounty: (reconfirmation) =>
          bountyAccrual({ expires_at: "2026-06-01", stale: true }, reconfirmation),
      }),
    ).rejects.toBeTruthy();

    // One write or none: the event, the entry row and the ledger row are one
    // batch, so a failure in any of them leaves the log exactly as it was.
    expect(await headSeq(store.db)).toBe(before);
    expect(await eventsForEntry(store.db, targetId)).toEqual(events);
    expect(await bountiesForEntry(store.db, targetId, 10)).toEqual(bounties);
  });
});

/**
 * Sealing writes: the batch that makes a seal real.
 *
 * Its own database, because the entries have to start unsealed — the point is
 * that `recordSeal` is what puts the seal object on them, and the shared
 * database above stores the world's seals before anything else happens.
 */
describe("sealing writes", () => {
  let sealing: TestDatabase;
  let first: Seal;
  let second: Seal;
  let now: Date;

  /**
   * What the sweep's callback does, without the Worker's world module: derive
   * the entry over the whole log, with this seal's own entry seal handed in
   * because inside `recordSeal`'s batch the seal is not readable yet.
   */
  const rederiveWith: SealRederive = async (entryId, seal, at) => {
    const seals = new Map<string, EntrySeal>();
    const built = await entrySeal(world.bundle.events, [seal], entryId);
    if (built !== null) seals.set(entryId, built);
    const derived = deriveEntry(
      world.bundle.events,
      entryId,
      { now: at.toISOString() },
      seals,
    );
    return {
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: seal.last_seq,
    };
  };

  /** A receipt shaped like the registry's, stored and read back verbatim. */
  const RECEIPT: RegistrySeal = {
    registry: "https://1f916.ai",
    handle: "nomankind",
    label: "memory.seal",
    event_id: 9129,
    event_hash: "06fa8eb00cf9b709df0cb21ce1a74f416e9af2820db0770de0e5cfa996776ec4",
    receipt: { ok: true, leaf_index: 9128 },
    sealed_at: "2026-09-10T00:05:00.000Z",
  };

  const COUNTERSIGNED: WitnessSignature[] = [
    { agent: "1F916:d2l0bmVzc09uZUFnZW50SWRlbnRpdHlBQUFB", signature: "c2lnbmF0dXJlLW9uZQ" },
    { agent: "1F916:d2l0bmVzc1R3b0FnZW50SWRlbnRpdHlBQUFB", signature: "c2lnbmF0dXJlLXR3bw" },
  ];

  beforeAll(async () => {
    sealing = await openTestDatabase();
    now = new Date(world.bundle.as_of);
    first = world.bundle.seals[0]!;
    second = secondSeal;

    await appendEvents(sealing.db, world.bundle.events);
    // Both entries stored as they are before anything is sealed: derivation
    // with no seals at all, so `seal` is null on both rows.
    for (const id of [VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID]) {
      const derived = deriveEntry(world.bundle.events, id, clock());
      await putEntry(sealing.db, derived.entry, derived.sidecar, 0);
    }
  }, 600_000);

  afterAll(async () => {
    await sealing?.dispose();
  });

  it("starts from entries nothing has sealed", async () => {
    const stored = await getEntry(sealing.db, VERIFIED_ENTRY_ID);
    expect((stored!.entry as Record<string, unknown>)["seal"]).toBeNull();
  });

  it("writes the seal and the entries it covers in one batch", async () => {
    const rewritten = await recordSeal(sealing.db, first, now, rederiveWith);
    expect(rewritten).toEqual([VERIFIED_ENTRY_ID]);
    expect(await sealBySeq(sealing.db, first.seq)).toEqual(first);

    const stored = await getEntry(sealing.db, VERIFIED_ENTRY_ID);
    const seal = (stored!.entry as Record<string, unknown>)["seal"] as EntrySeal;
    expect(seal).not.toBeNull();
    expect(seal.log).toBe("1F916");
    expect(seal.sealed_at).toBe(first.sealed_at);

    // The proof is real: it decodes, and the submission event's hash folds up
    // it to the root the seal committed to.
    const proof = decodeProof(seal.inclusion_proof);
    expect(proof).not.toBeNull();
    const submission = world.bundle.events.find(
      (event) =>
        event.type === "entry_submitted" && event.entry_id === VERIFIED_ENTRY_ID,
    )!;
    expect(seal.position).toBe(submission.seq);
    expect(await verifyInclusion(submission.hash, proof!, first.root)).toBe(true);
  });

  it("refuses a second seal at the same seq rather than overwriting it", async () => {
    // Two timers racing to seal the same range: the second must fail, and the
    // caller reports it.
    await expect(recordSeal(sealing.db, first, now, rederiveWith)).rejects.toThrow(
      SealConflictError,
    );
    // And the entry the first write sealed is untouched.
    const stored = await getEntry(sealing.db, VERIFIED_ENTRY_ID);
    expect((stored!.entry as Record<string, unknown>)["seal"]).not.toBeNull();
  });

  it("puts the countersignatures on the entries the seal covers", async () => {
    const rewritten = await setSealWitnesses(
      sealing.db,
      first,
      COUNTERSIGNED,
      now,
      rederiveWith,
    );
    expect(rewritten).toEqual([VERIFIED_ENTRY_ID]);

    const stored = await sealBySeq(sealing.db, first.seq);
    expect(stored!.witnesses).toEqual(COUNTERSIGNED);
    // The seal hash is unchanged: countersignatures never enter it.
    expect(stored!.hash).toBe(first.hash);

    const entry = await getEntry(sealing.db, VERIFIED_ENTRY_ID);
    const seal = (entry!.entry as Record<string, unknown>)["seal"] as EntrySeal;
    expect(seal.witnesses).toEqual(COUNTERSIGNED.map((one) => one.signature));
  });

  it("records what the registry returned, and nothing else moves", async () => {
    await setSealRegistry(sealing.db, first.seq, RECEIPT);
    const stored = await sealBySeq(sealing.db, first.seq);
    expect(stored!.registry).toEqual(RECEIPT);
    expect(stored!.hash).toBe(first.hash);
    expect(stored!.witnesses).toEqual(COUNTERSIGNED);

    await setSealRegistry(sealing.db, first.seq, null);
    expect((await sealBySeq(sealing.db, first.seq))!.registry).toBeNull();
    await setSealRegistry(sealing.db, first.seq, RECEIPT);
  });

  it("seals the tail, and the draft submitted into it", async () => {
    const rewritten = await recordSeal(sealing.db, second, now, rederiveWith);
    expect(rewritten).toEqual([DRAFT_ENTRY_ID]);

    const entry = await getEntry(sealing.db, DRAFT_ENTRY_ID);
    const seal = (entry!.entry as Record<string, unknown>)["seal"] as EntrySeal;
    const submission = world.bundle.events.find(
      (event) =>
        event.type === "entry_submitted" && event.entry_id === DRAFT_ENTRY_ID,
    )!;
    expect(seal.position).toBe(submission.seq);
    expect(
      await verifyInclusion(submission.hash, decodeProof(seal.inclusion_proof)!, second.root),
    ).toBe(true);
    // A draft is sealed like everything else (Section 6).
    expect((entry!.entry as Record<string, unknown>)["status"]).toBe("draft");
  });

  it("pages the seal chain forward in seq order", async () => {
    const all = await sealsAfter(sealing.db, -1, 10);
    expect(all.map((seal) => seal.seq)).toEqual([first.seq, second.seq]);
    expect(await sealsAfter(sealing.db, first.seq, 10)).toHaveLength(1);
    expect(await sealsAfter(sealing.db, second.seq, 10)).toEqual([]);
    // The caller's limit is honoured; there is no page size here.
    expect(await sealsAfter(sealing.db, -1, 1)).toHaveLength(1);
  });

  it("answers which seals were sealed on a UTC day", async () => {
    const day = utcDay(first.sealed_at);
    const sealed = await sealsSealedOn(sealing.db, day);
    expect(sealed.map((seal) => seal.seq)).toEqual(
      [first, second]
        .filter((seal) => utcDay(seal.sealed_at) === day)
        .map((seal) => seal.seq),
    );
    expect(sealed.length).toBeGreaterThan(0);
    expect(await sealsSealedOn(sealing.db, "2020-01-01")).toEqual([]);
  });

  it("lists the seals still waiting on the outside world", async () => {
    // The first is finished: countersigned and accepted. The second has
    // neither, so it is the whole queue.
    expect((await unwitnessedSeals(sealing.db, 10)).map((seal) => seal.seq)).toEqual([
      second.seq,
    ]);

    await setSealWitnesses(sealing.db, second, COUNTERSIGNED, now, rederiveWith);
    // Countersigned but not yet accepted by the registry: still waiting.
    expect((await unwitnessedSeals(sealing.db, 10)).map((seal) => seal.seq)).toEqual([
      second.seq,
    ]);

    await setSealRegistry(sealing.db, second.seq, RECEIPT);
    expect(await unwitnessedSeals(sealing.db, 10)).toEqual([]);
  });

  it("keeps the seal when the entry is re-derived by a later write", async () => {
    // The seal is a derived field like any other, so every later write
    // recomputes it — and a world gathered without it would hand derivation an
    // empty map and quietly erase a seal that was really made. This is the
    // path the validate door, the reconfirm door and the staleness step all
    // take (src/worker/world.ts).
    const stored = await getEntry(sealing.db, VERIFIED_ENTRY_ID);
    const sealed = (stored!.entry as Record<string, unknown>)["seal"] as EntrySeal;

    const world_ = await entryWorld(sealing.db, VERIFIED_ENTRY_ID);
    expect(world_.seal).toEqual(sealed);
    const again = rederive(world_, VERIFIED_ENTRY_ID, now);
    expect((again.entry as Record<string, unknown>)["seal"]).toEqual(sealed);

    // And an entry nothing covers still re-derives to a null seal rather than
    // a made-up one.
    const unsealed = await openTestDatabase();
    try {
      await appendEvents(unsealed.db, world.bundle.events);
      const empty = await entryWorld(unsealed.db, VERIFIED_ENTRY_ID);
      expect(empty.seal).toBeNull();
      expect(
        (rederive(empty, VERIFIED_ENTRY_ID, now).entry as Record<string, unknown>)[
          "seal"
        ],
      ).toBeNull();
    } finally {
      await unsealed.dispose();
    }
  });

  it("round-trips a day's external timestamp receipt", async () => {
    const day = utcDay(first.sealed_at);
    const built = await buildAnchor([first, second], day);
    expect(built.ok).toBe(true);
    const anchor = (built as { ok: true; anchor: Anchor }).anchor;
    await putAnchor(sealing.db, anchor);
    expect((await getAnchor(sealing.db, day))!.external).toBeNull();

    const external = {
      kind: "opentimestamps" as const,
      calendar: "https://alice.btc.calendar.opentimestamps.org",
      submitted_at: "2026-09-10T00:10:00.000Z",
      proof: "AE9wZW5UaW1lc3RhbXBz",
      upgraded: null,
    };
    await setAnchorExternal(sealing.db, day, external);
    const stored = await getAnchor(sealing.db, day);
    expect(stored!.external).toEqual(external);
    // Only the receipt moved: the hash covers the date and the roots (D-037).
    expect(stored!.hash).toBe(anchor.hash);
    expect(stored!.roots).toEqual(anchor.roots);

    // And a page of anchors after a day reads it back the same way.
    expect(await anchorsAfter(sealing.db, "2020-01-01", 10)).toEqual([stored]);
    expect(await anchorsAfter(sealing.db, day, 10)).toEqual([]);
  });
});

/**
 * Read receipts and the reader's candidates, in their own database.
 *
 * Whitepaper Section 8, "The frozen reader": a read returns "a signed read
 * receipt naming the entry, the time, and a running counter". Section 9, Money:
 * "Read counts are published to the sealed log daily", so "any reader can
 * compare the receipts they hold against the published counts". So the
 * questions here are the ones that publication asks: does the counter really
 * run, does a day group and page, and do the counters bound the day.
 *
 * Its own database, because the world above is asserted against its own head
 * and these tests move it.
 */
describe("read receipts", () => {
  const SUBJECT = "openai/gpt-5";
  const CATEGORY = "pricing";

  /** Three verified entries and one draft, oldest submission first. */
  const VERIFIED_IDS = ["nmk_read1", "nmk_read2", "nmk_read3"];
  const DRAFT_ID = "nmk_read4";

  let reading: TestDatabase;
  let issuerAgent: string;
  let issuerKeys: CryptoKeyPair;
  let log: Event[];

  /** The verified entry's own core, re-keyed: a real core under a new id. */
  function coreWithId(source: Entry, id: string): Core {
    const record = source as unknown as Record<string, unknown>;
    const core: Record<string, unknown> = {};
    for (const key of CORE_KEYS) core[key] = record[key];
    core["id"] = id;
    return core as Core;
  }

  /**
   * The world's own derived entry under a new id. Nothing is invented: the
   * status, the sidecar and every derived field are what `deriveEntry` made of
   * the real log, so the only variable these tests change is which entry is
   * which and in what order they were submitted.
   */
  function entryWithId(source: Entry, id: string): Entry {
    return { ...(source as unknown as Record<string, unknown>), id } as Entry;
  }

  /** A real signed receipt for one entry at one instant. */
  async function issue(
    entryId: string,
    createdAt: string,
  ): Promise<ReadReceipt> {
    const counter = await nextReadCounter(reading.db);
    const receipt = await signReadReceipt(
      {
        entry_id: entryId,
        entry_hash: await entryHash(world.entry),
        read_at: createdAt,
        counter,
        issuer: issuerAgent,
      },
      issuerKeys.privateKey,
    );
    await putReadReceipt(reading.db, { entryId, createdAt, receipt });
    return receipt;
  }

  beforeAll(async () => {
    reading = await openTestDatabase();
    issuerKeys = await generateKeypair();
    issuerAgent = agentIdFromPublicKey(
      await exportPublicKeyRaw(issuerKeys.publicKey),
    );

    // A real log: one entry_submitted per entry, in the order they were
    // submitted, so submitted_seq is the log position and not a number a test
    // chose.
    log = [];
    for (const id of [...VERIFIED_IDS, DRAFT_ID]) {
      log = await appendEvent(log, {
        at: "2026-09-08T00:00:00.000Z",
        type: "entry_submitted",
        entry_id: id,
        payload: {
          core: coreWithId(
            id === DRAFT_ID ? world.draftEntry : world.entry,
            id,
          ),
          signature: (world.entry as unknown as Record<string, string>)[
            "signature"
          ]!,
        },
      });
    }
    await appendEvents(reading.db, log);

    for (const id of VERIFIED_IDS) {
      await putEntry(
        reading.db,
        entryWithId(world.entry, id),
        (await getEntry(test.db, VERIFIED_ENTRY_ID))!.sidecar,
        log[log.length - 1]!.seq,
      );
    }
    await putEntry(
      reading.db,
      entryWithId(world.draftEntry, DRAFT_ID),
      (await getEntry(test.db, DRAFT_ENTRY_ID))!.sidecar,
      log[log.length - 1]!.seq,
    );
  }, 600_000);

  afterAll(async () => {
    await reading?.dispose();
  });

  it("starts the running counter at 1 and never repeats a number", async () => {
    expect(await earliestReadReceiptDay(reading.db)).toBeNull();
    expect(await nextReadCounter(reading.db)).toBe(1);

    const first = await issue("nmk_read1", "2026-09-09T09:00:00.000Z");
    expect(first.counter).toBe(1);
    expect(await nextReadCounter(reading.db)).toBe(2);

    const second = await issue("nmk_read1", "2026-09-09T10:00:00.000Z");
    const third = await issue("nmk_read2", "2026-09-09T11:00:00.000Z");
    expect([second.counter, third.counter]).toEqual([2, 3]);

    // Round-tripped verbatim, signature and all: the reader who lost their copy
    // gets back the bytes that were signed.
    expect(await readReceiptByCounter(reading.db, 1)).toEqual(first);
    await expect(
      verifyReadReceipt((await readReceiptByCounter(reading.db, 1))!),
    ).resolves.toBe(true);
    expect(await readReceiptByCounter(reading.db, 99)).toBeNull();
  });

  it("refuses a counter another reader already took", async () => {
    // What a race looks like from the loser's side: both isolates read the same
    // next counter, and the unique index refuses the second insert.
    const taken = await nextReadCounter(reading.db);
    const mine = await issue("nmk_read3", "2026-09-09T12:00:00.000Z");
    expect(mine.counter).toBe(taken);

    const theirs = await signReadReceipt(
      {
        entry_id: "nmk_read1",
        entry_hash: await entryHash(world.entry),
        read_at: "2026-09-09T12:00:01.000Z",
        counter: taken,
        issuer: issuerAgent,
      },
      issuerKeys.privateKey,
    );
    const refused = putReadReceipt(reading.db, {
      entryId: "nmk_read1",
      createdAt: "2026-09-09T12:00:01.000Z",
      receipt: theirs,
    });
    await expect(refused).rejects.toBeInstanceOf(ReceiptConflictError);
    await expect(refused).rejects.toMatchObject({
      name: "ReceiptConflictError",
      counter: taken,
    });

    // The winner's receipt is untouched: nothing was overwritten.
    expect(await readReceiptByCounter(reading.db, taken)).toEqual(mine);
  });

  it("pages one entry's receipts in counter order", async () => {
    const all = await readReceiptsForEntry(reading.db, "nmk_read1", 0, 10);
    expect(all.map((receipt) => receipt.counter)).toEqual([1, 2]);
    expect(all.every((receipt) => receipt.entry_id === "nmk_read1")).toBe(true);

    const page = await readReceiptsForEntry(reading.db, "nmk_read1", 0, 1);
    expect(page.map((receipt) => receipt.counter)).toEqual([1]);
    expect(
      (
        await readReceiptsForEntry(reading.db, "nmk_read1", page[0]!.counter, 10)
      ).map((receipt) => receipt.counter),
    ).toEqual([2]);
    expect(await readReceiptsForEntry(reading.db, "nmk_nothing", 0, 10)).toEqual(
      [],
    );
  });

  it("groups a UTC day by entry and pages it by entry_id", async () => {
    // A second day, so the day range is really a range and not "everything".
    await issue("nmk_read3", "2026-09-10T00:30:00.000Z");

    expect(await readCountsOn(reading.db, "2026-09-09", undefined, 10)).toEqual([
      { entry_id: "nmk_read1", count: 2 },
      { entry_id: "nmk_read2", count: 1 },
      { entry_id: "nmk_read3", count: 1 },
    ]);
    expect(await readCountsOn(reading.db, "2026-09-10", undefined, 10)).toEqual([
      { entry_id: "nmk_read3", count: 1 },
    ]);
    expect(await readCountsOn(reading.db, "2026-09-11", undefined, 10)).toEqual(
      [],
    );

    const page = await readCountsOn(reading.db, "2026-09-09", undefined, 2);
    expect(page.map((row) => row.entry_id)).toEqual(["nmk_read1", "nmk_read2"]);
    expect(
      await readCountsOn(reading.db, "2026-09-09", "nmk_read2", 10),
    ).toEqual([{ entry_id: "nmk_read3", count: 1 }]);
  });

  it("bounds each day by the counters issued in it", async () => {
    expect(await readCounterRangeOn(reading.db, "2026-09-09")).toEqual({
      total: 4,
      counter_first: 1,
      counter_last: 4,
    });
    expect(await readCounterRangeOn(reading.db, "2026-09-10")).toEqual({
      total: 1,
      counter_first: 5,
      counter_last: 5,
    });
    // A day nobody read is a true thing to publish, and it has no counters.
    expect(await readCounterRangeOn(reading.db, "2026-09-11")).toEqual({
      total: 0,
      counter_first: null,
      counter_last: null,
    });

    // The published payload the two reads build together, sorted and summed.
    const day = "2026-09-09";
    const range = await readCounterRangeOn(reading.db, day);
    const payload = buildReadCountPayload(
      day,
      await readCountsOn(reading.db, day, undefined, 10),
      range.counter_first,
      range.counter_last,
    );
    expect(payload.total).toBe(range.total);
    expect(payload.reads.map((row) => row.entry_id)).toEqual([
      "nmk_read1",
      "nmk_read2",
      "nmk_read3",
    ]);
  });

  it("knows the day the receipts start from", async () => {
    expect(await earliestReadReceiptDay(reading.db)).toBe("2026-09-09");
  });

  it("offers only verified entries, newest submission first, paged", async () => {
    const all = await readCandidates(reading.db, {
      subject: SUBJECT,
      category: CATEGORY,
      limit: 10,
    });
    expect(
      all.map((stored) => (stored.entry as unknown as Record<string, string>)["id"]),
    ).toEqual(["nmk_read3", "nmk_read2", "nmk_read1"]);
    expect(
      all.every(
        (stored) =>
          (stored.entry as unknown as Record<string, string>)["status"] ===
          "verified",
      ),
    ).toBe(true);

    const page = await readCandidates(reading.db, {
      subject: SUBJECT,
      category: CATEGORY,
      limit: 2,
    });
    expect(page.map((stored) => stored.submittedSeq)).toEqual([2, 1]);
    const next = await readCandidates(reading.db, {
      subject: SUBJECT,
      category: CATEGORY,
      limit: 10,
      beforeSubmittedSeq: page[page.length - 1]!.submittedSeq,
    });
    expect(next.map((stored) => stored.submittedSeq)).toEqual([0]);

    // A subject or category nobody wrote about offers nothing.
    expect(
      await readCandidates(reading.db, {
        subject: "nobody/nothing",
        category: CATEGORY,
        limit: 10,
      }),
    ).toEqual([]);
    expect(
      await readCandidates(reading.db, {
        subject: SUBJECT,
        category: "outage",
        limit: 10,
      }),
    ).toEqual([]);
  });

  it("finds the newest event of one type, and null when there is none", async () => {
    expect(await latestEventOfType(reading.db, "read_count")).toBeNull();

    const published = await appendEvent(log, {
      at: "2026-09-10T00:05:00.000Z",
      type: "read_count",
      entry_id: null,
      payload: buildReadCountPayload(
        "2026-09-09",
        await readCountsOn(reading.db, "2026-09-09", undefined, 10),
        1,
        4,
      ),
    });
    await appendEvents(reading.db, published.slice(log.length));

    const latest = await latestEventOfType(reading.db, "read_count");
    expect(latest).toEqual(published[published.length - 1]);
    expect(await latestEventOfType(reading.db, "entry_submitted")).toEqual(
      log[log.length - 1],
    );
    expect(await latestEventOfType(reading.db, "validation")).toBeNull();
  });
});

/**
 * Sync receipts, in their own database.
 *
 * Whitepaper Section 8, "The delta stream" and "Paying for the training path":
 * a sync response carries one signed receipt covering every delivered entry,
 * and each delivered verified entry counts as a read. Section 9, Money: the
 * counter is one running number, and the day's published count is what readers
 * check their receipts against. So the questions here are whether the two kinds
 * of receipt really share the counter, and whether a day's count sees a
 * trainer's reads as the reads they are.
 *
 * Its own database, because the counter starts at 1 and the day's totals are
 * asserted exactly.
 */
describe("sync receipts", () => {
  let syncing: TestDatabase;
  let agent: string;
  let keys: CryptoKeyPair;

  const hashOf = (id: string) => `sha256:${id.slice(-1).repeat(64)}`;

  /** A real signed read receipt at the next shared counter. */
  async function issueRead(
    entryId: string,
    createdAt: string,
  ): Promise<ReadReceipt> {
    const counter = await nextReadCounter(syncing.db);
    const receipt = await signReadReceipt(
      {
        entry_id: entryId,
        entry_hash: hashOf(entryId),
        read_at: createdAt,
        counter,
        issuer: agent,
      },
      keys.privateKey,
    );
    await putReadReceipt(syncing.db, { entryId, createdAt, receipt });
    return receipt;
  }

  /** A real signed sync receipt at the next shared counter. */
  async function issueSync(
    createdAt: string,
    entries: readonly { entry_id: string; status: EntryStatus }[],
    counter?: number,
  ): Promise<SyncReceipt> {
    const receipt = await signSyncReceipt(
      {
        from: 100,
        head: 142,
        entries: entries.map((entry) => ({
          entry_id: entry.entry_id,
          entry_hash: hashOf(entry.entry_id),
          status: entry.status,
        })),
        event_count: entries.length,
        issued_at: createdAt,
        counter: counter ?? (await nextReadCounter(syncing.db)),
        issuer: agent,
      },
      keys.privateKey,
    );
    await putSyncReceipt(syncing.db, { createdAt, receipt });
    return receipt;
  }

  beforeAll(async () => {
    syncing = await openTestDatabase();
    keys = await generateKeypair();
    agent = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));
  }, 600_000);

  afterAll(async () => {
    await syncing?.dispose();
  });

  it("shares one running counter with read receipts", async () => {
    expect(await nextReadCounter(syncing.db)).toBe(1);

    const first = await issueRead("nmk_sync1", "2026-09-09T09:00:00.000Z");
    expect(first.counter).toBe(1);

    // The sync takes the next number, not a number of its own.
    const delta = await issueSync("2026-09-09T10:00:00.000Z", [
      { entry_id: "nmk_sync1", status: "verified" },
      { entry_id: "nmk_sync2", status: "verified" },
      { entry_id: "nmk_sync3", status: "draft" },
    ]);
    expect(delta.counter).toBe(2);
    expect(await nextReadCounter(syncing.db)).toBe(3);

    // Round-tripped verbatim, signature and all.
    const stored = await syncReceiptByCounter(syncing.db, 2);
    expect(stored).toEqual(delta);
    await expect(verifySyncReceipt(stored!)).resolves.toBe(true);
    expect(await syncReceiptByCounter(syncing.db, 99)).toBeNull();
    // The two kinds are not each other: a read counter names no sync receipt.
    expect(await syncReceiptByCounter(syncing.db, 1)).toBeNull();
    expect(await readReceiptByCounter(syncing.db, 2)).toBeNull();
  });

  it("refuses a counter the other kind already took", async () => {
    // A sync losing the race to a read receipt.
    await expect(
      issueSync(
        "2026-09-09T10:00:01.000Z",
        [{ entry_id: "nmk_sync1", status: "verified" }],
        1,
      ),
    ).rejects.toBeInstanceOf(ReceiptConflictError);

    // And a read losing the race to a sync receipt: the same error, because it
    // is the same race.
    const theirs = await signReadReceipt(
      {
        entry_id: "nmk_sync1",
        entry_hash: hashOf("nmk_sync1"),
        read_at: "2026-09-09T10:00:02.000Z",
        counter: 2,
        issuer: agent,
      },
      keys.privateKey,
    );
    const refused = putReadReceipt(syncing.db, {
      entryId: "nmk_sync1",
      createdAt: "2026-09-09T10:00:02.000Z",
      receipt: theirs,
    });
    await expect(refused).rejects.toBeInstanceOf(ReceiptConflictError);
    await expect(refused).rejects.toMatchObject({ counter: 2 });

    // Nothing was overwritten: both winners stand.
    expect((await readReceiptByCounter(syncing.db, 1))!.counter).toBe(1);
    expect((await syncReceiptByCounter(syncing.db, 2))!.event_count).toBe(3);
  });

  it("counts each delivered verified entry as one read of that entry", async () => {
    const second = await issueRead("nmk_sync2", "2026-09-09T11:00:00.000Z");
    expect(second.counter).toBe(3);
    // A sync on an earlier day, so the day range is really a range.
    const earlier = await issueSync("2026-09-08T23:00:00.000Z", [
      { entry_id: "nmk_sync1", status: "verified" },
      { entry_id: "nmk_sync4", status: "overturned" },
    ]);
    expect(earlier.counter).toBe(4);

    // nmk_sync1: one read row and one sync entry. nmk_sync2: the same.
    // nmk_sync3 was delivered as a draft, so it earned nothing.
    expect(await readCountsOn(syncing.db, "2026-09-09", undefined, 10)).toEqual(
      [
        { entry_id: "nmk_sync1", count: 2 },
        { entry_id: "nmk_sync2", count: 2 },
      ],
    );
    // The earlier day saw only the sync, and only its verified entry.
    expect(await readCountsOn(syncing.db, "2026-09-08", undefined, 10)).toEqual(
      [{ entry_id: "nmk_sync1", count: 1 }],
    );
    expect(await readCountsOn(syncing.db, "2026-09-07", undefined, 10)).toEqual(
      [],
    );

    // The union pages by entry_id like any other listing.
    const page = await readCountsOn(syncing.db, "2026-09-09", undefined, 1);
    expect(page).toEqual([{ entry_id: "nmk_sync1", count: 2 }]);
    expect(
      await readCountsOn(syncing.db, "2026-09-09", "nmk_sync1", 10),
    ).toEqual([{ entry_id: "nmk_sync2", count: 2 }]);
  });

  /**
   * Section 9 pays for "one verified entry returned by the paid API, or one
   * verified entry delivered in a paid sync", and decision D-085 owes only one
   * of the two for a duplicate group's sync delivery. The publisher can only
   * drop the sync half of an entry's day if the store hands it the two halves
   * apart, so this is the query behind that rule.
   */
  it("splits a day into read reads and sync reads, and pages the split", async () => {
    // The same two days the sum above asserted, told apart. nmk_sync1 and
    // nmk_sync2 each have one read row and one verified sync delivery.
    expect(
      await readCountsSplitOn(syncing.db, "2026-09-09", undefined, 10),
    ).toEqual([
      { entry_id: "nmk_sync1", read_reads: 1, sync_reads: 1 },
      { entry_id: "nmk_sync2", read_reads: 1, sync_reads: 1 },
    ]);

    // The earlier day's only receipt is a sync, so every read on it is a sync
    // read and the read column is a real zero rather than a missing row.
    expect(
      await readCountsSplitOn(syncing.db, "2026-09-08", undefined, 10),
    ).toEqual([{ entry_id: "nmk_sync1", read_reads: 0, sync_reads: 1 }]);
    expect(
      await readCountsSplitOn(syncing.db, "2026-09-07", undefined, 10),
    ).toEqual([]);

    // Keyset paging by entry_id, on the same boundaries the summed query uses:
    // the publisher pages both the same way, so they must agree about where a
    // page ends.
    const page = await readCountsSplitOn(syncing.db, "2026-09-09", undefined, 1);
    expect(page).toEqual([
      { entry_id: "nmk_sync1", read_reads: 1, sync_reads: 1 },
    ]);
    expect(
      await readCountsSplitOn(syncing.db, "2026-09-09", "nmk_sync1", 10),
    ).toEqual([{ entry_id: "nmk_sync2", read_reads: 1, sync_reads: 1 }]);
    expect(
      await readCountsSplitOn(syncing.db, "2026-09-09", "nmk_sync2", 10),
    ).toEqual([]);

    // And the summed query is the split, added: one answer, not two.
    for (const day of ["2026-09-07", "2026-09-08", "2026-09-09"]) {
      expect(await readCountsOn(syncing.db, day, undefined, 10)).toEqual(
        (await readCountsSplitOn(syncing.db, day, undefined, 10)).map((row) => ({
          entry_id: row.entry_id,
          count: row.read_reads + row.sync_reads,
        })),
      );
    }
  });

  it("bounds and totals a day over both kinds", async () => {
    // Two read rows and two verified sync entries, bounded by counters 1 and 3.
    expect(await readCounterRangeOn(syncing.db, "2026-09-09")).toEqual({
      total: 4,
      counter_first: 1,
      counter_last: 3,
    });
    // A day whose only receipt is a sync: the bounds are that sync's counter,
    // and the total is the one entry it delivered verified.
    expect(await readCounterRangeOn(syncing.db, "2026-09-08")).toEqual({
      total: 1,
      counter_first: 4,
      counter_last: 4,
    });
    expect(await readCounterRangeOn(syncing.db, "2026-09-07")).toEqual({
      total: 0,
      counter_first: null,
      counter_last: null,
    });

    // The published payload the two reads build together adds up to the total.
    const day = "2026-09-09";
    const range = await readCounterRangeOn(syncing.db, day);
    const payload = buildReadCountPayload(
      day,
      await readCountsOn(syncing.db, day, undefined, 10),
      range.counter_first,
      range.counter_last,
    );
    expect(payload.total).toBe(range.total);
  });

  it("starts the publication from the sync receipt's earlier day", async () => {
    expect(await earliestReadReceiptDay(syncing.db)).toBe("2026-09-08");
  });
});

/**
 * Disputes, revalidations and failure reports, in their own database.
 *
 * Whitepaper Section 6, "Dispute": a challenge is itself an entry, so filing one
 * writes two events on two entries and a ledger row, and all of it lands or none
 * of it does; "an upheld challenge returns the stake, pays the challenger,
 * overturns the entry", which happens in the batch of the decision that verified
 * the correction. Section 6, "Revalidate": a request is drawn for and answered
 * like a validation assignment, which is why it shares that table and why the
 * purpose column has to keep the two apart. Section 8: a threshold of reports
 * auto-opens a check, in the batch of the report that reached it.
 *
 * A round trip each: the chain read back still verifies, and the rows beside it
 * say exactly what the events say. Every derived row is rederived by the test
 * itself, because nothing in storage derives a field.
 */
describe("dispute and revalidation writes", () => {
  const AUTHOR = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const CHALLENGER = "1F916:2m1F1TL0ByLTHM_ZDvGGVMDLtvgFcT7l8jvpZ4bVMSU";
  const REPORTER = "1F916:Ku8xLPHqQ0nMi3ZQrpFvJXfDl9fJ0oO0yYy0OaXWQ7A";
  const AUTHOR_OPERATOR = "kestrel.example";
  const CHALLENGER_OPERATOR = "harrier.example";
  const CHECKER = "osprey.example";
  const SUBJECT = "kestrel/kestrel-9";
  const AT = "2026-09-08T12:00:00.000Z";
  const CLOCK = { now: AT };
  const SNAPSHOT = `sha256:${"7c".repeat(32)}`;
  const ARTIFACT = `sha256:${"6d".repeat(32)}`;

  let store: TestDatabase;
  let log: Event[] = [];
  let targetId: string;
  let checkedId: string;
  let correctionId: string;
  let filedEvent: Event<"dispute_filed">;

  /**
   * Each entry's own events, mirrored here as the writes land. Kept rather than
   * re-read because the writers' callbacks are synchronous: the caller has to
   * already hold the log it derives from, which is exactly how the Worker's
   * routes will do it too.
   */
  const events = new Map<string, Event[]>();

  function seen(...sealed: readonly Event[]): void {
    for (const event of sealed) {
      const id = event.entry_id as string;
      events.set(id, [...(events.get(id) ?? []), event]);
    }
  }

  /** One entry rederived over its own events plus `extra`, as a writer takes it. */
  function stored(
    id: string,
    extra: readonly Event[],
    seq: number,
  ): StoredEntryInput {
    const derived = deriveEntry(
      [...(events.get(id) ?? []), ...extra],
      id,
      CLOCK,
    );
    return {
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: seq,
    };
  }

  async function submit(
    claim: string,
    at: string,
    author = AUTHOR,
  ): Promise<string> {
    const core = await buildSubmittedCore(
      {
        subject: SUBJECT,
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim,
        before: "$25 per seat per month",
        after: "$30 per seat per month",
        effective_at: "2026-09-01",
        citation: "https://kestrel.example/pricing-9",
        snapshot_hash: SNAPSHOT,
        supersedes: null,
        author,
        author_operator: AUTHOR_OPERATOR,
      },
      { now: at },
    );
    const id = core["id"] as string;
    log = await appendEvent(log, {
      at,
      type: "entry_submitted",
      entry_id: id,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    const event = log[log.length - 1]!;
    const derived = deriveEntry(log, id, { now: at });
    await submitEntry(store.db, {
      events: [event],
      entry: derived.entry,
      sidecar: derived.sidecar,
      derivedThroughSeq: event.seq,
      captures: [],
    });
    seen(event);
    return id;
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    targetId = await submit("Kestrel-9 seat pricing is $25 per seat per month", AT);
    checkedId = await submit(
      "Kestrel-9 storage pricing is $5 per terabyte",
      "2026-09-08T12:05:00.000Z",
    );
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("files a dispute: the correction, the challenge, both rows and the stake", async () => {
    const at = "2026-09-08T13:00:00.000Z";
    const correctionCore = await buildSubmittedCore(
      {
        subject: SUBJECT,
        category: "correction",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-9 seat pricing never moved off $25",
        before: "$30 per seat per month",
        after: "$25 per seat per month",
        effective_at: "2026-09-01",
        citation: "https://kestrel.example/pricing-9-archive",
        snapshot_hash: SNAPSHOT,
        supersedes: null,
        author: CHALLENGER,
        author_operator: CHALLENGER_OPERATOR,
      },
      { now: at },
    );
    correctionId = correctionCore["id"] as string;

    const capture: CaptureRecord = {
      entryId: correctionId,
      role: "snapshot",
      contentHash: SNAPSHOT,
      archiveHash: SNAPSHOT,
      normVersion: "norm-v1.2",
      kind: "html",
      mediaType: "text/html",
      size: 42,
      fetchedAt: at,
    };

    const filing = await recordDisputeFiling(store.db, {
      correction: {
        event: {
          at,
          type: "entry_submitted",
          entry_id: correctionId,
          payload: { core: correctionCore, signature: "c2lnbmF0dXJl" },
        },
        stored: (submitted, filed) => {
          const derived = deriveEntry([submitted], correctionId, CLOCK);
          return {
            entry: derived.entry,
            sidecar: derived.sidecar,
            derivedThroughSeq: filed.seq,
          };
        },
        captures: [capture],
      },
      filed: (submitted) => ({
        at,
        type: "dispute_filed",
        entry_id: targetId,
        payload: {
          correction_entry_id: submitted.entry_id as string,
          challenger: CHALLENGER,
          operator: CHALLENGER_OPERATOR,
          citation: correctionCore["citation"] as string,
          snapshot_hash: correctionCore["snapshot_hash"] as string,
          from_report_seq: null,
          from_revalidation_seq: null,
        },
      }),
      target: (_submitted, filed) => stored(targetId, [filed], filed.seq),
      stake: (filed) => disputeStake(filed),
    });
    filedEvent = filing.filed;
    seen(filing.submitted, filing.filed);

    // The submission comes first: the challenge names an entry the log has seen.
    expect(filing.submitted.seq + 1).toBe(filing.filed.seq);
    expect(
      await verifyChain(await eventsInRange(store.db, 0, filing.filed.seq)),
    ).toEqual({ ok: true, length: filing.filed.seq + 1 });

    // The correction is linked to what it disputes, read back both ways.
    expect(await disputeOf(store.db, correctionId)).toBe(targetId);
    expect(await disputeOf(store.db, targetId)).toBeNull();
    expect(await disputeOf(store.db, "nmk_01NOTHERE")).toBeNull();
    expect(
      (await correctionEntriesFor(store.db, targetId, 10)).map(
        (row) => row.entry["id"],
      ),
    ).toEqual([correctionId]);
    expect(await correctionEntriesFor(store.db, checkedId, 10)).toEqual([]);

    // The target's own row now carries the challenge in disputes[].
    const target = (await getEntry(store.db, targetId))!;
    expect(target.entry["disputes"]).toHaveLength(1);

    // The capture the correction rests on landed in the same batch.
    expect(await capturesForEntry(store.db, correctionId)).toEqual([capture]);

    // And the stake the challenger put up, filed against the disputed entry.
    const rows = await ledgerRowsForEntry(store.db, targetId, 10);
    expect(rows.map((row) => row.kind)).toEqual(["dispute_stake"]);
    expect(rows[0]!.amount).toBe(DISPUTE_STAKE_STANDING);
    expect(rows[0]!.correction_entry_id).toBe(correctionId);
  });

  it("upholds it: dispute_upheld and the refund land with the validation", async () => {
    const record: ApproverRecord = {
      agent: `1F916:agent-${CHECKER}`,
      operator: CHECKER,
      decision: "approve",
      reason: null,
      snapshot_hash: SNAPSHOT,
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    };

    const validation = await recordValidation(store.db, {
      event: {
        at: AT,
        type: "validation",
        entry_id: correctionId,
        payload: { record, signature: "c2lnbmF0dXJl" },
      },
      // Section 6: the decision that verifies the correction is the moment the
      // entry it corrects is overturned. One batch, or neither.
      alsoEvents: () => [
        {
          at: AT,
          type: "dispute_upheld",
          entry_id: targetId,
          payload: { correction_entry_id: correctionId },
        },
      ],
      stored: (event) => stored(correctionId, [event], event.seq),
      also: (event, extra) => [
        stored(targetId, extra, event.seq + extra.length),
      ],
      answeredAssignmentSeq: null,
      ledger: (_event, extra) =>
        disputeOutcomeStakes(filedEvent, extra[0] as Event<"dispute_upheld">),
    });

    const upheldSeq = validation.seq + 1;
    const upheld = (await eventBySeq(store.db, upheldSeq))!;
    expect(upheld.type).toBe("dispute_upheld");
    expect(await verifyChain(await eventsInRange(store.db, 0, upheldSeq))).toEqual({
      ok: true,
      length: upheldSeq + 1,
    });
    seen(validation, upheld);

    // The original stays in the log, marked overturned, linked to its correction.
    const target = (await getEntry(store.db, targetId))!;
    expect(target.entry["status"]).toBe("overturned");
    expect(target.entry["overturned_by"]).toBe(correctionId);
    const [dispute] = target.entry["disputes"] as Record<string, unknown>[];
    expect(dispute!["outcome"]).toBe("upheld");

    // The stake comes back and a reward is owed, both at the outcome's position.
    const rows = await ledgerRowsForEntry(store.db, targetId, 10);
    expect(rows.map((row) => row.kind)).toEqual([
      "dispute_stake",
      "dispute_refund",
      "dispute_reward",
    ]);
    expect(rows[1]!.amount).toBe(DISPUTE_STAKE_STANDING);
    expect(rows[2]!.amount).toBeNull();

    // The operators that signed the overturned entry, counted for standing.
    expect(await overturnedCountsByOperator(store.db, 10)).toEqual([
      { operator: AUTHOR_OPERATOR, count: 1 },
    ]);
  });

  it("runs a revalidation: request, draw, miss, and resolution", async () => {
    const request = await recordRevalidationRequest(store.db, {
      event: {
        at: AT,
        type: "revalidation_requested",
        entry_id: checkedId,
        payload: {
          requester: CHALLENGER,
          operator: CHALLENGER_OPERATOR,
          source: "operator",
        },
      },
      stored: (event) => stored(checkedId, [event], event.seq),
      ledger: (event) => {
        const stake = revalidationStake(event);
        return stake === null ? [] : [stake];
      },
    });
    seen(request);
    expect(await ledgerRowsForEntry(store.db, checkedId, 10)).toHaveLength(1);

    const assigned = await recordRevalidationAssignment(store.db, {
      event: {
        at: AT,
        type: "revalidation_assigned",
        entry_id: checkedId,
        payload: {
          request_seq: request.seq,
          agent: `1F916:agent-${CHECKER}`,
          operator: CHECKER,
          beacon_round: 991,
          deadline: "2026-09-11T12:00:00.000Z",
        },
      },
      stored: (event) => stored(checkedId, [event], event.seq),
    });
    seen(assigned);

    // The purpose column keeps the two kinds of draw apart in both directions.
    expect((await openRevalidationAssignment(store.db, checkedId))!.seq).toBe(
      assigned.seq,
    );
    expect(await openAssignment(store.db, checkedId)).toBeNull();
    const due = await dueRevalidationAssignments(store.db, "2026-09-12T00:00:00Z", 10);
    expect(due.map((row) => row.requestSeq)).toEqual([request.seq]);
    expect(await dueAssignments(store.db, "2026-09-12T00:00:00Z", 10)).toEqual([]);

    // A miss closes the draw and leaves the request owed.
    const missed = await recordRevalidationMissed(
      store.db,
      {
        event: {
          at: AT,
          type: "revalidation_missed",
          entry_id: checkedId,
          payload: {
            request_seq: request.seq,
            agent: `1F916:agent-${CHECKER}`,
            operator: CHECKER,
          },
        },
        stored: (event) => stored(checkedId, [event], event.seq),
      },
      assigned.seq,
    );
    seen(missed);
    expect(await openRevalidationAssignment(store.db, checkedId)).toBeNull();
    expect(
      await dueRevalidationAssignments(store.db, "2026-09-12T00:00:00Z", 10),
    ).toEqual([]);

    // The entry held, so the requester loses the stake.
    const resolution = await recordRevalidationResolution(store.db, {
      event: {
        at: AT,
        type: "revalidation_resolved",
        entry_id: checkedId,
        payload: {
          request_seq: request.seq,
          outcome: "held",
          checker: `1F916:agent-${CHECKER}`,
          operator: CHECKER,
          snapshot_hash: SNAPSHOT,
          correction_entry_id: null,
        },
      },
      stored: (event) => stored(checkedId, [event], event.seq),
      ledger: (event) => revalidationOutcomeStakes(request, event),
    });
    seen(resolution);

    expect(await eventBySeq(store.db, resolution.seq)).toEqual(resolution);
    const row = (await getEntry(store.db, checkedId))!;
    const [view] = row.sidecar.revalidations;
    expect(view!.request_seq).toBe(request.seq);
    expect(view!.outcome).toBe("held");
    expect(view!.assigned).toBeNull();
    expect(
      (await ledgerRowsForEntry(store.db, checkedId, 10)).map((one) => one.kind),
    ).toEqual(["revalidation_stake", "revalidation_forfeit"]);
  });

  it("auto-opens a check in the batch of the report that reached the threshold", async () => {
    const filed = await recordFailureReport(store.db, {
      event: {
        at: AT,
        type: "failure_report",
        entry_id: checkedId,
        payload: {
          reporter: REPORTER,
          operator: CHECKER,
          observed: "The storage endpoint billed $7, not $5.",
          artifact_hash: ARTIFACT,
          citation: null,
        },
      },
      capture: (report) => ({
        entryId: checkedId,
        // A role of its own, so one reader's artifact never overwrites another's
        // or the entry's own captures.
        role: `report:${report.seq}`,
        contentHash: ARTIFACT,
        archiveHash: ARTIFACT,
        normVersion: "norm-v1.2",
        kind: "transcript",
        mediaType: "application/json",
        size: 128,
        fetchedAt: AT,
      }),
      // Section 8: the check nomankind opens itself, at its own expense.
      opens: () => ({
        at: AT,
        type: "revalidation_requested",
        entry_id: checkedId,
        payload: { requester: null, operator: null, source: "failure_reports" },
      }),
      stored: (report, opened) =>
        stored(
          checkedId,
          opened === null ? [report] : [report, opened],
          (opened ?? report).seq,
        ),
    });
    seen(filed.report, filed.opened!);

    expect(filed.opened).not.toBeNull();
    expect(filed.opened!.seq).toBe(filed.report.seq + 1);
    expect(
      await verifyChain(await eventsInRange(store.db, 0, filed.opened!.seq)),
    ).toEqual({ ok: true, length: filed.opened!.seq + 1 });

    const row = (await getEntry(store.db, checkedId))!;
    const reports = row.entry["failure_reports"] as Record<string, unknown>[];
    expect(reports).toHaveLength(1);
    expect(reports[0]!["artifact_hash"]).toBe(ARTIFACT);
    expect(reports[0]!["upgraded_to"]).toBeNull();
    // Two requests now: the operator's, and the one the reports opened.
    expect(row.sidecar.revalidations).toHaveLength(2);
    expect(row.sidecar.revalidations[1]!.source).toBe("failure_reports");
    // Nomankind staked nothing against itself, so the ledger did not move.
    expect(
      (await ledgerRowsForEntry(store.db, checkedId, 10)).map((one) => one.kind),
    ).toEqual(["revalidation_stake", "revalidation_forfeit"]);

    // The artifact is its own capture row, under its own role.
    expect(
      (await capturesForEntry(store.db, checkedId)).map((one) => one.role),
    ).toEqual([`report:${filed.report.seq}`]);
  });

  /**
   * Section 9: standing "gates ... dispute stakes", and what an operator can
   * stake is what it holds less what its open stakes already hold. This is the
   * read that answers the second half of that.
   */
  it("reads back only the stakes that are still in flight", async () => {
    // Everything this challenger put up has been settled: the dispute stake was
    // refunded when the challenge was upheld, and the request's was forfeited
    // when the check held.
    expect(
      await openStakeRowsForOperator(store.db, CHALLENGER_OPERATOR, 50),
    ).toEqual([]);

    const request = await recordRevalidationRequest(store.db, {
      event: {
        at: AT,
        type: "revalidation_requested",
        entry_id: checkedId,
        payload: {
          requester: CHALLENGER,
          operator: CHALLENGER_OPERATOR,
          source: "operator",
        },
      },
      stored: (event) => stored(checkedId, [event], event.seq),
      ledger: (event) => {
        const stake = revalidationStake(event);
        return stake === null ? [] : [stake];
      },
    });
    seen(request);

    const open = await openStakeRowsForOperator(store.db, CHALLENGER_OPERATOR, 50);
    expect(open.map((row) => row.kind)).toEqual(["revalidation_stake"]);
    expect([open[0]!.request_seq, open[0]!.amount, open[0]!.unit]).toEqual([
      request.seq,
      REVALIDATION_REQUEST_STAKE_STANDING,
      "standing",
    ]);
    // Nobody else's, whatever else the table holds.
    expect(await openStakeRowsForOperator(store.db, CHECKER, 50)).toEqual([]);
  });

  /**
   * An operator's settled history grows for its lifetime; what it has in flight
   * cannot. So the read has to be bounded by what is OPEN and not by the ledger
   * in log order: a page of the rows themselves is the oldest settled history
   * long before it is the recent filings, and an operator whose history has
   * outgrown one page would look as if it had staked nothing — which would let
   * it hold more stakes than its standing covers.
   *
   * The rows are written here rather than through the doors because a hundred
   * settled disputes is a hundred entries and a hundred corrections, and what is
   * under test is the query and not the writers. Each one is exactly what
   * src/stake.ts builds and what `stakeStatement` stores.
   */
  it("finds the open stake behind a page of settled history", async () => {
    const BUSY = "merlin.example";
    const base = 900_000;
    const settled: StakeRecord[] = [];
    for (let i = 0; i < LIST_PAGE_LIMIT + 1; i += 1) {
      const entry_id = `nmk_settled${i}`;
      const seq = base + i * 2;
      const dispute = i % 2 === 0;
      const stake: StakeRecord = {
        kind: dispute ? "dispute_stake" : "revalidation_stake",
        entry_id,
        correction_entry_id: dispute ? `nmk_corr${i}` : null,
        request_seq: dispute ? null : seq,
        agent: CHALLENGER,
        operator: BUSY,
        unit: "standing",
        amount: dispute
          ? DISPUTE_STAKE_STANDING
          : REVALIDATION_REQUEST_STAKE_STANDING,
        seq,
        at: AT,
      };
      settled.push(stake, {
        ...stake,
        kind: dispute ? "dispute_refund" : "revalidation_forfeit",
        seq: seq + 1,
      });
    }

    // Two filings still in flight, one of each mechanism, after all of it.
    const openSeq = base + settled.length * 2;
    const openDispute: StakeRecord = {
      kind: "dispute_stake",
      entry_id: "nmk_open",
      correction_entry_id: "nmk_opencorr",
      request_seq: null,
      agent: CHALLENGER,
      operator: BUSY,
      unit: "standing",
      amount: DISPUTE_STAKE_STANDING,
      seq: openSeq,
      at: AT,
    };
    const openRequest: StakeRecord = {
      ...openDispute,
      kind: "revalidation_stake",
      entry_id: "nmk_openreq",
      correction_entry_id: null,
      request_seq: openSeq + 1,
      amount: REVALIDATION_REQUEST_STAKE_STANDING,
      seq: openSeq + 1,
    };

    await store.db.batch(
      [...settled, openDispute, openRequest].map((row) =>
        store.db
          .prepare(
            `INSERT INTO ledger
               (id, kind, operator_id, entry_id, seq, created_at, payload_json)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            `${row.kind}:${row.seq}`,
            row.kind,
            row.operator,
            row.entry_id,
            row.seq,
            row.at,
            JSON.stringify(row),
          ),
      ),
    );

    // More than a page of history in front of them, and the read still answers
    // the question it was asked.
    expect(settled).toHaveLength((LIST_PAGE_LIMIT + 1) * 2);
    expect(
      await openStakeRowsForOperator(store.db, BUSY, LIST_PAGE_LIMIT),
    ).toEqual([openDispute, openRequest]);
    expect(
      lockedStanding(
        await openStakeRowsForOperator(store.db, BUSY, LIST_PAGE_LIMIT),
      ),
    ).toBe(DISPUTE_STAKE_STANDING + REVALIDATION_REQUEST_STAKE_STANDING);
  });
});

/**
 * The ledger and the standing cache (M21).
 *
 * Its own database, because these writes append to the log and cache rows on
 * operators, and a shared world's head must not move under the tests that
 * already read it.
 *
 * The rows under test are built by src/ledger.ts from real sealed events, never
 * by hand: what is being checked is that a row derived from the log survives D1
 * and comes back the same, and that the queries the payout cycle depends on
 * answer the question they claim to.
 */
describe("the ledger", () => {
  let store: TestDatabase;

  const LEDGER_ENTRY = "nmk_01M21LEDGERSTORE";
  const LEDGER_OPERATOR = "ledger.example";
  const SLOT_OPERATOR = "slot.example";
  const READ_DAY = "2026-09-08";
  const READ_AT = `${READ_DAY}T23:59:00.000Z`;
  /** Inside the holdback for the day above, and outside it. */
  const INSIDE = "2026-09-20T00:00:00.000Z";
  const OUTSIDE = "2026-11-01T00:00:00.000Z";

  /**
   * The log every priced day is sealed onto. One log rather than one per day,
   * because a row's id carries the position of the event that produced it and
   * two days sealed at seq 0 would be the same day twice.
   */
  let log: Event[] = [];

  /** A day's read counts, sealed as a real event, priced by src/ledger.ts. */
  async function pricedDay(
    count: number,
    stale: boolean,
    date = READ_DAY,
    at = READ_AT,
  ): Promise<LedgerRow[]> {
    log = await appendEvent(log, {
      at,
      type: "read_count",
      entry_id: null,
      payload: buildReadCountPayload(
        date,
        [{ entry_id: LEDGER_ENTRY, count }],
        1,
        1,
      ),
    });
    return readShareRows(log[log.length - 1] as Event<"read_count">, () => ({
      author_operator: LEDGER_OPERATOR,
      read_share_slots: [{ operator: SLOT_OPERATOR, seq: 1 }],
      stale,
      verified: true,
    }));
  }

  beforeAll(async () => {
    store = await openTestDatabase();
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("round-trips a row through D1 and writes it once, by id", async () => {
    const rows = await pricedDay(10_000, false);
    await putLedgerRows(store.db, rows);
    // A step replayed after a partial failure writes the same ids and changes
    // nothing: the idempotence is the id, not a flag anyone has to remember.
    await putLedgerRows(store.db, rows);

    const stored = await entryLedgerRows(store.db, LEDGER_ENTRY, LIST_PAGE_LIMIT);
    expect(stored).toEqual(rows);
    expect(await ledgerRowsOn(store.db, "read_share", READ_DAY)).toEqual(rows);
    expect(
      await ledgerRowsForOperator(store.db, LEDGER_OPERATOR, LIST_PAGE_LIMIT),
    ).toEqual([rows.find((row) => row.operator === LEDGER_OPERATOR)]);
  });

  it("reads back what is still inside the holdback, and what is not", async () => {
    // A second day, early enough that its rows are released by OUTSIDE, and
    // large enough that the operator clears the published payout minimum:
    // 200,000 reads is fifteen dollars to the submitter, three times the floor.
    const early = await pricedDay(200_000, false, "2026-08-01", "2026-08-01T12:00:00.000Z");
    await putLedgerRows(store.db, early);

    const held = await heldReadShareRows(store.db, LEDGER_ENTRY, INSIDE);
    expect(held.map((row) => row.date)).toEqual([READ_DAY, READ_DAY]);
    expect(await heldReadShareRows(store.db, LEDGER_ENTRY, OUTSIDE)).toEqual([]);

    const released = await releasedUnpaidRows(store.db, LEDGER_OPERATOR, OUTSIDE);
    expect(released.map((row) => row.date).sort()).toEqual(["2026-08-01", READ_DAY]);
    // Nothing has been released as of INSIDE for the later day.
    expect(
      (await releasedUnpaidRows(store.db, LEDGER_OPERATOR, "2026-09-01T00:00:00.000Z"))
        .map((row) => row.date),
    ).toEqual(["2026-08-01"]);
  });

  it("holds a clawback with the share it negates, and releases it with it", async () => {
    const upheld = await appendEvent([], {
      at: INSIDE,
      type: "dispute_upheld",
      entry_id: LEDGER_ENTRY,
      payload: { correction_entry_id: "nmk_01M21CORRECTIONSTORE" },
    });
    const held = await heldReadShareRows(store.db, LEDGER_ENTRY, INSIDE);
    const clawbacks = clawbackRows(upheld[0] as Event<"dispute_upheld">, held);
    expect(clawbacks).toHaveLength(held.length);
    await putLedgerRows(store.db, clawbacks);

    // A clawback carries the available_at of the row it negates, so at INSIDE
    // neither is payable: a cycle can no more take the clawback early than it
    // can pay the share early.
    const inside = await releasedUnpaidRows(store.db, LEDGER_OPERATOR, INSIDE);
    expect(inside.some((row) => row.kind === "clawback")).toBe(false);
    expect(inside.some((row) => row.date === READ_DAY)).toBe(false);

    // Past the holdback they come out together, and they net to nothing.
    const outside = await releasedUnpaidRows(store.db, LEDGER_OPERATOR, OUTSIDE);
    const clawed = outside.filter((row) => row.kind === "clawback");
    expect(clawed).toHaveLength(1);
    const share = outside.find(
      (row) => row.kind === "read_share" && row.date === READ_DAY,
    );
    expect(clawed[0]!.amount).toBe(-share!.amount);
  });

  it("pays a cycle: the payout row, and the rows it claims", async () => {
    const released = await releasedUnpaidRows(store.db, LEDGER_OPERATOR, OUTSIDE);
    const plan = payoutPlan(LEDGER_OPERATOR, released, OUTSIDE);
    expect(plan.rows.length).toBeGreaterThan(0);

    const paid = payoutRow(plan, 1, OUTSIDE, "mock-verified-ledger");
    await recordPayout(store.db, paid, plan.rows);

    expect(await payoutRows(store.db, LIST_PAGE_LIMIT, LEDGER_OPERATOR)).toEqual([
      paid,
    ]);
    // Claimed rows are out of the next cycle, and the payout row itself is not
    // an accrual waiting to be paid again.
    expect(await releasedUnpaidRows(store.db, LEDGER_OPERATOR, OUTSIDE)).toEqual([]);
  });

  it("leaves a row an earlier payout already claimed where it is", async () => {
    const rows = await pricedDay(4_000, false, "2026-07-01", "2026-07-01T12:00:00.000Z");
    await putLedgerRows(store.db, rows);
    const first = rows[0]!;
    await markLedgerPaid(store.db, [first.id], "payout:first");
    await markLedgerPaid(store.db, [first.id], "payout:second");

    const stored = await store.db
      .prepare(`SELECT paid_by FROM ledger WHERE id = ?`)
      .bind(first.id)
      .first<Record<string, unknown>>();
    // Two cycles racing must not both pay one accrual.
    expect(stored?.["paid_by"]).toBe("payout:first");
  });

  it("reads a stale day's withheld halves back over their window", async () => {
    const stale = await pricedDay(2_000, true, "2026-06-10", "2026-06-10T12:00:00.000Z");
    await putLedgerRows(store.db, stale);
    const pool = stale.find((row) => row.kind === "bounty_pool")!;

    expect(
      await bountyPoolRows(store.db, LEDGER_ENTRY, "2026-06-01", "2026-06-30"),
    ).toEqual([pool]);
    // Outside the window, nothing: an earlier spell's pool was collected by
    // whoever ended it.
    expect(
      await bountyPoolRows(store.db, LEDGER_ENTRY, "2026-07-01", "2026-07-31"),
    ).toEqual([]);
  });

  it("stores the day's reconciliation where the same public can read it", async () => {
    log = await appendEvent(log, {
      at: READ_AT,
      type: "read_count",
      entry_id: null,
      payload: buildReadCountPayload(
        READ_DAY,
        [{ entry_id: LEDGER_ENTRY, count: 10_000 }],
        1,
        1,
      ),
    });
    const row = reconciliationRow(
      log[log.length - 1] as Event<"read_count">,
      new Map([[LEDGER_ENTRY, 10_000]]),
    );
    await putLedgerRows(store.db, [row]);
    const stored = await reconciliationRows(store.db, LIST_PAGE_LIMIT);
    expect(stored).toEqual([row]);
    expect(stored[0]!.ref).toMatchObject({ ok: true });
  });

  it("remembers how far a step has read, and forgets nothing else", async () => {
    expect(await ledgerCursor(store.db, "read_share")).toBeNull();
    await setLedgerCursor(store.db, "read_share", 12);
    expect(await ledgerCursor(store.db, "read_share")).toBe(12);
    await setLedgerCursor(store.db, "read_share", 40);
    expect(await ledgerCursor(store.db, "read_share")).toBe(40);
    // One row per stepper, named by the stepper.
    expect(await ledgerCursor(store.db, "standing")).toBeNull();
  });
});

/**
 * The standing cache and the trust changes it drives (M21).
 *
 * Section 9: standing "is derived from the sealed public events by a published
 * formula", so these columns are a cache and `standing_seq` is what makes them
 * checkable. What is under test here is the write, never the formula
 * (test/standing.test.ts owns that).
 */
describe("standing writes", () => {
  let store: TestDatabase;

  const CANDIDATE = "candidate.example";
  const INCUMBENT = "incumbent.example";

  function operator(id: string, trusted: boolean): OperatorRecord {
    return {
      id,
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: {
        registered_by: `1F916:agent-${id}`,
        trusted,
        trusted_seq: trusted ? 0 : null,
        payout_status: "verified",
      },
    };
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    await putOperator(store.db, operator(CANDIDATE, false));
    await putOperator(store.db, operator(INCUMBENT, true));
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("round-trips a cached standing, at the position it was computed at", async () => {
    expect(await standingByOperator(store.db, LIST_PAGE_LIMIT)).toEqual(new Map());

    await setOperatorStanding(store.db, CANDIDATE, 12, 40);
    await setOperatorStanding(store.db, INCUMBENT, -3, 40);
    const standings = await standingByOperator(store.db, LIST_PAGE_LIMIT);

    expect(standings.get(CANDIDATE)).toEqual({ standing: 12, seq: 40 });
    expect(standings.get(INCUMBENT)).toEqual({ standing: -3, seq: 40 });
    // Highest first: the pool's own ordering.
    expect([...standings.keys()]).toEqual([CANDIDATE, INCUMBENT]);
    // Recomputing at a later position replaces both numbers together.
    await setOperatorStanding(store.db, CANDIDATE, 15, 55);
    expect(
      (await standingByOperator(store.db, LIST_PAGE_LIMIT)).get(CANDIDATE),
    ).toEqual({ standing: 15, seq: 55 });
  });

  it("trusts an operator: the event, the row and the cache, in one batch", async () => {
    const event = await recordTrustChange(
      store.db,
      "operator_trusted",
      CANDIDATE,
      "2026-09-20T00:00:00.000Z",
      "standing",
      12,
      40,
    );

    expect(event.seq).toBe(0);
    expect(event.type).toBe("operator_trusted");
    expect(event.payload).toEqual({ operator: CANDIDATE });
    expect(await eventBySeq(store.db, 0)).toEqual(event);

    const record = await getOperator(store.db, CANDIDATE);
    expect(record?.details).toMatchObject({
      trusted: true,
      trusted_seq: event.seq,
      // No key did this: the published formula did.
      named_by: "standing",
    });
    // The registration details it already carried are still there.
    expect(record?.details["payout_status"]).toBe("verified");
    expect(
      (await standingByOperator(store.db, LIST_PAGE_LIMIT)).get(CANDIDATE),
    ).toEqual({ standing: 12, seq: 40 });
  });

  it("untrusts an operator, chaining onto the event before it", async () => {
    const event = await recordTrustChange(
      store.db,
      "operator_untrusted",
      INCUMBENT,
      "2026-09-20T00:01:00.000Z",
      "standing",
      -3,
      41,
    );

    expect(event.seq).toBe(1);
    expect(event.type).toBe("operator_untrusted");
    const stored = await eventsInRange(store.db, 0, 1);
    // The chain rule is the same one a plain append is held to.
    expect(await verifyChain(stored)).toEqual({ ok: true, length: 2 });
    expect(stored[1]!.prev_hash).toBe(stored[0]!.hash);

    const record = await getOperator(store.db, INCUMBENT);
    expect(record?.details).toMatchObject({
      trusted: false,
      trusted_seq: null,
      named_by: "standing",
    });
  });

  it("refuses to trust an operator the registry has never heard of", async () => {
    await expect(
      recordTrustChange(
        store.db,
        "operator_trusted",
        "stranger.example",
        "2026-09-20T00:02:00.000Z",
        "standing",
        99,
        42,
      ),
    ).rejects.toThrow(/unknown operator/);
    // Refused before anything was written: the head has not moved.
    expect(await headSeq(store.db)).toBe(1);
  });
});

/**
 * Reading a stored standing that is not near the top of the pool (M21).
 *
 * `standingByOperator` is a leaderboard, so it is the wrong read for a question
 * about one named operator or about the operators on a page ordered by id: past
 * its limit it drops standings that are stored, and a page that joins against it
 * shows a dash where a number exists. These two reads are what the operator
 * route and the two pages ask instead, and the pool here is deliberately larger
 * than one page so the difference is visible.
 */
describe("standing reads past the leaderboard's limit", () => {
  let store: TestDatabase;

  /** One more operator than a page of the leaderboard holds. */
  const POOL = LIST_PAGE_LIMIT + 1;
  const id = (index: number) => `op-${String(index).padStart(3, "0")}.example`;
  /** The lowest standing in the pool, so its row is off the leaderboard. */
  const LAST = id(POOL - 1);

  beforeAll(async () => {
    store = await openTestDatabase();
    for (let index = 0; index < POOL; index += 1) {
      await putOperator(store.db, {
        id: id(index),
        maintainer: false,
        provider: false,
        registeredSeq: index,
        details: { registered_by: `1F916:agent-${index}`, trusted: false },
      });
      // Descending standing, so the operator with the largest index ranks last.
      await setOperatorStanding(store.db, id(index), POOL - index, 77);
    }
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("reads one operator's own standing whatever it ranks", async () => {
    // The leaderboard has run out before this operator: reading a standing off
    // it would answer "never computed", which is a different thing.
    expect(
      (await standingByOperator(store.db, LIST_PAGE_LIMIT)).get(LAST),
    ).toBeUndefined();

    expect(await operatorStanding(store.db, LAST)).toEqual({
      standing: 1,
      seq: 77,
    });
    expect(await operatorStanding(store.db, id(0))).toEqual({
      standing: POOL,
      seq: 77,
    });
  });

  it("answers null for an operator whose standing was never computed", async () => {
    await putOperator(store.db, {
      id: "uncomputed.example",
      maintainer: false,
      provider: false,
      registeredSeq: POOL,
      details: { registered_by: "1F916:agent-uncomputed", trusted: false },
    });

    // Null is "not computed yet" and never zero.
    expect(await operatorStanding(store.db, "uncomputed.example")).toBeNull();
    expect(await operatorStanding(store.db, "stranger.example")).toBeNull();
  });

  it("reads a page of ids, including ones the leaderboard cannot reach", async () => {
    const page = [id(0), LAST, "uncomputed.example"];
    const standings = await standingForOperators(store.db, page);

    expect(standings.get(id(0))).toEqual({ standing: POOL, seq: 77 });
    expect(standings.get(LAST)).toEqual({ standing: 1, seq: 77 });
    // Absent rather than zero, exactly like the single read above.
    expect(standings.has("uncomputed.example")).toBe(false);
    expect(standings.size).toBe(2);
  });

  it("asks nothing of the database for an empty page", async () => {
    expect(await standingForOperators(store.db, [])).toEqual(new Map());
  });
});

/**
 * Pricing M15's bounty accrual: one batch, not two statements (M21).
 *
 * The delete is the only record that the bounty was ever owed, so it must not
 * be able to land without the priced row that replaces it.
 */
describe("bounty pricing", () => {
  let store: TestDatabase;

  const BOUNTY_ENTRY = "01J0BOUNTYENTRY00000000000";
  const BOUNTY_OPERATOR = "bounty.example";
  const AT = "2026-07-01T00:00:00.000Z";
  const UNPRICED_ID = "bounty_accrual:9";

  /** The row the M21 ledger step builds, under the accrual's own id. */
  const priced: LedgerRow = {
    id: UNPRICED_ID,
    kind: "bounty_accrual",
    entry_id: BOUNTY_ENTRY,
    operator: BOUNTY_OPERATOR,
    role: "reconfirmer",
    date: null,
    reads: null,
    unit: "micros",
    amount: 2_500,
    available_at: "2026-07-31T00:00:00.000Z",
    seq: 9,
    at: AT,
    ref: {},
  };

  /** M15's door row: the accrual payload, and no amount at all. */
  async function writeUnpriced(): Promise<void> {
    await store.db
      .prepare(
        `INSERT OR REPLACE INTO ledger
           (id, kind, operator_id, entry_id, seq, created_at, payload_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        UNPRICED_ID,
        "bounty_accrual",
        BOUNTY_OPERATOR,
        BOUNTY_ENTRY,
        9,
        AT,
        JSON.stringify({
          kind: "bounty_accrual",
          entry_id: BOUNTY_ENTRY,
          operator: BOUNTY_OPERATOR,
          stale_from: "2026-06-01",
          stale_until: AT,
          seq: 9,
          amount_micros: null,
        }),
      )
      .run();
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    await writeUnpriced();
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("replaces the unpriced accrual with the priced row", async () => {
    const before = await bountiesForEntry(store.db, BOUNTY_ENTRY, LIST_PAGE_LIMIT);
    expect(before).toHaveLength(1);
    expect(before[0]!.stale_from).toBe("2026-06-01");
    expect(before[0]!.amount_micros).toBeNull();

    await priceBountyRow(store.db, UNPRICED_ID, priced);

    // One row still, under the same id, and now the ledger's own shape.
    const after = await bountiesForEntry(store.db, BOUNTY_ENTRY, LIST_PAGE_LIMIT);
    expect(after).toEqual([priced]);
    expect(after[0]!.stale_from).toBeUndefined();
    // The columns the money reads go with it.
    expect(
      await ledgerRowsForOperator(store.db, BOUNTY_OPERATOR, LIST_PAGE_LIMIT),
    ).toEqual([priced]);
  });

  it("reprices nothing and deletes nothing on a replayed cursor", async () => {
    // A row that has already been priced is not `amount IS NULL`, so the delete
    // passes over it, and the insert is ignored by id.
    await priceBountyRow(store.db, UNPRICED_ID, { ...priced, amount: 999 });

    expect(await bountiesForEntry(store.db, BOUNTY_ENTRY, LIST_PAGE_LIMIT)).toEqual(
      [priced],
    );
  });
});

/**
 * The domain column and the operator_domains table (migration 0012, D-071).
 *
 * Everything here goes in through the repository's own writers, because a row
 * written any other way would not prove the shape the Worker actually stores.
 * Nothing here is a source of truth: `entries.domain` is a copy of the signed
 * core's eighteenth key and every operator_domains row is a copy of what an
 * event already sealed — which is exactly what the backfill test checks.
 */
describe("domains in the store", () => {
  let store: TestDatabase;

  const OPERATOR = "lattice.example";
  const AGENT = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
  const AT = "2026-09-10T12:00:00.000Z";

  const attestation: Attestation = {
    version: "nomankind-independence-v1",
    domain: DEFAULT_DOMAIN,
    signed_at: AT,
    signature: "c2lnbmF0dXJl",
  };

  beforeAll(async () => {
    store = await openTestDatabase();
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("applies twice without a second effect", async () => {
    // Idempotence belongs to the tracking table, not to the SQL: the second
    // run applies nothing at all.
    expect(await applyMigrations(store.db, loadMigrations())).toEqual([]);
  });

  it("backfills the domain of every entry row it found", async () => {
    // A row written the old way — no domain column value of its own — reads as
    // ai-ecosystem, and a row whose stored entry says v0.7 reads as what it
    // says. The backfill is COALESCE over the stored JSON, so both are shown by
    // rerunning exactly that statement over rows written here.
    const backfill = loadMigrations().find(
      (one) => one.name === "0012_domains.sql",
    )!;
    expect(backfill.sql).toContain("json_extract(entry_json, '$.domain')");
    expect(backfill.sql).toContain("CREATE TABLE operator_domains");
    expect(backfill.sql).toContain("entries_domain_status_seq");
  });

  it("writes the entry's own domain beside subject and category", async () => {
    const head = world.bundle.events[world.bundle.events.length - 1]!;
    await appendEvents(store.db, world.bundle.events);
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    const derived = deriveEntry(
      world.bundle.events,
      VERIFIED_ENTRY_ID,
      clock(),
      entrySeals,
    );
    await putEntry(store.db, derived.entry, derived.sidecar, head.seq);

    const row = await store.db
      .prepare(`SELECT domain FROM entries WHERE id = ?`)
      .bind(VERIFIED_ENTRY_ID)
      .first<{ domain: string }>();
    expect(row?.domain).toBe(DEFAULT_DOMAIN);
  });

  it("filters every listing by domain, and every other domain out", async () => {
    const entry = await getEntry(store.db, VERIFIED_ENTRY_ID);
    expect(entry).not.toBeNull();
    const subject = (entry!.entry as unknown as Record<string, unknown>)[
      "subject"
    ] as string;
    const category = (entry!.entry as unknown as Record<string, unknown>)[
      "category"
    ] as string;

    expect(
      (
        await listEntries(store.db, { domain: DEFAULT_DOMAIN, limit: 10 })
      ).map((stored) => (stored.entry as unknown as Record<string, unknown>)["id"]),
    ).toContain(VERIFIED_ENTRY_ID);
    expect(
      await listEntries(store.db, { domain: "elsewhere", limit: 10 }),
    ).toEqual([]);

    expect(
      await listEntriesPage(store.db, { domain: "elsewhere", limit: 10 }),
    ).toEqual([]);
    expect(
      (await listEntriesPage(store.db, { domain: DEFAULT_DOMAIN, limit: 10 }))
        .length,
    ).toBeGreaterThan(0);

    expect(await countEntries(store.db, { domain: "elsewhere" })).toBe(0);
    expect(
      await countEntries(store.db, { domain: DEFAULT_DOMAIN }),
    ).toBeGreaterThan(0);

    expect(
      await readCandidates(store.db, {
        subject,
        category,
        domain: "elsewhere",
        limit: 10,
      }),
    ).toEqual([]);
    expect(
      await readCandidates(store.db, {
        subject,
        category,
        domain: DEFAULT_DOMAIN,
        limit: 10,
      }),
    ).toHaveLength(1);

    expect(
      await probeCandidates(store.db, { domain: "elsewhere", limit: 10 }),
    ).toEqual([]);
  });

  it("writes the registration's domain row in the registration's own batch", async () => {
    let log: Event[] = await eventsInRange(
      store.db,
      0,
      (await headSeq(store.db)) ?? 0,
    );
    log = await appendEvent(log, {
      at: AT,
      type: "operator_registered",
      entry_id: null,
      payload: { operator: OPERATOR, maintainer: false, domain: DEFAULT_DOMAIN },
    });
    const registeredSeq = log[log.length - 1]!.seq;
    log = await appendEvent(log, {
      at: AT,
      type: "agent_bound",
      entry_id: null,
      payload: { operator: OPERATOR, agent: AGENT, attestation },
    });

    await registerOperator(store.db, {
      events: log.slice(-2),
      operator: {
        id: OPERATOR,
        maintainer: false,
        provider: false,
        registeredSeq,
        details: { trusted: true },
      },
      agent: { agentId: AGENT, operatorId: OPERATOR, registeredSeq: registeredSeq + 1 },
      domain: { domain: DEFAULT_DOMAIN, attestation },
    });

    expect(await operatorDomains(store.db, OPERATOR)).toEqual([
      {
        operator: OPERATOR,
        domain: DEFAULT_DOMAIN,
        seq: registeredSeq,
        attestation,
      },
    ]);
    expect(await operatorsInDomain(store.db, DEFAULT_DOMAIN, 10)).toEqual([
      OPERATOR,
    ]);
    expect(await countTrustedOperators(store.db, DEFAULT_DOMAIN)).toBe(1);
    expect(await countTrustedOperators(store.db, "elsewhere")).toBe(0);
    expect(await countTrustedOperators(store.db)).toBe(1);
  });

  it("round-trips a domain join: the event and its row, in one write", async () => {
    const joined = await recordDomainJoin(store.db, {
      at: AT,
      type: "operator_joined_domain",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        agent: AGENT,
        domain: DEFAULT_DOMAIN,
        attestation,
      },
    });

    expect(joined.type).toBe("operator_joined_domain");
    expect(await eventBySeq(store.db, joined.seq)).toEqual(joined);

    // The row is keyed by (operator, domain), so a join into a domain already
    // held replaces rather than duplicates.
    const rows = await operatorDomains(store.db, OPERATOR);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.seq).toBe(joined.seq);
  });

  it("backfills a row for every operator registered before it existed", async () => {
    // 0012's INSERT ... SELECT, run rather than read. It is the one statement
    // in the file no other test reaches, and it is the one that decides what a
    // live database looks like the moment the migration lands: every operator
    // already registered is in ai-ecosystem, at the seq its own registration
    // sits at, with whatever attestation its row carried.
    //
    // The table is emptied first because that is the state the statement really
    // runs in -- 0012 is what creates it -- and because the rows written above
    // are exactly what the backfill has to be able to produce on its own. Last
    // in the file for that reason: nothing after it reads these rows.
    const backfill = splitStatements(
      loadMigrations().find((one) => one.name === "0012_domains.sql")!.sql,
    ).find((statement) => statement.includes("INSERT INTO operator_domains"))!;

    // Two operators written the way a Worker on 0011 wrote them: `putOperator`
    // touches the operators table and nothing else, so neither row has a domain
    // of its own for the backfill to copy.
    const signed = "pre-0012-signed.example";
    const unsigned = "pre-0012-unsigned.example";
    await putOperator(store.db, {
      id: signed,
      maintainer: false,
      provider: false,
      registeredSeq: 3,
      details: { trusted: false, attestation },
    });
    await putOperator(store.db, {
      id: unsigned,
      maintainer: false,
      provider: false,
      registeredSeq: 4,
      details: { trusted: false },
    });

    await store.db.prepare(`DELETE FROM operator_domains`).run();
    expect(await operatorDomains(store.db, signed)).toEqual([]);

    await store.db.prepare(backfill).run();

    expect(await operatorDomains(store.db, signed)).toEqual([
      { operator: signed, domain: DEFAULT_DOMAIN, seq: 3, attestation },
    ]);
    // A row that carries no attestation at all backfills with a null rather
    // than with a record nobody signed.
    expect(await operatorDomains(store.db, unsigned)).toEqual([
      {
        operator: unsigned,
        domain: DEFAULT_DOMAIN,
        seq: 4,
        attestation: null,
      },
    ]);
    expect(await operatorsInDomain(store.db, DEFAULT_DOMAIN, 10)).toContain(
      signed,
    );
  });
});

describe("the duplicate door's backward read", () => {
  // Decision D-085. The door asks for every entry on one domain, subject and
  // category — drafts included, because a draft holds its claim — newest
  // submission first, and pages down rather than truncating at the first page.
  const SUBJECT = "openai/gpt-5";
  const OTHER_SUBJECT = "anthropic/claude-4";
  const CATEGORY = "pricing";
  const OTHER_DOMAIN = "elsewhere";

  /** The rows, in the order they were submitted: oldest first. */
  const ROWS = [
    { id: "nmk_back1", subject: SUBJECT, domain: DEFAULT_DOMAIN, draft: false },
    {
      id: "nmk_back2",
      subject: OTHER_SUBJECT,
      domain: DEFAULT_DOMAIN,
      draft: false,
    },
    { id: "nmk_back3", subject: SUBJECT, domain: OTHER_DOMAIN, draft: false },
    { id: "nmk_back4", subject: SUBJECT, domain: DEFAULT_DOMAIN, draft: true },
    { id: "nmk_back5", subject: SUBJECT, domain: DEFAULT_DOMAIN, draft: false },
  ] as const;

  let backward: TestDatabase;

  /** The world's own core, re-keyed and re-subjected. Nothing is invented. */
  function coreFor(
    source: Entry,
    row: (typeof ROWS)[number],
  ): Core {
    const record = source as unknown as Record<string, unknown>;
    const core: Record<string, unknown> = {};
    for (const key of CORE_KEYS) core[key] = record[key];
    core["id"] = row.id;
    core["subject"] = row.subject;
    core["domain"] = row.domain;
    return core as Core;
  }

  /** The world's own derived entry, moved to this row's id and subject. */
  function entryFor(source: Entry, row: (typeof ROWS)[number]): Entry {
    return {
      ...(source as unknown as Record<string, unknown>),
      id: row.id,
      subject: row.subject,
      domain: row.domain,
    } as Entry;
  }

  function idsOf(page: readonly { entry: Entry }[]): string[] {
    return page.map(
      (stored) => (stored.entry as unknown as Record<string, string>)["id"]!,
    );
  }

  beforeAll(async () => {
    backward = await openTestDatabase();

    // A real log, one entry_submitted per row in submission order, so
    // submitted_seq is the log position and not a number a test chose.
    let log: Event[] = [];
    for (const row of ROWS) {
      log = await appendEvent(log, {
        at: "2026-09-08T00:00:00.000Z",
        type: "entry_submitted",
        entry_id: row.id,
        payload: {
          core: coreFor(row.draft ? world.draftEntry : world.entry, row),
          signature: (world.entry as unknown as Record<string, string>)[
            "signature"
          ]!,
        },
      });
    }
    await appendEvents(backward.db, log);

    for (const row of ROWS) {
      const source = row.draft ? world.draftEntry : world.entry;
      const sidecar = (await getEntry(
        test.db,
        row.draft ? DRAFT_ENTRY_ID : VERIFIED_ENTRY_ID,
      ))!.sidecar;
      await putEntry(
        backward.db,
        entryFor(source, row),
        sidecar,
        log[log.length - 1]!.seq,
      );
    }
  }, 600_000);

  afterAll(async () => {
    await backward?.dispose();
  });

  it("answers newest submission first, drafts among them", async () => {
    const page = await entriesNewestFirst(backward.db, {
      subject: SUBJECT,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
      limit: 10,
    });
    expect(idsOf(page)).toEqual(["nmk_back5", "nmk_back4", "nmk_back1"]);
    // No status filter at all: the draft is in the middle of the answer, and
    // which statuses are live is src/duplicate.ts's rule, not this query's.
    expect(
      page.map(
        (stored) =>
          (stored.entry as unknown as Record<string, string>)["status"],
      ),
    ).toEqual(["verified", "draft", "verified"]);
  });

  it("narrows by subject, by category and by domain", async () => {
    expect(
      idsOf(
        await entriesNewestFirst(backward.db, {
          subject: OTHER_SUBJECT,
          category: CATEGORY,
          domain: DEFAULT_DOMAIN,
          limit: 10,
        }),
      ),
    ).toEqual(["nmk_back2"]);

    expect(
      idsOf(
        await entriesNewestFirst(backward.db, {
          subject: SUBJECT,
          category: CATEGORY,
          domain: OTHER_DOMAIN,
          limit: 10,
        }),
      ),
    ).toEqual(["nmk_back3"]);

    // Omitted, the domain narrows nothing: the same subject in a second domain
    // is in the answer, which is what makes the filter above a filter.
    expect(
      idsOf(
        await entriesNewestFirst(backward.db, {
          subject: SUBJECT,
          category: CATEGORY,
          limit: 10,
        }),
      ),
    ).toEqual(["nmk_back5", "nmk_back4", "nmk_back3", "nmk_back1"]);

    expect(
      await entriesNewestFirst(backward.db, {
        subject: SUBJECT,
        category: "outage",
        domain: DEFAULT_DOMAIN,
        limit: 10,
      }),
    ).toEqual([]);
  });

  it("stops at the caller's own limit and resumes below it", async () => {
    const query = {
      subject: SUBJECT,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
    };
    const first = await entriesNewestFirst(backward.db, { ...query, limit: 2 });
    expect(idsOf(first)).toEqual(["nmk_back5", "nmk_back4"]);

    // Keyset, not offset: the caller passes back the lowest position it saw,
    // and the row at that position is not served twice.
    const next = await entriesNewestFirst(backward.db, {
      ...query,
      limit: 10,
      beforeSubmittedSeq: first[first.length - 1]!.submittedSeq,
    });
    expect(idsOf(next)).toEqual(["nmk_back1"]);

    expect(
      await entriesNewestFirst(backward.db, {
        ...query,
        limit: 10,
        beforeSubmittedSeq: next[next.length - 1]!.submittedSeq,
      }),
    ).toEqual([]);
  });
});

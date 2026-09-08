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
  appendEvent,
  buildAnchor,
  buildSeal,
  buildSubmittedCore,
  deriveEntry,
  sealsForEntries,
  utcDay,
  verifyChain,
  type Anchor,
  type Attestation,
  type Core,
  type Event,
  type OpenAssignment,
  type Seal,
} from "../src/index.js";
import { applyMigrations } from "../src/storage/migrate.js";
import {
  EventAppendError,
  agentsForOperator,
  appendEvents,
  captureForHash,
  capturesForEntry,
  eventBySeq,
  eventsAfter,
  eventsForEntry,
  eventsInRange,
  eventsOfType,
  getAnchor,
  getEntry,
  getOperator,
  headSeq,
  latestAnchor,
  latestSeal,
  listEntries,
  listOperators,
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
  putSeal,
  registerOperator,
  sealCovering,
  sealsBetween,
  submitEntry,
  trustOperator,
  type AgentRecord,
  type CaptureRecord,
  type OperatorRecord,
} from "../src/storage/repository.js";
import {
  archiveCapture,
  readCapture,
  readSidecar,
  type Sidecar,
} from "../src/storage/r2.js";
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

beforeAll(async () => {
  world = await buildVerifyWorld({ withReconfirmation: true });
  test = await openTestDatabase();
  await appendEvents(test.db, world.bundle.events);
  for (const seal of world.bundle.seals) await putSeal(test.db, seal);

  const previous = world.bundle.seals[world.bundle.seals.length - 1]!;
  const built = await buildSeal(world.bundle.events, previous, clock());
  if (!built.ok) throw new Error(`storage.test: buildSeal ${built.reason}`);
  secondSeal = built.seal;
});

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
  });

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
  });

  it("round-trips an operator", async () => {
    const maintainer = await getOperator(test.db, MAINTAINER_OPERATOR);
    expect(maintainer).toMatchObject({
      id: MAINTAINER_OPERATOR,
      maintainer: true,
      provider: false,
    });
    expect(maintainer!.details).toEqual({ maintainer: true, provider: false });

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
  });

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
  });

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

describe("migrations", () => {
  it("applies nothing the second time", async () => {
    expect(await applyMigrations(test.db, loadMigrations())).toEqual([]);
  });

  it("records the migration under the name wrangler would use", async () => {
    const applied = await test.db
      .prepare(`SELECT name FROM "d1_migrations" ORDER BY id`)
      .all<{ name: string }>();
    expect(applied.results.map((row) => row.name)).toEqual([
      "0001_init.sql",
      "0002_registry.sql",
      "0003_captures.sql",
    ]);
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
  });

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
  });

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
  });

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
  });

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

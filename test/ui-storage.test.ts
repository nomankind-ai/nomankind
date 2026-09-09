/**
 * The reads the browsing UI adds, against a real D1.
 *
 * miniflare's D1 is the same SQLite engine Cloudflare runs, so these exercise the
 * actual query planner, the actual JSON extraction and the actual ordering rather
 * than a fake that would agree with whatever the code did. Every fixture goes in
 * through the repository's own writers — `appendEvents`, `putEntry`,
 * `registerOperator`, `trustOperator`, `putSeal` — because a row written any
 * other way would not prove the shape the Worker actually stores.
 *
 * Nothing here derives anything. The entries carry the status, the staleness and
 * the effective tier that derivation would have computed, and the counts read
 * them back exactly as stored.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { extractCore, type Core } from "../src/core.js";
import {
  appendEvent,
  type ApproverRecord,
  type Attestation,
  type Event,
  type EventInput,
} from "../src/events.js";
import type { Sidecar } from "../src/derive.js";
import type { Entry } from "../src/schema.js";
import type { Seal } from "../src/seal.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  agentCountsByOperator,
  appendEvents,
  countEntries,
  countSeals,
  countTrustedOperators,
  listEntriesPage,
  putEntry,
  putOperator,
  putSeal,
  registerOperator,
  trustOperator,
  validationCountsByOperator,
  validationsByOperator,
  type OperatorRecord,
} from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ATTESTATION: Attestation = {
  version: "attest-v1",
  signed_at: "2026-08-01T00:00:00.000Z",
  signature: "c2lnbmF0dXJl",
};

/** A fixture entry: what derivation would have left behind, spelled out. */
interface Fixture {
  readonly id: string;
  readonly subject: string;
  readonly category: string;
  readonly status: string;
  /** The sidecar's effective_tier: the tier the entry actually verified at. */
  readonly effectiveTier: string | null;
  readonly stale: boolean;
  readonly expiresAt: string | null;
}

const FIXTURES: readonly Fixture[] = [
  {
    id: "nmk_e1",
    subject: "openai/gpt-5",
    category: "pricing",
    status: "verified",
    effectiveTier: "observed",
    stale: false,
    expiresAt: "2026-12-01",
  },
  {
    id: "nmk_e2",
    subject: "anthropic/claude",
    category: "limit",
    status: "verified",
    effectiveTier: "stated",
    stale: true,
    expiresAt: "2026-06-01",
  },
  {
    id: "nmk_e3",
    subject: "openai/gpt-5",
    category: "behavior",
    status: "draft",
    effectiveTier: null,
    stale: false,
    expiresAt: null,
  },
  {
    id: "nmk_e4",
    subject: "google/gemini",
    category: "pricing",
    status: "rejected",
    effectiveTier: "stated",
    stale: false,
    expiresAt: null,
  },
  {
    id: "nmk_e5",
    subject: "openai/gpt-5",
    category: "pricing",
    status: "verified",
    effectiveTier: "observed",
    stale: true,
    expiresAt: "2026-05-01",
  },
];

function entryOf(fixture: Fixture): Entry {
  return {
    id: fixture.id,
    subject: fixture.subject,
    category: fixture.category,
    claim: `${fixture.subject} ${fixture.category} changed`,
    before: "old",
    after: "new",
    effective_at: "2026-04-01",
    evidence_tier: fixture.effectiveTier ?? "stated",
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
    staleness_window_days: fixture.expiresAt === null ? null : 90,
    verified_at: fixture.status === "verified" ? "2026-04-03T00:00:00.000Z" : null,
    last_confirmed: "2026-04-03",
    expires_at: fixture.expiresAt,
    stale: fixture.stale,
    superseded_by: null,
    overturned_by: null,
    confidence: null,
  };
}

function sidecarOf(fixture: Fixture): Sidecar {
  return {
    needs_replacement: false,
    effective_tier: fixture.effectiveTier as Sidecar["effective_tier"],
    test_verdict: null,
    trusted_count_at_decision: null,
    read_share_slots: null,
  };
}

function sealAt(seq: number, firstSeq: number, lastSeq: number): Seal {
  const digit = String(seq % 10);
  return {
    seq,
    first_seq: firstSeq,
    last_seq: lastSeq,
    size: lastSeq - firstSeq + 1,
    root: `sha256:${digit.repeat(64)}`,
    sealed_at: `2026-04-0${seq + 4}T00:00:00.000Z`,
    prev_hash: seq === 0 ? null : `sha256:${String(seq - 1).repeat(64)}`,
    hash: `sha256:${String(seq).repeat(64)}`,
    witnesses: [],
    registry: null,
  };
}

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

describe("the browsing reads", () => {
  let world: TestDatabase;
  let db: D1Like;
  /** The log as the fixtures built it, so every append links to the last hash. */
  let chain: Event[] = [];
  /** Each fixture's submitted position, which is what the listings page by. */
  const positions = new Map<string, number>();

  /** Seal one more event onto the fixture chain and hand back just that event. */
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
        payout_status: "verified",
      },
    };
  }

  beforeAll(async () => {
    world = await openTestDatabase();
    db = world.db;

    // The submissions, in fixture order, so submitted_seq runs 0..4.
    const submissions: Event[] = [];
    for (const fixture of FIXTURES) {
      const core: Core = extractCore(entryOf(fixture));
      const event = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "entry_submitted",
        entry_id: fixture.id,
        payload: { core, signature: "c2lnbmF0dXJl" },
      });
      positions.set(fixture.id, event.seq);
      submissions.push(event);
    }
    await appendEvents(db, submissions);
    for (const fixture of FIXTURES) {
      await putEntry(db, entryOf(fixture), sidecarOf(fixture), chain.length - 1);
    }

    // Three operators registered through the repository, so the stored shape is
    // the one the Worker writes; two of them then trusted by an event.
    for (const id of ["op-alpha", "op-beta", "op-gamma"]) {
      const registered = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "operator_registered",
        entry_id: null,
        payload: { operator: id, maintainer: false },
      });
      const bound = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "agent_bound",
        entry_id: null,
        payload: {
          operator: id,
          agent: `1F916:${id}-agent`,
          attestation: ATTESTATION,
        },
      });
      await registerOperator(db, {
        events: [registered, bound],
        operator: operatorRecord(id, registered.seq, null),
        agent: {
          agentId: `1F916:${id}-agent`,
          operatorId: id,
          registeredSeq: bound.seq,
        },
      });
    }
    for (const id of ["op-alpha", "op-beta"]) {
      const event = await add({
        at: "2026-04-02T00:00:00.000Z",
        type: "operator_trusted",
        entry_id: null,
        payload: { operator: id },
      });
      await trustOperator(db, {
        event,
        operator: operatorRecord(id, event.seq - 1, event.seq),
      });
    }
    // A row that never carried the field at all: null is not trusted.
    await putOperator(db, {
      id: "op-delta",
      maintainer: false,
      provider: false,
      registeredSeq: 0,
      details: {},
    });

    // Two seals.
    await putSeal(db, sealAt(0, 0, 4));
    await putSeal(db, sealAt(1, 5, chain.length - 1));

    // Three decisions, in signing order, so the newest seq is the newest one.
    const validations: Event[] = [];
    for (const [operator, decision, entryId, signedAt] of [
      ["op-alpha", "approve", "nmk_e1", "2026-09-01T00:00:00.000Z"],
      ["op-beta", "approve", "nmk_e1", "2026-09-02T00:00:00.000Z"],
      ["op-alpha", "reject", "nmk_e4", "2026-09-03T00:00:00.000Z"],
    ] as const) {
      validations.push(
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
    await appendEvents(db, validations);
  });

  afterAll(async () => {
    await world.dispose();
  });

  it("counts every entry, and counts by status and by staleness", async () => {
    expect(await countEntries(db, {})).toBe(5);
    expect(await countEntries(db, { status: "verified" })).toBe(3);
    expect(await countEntries(db, { status: "draft" })).toBe(1);
    expect(await countEntries(db, { stale: true })).toBe(2);
    expect(await countEntries(db, { stale: false })).toBe(3);
    expect(await countEntries(db, { status: "verified", stale: true })).toBe(2);
    expect(await countEntries(db, { status: "overturned" })).toBe(0);
  });

  it("lists newest sealed position first", async () => {
    const rows = await listEntriesPage(db, { limit: 10 });
    expect(rows.map((row) => row.entry["id"])).toEqual([
      "nmk_e5",
      "nmk_e4",
      "nmk_e3",
      "nmk_e2",
      "nmk_e1",
    ]);
    expect(rows[0]!.submittedSeq).toBe(positions.get("nmk_e5"));
  });

  it("narrows by category, by status, by effective tier and by staleness", async () => {
    const ids = async (query: Parameters<typeof listEntriesPage>[1]) =>
      (await listEntriesPage(db, query)).map((row) => row.entry["id"]);

    expect(await ids({ limit: 10, category: "pricing" })).toEqual([
      "nmk_e5",
      "nmk_e4",
      "nmk_e1",
    ]);
    expect(await ids({ limit: 10, status: "verified" })).toEqual([
      "nmk_e5",
      "nmk_e2",
      "nmk_e1",
    ]);
    // The tier filter reads the sidecar's effective_tier, not the entry's claim
    // about its own tier.
    expect(await ids({ limit: 10, tier: "observed" })).toEqual([
      "nmk_e5",
      "nmk_e1",
    ]);
    expect(await ids({ limit: 10, tier: "stated" })).toEqual([
      "nmk_e4",
      "nmk_e2",
    ]);
    expect(await ids({ limit: 10, stale: true })).toEqual(["nmk_e5", "nmk_e2"]);
    expect(
      await ids({ limit: 10, category: "pricing", status: "verified", stale: true }),
    ).toEqual(["nmk_e5"]);
    expect(await ids({ limit: 10, category: "outage" })).toEqual([]);
  });

  it("pages backward by keyset, strictly before the position it was given", async () => {
    const first = await listEntriesPage(db, { limit: 2 });
    expect(first.map((row) => row.entry["id"])).toEqual(["nmk_e5", "nmk_e4"]);
    const second = await listEntriesPage(db, {
      limit: 2,
      beforeSubmittedSeq: first[first.length - 1]!.submittedSeq,
    });
    expect(second.map((row) => row.entry["id"])).toEqual(["nmk_e3", "nmk_e2"]);
    const third = await listEntriesPage(db, {
      limit: 2,
      beforeSubmittedSeq: second[second.length - 1]!.submittedSeq,
    });
    expect(third.map((row) => row.entry["id"])).toEqual(["nmk_e1"]);
    expect(
      await listEntriesPage(db, { limit: 2, beforeSubmittedSeq: 0 }),
    ).toEqual([]);
  });

  it("counts the trusted pool from the stored registry rows", async () => {
    expect(await countTrustedOperators(db)).toBe(2);
  });

  it("counts the seals", async () => {
    expect(await countSeals(db)).toBe(2);
  });

  it("counts validations per operator, with the last one each signed", async () => {
    expect(await validationCountsByOperator(db, 10)).toEqual([
      {
        operator: "op-alpha",
        count: 2,
        lastSignedAt: "2026-09-03T00:00:00.000Z",
      },
      {
        operator: "op-beta",
        count: 1,
        lastSignedAt: "2026-09-02T00:00:00.000Z",
      },
    ]);
  });

  it("counts the agents each operator has bound, in one grouped read", async () => {
    // Three operators each bound one agent through registerOperator; op-delta was
    // written straight to the table and bound none, so it has no row at all —
    // the directory reads a missing operator as zero, which is what it is.
    expect(await agentCountsByOperator(db, 10)).toEqual([
      { operator: "op-alpha", count: 1 },
      { operator: "op-beta", count: 1 },
      { operator: "op-gamma", count: 1 },
    ]);

    // The caller's limit, like every other read here: this module holds no page
    // size of its own.
    expect(await agentCountsByOperator(db, 1)).toEqual([
      { operator: "op-alpha", count: 1 },
    ]);
  });

  it("takes the caller's limit and holds no page size of its own", async () => {
    const one = await validationCountsByOperator(db, 1);
    expect(one).toHaveLength(1);
    expect(one[0]!.operator).toBe("op-alpha");
    expect(await validationsByOperator(db, "op-alpha", 1)).toHaveLength(1);
  });

  it("lists one operator's decisions, newest first", async () => {
    const alpha = await validationsByOperator(db, "op-alpha", 10);
    expect(alpha.map((row) => [row.entryId, row.decision])).toEqual([
      ["nmk_e4", "reject"],
      ["nmk_e1", "approve"],
    ]);
    expect(alpha[0]!.signed_at).toBe("2026-09-03T00:00:00.000Z");
    expect(alpha[0]!.seq).toBeGreaterThan(alpha[1]!.seq);
    expect(await validationsByOperator(db, "op-gamma", 10)).toEqual([]);
  });
});

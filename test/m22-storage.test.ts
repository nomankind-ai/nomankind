/**
 * The attestation store, against a real D1.
 *
 * miniflare's D1 is the same SQLite engine Cloudflare runs, so these exercise
 * the actual migration, the actual query planner and the actual JSON round-trip
 * rather than a fake that would agree with whatever the code did. Every fixture
 * goes in through the repository's own writers, because a row written any other
 * way would not prove the shape the Worker actually stores.
 *
 * Nothing here derives anything by hand: the attestation each writer stores is
 * what `deriveAttestation` made of the log that already held the sealed event.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { extractCore, type Core } from "../src/core.js";
import { deriveAttestation, type DerivedAttestation } from "../src/attest.js";
import type { Clock, Sidecar } from "../src/derive.js";
import {
  appendEvent,
  type AttestationScorer,
  type Event,
  type EventInput,
  type Probe,
} from "../src/events.js";
import type { ProbeAnswer } from "../src/probe.js";
import type { Entry } from "../src/schema.js";
import type { D1Like } from "../src/storage/d1.js";
import { applyMigrations } from "../src/storage/migrate.js";
import {
  appendEvents,
  attestationsForOperator,
  dueAttestations,
  eventsForAttestation,
  getAttestation,
  listAttestations,
  openAttestationForModel,
  probeCandidates,
  putEntry,
  recordAttestationAnswers,
  recordAttestationExpired,
  recordAttestationRequest,
  recordAttestationScore,
} from "../src/storage/repository.js";
import { loadMigrations, openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";

const CLOCK: Clock = { now: "2026-09-10T00:00:00.000Z" };
const SIGNATURE = "c2lnbmF0dXJl";

/** A fixture entry: what derivation would have left behind, spelled out. */
interface Fixture {
  readonly id: string;
  readonly status: string;
  readonly effectiveTier: "stated" | "observed" | null;
  readonly stale: boolean;
}

const ENTRIES: readonly Fixture[] = [
  { id: "nmk_a01", status: "verified", effectiveTier: "observed", stale: false },
  { id: "nmk_a02", status: "verified", effectiveTier: "observed", stale: false },
  { id: "nmk_a03", status: "verified", effectiveTier: "observed", stale: false },
  // Excluded, one reason each: past its window, validated as a document, and
  // never verified at all.
  { id: "nmk_b01", status: "verified", effectiveTier: "observed", stale: true },
  { id: "nmk_b02", status: "verified", effectiveTier: "stated", stale: false },
  { id: "nmk_b03", status: "draft", effectiveTier: null, stale: false },
];

const CANDIDATE_IDS = ["nmk_a01", "nmk_a02", "nmk_a03"];

function entryOf(fixture: Fixture): Entry {
  return {
    id: fixture.id,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "input is $1.25 per million tokens",
    before: "1.00",
    after: "1.25",
    effective_at: "2026-08-01",
    evidence_tier: fixture.effectiveTier ?? "observed",
    evidence: null,
    observation: null,
    citation: "https://example.test/pricing",
    snapshot_hash: `sha256:${"1".repeat(64)}`,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: "1F916:author",
    author_operator: "op_alpha",
    submitted_at: "2026-08-01T00:00:00.000Z",
    signature: SIGNATURE,
    approvers: [],
    reconfirmations: [],
    disputes: [],
    failure_reports: [],
    seal: null,
    staleness_window_days: 90,
    verified_at: fixture.status === "verified" ? "2026-08-02T00:00:00.000Z" : null,
    last_confirmed: "2026-08-01",
    expires_at: "2026-10-30",
    stale: fixture.stale,
    superseded_by: null,
    overturned_by: null,
    status: fixture.status,
    confidence: null,
  } as Entry;
}

function sidecarOf(fixture: Fixture): Sidecar {
  return {
    needs_replacement: false,
    effective_tier: fixture.effectiveTier,
    test_verdict: null,
    trusted_count_at_decision: null,
    read_share_slots: null,
    revalidations: [],
  };
}

const PROBES: readonly Probe[] = CANDIDATE_IDS.map((id, index) => ({
  entry_id: id,
  entry_hash: `sha256:${String(index + 1).repeat(64)}`,
}));

const ANSWERS: readonly ProbeAnswer[] = CANDIDATE_IDS.map((id) => ({
  entry_id: id,
  answer: `answer for ${id}`,
}));

const ANSWERS_HASH = `sha256:${"b".repeat(64)}`;

function scorerFor(operator: string): AttestationScorer {
  return { operator, agent: `1F916:${operator}-agent` };
}

/** One attestation under construction: the events it has, and its answers. */
class Fold {
  readonly events: Event[] = [];
  answers: readonly ProbeAnswer[] | null = null;
  probeHash = "";

  /** The attestation as it stands once `event` is folded in. */
  with(event: Event): DerivedAttestation {
    this.events.push(event);
    return deriveAttestation(this.events, CLOCK);
  }
}

describe("the attestation store", () => {
  let world: TestDatabase;
  let db: D1Like;
  const folds = new Map<string, Fold>();

  /** Open an attestation and store it, exactly as the request route does. */
  async function request(input: {
    id: string;
    model: string;
    modelOperator: string | null;
    scorers: readonly AttestationScorer[];
    requestedAt: string;
    deadline: string;
    round: number;
  }): Promise<void> {
    const fold = new Fold();
    fold.probeHash = `sha256:${String(input.round % 10).repeat(64)}`;
    folds.set(input.id, fold);
    const event: EventInput<"attestation_requested"> = {
      at: input.requestedAt,
      type: "attestation_requested",
      entry_id: null,
      payload: {
        attestation: input.id,
        domain: DEFAULT_DOMAIN,
        model: input.model,
        model_operator: input.modelOperator,
        probes: PROBES,
        probe_hash: fold.probeHash,
        probe_count: PROBES.length,
        pool_snapshot_seq: 0,
        beacon_round: input.round,
        beacon_randomness: `${"7c1f".repeat(15)}${input.round % 10}`,
        scorers: input.scorers,
        deadline: input.deadline,
      },
    };
    await recordAttestationRequest(db, {
      event,
      row: (sealed) => fold.with(sealed),
      scorers: input.scorers,
    });
  }

  async function answer(id: string, at: string): Promise<void> {
    const fold = folds.get(id)!;
    fold.answers = ANSWERS;
    await recordAttestationAnswers(db, {
      event: {
        at,
        type: "attestation_answered",
        entry_id: null,
        payload: { attestation: id, answers_hash: ANSWERS_HASH },
      },
      id,
      answers: ANSWERS,
      attestation: (sealed) => fold.with(sealed),
    });
  }

  async function score(
    id: string,
    operator: string,
    agreed: number,
    at: string,
  ): Promise<void> {
    const fold = folds.get(id)!;
    await recordAttestationScore(db, {
      event: {
        at,
        type: "attestation_scored",
        entry_id: null,
        payload: {
          attestation: id,
          record: {
            agent: `1F916:${operator}-agent`,
            operator,
            agreed,
            probe_hash: fold.probeHash,
            answers_hash: ANSWERS_HASH,
            signed_at: at,
          },
          signature: SIGNATURE,
        },
      },
      id,
      operator,
      answers: fold.answers,
      attestation: (sealed) => fold.with(sealed),
    });
  }

  async function expire(
    id: string,
    missing: readonly string[],
    at: string,
  ): Promise<void> {
    const fold = folds.get(id)!;
    await recordAttestationExpired(db, {
      event: {
        at,
        type: "attestation_expired",
        entry_id: null,
        payload: { attestation: id, missing },
      },
      id,
      answers: fold.answers,
      attestation: (sealed) => fold.with(sealed),
    });
  }

  beforeAll(async () => {
    world = await openTestDatabase();
    db = world.db;

    let chain: Event[] = [];
    const submissions: Event[] = [];
    for (const fixture of ENTRIES) {
      const core: Core = extractCore(entryOf(fixture));
      chain = await appendEvent(chain, {
        at: "2026-08-01T00:00:00.000Z",
        type: "entry_submitted",
        entry_id: fixture.id,
        payload: { core, signature: SIGNATURE },
      });
      submissions.push(chain[chain.length - 1]!);
    }
    await appendEvents(db, submissions);
    for (const fixture of ENTRIES) {
      await putEntry(db, entryOf(fixture), sidecarOf(fixture), chain.length - 1);
    }

    // A: the whole cycle, request through three scores.
    await request({
      id: "att_" + "a".repeat(32),
      model: "1F916:model-a",
      modelOperator: "op_lab",
      scorers: [scorerFor("op_s1"), scorerFor("op_s2"), scorerFor("op_s3")],
      requestedAt: "2026-09-01T00:00:00.000Z",
      deadline: "2026-09-04T00:00:00.000Z",
      round: 4201,
    });
    await answer("att_" + "a".repeat(32), "2026-09-01T01:00:00.000Z");
    await score("att_" + "a".repeat(32), "op_s1", 3, "2026-09-01T02:00:00.000Z");
    await score("att_" + "a".repeat(32), "op_s2", 2, "2026-09-01T03:00:00.000Z");
    await score("att_" + "a".repeat(32), "op_s3", 3, "2026-09-02T04:00:00.000Z");

    // B: requested, never answered, and swept.
    await request({
      id: "att_" + "b".repeat(32),
      model: "1F916:model-b",
      modelOperator: "op_lab2",
      scorers: [scorerFor("op_s1"), scorerFor("op_s4"), scorerFor("op_s5")],
      requestedAt: "2026-09-01T00:00:00.000Z",
      deadline: "2026-09-04T00:00:00.000Z",
      round: 4202,
    });
    await expire(
      "att_" + "b".repeat(32),
      ["op_s1", "op_s4", "op_s5"],
      "2026-09-04T01:00:00.000Z",
    );

    // C: open, and still inside its window.
    await request({
      id: "att_" + "c".repeat(32),
      model: "1F916:model-c",
      modelOperator: "op_lab2",
      scorers: [scorerFor("op_s2"), scorerFor("op_s4"), scorerFor("op_s6")],
      requestedAt: "2026-09-09T00:00:00.000Z",
      deadline: "2026-09-12T00:00:00.000Z",
      round: 4203,
    });

    // D: answered, and out of time.
    await request({
      id: "att_" + "d".repeat(32),
      model: "1F916:model-d",
      modelOperator: null,
      scorers: [scorerFor("op_s1"), scorerFor("op_s7"), scorerFor("op_s8")],
      requestedAt: "2026-09-05T00:00:00.000Z",
      deadline: "2026-09-08T00:00:00.000Z",
      round: 4204,
    });
    await answer("att_" + "d".repeat(32), "2026-09-05T01:00:00.000Z");

    // E: open, and out of time, with an earlier deadline than D's.
    await request({
      id: "att_" + "e".repeat(32),
      model: "1F916:model-e",
      modelOperator: "op_lab3",
      scorers: [scorerFor("op_s2"), scorerFor("op_s7"), scorerFor("op_s9")],
      requestedAt: "2026-09-03T00:00:00.000Z",
      deadline: "2026-09-06T00:00:00.000Z",
      round: 4205,
    });
  });

  afterAll(async () => {
    await world.dispose();
  });

  it("applies migration 0011 cleanly, and a second run applies nothing", async () => {
    // `openTestDatabase` already ran every migration, 0011 included.
    const again = await applyMigrations(db, loadMigrations());
    expect(again).toEqual([]);
    expect(loadMigrations().map((one) => one.name)).toContain(
      "0011_attestations.sql",
    );
  });

  it("round-trips a request, the answers, three scores and their score", async () => {
    const id = "att_" + "a".repeat(32);
    const stored = await getAttestation(db, id);
    expect(stored).not.toBeNull();
    if (stored === null) return;

    expect(stored.attestation.id).toBe(id);
    expect(stored.attestation.model).toBe("1F916:model-a");
    expect(stored.attestation.model_operator).toBe("op_lab");
    expect(stored.attestation.status).toBe("scored");
    expect(stored.attestation.probes).toEqual(PROBES);
    expect(stored.attestation.answers_hash).toBe(ANSWERS_HASH);
    // The median of 3, 2 and 3.
    expect(stored.attestation.score).toEqual({ agreed: 3, probe_count: 3 });
    expect(stored.attestation.date).toBe("2026-09-02");
    expect(stored.attestation.scores).toHaveLength(3);
    // The answers themselves are the one thing the log does not carry.
    expect(stored.answers).toEqual(ANSWERS);

    // And the row is exactly what rederiving the stored events gives back.
    const events = await eventsForAttestation(db, id);
    expect(events.map((event) => event.type)).toEqual([
      "attestation_requested",
      "attestation_answered",
      "attestation_scored",
      "attestation_scored",
      "attestation_scored",
    ]);
    expect(deriveAttestation(events, CLOCK)).toEqual(stored.attestation);
  });

  it("round-trips an expiry, keeping the missing scorers in the log", async () => {
    const id = "att_" + "b".repeat(32);
    const stored = await getAttestation(db, id);
    expect(stored?.attestation.status).toBe("expired");
    expect(stored?.attestation.score).toBeNull();
    expect(stored?.answers).toBeNull();

    const events = await eventsForAttestation(db, id);
    expect(events.map((event) => event.type)).toEqual([
      "attestation_requested",
      "attestation_expired",
    ]);
    expect(events[1]!.payload).toEqual({
      attestation: id,
      missing: ["op_s1", "op_s4", "op_s5"],
    });
  });

  it("reads one attestation's events and never another's", async () => {
    const events = await eventsForAttestation(db, "att_" + "c".repeat(32));
    expect(events).toHaveLength(1);
    const opened = events[0] as Event<"attestation_requested">;
    expect(opened.payload.attestation).toBe("att_" + "c".repeat(32));
  });

  it("finds the attestation a model still has running, and only that", async () => {
    // C is open; A is scored and B expired, so neither is running any more.
    expect((await openAttestationForModel(db, "1F916:model-c"))?.attestation.id).toBe(
      "att_" + "c".repeat(32),
    );
    expect((await openAttestationForModel(db, "1F916:model-d"))?.attestation.id).toBe(
      "att_" + "d".repeat(32),
    );
    expect(await openAttestationForModel(db, "1F916:model-a")).toBeNull();
    expect(await openAttestationForModel(db, "1F916:model-b")).toBeNull();
    expect(await openAttestationForModel(db, "1F916:nobody")).toBeNull();
  });

  it("pages probe candidates by id, excluding stale, stated and unverified rows", async () => {
    const first = await probeCandidates(db, { limit: 2 });
    expect(first.map((one) => one.entry["id"])).toEqual(["nmk_a01", "nmk_a02"]);

    const second = await probeCandidates(db, { limit: 2, afterId: "nmk_a02" });
    expect(second.map((one) => one.entry["id"])).toEqual(["nmk_a03"]);

    const all = await probeCandidates(db, { limit: 100 });
    expect(all.map((one) => one.entry["id"])).toEqual(CANDIDATE_IDS);
    // Every excluded row is excluded for its own reason, and none of them here.
    for (const excluded of ["nmk_b01", "nmk_b02", "nmk_b03"]) {
      expect(all.map((one) => one.entry["id"])).not.toContain(excluded);
    }
  });

  it("finds only past-deadline open or answered attestations, oldest first", async () => {
    const due = await dueAttestations(db, {
      now: "2026-09-10T00:00:00.000Z",
      limit: 10,
    });
    // E's deadline is earlier than D's; A is scored, B expired, C still inside.
    expect(due.map((one) => one.attestation.id)).toEqual([
      "att_" + "e".repeat(32),
      "att_" + "d".repeat(32),
    ]);
    expect(due.map((one) => one.attestation.status)).toEqual(["open", "answered"]);

    // Strictly before: the deadline instant itself is still inside the window.
    const atE = await dueAttestations(db, {
      now: "2026-09-06T00:00:00.000Z",
      limit: 10,
    });
    expect(atE).toEqual([]);

    const bounded = await dueAttestations(db, {
      now: "2026-09-10T00:00:00.000Z",
      limit: 1,
    });
    expect(bounded.map((one) => one.attestation.id)).toEqual([
      "att_" + "e".repeat(32),
    ]);
  });

  it("splits an operator's attestations into what it attested and what it scored", async () => {
    const scorer = await attestationsForOperator(db, "op_s1", 10);
    expect(scorer.asModel).toEqual([]);
    // Newest request first: D, then B, then A.
    expect(scorer.asScorer.map((one) => one.attestation.id)).toEqual([
      "att_" + "d".repeat(32),
      "att_" + "b".repeat(32),
      "att_" + "a".repeat(32),
    ]);

    const lab = await attestationsForOperator(db, "op_lab", 10);
    expect(lab.asModel.map((one) => one.attestation.id)).toEqual([
      "att_" + "a".repeat(32),
    ]);
    expect(lab.asScorer).toEqual([]);

    const both = await attestationsForOperator(db, "op_lab2", 10);
    expect(both.asModel.map((one) => one.attestation.id)).toEqual([
      "att_" + "c".repeat(32),
      "att_" + "b".repeat(32),
    ]);

    const nobody = await attestationsForOperator(db, "op_nobody", 10);
    expect(nobody).toEqual({ asModel: [], asScorer: [] });
  });

  it("lists attestations newest first, narrowed and keyset-paged", async () => {
    const all = await listAttestations(db, { limit: 10 });
    expect(all.map((one) => one.attestation.id)).toEqual([
      "att_" + "e".repeat(32),
      "att_" + "d".repeat(32),
      "att_" + "c".repeat(32),
      "att_" + "b".repeat(32),
      "att_" + "a".repeat(32),
    ]);

    const byModel = await listAttestations(db, {
      model: "1F916:model-a",
      limit: 10,
    });
    expect(byModel.map((one) => one.attestation.id)).toEqual([
      "att_" + "a".repeat(32),
    ]);

    const byOperator = await listAttestations(db, {
      operator: "op_lab2",
      limit: 10,
    });
    expect(byOperator.map((one) => one.attestation.id)).toEqual([
      "att_" + "c".repeat(32),
      "att_" + "b".repeat(32),
    ]);

    const page = await listAttestations(db, { limit: 2 });
    const next = await listAttestations(db, {
      limit: 2,
      beforeSeq: page[1]!.attestation.requested_seq,
    });
    expect(next.map((one) => one.attestation.id)).toEqual([
      "att_" + "c".repeat(32),
      "att_" + "b".repeat(32),
    ]);
  });
});

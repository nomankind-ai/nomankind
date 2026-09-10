/**
 * Drift attestation: the scorer draw is deterministic and excludes the parties
 * Section 8 says it must, the window is exactly the policy window, every refusal
 * fires in its declared order, and the fold walks open, answered, scored and
 * expired.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_DOMAIN } from "../src/policy.js";

import {
  ANSWER_REFUSALS,
  SCORE_REFUSALS,
  SCORER_DRAW_REFUSALS,
  attestationDeadline,
  attestationDue,
  attestationId,
  checkAnswer,
  checkScore,
  deriveAttestation,
  drawScorers,
  type DerivedAttestation,
  type ScoreRefusal,
} from "../src/attest.js";
import {
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
} from "../src/policy.js";
import { appendEvent, type Event, type EventInput } from "../src/events.js";
import type {
  AttestationScorer,
  AttestationScoreRecord,
  Probe,
} from "../src/events.js";
import type { Beacon, PoolSnapshot } from "../src/assign.js";
import type { Clock } from "../src/derive.js";

const SNAPSHOT_AT = "2026-09-01T00:00:00.000Z";
const BEACON_AT = "2026-09-01T01:00:00.000Z";
const REQUESTED_AT = "2026-09-01T02:00:00.000Z";
const DEADLINE = attestationDeadline(REQUESTED_AT);

const MODEL = "1F916:model-key";
const MODEL_OPERATOR = "op_lab";
const MAINTAINER = "op_maintainer";
const PROBE_HASH = `sha256:${"a".repeat(64)}`;
const ANSWERS_HASH = `sha256:${"b".repeat(64)}`;
const SIGNATURE = "c2lnbmF0dXJl";

/** Twelve trusted operators, plus the model's own and the maintainer's. */
const POOL = [
  ...Array.from({ length: 12 }, (_, index) => `op_s${index + 1}`),
  MODEL_OPERATOR,
  MAINTAINER,
];

const CLOCK: Clock = { now: "2026-09-02T00:00:00.000Z" };

function beacon(round: number, at: string = BEACON_AT): Beacon {
  return { round, randomness: `${"7c1f".repeat(15)}${round % 10}`, at };
}

function snapshotOf(
  operators: readonly string[] = POOL,
  at: string = SNAPSHOT_AT,
): PoolSnapshot {
  return { seq: 4, at, operators };
}

const PROBES: readonly Probe[] = Array.from({ length: 5 }, (_, index) => ({
  entry_id: `nmk_e${index + 1}`,
  entry_hash: `sha256:${String(index + 1).repeat(64)}`,
}));

function scorerFor(operator: string): AttestationScorer {
  return { operator, agent: `1F916:${operator}-agent` };
}

const SCORERS: readonly AttestationScorer[] = [
  scorerFor("op_s1"),
  scorerFor("op_s2"),
  scorerFor("op_s3"),
];

const ATTESTATION = "att_0123456789abcdef0123456789abcdef";

/** A hand-built log, as the derivation tests do; hashes are not read. */
async function logOf(inputs: readonly EventInput[]): Promise<Event[]> {
  let events: Event[] = [];
  for (const input of inputs) events = await appendEvent(events, input);
  return events;
}

function requested(at: string = REQUESTED_AT): EventInput {
  return {
    at,
    type: "attestation_requested",
    entry_id: null,
    payload: {
      attestation: ATTESTATION,
      domain: DEFAULT_DOMAIN,
      model: MODEL,
      model_operator: MODEL_OPERATOR,
      probes: PROBES,
      probe_hash: PROBE_HASH,
      probe_count: PROBES.length,
      pool_snapshot_seq: 4,
      beacon_round: 4200,
      beacon_randomness: beacon(4200).randomness,
      scorers: SCORERS,
      deadline: attestationDeadline(at),
    },
  };
}

function answered(at = "2026-09-01T03:00:00.000Z"): EventInput {
  return {
    at,
    type: "attestation_answered",
    entry_id: null,
    payload: { attestation: ATTESTATION, answers_hash: ANSWERS_HASH },
  };
}

function scoreRecord(
  operator: string,
  agreed: number,
  signedAt: string,
): AttestationScoreRecord {
  return {
    agent: `1F916:${operator}-agent`,
    operator,
    agreed,
    probe_hash: PROBE_HASH,
    answers_hash: ANSWERS_HASH,
    signed_at: signedAt,
  };
}

function scored(
  operator: string,
  agreed: number,
  at: string,
): EventInput {
  return {
    at,
    type: "attestation_scored",
    entry_id: null,
    payload: {
      attestation: ATTESTATION,
      record: scoreRecord(operator, agreed, at),
      signature: SIGNATURE,
    },
  };
}

function expired(missing: readonly string[], at: string): EventInput {
  return {
    at,
    type: "attestation_expired",
    entry_id: null,
    payload: { attestation: ATTESTATION, missing },
  };
}

async function derive(inputs: readonly EventInput[]): Promise<DerivedAttestation> {
  return deriveAttestation(await logOf(inputs), CLOCK);
}

describe("the attestation id", () => {
  it("is att_ and thirty-two hex, and is a function of exactly four things", async () => {
    const base = {
      model: MODEL,
      pool_snapshot_seq: 4,
      beacon_round: 4200,
      probe_hash: PROBE_HASH,
    };
    const id = await attestationId(base);
    expect(id).toMatch(/^att_[0-9a-f]{32}$/);
    expect(await attestationId({ ...base })).toBe(id);
    // One model, one round: the same request is the same id, and any of the
    // four moving makes a different one.
    expect(await attestationId({ ...base, beacon_round: 4201 })).not.toBe(id);
    expect(await attestationId({ ...base, model: "1F916:other" })).not.toBe(id);
    expect(await attestationId({ ...base, pool_snapshot_seq: 5 })).not.toBe(id);
    expect(
      await attestationId({ ...base, probe_hash: `sha256:${"c".repeat(64)}` }),
    ).not.toBe(id);
  });
});

describe("the scorer draw", () => {
  const input = {
    model: MODEL,
    probe_hash: PROBE_HASH,
    snapshot: snapshotOf(),
    beacon: beacon(4200),
    exclude: [MODEL_OPERATOR, MAINTAINER],
  };

  it("draws exactly the published number of distinct operators", async () => {
    const drawn = await drawScorers(input);
    if (!drawn.ok) throw new Error("draw should have run");
    expect(drawn.scorers).toHaveLength(ATTESTATION_SCORERS);
    expect(new Set(drawn.scorers).size).toBe(ATTESTATION_SCORERS);
  });

  it("never draws the model's own operator or a maintainer", async () => {
    // Every round, not one: an exclusion that held once by luck is not a rule.
    for (let round = 4200; round < 4260; round += 1) {
      const drawn = await drawScorers({ ...input, beacon: beacon(round) });
      if (!drawn.ok) throw new Error("draw should have run");
      expect(drawn.scorers).not.toContain(MODEL_OPERATOR);
      expect(drawn.scorers).not.toContain(MAINTAINER);
    }
  });

  it("gives the same three for the same inputs, whatever order the pool arrived in", async () => {
    const first = await drawScorers(input);
    const second = await drawScorers({
      ...input,
      snapshot: snapshotOf([...POOL].reverse()),
    });
    if (!first.ok || !second.ok) throw new Error("both draws should have run");
    expect(second.scorers).toEqual(first.scorers);
  });

  it("draws differently on a different beacon round", async () => {
    const first = await drawScorers(input);
    const second = await drawScorers({ ...input, beacon: beacon(4201) });
    if (!first.ok || !second.ok) throw new Error("both draws should have run");
    expect(second.scorers).not.toEqual(first.scorers);
  });

  it("refuses a snapshot sealed at or after the round it would use", async () => {
    expect(
      await drawScorers({
        ...input,
        snapshot: snapshotOf(POOL, "2026-09-01T02:00:00.000Z"),
      }),
    ).toEqual({ ok: false, reason: "snapshot_after_beacon" });
    expect(
      await drawScorers({ ...input, snapshot: snapshotOf(POOL, BEACON_AT) }),
    ).toEqual({ ok: false, reason: "snapshot_after_beacon" });
  });

  it("refuses an empty pool", async () => {
    expect(await drawScorers({ ...input, snapshot: snapshotOf([]) })).toEqual({
      ok: false,
      reason: "empty_pool",
    });
  });

  it("refuses when the eligible pool is smaller than the published number", async () => {
    // Three eligible is enough; two is not, and the exclusions are what make
    // the difference.
    const eligible = ["op_s1", "op_s2", "op_s3", MODEL_OPERATOR, MAINTAINER];
    expect(
      await drawScorers({ ...input, snapshot: snapshotOf(eligible) }),
    ).toMatchObject({ ok: true });
    expect(
      await drawScorers({
        ...input,
        snapshot: snapshotOf(eligible.slice(1)),
      }),
    ).toEqual({ ok: false, reason: "insufficient_scorers" });
  });

  it("declares its refusals in check order", () => {
    expect(SCORER_DRAW_REFUSALS).toEqual([
      "snapshot_after_beacon",
      "empty_pool",
      "insufficient_scorers",
    ]);
  });
});

describe("the window", () => {
  it("is exactly the policy window past the request", () => {
    const deadline = attestationDeadline("2026-09-01T02:00:00.000Z");
    const hours =
      (Date.parse(deadline) - Date.parse("2026-09-01T02:00:00.000Z")) / 3_600_000;
    expect(hours).toBe(ATTESTATION_WINDOW_HOURS);
    expect(deadline).toBe("2026-09-04T02:00:00.000Z");
  });
});

describe("the fold", () => {
  it("throws when no request is among the events", async () => {
    await expect(derive([answered()])).rejects.toThrow(
      /no attestation_requested/,
    );
  });

  it("reads a request as open, with nothing answered and nothing scored", async () => {
    const attestation = await derive([requested()]);
    expect(attestation.id).toBe(ATTESTATION);
    expect(attestation.status).toBe("open");
    expect(attestation.model).toBe(MODEL);
    expect(attestation.model_operator).toBe(MODEL_OPERATOR);
    expect(attestation.probes).toEqual(PROBES);
    expect(attestation.probe_hash).toBe(PROBE_HASH);
    expect(attestation.probe_count).toBe(PROBES.length);
    expect(attestation.pool_snapshot_seq).toBe(4);
    expect(attestation.beacon_round).toBe(4200);
    expect(attestation.scorers).toEqual(SCORERS);
    expect(attestation.requested_seq).toBe(0);
    expect(attestation.requested_at).toBe(REQUESTED_AT);
    expect(attestation.deadline).toBe(DEADLINE);
    expect(attestation.answers_hash).toBeNull();
    expect(attestation.answered_at).toBeNull();
    expect(attestation.scores).toEqual([]);
    expect(attestation.score).toBeNull();
    expect(attestation.scored_at).toBeNull();
    expect(attestation.date).toBeNull();
  });

  it("reads an answer as answered, and remembers when it landed", async () => {
    const attestation = await derive([requested(), answered()]);
    expect(attestation.status).toBe("answered");
    expect(attestation.answers_hash).toBe(ANSWERS_HASH);
    expect(attestation.answered_at).toBe("2026-09-01T03:00:00.000Z");
    expect(attestation.score).toBeNull();
  });

  it("stays answered while fewer than every scorer has scored", async () => {
    const attestation = await derive([
      requested(),
      answered(),
      scored("op_s1", 4, "2026-09-01T04:00:00.000Z"),
      scored("op_s2", 3, "2026-09-01T05:00:00.000Z"),
    ]);
    expect(attestation.status).toBe("answered");
    expect(attestation.scores.map((score) => score.operator)).toEqual([
      "op_s1",
      "op_s2",
    ]);
    expect(attestation.score).toBeNull();
    expect(attestation.date).toBeNull();
  });

  it("scores at the median of three, dated the UTC day the last score landed", async () => {
    const attestation = await derive([
      requested(),
      answered(),
      scored("op_s1", 5, "2026-09-01T04:00:00.000Z"),
      scored("op_s2", 3, "2026-09-01T05:00:00.000Z"),
      scored("op_s3", 4, "2026-09-02T23:30:00.000Z"),
    ]);
    expect(attestation.status).toBe("scored");
    // The middle of 5, 3 and 4: one generous scorer moves nothing.
    expect(attestation.score).toEqual({ agreed: 4, probe_count: PROBES.length });
    expect(attestation.scored_at).toBe("2026-09-02T23:30:00.000Z");
    expect(attestation.date).toBe("2026-09-02");
    expect(attestation.scores).toEqual([
      {
        operator: "op_s1",
        agent: "1F916:op_s1-agent",
        agreed: 5,
        seq: 2,
        signed_at: "2026-09-01T04:00:00.000Z",
      },
      {
        operator: "op_s2",
        agent: "1F916:op_s2-agent",
        agreed: 3,
        seq: 3,
        signed_at: "2026-09-01T05:00:00.000Z",
      },
      {
        operator: "op_s3",
        agent: "1F916:op_s3-agent",
        agreed: 4,
        seq: 4,
        signed_at: "2026-09-02T23:30:00.000Z",
      },
    ]);
  });

  it("ignores a score from an operator that was never drawn", async () => {
    const attestation = await derive([
      requested(),
      answered(),
      scored("op_s9", 5, "2026-09-01T04:00:00.000Z"),
    ]);
    expect(attestation.scores).toEqual([]);
    expect(attestation.status).toBe("answered");
  });

  it("reads an expiry as expired, keeping the partial scores and no score", async () => {
    const attestation = await derive([
      requested(),
      answered(),
      scored("op_s1", 4, "2026-09-01T04:00:00.000Z"),
      expired(["op_s2", "op_s3"], "2026-09-04T03:00:00.000Z"),
    ]);
    expect(attestation.status).toBe("expired");
    expect(attestation.scores).toHaveLength(1);
    expect(attestation.score).toBeNull();
    expect(attestation.date).toBeNull();
  });
});

describe("answering", () => {
  it("declares its refusals in check order", () => {
    expect(ANSWER_REFUSALS).toEqual([
      "not_model",
      "not_open",
      "deadline_passed",
    ]);
  });

  it("lets the model answer inside the window and nobody else, ever", async () => {
    const open = await derive([requested()]);
    expect(
      checkAnswer({ attestation: open, agent: MODEL, now: REQUESTED_AT }),
    ).toEqual({ ok: true });
    // The deadline instant itself is still inside the window.
    expect(
      checkAnswer({ attestation: open, agent: MODEL, now: DEADLINE }),
    ).toEqual({ ok: true });

    expect(
      checkAnswer({ attestation: open, agent: "1F916:other", now: REQUESTED_AT }),
    ).toEqual({ ok: false, reason: "not_model" });
    expect(
      checkAnswer({
        attestation: open,
        agent: MODEL,
        now: "2026-09-05T00:00:00.000Z",
      }),
    ).toEqual({ ok: false, reason: "deadline_passed" });

    const twice = await derive([requested(), answered()]);
    expect(
      checkAnswer({ attestation: twice, agent: MODEL, now: REQUESTED_AT }),
    ).toEqual({ ok: false, reason: "not_open" });
  });
});

describe("scoring", () => {
  const NOW = "2026-09-01T06:00:00.000Z";

  it("declares its refusals in check order", () => {
    expect(SCORE_REFUSALS).toEqual([
      "not_open",
      "deadline_passed",
      "not_a_scorer",
      "operator_mismatch",
      "model_operator",
      "operator_not_in_domain",
      "duplicate_scorer",
      "probe_hash_mismatch",
      "answers_hash_mismatch",
      "bad_agreed",
    ]);
  });

  it("accepts a drawn scorer's record inside the window", async () => {
    const attestation = await derive([requested(), answered()]);
    expect(
      checkScore({
        attestation,
        record: scoreRecord("op_s1", 4, NOW),
        scorerOperator: "op_s1",
        now: NOW,
      }),
    ).toEqual({ ok: true });
  });

  it("refuses every reason, one fixture each", async () => {
    const open = await derive([requested()]);
    const attestation = await derive([requested(), answered()]);
    const oneScored = await derive([
      requested(),
      answered(),
      scored("op_s1", 4, "2026-09-01T05:00:00.000Z"),
    ]);
    // A model whose agent answers to the operator that was also drawn to score
    // it: the draw's exclusion is the first line and this is the second.
    const inHouse = await derive([
      {
        ...requested(),
        payload: {
          ...(requested().payload as Record<string, unknown>),
          model_operator: "op_s1",
        },
      } as EventInput,
      answered(),
    ]);

    const cases: ReadonlyArray<[ScoreRefusal, Parameters<typeof checkScore>[0]]> = [
      [
        "not_open",
        {
          attestation: open,
          record: scoreRecord("op_s1", 4, NOW),
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
      [
        "deadline_passed",
        {
          attestation,
          record: scoreRecord("op_s1", 4, NOW),
          scorerOperator: "op_s1",
          now: "2026-09-05T00:00:00.000Z",
        },
      ],
      [
        "not_a_scorer",
        {
          attestation,
          record: scoreRecord("op_s9", 4, NOW),
          scorerOperator: "op_s9",
          now: NOW,
        },
      ],
      [
        "operator_mismatch",
        {
          attestation,
          record: { ...scoreRecord("op_s1", 4, NOW), operator: "op_s2" },
          scorerOperator: "op_s2",
          now: NOW,
        },
      ],
      [
        "model_operator",
        {
          attestation: inHouse,
          record: scoreRecord("op_s1", 4, NOW),
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
      [
        // Decision D-071: a scorer signs about an attestation only in a domain
        // it has attested in.
        "operator_not_in_domain",
        {
          attestation,
          record: scoreRecord("op_s1", 4, NOW),
          scorerOperator: "op_s1",
          scorerDomains: ["elsewhere"],
          now: NOW,
        },
      ],
      [
        "duplicate_scorer",
        {
          attestation: oneScored,
          record: scoreRecord("op_s1", 5, NOW),
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
      [
        "probe_hash_mismatch",
        {
          attestation,
          record: {
            ...scoreRecord("op_s1", 4, NOW),
            probe_hash: `sha256:${"9".repeat(64)}`,
          },
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
      [
        "answers_hash_mismatch",
        {
          attestation,
          record: {
            ...scoreRecord("op_s1", 4, NOW),
            answers_hash: `sha256:${"9".repeat(64)}`,
          },
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
      [
        "bad_agreed",
        {
          attestation,
          record: { ...scoreRecord("op_s1", PROBES.length + 1, NOW) },
          scorerOperator: "op_s1",
          now: NOW,
        },
      ],
    ];

    for (const [reason, input] of cases) {
      expect(checkScore(input)).toEqual({ ok: false, reason });
    }
    // Every declared reason has a fixture, in the order they are declared.
    expect(cases.map(([reason]) => reason)).toEqual([...SCORE_REFUSALS]);
  });

  it("reads a caller that names no domains as the default domain", async () => {
    const attestation = await derive([requested(), answered()]);

    expect(attestation.domain).toBe(DEFAULT_DOMAIN);
    expect(
      checkScore({
        attestation,
        record: scoreRecord("op_s1", 4, NOW),
        scorerOperator: "op_s1",
        now: NOW,
      }),
    ).toEqual({ ok: true });
  });

  it("refuses a record whose operator is not the one behind its key", async () => {
    const attestation = await derive([requested(), answered()]);
    expect(
      checkScore({
        attestation,
        record: scoreRecord("op_s1", 4, NOW),
        scorerOperator: "op_s2",
        now: NOW,
      }),
    ).toEqual({ ok: false, reason: "operator_mismatch" });
  });

  it("refuses an agreed that is not a whole number of probes", async () => {
    const attestation = await derive([requested(), answered()]);
    for (const agreed of [-1, 2.5, Number.NaN, PROBES.length + 1]) {
      expect(
        checkScore({
          attestation,
          record: { ...scoreRecord("op_s1", agreed, NOW) },
          scorerOperator: "op_s1",
          now: NOW,
        }),
      ).toEqual({ ok: false, reason: "bad_agreed" });
    }
    // None and all of them are both counts.
    for (const agreed of [0, PROBES.length]) {
      expect(
        checkScore({
          attestation,
          record: { ...scoreRecord("op_s1", agreed, NOW) },
          scorerOperator: "op_s1",
          now: NOW,
        }),
      ).toEqual({ ok: true });
    }
  });
});

describe("expiry", () => {
  it("is owed only past the deadline, and names who never scored", async () => {
    const attestation = await derive([
      requested(),
      answered(),
      scored("op_s1", 4, "2026-09-01T05:00:00.000Z"),
    ]);
    // The deadline instant itself is still inside the window.
    expect(attestationDue(attestation, DEADLINE)).toBeNull();
    expect(attestationDue(attestation, "2026-09-04T02:00:00.001Z")).toEqual({
      attestation: ATTESTATION,
      missing: ["op_s2", "op_s3"],
    });
  });

  it("names every scorer when the model never answered", async () => {
    const open = await derive([requested()]);
    expect(attestationDue(open, "2026-09-05T00:00:00.000Z")).toEqual({
      attestation: ATTESTATION,
      missing: ["op_s1", "op_s2", "op_s3"],
    });
  });

  it("is owed nothing once the attestation is scored or already expired", async () => {
    const done = await derive([
      requested(),
      answered(),
      scored("op_s1", 4, "2026-09-01T04:00:00.000Z"),
      scored("op_s2", 4, "2026-09-01T05:00:00.000Z"),
      scored("op_s3", 4, "2026-09-01T06:00:00.000Z"),
    ]);
    expect(attestationDue(done, "2026-09-05T00:00:00.000Z")).toBeNull();

    const gone = await derive([
      requested(),
      expired(["op_s1", "op_s2", "op_s3"], "2026-09-04T03:00:00.000Z"),
    ]);
    expect(attestationDue(gone, "2026-09-05T00:00:00.000Z")).toBeNull();
  });
});

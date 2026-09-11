/**
 * Standing, recomputed from the log.
 *
 * Whitepaper Section 9: "Standing is not a score nomankind assigns. It is
 * derived from the sealed public events by a published formula, so anyone can
 * recompute anyone's standing from the log and get the same number." So the
 * first test is the promise itself — twice over the same events is the same
 * answer — and every test after it is one line of the formula.
 *
 * The worlds are real sealed logs built with `appendEvent`: every event is
 * hash-chained onto the one before it and every instant comes from a fake clock.
 * Nothing here writes a derived field, and no test asserts a bare number without
 * naming the policy constant it comes from.
 */

import { describe, expect, it } from "vitest";
import {
  DISPUTE_STAKE_STANDING,
  POLICY,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  REVALIDATION_REQUEST_STAKE_STANDING,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_ATTESTATION_SCORED,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_REVALIDATION_CHANGED,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_TRUSTED_ENTRY,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_VALIDATION_REPRODUCED,
  STANDING_VALIDATION_VOLUNTEERED,
  STANDING_FORMULA,
  appendEvent,
  standingAt,
  standingOf,
  trustChangesAt,
  type ApproverRecord,
  type Core,
  type Event,
  type EventInput,
} from "../src/index.js";

const MAINTAINER = "nomankind.example";
const SUBMITTER = "sub.example";
const VALIDATORS = ["v1.example", "v2.example", "v3.example"] as const;
const CHALLENGER = "chal.example";
const ENTRY = "nmk_01M21STANDING";

/** norm-v1.2 is in force from 2026-09-08, so every world starts there. */
const EPOCH = "2026-09-08T00:00:00.000Z";
const MINUTE = 60_000;

function at(seq: number): string {
  return new Date(Date.parse(EPOCH) + seq * MINUTE).toISOString();
}

/** One more event, sealed onto the log with the fake clock's next minute. */
async function seal(
  events: readonly Event[],
  input: Omit<EventInput, "at">,
): Promise<Event[]> {
  return appendEvent(events, { ...input, at: at(events.length) });
}

function core(overrides: Partial<Record<string, unknown>> = {}): Core {
  return {
    id: ENTRY,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://platform.openai.com/docs/pricing",
    snapshot_hash: `sha256:${"4d".repeat(32)}`,
    norm_version: POLICY.NORM_VERSION,
    supersedes: null,
    author: "1F916:agent-sub",
    author_operator: SUBMITTER,
    submitted_at: EPOCH,
    ...overrides,
  } as Core;
}

function approval(
  operator: string,
  assignedRandom: boolean,
  signedAt: string,
  decision: "approve" | "reject" = "approve",
): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision,
    reason: null,
    snapshot_hash: `sha256:${"4d".repeat(32)}`,
    assigned_random: assignedRandom,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt,
  };
}

/**
 * The registry every world starts from: a maintainer, a submitter, three
 * validators (all trusted, so the pool is non-empty and under the switch) and a
 * challenger. Four non-maintainer operators outside the submitter's own, which
 * is what the verification preconditions ask for.
 */
async function registry(): Promise<Event[]> {
  let events: Event[] = await seal([], {
    type: "operator_registered",
    entry_id: null,
    payload: { operator: MAINTAINER, maintainer: true },
  });
  for (const operator of [SUBMITTER, ...VALIDATORS, CHALLENGER]) {
    events = await seal(events, {
      type: "operator_registered",
      entry_id: null,
      payload: { operator, maintainer: false },
    });
  }
  for (const operator of VALIDATORS) {
    events = await seal(events, {
      type: "operator_trusted",
      entry_id: null,
      payload: { operator },
    });
  }
  return events;
}

/** The registry, plus a submitted entry that nobody has validated yet. */
async function submitted(overrides: Record<string, unknown> = {}): Promise<Event[]> {
  const events = await registry();
  return seal(events, {
    type: "entry_submitted",
    entry_id: (overrides["id"] as string | undefined) ?? ENTRY,
    payload: { core: core(overrides), signature: "c2ln" },
  });
}

/** A submitted entry and the two approvals that verify it in a small pool. */
async function verified(overrides: Record<string, unknown> = {}): Promise<Event[]> {
  let events = await submitted(overrides);
  const entryId = (overrides["id"] as string | undefined) ?? ENTRY;
  events = await seal(events, {
    type: "validation",
    entry_id: entryId,
    payload: {
      record: approval(VALIDATORS[0], false, at(events.length)),
      signature: "c2ln",
    },
  });
  return seal(events, {
    type: "validation",
    entry_id: entryId,
    payload: {
      record: approval(VALIDATORS[1], true, at(events.length)),
      signature: "c2ln",
    },
  });
}

const HEAD = Number.MAX_SAFE_INTEGER;

describe("standingAt", () => {
  it("gives the same answer twice over the same events", async () => {
    const events = await verified();
    const first = standingAt(events, HEAD);
    const second = standingAt(events, HEAD);
    expect([...second.entries()]).toEqual([...first.entries()]);
  });

  it("agrees with standingOf, operator by operator", async () => {
    const events = await verified();
    const all = standingAt(events, HEAD);
    for (const [operator, standing] of all) {
      expect(standingOf(events, operator, HEAD)).toEqual(standing);
    }
    // An operator the log has never mentioned owns nothing, and says so rather
    // than being absent.
    expect(standingOf(events, "stranger.example", HEAD)).toMatchObject({
      operator: "stranger.example",
      earned: 0,
      burned: 0,
      standing: 0,
      available: 0,
    });
  });

  it("answers as of a position and never past it", async () => {
    const events = await verified();
    const before = events[events.length - 1]!.seq - 1;
    // The verifying approval is the last event, so one position back the
    // submitter has not been paid and the second validator has not validated.
    expect(standingOf(events, SUBMITTER, before).standing).toBe(0);
    expect(standingOf(events, VALIDATORS[1], before).standing).toBe(0);
    expect(standingOf(events, SUBMITTER, HEAD).standing).toBe(
      STANDING_SUBMISSION_VERIFIED,
    );
  });

  it("pays a volunteered validation less than an assigned one", async () => {
    const events = await verified();
    const volunteered = standingOf(events, VALIDATORS[0], HEAD);
    const assigned = standingOf(events, VALIDATORS[1], HEAD);

    expect(volunteered.earned).toBe(STANDING_VALIDATION_VOLUNTEERED);
    expect(volunteered.counts.validations_volunteered).toBe(1);
    expect(assigned.earned).toBe(STANDING_VALIDATION_ASSIGNED);
    expect(assigned.counts.validations_assigned).toBe(1);
    // Section 9: "assigned validations weigh more than volunteered ones".
    expect(STANDING_VALIDATION_ASSIGNED).toBeGreaterThan(
      STANDING_VALIDATION_VOLUNTEERED,
    );
  });

  it("pays a validator that measured beside the credit for the decision (D-087)", async () => {
    // Section 4: "the operators who measure are paid more than the operators
    // who copy." The standing side of that rule: the same volunteered
    // validation, once with a passing n-of-k measurement and once without.
    let events = await verified();
    const copier = standingOf(events, VALIDATORS[0], HEAD);
    expect(copier.earned).toBe(STANDING_VALIDATION_VOLUNTEERED);
    expect(copier.counts.validations_reproduced).toBe(0);

    events = await seal(events, {
      type: "validation",
      entry_id: ENTRY,
      payload: {
        record: {
          ...approval(VALIDATORS[2], false, at(events.length)),
          test_accepted: true,
          observation: {
            method: "completed_request",
            runs: REPRODUCTION_RUNS,
            holds: REPRODUCTION_HOLDS,
          },
        } as ApproverRecord,
        signature: "c2ln",
      },
    });
    const measurer = standingOf(events, VALIDATORS[2], HEAD);
    expect(measurer.earned).toBe(
      STANDING_VALIDATION_VOLUNTEERED + STANDING_VALIDATION_REPRODUCED,
    );
    expect(measurer.counts.validations_volunteered).toBe(1);
    expect(measurer.counts.validations_reproduced).toBe(1);
    expect(measurer.earned).toBeGreaterThan(copier.earned);
  });

  it("pays nothing extra for a measurement that did not pass the n-of-k rule", async () => {
    let events = await verified();
    events = await seal(events, {
      type: "validation",
      entry_id: ENTRY,
      payload: {
        record: {
          ...approval(VALIDATORS[2], false, at(events.length)),
          test_accepted: true,
          // Accepted the test, ran it, and it did not hold often enough: the
          // decision is paid, the measurement is not.
          observation: {
            method: "completed_request",
            runs: REPRODUCTION_RUNS,
            holds: REPRODUCTION_HOLDS - 1,
          },
        } as ApproverRecord,
        signature: "c2ln",
      },
    });
    const standing = standingOf(events, VALIDATORS[2], HEAD);
    expect(standing.earned).toBe(STANDING_VALIDATION_VOLUNTEERED);
    expect(standing.counts.validations_reproduced).toBe(0);
  });

  it("pays a reconfirmation that measured the same way", async () => {
    let events = await verified();
    events = await seal(events, {
      type: "reconfirmation",
      entry_id: ENTRY,
      payload: {
        record: {
          agent: `1F916:agent-${VALIDATORS[2]}`,
          operator: VALIDATORS[2],
          snapshot_hash: `sha256:${"4d".repeat(32)}`,
          reproduction: {
            method: "rerun_prompt",
            runs: REPRODUCTION_RUNS,
            holds: REPRODUCTION_RUNS,
          },
          observation: null,
          signed_at: at(events.length),
        },
        signature: "c2ln",
      },
    });
    const standing = standingOf(events, VALIDATORS[2], HEAD);
    expect(standing.earned).toBe(
      STANDING_VALIDATION_VOLUNTEERED + STANDING_VALIDATION_REPRODUCED,
    );
    expect(standing.counts.validations_reproduced).toBe(1);
  });

  it("pays the submitter's operator once, and only once the entry verifies", async () => {
    const draft = await submitted();
    expect(standingOf(draft, SUBMITTER, HEAD).standing).toBe(0);
    expect(standingOf(draft, SUBMITTER, HEAD).counts.submissions_verified).toBe(0);

    let events = await verified();
    const paid = standingOf(events, SUBMITTER, HEAD);
    expect(paid.standing).toBe(STANDING_SUBMISSION_VERIFIED);
    expect(paid.counts.submissions_verified).toBe(1);

    // A third approval lands on an entry that is already verified: the
    // validator is paid, and the submitter is not paid twice.
    events = await seal(events, {
      type: "validation",
      entry_id: ENTRY,
      payload: {
        record: approval(VALIDATORS[2], false, at(events.length)),
        signature: "c2ln",
      },
    });
    expect(standingOf(events, SUBMITTER, HEAD).standing).toBe(
      STANDING_SUBMISSION_VERIFIED,
    );
    expect(standingOf(events, SUBMITTER, HEAD).counts.submissions_verified).toBe(1);
    expect(standingOf(events, VALIDATORS[2], HEAD).earned).toBe(
      STANDING_VALIDATION_VOLUNTEERED,
    );
  });

  it("pays nothing to a bare-key submitter's absent operator", async () => {
    const events = await verified({ author_operator: null });
    for (const standing of standingAt(events, HEAD).values()) {
      expect(standing.counts.submissions_verified).toBe(0);
    }
  });

  it("pays a reconfirmation as volunteered work", async () => {
    let events = await verified();
    events = await seal(events, {
      type: "reconfirmation",
      entry_id: ENTRY,
      payload: {
        record: {
          agent: `1F916:agent-${VALIDATORS[2]}`,
          operator: VALIDATORS[2],
          snapshot_hash: `sha256:${"4d".repeat(32)}`,
          reproduction: null,
          observation: null,
          signed_at: at(events.length),
        },
        signature: "c2ln",
      },
    });
    const standing = standingOf(events, VALIDATORS[2], HEAD);
    expect(standing.earned).toBe(STANDING_VALIDATION_VOLUNTEERED);
    expect(standing.counts.validations_volunteered).toBe(1);
  });

  it("burns a missed assignment and a missed revalidation check", async () => {
    let events = await verified();
    events = await seal(events, {
      type: "assignment_missed",
      entry_id: ENTRY,
      payload: { agent: `1F916:agent-${VALIDATORS[2]}`, operator: VALIDATORS[2] },
    });
    expect(standingOf(events, VALIDATORS[2], HEAD)).toMatchObject({
      burned: STANDING_ASSIGNMENT_MISSED,
      standing: -STANDING_ASSIGNMENT_MISSED,
    });

    events = await seal(events, {
      type: "revalidation_missed",
      entry_id: ENTRY,
      payload: {
        request_seq: 0,
        agent: `1F916:agent-${VALIDATORS[2]}`,
        operator: VALIDATORS[2],
      },
    });
    const standing = standingOf(events, VALIDATORS[2], HEAD);
    expect(standing.burned).toBe(2 * STANDING_ASSIGNMENT_MISSED);
    expect(standing.counts.missed).toBe(2);
  });
});

describe("drift attestations", () => {
  const ATTESTATION = "att_01M22STANDING";

  /** One drawn scorer's signed verdict, in the payload's own shape. */
  function score(operator: string): {
    attestation: string;
    record: {
      agent: string;
      operator: string;
      agreed: number;
      probe_hash: string;
      answers_hash: string;
      signed_at: string;
    };
    signature: string;
  } {
    return {
      attestation: ATTESTATION,
      record: {
        agent: `1F916:agent-${operator}`,
        operator,
        agreed: 9,
        probe_hash: `sha256:${"a1".repeat(32)}`,
        answers_hash: `sha256:${"b2".repeat(32)}`,
        signed_at: EPOCH,
      },
      signature: "c2ln",
    };
  }

  it("pays each scorer's operator for a score it signed", async () => {
    // Section 8: three trusted operators "score its answers against the log and
    // sign the result", which is completed work Section 9 pays for. All three
    // move by the same amount, because all three did the same work.
    let events = await verified();
    const before = VALIDATORS.map(
      (operator) => standingOf(events, operator, HEAD).earned,
    );
    for (const operator of VALIDATORS) {
      events = await seal(events, {
        type: "attestation_scored",
        entry_id: null,
        payload: score(operator),
      });
    }
    VALIDATORS.forEach((operator, index) => {
      const standing = standingOf(events, operator, HEAD);
      expect([operator, standing.earned]).toEqual([
        operator,
        before[index]! + STANDING_ATTESTATION_SCORED,
      ]);
      expect(standing.counts.attestations_scored).toBe(1);
      // A score is not a validation: the validation counters stand still.
      expect(standing.counts.validations_reproduced).toBe(0);
    });
  });

  it("burns every scorer an expiry names, and none of the ones that scored", async () => {
    // "An attestation that expires is not a failing score: it is no score at
    // all", and what the expiry says is who never answered. A drawn scorer that
    // let the window run out missed an assignment, at the rate a missed
    // assignment already carries.
    let events = await verified();
    events = await seal(events, {
      type: "attestation_scored",
      entry_id: null,
      payload: score(VALIDATORS[0]),
    });
    const scored = standingOf(events, VALIDATORS[0], HEAD);

    events = await seal(events, {
      type: "attestation_expired",
      entry_id: null,
      payload: {
        attestation: ATTESTATION,
        missing: [VALIDATORS[1], VALIDATORS[2]],
      },
    });

    // The scorer is untouched by the expiry: it answered.
    expect(standingOf(events, VALIDATORS[0], HEAD)).toEqual(scored);
    expect(standingOf(events, VALIDATORS[0], HEAD).counts.missed).toBe(0);

    for (const operator of [VALIDATORS[1], VALIDATORS[2]]) {
      const standing = standingOf(events, operator, HEAD);
      expect([operator, standing.burned]).toEqual([
        operator,
        STANDING_ASSIGNMENT_MISSED,
      ]);
      expect(standing.counts.missed).toBe(1);
      expect(standing.counts.attestations_scored).toBe(0);
    }
  });
});

describe("disputes", () => {
  /** A verified entry, challenged by CHALLENGER as an operator or as a bare key. */
  async function filed(operator: string | null): Promise<Event[]> {
    const events = await verified();
    return seal(events, {
      type: "dispute_filed",
      entry_id: ENTRY,
      payload: {
        correction_entry_id: "nmk_01M21CORRECTION",
        challenger: `1F916:agent-${operator ?? "burner"}`,
        operator,
        citation: "https://platform.openai.com/docs/pricing",
        snapshot_hash: `sha256:${"5e".repeat(32)}`,
        from_report_seq: null,
        from_revalidation_seq: null,
      },
    });
  }

  it("locks the challenger's stake while the dispute is open", async () => {
    const events = await filed(CHALLENGER);
    expect(standingOf(events, CHALLENGER, HEAD)).toMatchObject({
      locked: DISPUTE_STAKE_STANDING,
      standing: 0,
      available: -DISPUTE_STAKE_STANDING,
    });
  });

  it("unlocks the stake, pays the challenger and burns every signer when upheld", async () => {
    let events = await filed(CHALLENGER);
    events = await seal(events, {
      type: "dispute_upheld",
      entry_id: ENTRY,
      payload: { correction_entry_id: "nmk_01M21CORRECTION" },
    });

    const challenger = standingOf(events, CHALLENGER, HEAD);
    expect(challenger.locked).toBe(0);
    expect(challenger.standing).toBe(STANDING_DISPUTE_UPHELD);
    expect(challenger.counts.disputes_upheld).toBe(1);

    // The author's operator and both approving operators, once each.
    expect(standingOf(events, SUBMITTER, HEAD)).toMatchObject({
      burned: STANDING_OVERTURNED_SIGNER,
      standing: STANDING_SUBMISSION_VERIFIED - STANDING_OVERTURNED_SIGNER,
    });
    for (const [index, operator] of [VALIDATORS[0], VALIDATORS[1]].entries()) {
      const earned = index === 0
        ? STANDING_VALIDATION_VOLUNTEERED
        : STANDING_VALIDATION_ASSIGNED;
      expect(standingOf(events, operator, HEAD)).toMatchObject({
        burned: STANDING_OVERTURNED_SIGNER,
        standing: earned - STANDING_OVERTURNED_SIGNER,
        counts: expect.objectContaining({ overturned: 1 }),
      });
    }
    // The validator that never signed this entry is untouched.
    expect(standingOf(events, VALIDATORS[2], HEAD).burned).toBe(0);
  });

  it("burns an operator once however many of its agents signed", async () => {
    let events = await verified();
    // A second decision from an operator that already approved: counted by
    // nobody, and burned once when the entry is overturned.
    events = await seal(events, {
      type: "validation",
      entry_id: ENTRY,
      payload: {
        record: approval(VALIDATORS[0], false, at(events.length)),
        signature: "c2ln",
      },
    });
    events = await seal(events, {
      type: "dispute_filed",
      entry_id: ENTRY,
      payload: {
        correction_entry_id: "nmk_01M21CORRECTION",
        challenger: `1F916:agent-${CHALLENGER}`,
        operator: CHALLENGER,
        citation: "https://platform.openai.com/docs/pricing",
        snapshot_hash: `sha256:${"5e".repeat(32)}`,
        from_report_seq: null,
        from_revalidation_seq: null,
      },
    });
    events = await seal(events, {
      type: "dispute_upheld",
      entry_id: ENTRY,
      payload: { correction_entry_id: "nmk_01M21CORRECTION" },
    });
    expect(standingOf(events, VALIDATORS[0], HEAD).counts.overturned).toBe(1);
    expect(standingOf(events, VALIDATORS[0], HEAD).burned).toBe(
      STANDING_OVERTURNED_SIGNER,
    );
  });

  it("forfeits the stake when the challenge fails", async () => {
    let events = await filed(CHALLENGER);
    events = await seal(events, {
      type: "dispute_failed",
      entry_id: ENTRY,
      payload: {
        correction_entry_id: "nmk_01M21CORRECTION",
        reason: "no evidence",
      },
    });
    expect(standingOf(events, CHALLENGER, HEAD)).toMatchObject({
      locked: 0,
      burned: DISPUTE_STAKE_STANDING,
      standing: -DISPUTE_STAKE_STANDING,
      counts: expect.objectContaining({ forfeits: 1 }),
    });
    // A failed challenge does not touch the entry's signers.
    expect(standingOf(events, SUBMITTER, HEAD).burned).toBe(0);
  });

  it("moves nothing for a bare-key challenger", async () => {
    let events = await filed(null);
    const filedAt = standingAt(events, HEAD);
    events = await seal(events, {
      type: "dispute_upheld",
      entry_id: ENTRY,
      payload: { correction_entry_id: "nmk_01M21CORRECTION" },
    });
    // Nobody was locked by the filing: Section 6 says a bare key stakes a
    // refundable filing fee, which is money and not standing.
    for (const standing of filedAt.values()) expect(standing.locked).toBe(0);
    for (const standing of standingAt(events, HEAD).values()) {
      expect(standing.counts.disputes_upheld).toBe(0);
    }
    // The entry is still overturned, so its signers are still burned.
    expect(standingOf(events, SUBMITTER, HEAD).burned).toBe(
      STANDING_OVERTURNED_SIGNER,
    );
  });
});

describe("revalidation requests", () => {
  async function requested(): Promise<Event[]> {
    const events = await verified();
    return seal(events, {
      type: "revalidation_requested",
      entry_id: ENTRY,
      payload: {
        requester: `1F916:agent-${CHALLENGER}`,
        operator: CHALLENGER,
        source: "operator",
      },
    });
  }

  async function resolve(
    events: readonly Event[],
    requestSeq: number,
    outcome: "held" | "changed" | "upgraded",
  ): Promise<Event[]> {
    return seal(events, {
      type: "revalidation_resolved",
      entry_id: ENTRY,
      payload: {
        request_seq: requestSeq,
        outcome,
        checker: `1F916:agent-${VALIDATORS[2]}`,
        operator: VALIDATORS[2],
        snapshot_hash: `sha256:${"6f".repeat(32)}`,
        correction_entry_id: null,
      },
    });
  }

  it("locks the requester's stake while the check is open", async () => {
    const events = await requested();
    expect(standingOf(events, CHALLENGER, HEAD).locked).toBe(
      REVALIDATION_REQUEST_STAKE_STANDING,
    );
  });

  it("forfeits the stake when the entry holds, and pays the checker", async () => {
    const open = await requested();
    const requestSeq = open[open.length - 1]!.seq;
    const events = await resolve(open, requestSeq, "held");

    expect(standingOf(events, CHALLENGER, HEAD)).toMatchObject({
      locked: 0,
      burned: REVALIDATION_REQUEST_STAKE_STANDING,
      counts: expect.objectContaining({ forfeits: 1 }),
    });
    // The drawn checker did assigned work and is paid for it either way.
    expect(standingOf(events, VALIDATORS[2], HEAD)).toMatchObject({
      earned: STANDING_VALIDATION_ASSIGNED,
      counts: expect.objectContaining({ validations_assigned: 1 }),
    });
  });

  it("returns the stake when the fact changed or the request was upgraded", async () => {
    for (const outcome of ["changed", "upgraded"] as const) {
      const open = await requested();
      const requestSeq = open[open.length - 1]!.seq;
      const events = await resolve(open, requestSeq, outcome);
      expect(standingOf(events, CHALLENGER, HEAD)).toMatchObject({
        locked: 0,
        burned: 0,
        counts: expect.objectContaining({ forfeits: 0 }),
      });
    }
  });

  it("pays the requester the changed reward, in standing (D-095)", async () => {
    // Section 6: "If the check finds the fact changed, the requester gets the
    // stake back plus a challenger-style reward." The stake was standing, so
    // the reward is standing.
    const open = await requested();
    const before = standingOf(open, CHALLENGER, HEAD);
    const requestSeq = open[open.length - 1]!.seq;
    const events = await resolve(open, requestSeq, "changed");

    const after = standingOf(events, CHALLENGER, HEAD);
    expect(after.earned - before.earned).toBe(STANDING_REVALIDATION_CHANGED);
    expect(after.counts.revalidations_changed).toBe(1);
    // Smaller than an upheld dispute: a request carries no citation.
    expect(STANDING_REVALIDATION_CHANGED).toBeLessThan(STANDING_DISPUTE_UPHELD);
  });

  it("pays the requester nothing when the entry held or the request was upgraded", async () => {
    // An upgraded request is paid by the dispute it becomes, not twice here.
    for (const outcome of ["held", "upgraded"] as const) {
      const open = await requested();
      const before = standingOf(open, CHALLENGER, HEAD);
      const requestSeq = open[open.length - 1]!.seq;
      const events = await resolve(open, requestSeq, outcome);

      const after = standingOf(events, CHALLENGER, HEAD);
      expect(after.earned).toBe(before.earned);
      expect(after.counts.revalidations_changed).toBe(0);
    }
  });

  it("locks nothing for a check nomankind opened at its own expense", async () => {
    let events = await verified();
    events = await seal(events, {
      type: "revalidation_requested",
      entry_id: ENTRY,
      payload: { requester: null, operator: null, source: "failure_reports" },
    });
    for (const standing of standingAt(events, HEAD).values()) {
      expect(standing.locked).toBe(0);
    }
  });
});

describe("trustChangesAt", () => {
  /** A registered operator with `count` volunteered reconfirmations behind it. */
  async function earn(
    events: readonly Event[],
    operator: string,
    count: number,
  ): Promise<Event[]> {
    let log = [...events];
    for (let index = 0; index < count; index += 1) {
      log = await seal(log, {
        type: "reconfirmation",
        entry_id: ENTRY,
        payload: {
          record: {
            agent: `1F916:agent-${operator}`,
            operator,
            snapshot_hash: `sha256:${"4d".repeat(32)}`,
            reproduction: null,
            observation: null,
            signed_at: at(log.length),
          },
          signature: "c2ln",
        },
      });
    }
    return log;
  }

  const TO_ENTRY = STANDING_TRUSTED_ENTRY / STANDING_VALIDATION_VOLUNTEERED;

  it("trusts an operator at the entry threshold and not one below it", async () => {
    let events = await verified();
    events = await earn(events, CHALLENGER, TO_ENTRY - 1);
    expect(trustChangesAt(events, HEAD).trust).not.toContain(CHALLENGER);

    events = await earn(events, CHALLENGER, 1);
    expect(standingOf(events, CHALLENGER, HEAD).standing).toBe(
      STANDING_TRUSTED_ENTRY,
    );
    expect(trustChangesAt(events, HEAD).trust).toContain(CHALLENGER);
  });

  it("never trusts the maintainer's own operator or a model provider's", async () => {
    let events = await registry();
    // A provider registered as an operator: Section 10 refuses it a place in the
    // pool however much standing it has, and the door refuses the domain too.
    events = await seal(events, {
      type: "operator_registered",
      entry_id: null,
      payload: { operator: "openai.com", maintainer: false },
    });
    events = await seal(events, {
      type: "entry_submitted",
      entry_id: ENTRY,
      payload: { core: core(), signature: "c2ln" },
    });
    for (const operator of [MAINTAINER, "openai.com"]) {
      events = await earn(events, operator, TO_ENTRY);
      expect(standingOf(events, operator, HEAD).standing).toBeGreaterThanOrEqual(
        STANDING_TRUSTED_ENTRY,
      );
    }
    const changes = trustChangesAt(events, HEAD);
    expect(changes.trust).not.toContain(MAINTAINER);
    expect(changes.trust).not.toContain("openai.com");
  });

  it("does not name an operator that is already trusted", async () => {
    const events = await earn(await verified(), VALIDATORS[0], TO_ENTRY);
    expect(trustChangesAt(events, HEAD).trust).not.toContain(VALIDATORS[0]);
  });

  it("untrusts a trusted operator that falls below the stay threshold", async () => {
    let events = await verified();
    // VALIDATORS[1] is trusted and earned an assigned validation; enough misses
    // put it under the bar.
    expect(trustChangesAt(events, HEAD).untrust).toEqual([]);
    for (let index = 0; index < 3; index += 1) {
      events = await seal(events, {
        type: "assignment_missed",
        entry_id: ENTRY,
        payload: {
          agent: `1F916:agent-${VALIDATORS[1]}`,
          operator: VALIDATORS[1],
        },
      });
    }
    expect(standingOf(events, VALIDATORS[1], HEAD).standing).toBeLessThan(
      POLICY.STANDING_TRUSTED_STAY,
    );
    expect(trustChangesAt(events, HEAD).untrust).toEqual([VALIDATORS[1]]);
  });

  it("sorts both lists, so two runs of the sweep seal the same order", async () => {
    let events = await verified();
    for (const operator of [CHALLENGER, SUBMITTER]) {
      events = await earn(events, operator, TO_ENTRY);
    }
    const changes = trustChangesAt(events, HEAD);
    expect(changes.trust).toEqual([...changes.trust].sort());
    expect(changes.trust).toContain(CHALLENGER);
    expect(changes.trust).toContain(SUBMITTER);
  });
});

describe("STANDING_FORMULA", () => {
  it("names only policy keys, and every term the fold applies", () => {
    expect(Object.isFrozen(STANDING_FORMULA)).toBe(true);
    for (const name of STANDING_FORMULA) {
      expect(Object.keys(POLICY)).toContain(name);
    }
    for (const name of [
      "STANDING_VALIDATION_VOLUNTEERED",
      "STANDING_VALIDATION_ASSIGNED",
      "STANDING_ATTESTATION_SCORED",
      "STANDING_SUBMISSION_VERIFIED",
      "STANDING_DISPUTE_UPHELD",
      "STANDING_REVALIDATION_CHANGED",
      "STANDING_OVERTURNED_SIGNER",
      "STANDING_ASSIGNMENT_MISSED",
      "DISPUTE_STAKE_STANDING",
      "REVALIDATION_REQUEST_STAKE_STANDING",
      "STANDING_DECAY_PAUSED",
    ]) {
      expect(STANDING_FORMULA).toContain(name);
    }
  });

  it("publishes no decay term while decay is paused", () => {
    // Section 9: decay "is paused until the paid loop starts", and the paper
    // publishes no rate. A rate here would be a policy nobody decided.
    expect(POLICY.STANDING_DECAY_PAUSED).toBe(true);
    for (const name of Object.keys(POLICY)) {
      expect(name).not.toMatch(/DECAY_RATE/);
    }
  });
});

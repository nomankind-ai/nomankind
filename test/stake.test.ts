/**
 * The stake rows a dispute and a revalidation request produce.
 *
 * Whitepaper Section 6, "Dispute": "A verified operator stakes standing, a bare
 * key stakes a refundable filing fee ... An upheld challenge returns the stake,
 * pays the challenger ... A failed challenge forfeits the stake." And
 * "Revalidate": "If the entry holds, the requester loses the stake", and a
 * request that turns up a citation "can be upgraded into a dispute" — so a
 * check earns no reward of its own, and the only reward here is the dispute's.
 *
 * Every amount is read from src/policy.ts; a literal here would put a policy
 * number in a second place. Every field is read out of a sealed event, which is
 * the property under test: drop the ledger and the same rows come back.
 */

import { describe, expect, it } from "vitest";

import type { Event, EventPayloads, EventType } from "../src/events.js";
import {
  DISPUTE_FILING_FEE_CENTS,
  DISPUTE_STAKE_STANDING,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "../src/policy.js";
import {
  disputeOutcomeStakes,
  disputeStake,
  revalidationOutcomeStakes,
  revalidationStake,
} from "../src/stake.js";

const TARGET = "nmk_01TARGET";
const CORRECTION = "nmk_01CORRECT";
const CHALLENGER = "1F916:Y2hhbGxlbmdlcg";
const REQUESTER = "1F916:cmVxdWVzdGVy";
const OPERATOR = "op_challenger";
const CITATION = "https://platform.openai.com/docs/pricing";
const HASH = `sha256:${"b".repeat(64)}`;

/** A hand-built event. The stake builders never look at the hashes. */
function event<T extends EventType>(
  seq: number,
  type: T,
  entryId: string | null,
  payload: EventPayloads[T],
): Event<T> {
  return {
    seq,
    at: new Date(Date.parse("2026-09-01T00:00:00Z") + seq * 60_000).toISOString(),
    type,
    entry_id: entryId,
    payload,
    prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
    hash: `hash-${seq}`,
  };
}

function filed(operator: string | null): Event<"dispute_filed"> {
  return event(10, "dispute_filed", TARGET, {
    correction_entry_id: CORRECTION,
    challenger: CHALLENGER,
    operator,
    citation: CITATION,
    snapshot_hash: HASH,
    from_report_seq: null,
    from_revalidation_seq: null,
  });
}

function requested(
  source: "operator" | "failure_reports",
): Event<"revalidation_requested"> {
  return event(20, "revalidation_requested", TARGET, {
    requester: source === "operator" ? REQUESTER : null,
    operator: source === "operator" ? OPERATOR : null,
    source,
  });
}

function resolved(
  outcome: "held" | "changed" | "upgraded",
): Event<"revalidation_resolved"> {
  return event(30, "revalidation_resolved", TARGET, {
    request_seq: 20,
    outcome,
    checker: outcome === "upgraded" ? null : "1F916:Y2hlY2tlcg",
    operator: outcome === "upgraded" ? null : "op_checker",
    snapshot_hash: outcome === "upgraded" ? null : HASH,
    correction_entry_id: outcome === "upgraded" ? CORRECTION : null,
  });
}

describe("disputeStake", () => {
  it("stakes standing when the challenger has an operator", () => {
    const stake = disputeStake(filed(OPERATOR));
    expect(stake).toEqual({
      kind: "dispute_stake",
      entry_id: TARGET,
      correction_entry_id: CORRECTION,
      request_seq: null,
      agent: CHALLENGER,
      operator: OPERATOR,
      unit: "standing",
      amount: DISPUTE_STAKE_STANDING,
      seq: 10,
      at: filed(OPERATOR).at,
    });
  });

  it("stakes a refundable filing fee for a bare key", () => {
    const stake = disputeStake(filed(null));
    expect(stake.operator).toBeNull();
    expect(stake.unit).toBe("cents");
    expect(stake.amount).toBe(DISPUTE_FILING_FEE_CENTS);
  });

  it("refuses a filing with no entry to be filed against", () => {
    const orphan = { ...filed(OPERATOR), entry_id: null } as Event<"dispute_filed">;
    expect(() => disputeStake(orphan)).toThrow(TypeError);
  });
});

describe("disputeOutcomeStakes", () => {
  it("returns the stake and owes a reward when the challenge is upheld", () => {
    const upheld = event(11, "dispute_upheld", TARGET, {
      correction_entry_id: CORRECTION,
    });
    const rows = disputeOutcomeStakes(filed(OPERATOR), upheld);
    expect(rows.map((row) => row.kind)).toEqual([
      "dispute_refund",
      "dispute_reward",
    ]);
    // The refund is exactly what was staked.
    expect(rows[0]!.unit).toBe("standing");
    expect(rows[0]!.amount).toBe(DISPUTE_STAKE_STANDING);
    // The reward is owed here and priced by the ledger step, from the
    // clawbacks of this same event: a number invented here would be a second
    // answer to what the entry lost.
    expect(rows[1]!.unit).toBeNull();
    expect(rows[1]!.amount).toBeNull();
    // Both rows sit at the outcome's position, not the filing's.
    for (const row of rows) {
      expect(row.seq).toBe(11);
      expect(row.at).toBe(upheld.at);
      expect(row.entry_id).toBe(TARGET);
      expect(row.correction_entry_id).toBe(CORRECTION);
    }
  });

  it("forfeits the stake when the challenge fails", () => {
    const failedOutcome = event(11, "dispute_failed", TARGET, {
      correction_entry_id: CORRECTION,
      reason: "The cited page says what the entry says.",
    });
    const rows = disputeOutcomeStakes(filed(OPERATOR), failedOutcome);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.kind).toBe("dispute_forfeit");
    expect(rows[0]!.amount).toBe(DISPUTE_STAKE_STANDING);
  });

  it("forfeits a bare key's fee in the unit it was staked in", () => {
    const failedOutcome = event(11, "dispute_failed", TARGET, {
      correction_entry_id: CORRECTION,
      reason: null,
    });
    const rows = disputeOutcomeStakes(filed(null), failedOutcome);
    expect(rows[0]!.unit).toBe("cents");
    expect(rows[0]!.amount).toBe(DISPUTE_FILING_FEE_CENTS);
    expect(rows[0]!.operator).toBeNull();
  });
});

describe("revalidationStake", () => {
  it("stakes standing for an operator's request", () => {
    expect(revalidationStake(requested("operator"))).toEqual({
      kind: "revalidation_stake",
      entry_id: TARGET,
      correction_entry_id: null,
      request_seq: 20,
      agent: REQUESTER,
      operator: OPERATOR,
      unit: "standing",
      amount: REVALIDATION_REQUEST_STAKE_STANDING,
      seq: 20,
      at: requested("operator").at,
    });
  });

  it("stakes nothing when failure reports opened the check", () => {
    // Section 8: the check is auto-opened "at nomankind's expense".
    expect(revalidationStake(requested("failure_reports"))).toBeNull();
  });
});

describe("revalidationOutcomeStakes", () => {
  it("forfeits the stake when the entry holds", () => {
    const rows = revalidationOutcomeStakes(requested("operator"), resolved("held"));
    expect(rows.map((row) => row.kind)).toEqual(["revalidation_forfeit"]);
    expect(rows[0]!.amount).toBe(REVALIDATION_REQUEST_STAKE_STANDING);
    expect(rows[0]!.seq).toBe(30);
  });

  it("returns the stake and nothing beside it when the fact changed", () => {
    // The request staked for a check and got one. Section 6 pays a reward on a
    // dispute, and a check that turns up a citation is upgraded into one.
    const rows = revalidationOutcomeStakes(
      requested("operator"),
      resolved("changed"),
    );
    expect(rows.map((row) => row.kind)).toEqual(["revalidation_refund"]);
    expect(rows[0]!.amount).toBe(REVALIDATION_REQUEST_STAKE_STANDING);
  });

  it("returns the stake alone when the request is upgraded to a dispute", () => {
    // The dispute's own stake takes over: nobody stakes twice for one doubt.
    const rows = revalidationOutcomeStakes(
      requested("operator"),
      resolved("upgraded"),
    );
    expect(rows.map((row) => row.kind)).toEqual(["revalidation_refund"]);
    expect(rows[0]!.correction_entry_id).toBe(CORRECTION);
  });

  it("settles nothing on a check nobody staked for", () => {
    expect(
      revalidationOutcomeStakes(requested("failure_reports"), resolved("held")),
    ).toEqual([]);
    expect(
      revalidationOutcomeStakes(requested("failure_reports"), resolved("changed")),
    ).toEqual([]);
  });
});

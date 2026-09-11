/**
 * Disputes, revalidation requests and failure reports: the rules at the door,
 * the exclusions, and what derivation makes of the events they seal.
 *
 * Whitepaper Section 6, "Dispute" and "Revalidate"; Section 8, "Failure
 * reports"; Section 12, "Failure reports can be flooded". Every policy number
 * comes from src/policy.ts; a literal here would put a policy number in a second
 * place.
 *
 * The refusal tests walk the rules in order, each fixture failing exactly one
 * rule and no earlier one, so the first-refusal-wins promise is what is checked
 * and not merely the set of names.
 */

import { describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import { deriveEntry, type Clock } from "../src/derive.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { validateEntry } from "../src/schema.js";
import {
  DISPUTE_REFUSALS,
  FAILURE_REPORT_REFUSALS,
  REVALIDATION_REFUSALS,
  checkDisputeFiling,
  checkFailureReport,
  checkRevalidationRequest,
  checkStakeCover,
  lockedStanding,
  disputeExclusions,
  failureReportThresholdReached,
  openDispute,
  openRevalidation,
  requestsByOperatorInWindow,
  revalidationDrawExclusions,
} from "../src/dispute.js";
import type {
  ApproverRecord,
  Event,
  EventPayloads,
  EventType,
} from "../src/events.js";
import {
  DISPUTE_STAKE_STANDING,
  FAILURE_REPORT_THRESHOLD,
  REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "../src/policy.js";
import type { StakeRecord } from "../src/stake.js";

const TARGET = "nmk_01TARGET";
const CORRECTION = "nmk_01CORRECT";
const SUBJECT = "openai/gpt-5";
const CHALLENGER = "1F916:Y2hhbGxlbmdlcg";
const REPORTER = "1F916:cmVwb3J0ZXI";
const CITATION = "https://platform.openai.com/docs/pricing";
const HASH = `sha256:${"c".repeat(64)}`;
const ARTIFACT = `sha256:${"d".repeat(64)}`;
const SIGNATURE = "c2lnbmF0dXJl";
const AUTHOR_OPERATOR = "op_author";

/** The challenge's own frozen core: the eighteen keys, as the schema names them. */
function correctionCore(overrides: Record<string, unknown> = {}): Core {
  return {
    id: CORRECTION,
    subject: SUBJECT,
    category: "correction",
    domain: DEFAULT_DOMAIN,
    claim: "the price never moved",
    before: "$2.50",
    after: "$3.00",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: CHALLENGER,
    author_operator: "op_challenger",
    submitted_at: "2026-09-05T10:00:00Z",
    ...overrides,
  } as Core;
}

const VERIFIED_TARGET = {
  id: TARGET,
  subject: SUBJECT,
  status: "verified" as const,
};

function filingContext(overrides: Record<string, unknown> = {}) {
  return {
    challenger: CHALLENGER,
    challengerOperator: "op_challenger" as string | null,
    openDisputes: 0,
    ...overrides,
  };
}

describe("checkDisputeFiling", () => {
  it("accepts a correction filed by its own author against a verified entry", () => {
    expect(
      checkDisputeFiling(correctionCore(), VERIFIED_TARGET, filingContext()),
    ).toEqual({ ok: true });
  });

  const cases: readonly {
    reason: (typeof DISPUTE_REFUSALS)[number];
    core: Core;
    target: typeof VERIFIED_TARGET;
    context: ReturnType<typeof filingContext>;
  }[] = [
    {
      reason: "entry_not_verified",
      core: correctionCore(),
      target: { ...VERIFIED_TARGET, status: "draft" as never },
      context: filingContext(),
    },
    {
      reason: "not_correction",
      core: correctionCore({ category: "pricing" }),
      target: VERIFIED_TARGET,
      context: filingContext(),
    },
    {
      reason: "missing_citation",
      core: correctionCore({ citation: "   " }),
      target: VERIFIED_TARGET,
      context: filingContext(),
    },
    {
      reason: "subject_mismatch",
      core: correctionCore({ subject: "anthropic/claude-4" }),
      target: VERIFIED_TARGET,
      context: filingContext(),
    },
    {
      reason: "self_dispute",
      core: correctionCore({ author: "1F916:c29tZWJvZHlFbHNl" }),
      target: VERIFIED_TARGET,
      context: filingContext(),
    },
    {
      reason: "dispute_open",
      core: correctionCore(),
      target: VERIFIED_TARGET,
      context: filingContext({ openDisputes: 1 }),
    },
  ];

  it.each(cases)("refuses $reason", ({ reason, core, target, context }) => {
    expect(checkDisputeFiling(core, target, context)).toEqual({
      ok: false,
      reason,
    });
  });

  it("covers every refusal in DISPUTE_REFUSALS, in check order", () => {
    expect(cases.map((one) => one.reason)).toEqual([...DISPUTE_REFUSALS]);
    expect(new Set(DISPUTE_REFUSALS).size).toBe(DISPUTE_REFUSALS.length);
  });
});

/**
 * Section 9: standing "gates everything discretionary, from entry to and stay in
 * the trusted pool to revalidation-request caps and dispute stakes". What an
 * operator can stake is what it holds less what its open stakes already hold.
 */
describe("checkStakeCover", () => {
  it("passes at exactly the stake and refuses one below it", () => {
    const stake = DISPUTE_STAKE_STANDING;
    expect(checkStakeCover({ standing: stake, locked: 0, stake })).toEqual({
      ok: true,
    });
    expect(checkStakeCover({ standing: stake - 1, locked: 0, stake })).toEqual({
      ok: false,
      reason: "insufficient_standing",
    });
  });

  it("counts what open stakes already hold against what is available", () => {
    const stake = DISPUTE_STAKE_STANDING;
    // Standing enough for two filings, one of them already in flight: the
    // second is covered, the third is not.
    expect(
      checkStakeCover({ standing: stake * 2, locked: stake, stake }),
    ).toEqual({ ok: true });
    expect(
      checkStakeCover({ standing: stake * 2, locked: stake + 1, stake }),
    ).toEqual({ ok: false, reason: "insufficient_standing" });
  });

  it("refuses an operator with nothing, and one whose standing went negative", () => {
    const stake = REVALIDATION_REQUEST_STAKE_STANDING;
    expect(checkStakeCover({ standing: 0, locked: 0, stake })).toEqual({
      ok: false,
      reason: "insufficient_standing",
    });
    expect(checkStakeCover({ standing: -5, locked: 0, stake })).toEqual({
      ok: false,
      reason: "insufficient_standing",
    });
  });
});

describe("lockedStanding", () => {
  function stakeRow(overrides: Partial<StakeRecord> = {}): StakeRecord {
    return {
      kind: "dispute_stake",
      entry_id: TARGET,
      correction_entry_id: CORRECTION,
      request_seq: null,
      agent: CHALLENGER,
      operator: AUTHOR_OPERATOR,
      unit: "standing",
      amount: DISPUTE_STAKE_STANDING,
      seq: 4,
      at: "2026-09-08T12:00:00.000Z",
      ...overrides,
    };
  }

  it("adds up the standing rows and nothing else", () => {
    const rows = [
      stakeRow(),
      stakeRow({
        kind: "revalidation_stake",
        correction_entry_id: null,
        request_seq: 9,
        amount: REVALIDATION_REQUEST_STAKE_STANDING,
      }),
      // A bare key's filing fee is money, not standing: two units are never
      // added together.
      stakeRow({ unit: "cents", amount: 500, operator: null }),
      // A reward is not a stake: unpriced it carries no amount at all, and
      // priced it is micros — what the overturned entry lost.
      stakeRow({ kind: "dispute_reward", unit: null, amount: null }),
      stakeRow({ kind: "dispute_reward", unit: "micros", amount: 750_000 }),
    ];
    expect(lockedStanding(rows)).toBe(
      DISPUTE_STAKE_STANDING + REVALIDATION_REQUEST_STAKE_STANDING,
    );
    expect(lockedStanding([])).toBe(0);
  });
});

describe("checkRevalidationRequest", () => {
  const fresh = {
    status: "verified" as const,
    stale: false,
    domain: DEFAULT_DOMAIN,
  };

  function context(overrides: Record<string, unknown> = {}) {
    return {
      requesterOperator: "op_asker" as string | null,
      requestsThisWindow: 0,
      openRequest: false,
      operatorDomains: [DEFAULT_DOMAIN] as readonly string[],
      ...overrides,
    };
  }

  it("accepts an operator's first request inside the window", () => {
    expect(checkRevalidationRequest(fresh, context())).toEqual({ ok: true });
  });

  const cases: readonly {
    reason: (typeof REVALIDATION_REFUSALS)[number];
    target: typeof fresh;
    context: ReturnType<typeof context>;
  }[] = [
    {
      reason: "entry_not_verified",
      target: { ...fresh, status: "rejected" as never },
      context: context(),
    },
    {
      // Section 6 scopes the request to an entry inside its window; a stale one
      // is reconfirmed instead (src/reconfirm.ts).
      reason: "entry_stale",
      target: { ...fresh, stale: true },
      context: context(),
    },
    {
      reason: "bare_key",
      target: fresh,
      context: context({ requesterOperator: null }),
    },
    {
      // Decision D-071: standing staked in one domain buys no check in another.
      reason: "operator_not_in_domain",
      target: fresh,
      context: context({ operatorDomains: ["elsewhere"] }),
    },
    {
      reason: "cap_exceeded",
      target: fresh,
      context: context({
        requestsThisWindow: REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
      }),
    },
    {
      reason: "request_open",
      target: fresh,
      context: context({ openRequest: true }),
    },
  ];

  it.each(cases)("refuses $reason", ({ reason, target, context: ctx }) => {
    expect(checkRevalidationRequest(target, ctx)).toEqual({ ok: false, reason });
  });

  it("covers every refusal in REVALIDATION_REFUSALS, in check order", () => {
    expect(cases.map((one) => one.reason)).toEqual([...REVALIDATION_REFUSALS]);
    expect(new Set(REVALIDATION_REFUSALS).size).toBe(REVALIDATION_REFUSALS.length);
  });

  it("holds the cap at the policy number, one below it and one at it", () => {
    expect(
      checkRevalidationRequest(
        fresh,
        context({
          requestsThisWindow: REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW - 1,
        }),
      ).ok,
    ).toBe(true);
    expect(
      checkRevalidationRequest(
        fresh,
        context({
          requestsThisWindow: REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
        }),
      ).ok,
    ).toBe(false);
  });
});

describe("checkFailureReport", () => {
  const verified = { status: "verified" as const };

  function context(overrides: Record<string, unknown> = {}) {
    return {
      priorReporters: [] as readonly string[],
      reporter: REPORTER,
      observed: "The endpoint returned 404, not the documented 200.",
      artifactHash: ARTIFACT,
      ...overrides,
    };
  }

  it("accepts a bare key's first report on a verified entry", () => {
    // Section 8: readers are the largest verification pool the log has, so the
    // door is open; the flood answer is at the threshold, not here.
    expect(checkFailureReport(verified, context())).toEqual({ ok: true });
  });

  const cases: readonly {
    reason: (typeof FAILURE_REPORT_REFUSALS)[number];
    target: typeof verified;
    context: ReturnType<typeof context>;
  }[] = [
    {
      reason: "entry_not_verified",
      target: { status: "draft" as never },
      context: context(),
    },
    { reason: "empty_observed", target: verified, context: context({ observed: "  " }) },
    {
      reason: "bad_artifact_hash",
      target: verified,
      context: context({ artifactHash: "sha256:not-a-hash" }),
    },
    {
      reason: "duplicate_reporter",
      target: verified,
      context: context({ priorReporters: [REPORTER] }),
    },
  ];

  it.each(cases)("refuses $reason", ({ reason, target, context: ctx }) => {
    expect(checkFailureReport(target, ctx)).toEqual({ ok: false, reason });
  });

  it("covers every refusal in FAILURE_REPORT_REFUSALS, in check order", () => {
    expect(cases.map((one) => one.reason)).toEqual([...FAILURE_REPORT_REFUSALS]);
    expect(new Set(FAILURE_REPORT_REFUSALS).size).toBe(
      FAILURE_REPORT_REFUSALS.length,
    );
  });
});

describe("failureReportThresholdReached", () => {
  function report(
    seq: number,
    operator: string | null,
    reporter = `1F916:cmVwb3J0ZXI${seq}`,
  ): Event<"failure_report"> {
    return event(seq, "failure_report", TARGET, {
      reporter,
      operator,
      observed: "different behaviour",
      artifact_hash: ARTIFACT,
      citation: null,
    });
  }

  const registered = new Set(
    Array.from({ length: FAILURE_REPORT_THRESHOLD }, (_, i) => `op_r${i}`),
  );

  it("opens nothing on reports from bare keys alone", () => {
    // Section 12: "The threshold that auto-opens revalidation counts distinct
    // verified operators only", so a campaign of burner keys buys no check.
    const reports = Array.from({ length: FAILURE_REPORT_THRESHOLD }, (_, i) =>
      report(i, null),
    );
    expect(failureReportThresholdReached(reports, registered)).toBe(false);
  });

  it("opens a check on reports from the threshold of registered operators", () => {
    const reports = Array.from({ length: FAILURE_REPORT_THRESHOLD }, (_, i) =>
      report(i, `op_r${i}`),
    );
    expect(failureReportThresholdReached(reports, registered)).toBe(true);
  });

  it("does not count a bare key towards the threshold", () => {
    const reports = [
      ...Array.from({ length: FAILURE_REPORT_THRESHOLD - 1 }, (_, i) =>
        report(i, `op_r${i}`),
      ),
      report(FAILURE_REPORT_THRESHOLD, null),
    ];
    expect(failureReportThresholdReached(reports, registered)).toBe(false);
  });

  it("does not count an operator the registry does not hold", () => {
    const reports = [
      ...Array.from({ length: FAILURE_REPORT_THRESHOLD - 1 }, (_, i) =>
        report(i, `op_r${i}`),
      ),
      report(FAILURE_REPORT_THRESHOLD, "op_unknown"),
    ];
    expect(failureReportThresholdReached(reports, registered)).toBe(false);
  });

  it("counts one operator once however many of its agents reported", () => {
    const reports = Array.from({ length: FAILURE_REPORT_THRESHOLD + 2 }, (_, i) =>
      report(i, "op_r0"),
    );
    expect(failureReportThresholdReached(reports, registered)).toBe(false);
  });
});

describe("disputeExclusions", () => {
  function approver(operator: string, decision: "approve" | "reject"): ApproverRecord {
    return {
      agent: `1F916:${operator}`,
      operator,
      decision,
      snapshot_hash: decision === "approve" ? HASH : null,
      reason: decision === "reject" ? "wrong" : null,
      assigned_random: false,
      signed_at: "2026-09-02T10:00:00Z",
    };
  }

  it("bars the submitter's operator and every operator that signed", () => {
    // Section 6: "no operator that signed the original, submitter or validator,
    // may validate the challenge against it." A rejection is a signature too.
    expect(
      disputeExclusions({
        author_operator: AUTHOR_OPERATOR,
        approvers: [
          approver("op_v1", "approve"),
          approver("op_v2", "reject"),
          approver("op_v1", "approve"),
        ],
      }),
    ).toEqual([AUTHOR_OPERATOR, "op_v1", "op_v2"]);
  });

  it("bars nobody for a bare-key submitter with no decisions yet", () => {
    expect(disputeExclusions({ author_operator: null, approvers: [] })).toEqual([]);
  });

  it("does not repeat the submitter's operator when it also validated", () => {
    expect(
      disputeExclusions({
        author_operator: AUTHOR_OPERATOR,
        approvers: [approver(AUTHOR_OPERATOR, "approve")],
      }),
    ).toEqual([AUTHOR_OPERATOR]);
  });
});

describe("revalidationDrawExclusions", () => {
  it("bars the submitter's operator and the requester's", () => {
    expect(revalidationDrawExclusions(AUTHOR_OPERATOR, "op_asker")).toEqual([
      AUTHOR_OPERATOR,
      "op_asker",
    ]);
  });

  it("bars each only once, and bars nothing nomankind opened itself", () => {
    expect(revalidationDrawExclusions(AUTHOR_OPERATOR, AUTHOR_OPERATOR)).toEqual([
      AUTHOR_OPERATOR,
    ]);
    expect(revalidationDrawExclusions(null, null)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The target's own events
// ---------------------------------------------------------------------------

/** A hand-built event. These folds never look at the hashes. */
function event<T extends EventType>(
  seq: number,
  type: T,
  entryId: string | null,
  payload: EventPayloads[T],
): Event<T> {
  return {
    seq,
    at: new Date(Date.parse("2026-09-01T00:00:00Z") + seq * 3_600_000).toISOString(),
    type,
    entry_id: entryId,
    payload,
    prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
    hash: `hash-${seq}`,
  };
}

function filedEvent(
  seq: number,
  correction = CORRECTION,
  from: { report?: number; revalidation?: number } = {},
): Event<"dispute_filed"> {
  return event(seq, "dispute_filed", TARGET, {
    correction_entry_id: correction,
    challenger: CHALLENGER,
    operator: "op_challenger",
    citation: CITATION,
    snapshot_hash: HASH,
    from_report_seq: from.report ?? null,
    from_revalidation_seq: from.revalidation ?? null,
  });
}

describe("openDispute and openRevalidation", () => {
  it("finds the filed dispute nothing has settled", () => {
    const events = [filedEvent(5)];
    expect(openDispute(events)?.seq).toBe(5);
  });

  it("finds nothing once the dispute is upheld or failed", () => {
    expect(
      openDispute([
        filedEvent(5),
        event(6, "dispute_upheld", TARGET, { correction_entry_id: CORRECTION }),
      ]),
    ).toBeNull();
    expect(
      openDispute([
        filedEvent(5),
        event(6, "dispute_failed", TARGET, {
          correction_entry_id: CORRECTION,
          reason: "no",
        }),
      ]),
    ).toBeNull();
  });

  it("matches an outcome to its own correction, not to a later filing", () => {
    const events = [
      filedEvent(5, "nmk_01FIRST"),
      event(6, "dispute_failed", TARGET, {
        correction_entry_id: "nmk_01FIRST",
        reason: null,
      }),
      filedEvent(7, "nmk_01SECOND"),
    ];
    expect(openDispute(events)?.payload.correction_entry_id).toBe("nmk_01SECOND");
  });

  it("finds an unresolved request, and nothing once it resolves", () => {
    const request = event(5, "revalidation_requested", TARGET, {
      requester: "1F916:cmVx",
      operator: "op_asker",
      source: "operator" as const,
    });
    expect(openRevalidation([request])?.seq).toBe(5);
    expect(
      openRevalidation([
        request,
        event(6, "revalidation_resolved", TARGET, {
          request_seq: 5,
          outcome: "held" as const,
          checker: "1F916:Y2hr",
          operator: "op_checker",
          snapshot_hash: HASH,
          correction_entry_id: null,
        }),
      ]),
    ).toBeNull();
  });

  it("leaves the request open when only the assignment was missed", () => {
    const request = event(5, "revalidation_requested", TARGET, {
      requester: "1F916:cmVx",
      operator: "op_asker",
      source: "operator" as const,
    });
    const missed = event(7, "revalidation_missed", TARGET, {
      request_seq: 5,
      agent: "1F916:Y2hr",
      operator: "op_checker",
    });
    expect(openRevalidation([request, missed])?.seq).toBe(5);
  });
});

describe("requestsByOperatorInWindow", () => {
  function request(seq: number, operator: string | null) {
    return event(seq, "revalidation_requested", TARGET, {
      requester: operator === null ? null : `1F916:${operator}`,
      operator,
      source: (operator === null ? "failure_reports" : "operator") as
        | "operator"
        | "failure_reports",
    });
  }

  it("counts one operator's requests since the window opened", () => {
    const events = [request(1, "op_a"), request(2, "op_b"), request(3, "op_a")];
    const windowStart = events[0]!.at;
    expect(requestsByOperatorInWindow(events, "op_a", windowStart)).toBe(2);
    expect(requestsByOperatorInWindow(events, "op_b", windowStart)).toBe(1);
    expect(requestsByOperatorInWindow(events, "op_c", windowStart)).toBe(0);
  });

  it("drops requests made before the current window opened", () => {
    const early = request(1, "op_a");
    const late = request(5, "op_a");
    // The window opened before both: both count.
    expect(requestsByOperatorInWindow([early, late], "op_a", early.at)).toBe(2);
    // It reopened between them, so the older one is outside it and the cap
    // resets with the window, exactly as "per operator per window" says.
    expect(requestsByOperatorInWindow([early, late], "op_a", late.at)).toBe(1);
  });

  it("counts nothing for a request nobody staked, which names no operator", () => {
    expect(requestsByOperatorInWindow([request(1, null)], "op_a", "")).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/** A verified target and the events that made it so, then the dispute events. */
function targetLog(extra: readonly Event[]): Event[] {
  const core = {
    id: TARGET,
    subject: SUBJECT,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00",
    after: "$2.50",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: "1F916:YXV0aG9y",
    author_operator: AUTHOR_OPERATOR,
    submitted_at: "2026-09-01T00:00:00Z",
  } as Core;
  return [
    event(0, "entry_submitted", TARGET, { core, signature: SIGNATURE }),
    ...extra,
  ];
}

describe("derivation of disputes[]", () => {
  it("folds a filed dispute into the schema's disputes[] item, open", () => {
    const filed = filedEvent(1);
    const derived = deriveEntry(targetLog([filed]), TARGET, CLOCK);
    expect(derived.entry.disputes).toEqual([
      {
        id: CORRECTION,
        challenger: CHALLENGER,
        operator: "op_challenger",
        citation: CITATION,
        snapshot_hash: HASH,
        outcome: "open",
        reason: null,
        filed_at: filed.at,
        resolved_at: null,
      },
    ]);
  });

  it("marks it upheld and overturns the entry, linked to its correction", () => {
    const upheld = event(2, "dispute_upheld", TARGET, {
      correction_entry_id: CORRECTION,
    });
    const derived = deriveEntry(targetLog([filedEvent(1), upheld]), TARGET, CLOCK);
    const [dispute] = derived.entry.disputes as Record<string, unknown>[];
    expect(dispute!["outcome"]).toBe("upheld");
    expect(dispute!["resolved_at"]).toBe(upheld.at);
    // Section 6: "The original stays in the log, marked overturned, linked to
    // its correction."
    expect(derived.derived.status).toBe("overturned");
    expect(derived.derived.overturned_by).toBe(CORRECTION);
  });

  it("marks it failed and carries the rejection's reason", () => {
    const failed = event(2, "dispute_failed", TARGET, {
      correction_entry_id: CORRECTION,
      reason: "The cited page says what the entry says.",
    });
    const derived = deriveEntry(targetLog([filedEvent(1), failed]), TARGET, CLOCK);
    const [dispute] = derived.entry.disputes as Record<string, unknown>[];
    expect(dispute!["outcome"]).toBe("failed");
    expect(dispute!["reason"]).toBe("The cited page says what the entry says.");
    expect(derived.derived.status).not.toBe("overturned");
  });

  it("produces arrays the published schema accepts", () => {
    // The schema is the field-name authority (schema/nomankind-entry-schema.json,
    // disputes[] and failure_reports[]): additionalProperties is false on both,
    // so a folded item with a key of its own would be refused here.
    const events = [
      ...targetLog([]),
      event(1, "failure_report", TARGET, {
        reporter: REPORTER,
        operator: "op_r0",
        observed: "The endpoint returned 404.",
        artifact_hash: ARTIFACT,
        citation: CITATION,
      }),
      filedEvent(2, CORRECTION, { report: 1 }),
      event(3, "dispute_failed", TARGET, {
        correction_entry_id: CORRECTION,
        reason: "The cited page says what the entry says.",
      }),
    ];
    const derived = deriveEntry(events, TARGET, CLOCK);
    const result = validateEntry(derived.entry);
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("leaves the array empty when nobody has disputed the entry", () => {
    expect(deriveEntry(targetLog([]), TARGET, CLOCK).entry.disputes).toEqual([]);
    expect(deriveEntry(targetLog([]), TARGET, CLOCK).entry.failure_reports).toEqual(
      [],
    );
  });
});

describe("derivation of failure_reports[]", () => {
  function reportEvent(seq: number, operator: string | null, citation: string | null) {
    return event(seq, "failure_report", TARGET, {
      reporter: `1F916:cmVwb3J0ZXI${seq}`,
      operator,
      observed: "The endpoint returned 404.",
      artifact_hash: ARTIFACT,
      citation,
    });
  }

  it("folds a report into the schema's failure_reports[] item", () => {
    const report = reportEvent(1, "op_r0", null);
    const derived = deriveEntry(targetLog([report]), TARGET, CLOCK);
    expect(derived.entry.failure_reports).toEqual([
      {
        reporter: report.payload.reporter,
        operator: "op_r0",
        observed: "The endpoint returned 404.",
        artifact_hash: ARTIFACT,
        citation: null,
        upgraded_to: null,
        filed_at: report.at,
      },
    ]);
  });

  it("links the report a dispute was upgraded from to that dispute", () => {
    const report = reportEvent(1, "op_r0", CITATION);
    const derived = deriveEntry(
      targetLog([report, filedEvent(2, CORRECTION, { report: 1 })]),
      TARGET,
      CLOCK,
    );
    const [row] = derived.entry.failure_reports as Record<string, unknown>[];
    expect(row!["upgraded_to"]).toBe(CORRECTION);
    // A report nobody upgraded keeps a null link.
    const other = deriveEntry(targetLog([reportEvent(1, "op_r1", null)]), TARGET, CLOCK);
    expect((other.entry.failure_reports as Record<string, unknown>[])[0]!["upgraded_to"])
      .toBeNull();
  });
});

describe("derivation of the sidecar's revalidations", () => {
  const request = event(1, "revalidation_requested", TARGET, {
    requester: "1F916:cmVx",
    operator: "op_asker",
    source: "operator" as const,
  });
  const assigned = event(2, "revalidation_assigned", TARGET, {
    request_seq: 1,
    agent: "1F916:Y2hlY2tlcg",
    operator: "op_checker",
    beacon_round: 991,
    deadline: "2026-09-05T00:00:00Z",
  });

  it("opens with the request and the draw in force", () => {
    const derived = deriveEntry(targetLog([request, assigned]), TARGET, CLOCK);
    expect(derived.sidecar.revalidations).toEqual([
      {
        request_seq: 1,
        requester: "1F916:cmVx",
        operator: "op_asker",
        source: "operator",
        requested_at: request.at,
        assigned: {
          agent: "1F916:Y2hlY2tlcg",
          operator: "op_checker",
          deadline: "2026-09-05T00:00:00Z",
        },
        outcome: "open",
        resolved_at: null,
        checker: null,
        correction_entry_id: null,
      },
    ]);
  });

  it("clears the draw on a miss and leaves the request open", () => {
    const missed = event(3, "revalidation_missed", TARGET, {
      request_seq: 1,
      agent: "1F916:Y2hlY2tlcg",
      operator: "op_checker",
    });
    const derived = deriveEntry(targetLog([request, assigned, missed]), TARGET, CLOCK);
    expect(derived.sidecar.revalidations[0]!.assigned).toBeNull();
    expect(derived.sidecar.revalidations[0]!.outcome).toBe("open");
  });

  it("carries the outcome the checker signed", () => {
    const resolvedEvent = event(3, "revalidation_resolved", TARGET, {
      request_seq: 1,
      outcome: "held" as const,
      checker: "1F916:Y2hlY2tlcg",
      operator: "op_checker",
      snapshot_hash: HASH,
      correction_entry_id: null,
    });
    const derived = deriveEntry(
      targetLog([request, assigned, resolvedEvent]),
      TARGET,
      CLOCK,
    );
    const [view] = derived.sidecar.revalidations;
    expect(view!.outcome).toBe("held");
    expect(view!.resolved_at).toBe(resolvedEvent.at);
    expect(view!.checker).toBe("1F916:Y2hlY2tlcg");
  });

  it("names nomankind's own check as auto-opened, with nobody staking", () => {
    const auto = event(1, "revalidation_requested", TARGET, {
      requester: null,
      operator: null,
      source: "failure_reports" as const,
    });
    const [view] = deriveEntry(targetLog([auto]), TARGET, CLOCK).sidecar.revalidations;
    expect(view!.source).toBe("failure_reports");
    expect(view!.requester).toBeNull();
    expect(view!.operator).toBeNull();
  });

  it("is empty when nobody has asked for a check", () => {
    expect(deriveEntry(targetLog([]), TARGET, CLOCK).sidecar.revalidations).toEqual([]);
  });
});

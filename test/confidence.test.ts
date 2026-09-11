/**
 * The confidence field: null for every entry, with no formula named, and every
 * input to it exposed raw exactly as Section 8 promises.
 */

import { describe, expect, it } from "vitest";

import { confidenceInputs } from "../src/confidence.js";
import type { Sidecar } from "../src/derive.js";
import type { Entry } from "../src/schema.js";

const NOW = "2026-09-10T12:00:00.000Z";

const SIDECAR: Sidecar = {
  needs_replacement: false,
  effective_tier: "observed",
  test_verdict: "accepted",
  trusted_count_at_decision: 12,
  read_share_slots: null,
  revalidations: [],
  source: {
    class: "official",
    matched_host: "platform.openai.com",
    authority: "openai",
  },
};

function reproduction(runs: number, holds: number): Record<string, unknown> {
  return {
    model: "openai/gpt-5",
    output: "404 model_deprecated",
    observed_at: "2026-08-01",
    runs,
    holds,
  };
}

function observation(runs: number, holds: number): Record<string, unknown> {
  return {
    method: "metered_call",
    receipt_hash: `sha256:${"3".repeat(64)}`,
    observed_at: "2026-08-01",
    runs,
    holds,
  };
}

function approver(
  operator: string,
  decision: "approve" | "reject",
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
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
    signed_at: "2026-08-02T00:00:00.000Z",
    ...extra,
  };
}

function reconfirmation(
  operator: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    agent: `1F916:${operator}-agent`,
    operator,
    snapshot_hash: `sha256:${"4".repeat(64)}`,
    reproduction: null,
    observation: null,
    signed_at: "2026-09-01T00:00:00.000Z",
    ...extra,
  };
}

function entryOf(overrides: Record<string, unknown> = {}): Entry {
  return {
    id: "nmk_e1",
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "input is $1.25 per million tokens",
    before: "1.00",
    after: "1.25",
    effective_at: "2026-08-01",
    evidence_tier: "observed",
    evidence: null,
    observation: observation(10, 10),
    citation: "https://example.test/pricing",
    snapshot_hash: `sha256:${"1".repeat(64)}`,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: "1F916:author",
    author_operator: "op_alpha",
    submitted_at: "2026-08-01T00:00:00.000Z",
    signature: "c2lnbmF0dXJl",
    approvers: [],
    reconfirmations: [],
    disputes: [],
    failure_reports: [],
    seal: null,
    staleness_window_days: 90,
    verified_at: "2026-08-02T00:00:00.000Z",
    last_confirmed: "2026-09-01",
    expires_at: "2026-11-30",
    stale: false,
    superseded_by: null,
    overturned_by: null,
    status: "verified",
    confidence: null,
    ...overrides,
  } as Entry;
}

/** Exactly the fields the endpoint publishes, in the order it publishes them. */
const FIELDS = [
  "confidence",
  "formula",
  "evidence_tier",
  "effective_tier",
  "source_class",
  "source_matched_host",
  "test_verdict",
  "test_acceptance",
  "counts",
  "age_ratio",
  "stale",
  "dispute_count",
  "report_count",
  "duplicate_of",
  "duplicate_rejections",
  "superseded",
  "overturned",
  "status",
];

describe("the confidence inputs", () => {
  it("publishes exactly the named fields, with confidence and formula null", () => {
    const inputs = confidenceInputs({
      entry: entryOf(),
      sidecar: SIDECAR,
      now: NOW,
    });
    expect(Object.keys(inputs)).toEqual(FIELDS);
    expect(inputs.confidence).toBeNull();
    expect(inputs.formula).toBeNull();
  });

  it("publishes the source class and the host it matched, raw (D-080)", () => {
    // Where the claim came from is a receipt like every other input here: it is
    // exposed and never weighted, so a learner can prefer provider-stated
    // pricing for itself without waiting for a formula nobody has calibrated.
    const inputs = confidenceInputs({
      entry: entryOf(),
      sidecar: SIDECAR,
      now: NOW,
    });

    expect(inputs.source_class).toBe("official");
    expect(inputs.source_matched_host).toBe("platform.openai.com");
  });

  it("reads a sidecar with no source key at all as no class", () => {
    // A row written before the key existed, handed over by a caller that did not
    // default it: null is the honest answer, and it fails any reader's demand.
    const { source: _source, ...withoutSource } = SIDECAR;
    const inputs = confidenceInputs({
      entry: entryOf(),
      sidecar: withoutSource as typeof SIDECAR,
      now: NOW,
    });

    expect(inputs.source_class).toBeNull();
    expect(inputs.source_matched_host).toBeNull();
  });

  it("says nothing about duplication for an entry nobody claimed was one", () => {
    // Null and zero, not absent: the fields are published for every entry, and
    // most entries are nobody's duplicate.
    const inputs = confidenceInputs({
      entry: entryOf({ approvers: [approver("op_d", "reject")] }),
      sidecar: SIDECAR,
      now: NOW,
    });

    expect(inputs.duplicate_of).toBeNull();
    expect(inputs.duplicate_rejections).toBe(0);
  });

  it("publishes the entry a validator rejected this one as a duplicate of (D-085)", () => {
    // The mechanical duplicate never reaches a row — the submit door refuses it
    // — so what a reader sees here is a judgment, published raw with its size
    // beside it and weighted by nobody.
    const duplicated = "nmk_00112233445566778899aabbccddeeff";
    const inputs = confidenceInputs({
      entry: entryOf({
        approvers: [
          approver("op_b", "approve"),
          approver("op_c", "reject", {
            reason: `duplicate_claim:${duplicated}`,
          }),
        ],
      }),
      sidecar: SIDECAR,
      now: NOW,
    });

    expect(inputs.duplicate_of).toBe(duplicated);
    expect(inputs.duplicate_rejections).toBe(1);
  });

  it("reads a verified observed entry's tiers, counts and age", () => {
    const entry = entryOf({
      approvers: [
        approver("op_b", "approve", {
          test_accepted: true,
          observation: observation(10, 9),
        }),
        approver("op_c", "approve", {
          test_accepted: true,
          reproduction: reproduction(10, 8),
        }),
        approver("op_d", "reject", { test_accepted: false }),
      ],
      reconfirmations: [
        reconfirmation("op_e", { reproduction: reproduction(10, 10) }),
        reconfirmation("op_f", { observation: observation(5, 5) }),
      ],
    });
    const inputs = confidenceInputs({ entry, sidecar: SIDECAR, now: NOW });

    expect(inputs.evidence_tier).toBe("observed");
    expect(inputs.effective_tier).toBe("observed");
    expect(inputs.test_verdict).toBe("accepted");
    expect(inputs.test_acceptance).toEqual({ accepted: 2, rejected: 1 });
    expect(inputs.counts).toEqual({
      approvals: 2,
      rejections: 1,
      // An approval and a reconfirmation both count as somebody having run it.
      reproductions: { records: 2, runs: 20, holds: 18 },
      observations: 2,
      reconfirmations: 2,
    });
    // 2026-09-01 to 2026-09-10 is nine whole UTC days, against a 90-day window.
    expect(inputs.age_ratio).toEqual({ days: 9, window_days: 90 });
    expect(inputs.stale).toBe(false);
    expect(inputs.superseded).toBe(false);
    expect(inputs.overturned).toBe(false);
    expect(inputs.status).toBe("verified");
  });

  it("counts nothing at all on an entry nobody has touched", () => {
    const inputs = confidenceInputs({
      entry: entryOf(),
      sidecar: SIDECAR,
      now: NOW,
    });
    expect(inputs.test_acceptance).toEqual({ accepted: 0, rejected: 0 });
    expect(inputs.counts).toEqual({
      approvals: 0,
      rejections: 0,
      reproductions: { records: 0, runs: 0, holds: 0 },
      observations: 0,
      reconfirmations: 0,
    });
    expect(inputs.dispute_count).toEqual({
      open: 0,
      upheld: 0,
      failed: 0,
      total: 0,
    });
    expect(inputs.report_count).toEqual({ total: 0, distinct_operators: 0 });
  });

  it("gives an unverified entry no age ratio", () => {
    const draft = confidenceInputs({
      entry: entryOf({
        status: "draft",
        verified_at: null,
        approvers: [approver("op_b", "approve", { test_accepted: true })],
      }),
      sidecar: { ...SIDECAR, effective_tier: null, test_verdict: null },
      now: NOW,
    });
    expect(draft.status).toBe("draft");
    expect(draft.age_ratio).toBeNull();
    expect(draft.effective_tier).toBeNull();
    expect(draft.test_verdict).toBeNull();
    // The counts still say what happened: an unverified entry has receipts too.
    expect(draft.counts.approvals).toBe(1);
  });

  it("gives an entry with no window no age ratio either", () => {
    // Section 7: event categories carry no window, "because once they happened
    // they stay true", so there is nothing for an age to be a ratio against.
    const inputs = confidenceInputs({
      entry: entryOf({
        category: "release",
        staleness_window_days: null,
        expires_at: null,
      }),
      sidecar: SIDECAR,
      now: NOW,
    });
    expect(inputs.age_ratio).toBeNull();
    expect(inputs.stale).toBe(false);
  });

  it("never reports a negative age", () => {
    const inputs = confidenceInputs({
      entry: entryOf({ last_confirmed: "2026-09-20" }),
      sidecar: SIDECAR,
      now: NOW,
    });
    expect(inputs.age_ratio).toEqual({ days: 0, window_days: 90 });
  });

  it("counts disputes in each outcome", () => {
    const dispute = (
      id: string,
      outcome: "open" | "upheld" | "failed",
    ): Record<string, unknown> => ({
      id,
      challenger: "1F916:challenger",
      operator: "op_z",
      citation: "https://example.test/correction",
      snapshot_hash: `sha256:${"5".repeat(64)}`,
      outcome,
      reason: null,
      filed_at: "2026-09-02T00:00:00.000Z",
      resolved_at: outcome === "open" ? null : "2026-09-03T00:00:00.000Z",
    });

    const inputs = confidenceInputs({
      entry: entryOf({
        disputes: [
          dispute("nmk_d1", "open"),
          dispute("nmk_d2", "upheld"),
          dispute("nmk_d3", "failed"),
          dispute("nmk_d4", "failed"),
        ],
        overturned_by: "nmk_d2",
        status: "overturned",
      }),
      sidecar: SIDECAR,
      now: NOW,
    });

    expect(inputs.dispute_count).toEqual({
      open: 1,
      upheld: 1,
      failed: 2,
      total: 4,
    });
    expect(inputs.overturned).toBe(true);
    expect(inputs.status).toBe("overturned");
    // Not verified any more, so the age says nothing.
    expect(inputs.age_ratio).toBeNull();
  });

  it("counts failure reports in total and distinct verified operators only", () => {
    const report = (operator: string | null): Record<string, unknown> => ({
      reporter: `1F916:${operator ?? "bare"}-reporter`,
      operator,
      observed: "the endpoint charged a different price",
      artifact_hash: `sha256:${"6".repeat(64)}`,
      citation: null,
      upgraded_to: null,
      filed_at: "2026-09-04T00:00:00.000Z",
    });

    const inputs = confidenceInputs({
      entry: entryOf({
        failure_reports: [
          report("op_r1"),
          // The same operator twice is one distinct operator.
          report("op_r1"),
          report("op_r2"),
          // Section 12: a flood of bare keys moves the total and nothing else.
          report(null),
          report(null),
          report(null),
        ],
      }),
      sidecar: SIDECAR,
      now: NOW,
    });

    expect(inputs.report_count).toEqual({ total: 6, distinct_operators: 2 });
  });

  it("says when an entry is stale or superseded", () => {
    const inputs = confidenceInputs({
      entry: entryOf({
        stale: true,
        superseded_by: "nmk_e2",
        status: "superseded",
      }),
      sidecar: SIDECAR,
      now: NOW,
    });
    expect(inputs.stale).toBe(true);
    expect(inputs.superseded).toBe(true);
    expect(inputs.status).toBe("superseded");
  });

  it("reads the effective tier and not the claimed one", () => {
    // Section 4: an observed entry whose test a majority rejected "is validated
    // as a document and its effective tier is stated".
    const inputs = confidenceInputs({
      entry: entryOf({
        approvers: [
          approver("op_b", "approve", { test_accepted: false }),
          approver("op_c", "approve", { test_accepted: false }),
        ],
      }),
      sidecar: {
        ...SIDECAR,
        effective_tier: "stated",
        test_verdict: "rejected",
      },
      now: NOW,
    });
    expect(inputs.evidence_tier).toBe("observed");
    expect(inputs.effective_tier).toBe("stated");
    expect(inputs.test_verdict).toBe("rejected");
    expect(inputs.test_acceptance).toEqual({ accepted: 0, rejected: 2 });
  });
});

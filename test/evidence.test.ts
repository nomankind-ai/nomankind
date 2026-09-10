/**
 * Two tiers of evidence: which text the validators judge, the shape a core and
 * a record must carry, the n-of-k rule, and the tier an entry ends up at.
 *
 * Every n-of-k number here comes from src/policy.ts; a literal would put a
 * policy number in a second place.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { DEFAULT_DOMAIN, DOMAINS } from "../src/policy.js";

import { extractCore, type Core } from "../src/core.js";
import type { ApproverRecord } from "../src/events.js";
import { REPRODUCTION_HOLDS, REPRODUCTION_RUNS } from "../src/policy.js";
import {
  CORE_EVIDENCE_REFUSALS,
  NO_PREDICATE,
  RECORD_EVIDENCE_REFUSALS,
  checkCoreEvidence,
  checkRecordEvidence,
  evidenceGate,
  isTranscriptCategory,
  isWellFormedMeasurement,
  measurementPasses,
  proposedTest,
  testVerdict,
  type CoreEvidenceRefusal,
  type RecordEvidenceRefusal,
  type TestVerdict,
} from "../src/evidence.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

/** The worked example: an observed deprecation with three approvals. */
function exampleCore(): Core {
  return extractCore(
    JSON.parse(readFileSync(examplePath, "utf8")) as Record<string, unknown>,
  );
}

const CITATION = "https://platform.openai.com/docs/deprecations";
const OTHER_CITATION = "https://example.com/other";
const HASH = `sha256:${"a".repeat(64)}`;
const RECEIPT = `sha256:${"b".repeat(64)}`;
const SIGNED_AT = "2026-09-08T00:00:00Z";

/** A stated release core: the seventeen keys, exactly as the schema names them. */
function statedCore(overrides: Partial<Record<string, unknown>> = {}): Core {
  return {
    id: "nmk_01STATED01",
    subject: "openai/gpt-5",
    category: "release",
    claim: "GPT-5 announced on the OpenAI blog",
    before: null,
    after: "available",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: "1F916:c3RhdGVkQXV0aG9y",
    author_operator: "op_brightloop",
    submitted_at: "2026-09-01T14:05:00Z",
    ...overrides,
  } as Core;
}

/** An observed pricing core: the measurement lives in `observation`. */
function observedCore(observation: unknown = defaultObservation()): Core {
  return statedCore({
    id: "nmk_01OBSERVED",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    evidence_tier: "observed",
    observation,
  });
}

function defaultObservation(): Record<string, unknown> {
  return {
    method: "metered_call",
    test: "Bill one 1000-token call; holds if the invoice line reads $2.50 per million input tokens.",
    receipt_hash: RECEIPT,
    observed_at: "2026-09-01",
    notes: null,
  };
}

/** A behavior core: always observed, measurement frozen in `evidence`. */
function behaviorCore(evidence: unknown = defaultEvidence()): Core {
  return statedCore({
    id: "nmk_01BEHAVIOR",
    category: "behavior",
    claim: "gpt-5 refuses the frozen prompt",
    evidence_tier: "observed",
    evidence,
  });
}

function defaultEvidence(
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    model: "gpt-5",
    prompt: "Summarize this in one word.",
    parameters: { temperature: 0 },
    output: "I can't help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
    ...overrides,
  };
}

function measurement(runs: number, holds: number): Record<string, unknown> {
  return { method: "metered_call", receipt_hash: RECEIPT, observed_at: "2026-09-01", runs, holds };
}

function reproduction(runs: number, holds: number): Record<string, unknown> {
  return {
    model: "gpt-5",
    output: "I can't help with that.",
    observed_at: "2026-09-01",
    runs,
    holds,
  };
}

let nextAgent = 0;

function record(overrides: Partial<ApproverRecord> = {}): ApproverRecord {
  nextAgent += 1;
  return {
    agent: `1F916:YWdlbnQ${nextAgent}`,
    operator: `op_v${nextAgent}`,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: SIGNED_AT,
    ...overrides,
  };
}

describe("transcript categories", () => {
  it("names behavior and misbehavior of the default domain, and nothing else", () => {
    expect(DOMAINS[DEFAULT_DOMAIN]!.transcript_categories).toEqual([
      "behavior",
      "misbehavior",
    ]);
    expect(isTranscriptCategory(DEFAULT_DOMAIN, "behavior")).toBe(true);
    expect(isTranscriptCategory(DEFAULT_DOMAIN, "misbehavior")).toBe(true);
    for (const category of ["release", "deprecation", "pricing", "limit", "outage", "correction"]) {
      expect(isTranscriptCategory(DEFAULT_DOMAIN, category)).toBe(false);
    }
    expect(isTranscriptCategory(DEFAULT_DOMAIN, null)).toBe(false);
    expect(isTranscriptCategory(DEFAULT_DOMAIN, undefined)).toBe(false);
    expect(isTranscriptCategory(DEFAULT_DOMAIN, 42)).toBe(false);
  });

  it("answers no for a domain nobody registered", () => {
    expect(isTranscriptCategory("biotech", "behavior")).toBe(false);
  });
});

describe("proposedTest", () => {
  it("reads observation.test on an observed non-transcript entry", () => {
    const core = exampleCore();
    const observation = core.observation as Record<string, unknown>;
    expect(proposedTest(core)).toBe(observation.test);
    expect(proposedTest(core)).toContain("model_deprecated");
  });

  it("reads evidence.predicate on a transcript entry", () => {
    expect(proposedTest(behaviorCore())).toBe("the model refuses this prompt");
    expect(
      proposedTest(
        statedCore({
          category: "misbehavior",
          evidence_tier: "observed",
          evidence: defaultEvidence({ predicate: "the model names a competitor" }),
        }),
      ),
    ).toBe("the model names a competitor");
  });

  it("is null for a stated entry", () => {
    expect(proposedTest(statedCore())).toBeNull();
  });

  it("is null when the text is missing, blank, or not a string", () => {
    expect(proposedTest(observedCore(null))).toBeNull();
    expect(proposedTest(observedCore({ method: "metered_call" }))).toBeNull();
    expect(proposedTest(observedCore({ ...defaultObservation(), test: "   " }))).toBeNull();
    expect(proposedTest(observedCore({ ...defaultObservation(), test: 7 }))).toBeNull();
    expect(proposedTest(behaviorCore(defaultEvidence({ predicate: "\t\n " })))).toBeNull();
    expect(proposedTest(behaviorCore(null))).toBeNull();
  });
});

describe("checkCoreEvidence", () => {
  it("lists its refusals in check order", () => {
    expect(CORE_EVIDENCE_REFUSALS).toEqual(["provider_statement_mismatch", "no_predicate"]);
    expect(NO_PREDICATE).toBe("no_predicate");
  });

  it("refuses a provider_statement that is not the citation", () => {
    const core = behaviorCore(defaultEvidence({ provider_statement: OTHER_CITATION }));
    expect(checkCoreEvidence(core)).toEqual({
      ok: false,
      reason: "provider_statement_mismatch" satisfies CoreEvidenceRefusal,
    });
  });

  it("passes when the provider_statement equals the citation, or is null", () => {
    expect(
      checkCoreEvidence(behaviorCore(defaultEvidence({ provider_statement: CITATION }))),
    ).toEqual({ ok: true });
    expect(checkCoreEvidence(behaviorCore())).toEqual({ ok: true });
  });

  it("refuses an observed entry with no proposed test", () => {
    expect(
      checkCoreEvidence(observedCore({ ...defaultObservation(), test: "  " })),
    ).toEqual({ ok: false, reason: "no_predicate" });
    expect(
      checkCoreEvidence(behaviorCore(defaultEvidence({ predicate: "" }))),
    ).toEqual({ ok: false, reason: NO_PREDICATE });
    expect(checkCoreEvidence(observedCore(null))).toEqual({ ok: false, reason: "no_predicate" });
  });

  it("checks the provider statement before the predicate", () => {
    const core = behaviorCore(
      defaultEvidence({ provider_statement: OTHER_CITATION, predicate: " " }),
    );
    expect(checkCoreEvidence(core)).toEqual({
      ok: false,
      reason: "provider_statement_mismatch",
    });
  });

  it("passes a stated core and the worked example", () => {
    expect(checkCoreEvidence(statedCore())).toEqual({ ok: true });
    expect(checkCoreEvidence(exampleCore())).toEqual({ ok: true });
  });
});

describe("isWellFormedMeasurement", () => {
  it("accepts the schema's reproduction and observation shapes", () => {
    expect(isWellFormedMeasurement(measurement(REPRODUCTION_RUNS, REPRODUCTION_HOLDS))).toBe(true);
    expect(isWellFormedMeasurement(reproduction(REPRODUCTION_RUNS, 0))).toBe(true);
    expect(isWellFormedMeasurement({ runs: 1, holds: 1 })).toBe(true);
  });

  it("rejects counts that cannot be counts", () => {
    expect(isWellFormedMeasurement({ runs: 5, holds: 6 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: 0, holds: 0 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: 10, holds: -1 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: 10.5, holds: 8 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: 10, holds: 8.5 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: "10", holds: 8 })).toBe(false);
    expect(isWellFormedMeasurement({ holds: 8 })).toBe(false);
    expect(isWellFormedMeasurement({ runs: 10 })).toBe(false);
  });

  it("rejects anything that is not an object", () => {
    for (const value of [null, undefined, 10, "10", true, [10, 8]]) {
      expect(isWellFormedMeasurement(value)).toBe(false);
    }
  });
});

describe("measurementPasses", () => {
  const cases: ReadonlyArray<readonly [number, number, boolean]> = [
    [REPRODUCTION_RUNS, REPRODUCTION_HOLDS, true],
    [REPRODUCTION_RUNS, REPRODUCTION_RUNS, true],
    [REPRODUCTION_RUNS, REPRODUCTION_HOLDS - 1, false],
    [REPRODUCTION_RUNS - 1, REPRODUCTION_HOLDS, false],
    [REPRODUCTION_RUNS + 1, REPRODUCTION_HOLDS, false],
  ];

  for (const [runs, holds, expected] of cases) {
    it(`${holds} of ${runs} ${expected ? "passes" : "fails"} the n-of-k rule`, () => {
      expect(measurementPasses({ runs, holds })).toBe(expected);
    });
  }
});

describe("checkRecordEvidence", () => {
  it("lists its refusals in check order", () => {
    expect(RECORD_EVIDENCE_REFUSALS).toEqual([
      "missing_test_accepted",
      "unexpected_test_accepted",
      "misplaced_measurement",
      "bad_measurement",
      "missing_observation",
    ]);
  });

  it("needs a boolean test_accepted on an observed entry", () => {
    const refusal = { ok: false, reason: "missing_test_accepted" satisfies RecordEvidenceRefusal };
    expect(checkRecordEvidence(record({ test_accepted: null }), observedCore())).toEqual(refusal);
    expect(checkRecordEvidence(record({ test_accepted: undefined }), observedCore())).toEqual(
      refusal,
    );
  });

  it("needs it on a rejection just as much as on an approval", () => {
    expect(
      checkRecordEvidence(
        record({ decision: "reject", reason: "Page does not say this.", test_accepted: null }),
        observedCore(),
      ),
    ).toEqual({ ok: false, reason: "missing_test_accepted" });
    const rejection = record({
      decision: "reject",
      reason: "Page does not say this.",
      test_accepted: true,
    });
    expect(checkRecordEvidence(rejection, observedCore())).toEqual({ ok: true, record: rejection });
  });

  it("refuses a test judgment on a stated entry", () => {
    expect(checkRecordEvidence(record({ test_accepted: true }), statedCore())).toEqual({
      ok: false,
      reason: "unexpected_test_accepted",
    });
    expect(checkRecordEvidence(record({ test_accepted: false }), statedCore())).toEqual({
      ok: false,
      reason: "unexpected_test_accepted",
    });
  });

  it("refuses a measurement in the wrong slot", () => {
    const misplaced = { ok: false, reason: "misplaced_measurement" satisfies RecordEvidenceRefusal };
    expect(
      checkRecordEvidence(
        record({ test_accepted: true, reproduction: reproduction(REPRODUCTION_RUNS, REPRODUCTION_HOLDS), observation: measurement(REPRODUCTION_RUNS, REPRODUCTION_HOLDS) }),
        observedCore(),
      ),
    ).toEqual(misplaced);
    expect(
      checkRecordEvidence(
        record({ test_accepted: true, observation: measurement(REPRODUCTION_RUNS, REPRODUCTION_HOLDS) }),
        behaviorCore(),
      ),
    ).toEqual(misplaced);
    expect(
      checkRecordEvidence(
        record({ observation: measurement(REPRODUCTION_RUNS, REPRODUCTION_HOLDS) }),
        statedCore(),
      ),
    ).toEqual(misplaced);
    expect(
      checkRecordEvidence(
        record({ reproduction: reproduction(REPRODUCTION_RUNS, REPRODUCTION_HOLDS) }),
        statedCore(),
      ),
    ).toEqual(misplaced);
  });

  it("refuses counts it cannot read", () => {
    const bad = { ok: false, reason: "bad_measurement" satisfies RecordEvidenceRefusal };
    expect(
      checkRecordEvidence(
        record({ test_accepted: true, observation: measurement(REPRODUCTION_RUNS, REPRODUCTION_RUNS + 1) }),
        observedCore(),
      ),
    ).toEqual(bad);
    expect(
      checkRecordEvidence(
        record({ test_accepted: true, reproduction: { model: "gpt-5", output: "x" } }),
        behaviorCore(),
      ),
    ).toEqual(bad);
  });

  it("needs the validator's own observation on an accepted-test approval", () => {
    expect(
      checkRecordEvidence(record({ test_accepted: true, observation: null }), observedCore()),
    ).toEqual({ ok: false, reason: "missing_observation" });
    expect(
      checkRecordEvidence(record({ test_accepted: true, observation: undefined }), observedCore()),
    ).toEqual({ ok: false, reason: "missing_observation" });
  });

  it("needs no observation when the validator rejected the test, or rejected the entry", () => {
    const document = record({ test_accepted: false, observation: null });
    expect(checkRecordEvidence(document, observedCore())).toEqual({ ok: true, record: document });
    const rejection = record({
      decision: "reject",
      reason: "The measurement does not hold.",
      test_accepted: true,
      observation: null,
    });
    expect(checkRecordEvidence(rejection, observedCore())).toEqual({ ok: true, record: rejection });
  });

  it("needs no reproduction on a transcript approval: that rule is the gate's, not the door's", () => {
    const approval = record({ test_accepted: true, reproduction: null });
    expect(checkRecordEvidence(approval, behaviorCore())).toEqual({ ok: true, record: approval });
  });

  it("passes a stated approval and every approval on the worked example", () => {
    const plain = record();
    expect(checkRecordEvidence(plain, statedCore())).toEqual({ ok: true, record: plain });

    const entry = JSON.parse(readFileSync(examplePath, "utf8")) as {
      approvers: ApproverRecord[];
    };
    const core = exampleCore();
    for (const approval of entry.approvers) {
      expect(checkRecordEvidence(approval, core)).toEqual({ ok: true, record: approval });
    }
  });
});

describe("testVerdict", () => {
  const cases: ReadonlyArray<readonly [string, ReadonlyArray<boolean | null | undefined>, TestVerdict]> = [
    ["two accept, one rejects", [true, true, false], "accepted"],
    ["one accepts, two reject", [true, false, false], "rejected"],
    ["one each", [true, false], "undecided"],
    ["no judgments at all", [], "undecided"],
    ["only nulls", [null, null], "undecided"],
    ["one judgment among nulls", [null, true, undefined], "accepted"],
    ["one rejection among nulls", [null, false, undefined], "rejected"],
  ];

  for (const [name, judgments, expected] of cases) {
    it(`${name} is ${expected}`, () => {
      const records = judgments.map((test_accepted) => record({ test_accepted }));
      expect(testVerdict(records)).toBe(expected);
    });
  }

  it("counts rejections' judgments too", () => {
    const records = [
      record({ decision: "reject", reason: "no", test_accepted: false }),
      record({ test_accepted: false }),
      record({ test_accepted: true }),
    ];
    expect(testVerdict(records)).toBe("rejected");
  });
});

describe("evidenceGate", () => {
  function approvalWithObservation(runs: number, holds: number): ApproverRecord {
    return record({ test_accepted: true, observation: measurement(runs, holds) });
  }

  function approvalWithReproduction(runs: number, holds: number): ApproverRecord {
    return record({ test_accepted: true, reproduction: reproduction(runs, holds) });
  }

  const PASSING = [REPRODUCTION_RUNS, REPRODUCTION_HOLDS] as const;
  const FAILING = [REPRODUCTION_RUNS, REPRODUCTION_HOLDS - 1] as const;

  it("verifies a stated entry as a document", () => {
    expect(evidenceGate(statedCore(), [])).toEqual({
      test_verdict: null,
      verifiable: true,
      effective_tier: "stated",
    });
    expect(evidenceGate(statedCore(), [record(), record()])).toEqual({
      test_verdict: null,
      verifiable: true,
      effective_tier: "stated",
    });
  });

  describe("observed, non-transcript", () => {
    it("falls to stated when a majority rejects the test", () => {
      const records = [
        record({ test_accepted: false }),
        record({ test_accepted: false }),
        approvalWithObservation(...PASSING),
      ];
      expect(evidenceGate(observedCore(), records)).toEqual({
        test_verdict: "rejected",
        verifiable: true,
        effective_tier: "stated",
      });
    });

    it("verifies as observed when the approvals measure at n-of-k", () => {
      const records = [approvalWithObservation(...PASSING), approvalWithObservation(...PASSING)];
      expect(evidenceGate(observedCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "observed",
      });
    });

    it("verifies the worked example as observed", () => {
      const entry = JSON.parse(readFileSync(examplePath, "utf8")) as {
        approvers: ApproverRecord[];
      };
      expect(evidenceGate(exampleCore(), entry.approvers)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "observed",
      });
    });

    it("does not verify when the measurements fall short of k", () => {
      const records = [approvalWithObservation(...FAILING), approvalWithObservation(...FAILING)];
      expect(evidenceGate(observedCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: false,
        effective_tier: null,
      });
    });

    it("takes a majority of the approvals", () => {
      const majority = [
        approvalWithObservation(...PASSING),
        approvalWithObservation(...PASSING),
        approvalWithObservation(...FAILING),
      ];
      expect(evidenceGate(observedCore(), majority)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "observed",
      });
      const minority = [
        approvalWithObservation(...PASSING),
        approvalWithObservation(...FAILING),
        approvalWithObservation(...FAILING),
      ];
      expect(evidenceGate(observedCore(), minority)).toEqual({
        test_verdict: "accepted",
        verifiable: false,
        effective_tier: null,
      });
    });

    it("does not verify while the test is undecided", () => {
      const records = [
        approvalWithObservation(...PASSING),
        record({ test_accepted: false, decision: "reject", reason: "The test proves nothing." }),
      ];
      expect(evidenceGate(observedCore(), records)).toEqual({
        test_verdict: "undecided",
        verifiable: false,
        effective_tier: null,
      });
      expect(evidenceGate(observedCore(), [])).toEqual({
        test_verdict: "undecided",
        verifiable: false,
        effective_tier: null,
      });
    });
  });

  describe("transcript categories", () => {
    const withStatement = () =>
      behaviorCore(defaultEvidence({ provider_statement: CITATION }));

    it("verifies nothing on the frozen artifact alone", () => {
      const records = [record({ test_accepted: true }), record({ test_accepted: true })];
      expect(evidenceGate(behaviorCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: false,
        effective_tier: null,
      });
    });

    it("verifies as stated on a provider statement alone", () => {
      const records = [record({ test_accepted: true }), record({ test_accepted: true })];
      expect(evidenceGate(withStatement(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "stated",
      });
    });

    it("earns the observed badge from one passing reproduction", () => {
      const records = [record({ test_accepted: true }), approvalWithReproduction(...PASSING)];
      expect(evidenceGate(behaviorCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "observed",
      });
      expect(evidenceGate(withStatement(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "observed",
      });
    });

    it("ignores a reproduction that falls short of k", () => {
      const records = [approvalWithReproduction(...FAILING), record({ test_accepted: true })];
      expect(evidenceGate(behaviorCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: false,
        effective_tier: null,
      });
      expect(evidenceGate(withStatement(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: true,
        effective_tier: "stated",
      });
    });

    it("falls back to the statement path when a majority rejects the test", () => {
      const records = [
        approvalWithReproduction(...PASSING),
        record({ decision: "reject", reason: "The predicate decides nothing.", test_accepted: false }),
        record({ decision: "reject", reason: "Agreed.", test_accepted: false }),
      ];
      expect(evidenceGate(withStatement(), records)).toEqual({
        test_verdict: "rejected",
        verifiable: true,
        effective_tier: "stated",
      });
      expect(evidenceGate(behaviorCore(), records)).toEqual({
        test_verdict: "rejected",
        verifiable: false,
        effective_tier: null,
      });
    });

    it("counts only approvals' reproductions", () => {
      const records = [
        record({
          decision: "reject",
          reason: "It reproduces, but the claim overstates it.",
          test_accepted: true,
          reproduction: reproduction(...PASSING),
        }),
        record({ test_accepted: true }),
      ];
      expect(evidenceGate(behaviorCore(), records)).toEqual({
        test_verdict: "accepted",
        verifiable: false,
        effective_tier: null,
      });
    });
  });
});

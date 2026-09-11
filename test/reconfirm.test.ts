/**
 * Who may reconfirm an entry: the exclusions the whitepaper names, the evidence
 * each of the three shapes has to carry, and the order the rules are checked in.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_DOMAIN } from "../src/policy.js";

import {
  RECONFIRMATION_REFUSALS,
  checkReconfirmation,
  type ReconfirmationContext,
  type ReconfirmationRefusal,
} from "../src/reconfirm.js";
import type { Core } from "../src/core.js";
import type { ReconfirmationRecord } from "../src/events.js";

const SUBMITTER_AGENT = "1F916:aG9tZUJhc2U";
/** A second agent under the submitter's own operator: Section 5 counts them as one. */
const SIBLING_AGENT = "1F916:c2libGluZzE";
const R1_AGENT = "1F916:cmVjb24xX2s";
const R2_AGENT = "1F916:cmVjb24yX2s";
/** Registered, but its operator is not in the trusted pool. */
const OUTSIDER_AGENT = "1F916:b3V0c2lkZXI";
/** Never registered at all. */
const STRANGER_AGENT = "1F916:c3RyYW5nZXI";

const SUBMITTER_OPERATOR = "op_brightloop";

const AGENT_OPERATORS: Readonly<Record<string, string>> = Object.freeze({
  [SUBMITTER_AGENT]: SUBMITTER_OPERATOR,
  [SIBLING_AGENT]: SUBMITTER_OPERATOR,
  [R1_AGENT]: "op_r1",
  [R2_AGENT]: "op_r2",
  [OUTSIDER_AGENT]: "op_outsider",
});

/** The trusted pool. op_outsider and the submitter's own operator are absent. */
const TRUSTED: readonly string[] = Object.freeze(["op_r1", "op_r2"]);

const HASH = `sha256:${"a".repeat(64)}`;
const RECEIPT_HASH = `sha256:${"b".repeat(64)}`;
const SIGNED_AT = "2026-09-08T00:00:00Z";

/** A passing reproduction: the frozen prompt rerun under the n-of-k rule. */
function reproduction(runs: number, holds: number): Record<string, unknown> {
  return {
    model: "vendor-model-4",
    output: "The predicate still holds.",
    observed_at: "2026-09-08",
    runs,
    holds,
  };
}

/** A passing observation: a fresh measurement in a non-transcript category. */
function observation(runs: number, holds: number): Record<string, unknown> {
  return {
    method: "metered_call",
    receipt_hash: RECEIPT_HASH,
    observed_at: "2026-09-08",
    runs,
    holds,
  };
}

function record(overrides: Partial<ReconfirmationRecord> = {}): ReconfirmationRecord {
  return {
    agent: R1_AGENT,
    operator: "op_r1",
    snapshot_hash: HASH,
    reproduction: null,
    observation: null,
    signed_at: SIGNED_AT,
    ...overrides,
  };
}

function core(overrides: Partial<Record<string, unknown>> = {}): Core {
  return {
    id: "nmk_01J8Z9",
    subject: "vendor/model-4",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Input tokens cost two dollars per million.",
    before: null,
    after: null,
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://vendor.example/pricing",
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: SUBMITTER_AGENT,
    author_operator: SUBMITTER_OPERATOR,
    submitted_at: "2026-08-02T00:00:00Z",
    ...overrides,
  } as Core;
}

/** A behavior entry: a transcript category, always observed. */
const BEHAVIOR_CORE = core({
  category: "behavior",
  evidence_tier: "observed",
  evidence: {
    predicate: "The model refuses the request.",
    provider_statement: null,
  },
});

/** A pricing entry that verified at the observed tier on a measurement. */
const OBSERVED_PRICING_CORE = core({
  evidence_tier: "observed",
  observation: { test: "Meter one call and read the billed amount." },
});

function context(overrides: Partial<ReconfirmationContext> = {}): ReconfirmationContext {
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR },
    agentOperators: AGENT_OPERATORS,
    trustedOperators: TRUSTED,
    operatorDomains: [DEFAULT_DOMAIN],
    status: "verified",
    effectiveTier: "stated",
    ...overrides,
  };
}

/** The behavior shape: a passing reproduction and nothing else. */
function behaviorContext(overrides: Partial<ReconfirmationContext> = {}): ReconfirmationContext {
  return context({ effectiveTier: "observed", ...overrides });
}

describe("the refusal list", () => {
  it("names every refusal exactly once, in check order", () => {
    const expected: readonly ReconfirmationRefusal[] = [
      "entry_not_verified",
      "version_stale",
      "unregistered_agent",
      "operator_mismatch",
      "submitter_agent",
      "submitter_operator",
      "untrusted_operator",
      "subject_authority",
      "operator_not_in_domain",
      "missing_snapshot_hash",
      "unexpected_reproduction",
      "unexpected_observation",
      "missing_reproduction",
      "bad_reproduction",
      "failed_reproduction",
      "missing_observation",
      "bad_observation",
      "failed_observation",
    ];
    expect([...RECONFIRMATION_REFUSALS]).toEqual([...expected]);
    expect(new Set(RECONFIRMATION_REFUSALS).size).toBe(RECONFIRMATION_REFUSALS.length);
  });
});

describe("who may reconfirm", () => {
  it("refuses an operator not attested in the entry's domain (D-071)", () => {
    expect(
      checkReconfirmation(
        record(),
        core(),
        context({ operatorDomains: ["elsewhere"] }),
      ),
    ).toEqual({ ok: false, reason: "operator_not_in_domain" });

    // The same trusted operator, refreshing an entry of a domain it attested
    // in: being trusted is not being attested everywhere.
    expect(
      checkReconfirmation(
        record(),
        core({ domain: "elsewhere" }),
        context({ operatorDomains: ["elsewhere"] }),
      ).ok,
    ).toBe(true);
  });

  it("reads a context that names no domains as the default domain", () => {
    const { operatorDomains: _absent, ...legacy } = context();
    expect(checkReconfirmation(record(), core(), legacy).ok).toBe(true);
  });

  it("refuses a draft entry", () => {
    expect(checkReconfirmation(record(), core(), context({ status: "draft" }))).toEqual({
      ok: false,
      reason: "entry_not_verified",
    });
  });

  it("refuses rejected, superseded and overturned entries alike", () => {
    for (const status of ["rejected", "superseded", "overturned"] as const) {
      expect(checkReconfirmation(record(), core(), context({ status }))).toEqual({
        ok: false,
        reason: "entry_not_verified",
      });
    }
  });

  it("refuses an unregistered agent", () => {
    const verdict = checkReconfirmation(
      record({ agent: STRANGER_AGENT }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unregistered_agent" });
  });

  it("refuses an operator the agent does not belong to", () => {
    const verdict = checkReconfirmation(
      record({ agent: R1_AGENT, operator: "op_r2" }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "operator_mismatch" });
  });

  it("refuses the submitting agent itself", () => {
    const verdict = checkReconfirmation(
      record({ agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR }),
      core(),
      context({ trustedOperators: [...TRUSTED, SUBMITTER_OPERATOR] }),
    );
    expect(verdict).toEqual({ ok: false, reason: "submitter_agent" });
  });

  it("refuses another agent under the submitter's own operator", () => {
    // Section 6: the one exception mirrors validation. Even in the trusted pool,
    // the submitter's operator may not reconfirm its own entry.
    const verdict = checkReconfirmation(
      record({ agent: SIBLING_AGENT, operator: SUBMITTER_OPERATOR }),
      core(),
      context({ trustedOperators: [...TRUSTED, SUBMITTER_OPERATOR] }),
    );
    expect(verdict).toEqual({ ok: false, reason: "submitter_operator" });
  });

  it("refuses an operator outside the trusted pool", () => {
    const verdict = checkReconfirmation(
      record({ agent: OUTSIDER_AGENT, operator: "op_outsider" }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "untrusted_operator" });
  });

  it("does not apply the operator exclusion to a bare-key submitter", () => {
    // The core names no author_operator, so only the submitting agent is barred;
    // a sibling under the same registry operator may reconfirm.
    const verdict = checkReconfirmation(
      record({ agent: SIBLING_AGENT, operator: SUBMITTER_OPERATOR }),
      core({ author_operator: null }),
      context({
        submitter: { agent: SUBMITTER_AGENT, operator: null },
        trustedOperators: [...TRUSTED, SUBMITTER_OPERATOR],
      }),
    );
    expect(verdict.ok).toBe(true);
  });

  it("still bars the submitting agent when the submitter is a bare key", () => {
    const verdict = checkReconfirmation(
      record({ agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR }),
      core({ author_operator: null }),
      context({
        submitter: { agent: SUBMITTER_AGENT, operator: null },
        trustedOperators: [...TRUSTED, SUBMITTER_OPERATOR],
      }),
    );
    expect(verdict).toEqual({ ok: false, reason: "submitter_agent" });
  });

  it("accepts a stale verified entry", () => {
    // Section 5: past its window an entry stays verified but shows as stale.
    // Staleness is what reconfirmation is for, so it is never a gate.
    const verdict = checkReconfirmation(record(), core(), context({ status: "verified" }));
    expect(verdict.ok).toBe(true);
  });
});

describe("the attestation's shape", () => {
  it("refuses a missing snapshot hash", () => {
    const verdict = checkReconfirmation(
      record({ snapshot_hash: "" }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "missing_snapshot_hash" });
  });

  it("refuses a snapshot hash that is not the schema's shape", () => {
    const verdict = checkReconfirmation(
      record({ snapshot_hash: `sha256:${"A".repeat(64)}` }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "missing_snapshot_hash" });
  });

  it("accepts a stated entry on the fresh snapshot hash alone", () => {
    const verdict = checkReconfirmation(record(), core(), context());
    expect(verdict.ok).toBe(true);
  });

  it("refuses a reproduction on a stated entry", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: reproduction(10, 10) }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_reproduction" });
  });

  it("refuses an observation on a stated entry", () => {
    const verdict = checkReconfirmation(
      record({ observation: observation(10, 10) }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_observation" });
  });

  it("accepts a stated shape while the entry carries no tier yet", () => {
    const verdict = checkReconfirmation(record(), core(), context({ effectiveTier: null }));
    expect(verdict.ok).toBe(true);
  });
});

describe("behavior and misbehavior: reconfirmation means reproduction", () => {
  it("accepts a passing reproduction", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: reproduction(10, 8) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict.ok).toBe(true);
  });

  it("refuses eight of ten held in seven runs and accepts it in eight", () => {
    // Section 4: the predicate has to hold in at least k of the n runs.
    const failing = checkReconfirmation(
      record({ reproduction: reproduction(10, 7) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(failing).toEqual({ ok: false, reason: "failed_reproduction" });

    const passing = checkReconfirmation(
      record({ reproduction: reproduction(10, 8) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(passing.ok).toBe(true);
  });

  it("refuses a missing reproduction", () => {
    const verdict = checkReconfirmation(record(), BEHAVIOR_CORE, behaviorContext());
    expect(verdict).toEqual({ ok: false, reason: "missing_reproduction" });
  });

  it("refuses a reproduction whose counts are not countable", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: { ...reproduction(10, 8), holds: "eight" } }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "bad_reproduction" });
  });

  it("refuses an observation on a transcript category", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: reproduction(10, 8), observation: observation(10, 10) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_observation" });
  });

  it("still demands a reproduction when the entry verified as stated", () => {
    // A transcript entry can verify as stated on a provider statement, but its
    // window still reopens only by rerunning the frozen prompt.
    const verdict = checkReconfirmation(
      record(),
      BEHAVIOR_CORE,
      behaviorContext({ effectiveTier: "stated" }),
    );
    expect(verdict).toEqual({ ok: false, reason: "missing_reproduction" });
  });

  it("applies the same rule to misbehavior", () => {
    const misbehaviour = core({
      category: "misbehavior",
      evidence_tier: "observed",
      evidence: { predicate: "The model leaks the system prompt.", provider_statement: null },
    });
    expect(
      checkReconfirmation(record(), misbehaviour, behaviorContext()),
    ).toEqual({ ok: false, reason: "missing_reproduction" });
  });
});

describe("observed entries in other categories: a fresh measurement", () => {
  const observedContext = (overrides: Partial<ReconfirmationContext> = {}) =>
    context({ effectiveTier: "observed", ...overrides });

  it("accepts a passing observation on an observed pricing entry", () => {
    const verdict = checkReconfirmation(
      record({ observation: observation(10, 9) }),
      OBSERVED_PRICING_CORE,
      observedContext(),
    );
    expect(verdict.ok).toBe(true);
  });

  it("refuses a reproduction in place of the observation", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: reproduction(10, 10), observation: observation(10, 10) }),
      OBSERVED_PRICING_CORE,
      observedContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_reproduction" });
  });

  it("refuses a missing observation", () => {
    const verdict = checkReconfirmation(record(), OBSERVED_PRICING_CORE, observedContext());
    expect(verdict).toEqual({ ok: false, reason: "missing_observation" });
  });

  it("refuses an observation whose counts are not countable", () => {
    const verdict = checkReconfirmation(
      record({ observation: { ...observation(10, 8), runs: 0 } }),
      OBSERVED_PRICING_CORE,
      observedContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "bad_observation" });
  });

  it("refuses an observation that does not meet the n-of-k rule", () => {
    const verdict = checkReconfirmation(
      record({ observation: observation(10, 7) }),
      OBSERVED_PRICING_CORE,
      observedContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "failed_observation" });
  });
});

describe("check order", () => {
  it("reports entry_not_verified before every identity rule", () => {
    const verdict = checkReconfirmation(
      record({ agent: STRANGER_AGENT, operator: "op_nowhere", snapshot_hash: "" }),
      core(),
      context({ status: "rejected" }),
    );
    expect(verdict).toEqual({ ok: false, reason: "entry_not_verified" });
  });

  it("reports operator_mismatch before submitter_operator", () => {
    const verdict = checkReconfirmation(
      record({ agent: R1_AGENT, operator: SUBMITTER_OPERATOR }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "operator_mismatch" });
  });

  it("reports submitter_agent before submitter_operator", () => {
    const verdict = checkReconfirmation(
      record({ agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "submitter_agent" });
  });

  it("reports untrusted_operator before missing_snapshot_hash", () => {
    const verdict = checkReconfirmation(
      record({ agent: OUTSIDER_AGENT, operator: "op_outsider", snapshot_hash: "nope" }),
      core(),
      context(),
    );
    expect(verdict).toEqual({ ok: false, reason: "untrusted_operator" });
  });

  it("reports missing_snapshot_hash before the evidence rules", () => {
    const verdict = checkReconfirmation(
      record({ snapshot_hash: "nope", observation: observation(10, 1) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "missing_snapshot_hash" });
  });

  it("reports unexpected_observation before missing_reproduction", () => {
    const verdict = checkReconfirmation(
      record({ observation: observation(10, 10) }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_observation" });
  });

  it("reports bad_reproduction before failed_reproduction", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: { ...reproduction(10, 2), runs: 1.5 } }),
      BEHAVIOR_CORE,
      behaviorContext(),
    );
    expect(verdict).toEqual({ ok: false, reason: "bad_reproduction" });
  });

  it("reports unexpected_reproduction before missing_observation", () => {
    const verdict = checkReconfirmation(
      record({ reproduction: reproduction(10, 10) }),
      OBSERVED_PRICING_CORE,
      context({ effectiveTier: "observed" }),
    );
    expect(verdict).toEqual({ ok: false, reason: "unexpected_reproduction" });
  });

  it("always reports the first refusal in RECONFIRMATION_REFUSALS", () => {
    // Broken every way at once: unverified, unregistered, off the pool, no hash,
    // and both measurement slots filled on a stated entry.
    const verdict = checkReconfirmation(
      record({
        agent: STRANGER_AGENT,
        operator: "op_nowhere",
        snapshot_hash: "",
        reproduction: reproduction(1, 0),
        observation: observation(1, 0),
      }),
      core(),
      context({ status: "draft" }),
    );
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(RECONFIRMATION_REFUSALS.indexOf(verdict.reason)).toBe(0);
    }
  });
});

describe("the accepted record", () => {
  it("returns the very same record object, uncopied", () => {
    const attestation = record({ reproduction: reproduction(10, 8) });
    const verdict = checkReconfirmation(attestation, BEHAVIOR_CORE, behaviorContext());
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.record).toBe(attestation);
  });

  it("returns the same object for the observed and stated shapes too", () => {
    const observed = record({ agent: R2_AGENT, operator: "op_r2", observation: observation(10, 8) });
    const observedVerdict = checkReconfirmation(
      observed,
      OBSERVED_PRICING_CORE,
      context({ effectiveTier: "observed" }),
    );
    expect(observedVerdict.ok).toBe(true);
    if (observedVerdict.ok) expect(observedVerdict.record).toBe(observed);

    const stated = record({ agent: R2_AGENT, operator: "op_r2" });
    const statedVerdict = checkReconfirmation(stated, core(), context());
    expect(statedVerdict.ok).toBe(true);
    if (statedVerdict.ok) expect(statedVerdict.record).toBe(stated);
  });
});

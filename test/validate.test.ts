/**
 * Who may validate an entry: every exclusion the whitepaper names, the shape a
 * decision has to carry, and the order the rules are checked in.
 */

import { describe, expect, it } from "vitest";

import {
  VALIDATION_REFUSALS,
  checkValidation,
  type OperatorInfo,
  type ValidationContext,
  type ValidationRefusal,
} from "../src/validate.js";
import type { ApproverRecord } from "../src/events.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";

const SUBMITTER_AGENT = "1F916:aG9tZUJhc2U";
/** A second agent under the submitter's own operator: Section 5 counts them as one. */
const SIBLING_AGENT = "1F916:c2libGluZzE";
const V1_AGENT = "1F916:dmFsMV9rZXk";
const V1_SECOND_AGENT = "1F916:dmFsMV9hbHQ";
const V2_AGENT = "1F916:dmFsMl9rZXk";
/** Registered as an agent, under an operator the registry does not know. */
const V3_AGENT = "1F916:dmFsM19rZXk";
const MAINTAINER_AGENT = "1F916:bWFpbnRhaW4";
const PROVIDER_AGENT = "1F916:cHJvdmlkZXI";
/** Never registered at all. */
const STRANGER_AGENT = "1F916:c3RyYW5nZXI";

const SUBMITTER_OPERATOR = "op_brightloop";
const MAINTAINER_OPERATOR = "op_maintainer";
const PROVIDER_OPERATOR = "op_provider";

const AGENT_OPERATORS: Readonly<Record<string, string>> = Object.freeze({
  [SUBMITTER_AGENT]: SUBMITTER_OPERATOR,
  [SIBLING_AGENT]: SUBMITTER_OPERATOR,
  [V1_AGENT]: "op_v1",
  [V1_SECOND_AGENT]: "op_v1",
  [V2_AGENT]: "op_v2",
  [V3_AGENT]: "op_v3",
  [MAINTAINER_AGENT]: MAINTAINER_OPERATOR,
  [PROVIDER_AGENT]: PROVIDER_OPERATOR,
});

const PLAIN: OperatorInfo = {
  maintainer: false,
  provider: false,
  domains: [DEFAULT_DOMAIN],
};

/** Registered operators. op_v3 is deliberately absent. */
const OPERATORS: Readonly<Record<string, OperatorInfo>> = Object.freeze({
  [SUBMITTER_OPERATOR]: PLAIN,
  op_v1: PLAIN,
  op_v2: PLAIN,
  [MAINTAINER_OPERATOR]: { ...PLAIN, maintainer: true },
  [PROVIDER_OPERATOR]: { ...PLAIN, provider: true },
});

const HASH = `sha256:${"a".repeat(64)}`;
const OTHER_HASH = `sha256:${"b".repeat(64)}`;
const SIGNED_AT = "2026-09-08T00:00:00Z";

function approval(agent: string, operator: string): ApproverRecord {
  return {
    agent,
    operator,
    decision: "approve",
    snapshot_hash: HASH,
    assigned_random: false,
    signed_at: SIGNED_AT,
  };
}

function rejection(agent: string, operator: string): ApproverRecord {
  return {
    agent,
    operator,
    decision: "reject",
    reason: "The cited page does not say what the entry claims.",
    assigned_random: false,
    signed_at: SIGNED_AT,
  };
}

function context(overrides: Partial<ValidationContext> = {}): ValidationContext {
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR },
    agentOperators: AGENT_OPERATORS,
    operators: OPERATORS,
    priorRecords: [],
    openAssignment: null,
    ...overrides,
  };
}

/** One fixture per refusal, each failing that rule and no earlier one. */
const REFUSAL_CASES: readonly {
  reason: ValidationRefusal;
  record: ApproverRecord;
  context: ValidationContext;
}[] = [
  {
    reason: "unregistered_agent",
    record: approval(STRANGER_AGENT, "op_v1"),
    context: context(),
  },
  {
    reason: "operator_mismatch",
    record: approval(V1_AGENT, "op_v2"),
    context: context(),
  },
  {
    reason: "unregistered_operator",
    record: approval(V3_AGENT, "op_v3"),
    context: context(),
  },
  {
    // The submitter is a bare key, so only the agent itself is excluded here.
    reason: "submitter_agent",
    record: approval(V1_AGENT, "op_v1"),
    context: context({ submitter: { agent: V1_AGENT, operator: null } }),
  },
  {
    // A different agent, but under the submitter's operator: one entity.
    reason: "submitter_operator",
    record: approval(SIBLING_AGENT, SUBMITTER_OPERATOR),
    context: context(),
  },
  {
    // Section 6: an operator that signed the original may not validate the
    // challenge against it. The list is the caller's, and it is empty for every
    // entry that is not a challenge.
    reason: "original_signer",
    record: approval(V1_AGENT, "op_v1"),
    context: context({ excludedOperators: ["op_v1"] }),
  },
  {
    reason: "maintainer_operator",
    record: approval(MAINTAINER_AGENT, MAINTAINER_OPERATOR),
    context: context(),
  },
  {
    reason: "provider_operator",
    record: approval(PROVIDER_AGENT, PROVIDER_OPERATOR),
    context: context(),
  },
  {
    // Decision D-096: the operator's own domain is an official host of the
    // authority this entry's subject names, so it is the party being checked.
    reason: "subject_authority",
    record: approval(V1_AGENT, "op_v1"),
    context: context({ authority_hosts: ["op_v1"] }),
  },
  {
    // Decision D-071: attested in some domain, but not in this entry's.
    reason: "operator_not_in_domain",
    record: approval(V1_AGENT, "op_v1"),
    context: context({ domain: "some-other-domain" }),
  },
  {
    reason: "missing_snapshot_hash",
    record: {
      agent: V1_AGENT,
      operator: "op_v1",
      decision: "approve",
      assigned_random: false,
      signed_at: SIGNED_AT,
    },
    context: context(),
  },
  {
    reason: "missing_reason",
    record: { ...rejection(V1_AGENT, "op_v1"), reason: "   " },
    context: context(),
  },
  {
    reason: "duplicate_operator",
    record: approval(V1_AGENT, "op_v1"),
    context: context({
      priorRecords: [rejection(V1_SECOND_AGENT, "op_v1")],
    }),
  },
  {
    reason: "assigned_random_without_assignment",
    record: { ...approval(V1_AGENT, "op_v1"), assigned_random: true },
    context: context(),
  },
  {
    reason: "assignment_without_assigned_random",
    record: approval(V1_AGENT, "op_v1"),
    context: context({ openAssignment: { operator: "op_v1" } }),
  },
];

describe("checkValidation refusals", () => {
  it.each(REFUSAL_CASES)("refuses $reason", ({ reason, record, context: ctx }) => {
    expect(checkValidation(record, ctx)).toEqual({ ok: false, reason });
  });

  it("names every refusal in VALIDATION_REFUSALS exactly once", () => {
    expect([...VALIDATION_REFUSALS]).toEqual([
      "unregistered_agent",
      "operator_mismatch",
      "unregistered_operator",
      "submitter_agent",
      "submitter_operator",
      "original_signer",
      "maintainer_operator",
      "provider_operator",
      "subject_authority",
      "operator_not_in_domain",
      "missing_snapshot_hash",
      "missing_reason",
      "duplicate_operator",
      "assigned_random_without_assignment",
      "assignment_without_assigned_random",
    ]);
    expect(new Set(VALIDATION_REFUSALS).size).toBe(VALIDATION_REFUSALS.length);
  });

  it("covers every refusal with a fixture, and none twice", () => {
    const covered = REFUSAL_CASES.map((testCase) => testCase.reason);
    expect(new Set(covered).size).toBe(covered.length);
    expect([...covered].sort()).toEqual([...VALIDATION_REFUSALS].sort());
  });

  it("lets an operator attested in the entry's domain through", () => {
    // The same record and the same operator, judged in the domain it attested
    // in: eligibility is per domain, so one refusal is exactly the absence of
    // the other (decision D-071).
    expect(
      checkValidation(approval(V1_AGENT, "op_v1"), context({ domain: DEFAULT_DOMAIN })),
    ).toEqual({ ok: true, record: approval(V1_AGENT, "op_v1") });
  });

  it("reads a context that names no domains as the default domain", () => {
    // A caller written before v0.7 built neither field; its world was
    // ai-ecosystem and reads as ai-ecosystem.
    expect(checkValidation(approval(V1_AGENT, "op_v1"), context()).ok).toBe(true);
  });

  it("keeps an operator excluded in one domain eligible in another", () => {
    const operators = {
      ...OPERATORS,
      op_v1: { maintainer: false, provider: false, domains: ["elsewhere"] },
    };

    expect(
      checkValidation(
        approval(V1_AGENT, "op_v1"),
        context({ operators, domain: "elsewhere" }),
      ).ok,
    ).toBe(true);
    expect(
      checkValidation(
        approval(V1_AGENT, "op_v1"),
        context({ operators, domain: DEFAULT_DOMAIN }),
      ),
    ).toEqual({ ok: false, reason: "operator_not_in_domain" });
  });

  it("refuses an approve whose snapshot_hash is malformed", () => {
    const record = { ...approval(V1_AGENT, "op_v1"), snapshot_hash: "sha256:ZZZ" };
    expect(checkValidation(record, context())).toEqual({
      ok: false,
      reason: "missing_snapshot_hash",
    });
  });

  it("refuses an approve whose snapshot_hash is null", () => {
    const record = { ...approval(V1_AGENT, "op_v1"), snapshot_hash: null };
    expect(checkValidation(record, context())).toEqual({
      ok: false,
      reason: "missing_snapshot_hash",
    });
  });

  it("refuses a reject with no reason at all", () => {
    const record: ApproverRecord = {
      agent: V1_AGENT,
      operator: "op_v1",
      decision: "reject",
      assigned_random: false,
      signed_at: SIGNED_AT,
    };
    expect(checkValidation(record, context())).toEqual({
      ok: false,
      reason: "missing_reason",
    });
  });
});

describe("checkValidation acceptances", () => {
  it("accepts a clean approve", () => {
    expect(checkValidation(approval(V1_AGENT, "op_v1"), context()).ok).toBe(true);
  });

  it("accepts a clean reject", () => {
    expect(checkValidation(rejection(V1_AGENT, "op_v1"), context()).ok).toBe(true);
  });

  it("accepts a reject that carries a snapshot hash", () => {
    const record = { ...rejection(V1_AGENT, "op_v1"), snapshot_hash: OTHER_HASH };
    expect(checkValidation(record, context()).ok).toBe(true);
  });

  it("accepts the assigned validator when the flag matches the assignment", () => {
    const record = { ...approval(V1_AGENT, "op_v1"), assigned_random: true };
    const verdict = checkValidation(
      record,
      context({ openAssignment: { operator: "op_v1" } }),
    );
    expect(verdict.ok).toBe(true);
  });

  it("accepts a volunteer while another operator holds the assignment", () => {
    const verdict = checkValidation(
      approval(V1_AGENT, "op_v1"),
      context({ openAssignment: { operator: "op_v2" } }),
    );
    expect(verdict.ok).toBe(true);
  });

  it("accepts a prior record from a different operator", () => {
    const verdict = checkValidation(
      approval(V1_AGENT, "op_v1"),
      context({ priorRecords: [rejection(V2_AGENT, "op_v2")] }),
    );
    expect(verdict.ok).toBe(true);
  });

  it("does not apply the operator exclusion to a bare-key submitter", () => {
    // The submitting agent belongs to op_brightloop in the registry, but the
    // core names no author_operator, so only the agent itself is excluded.
    const verdict = checkValidation(
      approval(SIBLING_AGENT, SUBMITTER_OPERATOR),
      context({ submitter: { agent: SUBMITTER_AGENT, operator: null } }),
    );
    expect(verdict.ok).toBe(true);
  });

  it("returns the very same record object, uncopied", () => {
    const record = approval(V1_AGENT, "op_v1");
    const verdict = checkValidation(record, context());
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.record).toBe(record);
  });
});

describe("check order", () => {
  it("reports operator_mismatch before unregistered_operator", () => {
    // Both broken: the claimed operator is neither the agent's nor registered.
    expect(checkValidation(approval(V1_AGENT, "op_nowhere"), context())).toEqual({
      ok: false,
      reason: "operator_mismatch",
    });
  });

  it("reports submitter_agent before submitter_operator", () => {
    expect(
      checkValidation(approval(SUBMITTER_AGENT, SUBMITTER_OPERATOR), context()),
    ).toEqual({ ok: false, reason: "submitter_agent" });
  });

  it("reports submitter_operator before maintainer_operator", () => {
    const verdict = checkValidation(
      approval(MAINTAINER_AGENT, MAINTAINER_OPERATOR),
      context({
        submitter: { agent: SUBMITTER_AGENT, operator: MAINTAINER_OPERATOR },
      }),
    );
    expect(verdict).toEqual({ ok: false, reason: "submitter_operator" });
  });

  it("reports missing_snapshot_hash before duplicate_operator", () => {
    const record: ApproverRecord = {
      agent: V1_AGENT,
      operator: "op_v1",
      decision: "approve",
      assigned_random: false,
      signed_at: SIGNED_AT,
    };
    const verdict = checkValidation(
      record,
      context({ priorRecords: [rejection(V1_SECOND_AGENT, "op_v1")] }),
    );
    expect(verdict).toEqual({ ok: false, reason: "missing_snapshot_hash" });
  });

  it("reports duplicate_operator before the assignment mismatch", () => {
    const record = { ...approval(V1_AGENT, "op_v1"), assigned_random: true };
    const verdict = checkValidation(
      record,
      context({ priorRecords: [rejection(V1_SECOND_AGENT, "op_v1")] }),
    );
    expect(verdict).toEqual({ ok: false, reason: "duplicate_operator" });
  });
});

/**
 * Two tiers of evidence, seen through derivation: which tier an entry actually
 * verifies at, and when the evidence keeps it in draft however the count runs.
 *
 * The tier rule itself lives in src/evidence.ts and is tested there. What is
 * tested here is the wiring: derivation asks the gate at the moment the count
 * would promote, over exactly the decisions it has counted, and records the
 * answer in the sidecar. Every n-of-k number comes from src/policy.ts; a
 * literal would put a policy number in a second place.
 */

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry, type Clock } from "../src/derive.js";
import type { ApproverRecord, Event, EventType } from "../src/events.js";
import {
  APPROVALS_TO_VERIFY_SMALL_POOL,
  REJECTIONS_TO_REJECT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";

const AUTHOR_OPERATOR = "op_brightloop";
const MAINTAINER = "op_maintainer";
const SIGNATURE = "c2lnbmF0dXJl";
const HASH = `sha256:${"a".repeat(64)}`;
const RECEIPT = `sha256:${"b".repeat(64)}`;
const CITATION = "https://platform.openai.com/docs/deprecations";
const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/**
 * The small pool the cases run in: four trusted outside operators, which is
 * both under the switch to the large pool and enough outside operators for
 * verification's precondition. Four, not three, so a case can spend two
 * approvals and still have two more operators left to reject with.
 */
const VALIDATORS = ["op_v1", "op_v2", "op_v3", "op_v4"] as const;
const POOL = VALIDATORS.length;

/** A hand-built event log. Derivation never looks at the hashes. */
class Log {
  readonly events: Event[] = [];
  private next = 0;

  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): void {
    const seq = this.next;
    this.next += 1;
    this.events.push({
      seq,
      at: new Date(
        Date.parse("2026-09-01T00:00:00Z") + seq * 60_000,
      ).toISOString(),
      type,
      entry_id: entryId,
      payload,
      prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
      hash: `hash-${seq}`,
    });
  }
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
}

/** The maintainer, the submitter's operator, and the three trusted outsiders. */
function baseLog(): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: MAINTAINER,
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (const operator of VALIDATORS) {
    log.add("operator_registered", null, { operator, maintainer: false });
    log.add("operator_trusted", null, { operator });
  }
  return log;
}

/** A stated release core: the seventeen keys, exactly as the schema names them. */
function statedCore(overrides: Record<string, unknown> = {}): Core {
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
    author_operator: AUTHOR_OPERATOR,
    submitted_at: "2026-09-01T14:05:00Z",
    ...overrides,
  } as Core;
}

/** An observed pricing core: the proposed test lives in `observation`. */
function pricingCore(): Core {
  return statedCore({
    id: "nmk_01PRICING1",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    evidence_tier: "observed",
    observation: {
      method: "metered_call",
      test: "Bill one 1000-token call; holds if the invoice line reads $2.50 per million input tokens.",
      receipt_hash: RECEIPT,
      observed_at: "2026-09-01",
      notes: null,
    },
  });
}

/**
 * A behavior core: always observed, the predicate frozen in `evidence`.
 * `provider_statement` is either null or the entry's own citation; the schema
 * allows nothing else.
 */
function behaviorCore(providerStatement: string | null): Core {
  return statedCore({
    id: "nmk_01BEHAVIOR",
    category: "behavior",
    claim: "gpt-5 refuses the frozen prompt",
    evidence_tier: "observed",
    evidence: {
      model: "gpt-5",
      prompt: "Summarize this in one word.",
      parameters: { temperature: 0 },
      output: "I can't help with that.",
      predicate: "the model refuses this prompt",
      observed_at: "2026-09-01",
      provider_statement: providerStatement,
    },
  });
}

function approval(
  operator: string,
  index: number,
  extra: Record<string, unknown> = {},
): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: false,
    test_accepted: true,
    reproduction: null,
    observation: null,
    signed_at: signedAt(index),
    ...extra,
  } as unknown as ApproverRecord;
}

/** A validator's own measurement, in the slot a non-transcript category uses. */
function measured(holds: number): Record<string, unknown> {
  return {
    method: "metered_call",
    receipt_hash: RECEIPT,
    observed_at: "2026-09-01",
    runs: REPRODUCTION_RUNS,
    holds,
  };
}

/** A validator's own rerun, in the slot a transcript category uses. */
function reproduced(holds: number): Record<string, unknown> {
  return {
    model: "gpt-5",
    output: "I can't help with that.",
    observed_at: "2026-09-01",
    runs: REPRODUCTION_RUNS,
    holds,
  };
}

/** An approval that ran the test and reports its counts. */
const observing = (operator: string, index: number, holds: number) =>
  approval(operator, index, { observation: measured(holds) });

/** An approval that reran the frozen prompt and reports its counts. */
const reproducing = (operator: string, index: number, holds: number) =>
  approval(operator, index, { reproduction: reproduced(holds) });

/** An approval whose validator judged the proposed test not to decide the claim. */
const testRejecting = (operator: string, index: number) =>
  approval(operator, index, { test_accepted: false });

/** A stated entry's approval: there is no test to judge and nothing to measure. */
const documentary = (operator: string, index: number) =>
  approval(operator, index, { test_accepted: null });

/**
 * A rejection. The test itself is judged sound, so the rejection is about the
 * claim and not about the test; a rejection signs the reason it rejects.
 */
const rejecting = (operator: string, index: number) =>
  approval(operator, index, {
    decision: "reject",
    reason: "the invoice line does not read this price",
    observation: null,
  });

function submit(log: Log, core: Core): void {
  log.add("entry_submitted", core["id"] as string, { core, signature: SIGNATURE });
}

function validate(log: Log, core: Core, record: ApproverRecord): void {
  log.add("validation", core["id"] as string, { record, signature: SIGNATURE });
}

/** A fresh log with the core submitted and every record validated in order. */
function logFor(core: Core, records: readonly ApproverRecord[]): Log {
  const log = baseLog();
  submit(log, core);
  for (const record of records) validate(log, core, record);
  return log;
}

function run(core: Core, records: readonly ApproverRecord[]) {
  return deriveEntry(logFor(core, records).events, core["id"] as string, CLOCK);
}

describe("the pool the tier cases run in", () => {
  it("is small, and large enough to verify at all", () => {
    expect(POOL).toBeLessThan(TRUSTED_POOL_SWITCH);
    expect(POOL).toBeGreaterThanOrEqual(VERIFICATION_MIN_OUTSIDE_OPERATORS);
    expect(POOL).toBeGreaterThanOrEqual(APPROVALS_TO_VERIFY_SMALL_POOL);
    // Enough operators to spend the approvals and still reject with the rest.
    expect(POOL).toBeGreaterThanOrEqual(
      APPROVALS_TO_VERIFY_SMALL_POOL + REJECTIONS_TO_REJECT,
    );
  });

  it("builds cores holding exactly the schema's core keys", () => {
    for (const core of [statedCore(), pricingCore(), behaviorCore(null)]) {
      expect(Object.keys(core).sort()).toEqual([...CORE_KEYS].sort());
    }
  });
});

describe("the tier an entry verifies at", () => {
  it("falls to stated when a majority rejects the proposed test", () => {
    const core = pricingCore();
    const records = [
      testRejecting(VALIDATORS[0], 1),
      observing(VALIDATORS[1], 2, REPRODUCTION_RUNS),
      testRejecting(VALIDATORS[2], 3),
    ];
    // At the second decision the judgments are one against one: no majority,
    // and the entry waits.
    expect(run(core, records.slice(0, 2)).derived.status).toBe("draft");

    const derived = run(core, records);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(3));
    expect(derived.sidecar.effective_tier).toBe("stated");
    expect(derived.sidecar.test_verdict).toBe("rejected");
  });

  it("is observed when the accepted test held in k of n runs", () => {
    const core = pricingCore();
    const derived = run(core, [
      observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS),
      observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS),
    ]);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.effective_tier).toBe("observed");
    expect(derived.sidecar.test_verdict).toBe("accepted");
  });

  it("stays draft one hold short of the n-of-k rule", () => {
    const core = pricingCore();
    const derived = run(core, [
      observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS - 1),
      observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS - 1),
    ]);
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
    // The log is append-only: the records that failed the gate are still there.
    const approvers = derived.entry["approvers"] as readonly Record<
      string,
      unknown
    >[];
    expect(approvers).toHaveLength(APPROVALS_TO_VERIFY_SMALL_POOL);
    expect(approvers.map((record) => record["operator"])).toEqual([
      VALIDATORS[0],
      VALIDATORS[1],
    ]);
  });

  it("stays draft on a behavior entry with neither statement nor reproduction", () => {
    const core = behaviorCore(null);
    const derived = run(core, [
      approval(VALIDATORS[0], 1),
      approval(VALIDATORS[1], 2),
    ]);
    expect(derived.derived.status).toBe("draft");
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
  });

  it("verifies a behavior entry on a provider statement, as stated", () => {
    const core = behaviorCore(CITATION);
    const derived = run(core, [
      approval(VALIDATORS[0], 1),
      approval(VALIDATORS[1], 2),
    ]);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.effective_tier).toBe("stated");
    expect(derived.sidecar.test_verdict).toBe("accepted");
  });

  it("earns the observed badge on a behavior entry from one reproduction", () => {
    const core = behaviorCore(null);
    const derived = run(core, [
      approval(VALIDATORS[0], 1),
      reproducing(VALIDATORS[1], 2, REPRODUCTION_HOLDS),
    ]);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.effective_tier).toBe("observed");
    expect(derived.sidecar.test_verdict).toBe("accepted");
  });

  it("verifies a stated entry as before, with no test to judge", () => {
    const core = statedCore();
    const derived = run(core, [
      documentary(VALIDATORS[0], 1),
      documentary(VALIDATORS[1], 2),
    ]);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.effective_tier).toBe("stated");
    expect(derived.sidecar.test_verdict).toBeNull();
  });
});

describe("the gate is asked again at the next counted decision", () => {
  const core = pricingCore();

  it("keeps the entry in draft while the passing measurements are the minority", () => {
    const derived = run(core, [
      observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS - 1),
      observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS - 1),
      observing(VALIDATORS[2], 3, REPRODUCTION_HOLDS),
    ]);
    expect(derived.derived.status).toBe("draft");
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
  });

  it("verifies observed once the passing measurements are the majority", () => {
    const derived = run(core, [
      observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS - 1),
      observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS),
      observing(VALIDATORS[2], 3, REPRODUCTION_HOLDS),
    ]);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(3));
    expect(derived.sidecar.effective_tier).toBe("observed");
    expect(derived.sidecar.test_verdict).toBe("accepted");
  });
});

describe("a gate refusal never shields an entry from the rejections", () => {
  const core = pricingCore();

  /**
   * The same four decisions every time: two approvals whose measurements are
   * the only thing that changes, then two rejections from two further eligible
   * operators.
   */
  const decisions = (holds: number) => [
    observing(VALIDATORS[0], 1, holds),
    observing(VALIDATORS[1], 2, holds),
    rejecting(VALIDATORS[2], 3),
    rejecting(VALIDATORS[3], 4),
  ];

  it("rejects an entry the gate keeps turning away", () => {
    const records = decisions(REPRODUCTION_HOLDS - 1);
    // The count to verify is met at the second decision and the gate refuses,
    // so the entry is still open when the rejections start arriving.
    expect(
      run(core, records.slice(0, APPROVALS_TO_VERIFY_SMALL_POOL)).derived.status,
    ).toBe("draft");
    expect(
      run(
        core,
        records.slice(
          0,
          APPROVALS_TO_VERIFY_SMALL_POOL + REJECTIONS_TO_REJECT - 1,
        ),
      ).derived.status,
    ).toBe("draft");

    const derived = run(core, records);
    expect(derived.derived.status).toBe("rejected");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
  });

  it("never reaches the rejections when the same approvals pass the gate", () => {
    const derived = run(core, decisions(REPRODUCTION_HOLDS));
    expect(derived.derived.status).toBe("verified");
    // The promoting decision is the second approval, signed at that index.
    expect(derived.derived.verified_at).toBe(
      signedAt(APPROVALS_TO_VERIFY_SMALL_POOL),
    );
    expect(derived.sidecar.effective_tier).toBe("observed");
    expect(derived.sidecar.test_verdict).toBe("accepted");
  });
});

describe("the gate reads the counted decisions and nothing else", () => {
  const core = pricingCore();

  /** One passing measurement against one failing: a tie, so no majority. */
  const tied = [
    observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS),
    observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS - 1),
  ];

  /** The index the extra record signs at: one past the counted decisions. */
  const extraIndex = tied.length + 1;

  it("is a tie on its own, and the entry waits", () => {
    const derived = run(core, tied);
    expect(derived.derived.status).toBe("draft");
    expect(derived.sidecar.effective_tier).toBeNull();
  });

  it("ignores a passing record from an operator that may not validate", () => {
    // The submitter's own operator. The log keeps the record, derivation counts
    // it for nobody, and the gate must not read it either: were it read, the
    // passing measurements would be the majority and the entry would verify.
    // It makes no difference where in the log the record lands, so both
    // orderings are asked: after the counted decisions, and between them.
    const ineligible = observing(AUTHOR_OPERATOR, extraIndex, REPRODUCTION_RUNS);
    const orderings = [
      [...tied, ineligible],
      [tied[0] as ApproverRecord, ineligible, tied[1] as ApproverRecord],
    ];
    for (const records of orderings) {
      const derived = run(core, records);
      expect(derived.derived.status).toBe("draft");
      expect(derived.derived.verified_at).toBeNull();
      expect(derived.sidecar.effective_tier).toBeNull();
      expect(derived.sidecar.test_verdict).toBeNull();
      // Append-only: the record is on the entry, it simply counts for nothing.
      expect(derived.entry["approvers"]).toHaveLength(tied.length + 1);
    }
  });

  it("ignores a second, passing record from an operator that already decided", () => {
    const derived = run(core, [
      ...tied,
      observing(VALIDATORS[1], extraIndex, REPRODUCTION_RUNS),
    ]);
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
    expect(derived.entry["approvers"]).toHaveLength(tied.length + 1);
  });
});

describe("a gate refusal is never lifted retroactively", () => {
  it("leaves the entry in draft when only the trusted pool moves", () => {
    const core = pricingCore();
    const log = logFor(core, [
      observing(VALIDATORS[0], 1, REPRODUCTION_HOLDS - 1),
      observing(VALIDATORS[1], 2, REPRODUCTION_HOLDS - 1),
    ]);
    expect(deriveEntry(log.events, core["id"] as string, CLOCK).derived.status).toBe(
      "draft",
    );

    // The pool changes in every direction, and no decision is taken.
    log.add("operator_untrusted", null, { operator: VALIDATORS[2] });
    for (let index = 0; index < TRUSTED_POOL_SWITCH; index += 1) {
      const operator = `op_late${index}`;
      log.add("operator_registered", null, { operator, maintainer: false });
      log.add("operator_trusted", null, { operator });
    }

    const derived = deriveEntry(log.events, core["id"] as string, CLOCK);
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();
    expect(derived.sidecar.trusted_count_at_decision).toBeNull();
  });
});

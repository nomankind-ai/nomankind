/**
 * The consensus table: what a run of validation decisions does to an entry, at
 * each trusted-pool size, and the retroactivity rules that keep a past verdict
 * from moving when the pool later moves (retrospective M8).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry, type Clock } from "../src/derive.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";
import type {
  ApproverRecord,
  Event,
  EventType,
  ReconfirmationRecord,
} from "../src/events.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = "nmk_01J8ZQ2K7";
const AUTHOR_OPERATOR = "op_brightloop";
const MAINTAINER = "op_maintainer";
const SIGNATURE = example["signature"] as string;
const HASH = `sha256:${"a".repeat(64)}`;
const SMALL_POOL = 3;
const LARGE_POOL = TRUSTED_POOL_SWITCH;
const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/** Twelve outside operators, enough to fill the large pool. */
const VALIDATORS = Array.from({ length: 12 }, (_, index) => `op_v${index + 1}`);

/** A hand-built event log. Derivation never looks at the hashes. */
class Log {
  readonly events: Event[] = [];
  private next = 0;

  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): number {
    const seq = this.next;
    this.next += 1;
    this.events.push({
      seq,
      at: at(seq),
      type,
      entry_id: entryId,
      payload,
      prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
      hash: `hash-${seq}`,
    });
    return seq;
  }
}

function at(index: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + index * 60_000,
  ).toISOString();
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
}

function coreFrom(overrides: Record<string, unknown> = {}): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["author_operator"] = AUTHOR_OPERATOR;
  return { ...core, ...overrides } as Core;
}

function decision(
  operator: string,
  outcome: "approve" | "reject",
  index: number,
  assignedRandom = false,
): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision: outcome,
    reason: outcome === "reject" ? "source does not say this" : null,
    snapshot_hash: HASH,
    assigned_random: assignedRandom,
    test_accepted: true,
    reproduction: null,
    observation: {
      method: "endpoint_error",
      receipt_hash: HASH,
      observed_at: "2026-09-01",
      runs: 10,
      holds: 10,
    },
    signed_at: signedAt(index),
  } as unknown as ApproverRecord;
}

const approve = (operator: string, index: number, assignedRandom = false) =>
  decision(operator, "approve", index, assignedRandom);
const reject = (operator: string, index: number) =>
  decision(operator, "reject", index);

/**
 * A log with the maintainer, the submitter's operator, `outside` other
 * registered operators, and `trusted` of them in the trusted pool.
 */
function baseLog(trusted: number, outside: number): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: MAINTAINER,
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (let index = 0; index < outside; index += 1) {
    log.add("operator_registered", null, {
      operator: VALIDATORS[index] as string,
      maintainer: false,
    });
  }
  for (let index = 0; index < trusted; index += 1) {
    log.add("operator_trusted", null, {
      operator: VALIDATORS[index] as string,
    });
  }
  return log;
}

function submit(log: Log, id: string, overrides: Record<string, unknown> = {}) {
  log.add("entry_submitted", id, {
    core: coreFrom({ id, ...overrides }),
    signature: SIGNATURE,
  });
}

function validate(log: Log, id: string, record: ApproverRecord) {
  log.add("validation", id, { record, signature: SIGNATURE });
}

function runCase(
  trusted: number,
  outside: number,
  records: readonly ApproverRecord[],
) {
  const log = baseLog(trusted, outside);
  submit(log, ENTRY_ID);
  for (const record of records) validate(log, ENTRY_ID, record);
  return deriveEntry(log.events, ENTRY_ID, CLOCK);
}

interface ConsensusCase {
  readonly name: string;
  readonly trusted: number;
  readonly outside: number;
  readonly records: readonly ApproverRecord[];
  readonly status: string;
  /** Index into `records` whose signed_at becomes verified_at, or null. */
  readonly verifiedAtIndex: number | null;
  readonly needsReplacement: boolean;
  readonly trustedCountAtDecision: number | null;
}

const ENOUGH_OUTSIDE = Math.max(VERIFICATION_MIN_OUTSIDE_OPERATORS, LARGE_POOL);

const cases: readonly ConsensusCase[] = [
  {
    name: "small pool: two approvals from distinct operators verify",
    trusted: SMALL_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v2", 2)],
    status: "verified",
    verifiedAtIndex: 1,
    needsReplacement: false,
    trustedCountAtDecision: SMALL_POOL,
  },
  {
    name: "small pool: two rejections reject",
    trusted: SMALL_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [reject("op_v1", 1), reject("op_v2", 2)],
    status: "rejected",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: SMALL_POOL,
  },
  {
    name: "small pool: one approve and one reject stay draft, no replacement",
    trusted: SMALL_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), reject("op_v2", 2)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "small pool: two approvals from the same operator count once",
    trusted: SMALL_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v1", 2)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "large pool: three approvals with exactly one drawn validator verify",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [
      approve("op_v1", 1),
      approve("op_v2", 2),
      approve("op_v3", 3, true),
    ],
    status: "verified",
    verifiedAtIndex: 2,
    needsReplacement: false,
    trustedCountAtDecision: LARGE_POOL,
  },
  {
    name: "large pool: three approvals with no drawn validator stay draft",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v2", 2), approve("op_v3", 3)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "large pool: two approvals stay draft",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v2", 2, true)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "large pool: two rejections reject",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [reject("op_v1", 1), reject("op_v2", 2)],
    status: "rejected",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: LARGE_POOL,
  },
  {
    name: "large pool: two approvals against one rejection owe a replacement",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v2", 2), reject("op_v3", 3)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: true,
    trustedCountAtDecision: null,
  },
  {
    name: "large pool: the replacement's approval completes verification",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [
      approve("op_v1", 1),
      approve("op_v2", 2),
      reject("op_v3", 3),
      approve("op_v4", 4, true),
    ],
    status: "verified",
    verifiedAtIndex: 3,
    needsReplacement: false,
    trustedCountAtDecision: LARGE_POOL,
  },
  {
    name: "large pool: the replacement's rejection lands the second rejection",
    trusted: LARGE_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [
      approve("op_v1", 1),
      approve("op_v2", 2),
      reject("op_v3", 3),
      reject("op_v4", 4),
    ],
    status: "rejected",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: LARGE_POOL,
  },
  {
    name: "no trusted operators: two approvals stay draft",
    trusted: 0,
    outside: ENOUGH_OUTSIDE,
    records: [approve("op_v1", 1), approve("op_v2", 2)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "too few outside operators: two approvals stay draft",
    trusted: SMALL_POOL,
    outside: VERIFICATION_MIN_OUTSIDE_OPERATORS - 1,
    records: [approve("op_v1", 1), approve("op_v2", 2)],
    status: "draft",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: null,
  },
  {
    name: "rejected is terminal: a later approval never verifies",
    trusted: SMALL_POOL,
    outside: ENOUGH_OUTSIDE,
    records: [
      reject("op_v1", 1),
      reject("op_v2", 2),
      approve("op_v3", 3),
      approve("op_v4", 4),
    ],
    status: "rejected",
    verifiedAtIndex: null,
    needsReplacement: false,
    trustedCountAtDecision: SMALL_POOL,
  },
];

describe("the consensus table", () => {
  it.each(cases)("$name", (testCase) => {
    const derived = runCase(
      testCase.trusted,
      testCase.outside,
      testCase.records,
    );
    expect(derived.derived.status).toBe(testCase.status);
    expect(derived.derived.verified_at).toBe(
      testCase.verifiedAtIndex === null
        ? null
        : (testCase.records[testCase.verifiedAtIndex] as unknown as {
            signed_at: string;
          }).signed_at,
    );
    expect(derived.sidecar.needs_replacement).toBe(testCase.needsReplacement);
    expect(derived.sidecar.trusted_count_at_decision).toBe(
      testCase.trustedCountAtDecision,
    );
    // Every record stays on the entry, counted or not.
    expect((derived.entry["approvers"] as unknown[]).length).toBe(
      testCase.records.length,
    );
  });

  it("names the pool sizes the table is driven at", () => {
    expect(SMALL_POOL).toBeLessThan(TRUSTED_POOL_SWITCH);
    expect(LARGE_POOL).toBe(TRUSTED_POOL_SWITCH);
    expect(APPROVALS_TO_VERIFY_SMALL_POOL).toBeLessThan(
      APPROVALS_TO_VERIFY_LARGE_POOL,
    );
  });
});

describe("thresholds are read at the decision's position", () => {
  it("keeps a small-pool verification after the pool grows past ten", () => {
    const log = baseLog(SMALL_POOL, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve("op_v1", 1));
    validate(log, ENTRY_ID, approve("op_v2", 2));
    for (let index = SMALL_POOL; index < TRUSTED_POOL_SWITCH; index += 1) {
      log.add("operator_trusted", null, {
        operator: VALIDATORS[index] as string,
      });
    }
    expect(
      trustedCountNow(log) >= TRUSTED_POOL_SWITCH,
    ).toBe(true);

    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.trusted_count_at_decision).toBe(SMALL_POOL);
  });

  it("keeps two large-pool approvals in draft after the pool shrinks", () => {
    const log = baseLog(LARGE_POOL, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve("op_v1", 1));
    validate(log, ENTRY_ID, approve("op_v2", 2));
    for (let index = SMALL_POOL; index < LARGE_POOL; index += 1) {
      log.add("operator_untrusted", null, {
        operator: VALIDATORS[index] as string,
      });
    }
    expect(trustedCountNow(log)).toBe(SMALL_POOL);

    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.trusted_count_at_decision).toBeNull();
  });

  it("never verifies retroactively when the trusted pool becomes non-empty", () => {
    const log = baseLog(0, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve("op_v1", 1));
    validate(log, ENTRY_ID, approve("op_v2", 2));
    expect(deriveEntry(log.events, ENTRY_ID, CLOCK).derived.status).toBe(
      "draft",
    );

    log.add("operator_trusted", null, { operator: VALIDATORS[0] as string });
    // Still draft: nothing re-evaluates without a new decision.
    expect(deriveEntry(log.events, ENTRY_ID, CLOCK).derived.status).toBe(
      "draft",
    );

    validate(log, ENTRY_ID, approve("op_v3", 3));
    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(3));
    expect(derived.sidecar.trusted_count_at_decision).toBe(1);
  });
});

describe("only outside registered operators count", () => {
  /** An operator the log never registers at all. */
  const STRANGER = "op_stranger";

  function drafted(record: ApproverRecord) {
    const log = baseLog(SMALL_POOL, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, record);
    validate(log, ENTRY_ID, approve("op_v1", 2));
    return deriveEntry(log.events, ENTRY_ID, CLOCK);
  }

  it("does not count an approval from the submitter's own operator", () => {
    const derived = drafted(approve(AUTHOR_OPERATOR, 1));
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
  });

  it("does not count an approval from the maintainer's operator", () => {
    const derived = drafted(approve(MAINTAINER, 1));
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
  });

  it("does not count an approval from an operator never registered", () => {
    const derived = drafted(approve(STRANGER, 1));
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
  });

  it("verifies on a second outside approval and keeps every record", () => {
    const log = baseLog(SMALL_POOL, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve(AUTHOR_OPERATOR, 1));
    validate(log, ENTRY_ID, approve(MAINTAINER, 2));
    validate(log, ENTRY_ID, approve(STRANGER, 3));
    validate(log, ENTRY_ID, approve("op_v1", 4));
    expect(deriveEntry(log.events, ENTRY_ID, CLOCK).derived.status).toBe(
      "draft",
    );

    validate(log, ENTRY_ID, approve("op_v2", 5));
    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(5));
    expect(derived.sidecar.trusted_count_at_decision).toBe(SMALL_POOL);

    // The log is append-only: an uncounted record is still on the entry.
    const approvers = derived.entry["approvers"] as readonly Record<
      string,
      unknown
    >[];
    expect(approvers).toHaveLength(5);
    expect(approvers.map((record) => record["operator"])).toEqual([
      AUTHOR_OPERATOR,
      MAINTAINER,
      STRANGER,
      "op_v1",
      "op_v2",
    ]);
  });
});

describe("the trusted pool at the decision's own position", () => {
  it("stays draft when an untrust before the decision empties the pool", () => {
    const log = baseLog(SMALL_POOL, ENOUGH_OUTSIDE);
    for (let index = 0; index < SMALL_POOL; index += 1) {
      log.add("operator_untrusted", null, {
        operator: VALIDATORS[index] as string,
      });
    }
    expect(trustedCountNow(log)).toBe(0);

    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve("op_v4", 1));
    validate(log, ENTRY_ID, approve("op_v5", 2));

    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("draft");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.trusted_count_at_decision).toBeNull();
  });

  it("counts a trust event at seq p-1 for the decision at seq p", () => {
    // Nine trusted operators, then the tenth arrives immediately before the
    // second approval. Read exclusively the pool would still be small and two
    // approvals would verify; read inclusively it is already large, so three
    // approvals with one drawn validator are needed.
    const log = baseLog(TRUSTED_POOL_SWITCH - 1, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    validate(log, ENTRY_ID, approve("op_v1", 1));

    const trustSeq = log.add("operator_trusted", null, {
      operator: VALIDATORS[TRUSTED_POOL_SWITCH - 1] as string,
    });
    const decisionSeq = log.add("validation", ENTRY_ID, {
      record: approve("op_v2", 2),
      signature: SIGNATURE,
    });
    expect(decisionSeq).toBe(trustSeq + 1);
    expect(trustedCountNow(log)).toBe(TRUSTED_POOL_SWITCH);

    const twoApprovals = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(twoApprovals.derived.status).toBe("draft");
    expect(twoApprovals.derived.verified_at).toBeNull();

    validate(log, ENTRY_ID, approve("op_v3", 3, true));
    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(3));
    expect(derived.sidecar.trusted_count_at_decision).toBe(TRUSTED_POOL_SWITCH);
  });
});

describe("last_confirmed follows log order", () => {
  function reconfirmation(
    operator: string,
    at: string,
  ): ReconfirmationRecord {
    return {
      agent: `1F916:agent-${operator}`,
      operator,
      snapshot_hash: HASH,
      reproduction: null,
      observation: {
        method: "endpoint_error",
        receipt_hash: HASH,
        observed_at: "2026-09-01",
        runs: 10,
        holds: 10,
      },
      signed_at: at,
    } as unknown as ReconfirmationRecord;
  }

  it("takes the latest reconfirmation by position, not the greatest signed_at", () => {
    const log = baseLog(SMALL_POOL, ENOUGH_OUTSIDE);
    submit(log, ENTRY_ID);
    log.add("reconfirmation", ENTRY_ID, {
      record: reconfirmation("op_v1", "2026-10-15T09:00:00Z"),
      signature: SIGNATURE,
    });
    // Appended second, but dated earlier: append position is the sealed truth,
    // so no reconfirmer can extend its window by forward-dating signed_at.
    log.add("reconfirmation", ENTRY_ID, {
      record: reconfirmation("op_v2", "2026-10-01T09:00:00Z"),
      signature: SIGNATURE,
    });

    const derived = deriveEntry(log.events, ENTRY_ID, CLOCK).derived;
    expect(derived.last_confirmed).toBe("2026-10-01");
  });
});

/** The trusted pool at the end of the log, for the fixture's own assertions. */
function trustedCountNow(log: Log): number {
  const trusted = new Set<string>();
  for (const event of log.events) {
    if (event.type === "operator_trusted") {
      trusted.add((event.payload as { operator: string }).operator);
    }
    if (event.type === "operator_untrusted") {
      trusted.delete((event.payload as { operator: string }).operator);
    }
  }
  return trusted.size;
}

/**
 * Derived fields: the schema-shaped entry, freshness, supersession, disputes,
 * and the promise that derivation never reads a wall clock.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveAll, deriveEntry, type Clock } from "../src/derive.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  POLICY,
  REJECTIONS_TO_REJECT,
  DEFAULT_DOMAIN,
  stalenessWindowDays,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";
import { validateEntry } from "../src/schema.js";
import type {
  ApproverRecord,
  Event,
  EventType,
  ReconfirmationRecord,
} from "../src/events.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const derivePath = fileURLToPath(new URL("../src/derive.ts", import.meta.url));
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = "nmk_01J8ZQ2K7";
const AUTHOR_OPERATOR = "op_brightloop";
const SIGNATURE = example["signature"] as string;
const HASH = `sha256:${"a".repeat(64)}`;
const SMALL_POOL = 3;
const VALIDATORS = ["op_v1", "op_v2", "op_v3", "op_v4"];

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

function coreFrom(overrides: Record<string, unknown>): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["author_operator"] = AUTHOR_OPERATOR;
  return { ...core, ...overrides } as Core;
}

function approval(
  operator: string,
  signedAt: string,
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
    observation: {
      method: "endpoint_error",
      receipt_hash: HASH,
      observed_at: "2026-09-01",
      runs: 10,
      holds: 10,
    },
    signed_at: signedAt,
    ...extra,
  } as unknown as ApproverRecord;
}

function reconfirmation(
  operator: string,
  signedAt: string,
): ReconfirmationRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    snapshot_hash: HASH,
    reproduction: null,
    observation: {
      method: "endpoint_error",
      receipt_hash: HASH,
      observed_at: "2026-10-15",
      runs: 10,
      holds: 10,
    },
    signed_at: signedAt,
  } as unknown as ReconfirmationRecord;
}

/** Registers the maintainer, the submitter, three others, and a trusted pool. */
function baseLog(): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: "op_maintainer",
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (const operator of VALIDATORS) {
    log.add("operator_registered", null, { operator, maintainer: false });
  }
  for (let index = 0; index < SMALL_POOL; index += 1) {
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

/** Two approvals from distinct operators: enough to verify in a small pool. */
function verifyIt(log: Log, id: string, first: string, second: string) {
  log.add("validation", id, {
    record: approval(VALIDATORS[0] as string, first),
    signature: SIGNATURE,
  });
  log.add("validation", id, {
    record: approval(VALIDATORS[1] as string, second),
    signature: SIGNATURE,
  });
}

describe("the derived entry", () => {
  it("builds a schema-valid entry from the example's core", () => {
    const log = baseLog();
    submit(log, ENTRY_ID);
    // The delivered record carries an envelope signature; the entry must not.
    log.add("validation", ENTRY_ID, {
      record: approval(VALIDATORS[0] as string, "2026-09-02T01:00:00Z", {
        signature: SIGNATURE,
      }),
      signature: SIGNATURE,
    });
    log.add("validation", ENTRY_ID, {
      record: approval(VALIDATORS[1] as string, "2026-09-02T02:00:00Z", {
        signature: SIGNATURE,
      }),
      signature: SIGNATURE,
    });

    const { entry, derived, sidecar } = deriveEntry(log.events, ENTRY_ID, {
      now: "2026-09-10T00:00:00Z",
    });

    const result = validateEntry(entry);
    expect(result.ok ? [] : result.errors).toEqual([]);
    expect(result.ok).toBe(true);

    expect(derived.status).toBe("verified");
    // The tier lives beside the entry, never on it: the schema has no field
    // for it, and the example's approvals carry the measurement it takes.
    expect(sidecar.effective_tier).toBe("observed");
    expect(sidecar.test_verdict).toBe("accepted");
    expect(Object.keys(entry)).not.toContain("effective_tier");
    expect(entry["confidence"]).toBeNull();
    expect(entry["seal"]).toBeNull();
    expect(entry["disputes"]).toEqual([]);
    expect(entry["failure_reports"]).toEqual([]);
    expect(entry["signature"]).toBe(SIGNATURE);

    const approvers = entry["approvers"] as readonly Record<string, unknown>[];
    expect(approvers).toHaveLength(2);
    for (const record of approvers) {
      expect(Object.keys(record)).not.toContain("signature");
      expect(record["operator"]).toBeTypeOf("string");
      expect(record["decision"]).toBe("approve");
      expect(record["assigned_random"]).toBe(false);
      expect(record["signed_at"]).toBeTypeOf("string");
    }
  });
});

describe("freshness and decay", () => {
  const PRICING_EXPIRES = "2026-11-30"; // 2026-09-01 + 90 days

  function pricingLog(): Log {
    const log = baseLog();
    submit(log, ENTRY_ID, { category: "pricing" });
    verifyIt(log, ENTRY_ID, "2026-09-02T01:00:00Z", "2026-09-02T02:00:00Z");
    return log;
  }

  it("is stale 91 days after the last confirmation", () => {
    const derived = deriveEntry(pricingLog().events, ENTRY_ID, {
      now: "2026-12-01T00:00:00Z",
    }).derived;
    expect(derived.staleness_window_days).toBe(
      stalenessWindowDays(DEFAULT_DOMAIN, "pricing"),
    );
    expect(derived.last_confirmed).toBe("2026-09-01");
    expect(derived.expires_at).toBe(PRICING_EXPIRES);
    expect(derived.stale).toBe(true);
    expect(derived.status).toBe("verified");
  });

  it("is not stale 89 days after the last confirmation", () => {
    const derived = deriveEntry(pricingLog().events, ENTRY_ID, {
      now: "2026-11-29T00:00:00Z",
    }).derived;
    expect(derived.expires_at).toBe(PRICING_EXPIRES);
    expect(derived.stale).toBe(false);
  });

  // expires_at is a calendar date, so the comparison is one of days, not
  // instants: the expiry date itself is the last fresh day.
  it("is not stale at the start of the expiry date itself", () => {
    const derived = deriveEntry(pricingLog().events, ENTRY_ID, {
      now: `${PRICING_EXPIRES}T00:00:00Z`,
    }).derived;
    expect(derived.expires_at).toBe(PRICING_EXPIRES);
    expect(derived.stale).toBe(false);
  });

  it("is not stale at the last second of the expiry date", () => {
    const derived = deriveEntry(pricingLog().events, ENTRY_ID, {
      now: `${PRICING_EXPIRES}T23:59:59Z`,
    }).derived;
    expect(derived.expires_at).toBe(PRICING_EXPIRES);
    expect(derived.stale).toBe(false);
  });

  it("is stale at the start of the day after the expiry date", () => {
    const derived = deriveEntry(pricingLog().events, ENTRY_ID, {
      now: "2026-12-01T00:00:00Z", // PRICING_EXPIRES + 1 day
    }).derived;
    expect(derived.expires_at).toBe(PRICING_EXPIRES);
    expect(derived.stale).toBe(true);
  });

  it("gives an event category no window at all", () => {
    const log = baseLog();
    submit(log, ENTRY_ID, { category: "release" });
    verifyIt(log, ENTRY_ID, "2026-09-02T01:00:00Z", "2026-09-02T02:00:00Z");
    const derived = deriveEntry(log.events, ENTRY_ID, {
      now: "2030-01-01T00:00:00Z",
    }).derived;
    expect(derived.staleness_window_days).toBeNull();
    expect(derived.expires_at).toBeNull();
    expect(derived.stale).toBe(false);
  });

  it("moves the window forward on a reconfirmation", () => {
    const log = pricingLog();
    const clock: Clock = { now: "2026-12-01T00:00:00Z" };
    expect(deriveEntry(log.events, ENTRY_ID, clock).derived.stale).toBe(true);

    log.add("reconfirmation", ENTRY_ID, {
      record: reconfirmation(VALIDATORS[2] as string, "2026-10-15T09:00:00Z"),
      signature: SIGNATURE,
    });

    const derived = deriveEntry(log.events, ENTRY_ID, clock).derived;
    expect(derived.last_confirmed).toBe("2026-10-15");
    expect(derived.expires_at).toBe("2027-01-13"); // 2026-10-15 + 90 days
    expect(derived.stale).toBe(false);
    expect(
      (deriveEntry(log.events, ENTRY_ID, clock).entry[
        "reconfirmations"
      ] as unknown[]).length,
    ).toBe(1);
  });
});

describe("supersession and disputes", () => {
  const FIRST = "nmk_first01";
  const SECOND = "nmk_second02";
  const CORRECTION = "nmk_correction03";

  function supersessionLog(): Log {
    const log = baseLog();
    submit(log, FIRST);
    verifyIt(log, FIRST, "2026-09-02T01:00:00Z", "2026-09-02T02:00:00Z");
    submit(log, SECOND, { supersedes: FIRST });
    return log;
  }

  const clock: Clock = { now: "2026-09-10T00:00:00Z" };

  it("leaves the first entry verified while the superseding entry is draft", () => {
    const derived = deriveEntry(supersessionLog().events, FIRST, clock).derived;
    expect(derived.status).toBe("verified");
    expect(derived.superseded_by).toBeNull();
  });

  it("supersedes the first entry once the second verifies", () => {
    const log = supersessionLog();
    verifyIt(log, SECOND, "2026-09-03T01:00:00Z", "2026-09-03T02:00:00Z");
    const derived = deriveEntry(log.events, FIRST, clock).derived;
    expect(derived.status).toBe("superseded");
    expect(derived.superseded_by).toBe(SECOND);
    expect(derived.verified_at).toBe("2026-09-02T02:00:00Z");
    expect(deriveEntry(log.events, SECOND, clock).derived.status).toBe(
      "verified",
    );
  });

  it("keeps the tier it verified at once superseded or overturned", () => {
    const log = supersessionLog();
    verifyIt(log, SECOND, "2026-09-03T01:00:00Z", "2026-09-03T02:00:00Z");
    const superseded = deriveEntry(log.events, FIRST, clock);
    expect(superseded.derived.status).toBe("superseded");
    expect(superseded.sidecar.effective_tier).toBe("observed");
    expect(superseded.sidecar.test_verdict).toBe("accepted");

    log.add("dispute_upheld", FIRST, { correction_entry_id: CORRECTION });
    const overturned = deriveEntry(log.events, FIRST, clock);
    expect(overturned.derived.status).toBe("overturned");
    expect(overturned.sidecar.effective_tier).toBe("observed");
    expect(overturned.sidecar.test_verdict).toBe("accepted");
  });

  it("carries no tier on an entry that never verified", () => {
    const sidecar = deriveEntry(supersessionLog().events, SECOND, clock).sidecar;
    expect(sidecar.effective_tier).toBeNull();
    expect(sidecar.test_verdict).toBeNull();
  });

  it("overturns the entry on an upheld dispute", () => {
    const log = supersessionLog();
    verifyIt(log, SECOND, "2026-09-03T01:00:00Z", "2026-09-03T02:00:00Z");
    log.add("dispute_upheld", FIRST, { correction_entry_id: CORRECTION });
    const derived = deriveEntry(log.events, FIRST, clock).derived;
    expect(derived.status).toBe("overturned");
    expect(derived.overturned_by).toBe(CORRECTION);
  });
});

describe("the derivation surface", () => {
  const clock: Clock = { now: "2026-09-10T00:00:00Z" };

  it("throws for an entry the log never saw submitted", () => {
    const log = baseLog();
    submit(log, ENTRY_ID);
    expect(() => deriveEntry(log.events, "nmk_missing", clock)).toThrow(
      /nmk_missing/,
    );
  });

  it("derives one entry per entry_submitted event", () => {
    const log = baseLog();
    submit(log, "nmk_one01");
    submit(log, "nmk_two02");
    const all = deriveAll(log.events, clock);
    expect(all.size).toBe(2);
    expect([...all.keys()].sort()).toEqual(["nmk_one01", "nmk_two02"]);
    expect(all.get("nmk_one01")?.derived.status).toBe("draft");
  });

  it("reads no wall clock", () => {
    const source = readFileSync(derivePath, "utf8");
    expect(source).not.toContain("Date.now");
    expect(source).not.toContain("new Date()");
  });
});

describe("the consensus policy numbers", () => {
  it("exports each threshold and collects it in POLICY", () => {
    expect(APPROVALS_TO_VERIFY_SMALL_POOL).toBe(2);
    expect(APPROVALS_TO_VERIFY_LARGE_POOL).toBe(3);
    expect(REJECTIONS_TO_REJECT).toBe(2);
    expect(VERIFICATION_MIN_OUTSIDE_OPERATORS).toBe(3);
    expect(POLICY.APPROVALS_TO_VERIFY_SMALL_POOL).toBe(
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );
    expect(POLICY.APPROVALS_TO_VERIFY_LARGE_POOL).toBe(
      APPROVALS_TO_VERIFY_LARGE_POOL,
    );
    expect(POLICY.REJECTIONS_TO_REJECT).toBe(REJECTIONS_TO_REJECT);
    expect(POLICY.VERIFICATION_MIN_OUTSIDE_OPERATORS).toBe(
      VERIFICATION_MIN_OUTSIDE_OPERATORS,
    );
  });
});

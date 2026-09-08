/**
 * Assignment: the beacon draw is deterministic and unsteerable, the
 * seventy-two-hour window is exactly the policy window, a miss redraws without
 * adding an approver, and the replacement draw resolves a 2-1 split either way.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  assignmentDeadline,
  buildAssignment,
  drawDue,
  poolSnapshotDue,
  buildAssignmentMissed,
  drawValidator,
  exclusionsFor,
  isAssignmentMissed,
  latestPoolSnapshot,
  openAssignment,
  type Beacon,
  type DrawDueVerdict,
  type PoolSnapshot,
} from "../src/assign.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry, type Clock } from "../src/derive.js";
import { appendEvent, verifyChain } from "../src/events.js";
import { ASSIGNMENT_WINDOW_HOURS, TRUSTED_POOL_SWITCH } from "../src/policy.js";
import type { ApproverRecord, Event, EventType } from "../src/events.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = "nmk_01J8ZQ2K7";
const OTHER_ENTRY_ID = "nmk_01J8ZQ2K8";
const AUTHOR_OPERATOR = "op_brightloop";
const MAINTAINER = "op_maintainer";
const SIGNATURE = example["signature"] as string;
const HASH = `sha256:${"a".repeat(64)}`;

/**
 * Sixteen outside operators. The draw only runs at or above the pool switch,
 * so every pool a draw is asked for holds at least TRUSTED_POOL_SWITCH of
 * these, with spare operators left over for exclusions and replacements.
 */
const VALIDATORS = Array.from({ length: 16 }, (_, index) => `op_v${index + 1}`);

const SNAPSHOT_AT = "2026-09-01T00:00:00.000Z";
const BEACON_AT = "2026-09-01T01:00:00.000Z";

/** A fixed fixture beacon: the round number picks the randomness. */
function beacon(round: number, at: string = BEACON_AT): Beacon {
  return { round, randomness: `${"7c1f".repeat(15)}${round % 10}`, at };
}

function snapshotOf(
  operators: readonly string[],
  at: string = SNAPSHOT_AT,
): PoolSnapshot {
  return { seq: 0, at, operators };
}

/** A hand-built event log, as the derivation tests do; hashes are not read. */
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
    signed_at: `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`,
  } as unknown as ApproverRecord;
}

const approve = (operator: string, index: number, assignedRandom = false) =>
  decision(operator, "approve", index, assignedRandom);
const reject = (operator: string, index: number, assignedRandom = false) =>
  decision(operator, "reject", index, assignedRandom);

/**
 * A real, hash-chained log: the maintainer, the submitter's operator, `trusted`
 * outside operators all registered and trusted, a pool snapshot of them, and
 * the sealed submission.
 */
async function sealedLog(trusted: number): Promise<Event[]> {
  const pool = VALIDATORS.slice(0, trusted);
  let events: Event[] = [];
  let seq = 0;
  const next = () => at(seq++);

  events = await appendEvent(events, {
    at: next(),
    type: "operator_registered",
    entry_id: null,
    payload: { operator: MAINTAINER, maintainer: true },
  });
  events = await appendEvent(events, {
    at: next(),
    type: "operator_registered",
    entry_id: null,
    payload: { operator: AUTHOR_OPERATOR, maintainer: false },
  });
  for (const operator of pool) {
    events = await appendEvent(events, {
      at: next(),
      type: "operator_registered",
      entry_id: null,
      payload: { operator, maintainer: false },
    });
  }
  for (const operator of pool) {
    events = await appendEvent(events, {
      at: next(),
      type: "operator_trusted",
      entry_id: null,
      payload: { operator },
    });
  }
  events = await appendEvent(events, {
    at: next(),
    type: "pool_snapshot",
    entry_id: null,
    payload: { operators: [...pool].sort() },
  });
  events = await appendEvent(events, {
    at: next(),
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: { core: coreFrom({ id: ENTRY_ID }), signature: SIGNATURE },
  });
  return events;
}

async function expectChainOk(events: readonly Event[]): Promise<void> {
  expect(await verifyChain(events)).toEqual({ ok: true, length: events.length });
}

function drawn(result: Awaited<ReturnType<typeof drawValidator>>): string {
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("draw refused");
  return result.operator;
}

/**
 * The drawn operator is one of the eligible operators, and the index really
 * points at it: an index outside [0, eligible.length) can never pass.
 */
function expectDrawInRange(
  result: Awaited<ReturnType<typeof drawValidator>>,
): void {
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("draw refused");
  expect(result.eligible).toContain(result.operator);
  expect(Number.isInteger(result.index)).toBe(true);
  expect(result.index).toBeGreaterThanOrEqual(0);
  expect(result.index).toBeLessThan(result.eligible.length);
  expect(result.eligible[result.index]).toBe(result.operator);
}

describe("drawValidator", () => {
  const POOL = VALIDATORS.slice(0, TRUSTED_POOL_SWITCH);

  it("is deterministic: ten calls on the same inputs agree", async () => {
    const first = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(POOL),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(first.ok).toBe(true);
    for (let call = 0; call < 9; call += 1) {
      const again = await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(POOL),
        beacon: beacon(4_100_100),
        exclude: [],
      });
      expect(again).toEqual(first);
    }
  });

  it("moves with the beacon round", async () => {
    const pool = POOL;
    const base = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(pool),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    let differing: number | null = null;
    for (let round = 4_100_101; round <= 4_100_140; round += 1) {
      const candidate = await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(pool),
        beacon: beacon(round),
        exclude: [],
      });
      if (drawn(candidate) !== drawn(base)) {
        differing = round;
        break;
      }
    }
    expect(differing).not.toBeNull();
    const other = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(pool),
      beacon: beacon(differing as number),
      exclude: [],
    });
    expect(drawn(other)).not.toBe(drawn(base));
  });

  it("never draws the submitter's operator or a prior signer", async () => {
    const priorSigner = VALIDATORS[0] as string;
    const pool = [AUTHOR_OPERATOR, ...VALIDATORS.slice(0, TRUSTED_POOL_SWITCH)];
    const exclude = [AUTHOR_OPERATOR, priorSigner];
    const distinct = new Set<string>();
    for (let round = 5_000_000; round < 5_000_120; round += 1) {
      const result = await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(pool),
        beacon: beacon(round),
        exclude,
      });
      const operator = drawn(result);
      expect(operator).not.toBe(AUTHOR_OPERATOR);
      expect(operator).not.toBe(priorSigner);
      // The index has to land inside the eligible list, or an out-of-range
      // draw could name an excluded operator without the assertions noticing.
      expectDrawInRange(result);
      distinct.add(operator);
    }
    // The draw still spreads over what is left, so the exclusion is not a
    // constant answer in disguise.
    expect(distinct.size).toBeGreaterThan(1);
  });

  it("refuses a snapshot that is not committed before the beacon round", async () => {
    const equal = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(POOL, BEACON_AT),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(equal).toEqual({ ok: false, reason: "snapshot_after_beacon" });

    const after = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(POOL, "2026-09-01T02:00:00.000Z"),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(after).toEqual({ ok: false, reason: "snapshot_after_beacon" });
  });

  it("refuses an empty pool and a fully excluded pool", async () => {
    expect(
      await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf([]),
        beacon: beacon(4_100_100),
        exclude: [],
      }),
    ).toEqual({ ok: false, reason: "empty_pool" });

    expect(
      await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(POOL),
        beacon: beacon(4_100_100),
        exclude: POOL,
      }),
    ).toEqual({ ok: false, reason: "no_eligible_operator" });
  });

  it("refuses a pool under the switch and draws at the switch", async () => {
    // The schema, of approvers[].assigned_random: "Always false while the pool
    // is under ten operators", because before then two approvals verify and no
    // draw is made. One operator short is still short.
    const short = VALIDATORS.slice(0, TRUSTED_POOL_SWITCH - 1);
    expect(short).toHaveLength(TRUSTED_POOL_SWITCH - 1);
    expect(
      await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(short),
        beacon: beacon(4_100_100),
        exclude: [],
      }),
    ).toEqual({ ok: false, reason: "pool_below_switch" });

    // The pool is counted after de-duplication, so padding it with repeats
    // does not buy a draw.
    expect(
      await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf([...short, ...short]),
        beacon: beacon(4_100_100),
        exclude: [],
      }),
    ).toEqual({ ok: false, reason: "pool_below_switch" });

    const atSwitch = VALIDATORS.slice(0, TRUSTED_POOL_SWITCH);
    const result = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(atSwitch),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(result.ok).toBe(true);
    expectDrawInRange(result);
  });

  it("digests the whole pool, so exclusions cannot steer the draw", async () => {
    // src/assign.ts: the digest covers the published snapshot, never the
    // eligible subset, so a caller cannot move it by claiming a different
    // exclusion set. Who comes out may change; the commitment may not.
    const pool = VALIDATORS.slice(0, TRUSTED_POOL_SWITCH + 2);
    const wide = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(pool),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    if (!wide.ok) throw new Error("draw refused");

    let differing: string | null = null;
    for (const excluded of pool) {
      const narrow = await drawValidator({
        entryId: ENTRY_ID,
        snapshot: snapshotOf(pool),
        beacon: beacon(4_100_100),
        exclude: [excluded],
      });
      if (!narrow.ok) throw new Error("draw refused");
      expect(narrow.digest).toBe(wide.digest);
      expect(narrow.eligible).not.toContain(excluded);
      expectDrawInRange(narrow);
      if (narrow.operator !== wide.operator) differing = narrow.operator;
    }
    // The drawn operator does move under a different exclusion list; only the
    // digest stays put.
    expect(differing).not.toBeNull();
  });

  it("binds the digest to the entry id and the pool, not to the pool's order", async () => {
    const base = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(POOL),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(base.ok).toBe(true);
    if (!base.ok) throw new Error("draw refused");

    const otherEntry = await drawValidator({
      entryId: OTHER_ENTRY_ID,
      snapshot: snapshotOf(POOL),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    if (!otherEntry.ok) throw new Error("draw refused");
    expect(otherEntry.digest).not.toBe(base.digest);

    const otherPool = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf([...POOL, VALIDATORS[TRUSTED_POOL_SWITCH] as string]),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    if (!otherPool.ok) throw new Error("draw refused");
    expect(otherPool.digest).not.toBe(base.digest);

    const shuffled = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf([...POOL].reverse()),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    if (!shuffled.ok) throw new Error("draw refused");
    expect(shuffled.digest).toBe(base.digest);
    expect(shuffled.operator).toBe(base.operator);
    expect(base.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("de-duplicates the pool before drawing", async () => {
    const once = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf(POOL),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    const twice = await drawValidator({
      entryId: ENTRY_ID,
      snapshot: snapshotOf([...POOL, ...POOL]),
      beacon: beacon(4_100_100),
      exclude: [],
    });
    expect(twice).toEqual(once);
  });
});

describe("the window", () => {
  it("is exactly the policy window after the assignment", () => {
    const start = "2026-09-01T00:00:00.000Z";
    const deadline = assignmentDeadline(start);
    expect(Date.parse(deadline) - Date.parse(start)).toBe(
      ASSIGNMENT_WINDOW_HOURS * 3_600_000,
    );
    expect(deadline).toBe("2026-09-04T00:00:00.000Z");
  });

  it("is missed only strictly past the deadline", () => {
    const assignment = {
      seq: 0,
      agent: "1F916:agent-op_v1",
      operator: "op_v1",
      beacon_round: 4_100_100,
      deadline: "2026-09-04T00:00:00.000Z",
      replacement: false,
    };
    expect(
      isAssignmentMissed(assignment, { now: "2026-09-03T23:59:59.999Z" }),
    ).toBe(false);
    expect(
      isAssignmentMissed(assignment, { now: "2026-09-04T00:00:00.000Z" }),
    ).toBe(false);
    expect(
      isAssignmentMissed(assignment, { now: "2026-09-04T00:00:00.001Z" }),
    ).toBe(true);
  });
});

describe("latestPoolSnapshot", () => {
  it("reads the newest snapshot at or before a position", () => {
    const log = new Log();
    const first = log.add("pool_snapshot", null, { operators: ["op_v1"] });
    const second = log.add("pool_snapshot", null, {
      operators: ["op_v1", "op_v2"],
    });
    log.add("pool_snapshot", null, { operators: ["op_v3"] });

    expect(latestPoolSnapshot(log.events, first)?.operators).toEqual(["op_v1"]);
    expect(latestPoolSnapshot(log.events, second)?.operators).toEqual([
      "op_v1",
      "op_v2",
    ]);
    expect(latestPoolSnapshot([], 0)).toBeNull();
  });
});

describe("openAssignment", () => {
  function withAssignment(operator: string): Log {
    const log = new Log();
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom({ id: ENTRY_ID }),
      signature: SIGNATURE,
    });
    log.add("assignment", ENTRY_ID, {
      agent: `1F916:agent-${operator}`,
      operator,
      beacon_round: 4_100_100,
      deadline: "2026-09-04T00:00:00.000Z",
      replacement: false,
    });
    return log;
  }

  it("is null when nothing was assigned", () => {
    const log = new Log();
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom({ id: ENTRY_ID }),
      signature: SIGNATURE,
    });
    expect(openAssignment(log.events, ENTRY_ID)).toBeNull();
  });

  it("is the assignment while it stands", () => {
    const log = withAssignment("op_v1");
    expect(openAssignment(log.events, ENTRY_ID)).toEqual({
      seq: 1,
      agent: "1F916:agent-op_v1",
      operator: "op_v1",
      beacon_round: 4_100_100,
      deadline: "2026-09-04T00:00:00.000Z",
      replacement: false,
    });
  });

  it("is null once the assignment was missed", () => {
    const log = withAssignment("op_v1");
    log.add("assignment_missed", ENTRY_ID, {
      agent: "1F916:agent-op_v1",
      operator: "op_v1",
    });
    expect(openAssignment(log.events, ENTRY_ID)).toBeNull();
  });

  it("is null once the assigned operator validated", () => {
    const log = withAssignment("op_v1");
    log.add("validation", ENTRY_ID, {
      record: approve("op_v1", 1, true),
      signature: SIGNATURE,
    });
    expect(openAssignment(log.events, ENTRY_ID)).toBeNull();
  });

  it("stays open when someone else validates", () => {
    const log = withAssignment("op_v1");
    log.add("validation", ENTRY_ID, {
      record: approve("op_v2", 1),
      signature: SIGNATURE,
    });
    expect(openAssignment(log.events, ENTRY_ID)?.operator).toBe("op_v1");
  });

  it("takes the later assignment when one supersedes another", () => {
    const log = withAssignment("op_v1");
    log.add("assignment", ENTRY_ID, {
      agent: "1F916:agent-op_v2",
      operator: "op_v2",
      beacon_round: 4_100_101,
      deadline: "2026-09-05T00:00:00.000Z",
      replacement: true,
    });
    const open = openAssignment(log.events, ENTRY_ID);
    expect(open?.operator).toBe("op_v2");
    expect(open?.replacement).toBe(true);
  });

  it("ignores assignments on another entry", () => {
    const log = withAssignment("op_v1");
    log.add("assignment", OTHER_ENTRY_ID, {
      agent: "1F916:agent-op_v9",
      operator: "op_v9",
      beacon_round: 4_100_102,
      deadline: "2026-09-06T00:00:00.000Z",
      replacement: false,
    });
    expect(openAssignment(log.events, ENTRY_ID)?.operator).toBe("op_v1");
  });
});

describe("a missed deadline", () => {
  it("redraws without adding an approver", async () => {
    const CLOCK_BEFORE: Clock = { now: "2026-09-03T00:00:00.000Z" };
    const CLOCK_AFTER: Clock = { now: "2026-09-06T00:00:00.000Z" };

    // At least TRUSTED_POOL_SWITCH trusted operators: below the switch no draw
    // is made at all, so a redraw is only a question in the large pool.
    let events = await sealedLog(TRUSTED_POOL_SWITCH);
    await expectChainOk(events);

    const snapshot = latestPoolSnapshot(events, events.length - 1);
    expect(snapshot).not.toBeNull();
    if (snapshot === null) throw new Error("no pool snapshot");

    const firstDraw = await drawValidator({
      entryId: ENTRY_ID,
      snapshot,
      beacon: beacon(4_100_100),
      exclude: exclusionsFor(events, ENTRY_ID),
    });
    const missing = drawn(firstDraw);
    expect(missing).not.toBe(AUTHOR_OPERATOR);

    const assignedAt = "2026-09-01T00:00:00.000Z";
    events = await appendEvent(
      events,
      buildAssignment({
        entryId: ENTRY_ID,
        at: assignedAt,
        agent: `1F916:agent-${missing}`,
        operator: missing,
        beaconRound: 4_100_100,
        replacement: false,
      }),
    );

    const open = openAssignment(events, ENTRY_ID);
    expect(open).not.toBeNull();
    if (open === null) throw new Error("no open assignment");
    expect(open.deadline).toBe(assignmentDeadline(assignedAt));
    expect(isAssignmentMissed(open, CLOCK_BEFORE)).toBe(false);
    expect(isAssignmentMissed(open, CLOCK_AFTER)).toBe(true);

    events = await appendEvent(
      events,
      buildAssignmentMissed({
        entryId: ENTRY_ID,
        at: CLOCK_AFTER.now,
        assignment: open,
      }),
    );
    expect(openAssignment(events, ENTRY_ID)).toBeNull();

    const exclusions = exclusionsFor(events, ENTRY_ID);
    expect(exclusions).toContain(missing);
    expect(exclusions).toContain(AUTHOR_OPERATOR);

    const redraw = await drawValidator({
      entryId: ENTRY_ID,
      snapshot,
      beacon: beacon(4_100_101),
      exclude: exclusions,
    });
    const replacement = drawn(redraw);
    expect(replacement).not.toBe(missing);

    events = await appendEvent(
      events,
      buildAssignment({
        entryId: ENTRY_ID,
        at: CLOCK_AFTER.now,
        agent: `1F916:agent-${replacement}`,
        operator: replacement,
        beaconRound: 4_100_101,
        replacement: true,
      }),
    );
    expect(openAssignment(events, ENTRY_ID)?.operator).toBe(replacement);

    // The miss costs standing; it never counts as a decision.
    const derived = deriveEntry(events, ENTRY_ID, CLOCK_AFTER);
    expect(derived.derived.status).toBe("draft");
    expect(derived.entry["approvers"]).toEqual([]);

    await expectChainOk(events);
  });
});

describe("the replacement draw on a 2-1 split", () => {
  const CLOCK: Clock = { now: "2026-09-10T00:00:00.000Z" };

  /** The large-pool log at the split: two approvals against one rejection. */
  async function splitLog(): Promise<{
    events: Event[];
    signers: readonly string[];
  }> {
    let events = await sealedLog(TRUSTED_POOL_SWITCH);
    const signers = VALIDATORS.slice(0, 3);
    const records = [
      approve(signers[0] as string, 1, true),
      approve(signers[1] as string, 2),
      reject(signers[2] as string, 3),
    ];
    let index = 100;
    for (const record of records) {
      events = await appendEvent(events, {
        at: at(index++),
        type: "validation",
        entry_id: ENTRY_ID,
        payload: { record, signature: SIGNATURE },
      });
    }
    return { events, signers };
  }

  /** The split, the exclusions, and the replacement assignment appended. */
  async function assignReplacement(): Promise<{
    events: Event[];
    replacement: string;
    signers: readonly string[];
  }> {
    const { events: split, signers } = await splitLog();

    const derived = deriveEntry(split, ENTRY_ID, CLOCK);
    expect(derived.sidecar.needs_replacement).toBe(true);
    expect(derived.derived.status).toBe("draft");

    const exclusions = exclusionsFor(split, ENTRY_ID);
    expect(exclusions).toEqual([AUTHOR_OPERATOR, ...signers].sort());

    const snapshot = latestPoolSnapshot(split, split.length - 1);
    if (snapshot === null) throw new Error("no pool snapshot");
    const draw = await drawValidator({
      entryId: ENTRY_ID,
      snapshot,
      beacon: beacon(4_100_200),
      exclude: exclusions,
    });
    const replacement = drawn(draw);
    for (const excluded of exclusions) {
      expect(replacement).not.toBe(excluded);
    }
    expectDrawInRange(draw);

    const events = await appendEvent(
      split,
      buildAssignment({
        entryId: ENTRY_ID,
        at: at(200),
        agent: `1F916:agent-${replacement}`,
        operator: replacement,
        beaconRound: 4_100_200,
        replacement: true,
      }),
    );
    expect(openAssignment(events, ENTRY_ID)?.replacement).toBe(true);
    await expectChainOk(events);
    return { events, replacement, signers };
  }

  it("completes the third approval when the replacement approves", async () => {
    const { events: assigned, replacement } = await assignReplacement();
    const events = await appendEvent(assigned, {
      at: at(210),
      type: "validation",
      entry_id: ENTRY_ID,
      payload: { record: approve(replacement, 4, true), signature: SIGNATURE },
    });
    await expectChainOk(events);

    expect(openAssignment(events, ENTRY_ID)).toBeNull();
    const derived = deriveEntry(events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.sidecar.needs_replacement).toBe(false);
  });

  it("lands the second rejection when the replacement rejects", async () => {
    const { events: assigned, replacement } = await assignReplacement();
    const events = await appendEvent(assigned, {
      at: at(210),
      type: "validation",
      entry_id: ENTRY_ID,
      // The replacement holds the open assignment, so its record signs
      // assigned_random true: checkValidation refuses a false one with
      // assignment_without_assigned_random. The verdict is still a rejection.
      payload: { record: reject(replacement, 4, true), signature: SIGNATURE },
    });
    await expectChainOk(events);

    expect(openAssignment(events, ENTRY_ID)).toBeNull();
    const derived = deriveEntry(events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("rejected");
    expect(derived.sidecar.needs_replacement).toBe(false);
  });
});

/**
 * The sweep rules: what the log owes before a draw can be made, and whether a
 * draw is owed at all. Both are pure functions of the events, so the same log
 * always gives the same verdict, and both take the registry events beside the
 * entry's own because the pool lives in the registry.
 */
describe("poolSnapshotDue", () => {
  /** A log holding `trusted` trusted operators and nothing else. */
  function trustedLog(operators: readonly string[]): Log {
    const log = new Log();
    for (const operator of operators) {
      log.add("operator_trusted", null, { operator });
    }
    return log;
  }

  it("owes the whole pool when the log holds no snapshot yet", () => {
    const log = trustedLog(["op_v2", "op_v1"]);
    expect(poolSnapshotDue(log.events)).toEqual(["op_v1", "op_v2"]);
  });

  it("owes nothing once the sealed snapshot says what the pool says", () => {
    const log = trustedLog(["op_v2", "op_v1"]);
    log.add("pool_snapshot", null, { operators: ["op_v1", "op_v2"] });
    expect(poolSnapshotDue(log.events)).toBeNull();
  });

  it("owes nothing when the sealed snapshot differs only in order or repeats", () => {
    const log = trustedLog(["op_v1", "op_v2"]);
    log.add("pool_snapshot", null, {
      operators: ["op_v2", "op_v1", "op_v1"],
    });
    expect(poolSnapshotDue(log.events)).toBeNull();
  });

  it("owes a new snapshot when an operator joins the pool", () => {
    const log = trustedLog(["op_v1", "op_v2"]);
    log.add("pool_snapshot", null, { operators: ["op_v1", "op_v2"] });
    log.add("operator_trusted", null, { operator: "op_v3" });
    expect(poolSnapshotDue(log.events)).toEqual(["op_v1", "op_v2", "op_v3"]);
  });

  it("owes a new snapshot when an operator leaves the pool", () => {
    const log = trustedLog(["op_v1", "op_v2"]);
    log.add("pool_snapshot", null, { operators: ["op_v1", "op_v2"] });
    log.add("operator_untrusted", null, { operator: "op_v2" });
    expect(poolSnapshotDue(log.events)).toEqual(["op_v1"]);
  });

  it("owes an empty snapshot when the last operator leaves", () => {
    const log = trustedLog(["op_v1"]);
    log.add("pool_snapshot", null, { operators: ["op_v1"] });
    log.add("operator_untrusted", null, { operator: "op_v1" });
    // Empty, not null: an operator leaving is as much a change as one joining,
    // and a log still naming them would let a draw pick an untrusted operator.
    expect(poolSnapshotDue(log.events)).toEqual([]);
  });

  it("reads the newest snapshot, not the first", () => {
    const log = trustedLog(["op_v1", "op_v2"]);
    log.add("pool_snapshot", null, { operators: ["op_v1"] });
    log.add("pool_snapshot", null, { operators: ["op_v1", "op_v2"] });
    expect(poolSnapshotDue(log.events)).toBeNull();
  });

  it("gives the same answer whatever order the events arrive in", () => {
    const log = trustedLog(["op_v1", "op_v2"]);
    log.add("pool_snapshot", null, { operators: ["op_v1"] });
    log.add("operator_trusted", null, { operator: "op_v3" });
    const forwards = poolSnapshotDue(log.events);
    const backwards = poolSnapshotDue([...log.events].reverse());
    expect(forwards).toEqual(["op_v1", "op_v2", "op_v3"]);
    expect(backwards).toEqual(forwards);
  });

  it("owes an empty snapshot on an empty log, and never throws", () => {
    expect(poolSnapshotDue([])).toEqual([]);
  });
});

describe("drawDue", () => {
  const ASSIGNED = VALIDATORS[0] as string;

  /**
   * A log with `trusted` trusted operators, a snapshot of them, and the entry
   * submitted. The draw only runs at or above the switch, so `trusted` is what
   * every case below moves to reach or miss it.
   */
  function poolLog(trusted: number): Log {
    const pool = VALIDATORS.slice(0, trusted);
    const log = new Log();
    for (const operator of pool) {
      log.add("operator_trusted", null, { operator });
    }
    log.add("pool_snapshot", null, { operators: [...pool].sort() });
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom({ id: ENTRY_ID }),
      signature: SIGNATURE,
    });
    return log;
  }

  function assign(log: Log, operator: string, replacement = false): number {
    return log.add("assignment", ENTRY_ID, {
      agent: `1F916:agent-${operator}`,
      operator,
      beacon_round: 4_100_100,
      deadline: "2026-09-04T00:00:00.000Z",
      replacement,
    });
  }

  function due(
    log: Log,
    overrides: { status?: string; needsReplacement?: boolean } = {},
  ): DrawDueVerdict {
    return drawDue({
      events: log.events,
      entryId: ENTRY_ID,
      status: (overrides.status ?? "draft") as "draft",
      needsReplacement: overrides.needsReplacement ?? false,
    });
  }

  it("is not due once the entry has left draft", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    for (const status of ["verified", "rejected", "superseded", "overturned"]) {
      expect(due(log, { status })).toEqual({ due: false, reason: "not_draft" });
    }
  });

  it("is not due under the switch, and is due at it", () => {
    // Nine trusted operators: "Until the pool holds ten operators, two
    // approvals verify ... and there is no replacement draw".
    expect(due(poolLog(TRUSTED_POOL_SWITCH - 1))).toEqual({
      due: false,
      reason: "pool_below_switch",
    });
    expect(due(poolLog(TRUSTED_POOL_SWITCH))).toEqual({
      due: true,
      replacement: false,
    });
  });

  it("is the first draw when nothing was ever assigned", () => {
    expect(due(poolLog(TRUSTED_POOL_SWITCH))).toEqual({
      due: true,
      replacement: false,
    });
  });

  it("is not due while an assignment stands", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    expect(due(log)).toEqual({ due: false, reason: "assignment_open" });
  });

  it("is a replacement once the assignment was missed", () => {
    // "A miss costs standing, and the next beacon round draws a replacement."
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    log.add("assignment_missed", ENTRY_ID, {
      agent: `1F916:agent-${ASSIGNED}`,
      operator: ASSIGNED,
    });
    expect(due(log)).toEqual({ due: true, replacement: true });
  });

  it("is a replacement when the split calls for one after the assigned validator answered", () => {
    // "two approvals against one rejection draw one replacement validator by
    // the same public randomness".
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    log.add("validation", ENTRY_ID, {
      record: reject(ASSIGNED, 1, true),
      signature: SIGNATURE,
    });
    expect(due(log, { needsReplacement: true })).toEqual({
      due: true,
      replacement: true,
    });
  });

  it("is not due when the answered assignment left no split to resolve", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    log.add("validation", ENTRY_ID, {
      record: approve(ASSIGNED, 1, true),
      signature: SIGNATURE,
    });
    expect(due(log, { needsReplacement: false })).toEqual({
      due: false,
      reason: "awaiting_volunteers",
    });
  });

  it("is not due again once the replacement was drawn", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    log.add("validation", ENTRY_ID, {
      record: reject(ASSIGNED, 1, true),
      signature: SIGNATURE,
    });
    assign(log, VALIDATORS[1] as string, true);
    expect(due(log, { needsReplacement: true })).toEqual({
      due: false,
      reason: "assignment_open",
    });
  });

  it("ignores an assignment on another entry", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    log.add("assignment", OTHER_ENTRY_ID, {
      agent: `1F916:agent-${ASSIGNED}`,
      operator: ASSIGNED,
      beacon_round: 4_100_100,
      deadline: "2026-09-04T00:00:00.000Z",
      replacement: false,
    });
    expect(due(log)).toEqual({ due: true, replacement: false });
  });

  it("gives the same verdict whatever order the events arrive in", () => {
    const log = poolLog(TRUSTED_POOL_SWITCH);
    assign(log, ASSIGNED);
    log.add("assignment_missed", ENTRY_ID, {
      agent: `1F916:agent-${ASSIGNED}`,
      operator: ASSIGNED,
    });
    const forwards = drawDue({
      events: log.events,
      entryId: ENTRY_ID,
      status: "draft",
      needsReplacement: false,
    });
    const backwards = drawDue({
      events: [...log.events].reverse(),
      entryId: ENTRY_ID,
      status: "draft",
      needsReplacement: false,
    });
    expect(forwards).toEqual({ due: true, replacement: true });
    expect(backwards).toEqual(forwards);
  });

  it("never throws on an empty log", () => {
    expect(
      drawDue({
        events: [],
        entryId: ENTRY_ID,
        status: "draft",
        needsReplacement: false,
      }),
    ).toEqual({ due: false, reason: "pool_below_switch" });
  });
});

describe("the kernel barrel", () => {
  it("re-exports the sweep rules", async () => {
    const kernel = (await import("../src/index.js")) as Record<string, unknown>;
    expect(typeof kernel["poolSnapshotDue"]).toBe("function");
    expect(typeof kernel["drawDue"]).toBe("function");
    // Storage and the adapters stay out of the kernel barrel.
    expect(kernel["DrandReader"]).toBeUndefined();
    expect(kernel["dueAssignments"]).toBeUndefined();
  });
});

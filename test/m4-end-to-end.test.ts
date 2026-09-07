/**
 * The M4 surface as a consumer sees it: who may validate (src/validate.ts) and
 * who is drawn to (src/assign.ts), joined onto the M3 log. Everything below is
 * imported from the package entry point, so a missing re-export fails here
 * rather than in a later milestone.
 *
 * The path is the large-pool one: ten trusted operators, two volunteers, a
 * beacon draw for the third, and checkValidation standing at the door in front
 * of every validation event. Nothing is appended that the check refused, so the
 * log only ever holds records the rules accept; derivation then recomputes the
 * status from those events, and the chain still verifies at the end.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  appendEvent,
  buildAssignment,
  checkValidation,
  deriveEntry,
  drawValidator,
  exclusionsFor,
  extractCore,
  latestPoolSnapshot,
  openAssignment,
  TRUSTED_POOL_SWITCH,
  verifyChain,
  type ApproverRecord,
  type Beacon,
  type Clock,
  type Core,
  type Event,
  type OperatorInfo,
  type ValidationContext,
} from "../src/index.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = example["id"] as string;
const SIGNATURE = example["signature"] as string;
const HASH = example["snapshot_hash"] as string;
const SUBMITTER_AGENT = example["author"] as string;
const SUBMITTER_OPERATOR = example["author_operator"] as string;

const MAINTAINER = "op_maintainer";
/** The trusted pool: exactly the switch, none of them the maintainer's. */
const POOL = Array.from(
  { length: TRUSTED_POOL_SWITCH },
  (_, index) => `op_pool${index + 1}`,
);

/** The fake clock. Nothing in this test reads a wall clock. */
const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/** A fixture beacon, its round sealed after the snapshot it draws over. */
const BEACON: Beacon = {
  round: 4_100_100,
  randomness: `${"7c1f".repeat(15)}3`,
  at: "2026-09-02T00:00:00.000Z",
};

/** Sequential event timestamps, from the same fake clock. */
function at(index: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + index * 60_000,
  ).toISOString();
}

/** One agent per operator, plus the submitter's own. */
function agentFor(operator: string): string {
  return `1F916:agent-${operator}`;
}

/** The registry's agent -> operator map at this point in the log. */
const AGENT_OPERATORS: Readonly<Record<string, string>> = Object.freeze({
  ...Object.fromEntries(POOL.map((operator) => [agentFor(operator), operator])),
  [agentFor(MAINTAINER)]: MAINTAINER,
  [agentFor(SUBMITTER_OPERATOR)]: SUBMITTER_OPERATOR,
  [SUBMITTER_AGENT]: SUBMITTER_OPERATOR,
});

/** The registry's operators, none of them a model provider. */
const OPERATORS: Readonly<Record<string, OperatorInfo>> = Object.freeze({
  ...Object.fromEntries(
    POOL.map((operator) => [operator, { maintainer: false, provider: false }]),
  ),
  [MAINTAINER]: { maintainer: true, provider: false },
  [SUBMITTER_OPERATOR]: { maintainer: false, provider: false },
});

function record(
  operator: string,
  outcome: "approve" | "reject",
  index: number,
  assignedRandom: boolean,
  agent: string = agentFor(operator),
): ApproverRecord {
  return {
    agent,
    operator,
    decision: outcome,
    reason: outcome === "reject" ? "the source does not say this" : null,
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
  record(operator, "approve", index, assignedRandom);

/**
 * The log the whole test runs on: the maintainer and the submitter's operator
 * registered, ten more registered and trusted, a snapshot of the trusted pool,
 * and the example's core sealed as the submission.
 */
async function buildLog(): Promise<Event[]> {
  const core: Core = extractCore(example);
  let events: Event[] = [];
  let index = 0;
  const append = async (
    type: Parameters<typeof appendEvent>[1]["type"],
    entryId: string | null,
    payload: Parameters<typeof appendEvent>[1]["payload"],
  ) => {
    events = await appendEvent(events, {
      at: at(index),
      type,
      entry_id: entryId,
      payload,
    });
    index += 1;
  };

  await append("operator_registered", null, {
    operator: MAINTAINER,
    maintainer: true,
  });
  await append("operator_registered", null, {
    operator: SUBMITTER_OPERATOR,
    maintainer: false,
  });
  for (const operator of POOL) {
    await append("operator_registered", null, { operator, maintainer: false });
  }
  for (const operator of POOL) {
    await append("operator_trusted", null, { operator });
  }
  await append("pool_snapshot", null, { operators: [...POOL].sort() });
  await append("entry_submitted", ENTRY_ID, { core, signature: SIGNATURE });
  return events;
}

/**
 * The context checkValidation reads, gathered from the log at its end: the
 * submitter from the core, the decisions already on the entry, and whatever
 * assignment is open right now.
 */
function contextFor(events: readonly Event[]): ValidationContext {
  const priorRecords: ApproverRecord[] = [];
  for (const event of events) {
    if (event.type !== "validation") continue;
    if (event.entry_id !== ENTRY_ID) continue;
    priorRecords.push((event as Event<"validation">).payload.record);
  }
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR },
    agentOperators: AGENT_OPERATORS,
    operators: OPERATORS,
    priorRecords,
    openAssignment: openAssignment(events, ENTRY_ID),
  };
}

/** Gate a record, then append it only if the check accepted it. */
async function gateAndAppend(
  events: readonly Event[],
  candidate: ApproverRecord,
  index: number,
): Promise<Event[]> {
  const verdict = checkValidation(candidate, contextFor(events));
  expect(verdict.ok ? null : verdict.reason).toBeNull();
  if (!verdict.ok) throw new Error(`refused: ${verdict.reason}`);
  return appendEvent(events, {
    at: at(index),
    type: "validation",
    entry_id: ENTRY_ID,
    payload: { record: verdict.record, signature: SIGNATURE },
  });
}

/** The reason a record was refused, for a record that must be refused. */
function refusalFor(
  events: readonly Event[],
  candidate: ApproverRecord,
): string {
  const verdict = checkValidation(candidate, contextFor(events));
  expect(verdict.ok).toBe(false);
  if (verdict.ok) throw new Error("expected a refusal");
  return verdict.reason;
}

describe("M4 end to end: the gate and the draw over one sealed log", () => {
  it("verifies through two volunteers and a beacon-drawn third", async () => {
    let events = await buildLog();
    await expectChainOk(events);

    // Two volunteers. Neither holds an assignment, so both sign
    // assigned_random false, and each carries its own snapshot hash.
    events = await gateAndAppend(events, approve(POOL[0] as string, 1), 100);
    events = await gateAndAppend(events, approve(POOL[1] as string, 2), 101);
    expect(deriveEntry(events, ENTRY_ID, CLOCK).derived.status).toBe("draft");

    // The third is drawn, over the snapshot as it stands and a beacon round
    // sealed after it, skipping the submitter and everyone who already signed.
    const snapshot = latestPoolSnapshot(events, events.length - 1);
    if (snapshot === null) throw new Error("no pool snapshot");
    const exclusions = exclusionsFor(events, ENTRY_ID);
    expect(exclusions).toContain(SUBMITTER_OPERATOR);
    expect(exclusions).toContain(POOL[0]);
    expect(exclusions).toContain(POOL[1]);

    const draw = await drawValidator({
      entryId: ENTRY_ID,
      snapshot,
      beacon: BEACON,
      exclude: exclusions,
    });
    expect(draw.ok).toBe(true);
    if (!draw.ok) throw new Error("draw refused");
    expect(draw.eligible).toContain(draw.operator);
    expect(draw.eligible[draw.index]).toBe(draw.operator);
    for (const excluded of exclusions) {
      expect(draw.operator).not.toBe(excluded);
    }

    const assigned = draw.operator;
    events = await appendEvent(
      events,
      buildAssignment({
        entryId: ENTRY_ID,
        at: at(102),
        agent: agentFor(assigned),
        operator: assigned,
        beaconRound: BEACON.round,
        replacement: false,
      }),
    );
    expect(openAssignment(events, ENTRY_ID)?.operator).toBe(assigned);

    // The flag has to match the log, in both directions. Neither of these ever
    // reaches the log.
    expect(refusalFor(events, approve(assigned, 3, false))).toBe(
      "assignment_without_assigned_random",
    );
    expect(refusalFor(events, approve(POOL[2] as string, 3, true))).toBe(
      "assigned_random_without_assignment",
    );

    // The assigned operator's own approval, signed as the draw says.
    events = await gateAndAppend(events, approve(assigned, 4, true), 103);
    expect(openAssignment(events, ENTRY_ID)).toBeNull();

    const derived = deriveEntry(events, ENTRY_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.sidecar.trusted_count_at_decision).toBeGreaterThanOrEqual(
      TRUSTED_POOL_SWITCH,
    );

    // One signature per operator per entry: a second record from an operator
    // that already signed is refused, whatever it decides.
    expect(refusalFor(events, approve(POOL[0] as string, 5))).toBe(
      "duplicate_operator",
    );

    await expectChainOk(events);
  });

  it("refuses the submitter's own operator and the maintainer's", async () => {
    const events = await buildLog();

    // A second agent under the submitter's operator: not the submitter's own
    // agent, so this is the operator rule and not the agent one.
    const sibling = agentFor(SUBMITTER_OPERATOR);
    expect(sibling).not.toBe(SUBMITTER_AGENT);
    expect(
      refusalFor(
        events,
        record(SUBMITTER_OPERATOR, "approve", 1, false, sibling),
      ),
    ).toBe("submitter_operator");

    expect(refusalFor(events, approve(MAINTAINER, 1))).toBe(
      "maintainer_operator",
    );
  });
});

async function expectChainOk(events: readonly Event[]): Promise<void> {
  expect(await verifyChain(events)).toEqual({ ok: true, length: events.length });
}

/**
 * The M5 surface as an application composes it: the evidence rules
 * (src/evidence.ts) standing beside M4's gate at the door, over the M3 log.
 * Everything below is imported from the package entry point, so a missing
 * re-export fails here rather than in a later milestone.
 *
 * The story is the small-pool one: three registered, trusted outside operators
 * and the submitter's own, no maintainer in the way. At submit the core's
 * evidence is checked; at every validation both checkValidation and
 * checkRecordEvidence are asked, and nothing either one refuses is ever
 * appended. Derivation then recomputes the status and the tier from the events,
 * and the chain still verifies at the end.
 */

import { describe, expect, it } from "vitest";

import {
  APPROVALS_TO_VERIFY_SMALL_POOL,
  appendEvent,
  checkCoreEvidence,
  checkRecordEvidence,
  checkValidation,
  deriveEntry,
  NO_PREDICATE,
  openAssignment,
  REJECTIONS_TO_REJECT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  verifyChain,
  type ApproverRecord,
  type Clock,
  type Core,
  type Event,
  type OperatorInfo,
  type ValidationContext,
} from "../src/index.js";

const SUBMITTER_AGENT = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const SUBMITTER_OPERATOR = "op_brightloop";
const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const HASH =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";
const RECEIPT =
  "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdefabcdef";
const CITATION = "https://platform.openai.com/docs/pricing";

/** The small pool: three trusted outside operators, and no maintainer at all. */
const POOL = ["op_northgate", "op_cindermill", "op_dryfield"] as const;

/** The fake clock. Nothing in this test reads a wall clock. */
const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

const PRICING_ID = "nmk_01M5PRICE";
const BEHAVIOR_ID = "nmk_01M5BEHAV";

/** Sequential event timestamps, from the same fake clock. */
function at(index: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + index * 60_000,
  ).toISOString();
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
}

/** One agent per operator, plus the submitter's own. */
function agentFor(operator: string): string {
  return `1F916:agent-${operator}`;
}

/** The registry's agent -> operator map at this point in the log. */
const AGENT_OPERATORS: Readonly<Record<string, string>> = Object.freeze({
  ...Object.fromEntries(POOL.map((operator) => [agentFor(operator), operator])),
  [SUBMITTER_AGENT]: SUBMITTER_OPERATOR,
});

/** The registry's operators, none of them a maintainer or a model provider. */
const OPERATORS: Readonly<Record<string, OperatorInfo>> = Object.freeze({
  ...Object.fromEntries(
    POOL.map((operator) => [operator, { maintainer: false, provider: false }]),
  ),
  [SUBMITTER_OPERATOR]: { maintainer: false, provider: false },
});

/** The seventeen core keys, in the schema's own names. */
function core(overrides: Record<string, unknown>): Core {
  return {
    id: PRICING_ID,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-08-15",
    evidence_tier: "observed",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: SUBMITTER_AGENT,
    author_operator: SUBMITTER_OPERATOR,
    submitted_at: "2026-09-01T14:05:00Z",
    ...overrides,
  } as Core;
}

/** The observed pricing entry: its proposed test frozen in `observation`. */
function pricingCore(): Core {
  return core({
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
 * The behavior entry: always observed, the predicate frozen in `evidence`
 * beside the transcript. `provider_statement` is null here, so nothing but a
 * reproduction could earn it the observed badge.
 */
function behaviorCore(providerStatement: string | null): Core {
  return core({
    id: BEHAVIOR_ID,
    category: "behavior",
    claim: "gpt-5 refuses the frozen prompt",
    before: "answers the prompt",
    after: "refuses the prompt",
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

function decisionFor(
  operator: string,
  outcome: "approve" | "reject",
  index: number,
  extra: Record<string, unknown> = {},
): ApproverRecord {
  return {
    agent: agentFor(operator),
    operator,
    decision: outcome,
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

/** An approval that ran the frozen test and reports its own n-of-k counts. */
const observing = (operator: string, index: number, holds: number) =>
  decisionFor(operator, "approve", index, { observation: measured(holds) });

/** The registrations and trust the whole story runs on. */
async function buildLog(): Promise<Event[]> {
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
    operator: SUBMITTER_OPERATOR,
    maintainer: false,
  });
  for (const operator of POOL) {
    await append("operator_registered", null, { operator, maintainer: false });
    await append("operator_trusted", null, { operator });
  }
  return events;
}

/** Seal a submission, once its core's evidence has been checked. */
async function submit(
  events: readonly Event[],
  submitted: Core,
  index: number,
): Promise<Event[]> {
  const verdict = checkCoreEvidence(submitted);
  expect(verdict.ok ? null : verdict.reason).toBeNull();
  return appendEvent(events, {
    at: at(index),
    type: "entry_submitted",
    entry_id: submitted["id"] as string,
    payload: { core: submitted, signature: SIGNATURE },
  });
}

/** The context M4's check reads, gathered from the log as it stands. */
function contextFor(
  events: readonly Event[],
  entryId: string,
): ValidationContext {
  const priorRecords: ApproverRecord[] = [];
  for (const event of events) {
    if (event.type !== "validation") continue;
    if (event.entry_id !== entryId) continue;
    priorRecords.push((event as Event<"validation">).payload.record);
  }
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: SUBMITTER_OPERATOR },
    agentOperators: AGENT_OPERATORS,
    operators: OPERATORS,
    priorRecords,
    openAssignment: openAssignment(events, entryId),
  };
}

/** Both door checks, in the order an application asks them. */
function doorFor(
  events: readonly Event[],
  entryId: string,
  submitted: Core,
  candidate: ApproverRecord,
): { ok: true; record: ApproverRecord } | { ok: false; reason: string } {
  const validation = checkValidation(candidate, contextFor(events, entryId));
  if (!validation.ok) return { ok: false, reason: validation.reason };
  const evidence = checkRecordEvidence(validation.record, submitted);
  if (!evidence.ok) return { ok: false, reason: evidence.reason };
  return { ok: true, record: evidence.record };
}

/** Gate a record through both checks, then append only what both accepted. */
async function gateAndAppend(
  events: readonly Event[],
  entryId: string,
  submitted: Core,
  candidate: ApproverRecord,
  index: number,
): Promise<Event[]> {
  const verdict = doorFor(events, entryId, submitted, candidate);
  expect(verdict.ok ? null : verdict.reason).toBeNull();
  if (!verdict.ok) throw new Error(`refused: ${verdict.reason}`);
  return appendEvent(events, {
    at: at(index),
    type: "validation",
    entry_id: entryId,
    payload: { record: verdict.record, signature: SIGNATURE },
  });
}

/** The reason a record was refused, for a record that must be refused. */
function refusalFor(
  events: readonly Event[],
  entryId: string,
  submitted: Core,
  candidate: ApproverRecord,
): string {
  const verdict = doorFor(events, entryId, submitted, candidate);
  expect(verdict.ok).toBe(false);
  if (verdict.ok) throw new Error("expected a refusal");
  return verdict.reason;
}

function validationCount(events: readonly Event[], entryId: string): number {
  return events.filter(
    (event) => event.type === "validation" && event.entry_id === entryId,
  ).length;
}

async function expectChainOk(events: readonly Event[]): Promise<void> {
  expect(await verifyChain(events)).toEqual({ ok: true, length: events.length });
}

describe("M5 end to end: the evidence rules over one sealed log", () => {
  it("runs the small pool it says it does", () => {
    expect(POOL.length).toBeLessThan(TRUSTED_POOL_SWITCH);
    expect(POOL.length).toBeGreaterThanOrEqual(
      VERIFICATION_MIN_OUTSIDE_OPERATORS,
    );
  });

  it("refuses a core whose provider statement is not the entry's citation", () => {
    const wrong = behaviorCore("https://example.invalid/some-other-page");
    const verdict = checkCoreEvidence(wrong);
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error("expected a refusal");
    expect(verdict.reason).toBe("provider_statement_mismatch");

    // Corrected: the statement is the citation itself, and the core passes.
    expect(checkCoreEvidence(behaviorCore(CITATION))).toEqual({ ok: true });
    // As does the same core with no provider statement at all.
    expect(checkCoreEvidence(behaviorCore(null))).toEqual({ ok: true });
  });

  it("verifies an observed pricing entry as observed, both doors asked", async () => {
    const submitted = pricingCore();
    let events = await submit(await buildLog(), submitted, 100);
    await expectChainOk(events);

    // A record with no judgment of the proposed test at all: M4 has nothing
    // against it, and the evidence rule turns it away.
    expect(
      refusalFor(
        events,
        PRICING_ID,
        submitted,
        decisionFor(POOL[0], "approve", 1, {
          test_accepted: null,
          observation: measured(REPRODUCTION_HOLDS),
        }),
      ),
    ).toBe("missing_test_accepted");

    // An approval that accepted the test and brought no measurement of its own.
    expect(
      refusalFor(
        events,
        PRICING_ID,
        submitted,
        decisionFor(POOL[0], "approve", 1),
      ),
    ).toBe("missing_observation");

    // Neither reached the log.
    expect(validationCount(events, PRICING_ID)).toBe(0);

    // Two approvals that ran the test at the policy's n, holding at its k.
    events = await gateAndAppend(
      events,
      PRICING_ID,
      submitted,
      observing(POOL[0], 1, REPRODUCTION_HOLDS),
      101,
    );
    expect(deriveEntry(events, PRICING_ID, CLOCK).derived.status).toBe("draft");

    events = await gateAndAppend(
      events,
      PRICING_ID,
      submitted,
      observing(POOL[1], 2, REPRODUCTION_HOLDS),
      102,
    );

    const derived = deriveEntry(events, PRICING_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.verified_at).toBe(signedAt(2));
    expect(derived.sidecar.effective_tier).toBe("observed");
    expect(derived.sidecar.test_verdict).toBe("accepted");
    expect(validationCount(events, PRICING_ID)).toBe(
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );

    await expectChainOk(events);
  });

  it("rejects a behavior entry whose validators find no predicate to run", async () => {
    const submitted = behaviorCore(null);
    let events = await submit(await buildLog(), submitted, 200);

    // Both validators judge that the frozen predicate does not decide the
    // claim, and reject on that ground (D-031: the judgment is theirs). Both
    // records pass both doors; it is the decisions, not the shapes, that reject.
    const rejectors = POOL.slice(0, REJECTIONS_TO_REJECT);
    for (let position = 0; position < rejectors.length; position += 1) {
      events = await gateAndAppend(
        events,
        BEHAVIOR_ID,
        submitted,
        decisionFor(rejectors[position] as string, "reject", position + 1, {
          reason: NO_PREDICATE,
          test_accepted: false,
        }),
        201 + position,
      );
    }

    const derived = deriveEntry(events, BEHAVIOR_ID, CLOCK);
    expect(derived.derived.status).toBe("rejected");
    expect(derived.derived.verified_at).toBeNull();
    expect(derived.sidecar.effective_tier).toBeNull();
    expect(derived.sidecar.test_verdict).toBeNull();

    await expectChainOk(events);
  });
});

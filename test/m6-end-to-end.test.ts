/**
 * The M6 surface as an application composes it: the supersession link check
 * (src/supersede.ts) at the submit door and the reconfirmation check
 * (src/reconfirm.ts) at the revalidate door, over the M3 log, with derivation
 * recomputing every consequence. Everything below is imported from the package
 * entry point, so a missing re-export fails here rather than in a later
 * milestone.
 *
 * The story is the large-pool one: ten trusted operators, so three approvals
 * verify and one of them is the beacon-drawn validator. The submitter's own
 * operator and one outsider are registered but never trusted, because both
 * exclusions have to be visible from the door.
 *
 * Nothing a check refuses is ever appended, and the context each check reads is
 * gathered from derived data — deriveEntry for the status and the effective
 * tier, trustedOperatorsAt for the pool — which is the composition a real
 * application makes.
 */

import { describe, expect, it } from "vitest";

import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  SLOT_COUNT,
  DEFAULT_DOMAIN,
  stalenessWindowDays,
  TRUSTED_POOL_SWITCH,
  appendEvent,
  checkReconfirmation,
  checkSupersedes,
  deriveEntry,
  trustedOperatorsAt,
  verifyChain,
  type ApproverRecord,
  type Clock,
  type Core,
  type Event,
  type ReadShareSlot,
  type ReconfirmationContext,
  type ReconfirmationRecord,
} from "../src/index.js";

const SUBMITTER_AGENT = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
/** A second agent under the submitter's own operator: Section 6 counts them as one. */
const SIBLING_AGENT = "1F916:c2libGluZ0FnZW50VW5kZXJUaGVTdWJtaXR0ZXI";
/** Registered, but its operator was never trusted. */
const OUTSIDER_AGENT = "1F916:b3V0c2lkZXJBZ2VudE5vdEluVGhlUG9vbA";

const SUBMITTER_OPERATOR = "op_brightloop";
const OUTSIDER_OPERATOR = "op_farhaven";

const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const HASH =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";
const CITATION = "https://platform.openai.com/docs/pricing";

/** The large pool: exactly the switch, so the three-approval rules apply. */
const POOL: readonly string[] = Array.from(
  { length: TRUSTED_POOL_SWITCH },
  (_, index) => `op_pool${index + 1}`,
);

/** The fourth trusted operator: it holds no slot, so its reconfirmation rotates. */
const RECONFIRMER = POOL[APPROVALS_TO_VERIFY_LARGE_POOL]!;

const OLD_ID = "nmk_01M6OLD";
const NEW_ID = "nmk_01M6NEW";
const STALE_ID = "nmk_01M6STALE";
const BEHAVIOR_ID = "nmk_01M6BEHAV";
const DRAFT_ID = "nmk_01M6DRAFT";
const ABSENT_ID = "nmk_01M6ABSENT";

const SUBMITTED_AT = "2026-09-01T14:05:00Z";
const RECONFIRMED_AT = "2026-12-10T09:00:00Z";
const RECONFIRMED_DATE = "2026-12-10";

/**
 * The fake clock. Nothing in this test reads a wall clock. Past the pricing
 * window from SUBMITTED_AT, so a pricing entry nobody has reconfirmed is stale.
 */
const CLOCK: Clock = { now: "2026-12-15T00:00:00Z" };

/** One agent per pool operator, plus the submitter's own and the outsider's. */
function agentFor(operator: string): string {
  return `1F916:agent-${operator}`;
}

/** The registry's agent -> operator map at every point in this log. */
const AGENT_OPERATORS: Readonly<Record<string, string>> = Object.freeze({
  ...Object.fromEntries(POOL.map((operator) => [agentFor(operator), operator])),
  [SUBMITTER_AGENT]: SUBMITTER_OPERATOR,
  [SIBLING_AGENT]: SUBMITTER_OPERATOR,
  [OUTSIDER_AGENT]: OUTSIDER_OPERATOR,
});

/** Sequential event timestamps, from the same fake clock. */
function at(seq: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + seq * 60_000,
  ).toISOString();
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
}

/** Seal one more event, timestamped from its own position in the log. */
function append(
  events: readonly Event[],
  type: Parameters<typeof appendEvent>[1]["type"],
  entryId: string | null,
  payload: Parameters<typeof appendEvent>[1]["payload"],
): Promise<Event[]> {
  return appendEvent(events, {
    at: at(events.length),
    type,
    entry_id: entryId,
    payload,
  });
}

/** The seventeen core keys, in the schema's own names. */
function core(overrides: Record<string, unknown>): Core {
  return {
    id: OLD_ID,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-08-15",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: SUBMITTER_AGENT,
    author_operator: SUBMITTER_OPERATOR,
    submitted_at: SUBMITTED_AT,
    ...overrides,
  } as Core;
}

/** The entry the story supersedes: a stated pricing claim. */
const OLD_CORE = core({});

/** The superseder: same subject, same category, a newer price. */
const NEW_CORE = core({
  id: NEW_ID,
  supersedes: OLD_ID,
  before: "$2.50 per million input tokens",
  after: "$2.00 per million input tokens",
});

/** A would-be superseder that names the right target in the wrong category. */
const WRONG_CATEGORY_CORE = core({
  id: NEW_ID,
  category: "limit",
  supersedes: OLD_ID,
  claim: "gpt-5 allows 10,000 requests per minute",
});

/** A would-be superseder naming a target the registry has never seen. */
const MISSING_TARGET_CORE = core({ id: NEW_ID, supersedes: ABSENT_ID });

/** The second pricing entry: verified, and stale under the clock. */
const STALE_CORE = core({
  id: STALE_ID,
  subject: "anthropic/claude-4",
  claim: "claude-4 input price is $3.00 per million tokens",
  before: "$4.00 per million input tokens",
  after: "$3.00 per million input tokens",
});

/** A behavior entry: a transcript category, always observed, predicate frozen. */
const BEHAVIOR_CORE = core({
  id: BEHAVIOR_ID,
  category: "behavior",
  claim: "gpt-5 refuses the frozen prompt",
  before: "answers the prompt",
  after: "refuses the prompt",
  evidence_tier: "observed",
  evidence: {
    model: "gpt-5",
    prompt: "Summarize this in one word.",
    parameters: { temperature: 0 },
    output: "I can't help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
  },
});

/** Submitted and never validated: nothing here has a window to reopen. */
const DRAFT_CORE = core({
  id: DRAFT_ID,
  subject: "google/gemini-3",
  claim: "gemini-3 input price is $1.00 per million tokens",
});

function approvalFor(
  operator: string,
  index: number,
  extra: Record<string, unknown> = {},
): ApproverRecord {
  return {
    agent: agentFor(operator),
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt(index),
    ...extra,
  } as unknown as ApproverRecord;
}

/** An approval on a stated entry: no test to judge, no measurement to bring. */
const stated = (operator: string, index: number) => approvalFor(operator, index);

/** An approval that reran the frozen prompt at the policy's n, holding at its k. */
const reproducing = (operator: string, index: number) =>
  approvalFor(operator, index, {
    test_accepted: true,
    reproduction: {
      model: "gpt-5",
      output: "I can't help with that.",
      observed_at: "2026-09-01",
      runs: REPRODUCTION_RUNS,
      holds: REPRODUCTION_HOLDS,
    },
  });

/** A stated entry's attestation: a fresh snapshot hash and nothing else. */
function reconfirmationRecord(
  agent: string,
  operator: string,
  overrides: Partial<ReconfirmationRecord> = {},
): ReconfirmationRecord {
  return {
    agent,
    operator,
    snapshot_hash: HASH,
    reproduction: null,
    observation: null,
    signed_at: RECONFIRMED_AT,
    ...overrides,
  };
}

/** A trusted pool operator's attestation, in its own agent's name. */
function poolReconfirmation(
  operator: string,
  overrides: Partial<ReconfirmationRecord> = {},
): ReconfirmationRecord {
  return reconfirmationRecord(agentFor(operator), operator, overrides);
}

/** Ten trusted pool operators, plus the submitter's own and one outsider's. */
async function registry(): Promise<Event[]> {
  let events: Event[] = [];
  for (const operator of [SUBMITTER_OPERATOR, OUTSIDER_OPERATOR, ...POOL]) {
    events = await append(events, "operator_registered", null, {
      operator,
      maintainer: false,
    });
  }
  for (const operator of POOL) {
    events = await append(events, "operator_trusted", null, { operator });
  }
  return events;
}

function submitEntry(
  events: readonly Event[],
  submitted: Core,
): Promise<Event[]> {
  return append(events, "entry_submitted", submitted["id"] as string, {
    core: submitted,
    signature: SIGNATURE,
  });
}

/**
 * Approve `submitted` once per operator, the first of them carrying the beacon
 * draw the large pool asks for, and report the slots those approvals seat.
 */
async function approve(
  events: readonly Event[],
  submitted: Core,
  operators: readonly string[],
  build: (operator: string, index: number) => ApproverRecord,
): Promise<{ events: Event[]; seats: ReadShareSlot[] }> {
  let current = [...events];
  const seats: ReadShareSlot[] = [];
  for (let index = 0; index < operators.length; index += 1) {
    const operator = operators[index]!;
    const record = {
      ...build(operator, index + 1),
      assigned_random: index === 0,
    } as ApproverRecord;
    current = await append(current, "validation", submitted["id"] as string, {
      record,
      signature: SIGNATURE,
    });
    seats.push({ operator, seq: current[current.length - 1]!.seq });
  }
  return { events: current, seats };
}

/** One id in, one core or null out: the query shape checkSupersedes reads. */
function lookupIn(events: readonly Event[]): (entryId: string) => Core | null {
  return (entryId) => {
    for (const event of events) {
      if (event.type !== "entry_submitted") continue;
      const submitted = (event as Event<"entry_submitted">).payload.core;
      if (submitted["id"] === entryId) return submitted;
    }
    return null;
  };
}

/**
 * The context the reconfirmation door reads, composed from derived data: the
 * status and effective tier deriveEntry recomputes, and the trusted pool as of
 * the log's own head.
 */
function reconfirmationContextFor(
  events: readonly Event[],
  entryId: string,
  submitted: Core,
): ReconfirmationContext {
  const derived = deriveEntry(events, entryId, CLOCK);
  const head = events[events.length - 1]!.seq;
  return {
    submitter: {
      agent: submitted["author"] as string,
      operator: (submitted["author_operator"] as string | null) ?? null,
    },
    agentOperators: AGENT_OPERATORS,
    trustedOperators: [...trustedOperatorsAt(events, head)],
    status: derived.derived.status,
    effectiveTier: derived.sidecar.effective_tier,
  };
}

/** The reason a record was refused, for a record the door must refuse. */
function reconfirmationRefusal(
  events: readonly Event[],
  entryId: string,
  submitted: Core,
  record: ReconfirmationRecord,
): string {
  const verdict = checkReconfirmation(
    record,
    submitted,
    reconfirmationContextFor(events, entryId, submitted),
  );
  expect(verdict.ok).toBe(false);
  if (verdict.ok) throw new Error("expected a refusal");
  return verdict.reason;
}

function countEvents(
  events: readonly Event[],
  type: string,
  entryId: string,
): number {
  return events.filter(
    (event) => event.type === type && event.entry_id === entryId,
  ).length;
}

async function expectChainOk(events: readonly Event[]): Promise<void> {
  expect(await verifyChain(events)).toEqual({ ok: true, length: events.length });
}

/** The old pricing entry, verified on three approvals. */
async function oldVerified(): Promise<{
  events: Event[];
  seats: ReadShareSlot[];
}> {
  const events = await submitEntry(await registry(), OLD_CORE);
  return approve(
    events,
    OLD_CORE,
    POOL.slice(0, APPROVALS_TO_VERIFY_LARGE_POOL),
    stated,
  );
}

/** The superseder submitted and still draft. */
async function supersederSubmitted(): Promise<Event[]> {
  const { events } = await oldVerified();
  return submitEntry(events, NEW_CORE);
}

/** The superseder verified by three other operators. */
async function supersederVerified(): Promise<Event[]> {
  const verified = await approve(
    await supersederSubmitted(),
    NEW_CORE,
    POOL.slice(
      APPROVALS_TO_VERIFY_LARGE_POOL,
      APPROVALS_TO_VERIFY_LARGE_POOL * 2,
    ),
    stated,
  );
  return verified.events;
}

/** The stale pricing entry, the behavior entry, and a draft to knock on. */
async function doorStage(): Promise<{
  events: Event[];
  staleSeats: ReadShareSlot[];
}> {
  const stale = await approve(
    await submitEntry(await supersederVerified(), STALE_CORE),
    STALE_CORE,
    POOL.slice(0, APPROVALS_TO_VERIFY_LARGE_POOL),
    stated,
  );
  const behavior = await approve(
    await submitEntry(stale.events, BEHAVIOR_CORE),
    BEHAVIOR_CORE,
    POOL.slice(0, APPROVALS_TO_VERIFY_LARGE_POOL),
    reproducing,
  );
  return {
    events: await submitEntry(behavior.events, DRAFT_CORE),
    staleSeats: stale.seats,
  };
}

/** The accepted reconfirmation, gated through the door and then appended. */
async function finalStage(): Promise<{
  events: Event[];
  staleSeats: ReadShareSlot[];
  seated: ReadShareSlot;
}> {
  const { events, staleSeats } = await doorStage();
  const record = poolReconfirmation(RECONFIRMER);
  const verdict = checkReconfirmation(
    record,
    STALE_CORE,
    reconfirmationContextFor(events, STALE_ID, STALE_CORE),
  );
  expect(verdict.ok ? null : verdict.reason).toBeNull();
  if (!verdict.ok) throw new Error(`refused: ${verdict.reason}`);

  const after = await append(events, "reconfirmation", STALE_ID, {
    record: verdict.record,
    signature: SIGNATURE,
  });
  return {
    events: after,
    staleSeats,
    seated: {
      operator: RECONFIRMER,
      seq: after[after.length - 1]!.seq,
    },
  };
}

describe("M6 end to end: supersession and reconfirmation over one sealed log", () => {
  it("runs the large pool it says it does", async () => {
    const events = await registry();
    const head = events[events.length - 1]!.seq;
    const trusted = trustedOperatorsAt(events, head);
    expect(trusted.size).toBe(TRUSTED_POOL_SWITCH);
    expect(trusted.has(SUBMITTER_OPERATOR)).toBe(false);
    expect(trusted.has(OUTSIDER_OPERATOR)).toBe(false);
    expect(APPROVALS_TO_VERIFY_LARGE_POOL).toBe(SLOT_COUNT);
  });

  it("refuses a superseder in another category and one naming a missing target", async () => {
    const { events } = await oldVerified();
    const lookup = lookupIn(events);

    expect(checkSupersedes(WRONG_CATEGORY_CORE, lookup)).toEqual({
      ok: false,
      reason: "category_mismatch",
    });
    expect(checkSupersedes(MISSING_TARGET_CORE, lookup)).toEqual({
      ok: false,
      reason: "target_missing",
    });

    // The one that matches its target's subject and category is accepted, and
    // comes back carrying the target itself.
    expect(checkSupersedes(NEW_CORE, lookup)).toEqual({
      ok: true,
      target: OLD_CORE,
    });

    // Neither refused core reached the log.
    expect(countEvents(events, "entry_submitted", NEW_ID)).toBe(0);
  });

  it("leaves the old entry verified while the accepted superseder is draft", async () => {
    const events = await supersederSubmitted();

    expect(deriveEntry(events, NEW_ID, CLOCK).derived.status).toBe("draft");

    const old = deriveEntry(events, OLD_ID, CLOCK).derived;
    expect(old.status).toBe("verified");
    expect(old.superseded_by).toBeNull();

    await expectChainOk(events);
  });

  it("supersedes the old entry once the superseder verifies", async () => {
    const events = await supersederVerified();

    expect(deriveEntry(events, NEW_ID, CLOCK).derived.status).toBe("verified");

    const old = deriveEntry(events, OLD_ID, CLOCK).derived;
    expect(old.status).toBe("superseded");
    expect(old.superseded_by).toBe(NEW_ID);

    await expectChainOk(events);
  });

  it("turns away at the door every reconfirmation the rules refuse", async () => {
    const { events } = await doorStage();

    // The stale entry is verified and past its window: exactly what a
    // reconfirmation is for.
    const stale = deriveEntry(events, STALE_ID, CLOCK).derived;
    expect(stale.status).toBe("verified");
    expect(stale.staleness_window_days).toBe(
      stalenessWindowDays(DEFAULT_DOMAIN, "pricing"),
    );
    expect(stale.stale).toBe(true);

    // An agent under the submitter's own operator: Section 6's one exception.
    expect(
      reconfirmationRefusal(
        events,
        STALE_ID,
        STALE_CORE,
        reconfirmationRecord(SIBLING_AGENT, SUBMITTER_OPERATOR),
      ),
    ).toBe("submitter_operator");

    // Registered, but its operator was never trusted.
    expect(
      reconfirmationRefusal(
        events,
        STALE_ID,
        STALE_CORE,
        reconfirmationRecord(OUTSIDER_AGENT, OUTSIDER_OPERATOR),
      ),
    ).toBe("untrusted_operator");

    // A draft entry has no window to reopen.
    expect(
      reconfirmationRefusal(
        events,
        DRAFT_ID,
        DRAFT_CORE,
        poolReconfirmation(RECONFIRMER),
      ),
    ).toBe("entry_not_verified");

    // A behavior entry's window reopens only by rerunning the frozen prompt,
    // and one short of the policy's k is not a rerun that holds.
    expect(
      reconfirmationRefusal(
        events,
        BEHAVIOR_ID,
        BEHAVIOR_CORE,
        poolReconfirmation(RECONFIRMER, {
          reproduction: {
            model: "gpt-5",
            output: "I can't help with that.",
            observed_at: "2026-12-10",
            runs: REPRODUCTION_RUNS,
            holds: REPRODUCTION_HOLDS - 1,
          },
        }),
      ),
    ).toBe("failed_reproduction");

    // Not one of them reached the log.
    for (const entryId of [STALE_ID, DRAFT_ID, BEHAVIOR_ID]) {
      expect(countEvents(events, "reconfirmation", entryId)).toBe(0);
    }

    await expectChainOk(events);
  });

  it("reopens the window and rotates the oldest slot on the accepted reconfirmation", async () => {
    const { events, staleSeats, seated } = await finalStage();
    expect(countEvents(events, "reconfirmation", STALE_ID)).toBe(1);
    expect(staleSeats).toHaveLength(SLOT_COUNT);

    const derived = deriveEntry(events, STALE_ID, CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.derived.stale).toBe(false);
    expect(derived.derived.last_confirmed).toBe(RECONFIRMED_DATE);

    // The oldest holder is replaced, not added to: still SLOT_COUNT slots.
    expect(derived.sidecar.read_share_slots).toEqual([
      staleSeats[1],
      staleSeats[2],
      seated,
    ]);
    expect(derived.sidecar.read_share_slots).toHaveLength(SLOT_COUNT);
    expect(
      derived.sidecar.read_share_slots?.some(
        (slot) => slot.operator === staleSeats[0]!.operator,
      ),
    ).toBe(false);
  });

  it("verifies the chain over the final log", async () => {
    const { events } = await finalStage();
    await expectChainOk(events);

    // The whole story still stands at the end of it.
    expect(deriveEntry(events, OLD_ID, CLOCK).derived.status).toBe("superseded");
    expect(deriveEntry(events, NEW_ID, CLOCK).derived.status).toBe("verified");
    expect(deriveEntry(events, STALE_ID, CLOCK).derived.stale).toBe(false);
    expect(deriveEntry(events, BEHAVIOR_ID, CLOCK).sidecar.effective_tier).toBe(
      "observed",
    );
    expect(deriveEntry(events, DRAFT_ID, CLOCK).derived.status).toBe("draft");
  });
});

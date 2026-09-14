/**
 * Freshness and decay, seen through derivation: the staleness windows, the
 * supersession link, and the three read-share slots a reconfirmation rotates.
 *
 * The link rule itself lives in src/supersede.ts and is tested there. What is
 * tested here is the wiring: derivation refuses a superseder the link check
 * refuses, flips the old entry only once the new one has verified, and folds
 * every reconfirmation after the promoting decision into the slots. Every
 * policy number comes from src/policy.ts; a literal would put a policy number
 * in a second place.
 */

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  deriveEntry,
  type Clock,
  type ReadShareSlot,
} from "../src/derive.js";
import type {
  ApproverRecord,
  Event,
  EventType,
  ReconfirmationRecord,
} from "../src/events.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  REJECTIONS_TO_REJECT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  DEFAULT_DOMAIN,
  stalenessWindowDays,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";

const MAINTAINER = "op_maintainer";
const AUTHOR_OPERATOR = "op_brightloop";
const SIGNATURE = "c2lnbmF0dXJl";
const HASH = `sha256:${"a".repeat(64)}`;
const CITATION = "https://platform.openai.com/docs/pricing";

const ENTRY = "nmk_01PRICING1";
const OLD = "nmk_01OLDENTRY";
const NEW = "nmk_01NEWENTRY";

const SUBMITTED_AT = "2026-09-01T14:05:00Z";
const SUBMITTED_DATE = "2026-09-01";
const RECONFIRMED_AT = "2026-10-15T09:00:00Z";
const RECONFIRMED_DATE = "2026-10-15";

const PRICING_WINDOW = stalenessWindowDays(DEFAULT_DOMAIN, "pricing") as number;
const BEHAVIOR_WINDOW = stalenessWindowDays(
  DEFAULT_DOMAIN,
  "behavior",
) as number;

const MILLISECONDS_PER_DAY = 86_400_000;

/** A UTC date, `days` after `date`. */
function datePlus(date: string, days: number): string {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * MILLISECONDS_PER_DAY)
    .toISOString()
    .slice(0, 10);
}

/** Midday on a calendar date: staleness is a comparison of days, not instants. */
function clockAt(date: string): Clock {
  return { now: `${date}T12:00:00Z` };
}

/** The clock a pricing entry submitted on SUBMITTED_DATE is stale under. */
const STALE_CLOCK = clockAt(datePlus(SUBMITTED_DATE, PRICING_WINDOW + 1));

/**
 * The small pool: four trusted outside operators, under the switch to the large
 * pool and past the outside-operator precondition. Four, so a case can spend the
 * approvals and still have operators left to reconfirm or reject with.
 */
const SMALL_VALIDATORS = operators("op_s", 4);

/** The large pool: exactly the switch, so the three-approval rules apply. */
const LARGE_VALIDATORS = operators("op_l", TRUSTED_POOL_SWITCH);

function operators(prefix: string, count: number): readonly string[] {
  return Array.from({ length: count }, (_, index) => `${prefix}${index + 1}`);
}

/** A hand-built event log. Derivation never looks at the hashes. */
class Log {
  readonly events: Event[] = [];
  private next = 0;

  /** Appends the event and returns the seq it was sealed at. */
  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): number {
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
    return seq;
  }
}

/** The maintainer, the submitter's operator, and the trusted pool. */
function baseLog(pool: readonly string[]): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: MAINTAINER,
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (const operator of pool) {
    log.add("operator_registered", null, { operator, maintainer: false });
    log.add("operator_trusted", null, { operator });
  }
  return log;
}

/** A stated pricing core: the eighteen keys, exactly as the schema names them. */
function statedCore(overrides: Record<string, unknown> = {}): Core {
  return {
    id: ENTRY,
    subject: "openai/gpt-5",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00",
    after: "$2.50",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: "1F916:ZnJlc2huZXNzQXV0aG9y",
    author_operator: AUTHOR_OPERATOR,
    submitted_at: SUBMITTED_AT,
    ...overrides,
  } as Core;
}

/** A behavior core: always observed, the predicate frozen in `evidence`. */
function behaviorCore(): Core {
  return statedCore({
    id: "nmk_01BEHAVIOR",
    category: "behavior",
    claim: "gpt-5 refuses the frozen prompt",
    before: null,
    after: "refuses",
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
}

/** A release core: an event category, so it carries no window at all. */
function releaseCore(): Core {
  return statedCore({
    id: "nmk_01RELEASE1",
    category: "release",
    claim: "GPT-5 announced on the OpenAI blog",
    before: null,
    after: "available",
  });
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
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
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt(index),
    ...extra,
  } as unknown as ApproverRecord;
}

/** An approval that reran the frozen prompt and reports its counts. */
const reproducing = (operator: string, index: number) =>
  approval(operator, index, {
    test_accepted: true,
    reproduction: {
      model: "gpt-5",
      output: "I can't help with that.",
      observed_at: "2026-09-01",
      runs: REPRODUCTION_RUNS,
      holds: REPRODUCTION_HOLDS,
    },
  });

/** A rejection signs the reason it rejects. */
const rejecting = (operator: string, index: number) =>
  approval(operator, index, {
    decision: "reject",
    reason: "the pricing page does not read this price",
  });

/** A stated entry's reconfirmation is a fresh snapshot hash and nothing else. */
function reconfirmationRecord(
  operator: string,
  at: string,
): ReconfirmationRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    snapshot_hash: HASH,
    reproduction: null,
    observation: null,
    signed_at: at,
  } as unknown as ReconfirmationRecord;
}

function submit(log: Log, core: Core): number {
  return log.add("entry_submitted", core["id"] as string, {
    core,
    signature: SIGNATURE,
  });
}

function validate(log: Log, core: Core, record: ApproverRecord): number {
  return log.add("validation", core["id"] as string, {
    record,
    signature: SIGNATURE,
  });
}

function reconfirm(
  log: Log,
  core: Core,
  operator: string,
  at = RECONFIRMED_AT,
): ReadShareSlot {
  const seq = log.add("reconfirmation", core["id"] as string, {
    record: reconfirmationRecord(operator, at),
    signature: SIGNATURE,
  });
  return { operator, seq };
}

/**
 * Approve `core` into verified in the pool the log was built with, and return
 * the slots those approvals seat.
 */
function approveInto(
  log: Log,
  core: Core,
  pool: readonly string[],
  approvals: number,
  record: (operator: string, index: number) => ApproverRecord = approval,
  offset = 0,
): ReadShareSlot[] {
  const slots: ReadShareSlot[] = [];
  for (let index = 0; index < approvals; index += 1) {
    const operator = pool[index]!;
    const built =
      index === 0 && approvals >= APPROVALS_TO_VERIFY_LARGE_POOL
        ? { ...record(operator, offset + index), assigned_random: true }
        : record(operator, offset + index);
    const seq = validate(log, core, built as ApproverRecord);
    slots.push({ operator, seq });
  }
  return slots;
}

/** A large-pool log with `core` submitted and verified on three approvals. */
function largeVerified(
  core: Core,
  record: (operator: string, index: number) => ApproverRecord = approval,
): { log: Log; slots: ReadShareSlot[] } {
  const log = baseLog(LARGE_VALIDATORS);
  submit(log, core);
  const slots = approveInto(
    log,
    core,
    LARGE_VALIDATORS,
    APPROVALS_TO_VERIFY_LARGE_POOL,
    record,
  );
  return { log, slots };
}

/** A small-pool log with `core` submitted and verified on two approvals. */
function smallVerified(
  core: Core,
  record: (operator: string, index: number) => ApproverRecord = approval,
): { log: Log; slots: ReadShareSlot[] } {
  const log = baseLog(SMALL_VALIDATORS);
  submit(log, core);
  const slots = approveInto(
    log,
    core,
    SMALL_VALIDATORS,
    APPROVALS_TO_VERIFY_SMALL_POOL,
    record,
  );
  return { log, slots };
}

function derive(log: Log, entryId: string, clock: Clock) {
  return deriveEntry(log.events, entryId, clock);
}

describe("the pools and cores the freshness cases run in", () => {
  it("build cores holding exactly the schema's core keys", () => {
    for (const core of [statedCore(), behaviorCore(), releaseCore()]) {
      expect(Object.keys(core).sort()).toEqual([...CORE_KEYS].sort());
    }
  });

  it("are one pool either side of the switch", () => {
    expect(SMALL_VALIDATORS.length).toBeLessThan(TRUSTED_POOL_SWITCH);
    expect(SMALL_VALIDATORS.length).toBeGreaterThanOrEqual(
      VERIFICATION_MIN_OUTSIDE_OPERATORS,
    );
    expect(LARGE_VALIDATORS.length).toBeGreaterThanOrEqual(
      TRUSTED_POOL_SWITCH,
    );
  });

  it("verify on fewer approvals in the small pool than in the large", () => {
    // The two pool sizes the lifecycle rules need a case each of. The slot
    // count they used to be measured against went with the read share (D-127),
    // so what is pinned is the pair itself.
    expect(APPROVALS_TO_VERIFY_SMALL_POOL).toBeLessThan(
      APPROVALS_TO_VERIFY_LARGE_POOL,
    );
    expect(APPROVALS_TO_VERIFY_SMALL_POOL).toBe(2);
    expect(APPROVALS_TO_VERIFY_LARGE_POOL).toBe(3);
  });
});

describe("staleness windows", () => {
  it("keeps a pricing entry fresh on the last day of its window", () => {
    const { log } = smallVerified(statedCore());
    const expires = datePlus(SUBMITTED_DATE, PRICING_WINDOW);
    expect(expires).toBe("2026-11-30");

    const derived = derive(log, ENTRY, clockAt(expires)).derived;
    expect(derived.status).toBe("verified");
    expect(derived.staleness_window_days).toBe(PRICING_WINDOW);
    expect(derived.last_confirmed).toBe(SUBMITTED_DATE);
    expect(derived.expires_at).toBe(expires);
    expect(derived.stale).toBe(false);
  });

  it("makes a pricing entry stale the day after its window", () => {
    const { log } = smallVerified(statedCore());
    const day = datePlus(SUBMITTED_DATE, PRICING_WINDOW + 1);
    expect(day).toBe("2026-12-01");

    const derived = derive(log, ENTRY, clockAt(day)).derived;
    expect(derived.expires_at).toBe(datePlus(SUBMITTED_DATE, PRICING_WINDOW));
    expect(derived.stale).toBe(true);
  });

  it("makes a behavior entry stale a month sooner", () => {
    const core = behaviorCore();
    const entryId = core["id"] as string;
    const { log } = smallVerified(core, reproducing);
    const expires = datePlus(SUBMITTED_DATE, BEHAVIOR_WINDOW);
    expect(expires).toBe("2026-10-01");

    const fresh = derive(log, entryId, clockAt(expires)).derived;
    expect(fresh.status).toBe("verified");
    expect(fresh.staleness_window_days).toBe(BEHAVIOR_WINDOW);
    expect(fresh.expires_at).toBe(expires);
    expect(fresh.stale).toBe(false);

    const stale = derive(
      log,
      entryId,
      clockAt(datePlus(SUBMITTED_DATE, BEHAVIOR_WINDOW + 1)),
    ).derived;
    expect(stale.stale).toBe(true);
  });

  it("never makes a release entry stale", () => {
    const core = releaseCore();
    const entryId = core["id"] as string;
    const { log } = smallVerified(core);

    for (const now of ["2026-09-02", "2027-09-01", "2126-09-01"]) {
      const derived = derive(log, entryId, clockAt(now)).derived;
      expect(derived.staleness_window_days).toBeNull();
      expect(derived.expires_at).toBeNull();
      expect(derived.stale).toBe(false);
    }
  });
});

describe("supersession", () => {
  const clock = clockAt("2026-09-10");

  /** The old entry verified, and the superseder submitted but still draft. */
  function supersessionLog(newOverrides: Record<string, unknown> = {}): {
    log: Log;
    newCore: Core;
  } {
    const oldCore = statedCore({ id: OLD });
    const newCore = statedCore({
      id: NEW,
      supersedes: OLD,
      before: "$2.50",
      after: "$2.00",
      ...newOverrides,
    });
    const log = baseLog(SMALL_VALIDATORS);
    submit(log, oldCore);
    approveInto(
      log,
      oldCore,
      SMALL_VALIDATORS,
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );
    submit(log, newCore);
    return { log, newCore };
  }

  it("leaves the old entry verified while the superseder is draft", () => {
    const { log } = supersessionLog();
    expect(derive(log, NEW, clock).derived.status).toBe("draft");

    const derived = derive(log, OLD, clock).derived;
    expect(derived.status).toBe("verified");
    expect(derived.superseded_by).toBeNull();
  });

  it("flips the old entry once the superseder verifies", () => {
    const { log, newCore } = supersessionLog();
    approveInto(
      log,
      newCore,
      SMALL_VALIDATORS,
      APPROVALS_TO_VERIFY_SMALL_POOL,
      approval,
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );
    expect(derive(log, NEW, clock).derived.status).toBe("verified");

    const derived = derive(log, OLD, clock).derived;
    expect(derived.status).toBe("superseded");
    expect(derived.superseded_by).toBe(NEW);
  });

  it("never flips the old entry for a superseder in another category", () => {
    const { log, newCore } = supersessionLog({ category: "limit" });
    approveInto(
      log,
      newCore,
      SMALL_VALIDATORS,
      APPROVALS_TO_VERIFY_SMALL_POOL,
      approval,
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );
    // The superseder verifies on its own merits; it is simply not a superseder.
    expect(derive(log, NEW, clock).derived.status).toBe("verified");

    const derived = derive(log, OLD, clock).derived;
    expect(derived.status).toBe("verified");
    expect(derived.superseded_by).toBeNull();
  });

  it("never flips the old entry for a superseder on another subject", () => {
    const { log, newCore } = supersessionLog({ subject: "anthropic/claude-4" });
    approveInto(
      log,
      newCore,
      SMALL_VALIDATORS,
      APPROVALS_TO_VERIFY_SMALL_POOL,
      approval,
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );
    expect(derive(log, NEW, clock).derived.status).toBe("verified");

    const derived = derive(log, OLD, clock).derived;
    expect(derived.status).toBe("verified");
    expect(derived.superseded_by).toBeNull();
  });

  it("keeps the superseded entry's read-share slots", () => {
    const { log, newCore } = supersessionLog();
    const slots = derive(log, OLD, clock).sidecar.read_share_slots;
    approveInto(
      log,
      newCore,
      SMALL_VALIDATORS,
      APPROVALS_TO_VERIFY_SMALL_POOL,
      approval,
      APPROVALS_TO_VERIFY_SMALL_POOL,
    );

    const derived = derive(log, OLD, clock);
    expect(derived.derived.status).toBe("superseded");
    expect(derived.sidecar.read_share_slots).toEqual(slots);
  });
});

describe("read-share slots, retired (D-127)", () => {
  // The read share is gone with the rest of the money: no approval seats a
  // slot and no reconfirmation rotates one. The field keeps its shape — null
  // until the entry verifies, an empty list from the decision that promotes it
  // — so every export, the mirror and the verifier read the document they
  // always read, and "no read share yet" and "no read share ever" stay two
  // different answers.
  //
  // What a reconfirmation still does is everything Freshness and decay asks of
  // it, and that is what each test below keeps pinning beside the empty list.

  it("are null while the entry is draft", () => {
    const log = baseLog(LARGE_VALIDATORS);
    const core = statedCore();
    submit(log, core);

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.derived.status).toBe("draft");
    expect(derived.sidecar.read_share_slots).toBeNull();
  });

  it("are null once the entry is rejected", () => {
    const log = baseLog(SMALL_VALIDATORS);
    const core = statedCore();
    submit(log, core);
    for (let index = 0; index < REJECTIONS_TO_REJECT; index += 1) {
      validate(log, core, rejecting(SMALL_VALIDATORS[index]!, index));
    }

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.derived.status).toBe("rejected");
    expect(derived.sidecar.read_share_slots).toBeNull();
  });

  it("are an empty list once the entry verifies, seating no approval", () => {
    const { log, slots } = largeVerified(statedCore());

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(slots.length).toBe(APPROVALS_TO_VERIFY_LARGE_POOL);
    expect(derived.sidecar.read_share_slots).toEqual([]);
    for (const slot of slots) {
      expect([
        slot.operator,
        derived.sidecar.read_share_slots?.some(
          (seat) => seat.operator === slot.operator,
        ),
      ]).toEqual([slot.operator, false]);
    }
  });

  it("seat no one for an approval that arrives after verification", () => {
    const { log } = largeVerified(statedCore());
    const latecomer = LARGE_VALIDATORS[APPROVALS_TO_VERIFY_LARGE_POOL]!;
    validate(
      log,
      statedCore(),
      approval(latecomer, APPROVALS_TO_VERIFY_LARGE_POOL),
    );

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.sidecar.read_share_slots).toEqual([]);
    expect(
      derived.sidecar.read_share_slots?.some(
        (slot) => slot.operator === latecomer,
      ),
    ).toBe(false);
  });

  it("seat no one for a reconfirmation sealed before the promoting approval", () => {
    // The list does not exist until the promoting decision, and it is empty
    // from there: a reconfirmation at or below that decision's seq is neither
    // seated nor counted, exactly as one after it is not.
    const core = statedCore();
    const log = baseLog(LARGE_VALIDATORS);
    submit(log, core);

    const seated: ReadShareSlot[] = [];
    const seat = (index: number): void => {
      const operator = LARGE_VALIDATORS[index]!;
      const seq = validate(
        log,
        core,
        approval(operator, index, { assigned_random: index === 0 }),
      );
      seated.push({ operator, seq });
    };

    // Every approval but the last: the entry is still draft.
    for (let index = 0; index < APPROVALS_TO_VERIFY_LARGE_POOL - 1; index += 1) {
      seat(index);
    }
    const beforePromotion = derive(log, ENTRY, STALE_CLOCK);
    expect(beforePromotion.derived.status).toBe("draft");
    expect(beforePromotion.sidecar.read_share_slots).toBeNull();

    // A reconfirmation arrives here, before the approval that promotes.
    const early = LARGE_VALIDATORS[APPROVALS_TO_VERIFY_LARGE_POOL]!;
    const earlySeat = reconfirm(log, core, early);

    seat(APPROVALS_TO_VERIFY_LARGE_POOL - 1);
    const promotingSeq = seated[seated.length - 1]!.seq;
    expect(earlySeat.seq).toBeLessThan(promotingSeq);

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.derived.status).toBe("verified");
    expect(derived.sidecar.read_share_slots).toEqual([]);
  });

  it("clear the staleness on a reconfirmation, and rotate nothing", () => {
    const core = statedCore();
    const { log, slots } = largeVerified(core);
    expect(derive(log, ENTRY, STALE_CLOCK).derived.stale).toBe(true);

    const reconfirmer = LARGE_VALIDATORS[APPROVALS_TO_VERIFY_LARGE_POOL]!;
    const seated = reconfirm(log, core, reconfirmer);

    const derived = derive(log, ENTRY, STALE_CLOCK);
    // The whole of the reconfirmation's job, untouched by D-127.
    expect(derived.derived.stale).toBe(false);
    expect(derived.derived.last_confirmed).toBe(RECONFIRMED_DATE);
    expect(derived.derived.expires_at).toBe(
      datePlus(RECONFIRMED_DATE, PRICING_WINDOW),
    );

    // And nothing rotates: neither the reconfirmer in nor the oldest holder
    // out, because there is no holder and nothing to hold.
    expect(derived.sidecar.read_share_slots).toEqual([]);
    for (const operator of [seated.operator, slots[0]!.operator]) {
      expect([
        operator,
        derived.sidecar.read_share_slots?.some(
          (slot) => slot.operator === operator,
        ),
      ]).toEqual([operator, false]);
    }
  });

  it("rotate nothing when the reconfirmer is one of the approvers either", () => {
    const core = statedCore();
    const { log, slots } = largeVerified(core);
    reconfirm(log, core, slots[0]!.operator);

    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.derived.stale).toBe(false);
    expect(derived.derived.last_confirmed).toBe(RECONFIRMED_DATE);
    expect(derived.sidecar.read_share_slots).toEqual([]);
  });

  it("stay empty through a second reconfirmation, which still refreshes", () => {
    const core = statedCore();
    const { log } = largeVerified(core);

    reconfirm(log, core, LARGE_VALIDATORS[APPROVALS_TO_VERIFY_LARGE_POOL]!);
    expect(derive(log, ENTRY, STALE_CLOCK).sidecar.read_share_slots).toEqual(
      [],
    );

    reconfirm(
      log,
      core,
      LARGE_VALIDATORS[APPROVALS_TO_VERIFY_LARGE_POOL + 1]!,
      "2026-10-20T09:00:00Z",
    );
    const derived = derive(log, ENTRY, STALE_CLOCK);
    expect(derived.sidecar.read_share_slots).toEqual([]);
    // The later reconfirmation is still the one the freshness rule reads.
    expect(derived.derived.last_confirmed).toBe("2026-10-20");
    expect(derived.derived.stale).toBe(false);
  });

  it("leave a small pool nothing to fill: two approvals seat nobody either", () => {
    const core = statedCore();
    const { log, slots } = smallVerified(core);
    expect(slots).toHaveLength(APPROVALS_TO_VERIFY_SMALL_POOL);
    expect(derive(log, ENTRY, STALE_CLOCK).sidecar.read_share_slots).toEqual(
      [],
    );

    // A small pool used to leave an empty seat an outsider could fill. There
    // is no seat to leave now, so an outsider's reconfirmation refreshes the
    // entry and adds nobody.
    reconfirm(log, core, SMALL_VALIDATORS[APPROVALS_TO_VERIFY_SMALL_POOL]!);
    const filled = derive(log, ENTRY, STALE_CLOCK);
    expect(filled.sidecar.read_share_slots).toEqual([]);
    expect(filled.derived.stale).toBe(false);

    reconfirm(
      log,
      core,
      SMALL_VALIDATORS[APPROVALS_TO_VERIFY_SMALL_POOL + 1]!,
      "2026-10-20T09:00:00Z",
    );
    expect(derive(log, ENTRY, STALE_CLOCK).sidecar.read_share_slots).toEqual(
      [],
    );
  });
});

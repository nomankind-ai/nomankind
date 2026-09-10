/**
 * The status rules, over fixtures.
 *
 * One fixture per stage per state, because the whole point of the rules is that
 * a state is a consequence of facts and not of a judgement: a test that only
 * showed the healthy case would be showing that nothing broke, which is not the
 * same as showing that a break is seen.
 *
 * Everything here is pure. No database, no clock, no Worker — `stageStates`,
 * `exercisedStages` and `statusCounters` take a `StatusInput` and an instant, so
 * a fixture is an object literal and a broken beacon is one field.
 *
 * The thresholds are read from src/policy.ts rather than written down again: a
 * test that hard-coded thirty minutes would pass after somebody changed the
 * policy and stopped testing the policy.
 */

import { describe, expect, it } from "vitest";
import {
  ASSIGNMENT_WINDOW_HOURS,
  SEAL_INTERVAL_MINUTES,
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
  SWEEP_INTERVAL_MINUTES,
  WITNESSES_REQUIRED,
} from "../src/policy.js";
import {
  exercisedStages,
  stageStates,
  statusCounters,
  type Stage,
  type StageState,
  type StatusInput,
  type SweepStep,
} from "../src/status.js";

/** The instant every fixture is read at: midday, so "yesterday" is unambiguous. */
const NOW = "2026-09-10T12:00:00.000Z";
const YESTERDAY = "2026-09-09";
const TODAY = "2026-09-10";

const MILLISECONDS_PER_MINUTE = 60_000;

/** An instant `minutes` before NOW. */
function minutesAgo(minutes: number): string {
  return new Date(
    Date.parse(NOW) - minutes * MILLISECONDS_PER_MINUTE,
  ).toISOString();
}

/** One step row, healthy unless the test says otherwise. */
function step(name: string, over: Partial<SweepStep> = {}): SweepStep {
  return {
    step: name,
    last_run_at: NOW,
    last_ok_at: NOW,
    last_skip_reason: null,
    last_skip_at: null,
    detail: {},
    trigger: "alarm",
    ...over,
  };
}

/**
 * The empty world: nothing registered, nothing submitted, nothing sealed, and no
 * sweep ever run. Every stage reads idle from it, which is what makes it the
 * base every other fixture is written as a difference from.
 */
function empty(): StatusInput {
  return {
    environment: "local",
    witness_kind: "mock",
    payout_kind: "mock",
    steps: [],
    head_seq: null,
    seal: null,
    seals: { total: 0, witnessed: 0 },
    unsealed: { count: 0, oldest_at: null },
    pool: { snapshot: null, trusted: [], registered: 0 },
    assignments: { overdue: 0, drafts: 0 },
    entries: 0,
    read_counts: { newest: null, earliest_receipt_day: null },
    anchor: null,
    seals_yesterday: 0,
    reconciliation: null,
    standing_position: null,
    attestations: { due: 0, total: 0 },
    mirror: { kind: "unavailable", newest: null },
    exercised: {
      submission: null,
      registration: null,
      read_receipt: null,
      sync_receipt: null,
      payout: null,
    },
  };
}

/** The state one named stage reads in one fixture. */
function stateOf(input: StatusInput, stage: string): StageState {
  const found = stageStates(input, NOW).find((one) => one.stage === stage);
  if (found === undefined) throw new Error(`no stage named ${stage}`);
  return found.state;
}

/** The whole row for one named stage. */
function rowOf(input: StatusInput, stage: string): Stage {
  const found = stageStates(input, NOW).find((one) => one.stage === stage);
  if (found === undefined) throw new Error(`no stage named ${stage}`);
  return found;
}

/** A world with a sweep that ran this instant and nothing else. */
function swept(over: Partial<StatusInput> = {}): StatusInput {
  return { ...empty(), steps: [step("sweep")], ...over };
}

describe("the thirteen stages", () => {
  it("names them in the pipeline's order and answers all thirteen", () => {
    expect(stageStates(empty(), NOW).map((one) => one.stage)).toEqual([
      "sweep timer",
      "pool snapshot",
      "beacon",
      "draws and deadlines",
      "staleness",
      "read counts",
      "sealing",
      "witnessing",
      "anchoring",
      "ledger",
      "standing",
      "attestations",
      "mirror export",
    ]);
  });

  it("says each rule in the page's words, with the numbers from policy", () => {
    // The thirteen sentences the mockup approved, pinned: the wording is the page
    // and changing it is a design change. Two of them say a number, and both
    // come from src/policy.ts rather than from a digit typed here.
    const rules = [
      `a run within ${STATUS_ATTENTION_AFTER_INTERVALS} × SWEEP_INTERVAL_MINUTES`,
      "the newest snapshot equals the trusted pool",
      "the newest round read is after the newest snapshot",
      "every due draw made; no assignment past ASSIGNMENT_WINDOW_HOURS unmarked",
      "every row past its window marked stale",
      "yesterday's read_count sealed",
      `the newest seal younger than ${STATUS_ATTENTION_AFTER_INTERVALS} × SEAL_INTERVAL_MINUTES; no unsealed event older`,
      "the newest seal countersigned by WITNESSES_REQUIRED pinned witnesses",
      "yesterday's anchor exists; posted to OpenTimestamps on production",
      "yesterday's reconciliation row present and equal",
      "standing stored at the sealed head",
      "no open attestation past ATTESTATION_WINDOW_HOURS",
      "today's export committed to the mirror repository",
    ];
    expect(stageStates(empty(), NOW).map((one) => one.rule)).toEqual(rules);
    // The rule is what the state was decided by and not a reading of it, so a
    // world where things have happened says exactly the same thirteen.
    expect(stageStates(swept(), NOW).map((one) => one.rule)).toEqual(rules);
  });

  it("names the constants it applies and never their values", () => {
    // A rule quoting ASSIGNMENT_WINDOW_HOURS must not print seventy-two: the
    // number is policy's to change and the page sends the reader to /policy.
    const draws = rowOf(empty(), "draws and deadlines").rule;
    expect(draws).toContain("ASSIGNMENT_WINDOW_HOURS");
    expect(draws).not.toContain(String(ASSIGNMENT_WINDOW_HOURS));
  });

  it("reads every stage idle on a log nothing has happened in", () => {
    for (const stage of stageStates(empty(), NOW)) {
      expect([stage.stage, stage.state]).toEqual([stage.stage, "idle"]);
    }
  });
});

describe("1. sweep timer", () => {
  it("is idle when no run was ever recorded", () => {
    expect(stateOf(empty(), "sweep timer")).toBe("idle");
    expect(rowOf(empty(), "sweep timer").last).toBe("never");
  });

  it("is ok inside the interval, and says the trigger", () => {
    const input = swept();
    expect(stateOf(input, "sweep timer")).toBe("ok");
    expect(rowOf(input, "sweep timer").last).toBe("12:00:00 UTC · 0 min ago · alarm");
  });

  it("wants attention past its own intervals", () => {
    const late = STATUS_ATTENTION_AFTER_INTERVALS * SWEEP_INTERVAL_MINUTES + 1;
    const input = {
      ...empty(),
      steps: [step("sweep", { last_run_at: minutesAgo(late), trigger: "cron" })],
    };
    expect(stateOf(input, "sweep timer")).toBe("attention");
    expect(rowOf(input, "sweep timer").last).toContain("cron");
  });

  it("is failing past the failing threshold", () => {
    const input = {
      ...empty(),
      steps: [
        step("sweep", {
          last_run_at: minutesAgo(STATUS_FAILING_AFTER_MINUTES + 1),
        }),
      ],
    };
    expect(stateOf(input, "sweep timer")).toBe("failing");
  });
});

describe("2. pool snapshot", () => {
  const snapshot = { seq: 7, at: minutesAgo(3), operators: ["a.example", "b.example"] };

  it("is idle with no operator registered", () => {
    expect(stateOf(swept(), "pool snapshot")).toBe("idle");
  });

  it("is ok when the sealed snapshot names the trusted pool", () => {
    const input = swept({
      pool: { snapshot, trusted: ["b.example", "a.example"], registered: 2 },
    });
    expect(stateOf(input, "pool snapshot")).toBe("ok");
    expect(rowOf(input, "pool snapshot").last).toContain("seq 7");
  });

  it("wants attention when the pool has moved past the snapshot", () => {
    const input = swept({
      pool: {
        snapshot,
        trusted: ["a.example", "b.example", "c.example"],
        registered: 3,
      },
    });
    expect(stateOf(input, "pool snapshot")).toBe("attention");
  });

  it("wants attention when operators exist and nothing was ever committed", () => {
    const input = swept({
      pool: { snapshot: null, trusted: ["a.example"], registered: 1 },
    });
    expect(stateOf(input, "pool snapshot")).toBe("attention");
    expect(rowOf(input, "pool snapshot").last).toContain("no snapshot yet");
  });
});

describe("3. beacon", () => {
  const snapshotAt = minutesAgo(20);

  function draws(detail: Record<string, unknown>, over: Partial<SweepStep> = {}) {
    return swept({
      steps: [step("sweep"), step("draws", { detail, ...over })],
      pool: {
        snapshot: { seq: 1, at: snapshotAt, operators: ["a.example"] },
        trusted: ["a.example"],
        registered: 1,
      },
    });
  }

  it("is idle before any read", () => {
    expect(stateOf(swept(), "beacon")).toBe("idle");
  });

  it("is ok on a round newer than the snapshot", () => {
    const input = draws({
      beacon_round: 4212,
      beacon_at: minutesAgo(1),
      beacon_reason: null,
    });
    expect(stateOf(input, "beacon")).toBe("ok");
    expect(rowOf(input, "beacon").last).toContain("round 4212");
  });

  it("wants attention on a round the snapshot is later than", () => {
    // The draw refuses this one with `snapshot_after_beacon`, which is the rule
    // working — and also a draw that will not happen until the next round.
    const input = draws({
      beacon_round: 1,
      beacon_at: minutesAgo(40),
      beacon_reason: null,
    });
    expect(stateOf(input, "beacon")).toBe("attention");
  });

  it("wants attention on a refusal the last round is still recent behind", () => {
    const input = draws(
      { beacon_round: null, beacon_at: null, beacon_reason: "beacon_unavailable" },
      { last_ok_at: minutesAgo(6) },
    );
    expect(stateOf(input, "beacon")).toBe("attention");
    expect(rowOf(input, "beacon").last).toContain("beacon_unavailable");
  });

  it("is failing once the refusal has stood past the threshold", () => {
    const input = draws(
      { beacon_round: null, beacon_at: null, beacon_reason: "bad_beacon" },
      { last_ok_at: minutesAgo(STATUS_FAILING_AFTER_MINUTES + 1) },
    );
    expect(stateOf(input, "beacon")).toBe("failing");
  });
});

describe("4. draws and deadlines", () => {
  it("is idle with no draft entry", () => {
    expect(stateOf(swept(), "draws and deadlines")).toBe("idle");
  });

  it("is ok when the only refusal is a rule saying no draw is owed", () => {
    const input = swept({
      steps: [
        step("sweep"),
        step("draws", {
          detail: { drawn: 0 },
          last_skip_reason: "awaiting_volunteers",
          last_skip_at: NOW,
        }),
      ],
      assignments: { overdue: 0, drafts: 3 },
    });
    expect(stateOf(input, "draws and deadlines")).toBe("ok");
  });

  it("wants attention when a draw was owed and did not happen", () => {
    const input = swept({
      steps: [
        step("sweep"),
        step("draws", {
          detail: { drawn: 0 },
          last_skip_reason: "no_eligible_operator",
          last_skip_at: NOW,
        }),
      ],
      assignments: { overdue: 0, drafts: 1 },
    });
    expect(stateOf(input, "draws and deadlines")).toBe("attention");
  });

  it("ignores a refusal from an older run", () => {
    const input = swept({
      steps: [
        step("sweep"),
        step("draws", {
          detail: { drawn: 1 },
          last_skip_reason: "no_eligible_operator",
          last_skip_at: minutesAgo(90),
        }),
      ],
      assignments: { overdue: 0, drafts: 1 },
    });
    expect(stateOf(input, "draws and deadlines")).toBe("ok");
  });

  it("wants attention while an assignment is past its window", () => {
    const input = swept({
      steps: [step("sweep"), step("draws", { detail: { drawn: 0 } })],
      assignments: { overdue: 2, drafts: 1 },
    });
    expect(stateOf(input, "draws and deadlines")).toBe("attention");
    expect(rowOf(input, "draws and deadlines").last).toContain("2 past deadline");
  });
});

describe("5. staleness", () => {
  it("is idle with no entry", () => {
    expect(stateOf(swept(), "staleness")).toBe("idle");
  });

  it("is ok when the run left no row unmarked", () => {
    const input = swept({
      steps: [step("sweep"), step("staleness", { detail: { staled: 2 } })],
      entries: 5,
    });
    expect(stateOf(input, "staleness")).toBe("ok");
    expect(rowOf(input, "staleness").last).toContain("2 rewritten");
  });

  it("wants attention when a row past its window was skipped", () => {
    const input = swept({
      steps: [
        step("sweep"),
        step("staleness", {
          detail: { staled: 0 },
          last_skip_reason: "schema_invalid",
          last_skip_at: NOW,
        }),
      ],
      entries: 5,
    });
    expect(stateOf(input, "staleness")).toBe("attention");
    expect(rowOf(input, "staleness").last).toContain("schema_invalid");
  });
});

describe("6. read counts", () => {
  const count = { seq: 40, date: YESTERDAY, total: 12, at: minutesAgo(30) };

  it("is idle when no receipt was ever issued", () => {
    expect(stateOf(swept(), "read counts")).toBe("idle");
  });

  it("is idle while the first receipt's day is not over", () => {
    const input = swept({
      read_counts: { newest: null, earliest_receipt_day: TODAY },
    });
    expect(stateOf(input, "read counts")).toBe("idle");
  });

  it("is ok when yesterday's count is published", () => {
    const input = swept({
      read_counts: { newest: count, earliest_receipt_day: "2026-09-01" },
    });
    expect(stateOf(input, "read counts")).toBe("ok");
    expect(rowOf(input, "read counts").last).toBe(
      `${YESTERDAY} · 12 reads · seq 40`,
    );
  });

  it("wants attention while a finished day is unpublished", () => {
    const input = swept({
      read_counts: {
        newest: { ...count, date: "2026-09-07" },
        earliest_receipt_day: "2026-09-01",
      },
    });
    expect(stateOf(input, "read counts")).toBe("attention");
  });
});

describe("7. sealing", () => {
  const window = STATUS_ATTENTION_AFTER_INTERVALS * SEAL_INTERVAL_MINUTES;

  it("is idle on a log with no event", () => {
    expect(stateOf(swept(), "sealing")).toBe("idle");
  });

  it("is ok while the newest seal is inside the interval", () => {
    const input = swept({
      head_seq: 30,
      seal: { seq: 3, last_seq: 30, sealed_at: minutesAgo(1), witnesses: 1 },
      unsealed: { count: 0, oldest_at: null },
    });
    expect(stateOf(input, "sealing")).toBe("ok");
  });

  it("is ok on an old seal while nothing new is waiting long", () => {
    const input = swept({
      head_seq: 31,
      seal: { seq: 3, last_seq: 30, sealed_at: minutesAgo(90), witnesses: 1 },
      unsealed: { count: 1, oldest_at: minutesAgo(1) },
    });
    expect(stateOf(input, "sealing")).toBe("ok");
  });

  it("wants attention when an event has waited past the interval", () => {
    const input = swept({
      head_seq: 31,
      seal: { seq: 3, last_seq: 30, sealed_at: minutesAgo(90), witnesses: 1 },
      unsealed: { count: 4, oldest_at: minutesAgo(window + 1) },
    });
    expect(stateOf(input, "sealing")).toBe("attention");
    expect(rowOf(input, "sealing").last).toContain("4 unsealed");
  });

  it("is failing when an event has waited past the failing threshold", () => {
    const input = swept({
      head_seq: 31,
      seal: null,
      unsealed: {
        count: 31,
        oldest_at: minutesAgo(STATUS_FAILING_AFTER_MINUTES + 1),
      },
    });
    expect(stateOf(input, "sealing")).toBe("failing");
  });
});

describe("8. witnessing", () => {
  it("is idle with no seal", () => {
    expect(stateOf(swept(), "witnessing")).toBe("idle");
  });

  it("is ok on a seal carrying the countersignatures policy asks for", () => {
    const input = swept({
      head_seq: 30,
      seal: {
        seq: 3,
        last_seq: 30,
        sealed_at: minutesAgo(1),
        witnesses: WITNESSES_REQUIRED,
      },
    });
    expect(stateOf(input, "witnessing")).toBe("ok");
    expect(rowOf(input, "witnessing").last).toContain(
      `${WITNESSES_REQUIRED}/${WITNESSES_REQUIRED} witnesses`,
    );
  });

  it("wants attention on a fresh seal still waiting", () => {
    const input = swept({
      head_seq: 30,
      seal: { seq: 3, last_seq: 30, sealed_at: minutesAgo(2), witnesses: 0 },
    });
    expect(stateOf(input, "witnessing")).toBe("attention");
  });

  it("is failing on a seal that has waited past the threshold", () => {
    const input = swept({
      head_seq: 30,
      seal: {
        seq: 3,
        last_seq: 30,
        sealed_at: minutesAgo(STATUS_FAILING_AFTER_MINUTES + 1),
        witnesses: 0,
      },
    });
    expect(stateOf(input, "witnessing")).toBe("failing");
  });
});

describe("9. anchoring", () => {
  it("is idle when no seal was made yesterday", () => {
    expect(stateOf(swept(), "anchoring")).toBe("idle");
  });

  it("is ok when yesterday's roots are anchored", () => {
    const input = swept({
      seals_yesterday: 4,
      anchor: { date: YESTERDAY, external: null },
    });
    expect(stateOf(input, "anchoring")).toBe("ok");
  });

  it("wants attention on production without an external record", () => {
    const input = swept({
      environment: "production",
      seals_yesterday: 4,
      anchor: { date: YESTERDAY, external: null },
    });
    expect(stateOf(input, "anchoring")).toBe("attention");
  });

  it("is ok on production once something outside has timestamped it", () => {
    const input = swept({
      environment: "production",
      seals_yesterday: 4,
      anchor: { date: YESTERDAY, external: "opentimestamps" },
    });
    expect(stateOf(input, "anchoring")).toBe("ok");
  });

  it("wants attention when it is owed and a run today has been and gone", () => {
    const input = swept({ seals_yesterday: 4, anchor: null });
    expect(stateOf(input, "anchoring")).toBe("attention");
    expect(rowOf(input, "anchoring").last).toBe(`${YESTERDAY} · not anchored`);
  });
});

describe("10. ledger", () => {
  const count = { seq: 40, date: YESTERDAY, total: 12, at: minutesAgo(30) };

  it("is idle before any read count", () => {
    expect(stateOf(swept(), "ledger")).toBe("idle");
  });

  it("is ok when the published day reconciles", () => {
    const input = swept({
      read_counts: { newest: count, earliest_receipt_day: "2026-09-01" },
      reconciliation: { date: YESTERDAY, ok: true, at: minutesAgo(29) },
    });
    expect(stateOf(input, "ledger")).toBe("ok");
    expect(rowOf(input, "ledger").last).toContain("agrees");
  });

  it("wants attention while the row is missing", () => {
    const input = swept({
      read_counts: { newest: count, earliest_receipt_day: "2026-09-01" },
      reconciliation: null,
    });
    expect(stateOf(input, "ledger")).toBe("attention");
  });

  it("is failing when the row is there and does not agree", () => {
    const input = swept({
      read_counts: { newest: count, earliest_receipt_day: "2026-09-01" },
      reconciliation: { date: YESTERDAY, ok: false, at: minutesAgo(29) },
    });
    expect(stateOf(input, "ledger")).toBe("failing");
    expect(rowOf(input, "ledger").last).toContain("disagrees");
  });
});

describe("11. standing", () => {
  const seal = { seq: 3, last_seq: 30, sealed_at: minutesAgo(1), witnesses: 1 };

  it("is idle with no operator", () => {
    expect(stateOf(swept(), "standing")).toBe("idle");
  });

  it("is idle while nothing is sealed to recompute against", () => {
    const input = swept({
      pool: { snapshot: null, trusted: [], registered: 3 },
    });
    expect(stateOf(input, "standing")).toBe("idle");
  });

  it("is ok at the sealed head", () => {
    const input = swept({
      head_seq: 30,
      seal,
      pool: { snapshot: null, trusted: [], registered: 3 },
      standing_position: 30,
    });
    expect(stateOf(input, "standing")).toBe("ok");
    expect(rowOf(input, "standing").last).toContain("position 30");
  });

  it("wants attention behind the sealed head", () => {
    const input = swept({
      head_seq: 30,
      seal,
      pool: { snapshot: null, trusted: [], registered: 3 },
      standing_position: 12,
    });
    expect(stateOf(input, "standing")).toBe("attention");
  });
});

describe("12. attestations", () => {
  it("is idle when none was ever asked for", () => {
    expect(stateOf(swept(), "attestations")).toBe("idle");
  });

  it("is ok while none is past its deadline", () => {
    const input = swept({ attestations: { due: 0, total: 6 } });
    expect(stateOf(input, "attestations")).toBe("ok");
    expect(rowOf(input, "attestations").last).toBe("6 in the log · 0 past deadline");
  });

  it("wants attention while one is past its deadline unexpired", () => {
    const input = swept({ attestations: { due: 1, total: 6 } });
    expect(stateOf(input, "attestations")).toBe("attention");
  });
});

describe("the four counters", () => {
  it("says never, empty and nothing on a world nothing has happened in", () => {
    const input = empty();
    const counters = statusCounters(stageStates(input, NOW), input);
    expect(counters).toEqual({
      lastSweepAt: null,
      lastSweepAge: null,
      lastSweepTrigger: null,
      stagesOk: 13,
      stagesTotal: 13,
      stagesFailing: 0,
      stagesAttention: 0,
      sealedHead: null,
      newestSealSeq: null,
      unsealedEvents: 0,
      seals: 0,
      witnessedSeals: 0,
      witnessKind: "mock witnesses on local",
    });
  });

  it("counts idle stages with the ok ones", () => {
    const input = swept();
    const counters = statusCounters(stageStates(input, NOW), input);
    expect([counters.stagesOk, counters.stagesTotal]).toEqual([13, 13]);
    expect(counters.lastSweepAge).toBe("0 min ago");
    expect(counters.lastSweepTrigger).toBe("alarm");
  });

  it("counts what is failing and what wants attention, apart", () => {
    const input = swept({
      steps: [
        step("sweep", {
          last_run_at: minutesAgo(STATUS_FAILING_AFTER_MINUTES + 1),
        }),
      ],
      head_seq: 31,
      seal: { seq: 3, last_seq: 30, sealed_at: minutesAgo(90), witnesses: 0 },
      seals: { total: 4, witnessed: 3 },
      unsealed: { count: 1, oldest_at: minutesAgo(15) },
    });
    const counters = statusCounters(stageStates(input, NOW), input);
    // The sweep timer and the witnessing of a ninety-minute-old seal are both
    // past the failing threshold; sealing has one event waiting past the seal
    // interval and not past the failing one.
    expect(counters.stagesFailing).toBe(2);
    expect(counters.stagesAttention).toBe(1);
    expect(counters.stagesOk).toBe(10);
    expect([counters.sealedHead, counters.newestSealSeq]).toEqual([30, 3]);
    expect([counters.seals, counters.witnessedSeals]).toEqual([4, 3]);
    expect(counters.unsealedEvents).toBe(1);
  });

  it("names the registry track on production", () => {
    const input = { ...empty(), environment: "production", witness_kind: "registry" };
    expect(statusCounters(stageStates(input, NOW), input).witnessKind).toBe(
      "registry witnesses",
    );
  });
});

describe("the exercised rows", () => {
  it("names five doors and says never for each on an untouched log", () => {
    const rows = exercisedStages(empty());
    expect(rows.map((row) => row.stage)).toEqual([
      "submit and archive",
      "registration, DNS check",
      "read receipts",
      "sync receipts",
      "payouts",
    ]);
    expect(rows.slice(0, 4).map((row) => row.last)).toEqual([
      "never",
      "never",
      "never",
      "never",
    ]);
    // The payout row says why nobody has been paid rather than only that nobody
    // has: an operator under the floor carries forward, which is the rule
    // working and not a payout that failed.
    expect(rows[4]!.last).toBe(
      "never · mock adapter · every operator below PAYOUT_MINIMUM_MICROS",
    );
  });

  it("says who last came through each door, and links what they left", () => {
    const rows = exercisedStages({
      ...empty(),
      exercised: {
        submission: { at: minutesAgo(5), id: "nmk_0123456789abcdef0123456789abcdef" },
        registration: { at: minutesAgo(400), operator: "lattice.example" },
        read_receipt: { counter: 91, created_at: minutesAgo(2) },
        sync_receipt: { counter: 90, created_at: minutesAgo(9) },
        payout: { at: minutesAgo(60), operator: "lattice.example", amount: 5_000_000 },
      },
    });
    expect(rows[0]!.last).toBe(
      "11:55:00 UTC · nmk_0123456789abcdef0123456789abcdef",
    );
    expect(rows[0]!.evidence).toEqual([
      {
        label: "/entries/nmk_0123456789abcdef0123456789abcdef",
        href: "/entries/nmk_0123456789abcdef0123456789abcdef",
      },
    ]);
    expect(rows[1]!.last).toBe("05:20:00 UTC · lattice.example");
    expect(rows[2]!.last).toBe("11:58:00 UTC · receipt 91");
    expect(rows[3]!.last).toBe("11:51:00 UTC · receipt 90");
    expect(rows[4]!.last).toBe("11:00:00 UTC · lattice.example · 5000000 micros");
  });
});

describe("time arithmetic", () => {
  it("never reports a negative age", () => {
    // A row written by a run whose instant was later than this reading's: a
    // redeploy can do it, and "minus four minutes ago" is not a thing to show.
    const input = {
      ...empty(),
      steps: [step("sweep", { last_run_at: "2026-09-10T12:04:00.000Z" })],
    };
    expect(rowOf(input, "sweep timer").last).toContain("0 min ago");
    expect(stateOf(input, "sweep timer")).toBe("ok");
  });
});

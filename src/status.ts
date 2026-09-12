/**
 * What the status page says, and why.
 *
 * Whitepaper Section 11, Deployment and status: nomankind publishes what it is
 * running and whether it is working. This module is the second half of that
 * sentence — fifteen stages of the machine, each with a state, the last thing
 * that happened in it, the rule that decides the state, and a link a reader can
 * follow to check the answer for themselves.
 *
 * Pure, and over one argument. Everything the rules need arrives as a
 * `StatusInput` — the sweep's own step rows, the head, the newest seal, the
 * counts — gathered query-shaped by src/worker/status.ts, so nothing here reads
 * a database, a clock or a network. The instant is the second argument for the
 * same reason it is everywhere else in the kernel: a status page that read the
 * wall clock could not be tested and could not be recomputed.
 *
 * Nothing here decides anything about the log either. A stage is a reading of
 * facts the log and the sweep already recorded; it appends nothing, stores
 * nothing, and a page that never loaded would leave the system exactly as it is.
 *
 * Time arithmetic is in whole seconds and never negative. A clock that appears
 * to run backwards — a row written by a run whose instant was later than this
 * one's, which a redeploy can do — reads as zero seconds old rather than as a
 * negative age, because "minus four minutes ago" is not a thing to show anyone.
 *
 * No policy number lives here: the two status thresholds, the sweep and seal
 * cadences and the witness bar all come from src/policy.ts.
 */

import type { MirrorKind } from "./adapters/mirror.js";
import type { PaymentsKind } from "./adapters/stripe.js";
import { utcDay } from "./anchor.js";
import {
  POLICY,
  SEAL_INTERVAL_MINUTES,
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
  SWEEP_INTERVAL_MINUTES,
  WITNESSES_REQUIRED,
} from "./policy.js";

// ---------------------------------------------------------------------------
// What the rules are given
// ---------------------------------------------------------------------------

/**
 * One step of the sweep, as the store keeps it.
 *
 * Structural rather than imported from src/storage/repository.ts: this module is
 * pure and must not depend on the store, and the stored row satisfies this shape
 * exactly.
 *
 * `last_skip_at` is what tells a fresh refusal from an old one. The store keeps
 * the last skip a step ever made, so a reason alone cannot say whether the step
 * refused on this run or last week; a `last_skip_at` equal to `last_run_at`
 * says it was this run.
 */
export interface SweepStep {
  readonly step: string;
  readonly last_run_at: string;
  readonly last_ok_at: string | null;
  readonly last_skip_reason: string | null;
  readonly last_skip_at: string | null;
  readonly detail: Record<string, unknown>;
  readonly trigger: string;
}

/** The newest `pool_snapshot` in the log. */
export interface SnapshotFact {
  readonly seq: number;
  readonly at: string;
  readonly operators: readonly string[];
}

/** The newest seal, with the two things the page asks of it. */
export interface SealFact {
  readonly seq: number;
  readonly last_seq: number;
  readonly sealed_at: string;
  readonly witnesses: number;
}

/** The newest `read_count` event. */
export interface ReadCountFact {
  readonly seq: number;
  readonly date: string;
  readonly total: number;
  readonly at: string;
}

/** Yesterday's anchor, and whether anything outside has timestamped it. */
export interface AnchorFact {
  readonly date: string;
  /** The external receipt's kind, or null when nothing has posted the hash. */
  readonly external: string | null;
  /**
   * Whether that receipt has been upgraded: the calendar's promise replaced by
   * a proof that reaches a Bitcoin block. Optional, and absent reads as false —
   * a receipt is pending until something says otherwise.
   */
  readonly upgraded?: boolean;
}

/**
 * The newest anchor whose OpenTimestamps proof has been upgraded: the day it
 * covers, the Bitcoin block the commitment reached, and when the sweep recorded
 * it. Structural, like every other fact here, so nothing is imported from the
 * store.
 */
export interface UpgradedAnchorFact {
  readonly date: string;
  readonly block_height: number;
  readonly upgraded_at: string;
}

/** The newest daily reconciliation the ledger wrote. */
export interface ReconciliationFact {
  readonly date: string;
  readonly ok: boolean;
  readonly at: string;
}

/**
 * The five doors nobody probes on a schedule: what the last person through each
 * one left behind.
 */
export interface ExercisedFacts {
  readonly submission: { readonly at: string; readonly id: string } | null;
  readonly registration:
    | { readonly at: string; readonly operator: string }
    | null;
  readonly read_receipt:
    | { readonly counter: number; readonly created_at: string }
    | null;
  readonly sync_receipt:
    | { readonly counter: number; readonly created_at: string }
    | null;
  readonly payout:
    | { readonly at: string; readonly operator: string; readonly amount: number }
    | null;
}

/**
 * Everything the status rules read, gathered once.
 *
 * One argument rather than a database handle: the gatherer
 * (src/worker/status.ts, `statusInput`) asks every question with an explicit
 * limit, and the rules below see only the answers. That is what lets the JSON
 * route and the page render from the same facts and be tested from fixtures.
 */
export interface StatusInput {
  /** `local`, `demo` or `production`, straight from the binding. */
  readonly environment: string;
  /** Which witness track this environment runs: mock, registry or unavailable. */
  readonly witness_kind: string;
  /** Which payout adapter this environment runs: mock or unavailable. */
  readonly payout_kind: string;
  readonly steps: readonly SweepStep[];
  readonly head_seq: number | null;
  readonly seal: SealFact | null;
  readonly seals: { readonly total: number; readonly witnessed: number };
  readonly unsealed: {
    readonly count: number;
    readonly oldest_at: string | null;
  };
  readonly pool: {
    readonly snapshot: SnapshotFact | null;
    readonly trusted: readonly string[];
    readonly registered: number;
  };
  readonly assignments: {
    /** Open assignments already past ASSIGNMENT_WINDOW_HOURS. */
    readonly overdue: number;
    readonly drafts: number;
  };
  readonly entries: number;
  readonly read_counts: {
    readonly newest: ReadCountFact | null;
    /** The first UTC day any receipt was issued on, or null when none was. */
    readonly earliest_receipt_day: string | null;
  };
  readonly anchor: AnchorFact | null;
  /**
   * The newest anchor whose external proof has reached a Bitcoin block, newest
   * by day, or null when none has.
   *
   * Beside `anchor` rather than inside it because it answers a different
   * question. `anchor` is yesterday's, and yesterday's proof is pending on most
   * days — a calendar folds commitments into a block on its own schedule. A
   * reader who saw only yesterday could not tell a chain that has never
   * completed a timestamp from one that completed the day before, so the page
   * names the newest finished proof and the block that holds it.
   */
  readonly upgraded_anchor: UpgradedAnchorFact | null;
  /** How many seals were sealed yesterday: whether an anchor was owed at all. */
  readonly seals_yesterday: number;
  readonly reconciliation: ReconciliationFact | null;
  /** The position the standing step last recomputed at, or null. */
  readonly standing_position: number | null;
  readonly attestations: { readonly due: number; readonly total: number };
  /**
   * The daily log mirror (M23): which track this environment runs, and the
   * newest export if there is one.
   *
   * `kind` is asked of the same `mirrorKindFor` the sweep asks, so the page
   * cannot claim a repository the sweep is not pushing to.
   */
  readonly mirror: {
    readonly kind: MirrorKind;
    readonly newest: {
      readonly date: string;
      readonly exported_at: string;
      readonly commit: string;
      readonly head: number;
      readonly url: string;
    } | null;
  };
  /**
   * Usage metering (M24): which payment track this environment runs, how many
   * key-days have been reported, and how many published ones have not.
   *
   * `kind` is asked of the same `paymentsAdapterFor` the sweep asks, so the page
   * cannot claim a provider the sweep is not billing through.
   */
  readonly metering: {
    readonly kind: PaymentsKind;
    readonly reported_days: number;
    readonly owed: number;
  };
  /**
   * Change alerts (M24): how many endpoints are subscribed, how far the alert
   * step has read over the sealed log, and what is waiting or has given up.
   */
  readonly alerts: {
    readonly endpoints: number;
    readonly cursor: number;
    readonly due: number;
    readonly failed: number;
  };
  readonly exercised: ExercisedFacts;
}

// ---------------------------------------------------------------------------
// What the rules answer
// ---------------------------------------------------------------------------

/**
 * The four readings.
 *
 * `idle` is not a fourth degree of broken: it says the stage has nothing to do
 * yet, which on a log with no entries is most of them. It is counted with `ok`
 * wherever a fraction is shown, because a stage that is not owed anything is not
 * behind on anything.
 */
export type StageState = "ok" | "attention" | "failing" | "idle";

/** A link a reader follows to check a stage for themselves. */
export interface StageEvidence {
  readonly label: string;
  readonly href: string;
}

/** One stage of the machine, read. */
export interface Stage {
  readonly stage: string;
  readonly state: StageState;
  /** One short line: the last thing that happened in this stage. */
  readonly last: string;
  /** The rule the state was decided by, in words. */
  readonly rule: string;
  readonly evidence: readonly StageEvidence[];
}

/**
 * A door that is exercised rather than probed: the log has no timer for it, so
 * the evidence that it works is the last time somebody used it.
 */
export interface Exercised {
  readonly stage: string;
  readonly last: string;
  readonly evidence: readonly StageEvidence[];
}

/**
 * The page's four headline counters.
 *
 * Numbers rather than sentences, because the page and the endpoint say them
 * differently: a reader sees "11 / 12 · all ok" laid out in tiles and an agent
 * parsing the endpoint wants the two integers. The one field that is words is
 * `lastSweepAge`, because a duration's only honest rendering is a rounded one
 * and rounding it twice would be two answers.
 *
 * Every number here is read off the same stages the table shows, so a tile and a
 * row can never disagree about whether something is wrong.
 */
export interface Counter {
  /** The last sweep run, ISO, null when the sweep has never run here. */
  readonly lastSweepAt: string | null;
  /** How long ago that was, in words: "2 min ago". Null with no run. */
  readonly lastSweepAge: string | null;
  /**
   * Which timer ran it, off the row. "alarm" for every run the sweep makes now;
   * a row left by the retired cron door still reads "cron". Null with no run.
   */
  readonly lastSweepTrigger: string | null;
  /**
   * Stages reading ok, with idle counted among them: a stage that is owed
   * nothing is not behind on anything, and a page that called an empty log
   * one-thirteenth working would be reporting the traffic rather than the
   * machine.
   */
  readonly stagesOk: number;
  readonly stagesTotal: number;
  readonly stagesFailing: number;
  readonly stagesAttention: number;
  /** The newest seal's last covered event seq, null before anything is sealed. */
  readonly sealedHead: number | null;
  readonly newestSealSeq: number | null;
  /** Events the newest seal does not cover yet. */
  readonly unsealedEvents: number;
  readonly seals: number;
  readonly witnessedSeals: number;
  /** "mock witnesses on demo" or "registry witnesses". */
  readonly witnessKind: string;
}

// ---------------------------------------------------------------------------
// Time, in whole seconds
// ---------------------------------------------------------------------------

const MILLISECONDS_PER_SECOND = 1000;
const SECONDS_PER_MINUTE = 60;

/** Whole seconds from `from` to `to`, floored at zero, and zero for a nonsense pair. */
function secondsBetween(from: string, to: string): number {
  const seconds = Math.floor(
    (Date.parse(to) - Date.parse(from)) / MILLISECONDS_PER_SECOND,
  );
  if (!Number.isFinite(seconds)) return 0;
  return seconds < 0 ? 0 : seconds;
}

/** A threshold in minutes, as whole seconds. */
function minutesInSeconds(minutes: number): number {
  return minutes * SECONDS_PER_MINUTE;
}

/** How long a stage on this cadence may fall behind before it wants attention. */
function attentionWindow(intervalMinutes: number): number {
  return minutesInSeconds(STATUS_ATTENTION_AFTER_INTERVALS * intervalMinutes);
}

/** How long any broken rule may stand before the page calls it failing. */
const FAILING_AFTER_SECONDS = minutesInSeconds(STATUS_FAILING_AFTER_MINUTES);

/** An instant as "HH:MM:SS UTC", or "—" when it does not parse. */
export function clockOf(at: string): string {
  const milliseconds = Date.parse(at);
  if (Number.isNaN(milliseconds)) return "—";
  return `${new Date(milliseconds).toISOString().slice(11, 19)} UTC`;
}

/** Whole minutes since `at`, as "n min ago". */
export function agoOf(at: string, now: string): string {
  const minutes = Math.floor(secondsBetween(at, now) / SECONDS_PER_MINUTE);
  return `${minutes} min ago`;
}

/** The page's one time format: the clock, then how long ago it was. */
export function stamp(at: string, now: string): string {
  return `${clockOf(at)} · ${agoOf(at, now)}`;
}

/** The UTC day before the one `at` falls on. */
function yesterdayOf(at: string): string {
  const MILLISECONDS_PER_DAY = 86_400_000;
  return utcDay(new Date(Date.parse(at) - MILLISECONDS_PER_DAY).toISOString());
}

/** The parts of a `last` line, joined the one way the page joins them. */
function line(...parts: readonly string[]): string {
  return parts.filter((part) => part !== "").join(" · ");
}

// ---------------------------------------------------------------------------
// Reading the sweep's step rows
// ---------------------------------------------------------------------------

/** One step by name, or null when no run has ever reached it. */
function stepOf(input: StatusInput, name: string): SweepStep | null {
  return input.steps.find((step) => step.step === name) ?? null;
}

/**
 * The reason this step refused on its most recent run, or null.
 *
 * The store keeps the last skip a step ever made, so the reason alone cannot say
 * when it was made. A `last_skip_at` equal to `last_run_at` is this run's.
 */
function freshSkip(step: SweepStep | null): string | null {
  if (step === null) return null;
  if (step.last_skip_at !== step.last_run_at) return null;
  return step.last_skip_reason;
}

/** A string out of a step's detail, or null when it carries none. */
function detailText(step: SweepStep | null, key: string): string | null {
  if (step === null) return null;
  const value = step.detail[key];
  return typeof value === "string" ? value : null;
}

/** A number out of a step's detail, or null when it carries none. */
function detailNumber(step: SweepStep | null, key: string): number | null {
  if (step === null) return null;
  const value = step.detail[key];
  return typeof value === "number" ? value : null;
}

// ---------------------------------------------------------------------------
// The fifteen rules
// ---------------------------------------------------------------------------

/**
 * A policy constant, named in a rule.
 *
 * A rule quotes the number it applies by name — a reader who wants the value
 * follows the /policy link rather than trusting a figure copied into a sentence.
 * The key is typed against POLICY, so the compiler checks every name a rule
 * prints: renaming a constant in src/policy.ts breaks the build here rather than
 * leaving stale wording on the page. Where a rule does say a number out loud it
 * is interpolated from src/policy.ts too, never typed out.
 */
function policyName(key: keyof typeof POLICY): string {
  return key;
}

/** Two pools, compared as sets of names. */
function samePool(
  left: readonly string[],
  right: readonly string[],
): boolean {
  const one = [...new Set(left)].sort();
  const two = [...new Set(right)].sort();
  return one.length === two.length && one.every((name, at) => name === two[at]);
}

/**
 * The draw refusals that mean no draw was owed.
 *
 * src/assign.ts's `drawDue` answers these when the entry is not waiting on a
 * draw at all — it is not a draft, the pool is under the switch, an assignment
 * is already open, or the volunteers have not come in yet. A run whose only
 * refusal is one of these did exactly what the rule says, so the stage is ok.
 * Every other refusal is a draw that was owed and did not happen.
 */
const DRAW_NOT_OWED: ReadonlySet<string> = new Set([
  "not_draft",
  "pool_below_switch",
  "assignment_open",
  "awaiting_volunteers",
]);

/** The two ways the beacon read can fail (src/adapters/beacon.ts). */
const BEACON_REFUSALS: ReadonlySet<string> = new Set([
  "beacon_unavailable",
  "bad_beacon",
]);

function sweepTimer(input: StatusInput, now: string): Stage {
  const rule = `a run within ${STATUS_ATTENTION_AFTER_INTERVALS} × ${policyName("SWEEP_INTERVAL_MINUTES")}`;
  const evidence = [{ label: "/status", href: "/status" }];
  const step = stepOf(input, "sweep");
  if (step === null) {
    return { stage: "sweep timer", state: "idle", last: "never", rule, evidence };
  }
  const age = secondsBetween(step.last_run_at, now);
  const state: StageState =
    age > FAILING_AFTER_SECONDS
      ? "failing"
      : age > attentionWindow(SWEEP_INTERVAL_MINUTES)
        ? "attention"
        : "ok";
  return {
    stage: "sweep timer",
    state,
    last: line(stamp(step.last_run_at, now), step.trigger),
    rule,
    evidence,
  };
}

function poolSnapshot(input: StatusInput, now: string): Stage {
  const rule = "the newest snapshot equals the trusted pool";
  const { snapshot, trusted, registered } = input.pool;
  const evidence = [
    ...(snapshot === null
      ? []
      : [{ label: `/events/${snapshot.seq}`, href: `/events/${snapshot.seq}` }]),
    { label: "/operators", href: "/operators" },
  ];
  if (registered === 0) {
    return {
      stage: "pool snapshot",
      state: "idle",
      last: "no operator registered",
      rule,
      evidence,
    };
  }
  if (snapshot === null) {
    return {
      stage: "pool snapshot",
      state: "attention",
      last: line("no snapshot yet", `${trusted.length} trusted`),
      rule,
      evidence,
    };
  }
  const agrees = samePool(snapshot.operators, trusted);
  return {
    stage: "pool snapshot",
    state: agrees ? "ok" : "attention",
    last: line(
      `seq ${snapshot.seq}`,
      stamp(snapshot.at, now),
      `${snapshot.operators.length} operators`,
    ),
    rule,
    evidence,
  };
}

function beacon(input: StatusInput, now: string): Stage {
  const rule = "the newest round read is after the newest snapshot";
  const evidence = [{ label: "/policy", href: "/policy" }];
  const step = stepOf(input, "draws");
  const round = detailNumber(step, "beacon_round");
  const at = detailText(step, "beacon_at");
  const reason = detailText(step, "beacon_reason");
  if (step === null || (round === null && reason === null)) {
    return { stage: "beacon", state: "idle", last: "never", rule, evidence };
  }

  if (reason !== null && BEACON_REFUSALS.has(reason)) {
    // Since the last round that did come back, or since this run when none ever
    // has: a beacon that has never answered has been failing for as long as
    // anyone has been asking.
    const since = step.last_ok_at ?? step.last_run_at;
    const failingFor = secondsBetween(since, now);
    return {
      stage: "beacon",
      state: failingFor > FAILING_AFTER_SECONDS ? "failing" : "attention",
      last: line(reason, stamp(step.last_run_at, now)),
      rule,
      evidence,
    };
  }

  const stale =
    secondsBetween(step.last_run_at, now) >
    attentionWindow(SWEEP_INTERVAL_MINUTES);
  // A round older than the snapshot it would be drawn against is the rule
  // working — src/assign.ts refuses that draw with `snapshot_after_beacon` —
  // but it is also a draw that will not happen until the next round, which is
  // something the page says out loud.
  const snapshot = input.pool.snapshot;
  const behindSnapshot =
    at !== null && snapshot !== null && Date.parse(at) <= Date.parse(snapshot.at);
  return {
    stage: "beacon",
    state: stale || behindSnapshot ? "attention" : "ok",
    last: line(
      round === null ? "no round" : `round ${round}`,
      at === null ? stamp(step.last_run_at, now) : stamp(at, now),
    ),
    rule,
    evidence,
  };
}

function drawsAndDeadlines(input: StatusInput, now: string): Stage {
  const rule = `every due draw made; no assignment past ${policyName("ASSIGNMENT_WINDOW_HOURS")} unmarked`;
  const step = stepOf(input, "draws");
  const snapshot = input.pool.snapshot;
  const href =
    snapshot === null ? "/events" : `/events?after=${String(snapshot.seq)}`;
  const evidence = [{ label: "/events", href }];
  const { drafts, overdue } = input.assignments;
  if (drafts === 0) {
    return {
      stage: "draws and deadlines",
      state: "idle",
      last: "no draft entry",
      rule,
      evidence,
    };
  }
  const refusal = freshSkip(step);
  const owedAndSkipped = refusal !== null && !DRAW_NOT_OWED.has(refusal);
  const drawn = detailNumber(step, "drawn") ?? 0;
  return {
    stage: "draws and deadlines",
    state: owedAndSkipped || overdue > 0 ? "attention" : "ok",
    last: line(
      `${drafts} draft`,
      `${drawn} drawn`,
      `${overdue} past deadline`,
      step === null ? "" : stamp(step.last_run_at, now),
    ),
    rule,
    evidence,
  };
}

function staleness(input: StatusInput, now: string): Stage {
  const rule = "every row past its window marked stale";
  const evidence = [{ label: "/entries?fresh=stale", href: "/entries?fresh=stale" }];
  const step = stepOf(input, "staleness");
  if (input.entries === 0) {
    return { stage: "staleness", state: "idle", last: "no entry", rule, evidence };
  }
  const refusal = freshSkip(step);
  const staled = detailNumber(step, "staled") ?? 0;
  return {
    stage: "staleness",
    state: refusal === null ? "ok" : "attention",
    last: line(
      `${staled} rewritten`,
      refusal ?? "",
      step === null ? "never run" : stamp(step.last_run_at, now),
    ),
    rule,
    evidence,
  };
}

function readCounts(input: StatusInput, now: string): Stage {
  const rule = "yesterday's read_count sealed";
  const { newest, earliest_receipt_day } = input.read_counts;
  const evidence = [
    newest === null
      ? { label: "/events", href: "/events" }
      : { label: `/events/${newest.seq}`, href: `/events/${newest.seq}` },
  ];
  const yesterday = yesterdayOf(now);
  // Nothing is owed until a receipt exists on a day that is over: a log whose
  // first read was served this morning owes no count yet.
  const owed =
    earliest_receipt_day !== null && earliest_receipt_day <= yesterday
      ? yesterday
      : null;
  if (owed === null) {
    return {
      stage: "read counts",
      state: "idle",
      last: earliest_receipt_day === null ? "no receipt yet" : "no day owed yet",
      rule,
      evidence,
    };
  }
  if (newest === null) {
    return {
      stage: "read counts",
      state: "attention",
      last: line("never", `${owed} owed`),
      rule,
      evidence,
    };
  }
  return {
    stage: "read counts",
    state: newest.date >= owed ? "ok" : "attention",
    last: line(newest.date, `${newest.total} reads`, `seq ${newest.seq}`),
    rule,
    evidence,
  };
}

function sealing(input: StatusInput, now: string): Stage {
  const rule = `the newest seal younger than ${STATUS_ATTENTION_AFTER_INTERVALS} × ${policyName("SEAL_INTERVAL_MINUTES")}; no unsealed event older`;
  const { seal, unsealed } = input;
  const evidence = [
    seal === null
      ? { label: "/seals", href: "/seals" }
      : { label: `/seals/${seal.seq}`, href: `/seals/${seal.seq}` },
  ];
  if (input.head_seq === null) {
    return { stage: "sealing", state: "idle", last: "no event", rule, evidence };
  }
  const window = attentionWindow(SEAL_INTERVAL_MINUTES);
  const waiting =
    unsealed.oldest_at === null ? null : secondsBetween(unsealed.oldest_at, now);
  const sealAge = seal === null ? null : secondsBetween(seal.sealed_at, now);

  const state: StageState =
    waiting !== null && waiting > FAILING_AFTER_SECONDS
      ? "failing"
      : (sealAge !== null && sealAge <= window) ||
          waiting === null ||
          waiting <= window
        ? "ok"
        : "attention";
  return {
    stage: "sealing",
    state,
    last: line(
      seal === null ? "no seal" : `seal ${seal.seq}`,
      seal === null ? "" : stamp(seal.sealed_at, now),
      `${unsealed.count} unsealed`,
    ),
    rule,
    evidence,
  };
}

function witnessing(input: StatusInput, now: string): Stage {
  const rule = `the newest seal countersigned by ${policyName("WITNESSES_REQUIRED")} pinned witnesses`;
  const { seal } = input;
  const evidence = [
    ...(seal === null
      ? [{ label: "/seals", href: "/seals" }]
      : [{ label: `/seals/${seal.seq}`, href: `/seals/${seal.seq}` }]),
    { label: "/policy", href: "/policy" },
  ];
  if (seal === null) {
    return { stage: "witnessing", state: "idle", last: "no seal", rule, evidence };
  }
  const enough = seal.witnesses >= WITNESSES_REQUIRED;
  const age = secondsBetween(seal.sealed_at, now);
  const state: StageState = enough
    ? "ok"
    : age > FAILING_AFTER_SECONDS
      ? "failing"
      : "attention";
  return {
    stage: "witnessing",
    state,
    last: line(
      `seal ${seal.seq}`,
      `${seal.witnesses}/${WITNESSES_REQUIRED} witnesses`,
      stamp(seal.sealed_at, now),
    ),
    rule,
    evidence,
  };
}

const PRODUCTION_ENVIRONMENT = "production";

/**
 * The newest finished proof, as one segment of the anchoring line, or "" when
 * nothing has been upgraded yet.
 *
 * Every state of the stage carries it, idle included: a day with no seal to
 * anchor says nothing about whether the chain the anchors go to is working, and
 * the block height is the one number in this stage a reader can check against
 * something that is not ours. It changes no state — a pending proof is still
 * not a fault — so it is a reading appended to whatever the state's own line
 * already said.
 */
function upgradeNote(input: StatusInput): string {
  const upgrade = input.upgraded_anchor;
  if (upgrade === null) return "";
  return `newest upgrade ${upgrade.date} · block ${upgrade.block_height}`;
}

function anchoring(input: StatusInput, now: string): Stage {
  const rule = "yesterday's anchor exists; posted to OpenTimestamps on production";
  const yesterday = yesterdayOf(now);
  const upgrade = upgradeNote(input);
  const evidence = [
    { label: `/anchors/${yesterday}`, href: `/anchors/${yesterday}` },
  ];
  if (input.seals_yesterday === 0) {
    return {
      stage: "anchoring",
      state: "idle",
      last: line(yesterday, "no seal that day", upgrade),
      rule,
      evidence,
    };
  }
  const anchor = input.anchor;
  if (anchor === null) {
    // Owed, and missing. Whether that is worth saying depends on whether the
    // sweep has had a chance today: before the first run of the day nothing has
    // been skipped, only not yet done.
    const sweep = stepOf(input, "sweep");
    const ranToday = sweep !== null && utcDay(sweep.last_run_at) === utcDay(now);
    return {
      stage: "anchoring",
      state: ranToday ? "attention" : "ok",
      last: line(yesterday, "not anchored", upgrade),
      rule,
      evidence,
    };
  }
  // Only production has an outside chain to be in. Everywhere else the anchor is
  // the day's roots and their hash, and an absent external record is the
  // environment rather than a fault.
  const needsExternal = input.environment === PRODUCTION_ENVIRONMENT;
  const state: StageState =
    needsExternal && anchor.external === null ? "attention" : "ok";
  return {
    stage: "anchoring",
    state,
    last: line(
      anchor.date,
      anchor.external === null ? "no external record" : anchor.external,
      // Named rather than counted: the difference between a calendar's promise
      // and a block that holds the commitment is the whole point of anchoring,
      // and a board that showed both as "opentimestamps" would hide it. Not a
      // state change — a pending proof is not a fault, only unfinished.
      anchor.external !== null && anchor.upgraded === true ? "upgraded" : "",
      // Even when the upgraded one is yesterday's own: "upgraded" says which
      // anchor finished and the segment says which block it reached, and a
      // reader who saw only the word would have nothing to check.
      upgrade,
    ),
    rule,
    evidence,
  };
}

function ledger(input: StatusInput, now: string): Stage {
  const rule = "yesterday's reconciliation row present and equal";
  const evidence = [{ label: "/ledger", href: "/ledger" }];
  const published = input.read_counts.newest;
  if (published === null) {
    return {
      stage: "ledger",
      state: "idle",
      last: "no read count",
      rule,
      evidence,
    };
  }
  const row = input.reconciliation;
  // The day the ledger owes a reconciliation for is the day the log published a
  // count for, not the calendar's yesterday: the ledger prices what the seal
  // committed to, so it cannot be ahead of the publishing step.
  if (row === null || row.date !== published.date) {
    return {
      stage: "ledger",
      state: "attention",
      last: line(published.date, row === null ? "never" : `last ${row.date}`),
      rule,
      evidence,
    };
  }
  return {
    stage: "ledger",
    state: row.ok ? "ok" : "failing",
    last: line(row.date, row.ok ? "agrees" : "disagrees", stamp(row.at, now)),
    rule,
    evidence,
  };
}

function standing(input: StatusInput, now: string): Stage {
  const rule = "standing stored at the sealed head";
  const evidence = [{ label: "/standing", href: "/standing" }];
  const head = input.seal === null ? null : input.seal.last_seq;
  if (input.pool.registered === 0) {
    return {
      stage: "standing",
      state: "idle",
      last: "no operator",
      rule,
      evidence,
    };
  }
  if (head === null) {
    // Section 9's three money steps read sealed events only, so before the first
    // seal there is nothing for standing to be behind on.
    return { stage: "standing", state: "idle", last: "nothing sealed", rule, evidence };
  }
  const position = input.standing_position;
  const step = stepOf(input, "standing");
  return {
    stage: "standing",
    state: position === head ? "ok" : "attention",
    last: line(
      position === null ? "never recomputed" : `position ${position}`,
      `sealed head ${head}`,
      step === null ? "" : stamp(step.last_run_at, now),
    ),
    rule,
    evidence,
  };
}

function attestations(input: StatusInput): Stage {
  const rule = `no open attestation past ${policyName("ATTESTATION_WINDOW_HOURS")}`;
  const evidence = [{ label: "/attestations", href: "/attestations" }];
  const { due, total } = input.attestations;
  if (total === 0) {
    return {
      stage: "attestations",
      state: "idle",
      last: "none yet",
      rule,
      evidence,
    };
  }
  return {
    stage: "attestations",
    state: due > 0 ? "attention" : "ok",
    last: line(`${total} in the log`, `${due} past deadline`),
    rule,
    evidence,
  };
}

/**
 * (13) The day's export to the public mirror.
 *
 * Whitepaper Section 11: the sealed log goes out daily to a public repository
 * under CC0, and the Conclusion makes it the exit right — "the exit is not a
 * promise, it is a copy". So the question is exactly "is today's copy there",
 * and the two ways it can be no are different: an environment with no token is
 * not configured to mirror at all, and an environment that has not reached
 * today's export yet is owed one rather than behind on one.
 *
 * The grace is STATUS_FAILING_AFTER_MINUTES from today's 00:00 UTC, reused
 * rather than given a number of its own: the export is owed once a day and the
 * page already has one bar for how long a broken rule may stand.
 */
function mirrorExport(input: StatusInput, now: string): Stage {
  const rule = "today's export committed to the mirror repository";
  const newest = input.mirror.newest;
  const evidence: StageEvidence[] = [
    { label: "/mirror/latest", href: "/mirror/latest" },
    ...(newest === null ? [] : [{ label: "commit", href: newest.url }]),
  ];

  if (input.mirror.kind === "unavailable") {
    return {
      stage: "mirror export",
      state: "idle",
      last: "not configured",
      rule,
      evidence,
    };
  }
  if (input.seal === null) {
    // The mirror is the sealed record, so a log with nothing sealed is owed no
    // export at all.
    return {
      stage: "mirror export",
      state: "idle",
      last: "nothing sealed",
      rule,
      evidence,
    };
  }

  const today = utcDay(now);
  if (newest !== null && newest.date === today) {
    return {
      stage: "mirror export",
      state: "ok",
      last: line(newest.date, stamp(newest.exported_at, now), `head ${newest.head}`),
      rule,
      evidence,
    };
  }

  // Owed, and not there. Whether that is worth saying depends on how far into
  // the day it is: the first half hour of a UTC day is a run that has not come
  // round yet rather than one that is missing.
  const sinceMidnight = secondsBetween(`${today}T00:00:00.000Z`, now);
  const reason = freshSkip(stepOf(input, "mirror"));
  return {
    stage: "mirror export",
    state: sinceMidnight <= FAILING_AFTER_SECONDS ? "attention" : "failing",
    last: line(
      today,
      sinceMidnight <= FAILING_AFTER_SECONDS
        ? "owed, not yet"
        : (reason ?? "not exported"),
      newest === null ? "no export yet" : `last ${newest.date}`,
    ),
    rule,
    evidence,
  };
}

/**
 * (14) The usage meter: is every published paid read on somebody's bill?
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily, so nomankind cannot quietly change the numbers later, and any operator
 * can reconcile their payout against the log." The bill is the other side of
 * that sentence, and this is the light that says whether the two are in step: a
 * key-day the log published and the provider was never told about is revenue
 * the reader was not charged for, and — worse for the reader — a number that
 * could later be billed from somewhere other than the published count.
 *
 * Two kinds of nothing to do, told apart. An environment with no payment
 * provider is not configured to meter at all, which is production's state until
 * M25 and is not a fault; an environment that has published no paid read has
 * nothing to report, which is every deployment before its first key.
 */
function usageMetering(input: StatusInput, now: string): Stage {
  const rule = "every published paid read reported to the provider";
  const evidence = [{ label: "/status", href: "/status" }];
  const { kind, reported_days, owed } = input.metering;

  if (kind === "unavailable") {
    return {
      stage: "usage metering",
      state: "idle",
      last: "not configured",
      rule,
      evidence,
    };
  }
  if (reported_days === 0 && owed === 0) {
    return {
      stage: "usage metering",
      state: "idle",
      last: "no paid read",
      rule,
      evidence,
    };
  }

  const step = stepOf(input, "metering");
  if (owed === 0) {
    return {
      stage: "usage metering",
      state: "ok",
      last: line(
        `${reported_days} key-days reported`,
        step === null ? "" : stamp(step.last_run_at, now),
      ),
      rule,
      evidence,
    };
  }

  // Owed, and not reported. How long that has stood is the step's own record of
  // when it last got through, exactly as the ledger stage reads its day: a
  // provider that refused one run is a run to try again, and one that has been
  // refusing since before the failing bar is somebody's morning.
  const lastOk = step === null ? null : step.last_ok_at;
  const stale = lastOk !== null && secondsBetween(lastOk, now) > FAILING_AFTER_SECONDS;
  return {
    stage: "usage metering",
    state: stale ? "failing" : "attention",
    last: line(
      `${owed} key-days owed`,
      freshSkip(step) ?? `${reported_days} reported`,
      step === null ? "never run" : stamp(step.last_run_at, now),
    ),
    rule,
    evidence,
  };
}

/**
 * (15) The change alerts: has every sealed change been offered to everyone who
 * asked for it?
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts." A subscriber pays to hear
 * about a change rather than to poll for it, so the question here is whether the
 * step has read the sealed log to its head and whether anything it built is
 * still waiting.
 *
 * A delivery that gave up is named in the line and changes no light. An endpoint
 * that answers 500 five times is that endpoint's fault and its operator's to
 * fix, and a status page that went red for it would be reporting somebody
 * else's outage as nomankind's.
 */
function changeAlerts(input: StatusInput, now: string): Stage {
  const rule = "every sealed change delivered to every subscribed endpoint";
  const evidence = [{ label: "/api", href: "/api" }];
  const { endpoints, cursor, due, failed } = input.alerts;
  const failedNote = failed === 0 ? "" : `${failed} failed`;

  if (endpoints === 0) {
    return {
      stage: "change alerts",
      state: "idle",
      last: line("no endpoint", failedNote),
      rule,
      evidence,
    };
  }
  if (input.seal === null) {
    return {
      stage: "change alerts",
      state: "idle",
      last: line("nothing sealed", failedNote),
      rule,
      evidence,
    };
  }

  const head = input.seal.last_seq;
  const step = stepOf(input, "alerts");
  if (cursor === head && due === 0) {
    return {
      stage: "change alerts",
      state: "ok",
      last: line(
        `${endpoints} endpoints`,
        `read to ${head}`,
        failedNote,
        step === null ? "" : stamp(step.last_run_at, now),
      ),
      rule,
      evidence,
    };
  }

  const lastOk = step === null ? null : step.last_ok_at;
  const stale = lastOk !== null && secondsBetween(lastOk, now) > FAILING_AFTER_SECONDS;
  return {
    stage: "change alerts",
    state: stale ? "failing" : "attention",
    last: line(
      `${endpoints} endpoints`,
      cursor === head ? `read to ${head}` : `read to ${cursor} of ${head}`,
      due === 0 ? "" : `${due} due`,
      failedNote,
      step === null ? "never run" : stamp(step.last_run_at, now),
    ),
    rule,
    evidence,
  };
}

/**
 * The fifteen stages, in the page's order, read against one instant.
 *
 * The order is the machine's own — the timer, then what the timer does, then
 * what the log owes at the end of the day — and it is fixed, because a status
 * page whose rows move around is a status page nobody learns to read.
 */
export function stageStates(input: StatusInput, now: string): Stage[] {
  return [
    sweepTimer(input, now),
    poolSnapshot(input, now),
    beacon(input, now),
    drawsAndDeadlines(input, now),
    staleness(input, now),
    readCounts(input, now),
    sealing(input, now),
    witnessing(input, now),
    anchoring(input, now),
    ledger(input, now),
    standing(input, now),
    attestations(input),
    mirrorExport(input, now),
    usageMetering(input, now),
    changeAlerts(input, now),
  ];
}

/** How many stages there are, for a fraction that cannot drift from the list. */
export const STAGE_COUNT = 15;

// ---------------------------------------------------------------------------
// Exercised, not probed
// ---------------------------------------------------------------------------

/**
 * The five doors with no timer behind them.
 *
 * Nothing here has a state. A door nobody has used is not broken, and a page
 * that painted it red would be reporting the traffic rather than the machine —
 * so these rows say when each was last used and link to what it left behind, and
 * stop there.
 */
export function exercisedStages(input: StatusInput): Exercised[] {
  const { submission, registration, read_receipt, sync_receipt, payout } =
    input.exercised;
  return [
    {
      stage: "submit and archive",
      last:
        submission === null
          ? "never"
          : line(clockOf(submission.at), submission.id),
      evidence:
        submission === null
          ? [{ label: "/entries", href: "/entries" }]
          : [
              {
                label: `/entries/${submission.id}`,
                href: `/entries/${submission.id}`,
              },
            ],
    },
    {
      stage: "registration, DNS check",
      last:
        registration === null
          ? "never"
          : line(clockOf(registration.at), registration.operator),
      evidence:
        registration === null
          ? [{ label: "/operators", href: "/operators" }]
          : [
              {
                label: `/operators/${registration.operator}`,
                href: `/operators/${registration.operator}`,
              },
            ],
    },
    {
      stage: "read receipts",
      last:
        read_receipt === null
          ? "never"
          : line(
              clockOf(read_receipt.created_at),
              `receipt ${read_receipt.counter}`,
            ),
      evidence: [{ label: "/api", href: "/api" }],
    },
    {
      stage: "sync receipts",
      last:
        sync_receipt === null
          ? "never"
          : line(
              clockOf(sync_receipt.created_at),
              `receipt ${sync_receipt.counter}`,
            ),
      evidence: [{ label: "/api", href: "/api" }],
    },
    {
      stage: "payouts",
      last:
        payout === null
          ? line(
              `never`,
              `${input.payout_kind} adapter`,
              "every operator below PAYOUT_MINIMUM_MICROS",
            )
          : line(
              clockOf(payout.at),
              payout.operator,
              `${payout.amount} micros`,
            ),
      evidence: [{ label: "/ledger", href: "/ledger" }],
    },
  ];
}

// ---------------------------------------------------------------------------
// The four counters
// ---------------------------------------------------------------------------

/** How the witness track reads in words, for the counter's note. */
function witnessNote(input: StatusInput): string {
  if (input.witness_kind === "registry") return "registry witnesses";
  if (input.witness_kind === "mock") {
    return `mock witnesses on ${input.environment}`;
  }
  return "no witness track";
}

/**
 * The four counters, computed from the same stages the table shows, so the
 * fraction and the rows can never disagree.
 */
export function statusCounters(
  stages: readonly Stage[],
  input: StatusInput,
): Counter {
  const sweep = stepOf(input, "sweep");
  const timer = stages.find((stage) => stage.stage === "sweep timer") ?? null;
  const failing = stages.filter((stage) => stage.state === "failing").length;
  const attention = stages.filter((stage) => stage.state === "attention").length;
  return {
    lastSweepAt: sweep === null ? null : sweep.last_run_at,
    lastSweepAge: sweep === null || timer === null ? null : agoPart(timer.last),
    lastSweepTrigger: sweep === null ? null : sweep.trigger,
    stagesOk: stages.length - failing - attention,
    stagesTotal: stages.length,
    stagesFailing: failing,
    stagesAttention: attention,
    sealedHead: input.seal === null ? null : input.seal.last_seq,
    newestSealSeq: input.seal === null ? null : input.seal.seq,
    unsealedEvents: input.unsealed.count,
    seals: input.seals.total,
    witnessedSeals: input.seals.witnessed,
    witnessKind: witnessNote(input),
  };
}

/**
 * The "n min ago" out of the sweep timer's own line.
 *
 * The counters take the stages rather than a second clock on purpose: an age
 * computed twice is two things that can disagree, and the sweep timer's `last`
 * already carries the age `stageStates` read against the instant it was given.
 * "0 min ago" when the line carries no age at all, which only a stage that never
 * ran can do — and that one answers "never" above instead.
 */
function agoPart(last: string): string {
  const match = /\d+ min ago/.exec(last);
  return match === null ? "0 min ago" : match[0];
}

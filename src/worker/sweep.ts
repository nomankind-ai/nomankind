/**
 * The sweep: the work that has to happen on a clock rather than on a request.
 *
 * Whitepaper, Lifecycle of an entry, Validate: "Two of the three volunteer. The
 * third is assigned from the trusted pool by public randomness. The draw is a
 * deterministic function of a public randomness beacon's output, the entry id,
 * and a published snapshot of the eligible pool. The pool snapshot is committed
 * to the sealed log before the beacon round it uses, so neither can be chosen
 * with the outcome in view, anyone can recompute who should have been drawn, and
 * neither the submitter nor the maintainer can steer it. An assigned validator
 * has seventy-two hours to respond. A miss costs standing, and the next beacon
 * round draws a replacement."
 *
 * Four steps. The first three are the paper's own order. Commit the pool
 * snapshot when the
 * sealed one no longer says what the pool is; close the assignments whose window
 * has run out; then draw for the entries that are owed a draw. The snapshot goes
 * first on purpose: a snapshot committed in this run is later than every beacon
 * round this run can read, so the draw that follows it refuses with
 * `snapshot_after_beacon` and waits for the next run. That refusal is the rule
 * working, not a failure, and the report says so by counting it.
 *
 * The fourth step is Section 7's, "Freshness and decay", and it appends nothing
 * at all: the entries whose freshness window has run out are rewritten from
 * their own events, because a window closing is a fact about the calendar and
 * the log rather than an event anyone signs.
 *
 * The fifth is Section 9's, the accounting paragraph of Money: "Read counts are
 * published to the sealed log daily ... Each day's published count is the number
 * the seal commits to." So each finished day's count goes in as an ordinary
 * event, before the seal below covers it in the same run. Yesterday is the
 * newest day it may publish, because today is not over. A log that has served no
 * reads publishes nothing at all.
 *
 * The sixth is Section 8's, "Drift attestation": a model has one window in which
 * to answer its probes and its three drawn scorers have the same one in which to
 * score them, and an attestation still waiting when the window runs out is closed
 * with an `attestation_expired` naming the scorers that never answered. It runs
 * before the seal for the same reason the read counts do. An expiry is not a
 * failing score and claims nothing about drift.
 *
 * Three more follow, and they are the Seal paragraph's: "Everything gets sealed,
 * including drafts and rejections ... with the registry head countersigned by
 * witnesses nomankind does not control ... at an initial interval of five
 * minutes set by policy", and the hardening beside it, "anchoring each day's
 * batch hash into an external public timestamping chain". So: seal whatever the
 * last seal did not cover, gather countersignatures for the seals still waiting
 * on the outside world, and anchor yesterday's roots once. Their order is not
 * free — a seal has to exist before it can be countersigned, and a day's roots
 * have to be fixed before that day is anchored — and each one refuses rather
 * than throws, exactly like the four before them.
 *
 * Three more close the run, and they are Section 9's, "Standing" and "Money":
 * price what the seal just committed to (read shares, clawbacks, the stale
 * bounty, the day's reconciliation), recompute every operator's standing by the
 * published formula and let it move the trusted pool, and pay the cycle. All
 * three read SEALED events only — through the latest seal's last_seq, this
 * run's own seal included — because a number computed off an event the log has
 * not committed to could be recomputed differently later, and Section 9's
 * promise that anyone can recompute standing and reconcile a payout against the
 * log would be worth nothing. Before the first seal they refuse with `unsealed`.
 *
 * The last one is not the paper's at all: it is the index's. Migration 0019
 * made the duplicate rule a column, and the rows written before it carry none,
 * so a bounded page of them is recomputed from their own signed cores each run
 * until the log has none left. It appends nothing, reads no seal, and once the
 * backlog is caught up it is one read that finds nothing.
 *
 * Nothing here decides anything. Whether a snapshot is owed, whether a draw is
 * owed, who is drawn, which operators are excluded, and when a window has run
 * out are all src/assign.ts's pure functions; the writers in
 * src/storage/repository.ts append the events and keep the rows that index
 * them. This file only gathers the facts, in order, and records what happened.
 *
 * No wall clock and no network of its own: the instant and the beacon both
 * arrive as arguments, so a test runs this exact function against a fixture
 * beacon and a fake clock (decision D-013 as amended keeps the fake out of the
 * deployed path — src/worker/index.ts constructs the real DrandReader).
 *
 * No policy number lives here: the seventy-two hours are ASSIGNMENT_WINDOW_HOURS
 * inside src/assign.ts, the pool switch is TRUSTED_POOL_SWITCH inside the same,
 * and the page size LIST_PAGE_LIMIT, the batch ceiling SEAL_MAX_EVENTS and the
 * witness bar WITNESSES_REQUIRED all come from src/policy.ts.
 */

import type { BeaconReader } from "../adapters/beacon.js";
import type { MirrorAdapter } from "../adapters/mirror.js";
import type { PayoutAdapter } from "../adapters/payout.js";
import type { EnvironmentWitnessAdapter } from "../adapters/witness.js";
import {
  buildAnchor,
  utcDay,
  type Anchor,
  type AnchorAdapter,
  type AnchorExternal,
  type AnchorUpgradeResult,
} from "../anchor.js";
import {
  assignmentDeadline,
  buildAssignment,
  buildAssignmentMissed,
  drawChecker,
  drawDue,
  drawValidator,
  exclusionsFor,
  isAssignmentMissed,
  latestPoolSnapshot,
  openAssignment as openAssignmentOf,
  poolSnapshotDue,
  type Beacon,
} from "../assign.js";
import { attestationDue, deriveAttestation } from "../attest.js";
import { coreVersion, domainOf, extractCore } from "../core.js";
import type { BountyAccrual } from "../bounty.js";
import {
  deriveEntry,
  mayValidateEntry,
  operatorDomainsAt,
  registeredOperatorsAt,
  type EntryStatus,
  type Sidecar,
} from "../derive.js";
import { openRevalidation, revalidationDrawExclusions } from "../dispute.js";
import { duplicateKey, sameDuplicateKey } from "../duplicate.js";
import { recordMeasured } from "../evidence.js";
import {
  appendEvent,
  eventHash,
  type Event,
  type EventPayloads,
  type EventType,
  type ReadCountDuplicate,
  type ReadCountRow,
} from "../events.js";
import type { LedgerRow } from "../ledger.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  DRAW_DRAFT_MAX_AGE_DAYS,
  DUPLICATE_BACKFILL_PER_RUN,
  LEDGER_ENTRIES_PER_RUN,
  LIST_PAGE_LIMIT,
  RELEASE_WINDOW_DAYS,
  SEAL_MAX_EVENTS,
  SWEEP_INTERVAL_MINUTES,
  WITNESSES_REQUIRED,
} from "../policy.js";
import {
  MirrorError,
  buildMirror,
  type MirrorAttestationAnswers,
  type MirrorEntryRecord,
  type MirrorOperator,
} from "../mirror.js";
import { entryHash } from "../hash.js";
import { buildReadCountPayload, type PaidReadCounts } from "../receipt.js";
import { validateEntry, type Entry } from "../schema.js";
import {
  buildSeal,
  entrySeal,
  type EntrySeal,
  type Seal,
  type WitnessSignature,
} from "../seal.js";
import {
  standingAfter,
  standingAt,
  trustChangesAt,
  type Standing,
} from "../standing.js";
import type { D1Like } from "../storage/d1.js";
import {
  EventAppendError,
  SealConflictError,
  agentsForOperator,
  anchorsAfter,
  appendEvents,
  backfillDuplicateKeys,
  bountiesForEntry,
  bountyPoolRows,
  addCosignPairs,
  completeSealRewrites,
  cosignaturesForEntry,
  cosignaturesInRange,
  readCosignCursor,
  writeCosignCursor,
  type CosignDelta,
  type Cosignature,
  countAttestations,
  countEntries,
  countOperators,
  countSeals,
  countSealsSealedOn,
  countTrustedOperators,
  countWitnessedSeals,
  dueAssignments,
  dueAttestations,
  dueRevalidationAssignments,
  disputeOf,
  earliestReadReceiptDay,
  firstSealedDayIn,
  entriesThrough,
  entryCountsByDomain,
  entryHeadsThrough,
  eventBySeq,
  eventsAfter,
  eventsForAttestation,
  eventsForEntry,
  eventsInRange,
  eventsOfType,
  getEntry,
  getOperator,
  headSeq,
  heldReadShareRows,
  latestAnchor,
  latestEventOfType,
  latestSeal,
  ledgerCursor,
  listAttestations,
  listEntries,
  listOperators,
  claimMirror,
  mirrorClaimOn,
  openRevalidationAssignment,
  operatorDomains,
  operatorsDue,
  pricedEntriesOfDay,
  priceLedgerRow,
  pendingAnchorsAfter,
  putAnchor,
  putEntry,
  putLedgerRows,
  putMirror,
  putSweepSteps,
  readCandidates,
  countReceiptsOn,
  readCounterRangeOn,
  readCountsByKeyOn,
  meterReported,
  recordAssignment,
  recordAssignmentMissed,
  recordAttestationExpired,
  recordPayout,
  recordPoolSnapshot,
  recordRevalidationAssignment,
  recordRevalidationMissed,
  recordSeal,
  recordTrustChange,
  recordVersionStale,
  releasedUnpaidRows,
  sealsAfter,
  sealsSealedOn,
  setAnchorExternal,
  setLedgerCursor,
  putStandings,
  storedStandings,
  supersedersOf,
  readChainCheckState,
  trustedOperatorCountsByDomain,
  validationCountsByOperator,
  writeChainCheckState,
  writeCounters,
  writeOperatorValidationCounters,
  setSealRegistry,
  setSealWitnesses,
  staleDue,
  unpricedStakeRow,
  unwitnessedSeals,
  type Counters,
  type OperatorRecord,
  type ReadCountKeyCursor,
  type ReadCountKeyRow,
  type StoredBountyRow,
  type SweepStepRow,
  type StoredEntry,
  type StoredEntryRow,
  type StoredEntryInput,
} from "../storage/repository.js";
import { keyById } from "../storage/keys.js";
import {
  alertCursor,
  countAlertEndpoints,
  countDueDeliveries,
  countFailedDeliveries,
} from "../storage/alerts.js";
import { checkWitnesses, witnessedCount, type Witness } from "../witness.js";
import { runAlertStep, type AlertStepReport } from "./alerts.js";
import {
  ENVIRONMENT_MISCONFIGURED,
  environmentConfigured,
} from "./config.js";
import type { Env } from "./env.js";
import {
  entryWorld,
  expiredByClock,
  rederive,
  registryEvents,
  worldAt,
  worldCache,
  type WorldCache,
} from "./world.js";

/**
 * The pinned witness set an environment judges countersignatures against:
 * exactly what `pinnedWitnessesFor` answers, named structurally so this module
 * imports no value from the adapters it is handed.
 */
export interface PinnedWitnesses {
  readonly witnesses: readonly Witness[];
  readonly registry: { origin: string; public_key: string } | null;
}

/**
 * What the sweep is given in place of the world: the instant, the beacon, and —
 * for the three sealing steps — the registry and witness adapter, the pinned
 * set it judges what comes back against, nomankind's own agent ids, and the
 * external timestamping adapter.
 *
 * The four sealing deps are optional and the three steps are skipped together
 * when they are absent (`sealing_unconfigured`), which is what lets a caller ask
 * for the pre-M16 sweep alone. Nothing else changes with them: the four steps
 * before them do exactly what they always did.
 */
export interface SweepDeps {
  readonly now: Date;
  readonly beacon: BeaconReader;
  readonly witness?: EnvironmentWitnessAdapter;
  readonly pinned?: PinnedWitnesses;
  readonly ineligibleAgents?: ReadonlySet<string>;
  readonly anchor?: AnchorAdapter;
  /**
   * Accepted and ignored (D-127). The payout step is retired — the record is
   * free, so a cycle has nothing to pay — and no run reads this. It stays in
   * the shape so a caller that still names an adapter is passing something
   * dead rather than failing to compile.
   */
  readonly payout?: PayoutAdapter;
  /**
   * Where the day's export goes (M23, Section 11's daily log mirror). Optional
   * like the payout adapter and for the same reason: a caller that asks for the
   * sweep without one gets every other step and a mirror step that counts
   * `mirror_unavailable` rather than one that pretends to have exported.
   */
  readonly mirror?: MirrorAdapter;
  /**
   * Which timer ran this sweep (M23, decision D-076). There is one: the Sweeper
   * Durable Object's alarm. The cron trigger arms that alarm and never sweeps,
   * so `alarm` is the only value a run writes, and the column stays because the
   * status board reads it and because rows written before the cron door was
   * retired still say `cron`.
   *
   * Optional and defaulted, so a caller that says nothing is the timer. It
   * reaches only the `sweep_steps` rows the last step writes, and no rule
   * anywhere reads it.
   */
  readonly trigger?: SweepTrigger;
  /**
   * What the alert step delivers through. The platform's own fetch when a
   * caller says nothing; a test injects its own so no alert leaves the process.
   */
  readonly alertFetch?: typeof fetch;
  /**
   * How long one alert delivery may take. The policy number when a caller says
   * nothing; injectable for the same reason `alertFetch` is, so a test can
   * watch a dead endpoint time out without waiting out the real window.
   */
  readonly alertTimeoutMs?: number;
}

/** Which timer ran the sweep. One timer, so one value. */
export type SweepTrigger = "alarm";

/**
 * The steps one run writes a `sweep_steps` row for, in the order they run.
 *
 * `sweep` is the run itself and the rest are its steps, so the page can tell "the
 * timer has stopped" from "the timer is running and the seal step is refusing" —
 * two very different things that look identical in a log that only records what
 * was appended.
 */
export const SWEEP_STEPS: readonly string[] = Object.freeze([
  "sweep",
  "snapshot",
  "expiry",
  "draws",
  "revalidation",
  "staleness",
  "publish",
  "seal",
  "witness",
  "anchor",
  "mirror",
  "ledger",
  "alerts",
  "standing",
  "attestation",
  "counters",
  "chain",
  "duplicates",
]);

/** The four sealing deps, once they are known to be there. */
interface SealingDeps {
  readonly now: Date;
  readonly witness: EnvironmentWitnessAdapter;
  readonly pinned: PinnedWitnesses;
  readonly ineligibleAgents: ReadonlySet<string>;
  readonly anchor: AnchorAdapter;
}

/** How a step counts a refusal. */
type Skip = (reason: string) => void;

/** The status the home page's "verified" counter counts, spelled once. */
const VERIFIED: EntryStatus = "verified";

/** One assignment whose seventy-two hours ran out. */
export interface SweepMiss {
  readonly entry_id: string;
  readonly operator: string;
  readonly agent: string;
  /** Position of the `assignment_missed` event this run appended. */
  readonly seq: number;
}

/** One draw this run made. */
export interface SweepDraw {
  readonly entry_id: string;
  readonly operator: string;
  readonly agent: string;
  readonly beacon_round: number;
  readonly replacement: boolean;
  /** Position of the `assignment` event this run appended. */
  readonly seq: number;
}

/**
 * One revalidation check this run drew.
 *
 * Whitepaper Section 6, "Revalidate": a request "is assigned at random to a
 * trusted operator". `request_seq` is the position of the
 * `revalidation_requested` this answers, which is what ties the two together.
 */
export interface SweepRevalidationDraw {
  readonly entry_id: string;
  readonly request_seq: number;
  readonly operator: string;
  readonly agent: string;
  readonly beacon_round: number;
  /** Position of the `revalidation_assigned` event this run appended. */
  readonly seq: number;
}

/** One revalidation check whose window ran out. */
export interface SweepRevalidationMiss {
  readonly entry_id: string;
  readonly request_seq: number;
  readonly operator: string;
  readonly agent: string;
  /** Position of the `revalidation_missed` event this run appended. */
  readonly seq: number;
}

/**
 * What one run did.
 *
 * The skip counts are the interesting half: a run that draws nothing has a
 * reason per entry it passed over, and those reasons are the rules
 * (`pool_below_switch`, `snapshot_after_beacon`, `awaiting_volunteers`) rather
 * than errors. A caller reading this can say why the log did not move.
 */
/**
 * The status board's numbers, as one run counted them.
 *
 * The QA of 2026-09-12 found the status gather making twenty-nine serialized
 * statements per view. Whitepaper Section 3: every number a page shows is a
 * view of the log, and a view may be taken once per run rather than once per
 * reader — the counters step already does exactly that for the public counts,
 * and these are the rest. They ride on the step's own board row rather than in
 * the counters table because two of them are not integers, and the board is
 * read by the gather already.
 */
export interface SweptNumbers {
  /** Entries still in draft: what the draw step is waiting to be given. */
  readonly drafts: number;
  /** The log's head, or -1 when nothing has ever been appended. */
  readonly head_seq: number;
  /** Assignments still past their window after this run's expiry step. */
  readonly overdue_assignments: number;
  /** Attestations still past their window after this run's attestation step. */
  readonly due_attestations: number;
  /** How many seals were sealed yesterday: whether an anchor was owed at all. */
  readonly seals_yesterday: number;
  /** The first UTC day any counted receipt was issued on, or null for none. */
  readonly earliest_receipt_day: string | null;
  /** Key-days reported to the payment provider, and key-days still owed. */
  /** The alert step's four numbers: endpoints, how far it read, due, given up. */
  readonly alert_endpoints: number;
  readonly alert_cursor: number;
  readonly alert_due: number;
  readonly alert_failed: number;
}

/** What one run's chain re-check walked, and what it found. */
export interface SweepChainReport {
  /** The first seq of the page walked. */
  readonly from: number;
  /** The last seq the page held, or `from - 1` when the page was empty. */
  readonly through: number;
  /** How many events the page held. */
  readonly events: number;
  /** Where the walk has now proved the log to, which a break does not move. */
  readonly checked_through: number;
  /** Whether this run restarted from seq 0 after passing the head. */
  readonly wrapped: boolean;
  /** The first event that did not agree with the chain rule, or null. */
  readonly break: { readonly seq: number; readonly reason: string } | null;
}

export interface SweepReport {
  /** The instant the run was made at, which is every event's `at`. */
  readonly at: string;
  /** The pool snapshot this run committed, or null when none was owed. */
  readonly snapshot: {
    readonly seq: number;
    readonly operators: readonly string[];
  } | null;
  readonly missed: readonly SweepMiss[];
  readonly drawn: readonly SweepDraw[];
  /**
   * The revalidation checks this run drew, and the ones whose window ran out.
   *
   * Their own fields rather than the two above: a validation assignment and a
   * revalidation check are different questions with different exclusions and
   * different miss consequences, and a caller reading one report must be able to
   * tell which of the two a row is about without looking anything up.
   */
  readonly revalidation_drawn: readonly SweepRevalidationDraw[];
  readonly revalidation_missed: readonly SweepRevalidationMiss[];
  /**
   * The entries this run rewrote because their freshness window had run out.
   * Ids only: no event is appended, so there is no position to report.
   */
  readonly staled: readonly string[];
  /**
   * The days whose read count this run published, oldest first, and empty when
   * nothing was owed. One `read_count` event each.
   */
  readonly published: readonly {
    readonly date: string;
    readonly total: number;
    readonly seq: number;
  }[];
  /**
   * The attestations whose window this run closed. Ids only, oldest deadline
   * first, and empty when nothing was owed.
   *
   * Whitepaper Section 8: an expiry is not a failing score and claims nothing
   * about drift, so there is nothing here but which attestations stopped
   * waiting — who never scored is in the event the run appended.
   */
  readonly attestations: { readonly expired: readonly string[] };
  /** The seal this run made, or null when nothing new was there to seal. */
  readonly sealed: {
    readonly seq: number;
    readonly first_seq: number;
    readonly last_seq: number;
    readonly size: number;
    /** The entries whose submission fell inside the batch, rewritten with it. */
    readonly entries: readonly string[];
  } | null;
  /** The seals this run attached countersignatures to, and whose. */
  readonly witnessed: readonly {
    readonly seq: number;
    readonly operators: readonly string[];
  }[];
  /** The day this run anchored, or null when there was nothing to do. */
  readonly anchored: {
    readonly date: string;
    readonly seals: number;
    /** The receipt's kind, or null when nothing has posted the hash yet. */
    readonly external: string | null;
  } | null;
  /**
   * The day this run upgraded, or null when it upgraded none.
   *
   * Separate from `anchored` rather than inside it: the day whose pending proof
   * finally reached a block is almost never the day this run anchored — a
   * calendar takes hours, and the oldest still-pending day is the one asked
   * about. A run that anchored nothing can still finish a proof.
   */
  readonly upgraded: {
    readonly date: string;
    /** The Bitcoin block height the completed proof attests to. */
    readonly block_height: number;
  } | null;
  /**
   * The day this run exported to the mirror, or null when it exported nothing.
   *
   * `unchanged` is a real export: the day's bytes were already in the
   * repository, so nothing was committed and the day is still current.
   */
  readonly mirror: {
    readonly date: string;
    readonly commit: string;
    readonly changed: number;
    readonly head: number;
    readonly seal_seq: number;
    readonly unchanged: boolean;
  } | null;
  /**
   * What the ledger step priced, and how far it has read. Null before the first
   * seal: nothing may be priced off events the log has not committed to.
   *
   * `ok` is the day's reconciliation, and it is a boolean rather than a count
   * because Section 9 asks one question of it — does what the ledger accrued
   * agree with what the log published — and a run where it does not is a run
   * somebody has to look at.
   */
  readonly ledger: {
    readonly through: number;
    readonly read_shares: number;
    readonly clawbacks: number;
    readonly bounties: number;
    readonly reconciliations: number;
    /**
     * How many of a published day's entries this run priced, at most
     * LEDGER_ENTRIES_PER_RUN.
     */
    readonly entries: number;
    /**
     * The published day this run stopped part-way through, or null when it did
     * not stop on one. A day named here is not a fault: it is a day longer than
     * one run prices, and the next run resumes it where this one stopped.
     */
    readonly day: string | null;
    readonly ok: boolean;
  } | null;
  /** What the alert step created, delivered, retried and gave up on (M24). */
  readonly alerts: AlertStepReport;
  /**
   * What the standing step recomputed, and what it changed about the trusted
   * pool. Null before the first seal, for the same reason.
   */
  readonly standing: {
    readonly position: number;
    readonly operators: number;
    readonly trusted: readonly string[];
    readonly untrusted: readonly string[];
  } | null;
  /**
   * What the counters step counted, or null when the step refused.
   *
   * The counts themselves and not the whole row: the row is in the table for
   * whoever reads a page, and this is the run's own account of what it wrote.
   */
  readonly counters: {
    readonly position: number;
    readonly entries: number;
    readonly operators: number;
    readonly seals: number;
    readonly attestations: number;
  } | null;
  /**
   * The numbers the status board used to ask the database for on every view,
   * counted once here instead.
   *
   * Every one of them is a question the sweep's own steps have just settled —
   * how many drafts are waiting on a draw, which assignments are still overdue
   * after the expiry step ran, how far the alert step read — so a reading taken
   * at the end of the run is the sweep's own account of itself and not a
   * second, later opinion. Null when the counters step refused, which leaves the
   * board showing the last run that got through.
   */
  readonly swept: SweptNumbers | null;
  /**
   * What the chain re-check walked, or null when the step refused.
   *
   * A break is reported and never healed: the walk says which event stopped
   * agreeing with its own hash, and repairing the log is not a thing a timer
   * may do.
   */
  readonly chain: SweepChainReport | null;
  /**
   * How many rows written before migration 0019 this run gave a duplicate key,
   * or null when the step refused.
   *
   * Zero on every run of a log that has none left, which is every log that was
   * never migrated and every migrated one once the backlog is caught up: a row
   * written since 0019 carries its key by construction.
   */
  readonly duplicates: { readonly filled: number } | null;
  /** One count per reason nothing was done, keyed by the reason's own name. */
  readonly skipped: Readonly<Record<string, number>>;
  /**
   * How long each step took, in milliseconds, keyed by the step's own name.
   *
   * The one wall-clock measurement in this file, and it is diagnostics and
   * nothing else: no event carries it, no derived field reads it, and the log's
   * own time is still the injected clock everywhere it matters. It is here
   * because a run that took thirty seconds of wall time on forty-six
   * milliseconds of CPU — which is what one uncancellable timeout did to the
   * demo deployment — looked, in the report, exactly like a run that took two.
   * A duration per step says which one waited.
   */
  readonly durations: Readonly<Record<string, number>>;
}

/** The largest seq present, or -1 when there is nothing to read at. */
function headPosition(events: readonly Event[]): number {
  let head = -1;
  for (const event of events) {
    if (event.seq > head) head = event.seq;
  }
  return head;
}

/**
 * The pool operators that are not attested in one domain (decision D-071).
 *
 * Whitepaper Section 10's rule is per domain now, and the independence
 * attestation with it, so an operator judges an entry only in a domain it has
 * signed that domain's attestation for. The draws themselves stay domain-blind
 * — `drawValidator`, `drawChecker` and `drawScorers` know nothing about domains
 * and are recomputable from the beacon, the snapshot and this list — so the
 * keying lives here, in the caller, as an exclusion like every other.
 *
 * An operator the fold does not know reads as the default domain, which is what
 * its registration meant before v0.7.
 */
function outsideDomain(
  attested: ReadonlyMap<string, readonly string[]>,
  operators: readonly string[],
  domain: string,
): string[] {
  return operators.filter(
    (operator) => !(attested.get(operator) ?? [DEFAULT_DOMAIN]).includes(domain),
  );
}

/**
 * Does this rederived entry still pass the published schema?
 *
 * Every rewrite this sweep makes -- the seal, the countersignatures, and the
 * staleness step -- validates the whole entry before it stores it, exactly as
 * the two write doors do. Schema v0.7 requires `domain` in the core, and a
 * legacy v0.6 entry does not have one, so the plain check would refuse every
 * batch that happened to cover one and the log would stop sealing (decision
 * D-071: legacy records are served and swept unchanged).
 *
 * So a v0.6 entry is checked against a probe copy with `domain` spliced in at
 * the value its core has always been read as. The probe is thrown away: nothing
 * about the stored core moves, and `rederive` copies the core verbatim, so no
 * hash, id or signature can move either. The derived fields are still checked
 * on the probe, which is the whole point of validating before a write -- a
 * derivation that went wrong is still refused, on a legacy entry as on any
 * other.
 */
function passesSchemaForRewrite(entry: Entry): boolean {
  if (coreVersion(entry) === "v0.7") return validateEntry(entry).ok;
  return validateEntry({ ...entry, domain: DEFAULT_DOMAIN }).ok;
}

/** A unit constant, not a policy number: a day, stated in milliseconds. */
const MILLISECONDS_PER_DAY = 86_400_000;

// ---------------------------------------------------------------------------
// (e): the day's read counts
// ---------------------------------------------------------------------------

/** The UTC day after this one. */
function dayAfter(date: string): string {
  return utcDay(
    new Date(Date.parse(`${date}T00:00:00Z`) + MILLISECONDS_PER_DAY).toISOString(),
  );
}

/**
 * Which entry of this one's duplicate group the log stands behind, or null when
 * the store answered no group at all.
 *
 * Whitepaper Section 9, Money: a read is "one verified entry delivered in a
 * paid sync". A sync hands the trainer everything the delta holds, and when two
 * verified entries assert the same fact about the same subject — the mechanical
 * duplicate of decision D-085, same domain, subject, category and normalized
 * `after` — the trainer was delivered one fact twice. One of the two is paid
 * for, and the paper has already said which: the newest is what the log stands
 * behind, which is the one GET /read serves.
 *
 * The candidates are the reader's own query, so "verified", "same subject and
 * category" and "newest submission first" are the store's answer rather than
 * this step's, and the first candidate whose key matches is by construction the
 * newest of the group. One page of it: the newest of a group is at the front of
 * a newest-first list, and the entry being asked about is in that page whenever
 * anything ahead of it is.
 *
 * An entry with no candidate group at all — nothing verified shares its key,
 * not even itself, which is what an entry that has since moved looks like — is
 * left alone, which is what the null says. Dropping a payment on a question the
 * store could not answer would be a silent under-count, and Section 9 asks
 * readers to check for exactly that.
 *
 * The answer is the id rather than a yes or no because the published payload
 * names it (M24b): a reader told that a read was dropped is told where the
 * group's reads went instead.
 */
async function newestOfGroup(
  db: D1Like,
  stored: StoredEntry,
): Promise<string | null> {
  const core = extractCore(stored.entry);
  const key = duplicateKey(core);
  const candidates = await readCandidates(db, {
    domain: key.domain,
    subject: key.subject,
    category: key.category,
    limit: LIST_PAGE_LIMIT,
  });
  for (const candidate of candidates) {
    if (!sameDuplicateKey(duplicateKey(extractCore(candidate.entry)), key)) {
      continue;
    }
    return candidate.entry["id"] as string;
  }
  return null;
}

/**
 * Every row of one day's reads, grouped by entry, however many pages that takes.
 * A day with more entries than one page still publishes in full: a total that
 * left a page out would be exactly the under-count Section 9 asks readers to
 * check for.
 *
 * The two kinds of read are counted apart and then added, because only one of
 * them can be owed for a duplicate. A read through GET /read is a read of what
 * the log chose to serve and is always owed. A sync delivers the whole delta,
 * so a verified entry that is not the newest of its duplicate group was
 * delivered as a second copy of a fact the trainer already has, and its sync
 * reads are dropped (decision D-085). An entry left with nothing is left out of
 * the payload entirely, exactly as an entry nobody read is.
 *
 * The rows come back split by key as well as by entry (M24), so the same fold
 * produces the day's `paid` block beside its rows: the same reads over keyed
 * receipts only, and the same reads per key. One pass, because the two must
 * agree — a paid block computed from a second read of the day could disagree
 * with the rows it is published beside, and Section 9 asks readers to check
 * exactly that arithmetic.
 *
 * Every drop is named rather than silent (M24b). A reader holding a sync
 * receipt for an entry that is not in `reads` cannot tell the duplicate rule
 * from an under-count, so the third half of the fold says which entry lost its
 * sync reads, which entry of its group the log stands behind instead, and how
 * many reads there were.
 */
async function readsOn(
  db: D1Like,
  date: string,
): Promise<{
  rows: ReadCountRow[];
  paid: PaidReadCounts;
  duplicates: ReadCountDuplicate[];
}> {
  const split: ReadCountKeyRow[] = [];
  let after: ReadCountKeyCursor | undefined;
  for (;;) {
    const page = await readCountsByKeyOn(db, date, after, LIST_PAGE_LIMIT);
    if (page.length === 0) break;
    split.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    const last = page[page.length - 1]!;
    after = { entry_id: last.entry_id, key_id: last.key_id };
  }

  // One entry's rows sit together, because the page is ordered by entry first:
  // the duplicate question is asked once per entry and answered for every key
  // that read it, since it is a question about the entry and not about who read
  // it. A reader who paid for a second copy of a fact paid for one fact.
  const byEntry = new Map<string, ReadCountKeyRow[]>();
  for (const row of split) {
    const held = byEntry.get(row.entry_id);
    if (held === undefined) byEntry.set(row.entry_id, [row]);
    else held.push(row);
  }

  const rows: ReadCountRow[] = [];
  const paidRows: ReadCountRow[] = [];
  const keys: Record<string, number> = {};
  const duplicates: ReadCountDuplicate[] = [];

  for (const [entryId, entryRows] of byEntry) {
    const syncReads = entryRows.reduce((sum, row) => sum + row.sync_reads, 0);
    let dropSync = false;
    if (syncReads > 0) {
      const stored = await getEntry(db, entryId);
      if (stored !== null && stored.entry["status"] === "verified") {
        const newest = await newestOfGroup(db, stored);
        if (newest !== null && newest !== entryId) {
          dropSync = true;
          duplicates.push({ entry_id: entryId, newest, sync_reads: syncReads });
        }
      }
    }

    let count = 0;
    let paidCount = 0;
    for (const row of entryRows) {
      const reads = row.read_reads + (dropSync ? 0 : row.sync_reads);
      if (reads <= 0) continue;
      count += reads;
      if (row.key_id === null) continue;
      paidCount += reads;
      keys[row.key_id] = (keys[row.key_id] ?? 0) + reads;
    }

    if (count > 0) rows.push({ entry_id: entryId, count });
    if (paidCount > 0) paidRows.push({ entry_id: entryId, count: paidCount });
  }

  return { rows, paid: { reads: paidRows, keys }, duplicates };
}

/**
 * (e) Publish each finished day's read count into the log.
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily ... every paid read also returns a signed receipt naming the entry, the
 * time, and a running counter ... Each day's published count is the number the
 * seal commits to." So the count goes in as an ordinary event and the seal step
 * below covers it in the same run, which is what makes the published number the
 * one the seal commits to rather than a number beside it.
 *
 * Yesterday is the newest day this may publish, because today is not over and a
 * count published mid-day would be false rather than merely early — the same
 * reason the anchor step waits a day.
 *
 * Where to start is the log's own answer: the day after the last `read_count`
 * published, or, when none ever was, the day of the oldest receipt. A log that
 * has served no reads publishes nothing at all, so a deployment with no readers
 * accrues no events.
 *
 * A day inside the range that nobody read publishes a total of zero. The gap is
 * the point: a reader checking a counter against the published days must find
 * every day accounted for, and a missing day and a quiet day would look the
 * same.
 *
 * A racing timer is a refusal rather than a repair, exactly as it is for the
 * seal: the chain rule refuses the loser's event, and the loser counts
 * `publish_conflict`, stops publishing, and carries on to its later steps.
 */
async function publishStep(
  db: D1Like,
  now: Date,
  at: string,
  skip: Skip,
): Promise<SweepReport["published"]> {
  const yesterday = utcDay(
    new Date(now.getTime() - MILLISECONDS_PER_DAY).toISOString(),
  );

  const last = await latestEventOfType(db, "read_count");
  let start: string;
  if (last === null) {
    const earliest = await earliestReadReceiptDay(db);
    if (earliest === null) {
      // Nothing has ever been read: there is no day to publish, and inventing
      // one would put a zero in the log for a system that has served nobody.
      skip("no_receipts");
      return [];
    }
    start = earliest;
  } else {
    start = dayAfter((last.payload as EventPayloads["read_count"]).date);
  }

  // Days are "YYYY-MM-DD", so text order is chronological. Start past yesterday
  // — today, or later on a log already published through it — means nothing is
  // owed yet.
  if (start > yesterday) {
    skip("read_counts_current");
    return [];
  }

  const days: string[] = [];
  for (let date = start; date <= yesterday; date = dayAfter(date)) {
    if (days.length === LIST_PAGE_LIMIT) {
      // Bounded like every other step: the rest is the next run's, and the
      // report says so once rather than per day left behind.
      skip("publish_bounded");
      break;
    }
    days.push(date);
  }

  const published: { date: string; total: number; seq: number }[] = [];
  for (const date of days) {
    const counted = await readsOn(db, date);
    const range = await readCounterRangeOn(db, date);
    const payload = buildReadCountPayload(
      date,
      counted.rows,
      range.counter_first,
      range.counter_last,
      counted.paid,
      // Present on every day this step publishes, empty on a day that dropped
      // nothing: a reader must be able to tell "no duplicate" from "not said".
      counted.duplicates,
      // Receipt rows, which `total` is not: one sync receipt can be six reads
      // or none, so this is the only number the counter range can be held
      // against, and the difference is a counter drawn and never handed over.
      await countReceiptsOn(db, date),
    );

    // The chain rule, through the one door that enforces it: the event is built
    // onto the stored head and `appendEvents` checks that it still links.
    const head = await headSeq(db);
    const previous = head === null ? [] : await eventsInRange(db, head, head);
    const chained = await appendEvent(previous, {
      at,
      type: "read_count",
      entry_id: null,
      payload,
    });
    const event = chained[chained.length - 1]!;
    try {
      await appendEvents(db, [event]);
    } catch (error) {
      if (error instanceof EventAppendError) {
        // The other timer appended between this step's read of the head and its
        // write, so the event no longer links and the door refused it. That
        // other run holds this day — it is publishing exactly the count this one
        // was about to — so this run stops publishing and lets its remaining
        // steps run, the way the seal step stands down on `seal_conflict`.
        skip("publish_conflict");
        break;
      }
      throw error;
    }

    published.push({ date, total: payload.total, seq: event.seq });
  }

  return published;
}

// ---------------------------------------------------------------------------
// (e2): the attestations whose window ran out
// ---------------------------------------------------------------------------

/**
 * Close every attestation whose seventy-two hours are up.
 *
 * Whitepaper Section 8, "Drift attestation": the model answers and three drawn
 * operators score, and this is what happens when one of them never does. An
 * expiry is not a failing score — a model whose scorers went quiet has not
 * drifted, it has not been scored — so the event says only that the window ran
 * out and names the scorer operators that never answered (src/attest.ts,
 * `attestationDue`). The model's operator asks for a new one.
 *
 * The rows say which attestations are past their deadline; the kernel says
 * whether each one is really owed an expiry, because the row is only an index
 * into the log and the log is the record. Bounded by the page size like every
 * other step, oldest deadline first.
 *
 * Before the seal, so an attestation that stopped waiting during this run is
 * sealed by the same run that closed it.
 *
 * A racing timer is a refusal rather than a repair, exactly as it is for the
 * seal and the read counts: the chain rule refuses the loser's event, the loser
 * counts `attestation_expired_conflict`, stops expiring, and carries on to its
 * later steps.
 */
async function attestationStep(
  db: D1Like,
  at: string,
  skip: Skip,
): Promise<SweepReport["attestations"]> {
  const expired: string[] = [];
  for (const due of await dueAttestations(db, {
    now: at,
    limit: LIST_PAGE_LIMIT,
  })) {
    const id = due.attestation.id;
    const events = await eventsForAttestation(db, id);
    const derived = deriveAttestation(events, { now: at });
    const payload = attestationDue(derived, at);
    if (payload === null) {
      // The column said the window had run out; the log is the authority on
      // whether it actually has, and on whether the attestation is still
      // waiting for anybody at all.
      skip("attestation_not_due");
      continue;
    }

    try {
      await recordAttestationExpired(db, {
        event: { at, type: "attestation_expired", entry_id: null, payload },
        id,
        answers: due.answers,
        attestation: (event) =>
          deriveAttestation([...events, event], { now: at }),
      });
    } catch (error) {
      if (error instanceof EventAppendError) {
        skip("attestation_expired_conflict");
        break;
      }
      throw error;
    }
    expired.push(id);
  }
  return { expired };
}

// ---------------------------------------------------------------------------
// (f), (g), (h): the seal, its witnesses, and the day's anchor
// ---------------------------------------------------------------------------

/**
 * The published schema refused an entry the seal was about to rewrite.
 *
 * Thrown out of a rederive callback and caught by the step that started it, so
 * a schema refusal counts like every other rule and leaves the log untouched:
 * the callback runs inside `recordSeal`'s batch, and the only way out of it is
 * an exception.
 */
class SealSchemaInvalid extends Error {
  constructor(entryId: string) {
    super(`sweep: the schema refused ${entryId} on sealing`);
    this.name = "SealSchemaInvalid";
  }
}

/**
 * Rewrite one entry the seal covers.
 *
 * The entry's `seal` object is a derived field like every other, so it is
 * recomputed here and stored by the writer. The seal is handed in rather than
 * read back: inside `recordSeal`'s own batch it is not readable yet, and after
 * `setSealWitnesses` the stored copy is still the one without the signatures
 * this run just gathered.
 *
 * No event is appended by either writer, so the row keeps the position it was
 * already derived through.
 */
async function rewriteForSeal(
  db: D1Like,
  entryId: string,
  seal: Seal,
  batch: readonly Event[],
  now: Date,
  cache: WorldCache,
): Promise<StoredEntryInput> {
  const world = await entryWorld(db, entryId, cache);
  const sealed = await entrySeal(batch, [seal], entryId);
  const seals =
    sealed === null
      ? undefined
      : new Map<string, EntrySeal>([[entryId, sealed]]);
  const derived = rederive(world, entryId, now, [], seals);
  if (!passesSchemaForRewrite(derived.entry)) throw new SealSchemaInvalid(entryId);
  const stored = await getEntry(db, entryId);
  return {
    entry: derived.entry,
    sidecar: derived.sidecar,
    derivedThroughSeq:
      stored?.derivedThroughSeq ?? headPosition(world.entryEvents),
  };
}

/**
 * Finish the newest seal's rewrites, when a run was killed part-way through
 * them.
 *
 * A seal's write is the seal row and one statement per entry it covers, sent to
 * D1 in chunks; the seal row is in the first chunk, so a run killed between
 * chunks leaves a seal standing over entries that do not carry it yet. The
 * repair is the same derivation the killed run was making — `rewriteForSeal`
 * over the seal's own events — and it is idempotent, so an entry already
 * rewritten is simply not among the ones this reads.
 *
 * The events are read only when there is something to rewrite. Nothing to do is
 * the usual answer and costs one indexed read: no page of events, no batch.
 *
 * False when the published schema refused one of the entries, which is the seal
 * step's own rule (`SealSchemaInvalid`) and stops this run from sealing more on
 * top of a seal it could not finish.
 */
async function finishPreviousSeal(
  db: D1Like,
  seal: Seal,
  deps: SealingDeps,
  skip: Skip,
  cache: WorldCache,
): Promise<boolean> {
  let events: Event[] | null = null;
  try {
    const finished = await completeSealRewrites(
      db,
      seal,
      deps.now,
      async (entryId, sealed, now) => {
        const batch = (events ??= await eventsInRange(
          db,
          seal.first_seq,
          seal.last_seq,
        ));
        return rewriteForSeal(db, entryId, sealed, batch, now, cache);
      },
    );
    if (finished.length > 0) skip("seal_rewrites_resumed");
  } catch (error) {
    if (error instanceof SealSchemaInvalid) {
      skip("schema_invalid");
      return false;
    }
    throw error;
  }
  return true;
}

/**
 * (f) Seal every event the last seal did not cover.
 *
 * Whitepaper, Lifecycle of an entry (Seal): "Everything gets sealed, including
 * drafts and rejections ... every later event ... is hashed into the day's batch
 * and sealed the same way". Nothing here asks an entry's status, and the batch
 * is whatever the log holds after the previous seal, up to SEAL_MAX_EVENTS.
 *
 * A racing timer is a refusal rather than a repair: `recordSeal` inserts plainly
 * and the second sweep counts `seal_conflict` and carries on, because the other
 * one sealed exactly the range this one was about to.
 *
 * Before it seals anything it finishes the last seal, because a seal's write is
 * several D1 batches and a run the platform killed between two of them leaves
 * entries that deny the seal standing over them. That is the one thing the
 * chunking costs and this is what pays for it: the rewrites are idempotent, so
 * the repair is the same derivation the killed run was making.
 */
async function sealStep(
  db: D1Like,
  deps: SealingDeps,
  skip: Skip,
  cache: WorldCache,
): Promise<SweepReport["sealed"]> {
  const previous = await latestSeal(db);
  if (
    previous !== null &&
    !(await finishPreviousSeal(db, previous, deps, skip, cache))
  ) {
    return null;
  }
  // -1, because eventsAfter reads strictly after and seq 0 is a real position.
  const after = previous === null ? -1 : previous.last_seq;
  const batch = await eventsAfter(db, after, SEAL_MAX_EVENTS);
  if (batch.length === 0) {
    skip("nothing_to_seal");
    return null;
  }

  const built = await buildSeal(batch, previous, { now: deps.now.toISOString() });
  if (!built.ok) {
    skip(built.reason);
    return null;
  }
  const seal = built.seal;

  let entries: string[];
  try {
    entries = await recordSeal(db, seal, deps.now, (entryId, sealed, now) =>
      rewriteForSeal(db, entryId, sealed, batch, now, cache),
    );
  } catch (error) {
    if (error instanceof SealConflictError) {
      // The other timer got there first with the same range: its seal stands.
      skip("seal_conflict");
      return null;
    }
    if (error instanceof SealSchemaInvalid) {
      skip("schema_invalid");
      return null;
    }
    throw error;
  }

  // The registry receipt, on the track that has a registry. Gathered after the
  // seal exists and kept beside it, never inside the hash it is gathered against.
  if (deps.witness.kind === "registry") {
    const receipt = await sealFingerprint(deps, seal);
    if (receipt === null) skip("registry_unavailable");
    else await setSealRegistry(db, seal.seq, receipt);
  }

  return {
    seq: seal.seq,
    first_seq: seal.first_seq,
    last_seq: seal.last_seq,
    size: seal.size,
    entries,
  };
}

/**
 * Submit a seal's fingerprint to the registry.
 *
 * Null on anything the adapter could not do, including a throw: the network is
 * not ours, and a registry that did not answer is a seal waiting for its receipt
 * rather than a sweep that failed.
 */
async function sealFingerprint(
  deps: SealingDeps,
  seal: Seal,
): Promise<Awaited<ReturnType<EnvironmentWitnessAdapter["seal"]>>> {
  try {
    return await deps.witness.seal(seal, deps.now);
  } catch (error) {
    // The message only: no binding contents and no credentials.
    console.error(
      `sweep: registry seal failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

/** The same, for the countersignatures: an empty list is "nothing came back". */
async function collectWitnesses(
  deps: SealingDeps,
  seal: Seal,
): Promise<WitnessSignature[]> {
  try {
    return await deps.witness.collect(seal, deps.now);
  } catch (error) {
    console.error(
      `sweep: witness collection failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return [];
  }
}

/** The operator behind a countersignature's agent, or null when it is unpinned. */
function operatorOf(pinned: PinnedWitnesses, agent: string): string | null {
  const witness = pinned.witnesses.find(
    (candidate) => candidate.agent === agent,
  );
  return witness === undefined ? null : witness.operator;
}

/**
 * (g) Gather countersignatures for the seals that are still waiting.
 *
 * Section 12's rule is src/witness.ts's, and it is asked one signature at a
 * time: `checkWitnesses` refuses a whole set on its first bad member (D-037), so
 * a batch holding one maintainer's witness beside three good ones would lose all
 * four. What is kept is merged with what the seal already carries, and the
 * entries the seal covers are rewritten in the same batch, because an entry's
 * `seal.witnesses` is the covering seal's signature strings.
 */
async function witnessStep(
  db: D1Like,
  deps: SealingDeps,
  maintainerOperators: ReadonlySet<string>,
  skip: Skip,
  cache: WorldCache,
): Promise<SweepReport["witnessed"]> {
  const witnessed: { seq: number; operators: string[] }[] = [];
  const context = {
    witnesses: deps.pinned.witnesses,
    maintainerOperators,
    ineligibleAgents: deps.ineligibleAgents,
    registry: deps.pinned.registry,
  };

  for (const waiting of await unwitnessedSeals(db, LIST_PAGE_LIMIT)) {
    let seal = waiting;

    // A seal whose fingerprint never reached the registry has nothing for a
    // real witness to have countersigned, so the receipt is retried first.
    if (deps.witness.kind === "registry" && seal.registry === null) {
      const receipt = await sealFingerprint(deps, seal);
      if (receipt === null) {
        skip("registry_unavailable");
        continue;
      }
      await setSealRegistry(db, seal.seq, receipt);
      seal = { ...seal, registry: receipt };
    }

    if ((await witnessedCount(seal, context)) >= WITNESSES_REQUIRED) {
      skip("already_witnessed");
      continue;
    }

    // A record stored before the registry's seal row id and the identity event
    // id were told apart names the wrong event, and a proof of the wrong event
    // can never be countersigned. The adapter re-resolves it from the citizen
    // record; what it hands back is kept before any proof is asked for, so such
    // a seal heals on a sweep run rather than by a migration.
    if (deps.witness.kind === "registry" && deps.witness.heal !== undefined) {
      const healed = await deps.witness.heal(seal);
      if (healed !== null) {
        await setSealRegistry(db, seal.seq, healed);
        seal = { ...seal, registry: healed };
      }
    }

    // Operators, not signatures: two keys under one operator are one witness
    // (D-033), and the one already stored is the one that counts.
    const used = new Set<string>();
    for (const stored of seal.witnesses) {
      const operator = operatorOf(deps.pinned, stored.agent);
      if (operator !== null) used.add(operator);
    }

    const kept: WitnessSignature[] = [];
    const operators: string[] = [];
    for (const candidate of await collectWitnesses(deps, seal)) {
      const check = await checkWitnesses(seal.hash, [candidate], context);
      if (!check.ok) {
        skip(check.reason);
        continue;
      }
      const operator = check.witnesses[0]!.operator;
      if (used.has(operator)) {
        // Keep the earlier one: a second key under an operator that already
        // countersigned adds no independence.
        skip("duplicate_operator");
        continue;
      }
      used.add(operator);
      kept.push(candidate);
      operators.push(operator);
    }

    if (kept.length === 0) {
      skip(
        deps.witness.kind === "unavailable"
          ? "witness_unavailable"
          : "witness_pending",
      );
      continue;
    }

    const batch = await eventsInRange(db, seal.first_seq, seal.last_seq);
    try {
      await setSealWitnesses(
        db,
        seal,
        [...seal.witnesses, ...kept],
        deps.now,
        (entryId, updated, now) =>
          rewriteForSeal(db, entryId, updated, batch, now, cache),
      );
    } catch (error) {
      if (error instanceof SealSchemaInvalid) {
        skip("schema_invalid");
        continue;
      }
      throw error;
    }
    witnessed.push({ seq: seal.seq, operators });
  }

  return witnessed;
}

/**
 * (h) Anchor a day's seals into an external timestamping chain.
 *
 * Whitepaper, Lifecycle of an entry (Seal): "Anchoring each day's batch hash
 * into an external public timestamping chain ... makes the existence proof
 * independent of 1F916's maturity." Never today, because today is not over: a
 * day anchored while seals are still being made would be false rather than
 * stale (src/anchor.ts, `verifyAnchor`).
 *
 * A backlog rather than yesterday alone: the days owed run from the day after
 * the newest anchored one — or from the log's first sealed day, when nothing
 * has ever been anchored — through yesterday, and each run takes the oldest one
 * still owed. Section 12: the anchor is what narrows a compromised witness
 * set's window to the gap between sealing and anchoring, so a day whose
 * following day saw no sweep at all has to stay owed until some later run takes
 * it, rather than falling out of the window forever, which is what asking only
 * about yesterday did.
 *
 * The next day owed is asked of the seals rather than counted out on the
 * calendar: `firstSealedDayIn` seeks the (sealed_at) index for the oldest seal
 * inside the window, so a hundred and fifty sealless days cost the same one
 * seek as none, and a gap can never stall the walk — which is what stepping
 * days a page at a time did, because a page of empty days recorded no progress
 * for the next run to start from.
 *
 * The newest anchored day is where the walk starts whatever its receipt says. A
 * calendar that was down is not a day to stand on: the record is written and
 * verifies without the receipt (D-037), and chasing the receipt is a separate
 * job — the retry below, which runs only when the walk owes nothing, and the
 * upgrade step (h1) after it. One outage cannot leave every later day
 * unanchored.
 *
 * One day a run, oldest first, because a chain asked for the whole of a long
 * backlog at once is a stranger asked for a year of favours in one night. A day
 * with no seals is never anchored at all — an anchor with no roots would be a
 * claim about a day nothing was sealed on — and the walk does not so much as
 * look at it.
 *
 * The record is written before the hash is posted, and the receipt is recorded
 * separately when it comes back, because the receipt is not in the anchor hash
 * (D-037): the day that was posted and the day that verifies are the same day.
 */
export async function anchorStep(
  db: D1Like,
  deps: SealingDeps,
  skip: Skip,
): Promise<SweepReport["anchored"]> {
  const yesterday = utcDay(
    new Date(deps.now.getTime() - MILLISECONDS_PER_DAY).toISOString(),
  );

  const latest = await latestAnchor(db);
  // Days are "YYYY-MM-DD", so text order is chronological. Null is "from the
  // beginning of the log": nothing has ever been anchored.
  const from = latest === null ? null : dayAfter(latest.date);
  const date =
    from !== null && from > yesterday
      ? null
      : await firstSealedDayIn(db, from, yesterday);
  if (date === null) return pendingReceipt(db, deps, latest, skip);

  // The day came out of the seals table, so it has seals; this reads them.
  const seals = await sealsSealedOn(db, date);
  const built = await buildAnchor(seals, date);
  if (!built.ok) {
    skip(built.reason);
    return null;
  }

  await putAnchor(db, built.anchor);
  const external = await postAnchor(deps, built.anchor);
  if (external === null) skip("anchor_pending");
  else await setAnchorExternal(db, date, external);

  // Another sealed day behind this one means the backlog is not empty, and the
  // run says so rather than looking current.
  if ((await firstSealedDayIn(db, dayAfter(date), yesterday)) !== null) {
    skip("anchor_bounded");
  }

  return {
    date,
    seals: seals.length,
    external: external === null ? null : external.kind,
  };
}

/**
 * The run owes no day: post the newest anchor's hash again if the chain never
 * took it, and otherwise say why nothing was anchored.
 *
 * This is the only place a receipt is chased, and it runs only when the walk
 * found nothing owed — so a calendar that is down costs the current log a retry
 * a run and costs a log with a backlog nothing at all. The record itself does
 * not move: the anchor hash never covered the receipt (D-037), so the day that
 * verified before the retry is the day that verifies after it.
 */
async function pendingReceipt(
  db: D1Like,
  deps: SealingDeps,
  latest: Anchor | null,
  skip: Skip,
): Promise<SweepReport["anchored"]> {
  if (latest === null) {
    // Nothing has ever been sealed on a finished day, so no day owes an anchor.
    skip("no_seals_to_anchor");
    return null;
  }
  if (latest.external !== null) {
    // Already anchored, and already carrying its receipt: nothing to do. Named
    // like every other no-op here, so a run that anchored nothing says why.
    skip("already_anchored");
    return null;
  }

  const external = await postAnchor(deps, latest);
  if (external === null) skip("anchor_pending");
  else await setAnchorExternal(db, latest.date, external);
  return {
    date: latest.date,
    seals: latest.roots.length,
    external: external === null ? null : external.kind,
  };
}

/**
 * (h1) Finish one pending proof, if a calendar has one to finish.
 *
 * At most one a run, and the oldest first. A calendar is a stranger doing this
 * for nothing; a sweep that walked every pending day every night would be
 * asking it for a favour once per day per anchor forever. One a run clears a
 * backlog at one day per day, which is the rate the backlog was made at.
 *
 * Only where the adapter can upgrade at all — production's OpenTimestamps one.
 * A local adapter has posted nothing, so it has nothing to ask about, and the
 * step does not run rather than counting a refusal on every laptop run.
 *
 * The proof is the only thing that moves. The anchor hash never covered the
 * receipt (D-037, item 5), so the day that verified before the upgrade is the
 * same day that verifies after it.
 */
async function upgradeStep(
  db: D1Like,
  deps: SealingDeps,
  skip: Skip,
): Promise<SweepReport["upgraded"]> {
  if (deps.anchor.upgrade === undefined) return null;

  // The empty string for the same reason `allAnchors` uses it: the read is
  // strictly after a day, and every real "YYYY-MM-DD" sorts above it.
  const [oldest] = await pendingAnchorsAfter(db, "", 1);
  if (oldest === undefined) {
    skip("upgrade_current");
    return null;
  }

  let result: AnchorUpgradeResult;
  try {
    result = await deps.anchor.upgrade(oldest);
  } catch (error) {
    console.error(
      `sweep: anchor upgrade failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    skip("upgrade_unavailable");
    return null;
  }

  if (!result.ok) {
    skip(`upgrade_${result.reason}`);
    return null;
  }

  const external = oldest.external;
  if (external === null) {
    // Unreachable: `pendingAnchorsAfter` reads only rows that hold a receipt.
    skip("upgrade_bad_proof");
    return null;
  }
  await setAnchorExternal(db, oldest.date, {
    ...external,
    upgraded: {
      proof: result.proof,
      block_height: result.block_height,
      upgraded_at: deps.now.toISOString(),
    },
  });
  return { date: oldest.date, block_height: result.block_height };
}

/** Post one day's hash. Null on anything the adapter could not do. */
async function postAnchor(
  deps: SealingDeps,
  anchor: Parameters<AnchorAdapter["anchor"]>[0],
): Promise<AnchorExternal> {
  try {
    return await deps.anchor.anchor(anchor);
  } catch (error) {
    console.error(
      `sweep: anchor failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// (h2): the day's mirror
// ---------------------------------------------------------------------------

/** What one refused push left behind, for the step row's detail. */
interface MirrorOutcome {
  readonly report: SweepReport["mirror"];
  /** The push's own detail, or null when nothing refused. */
  readonly detail: string | null;
}

/**
 * Every seal, in seq order, paged.
 *
 * -1 because `sealsAfter` reads strictly after and seq 0 is a real seal.
 */
async function allSeals(db: D1Like): Promise<Seal[]> {
  const seals: Seal[] = [];
  let after = -1;
  for (;;) {
    const page = await sealsAfter(db, after, LIST_PAGE_LIMIT);
    seals.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    after = page[page.length - 1]!.seq;
  }
  return seals;
}

/**
 * Every anchor, in date order, paged.
 *
 * The empty string because `anchorsAfter` reads strictly after a day and every
 * real day sorts above it.
 */
async function allAnchors(db: D1Like): Promise<Anchor[]> {
  const anchors: Anchor[] = [];
  let after = "";
  for (;;) {
    const page = await anchorsAfter(db, after, LIST_PAGE_LIMIT);
    anchors.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    after = page[page.length - 1]!.date;
  }
  return anchors;
}

/**
 * Every operator, with its agents and its domains, in id order, paged.
 *
 * Everything the offline verifier's Registry needs, plus trusted, so a forker
 * holding the mirror can build a bundle without asking this Worker anything.
 * `trusted` is read off the stored operator record, which is where the standing
 * step caches what the log says — the same place `trustedOperatorIds` reads it.
 */
async function allOperators(db: D1Like): Promise<MirrorOperator[]> {
  const operators: MirrorOperator[] = [];
  let afterId: string | undefined;
  for (;;) {
    const page = await listOperators(
      db,
      afterId === undefined
        ? { limit: LIST_PAGE_LIMIT }
        : { limit: LIST_PAGE_LIMIT, afterId },
    );
    if (page.length === 0) break;
    for (const record of page) {
      const agents = await agentsForOperator(db, record.id, LIST_PAGE_LIMIT);
      const domains = await operatorDomains(db, record.id);
      operators.push({
        operator: record.id,
        maintainer: record.maintainer,
        provider: record.provider,
        trusted: record.details["trusted"] === true,
        domains: domains.map((row) => row.domain),
        agents: agents.map((row) => row.agentId),
      });
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    afterId = page[page.length - 1]!.id;
  }
  return operators;
}

/**
 * Every entry at or below the sealed head, as the sealed head has it.
 *
 * What the export needs of an entry is the derivation the sealed head supports —
 * exactly what `GET /sync` produces, `worldAt` to the head then `rederive` at
 * the newest seal's instant, because the mirror and the delta stream must not be
 * able to describe the same entry at the same position two different ways.
 *
 * Almost always the stored row already is that derivation. A row's
 * `derived_through_seq` is the position of the last event its writer folded, and
 * when that is the entry's own last event at or below the head, the row was
 * derived over the world this export would rebuild, so rebuilding it would cost
 * ten statements to arrive at the bytes already in hand. So the rows are read a
 * page at a time with one grouped read of where each entry's events stop, and
 * only a row that is behind — or one derived past the head, over events the
 * export must not see, or one whose staleness the row cannot account for and
 * 0021 has not yet recorded a position for — is derived again. A thousand
 * entries costs the pages and the stragglers rather than ten thousand
 * statements.
 */
/**
 * A stored row read at an instant, or null when only the events can answer.
 *
 * `stale` is derivation's one clock-dependent field, and the row carries the
 * answer its writer's clock gave. The export's clock is the newest seal's, which
 * on a run that seals nothing is behind the staleness step's own `now`, so a row
 * taken as it stands could say an entry is stale at a position at which
 * `GET /sync` says it is fresh — one entry at one position described two ways,
 * which is the one thing the mirror and the delta stream may not do. So the
 * clock is applied here, by the rule src/worker/sync.ts applies at its own door
 * and out of the same function: `expiresAt` in the past at `asOf` is stale, and
 * a row that is stale with its window still open was made stale by something
 * else — D-096's version staleness, a fact about the log and not the clock.
 *
 * Which of the two it was is the one thing the derivation beside it does not
 * say, so until 0021 every ai-safety entry a later version had retired went back
 * to the events on every export: correct, and ten statements each, every day,
 * forever (the #78 QA, D-107). The column is that answer, kept: the sealed
 * position at which an export folded the events and found the entry
 * version-stale. A position and not a flag because an export reads at a head,
 * and a head below the one that proved it must not publish a staleness it does
 * not cover. It never has to be cleared and is never re-asked, because version
 * staleness never clears — the sibling's verification does not unhappen, and
 * `expires_at` is untouched by it, so a row carrying a position is stale at
 * every later head whatever the calendar says. A row with no position is the
 * only one left that the events have to answer for.
 */
function clockedAt(
  row: StoredEntryRow,
  asOf: Date,
  head: number,
): { entry: Entry; sidecar: Sidecar } | null {
  const fields = row.entry as unknown as Record<string, unknown>;
  const expiresAt = fields["expires_at"];
  const expired = expiredByClock(
    typeof expiresAt === "string" ? expiresAt : null,
    asOf,
  );
  const wasStale = fields["stale"] === true;
  if (wasStale && !expired) {
    const staledAt = row.versionStaleSeq;
    if (staledAt === null || staledAt > head) return null;
    // The row already says stale, and D-096 is why: it stands as it is.
    return { entry: row.entry, sidecar: row.sidecar };
  }
  return {
    entry:
      wasStale === expired
        ? row.entry
        : ({ ...row.entry, stale: expired } as Entry),
    sidecar: row.sidecar,
  };
}

async function mirrorEntries(
  db: D1Like,
  head: number,
  asOf: Date,
  cache: WorldCache,
): Promise<MirrorEntryRecord[]> {
  const records: MirrorEntryRecord[] = [];
  let afterSubmittedSeq: number | undefined;
  for (;;) {
    const page = await entriesThrough(
      db,
      afterSubmittedSeq === undefined
        ? { throughSeq: head, limit: LIST_PAGE_LIMIT }
        : { throughSeq: head, limit: LIST_PAGE_LIMIT, afterSubmittedSeq },
    );
    if (page.length === 0) break;
    const heads = await entryHeadsThrough(
      db,
      page.map((row) => row.id),
      head,
    );
    for (const row of page) {
      const needed = heads.get(row.id);
      const current =
        needed !== undefined &&
        row.derivedThroughSeq >= needed &&
        row.derivedThroughSeq <= head;
      const fromRow = current ? clockedAt(row, asOf, head) : null;
      let derived: { entry: Entry; sidecar: Sidecar } | null = fromRow;
      if (derived === null) {
        const full = rederive(
          worldAt(await entryWorld(db, row.id, cache), head),
          row.id,
          asOf,
        );
        derived = full;
        // The world was gathered anyway, so what it cost is kept: an entry the
        // events call stale with its window still open is stale by D-096, and
        // the position that proves it is this export's own head (0021). The next
        // export reads the row and gathers nothing. Written after the
        // derivation and never instead of it — this run publishes exactly what
        // it derived — and it writes one column beside the doors' row rather
        // than a row of its own.
        if (
          row.versionStaleSeq === null &&
          full.derived.stale &&
          !expiredByClock(full.derived.expires_at, asOf)
        ) {
          await recordVersionStale(db, row.id, head);
        }
      }
      records.push({
        entry: derived.entry,
        sidecar: derived.sidecar,
        entry_hash: await entryHash(extractCore(derived.entry)),
      });
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    afterSubmittedSeq = page[page.length - 1]!.submittedSeq;
  }
  return records;
}

/**
 * The model's answers, per attestation, for every attestation requested at or
 * below the sealed head.
 *
 * The one input to the export's attestation files that the log does not carry:
 * the attestations themselves are recomputed from the sealed events
 * (src/mirror.ts, `mirrorAttestations`), and the answers are hashed into the log
 * rather than written into it, so this is the one thing the export has to read.
 *
 * Keyset downward by `requested_seq`, the way `GET /attestations` pages, and
 * trimmed to the head: an attestation opened above the seal is not part of the
 * sealed record and the layout would drop it anyway.
 */
async function mirrorAnswers(
  db: D1Like,
  head: number,
): Promise<MirrorAttestationAnswers[]> {
  const answers: MirrorAttestationAnswers[] = [];
  let beforeSeq: number | undefined;
  for (;;) {
    const page = await listAttestations(
      db,
      beforeSeq === undefined
        ? { limit: LIST_PAGE_LIMIT }
        : { limit: LIST_PAGE_LIMIT, beforeSeq },
    );
    if (page.length === 0) break;
    for (const row of page) {
      if (row.attestation.requested_seq > head) continue;
      answers.push({
        attestation: row.attestation.id,
        answers: row.answers,
      });
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    beforeSeq = page[page.length - 1]!.attestation.requested_seq;
  }
  return answers;
}

/**
 * (h2) The day's export.
 *
 * Whitepaper Section 11: the sealed log goes out daily to a public repository
 * under CC0, which is the Conclusion's exit right made into files. Once per UTC
 * day, right after the anchor and before the money: the anchor is the last thing
 * that changes what a day's sealed record says, and the ledger reads the same
 * sealed head this export was built at.
 *
 * Nothing unsealed is ever exported. Every refusal is counted in the same words
 * the report and the status page use, and a refused push is a day that is not
 * mirrored yet rather than a run that failed — the sweep goes on to the ledger.
 */
export async function mirrorStep(
  db: D1Like,
  environment: string,
  adapter: MirrorAdapter | undefined,
  now: Date,
  at: string,
  skip: Skip,
  cache: WorldCache = worldCache(),
): Promise<MirrorOutcome> {
  const none: MirrorOutcome = { report: null, detail: null };

  if (adapter === undefined || adapter.kind === "unavailable") {
    skip("mirror_unavailable");
    return none;
  }

  const newest = await latestSeal(db);
  if (newest === null) {
    // The mirror is the sealed record, so a log with no seal has nothing to
    // mirror. Not a fault: it is the first minutes of a new environment.
    skip("no_seal");
    return none;
  }

  const date = utcDay(now.toISOString());
  const claim = await mirrorClaimOn(db, date);
  if (claim !== null && claim.state === "pushed") {
    skip("mirror_current");
    return none;
  }

  const head = newest.last_seq;
  // The claim, before the export is built and long before it is pushed. A run
  // that dies anywhere after this line leaves the row pending, which is the
  // whole point: the day is marked as being worked on rather than as done.
  //
  // Somebody else may be exporting this day already. A claim younger than one
  // interval is a run that has not come back yet and this one stands down; an
  // older one is a run that died, and this one takes the day over — so a killed
  // export is retried by the next run and not by every run of the day. Which of
  // two overlapping runs gets it is decided inside the one statement the claim
  // is, and the loser is told so here.
  const claimed = await claimMirror(db, {
    date,
    started_at: at,
    head,
    seal_seq: newest.seq,
    take_over_before: new Date(
      now.getTime() - SWEEP_INTERVAL_MINUTES * 60_000,
    ).toISOString(),
  });
  if (!claimed) {
    skip("mirror_pending");
    return none;
  }

  let files;
  try {
    files = buildMirror({
      environment,
      exported_at: at,
      // The release window is judged at the run's own instant, from the same
      // injected clock the rest of the sweep runs on (D-100), and the window is
      // policy's one number.
      now: at,
      release_window_days: RELEASE_WINDOW_DAYS,
      seals: await allSeals(db),
      anchors: await allAnchors(db),
      events: await sealedLog(db, head),
      entries: await mirrorEntries(db, head, new Date(newest.sealed_at), cache),
      operators: await allOperators(db),
      attestations: await mirrorAnswers(db, head),
    });
  } catch (error) {
    // The layout's own two refusals, in its own words. Anything else is a
    // storage failure and belongs to the run's own try/catch.
    if (!(error instanceof MirrorError)) throw error;
    skip(error.reason);
    return none;
  }

  const pushed = await adapter.push({
    prefix: environment,
    files,
    message: `mirror ${environment} ${date}: head ${head}, seal ${newest.seq}`,
  });
  if (!pushed.ok) {
    skip(pushed.reason);
    return { report: null, detail: pushed.detail };
  }

  // An unchanged push still writes the row: the day's bytes are in the
  // repository, so the day is current and the next run must not push again.
  // This is the claim turning into an export — the same row, now pushed.
  await putMirror(db, {
    date,
    exported_at: at,
    commit: pushed.commit,
    tree: pushed.tree,
    head,
    seal_seq: newest.seq,
    entries: files.filter((file) => file.path.startsWith("entries/")).length,
    files_changed: pushed.changed,
    url: pushed.url,
    raw_url: pushed.raw_url,
  });

  return {
    report: {
      date,
      commit: pushed.commit,
      changed: pushed.changed,
      head,
      seal_seq: newest.seq,
      unchanged: pushed.unchanged,
    },
    detail: null,
  };
}

// ---------------------------------------------------------------------------
// (i), (j), (k): the ledger, standing, and the payout cycle
// ---------------------------------------------------------------------------

/**
 * The ledger step's cursor, named in `ledger_state` by the step itself.
 *
 * Exported because a replay has to leave it where a sweep would have: `npm run
 * import-mirror` writes the mirror's ledger rows and then sets this to the
 * imported sealed head, so the fork's first sweep carries on from there rather
 * than pricing the whole log again.
 */
export const LEDGER_CURSOR = "ledger";

/**
 * (i) The ledger step: walk what the log has sealed, and price none of it.
 *
 * Decision D-127, "the record is free, no money anywhere". There is no read
 * price, no contributor share, no holdback money, no bounty, no dispute reward
 * and no payout, so there is nothing for this step to compute: it writes no
 * `read_share`, `clawback`, `bounty`, `dispute_reward`, `payout` or
 * `reconciliation` row, and it reports ok with a zero count. The rows the ledger
 * already holds are not touched — they are the log's own history of the months
 * the record was sold, and the ledger doors go on serving them.
 *
 * It stays a stage rather than disappearing, and it keeps its cursor, because
 * the cursor is a restart invariant and not a pricing detail: `npm run
 * import-mirror` sets LEDGER_CURSOR to the imported sealed head so a fork's
 * first sweep carries on from there (src/cli/import-mirror.ts), and a step that
 * stopped writing the cursor would leave that value standing at a position
 * nothing ever moves. So the walk is now exactly one statement — the cursor
 * forward to the sealed head — and the board goes on showing a ledger stage
 * whose position a reader can check.
 *
 * LEDGER_DAY_CURSOR is gone with the pricing it indexed: it was the position
 * inside a published day, and a day that is never priced has no inside.
 */
export async function ledgerStep(
  db: D1Like,
  sealedHead: number,
): Promise<SweepReport["ledger"]> {
  await setLedgerCursor(db, LEDGER_CURSOR, sealedHead);
  return {
    through: sealedHead,
    read_shares: 0,
    clawbacks: 0,
    bounties: 0,
    reconciliations: 0,
    entries: 0,
    day: null,
    ok: true,
  };
}

/**
 * The whole sealed log, in pages, oldest first.
 *
 * Exported because the standing endpoints recompute the same fold over the same
 * events (src/worker/standing.ts), and two paged reads of one log are two
 * chances to disagree about where it ends.
 */
export async function sealedLog(db: D1Like, sealedHead: number): Promise<Event[]> {
  const events: Event[] = [];
  for (let from = 0; from <= sealedHead; ) {
    const to = Math.min(from + LIST_PAGE_LIMIT - 1, sealedHead);
    const page = await eventsInRange(db, from, to);
    if (page.length === 0) break;
    events.push(...page);
    from = to + 1;
  }
  return events;
}

/**
 * The events one incremental standing fold needs, given a cursor.
 *
 * The tail is the point: at a cursor the sweep reads the events it has not
 * folded yet and not the log. Two things go in beside it, and both are about
 * what the fold asks of an entry's whole history rather than of one event — the
 * registry, which every derivation is judged against, and the events of the
 * entries the tail names whose own log starts before the cursor, so the fold can
 * see that an entry's submission credit is already spent and which of its
 * signers an earlier upheld dispute already burned. A superseding entry's events
 * come with its target's, because whether a target derives verified is a
 * question about both.
 *
 * Everything here is bounded by the tail: an idle five minutes reads the
 * registry and nothing else.
 */
async function standingTail(
  db: D1Like,
  from: number,
  head: number,
  cache: WorldCache,
): Promise<Event[]> {
  const tail: Event[] = [];
  for (let cursor = from + 1; cursor <= head; ) {
    const to = Math.min(cursor + LIST_PAGE_LIMIT - 1, head);
    const page = await eventsInRange(db, cursor, to);
    tail.push(...page);
    cursor = to + 1;
  }

  const bySeq = new Map<number, Event>();
  const add = (events: readonly Event[]): void => {
    for (const event of events) {
      if (event.seq <= head) bySeq.set(event.seq, event);
    }
  };
  add(await registryEvents(db, cache));
  add(tail);

  const submitted = new Set<string>();
  const touched = new Set<string>();
  for (const event of tail) {
    if (event.entry_id === null) continue;
    if (event.type === "entry_submitted") submitted.add(event.entry_id);
    touched.add(event.entry_id);
  }
  for (const entryId of touched) {
    // An entry the tail submitted is an entry the tail holds whole.
    if (submitted.has(entryId)) continue;
    add(await eventsForEntry(db, entryId));
    for (const superseder of await supersedersOf(db, entryId, LIST_PAGE_LIMIT)) {
      if (superseder === entryId) continue;
      add(await eventsForEntry(db, superseder));
    }
  }

  return [...bySeq.values()].sort((left, right) => left.seq - right.seq);
}

/**
 * (j) Recompute every operator's standing, and let it move the trusted pool.
 *
 * Whitepaper Section 9: standing "is derived from the sealed public events by a
 * published formula, so anyone can recompute anyone's standing from the log and
 * get the same number", and it "gates everything discretionary, from entry to
 * and stay in the trusted pool". So the fold is src/standing.ts's, over the
 * sealed log and nothing else, and what is written to the operator rows is a
 * cache of what it returned at a position anyone can check it at.
 *
 * The trust changes are appended here and are sealed by the next run, which is
 * also the run whose pool snapshot picks them up: a pool the log has not sealed
 * is not a pool anyone can recompute a draw against.
 *
 * Exported, like `mirrorStep` beside it, because what this step costs is now
 * part of what it promises: a run at a cursor must read the events after the
 * cursor and not the log, and a test that cannot call the step on its own can
 * only measure the whole sweep's reads and not this one's.
 */
export async function standingStep(
  db: D1Like,
  sealedHead: number,
  at: string,
  skip: Skip,
  cache: WorldCache = worldCache(),
): Promise<SweepReport["standing"]> {
  // The cursor: what a previous run folded, and how far. A position above the
  // sealed head is not a cursor this run can continue from — the log it covers
  // is not the log this run sees — and neither is a set of rows that disagree
  // about where they are, so both fold the whole thing and write a cursor the
  // next run can use.
  const stored = await storedStandings(db);
  const from =
    stored.position === null || stored.position > sealedHead ? -1 : stored.position;
  const prior = from === -1 ? new Map<string, Standing>() : stored.standings;
  const events =
    from === -1
      ? await sealedLog(db, sealedHead)
      : await standingTail(db, from, sealedHead, cache);

  const standings = standingAfter(events, prior, from, sealedHead);
  // The accumulators and the operator rows' cached column, together: what is
  // written is a cache of what the published formula says at this position, and
  // `position` is what makes it checkable.
  await putStandings(db, [...standings.values()]);

  const changes = trustChangesAt(events, sealedHead, standings);
  const applied: { trust: string[]; untrust: string[] } = { trust: [], untrust: [] };
  for (const [kind, operators] of [
    ["operator_trusted", changes.trust],
    ["operator_untrusted", changes.untrust],
  ] as const) {
    for (const operator of operators) {
      try {
        await recordTrustChange(
          db,
          kind,
          operator,
          at,
          "standing",
          standings.get(operator)?.standing ?? 0,
          sealedHead,
        );
      } catch (error) {
        if (error instanceof EventAppendError) {
          // The other timer appended between this step's read and its write.
          // Its run is making the same change; this one stands down.
          skip("trust_conflict");
          continue;
        }
        throw error;
      }
      if (kind === "operator_trusted") applied.trust.push(operator);
      else applied.untrust.push(operator);
    }
  }

  return {
    position: sealedHead,
    operators: standings.size,
    trusted: applied.trust,
    untrusted: applied.untrust,
  };
}

/** A pair's running numbers while one run folds. */
interface CosignAccumulator {
  operator: string;
  cosigner: string;
  both: number;
  agreed: number;
  opposed: number;
  newestEntryId: string;
  newestSeq: number;
}

/** The key a pair accumulates under: the two ids, in order, once. */
function pairKey(left: string, right: string): string {
  return left < right ? `${left} ${right}` : `${right} ${left}`;
}

/**
 * Who has co-signed with whom, folded from the sealed decisions (D-119).
 *
 * The question a reader asked of the demo: how do I tell three independent
 * confirmations from three copies of one procedure. The log has always held the
 * answer — `validation` and `reconfirmation` say who signed what — so this
 * folds it into the pairs the pages read, and the pages read nothing else.
 *
 * An operator's stance on an entry is the first one it signed. First and not
 * newest, because a co-signature is the act of signing beside somebody and a
 * later reading of the same fact by the same operator is a second act, not a
 * second co-signature — and because first is what makes this fold forward-only:
 * a pair is formed once, by whichever of the two signed second, and nothing
 * later takes it back.
 *
 * Incremental from the cursor the last run left. The tail is the decisions
 * after it, and beside it goes one read per entry the tail touched, because the
 * other half of a pair may have signed long before the cursor — the same bound
 * the standing fold's tail uses, and for the same reason. A run at a cursor with
 * nothing new reads one empty page. A cold start — no cursor, or a cursor above
 * this run's sealed head — folds every sealed decision once, exactly as the
 * standing step folds the whole log when it finds no cursor it can continue
 * from; the tail then holds every entry whole and the per-entry reads are not
 * made at all.
 */
async function cosignFold(
  db: D1Like,
  sealedHead: number,
  at: string,
): Promise<number> {
  const stored = await readCosignCursor(db);
  const from = stored === null || stored > sealedHead ? -1 : stored;

  const tail: Cosignature[] = [];
  for (let after = from; ; ) {
    const page = await cosignaturesInRange(db, after, sealedHead, LIST_PAGE_LIMIT);
    tail.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    after = page[page.length - 1]!.seq;
  }
  if (tail.length === 0) {
    // Nothing new is still a run: the cursor moves so the next one knows this
    // stretch of log has been folded and holds no decisions.
    await writeCosignCursor(db, sealedHead, at);
    return 0;
  }

  // The signatures this run judges pairs from, by entry. On a cold start the
  // tail is every sealed decision there is, so it is already whole.
  const byEntry = new Map<string, Cosignature[]>();
  for (const signature of tail) {
    const held = byEntry.get(signature.entryId);
    if (held === undefined) byEntry.set(signature.entryId, [signature]);
    else held.push(signature);
  }
  if (from !== -1) {
    for (const entryId of [...byEntry.keys()]) {
      byEntry.set(entryId, await cosignaturesForEntry(db, entryId, sealedHead));
    }
  }

  const deltas = new Map<string, CosignAccumulator>();
  for (const signatures of byEntry.values()) {
    const first = new Map<string, Cosignature>();
    for (const signature of signatures) {
      if (!first.has(signature.operator)) first.set(signature.operator, signature);
    }
    const signers = [...first.values()].sort((left, right) =>
      left.operator < right.operator ? -1 : left.operator > right.operator ? 1 : 0,
    );
    for (let i = 0; i < signers.length; i += 1) {
      for (let j = i + 1; j < signers.length; j += 1) {
        const one = signers[i]!;
        const other = signers[j]!;
        // The pair is formed when the second of the two signs. A pair formed at
        // or before the cursor was counted by an earlier run, and counting it
        // again is the one way an incremental fold can lie.
        const formedAt = Math.max(one.seq, other.seq);
        if (formedAt <= from) continue;
        const agreed = one.stance === other.stance;
        const key = pairKey(one.operator, other.operator);
        const held = deltas.get(key);
        if (held === undefined) {
          deltas.set(key, {
            operator: one.operator,
            cosigner: other.operator,
            both: 1,
            agreed: agreed ? 1 : 0,
            opposed: agreed ? 0 : 1,
            newestEntryId: one.entryId,
            newestSeq: formedAt,
          });
          continue;
        }
        held.both += 1;
        if (agreed) held.agreed += 1;
        else held.opposed += 1;
        if (formedAt > held.newestSeq) {
          held.newestSeq = formedAt;
          held.newestEntryId = one.entryId;
        }
      }
    }
  }

  const written: CosignDelta[] = [...deltas.values()];
  if (written.length > 0) await addCosignPairs(db, written, sealedHead);
  // After the rows and never before: a cursor ahead of the rows would skip a
  // tail nobody had folded. The other way round is safe because the add is
  // guarded by the position it carries (`addCosignPairs`).
  await writeCosignCursor(db, sealedHead, at);
  return written.length;
}

/**
 * (j2) Count everything the public pages show, once, and write the row.
 *
 * Whitepaper Section 3: the log is the record, and every number a page shows is
 * a view of it. The view was being taken per reader — the QA of 2026-09-12
 * found the home, entries, domains and status pages counting whole tables on
 * every view, including two conditions no index could serve — so it is taken
 * here instead, once per run, at the position the run sealed.
 *
 * After the standing step on purpose: that step is what moves the trusted pool,
 * so a count taken before it would publish the pool of the run before this one.
 *
 * Every count below rides an index and none of them parses JSON: status and
 * domain have had theirs since 0001 and 0012, and 0018 added the three the
 * scans needed — entries(stale), operators(trusted, id) and seals(witnessed).
 * The two per-domain counts are one grouped statement each rather than one per
 * registered slug, and a slug with nothing in it is written as the zero it is,
 * so the domains page never has to know which slugs the log has heard of.
 *
 * The co-signature fold (D-119) rides along at the end, because it is the same
 * bargain in a different shape: a view of the sealed events, taken once a run,
 * so that a page reads a row instead of folding the log.
 *
 * The whole step is a normal skip when it fails: the counters are a view of the
 * log and never the log, so a run that could not recount them has still swept,
 * and the pages go on showing the last position that was counted.
 */
export async function countersStep(
  db: D1Like,
  sealedHead: number,
  at: string,
  skip: Skip,
): Promise<{
  counters: SweepReport["counters"];
  swept: SweptNumbers | null;
}> {
  try {
    const entriesByDomain = await entryCountsByDomain(db);
    const trustedByDomain = await trustedOperatorCountsByDomain(db);
    const byDomain: Counters["entries_by_domain"] = {};
    for (const slug of DOMAIN_SLUGS) {
      byDomain[slug] = {
        entries: entriesByDomain[slug] ?? 0,
        trusted_operators: trustedByDomain[slug] ?? 0,
      };
    }

    const counters: Counters = {
      entries_total: await countEntries(db, {}),
      // "verified" is a status name from src/derive.ts's EntryStatus and not a
      // knob: the home page's second counter is the entries that verified.
      entries_verified: await countEntries(db, { status: VERIFIED }),
      entries_stale: await countEntries(db, { stale: true }),
      entries_by_domain: byDomain,
      operators_registered: await countOperators(db),
      operators_trusted: await countTrustedOperators(db),
      seals: await countSeals(db),
      seals_witnessed: await countWitnessedSeals(db),
      attestations: await countAttestations(db),
      sealed_head: sealedHead,
      position: sealedHead,
      updated_at: at,
    };
    await writeCounters(db, counters);

    // One counter pair per operator, in their own batch. The operators
    // directory and the genesis page grouped over every `validation` event in
    // the log on every view (the QA of 2026-09-12); this is that grouping, made
    // once per run, and the log is still what it is counted from.
    await writeOperatorValidationCounters(
      db,
      await validationCountsByOperator(db, LIST_PAGE_LIMIT),
      counters.position,
      at,
    );

    // And who signed beside whom (D-119), folded from the same sealed events at
    // the same position. Here rather than in a step of its own because it is
    // the same promise the counters are — a page reads a row and never the log
    // — and a seventeenth light on the status board would be a new thing for a
    // reader to learn about a view that is one more counter.
    await cosignFold(db, sealedHead, at);

    return { counters: {
      position: counters.position,
      entries: counters.entries_total,
      operators: counters.operators_registered,
      seals: counters.seals,
      attestations: counters.attestations,
    }, swept: await sweptNumbers(db, sealedHead, at) };
  } catch {
    skip("counters_failed");
    return { counters: null, swept: null };
  }
}

/**
 * The status board's own numbers, counted at the end of the run.
 *
 * Everything here was a statement the status gather made per view. Each is a
 * question this run has just finished answering — the expiry step closed the
 * assignments it could, the attestation step closed the windows it could, the
 * alert step read as far as it read — so counting them here is the run
 * reporting what it left behind, and reading them back costs the board nothing
 * beyond the row it already reads.
 *
 * `head_seq` is -1 on a log with no events, the same spelling every other
 * position in this file uses for "nothing yet".
 */
async function sweptNumbers(
  db: D1Like,
  sealedHead: number,
  at: string,
): Promise<SweptNumbers> {
  const yesterday = utcDay(
    new Date(Date.parse(at) - MILLISECONDS_PER_DAY).toISOString(),
  );
  const head = await headSeq(db);
  return {
    drafts: await countEntries(db, { status: "draft" }),
    head_seq: head ?? -1,
    // Bounded by one page, exactly as the gather bounded it: both stages ask
    // only whether anything is overdue, and a page is more than enough to say.
    overdue_assignments: (await dueAssignments(db, at, LIST_PAGE_LIMIT)).length,
    due_attestations: (
      await dueAttestations(db, { now: at, limit: LIST_PAGE_LIMIT })
    ).length,
    seals_yesterday: await countSealsSealedOn(db, yesterday),
    earliest_receipt_day: await earliestReadReceiptDay(db),
    alert_endpoints: await countAlertEndpoints(db),
    alert_cursor: await alertCursor(db),
    alert_due: await countDueDeliveries(db, at),
    alert_failed: await countFailedDeliveries(db),
  };
}

/**
 * (j2b) Re-walk one page of the log and check that it is still itself.
 *
 * The gap the QA of 2026-09-12 named: a hand-edited `prev_hash` is noticed by
 * nothing live. The offline verifier catches it and so does the mirror, but
 * both are things somebody has to run, and a record whose whole claim is that a
 * later change leaves proof (whitepaper Section 6, "Seal") should be the one
 * noticing. So every run re-checks one page from a stored cursor and wraps back
 * to seq 0 after the head, which walks the whole log continuously — a log of
 * any size is re-proved in (events / LIST_PAGE_LIMIT) runs and no run pays for
 * more than a page.
 *
 * The kernel's own rule and not a second copy of it: `eventHash`
 * (src/events.ts) recomputes each event's digest over its own fields, and the
 * link and contiguity checks are `verifyChain`'s, applied to a page that starts
 * wherever the cursor left off — which is why `verifyChain` itself cannot be
 * called here: it requires the list to begin at seq 0.
 *
 * A break is reported and never healed. The cursor does not move past it, so
 * the next run walks the same page and the stage stays failing until the row is
 * put back, at which point the walk passes it and moves on by itself. Nothing
 * here writes to the events table: a timer that repaired the record would be
 * the one thing this record must never have.
 */
export async function chainStep(
  db: D1Like,
  at: string,
  skip: Skip,
): Promise<SweepReport["chain"]> {
  try {
    const head = await headSeq(db);
    if (head === null) {
      skip("chain_no_event");
      return null;
    }
    const stored = await readChainCheckState(db);
    // Past the head, so back to the beginning: the log is re-walked for ever
    // rather than once, because an event proved last week is exactly the one a
    // hand edit would go for.
    const wrapped = stored.checked_through >= head;
    const from = wrapped ? 0 : stored.checked_through + 1;
    const page = await eventsAfter(db, from - 1, LIST_PAGE_LIMIT);

    // What the first event of the page must link to: null at seq 0, else the
    // hash of the event before it, read on its own because the page does not
    // hold it.
    const before = from === 0 ? null : await eventBySeq(db, from - 1);
    if (from > 0 && before === null) {
      const state = { checked_through: stored.checked_through, break_seq: from };
      await writeChainCheckState(db, state, at);
      skip("chain_break");
      return {
        from,
        through: from - 1,
        events: 0,
        checked_through: state.checked_through,
        wrapped,
        break: { seq: from, reason: "missing_prev" },
      };
    }

    let expectedSeq = from;
    let expectedPrev: string | null = before === null ? null : before.hash;
    let broken: { seq: number; reason: string } | null = null;
    for (const event of page) {
      if (event.seq !== expectedSeq) {
        broken = { seq: expectedSeq, reason: "bad_seq" };
        break;
      }
      if (event.prev_hash !== expectedPrev) {
        broken = { seq: event.seq, reason: "bad_prev_hash" };
        break;
      }
      const { hash, ...fields } = event;
      if ((await eventHash(fields)) !== hash) {
        broken = { seq: event.seq, reason: "bad_hash" };
        break;
      }
      expectedSeq = event.seq + 1;
      expectedPrev = event.hash;
    }

    const through = page.length === 0 ? from - 1 : page[page.length - 1]!.seq;
    const state = {
      // A break leaves the cursor where it was, so the next run walks the same
      // page again: the stage must go on reading failing until the row is back.
      checked_through: broken === null ? through : stored.checked_through,
      break_seq: broken === null ? null : broken.seq,
    };
    await writeChainCheckState(db, state, at);
    if (broken !== null) skip("chain_break");
    return {
      from,
      through,
      events: page.length,
      checked_through: state.checked_through,
      wrapped,
      break: broken,
    };
  } catch {
    skip("chain_failed");
    return null;
  }
}

/**
 * (j3) Give the rows carrying no duplicate key theirs.
 *
 * Decision D-085 and migration 0019: the duplicate rule — domain, subject,
 * category, the normalized `after` and, since the QA of 2026-09-12, the
 * normalized `effective_at` — is a column and an index, and both doors ask it
 * with one seek (`liveDuplicateOf`). A row whose key has not been computed
 * under the rule in force carries null, which is invisible to the index, so
 * until it is filled the log would take a second copy of a claim it already
 * holds. SQL cannot compute the key — the norm rule is Unicode normalization
 * and whitespace folding over arbitrary text — so the backfill is code, and
 * this is where code runs on a clock rather than on somebody's request.
 *
 * Two migrations feed it and it cannot tell them apart, which is the point:
 * 0019 added the column to rows that never had one, and 0020 set every row back
 * to null so `effective_at` could join the key. Both are "this row's key is not
 * current", both are answered by recomputing from the row's own signed core,
 * and the next change to the rule is one more `UPDATE ... SET duplicate_key =
 * NULL` and no new code at all.
 *
 * Bounded like every other step: at most DUPLICATE_BACKFILL_PER_RUN rows a run,
 * and the next run continues from whatever is left, because a table that only
 * grows must not be rewritten whole inside one request. `backfillDuplicateKeys`
 * is idempotent by its own WHERE, so a run interrupted halfway costs nothing.
 *
 * Idle once there is nothing left to fill: the one statement it makes is the
 * bounded SELECT for null keys, which comes back empty, and it writes nothing.
 * That is the state every deployment reaches a few runs after the migration and
 * stays in forever, which is why it is last in the run and why it appends no
 * event — nothing here is a fact about the record, only about the index over
 * it.
 *
 * A normal skip when it fails, for the same reason the counters step is: the
 * column is a function of the entry's own signed core and never a source of
 * truth, so a run that could not fill a row has still swept.
 */
export async function duplicateBackfillStep(
  db: D1Like,
  skip: Skip,
): Promise<SweepReport["duplicates"]> {
  try {
    const filled = await backfillDuplicateKeys(db, DUPLICATE_BACKFILL_PER_RUN);
    return { filled };
  } catch {
    skip("duplicate_backfill_failed");
    return null;
  }
}

/**
 * What a thrown thing says, as one line for the board.
 *
 * A step that throws did not refuse under a rule — there is no reason name for
 * "D1 was gone" — so the board shows the message itself rather than inventing a
 * word for it.
 */
function thrownReason(failure: unknown): string {
  return failure instanceof Error ? failure.message : String(failure);
}

/**
 * Run one sweep.
 *
 * Never throws for a rule: every refusal from the kernel is counted and the run
 * carries on to the next entry. A storage failure does throw, because a sweep
 * that could not read the log has not swept and the platform should see that.
 */
export async function runSweep(
  env: Env,
  deps: SweepDeps,
): Promise<SweepReport> {
  const db = env.DB;
  const at = deps.now.toISOString();
  const skipped: Record<string, number> = {};
  // Which step the run is in, for the status board only (M23, decision D-076).
  // The report is untouched by it: `skipped` counts exactly what it always
  // counted, and this records, per step, the first reason that step gave.
  let inStep = SWEEP_STEPS[0]!;
  // What each step spent, in wall-clock milliseconds. `Date.now()` and not the
  // injected clock on purpose: the injected clock is the log's time and does not
  // move inside a run, and what this measures is exactly what that hides — time
  // spent waiting on D1 and on the network. It never leaves the report.
  const durations: Record<string, number> = {};
  let stepStartedAt = Date.now();
  const closeStep = (): void => {
    const now = Date.now();
    durations[inStep] = (durations[inStep] ?? 0) + (now - stepStartedAt);
    stepStartedAt = now;
  };
  /** Close the step that was running and start the next one. */
  const enter = (step: string): void => {
    closeStep();
    inStep = step;
  };
  const stepSkip = new Map<string, string>();
  const noteSkip = (step: string, reason: string): void => {
    if (!stepSkip.has(step)) stepSkip.set(step, reason);
  };
  const skip = (reason: string): void => {
    skipped[reason] = (skipped[reason] ?? 0) + 1;
    noteSkip(inStep, reason);
  };

  // What the board is written from, hoisted out of the run because the rows are
  // written in a `finally`: a step that throws — D1 gone, an adapter breaking
  // its contract — still leaves a board saying which step it was in, which is
  // exactly the run a reader most needs to see.
  let beacon: Beacon | null = null;
  let beaconRefusal: string | null = null;
  /** Whether any step asked the chain for a round on this run. */
  let beaconRead = false;
  /**
   * The word a run that never needed one records.
   *
   * A run that owes no draw makes no beacon read (below), and the board has to
   * tell that from a read that failed: "nothing asked for one" is the clockwork
   * working, and `beacon_unavailable` is not. The status rules read the reason
   * word, and this one is not among the beacon's refusals (src/status.ts), so
   * the stage reads as a stage with no round rather than as one that is down.
   */
  const NO_DRAW_DUE = "no_draw_due";
  let report: SweepReport | null = null;
  /** What a refused mirror push said, or null while none has refused. */
  let mirrorDetail: string | null = null;
  /** The step the run threw in, or null while nothing has thrown. */
  let failedStep: string | null = null;
  /** Whether this run started at all. False only when it refused to. */
  let ran = true;

  // One registry reading for the whole run. Every step below that gathers an
  // entry's world asks the registry for it, and the registry is the same for all
  // of them: a run that re-read it per entry spent most of its subrequests
  // answering one question over and over. Created here and never outside a run,
  // because an isolate outlives the run and a registry remembered past it would
  // answer the next run with a log that has moved.
  const cache = worldCache();

  try {
    // Before anything is read, and before any adapter is asked for anything: a
    // deployment whose `ENVIRONMENT` is not one of the names this code knows
    // must not sweep (the QA of 2026-09-12). The name chooses the payout, the
    // payment and the witness adapters, and each picks its mock by asking
    // whether the name is `production` — so a var misspelt `prodcution` would
    // have countersigned real seals with a published test key and paid nobody,
    // quietly. The run does nothing at all and records the reason on every
    // step, which is how /status shows it rather than showing a clockwork that
    // looks like it is running.
    if (!environmentConfigured(env)) {
      ran = false;
      for (const step of SWEEP_STEPS) noteSkip(step, ENVIRONMENT_MISCONFIGURED);
      skipped[ENVIRONMENT_MISCONFIGURED] = SWEEP_STEPS.length;
      report = nothingSwept(at, skipped, durations);
      return report;
    }

    enter("snapshot");
    // (a) The pool snapshot. Committed before any draw, and never by a draw: the
    // commitment has to be in the log before the beacon round that uses it.
    const registry = await registryEvents(db, cache);
    // Decision D-071: every draw below is domain-blind by construction, so the
    // caller is the one that keeps an operator out of a domain it never attested
    // in. This is the fold the exclusion lists are built from, taken once for the
    // run and read again after the snapshot is sealed, because a registration in
    // this same run would otherwise be invisible to it.
    let snapshot: SweepReport["snapshot"] = null;
    const owed = poolSnapshotDue(registry);
    if (owed !== null) {
      const event = await recordPoolSnapshot(db, {
        at,
        type: "pool_snapshot",
        entry_id: null,
        payload: { operators: [...owed] },
      });
      // Kept in hand rather than re-read: the draws below read the pool through
      // the same events this run just sealed.
      registry.push(event);
      snapshot = { seq: event.seq, operators: [...owed] };
    }

    enter("expiry");
    // (b) Expiry. The rows say which assignments are past their deadline; the
    // kernel says whether each one is still open and really missed, because the
    // row is only an index into the log and the log is the record.
    const missed: SweepMiss[] = [];
    for (const due of await dueAssignments(db, at, LIST_PAGE_LIMIT)) {
      const events = await eventsForEntry(db, due.entryId);
      const open = openAssignmentOf(events, due.entryId);
      if (open === null || open.seq !== due.assignment.seq) {
        skip("assignment_not_open");
        continue;
      }
      if (!isAssignmentMissed(open, { now: at })) {
        skip("assignment_not_missed");
        continue;
      }
      const event = await recordAssignmentMissed(
        db,
        buildAssignmentMissed({ entryId: due.entryId, at, assignment: open }),
        open.seq,
      );
      missed.push({
        entry_id: due.entryId,
        operator: open.operator,
        agent: open.agent,
        seq: event.seq,
      });
    }

    enter("revalidation");
    // (b2) The same expiry, for the other purpose. Section 6, "Revalidate": the
    // check carries the same seventy-two hours as a validation assignment, and a
    // checker who lets them run out is missed exactly as a validator is. A miss
    // closes the assignment and never the request — the check is still owed — so
    // the draw step below finds the request open again and redraws it.
    const revalidationMissed: SweepRevalidationMiss[] = [];
    for (const due of await dueRevalidationAssignments(db, at, LIST_PAGE_LIMIT)) {
      const open = await openRevalidationAssignment(db, due.entryId);
      if (open === null || open.seq !== due.assignment.seq) {
        skip("revalidation_not_open");
        continue;
      }
      if (!isAssignmentMissed(open, { now: at })) {
        skip("revalidation_not_missed");
        continue;
      }
      const world = await entryWorld(db, due.entryId, cache);
      const event = await recordRevalidationMissed(
        db,
        {
          event: {
            at,
            type: "revalidation_missed",
            entry_id: due.entryId,
            payload: {
              request_seq: due.requestSeq,
              agent: open.agent,
              operator: open.operator,
            },
          },
          // The row is rewritten so the sidecar's view of the check goes back to
          // having no draw standing, which is what a reader is owed the moment
          // the window ran out.
          stored: (missedEvent): StoredEntryInput => {
            const derived = rederive(world, due.entryId, deps.now, [missedEvent]);
            return {
              entry: derived.entry,
              sidecar: derived.sidecar,
              derivedThroughSeq: missedEvent.seq,
            };
          },
        },
        open.seq,
      );
      revalidationMissed.push({
        entry_id: due.entryId,
        request_seq: due.requestSeq,
        operator: open.operator,
        agent: open.agent,
        seq: event.seq,
      });
    }

    enter("draws");
    // (c) The draws. One beacon read for the whole run, so every entry drawn in
    // this run is drawn against the same public round — and none at all on a run
    // that draws nothing.
    //
    // Read where the draw is decided rather than here, because the rule already
    // says which entries are owed one and reading the chain for a run that owes
    // none is a network call made on the strength of nothing: a log whose pool
    // is below the switch owes no draw at all, and its sweep spent a round trip
    // to the beacon every few minutes to be told what the log had already said.
    const readBeacon = async (): Promise<Beacon | null> => {
      if (!beaconRead) {
        beaconRead = true;
        const result = await deps.beacon.latest();
        beacon = result.ok ? result.beacon : null;
        beaconRefusal = result.ok ? null : result.reason;
      }
      return beacon;
    };

    // The queue's own bound (the QA of 2026-09-12): the drafts submitted within
    // DRAW_DRAFT_MAX_AGE_DAYS of this run's clock, and not every draft the log
    // has ever held. An abandoned draft leaves the working set on the day it
    // ages out, so a run's cost follows how much was submitted lately rather
    // than how much was ever submitted. It is a bound on the queue and not on
    // the entry: the draft is still a draft, still readable, and a volunteer
    // may still validate it — what it stops getting is a draw, and a validation
    // does not put it back, because the cutoff is on `submitted_at` and nothing
    // moves that.
    const drawnSince = new Date(
      Date.parse(at) - DRAW_DRAFT_MAX_AGE_DAYS * MILLISECONDS_PER_DAY,
    ).toISOString();
    const drawn: SweepDraw[] = [];
    let afterSubmittedSeq: number | undefined;
    for (;;) {
      const page = await listEntries(db, {
        status: "draft",
        limit: LIST_PAGE_LIMIT,
        submittedAtOrAfter: drawnSince,
        ...(afterSubmittedSeq === undefined ? {} : { afterSubmittedSeq }),
      });
      if (page.length === 0) break;

      for (const stored of page) {
        const entryId = (stored.entry as Record<string, unknown>)["id"] as string;
        const events = await eventsForEntry(db, entryId);
        const all = [...registry, ...events];

        // Whether a draw is owed at all is read from the log, and from the status
        // and the split derivation already computed. Asked before the beacon, so
        // an entry that is owed no draw reports the rule that says so rather than
        // whatever the network happened to answer.
        const due = drawDue({
          events: all,
          entryId,
          status: (stored.entry as Record<string, unknown>)[
            "status"
          ] as EntryStatus,
          needsReplacement: stored.sidecar.needs_replacement,
        });
        if (!due.due) {
          skip(due.reason);
          continue;
        }

        // A draw is owed, so the chain is asked — once, for the whole run.
        const round = await readBeacon();
        if (round === null) {
          skip(beaconRefusal ?? "beacon_unavailable");
          continue;
        }

        const pool = latestPoolSnapshot(all, headPosition(all));
        if (pool === null) {
          skip("no_pool_snapshot");
          continue;
        }

        // Who could not judge this entry if they were drawn. The QA of
        // 2026-09-12: drawing an operator the validation door would refuse is
        // drawing nobody — the seventy-two hours run out, the miss costs that
        // operator standing for a decision it was never allowed to make, and the
        // entry waits for a replacement draw to make the same mistake. So the
        // draw asks the one eligibility predicate derivation and the door ask
        // (src/derive.ts, `mayValidateEntry`), over the whole registry and the
        // challenged entry's own events, rather than restating a subset of the
        // rules here. `exclusionsFor` stays beside it because it answers a
        // different question — who has already signed, and who has already
        // missed — which is a fact about this entry's history and not about
        // eligibility.
        //
        // The entry's domain and subject are read off its stored copy, which
        // carries the signed core verbatim; a legacy v0.6 entry names no domain
        // and reads as ai-ecosystem.
        const target = {
          id: entryId,
          authorOperator:
            ((stored.entry as Record<string, unknown>)["author_operator"] as
              | string
              | null) ?? null,
          domain: domainOf(stored.entry),
          subject: (stored.entry as Record<string, unknown>)["subject"],
        };
        // A challenge's extra exclusion (Section 6) is carried by the CHALLENGED
        // entry's events — the `dispute_filed` event is scoped to the target —
        // so those are fetched when, and only when, this entry is a challenge.
        const disputed = await disputeOf(db, entryId);
        const eligibilityEvents =
          disputed === null
            ? all
            : [...all, ...(await eventsForEntry(db, disputed))];
        const draw = await drawValidator({
          entryId,
          snapshot: pool,
          beacon: round,
          exclude: [
            ...exclusionsFor(all, entryId),
            ...pool.operators.filter(
              (operator) =>
                !mayValidateEntry(
                  eligibilityEvents,
                  headPosition(eligibilityEvents),
                  target,
                  operator,
                ),
            ),
          ],
        });
        if (!draw.ok) {
          // snapshot_after_beacon is the paper's own ordering rule: the round
          // this run can read precedes the snapshot it would draw against, so the
          // entry waits for a later round rather than being drawn against a
          // commitment made after it.
          skip(draw.reason);
          continue;
        }

        // Identity and operators: the operator is the unit of assignment, and the
        // agent named beside it is the first one bound under it.
        const agents = await agentsForOperator(db, draw.operator, LIST_PAGE_LIMIT);
        const agent = agents[0];
        if (agent === undefined) {
          skip("no_agent_for_operator");
          continue;
        }

        const event = await recordAssignment(
          db,
          buildAssignment({
            entryId,
            at,
            agent: agent.agentId,
            operator: draw.operator,
            beaconRound: round.round,
            replacement: due.replacement,
          }),
        );

        // The entry itself is rederived so its stored copy is caught up with the
        // log; an assignment changes no derived field, and derived_through_seq
        // saying otherwise would be a row that had fallen behind its own events.
        const derived = deriveEntry([...all, event], entryId, { now: at });
        await putEntry(db, derived.entry, derived.sidecar, event.seq);

        drawn.push({
          entry_id: entryId,
          operator: draw.operator,
          agent: agent.agentId,
          beacon_round: round.round,
          replacement: due.replacement,
          seq: event.seq,
        });
      }

      if (page.length < LIST_PAGE_LIMIT) break;
      afterSubmittedSeq = page[page.length - 1]!.submittedSeq;
    }

    // (c2) The revalidation draws. Section 6, "Revalidate": the request "is
    // assigned at random to a TRUSTED OPERATOR", by the same public randomness as
    // a validation draw and against the same committed snapshot, so anyone
    // holding the log and the beacon can recompute who should have been drawn.
    //
    // The requests are found through the (type, seq) index rather than by scanning
    // the log: every `revalidation_requested` ever made, paged, and each one asked
    // of the kernel whether it is still open. That is bounded by how many checks
    // have ever been asked for, which is what the cap and the stake exist to keep
    // small.
    enter("revalidation");
    const revalidationDrawn: SweepRevalidationDraw[] = [];
    let afterRequestSeq = -1;
    for (;;) {
      const requests = await eventsOfType(
        db,
        "revalidation_requested",
        afterRequestSeq,
        LIST_PAGE_LIMIT,
      );
      if (requests.length === 0) break;

      for (const request of requests) {
        const entryId = request.entry_id;
        // Unreachable: `appendEvent` refuses an entry-scoped event without one.
        if (entryId === null) continue;

        const world = await entryWorld(db, entryId, cache);
        const open = openRevalidation(world.entryEvents);
        if (open === null || open.seq !== request.seq) {
          skip("revalidation_resolved");
          continue;
        }
        if ((await openRevalidationAssignment(db, entryId)) !== null) {
          skip("revalidation_assigned");
          continue;
        }

        // The same one read, whichever step needs it first.
        const round = await readBeacon();
        if (round === null) {
          skip(beaconRefusal ?? "beacon_unavailable");
          continue;
        }

        const all = [...registry, ...world.entryEvents];
        const pool = latestPoolSnapshot(all, headPosition(all));
        if (pool === null) {
          skip("no_pool_snapshot");
          continue;
        }

        // The submitter's operator and the requester's, and nobody else's: a
        // revalidation is a recheck rather than a challenge, so it does not carry
        // the dispute's extra exclusion (src/dispute.ts).
        const submission = world.entryEvents.find(
          (event) => event.type === "entry_submitted",
        ) as Event<"entry_submitted"> | undefined;
        const authorOperator =
          (submission?.payload.core["author_operator"] as string | null) ?? null;
        const exclude = [
          ...revalidationDrawExclusions(
            authorOperator,
            (open as Event<"revalidation_requested">).payload.operator,
          ),
          // And every pool operator not attested in the entry's own domain, off
          // the signed core the submission event carries (decision D-071).
          ...outsideDomain(
            operatorDomainsAt(registry, headPosition(registry)),
            pool.operators,
            domainOf(submission?.payload.core ?? null),
          ),
        ];

        // The M4 draw first, so above the switch a checker and a validator are
        // drawn by exactly the same function. Below it, `drawChecker` answers the
        // same question without the rule that belongs to validation alone.
        const attempted = await drawValidator({
          entryId,
          snapshot: pool,
          beacon: round,
          exclude,
        });
        const draw =
          !attempted.ok && attempted.reason === "pool_below_switch"
            ? await drawChecker({ entryId, snapshot: pool, beacon: round, exclude })
            : attempted;
        if (!draw.ok) {
          skip(draw.reason);
          continue;
        }

        // Identity and operators: the operator is the unit, and the agent named
        // beside it is the first one bound under it.
        const agents = await agentsForOperator(db, draw.operator, LIST_PAGE_LIMIT);
        const agent = agents[0];
        if (agent === undefined) {
          skip("no_agent_for_operator");
          continue;
        }

        const event = await recordRevalidationAssignment(db, {
          event: {
            at,
            type: "revalidation_assigned",
            entry_id: entryId,
            payload: {
              request_seq: request.seq,
              agent: agent.agentId,
              operator: draw.operator,
              beacon_round: round.round,
              // The same seventy-two hours a validation assignment carries.
              deadline: assignmentDeadline(at),
            },
          },
          stored: (assigned): StoredEntryInput => {
            const derived = rederive(world, entryId, deps.now, [assigned]);
            return {
              entry: derived.entry,
              sidecar: derived.sidecar,
              derivedThroughSeq: assigned.seq,
            };
          },
        });

        revalidationDrawn.push({
          entry_id: entryId,
          request_seq: request.seq,
          operator: draw.operator,
          agent: agent.agentId,
          beacon_round: round.round,
          seq: event.seq,
        });
      }

      afterRequestSeq = requests[requests.length - 1]!.seq;
      if (requests.length < LIST_PAGE_LIMIT) break;
    }

    enter("staleness");
    // (d) Staleness. Whitepaper Section 7, "Freshness and decay": past its window
    // an entry stays verified but shows as stale. Nobody appends an event for
    // that — the window closing is a fact about the calendar and about the log,
    // and derivation already computes it — so this step appends nothing. It finds
    // the rows the day turned on and rewrites them from their own events, which
    // is what makes the stored copy agree with what a reader deriving for
    // themselves would get.
    //
    // The rederivation goes through the entry's whole world (src/worker/world.ts)
    // rather than its own events alone, because a superseded entry can also go
    // stale, and reading it without its superseders would drop the
    // `superseded_by` the log says is there.
    const staled: string[] = [];
    const today = at.slice(0, 10);
    let afterExpiresAt: string | undefined;
    let afterId: string | undefined;
    for (;;) {
      const page = await staleDue(
        db,
        afterExpiresAt === undefined || afterId === undefined
          ? { today, limit: LIST_PAGE_LIMIT }
          : { today, limit: LIST_PAGE_LIMIT, afterExpiresAt, afterId },
      );
      if (page.length === 0) break;

      for (const due of page) {
        const world = await entryWorld(db, due.id, cache);
        const derived = rederive(world, due.id, deps.now);
        // The column said the window had run out; derivation is the authority on
        // whether it actually has. A row that comes back fresh is left alone —
        // storing it would be storing the column's opinion over the log's — and
        // the cursor carries past it, so the loop still terminates.
        if (!derived.derived.stale) {
          skip("not_stale_on_rederive");
          continue;
        }
        // A rewrite is a write, so the whole derived entry goes past the
        // published schema first, exactly as the two write doors do it before
        // they store anything. A refusal is counted like any other rule rather
        // than thrown — the run carries on — and, as with a row that came back
        // fresh, the cursor carries past the row it refused, so the loop still
        // terminates.
        if (!passesSchemaForRewrite(derived.entry)) {
          skip("schema_invalid");
          continue;
        }
        // The entry is stored at the position it was already derived through: no
        // event was appended, so the log has not moved.
        const stored = await getEntry(db, due.id);
        await putEntry(
          db,
          derived.entry,
          derived.sidecar,
          stored?.derivedThroughSeq ?? headPosition(world.entryEvents),
        );
        staled.push(due.id);
      }

      // Keyset, always advanced past the page just read. A row this run rewrote
      // leaves the index, so resuming from the start would be right too; resuming
      // from the cursor is what keeps a row it skipped from coming back forever.
      afterExpiresAt = page[page.length - 1]!.expires_at;
      afterId = page[page.length - 1]!.id;
    }

    enter("publish");
    // (e) The day's read counts. Before the seal on purpose: the count this run
    // publishes is sealed by this same run, which is what Section 9's "each day's
    // published count is the number the seal commits to" asks for. It needs
    // nothing but the clock, so it runs on every environment.
    const published = await publishStep(db, deps.now, at, skip);

    enter("attestation");
    // (e2) The attestations whose window ran out. Before the seal for the same
    // reason the read counts are: an expiry appended here is sealed by this same
    // run, so the log commits to it at once rather than a cycle later.
    const attestations = await attestationStep(db, at, skip);

    // (f), (g) and (h). The seal, the countersignatures, and yesterday's anchor,
    // in that order: a seal has to exist before anyone can countersign it, and a
    // day's roots have to be fixed before the day is anchored. Every refusal is
    // counted like the five steps above, and the run carries on.
    let sealed: SweepReport["sealed"] = null;
    let witnessed: SweepReport["witnessed"] = [];
    let anchored: SweepReport["anchored"] = null;
    let upgraded: SweepReport["upgraded"] = null;
    const sealing = sealingDeps(deps);
    enter("seal");
    if (sealing === null) {
      skip("sealing_unconfigured");
      // One refusal in the report, three steps on the status board: the witness
      // and anchor steps did not run either, and a board that showed them blank
      // would read as "never reached" rather than "not configured here".
      noteSkip("witness", "sealing_unconfigured");
      noteSkip("anchor", "sealing_unconfigured");
    } else {
      sealed = await sealStep(db, sealing, skip, cache);
      // Who the maintainer is, read exactly as derivation reads it: the operators
      // the registry events flag, at the head of what this run read.
      const { maintainers } = registeredOperatorsAt(
        registry,
        headPosition(registry),
      );
      enter("witness");
      witnessed = await witnessStep(db, sealing, maintainers, skip, cache);
      enter("anchor");
      anchored = await anchorStep(db, sealing, skip);
      // (h1) And, in the same step, one pending proof finished if a calendar
      // has finished one. After the day's anchor, because a day that was just
      // posted is never the day that is ready.
      upgraded = await upgradeStep(db, sealing, skip);
    }

    // (h2) The day's export to the public mirror. After the anchor, because the
    // anchor is the last thing that changes what a day's sealed record says, and
    // before the money, because the ledger reads the same sealed head this
    // export was built at. It never throws past this try/catch for a rule: every
    // refusal is counted like every step above it.
    enter("mirror");
    const mirrored = await mirrorStep(
      db,
      env.ENVIRONMENT,
      deps.mirror,
      deps.now,
      at,
      skip,
      cache,
    );
    mirrorDetail = mirrored.detail;

    // (i) and (j). The ledger and the standing, read off what the log has
    // sealed — this run's own seal included, which is why they come after the
    // seal step and not before it. A log with no seal at all has nothing either
    // of them may read, and both say so in the same word.
    let ledger: SweepReport["ledger"] = null;
    let standing: SweepReport["standing"] = null;
    let alerts: AlertStepReport = {
      created: 0,
      delivered: 0,
      failed: 0,
      retried: 0,
    };
    const sealedHead = await latestSeal(db);
    enter("ledger");
    if (sealedHead === null) {
      skip("unsealed");
      skip("unsealed");
      // The same refusals the report counts, told apart by step. The metering
      // and payout steps used to stand behind this same wall and are retired
      // (D-127), so the count is two rather than the three it was since M21.
      noteSkip("standing", "unsealed");
      noteSkip("alerts", "unsealed");
    } else {
      ledger = await ledgerStep(db, sealedHead.last_seq);
      // (i2) The change alerts, after the ledger and before the standing fold:
      // an endpoint hears about a sealed change in the run that sealed it.
      enter("alerts");
      alerts = await runAlertStep(
        db,
        {
          now: deps.now,
          sealedHead: sealedHead.last_seq,
          fetch: deps.alertFetch ?? globalThis.fetch.bind(globalThis),
          // The bodies carry paths and the reader knows the host it subscribed
          // to, so no origin is invented here (contract section 8.2).
          origin: "",
          ...(deps.alertTimeoutMs === undefined
            ? {}
            : { timeoutMs: deps.alertTimeoutMs }),
        },
        skip,
      );
      enter("standing");
      standing = await standingStep(db, sealedHead.last_seq, at, skip, cache);
    }

    // (j2) The counters the public pages read, after the standing step so the
    // trusted count is this run's, and outside the wall the three money steps
    // stand behind: a log with nothing sealed still has entries, operators and
    // an empty seals table to count, and a page on a fresh deployment should be
    // shown those rather than nothing. The position is then -1, which is what
    // "counted before anything was sealed" means everywhere else in this file.
    enter("counters");
    const counted = await countersStep(
      db,
      sealedHead === null ? -1 : sealedHead.last_seq,
      at,
      skip,
    );

    // (j2b) One page of the log, re-walked against the kernel's own hash rule.
    // After the counters and before the backfill: it reads the events table and
    // writes nothing to it, so it stands outside every wall above, and a run
    // that could not walk its page has still swept.
    enter("chain");
    const chain = await chainStep(db, at, skip);

    // (j3) The duplicate-key backfill, last and outside every wall: it reads no
    // seal, appends nothing, and on a log with nothing left to fill it is one
    // bounded read that finds nothing. Last so that a migrated log catching up
    // spends what is left of a run rather than what the steps above it need.
    enter("duplicates");
    const duplicates = await duplicateBackfillStep(db, skip);

    closeStep();
    report = {
      at,
      snapshot,
      missed,
      drawn,
      revalidation_drawn: revalidationDrawn,
      revalidation_missed: revalidationMissed,
      staled,
      published,
      attestations,
      sealed,
      witnessed,
      anchored,
      upgraded,
      mirror: mirrored.report,
      ledger,
      alerts,
      standing,
      counters: counted.counters,
      swept: counted.swept,
      chain,
      duplicates,
      skipped,
      durations,
    };

    // The run's own account of itself, once, on stdout. Nothing else surfaces the
    // skip counts in production: a scheduled sweep has no caller to hand the
    // report to, so a step that did nothing looked the same as one that was never
    // reached. Cloudflare's observability keeps this line, which is how a
    // `witness_pending` in production becomes a reason someone can read.
    //
    // Safe to log in full: the report is ids, positions, counts, operator names
    // and reason names. No key, credential or bearer token is ever in it, and the
    // adapters that hold those never put them in what they return.
    console.log(JSON.stringify({ sweep: report }));

    return report;
  } catch (failure) {
    // The step the run was in when it threw, marked with what the throw said,
    // and the run itself with it, because a run that fell over did not get
    // through. `noteSkip` and not `skip`: the report counts rule refusals and a
    // throw is not one. The steps below this one get no row at all — they never
    // ran, and the row they have is the last run that did reach them. The error
    // is rethrown untouched, because a sweep that could not finish has not
    // swept and the platform should see that.
    failedStep = inStep;
    const reason = thrownReason(failure);
    noteSkip(inStep, reason);
    noteSkip("sweep", reason);
    throw failure;
  } finally {
    // (l) The status board, one row per step: when it last ran, when it last got
    // through, and what it last refused with. In a `finally` so the run that
    // failed is the one the board describes — on a throw it writes the steps
    // the run reached and no others, with no detail, because there is no report
    // to take it from, and the step that threw carries the message as its
    // reason.
    //
    // Nothing above it changes and nothing below reads it: the rows exist so
    // src/worker/status.ts can answer "is the clockwork running", which the
    // events table cannot, because a step that did nothing appends nothing.
    // A failure of this write is not caught either, for the same reason.
    await putSweepSteps(
      db,
      stepRows(at, report, deps, {
        stepSkip,
        beacon,
        // A run that never needed a round says so, rather than leaving the
        // stage looking like one that has never been read.
        beaconRefusal: beaconRead ? beaconRefusal : NO_DRAW_DUE,
        beaconNeeded: beaconRead,
        mirrorDetail,
        failedStep,
        ran,
      }),
    );
  }
}

/**
 * The report of a run that did nothing.
 *
 * Every field at its empty value, so a caller reading a report cannot tell a
 * misconfigured run from a busy one by its shape — only by `skipped`, which is
 * where the reason is. It is the report a run returns when it refuses to start,
 * and there is exactly one such refusal today.
 */
function nothingSwept(
  at: string,
  skipped: Readonly<Record<string, number>>,
  durations: Readonly<Record<string, number>>,
): SweepReport {
  return {
    at,
    snapshot: null,
    missed: [],
    drawn: [],
    revalidation_drawn: [],
    revalidation_missed: [],
    staled: [],
    published: [],
    attestations: { expired: [] },
    sealed: null,
    witnessed: [],
    anchored: null,
    upgraded: null,
    mirror: null,
    ledger: null,
    alerts: { created: 0, delivered: 0, failed: 0, retried: 0 },
    standing: null,
    counters: null,
    swept: null,
    chain: null,
    duplicates: null,
    skipped,
    durations,
  };
}

/** The sealing deps, or null when this caller asked for the sweep without them. */
function sealingDeps(deps: SweepDeps): SealingDeps | null {
  if (deps.witness === undefined || deps.anchor === undefined) return null;
  return {
    now: deps.now,
    witness: deps.witness,
    pinned: deps.pinned ?? { witnesses: [], registry: null },
    ineligibleAgents: deps.ineligibleAgents ?? new Set<string>(),
    anchor: deps.anchor,
  };
}

/**
 * The instant a step of this run last got through, or null when it did not.
 *
 * Null is "no news" and never "never": `putSweepSteps` carries the stored value
 * forward past a null, so a step that has been refusing since this morning keeps
 * the morning it last worked.
 */
function okAt(
  at: string,
  step: string,
  stepSkip: ReadonlyMap<string, string>,
): string | null {
  return stepSkip.has(step) ? null : at;
}

/**
 * What the board is written from besides the report: the reasons each step gave,
 * the beacon read (which no report field carries), and the step a run threw in.
 */
interface Board {
  readonly stepSkip: ReadonlyMap<string, string>;
  readonly beacon: Beacon | null;
  readonly beaconRefusal: string | null;
  /**
   * Whether the run asked the chain at all.
   *
   * False is a run that owed no draw, and its draws row is a step that worked:
   * `last_ok_at` for this one step means "the beacon answered", and a run that
   * never had to ask did what the rule said. Only a read that was made and came
   * back empty leaves the stage without a good instant.
   */
  readonly beaconNeeded: boolean;
  /** What a refused push said, which no report field carries. */
  readonly mirrorDetail: string | null;
  /** The step the run threw in, or null when it finished. */
  readonly failedStep: string | null;
  /**
   * Whether the run started at all.
   *
   * False only for a run that refused to start — today, a deployment whose
   * `ENVIRONMENT` is not a name this code knows. It is what keeps the draws
   * exemption below honest: "a run that owed no draw did what the rule said"
   * is true of a run that looked, and not of one that never got that far.
   */
  readonly ran?: boolean;
}

/**
 * One run's seventeen step rows.
 *
 * The details are each step's own slice of the report, plus the three facts no
 * report field carries and the status rules need: the round the beacon read (or
 * why it did not), and the sealed position the standing step recomputed against.
 *
 * A null report is the run that threw: there is no report to slice, so the rows
 * carry an empty detail and say only what the run is known to have done — when
 * it ran, what started it, and which step refused with what. Only the steps it
 * reached get a row, and the board is still written, because a run that fell
 * over is the one worth seeing.
 *
 * The beacon is the exception to what `last_ok_at` means. For every other step it
 * is "this run reached the step and it refused nothing"; for `draws` it is "the
 * beacon answered", because a run that skipped every draft with
 * `awaiting_volunteers` did exactly what the rule says and the status page's
 * beacon stage needs to know when a round last came back rather than when every
 * entry last happened to be drawable.
 */
function stepRows(
  at: string,
  report: SweepReport | null,
  deps: SweepDeps,
  board: Board,
): SweepStepRow[] {
  const { stepSkip, beacon, beaconRefusal, beaconNeeded } = board;
  const trigger = deps.trigger ?? "alarm";
  const details: Record<string, Record<string, unknown>> =
    report === null
      ? {}
      : {
          // The clock is injected and read once per run (decision D-013 as
          // amended), so a run begins and ends at the same instant of the log's
          // own time and the duration is zero by construction. The three keys
          // are here because the page reads them; none of them is a wall-clock
          // measurement and none pretends to be one.
          sweep: { started_at: at, finished_at: at, duration_ms: 0 },
          snapshot: {
            seq: report.snapshot === null ? null : report.snapshot.seq,
            operators: report.snapshot === null ? 0 : report.snapshot.operators.length,
          },
          expiry: { missed: report.missed.length },
          draws: {
            drawn: report.drawn.length,
            beacon_round: beacon === null ? null : beacon.round,
            beacon_at: beacon === null ? null : beacon.at,
            beacon_reason: beaconRefusal,
          },
          revalidation: {
            drawn: report.revalidation_drawn.length,
            missed: report.revalidation_missed.length,
          },
          staleness: { staled: report.staled.length },
          publish: {
            published: report.published.length,
            date:
              report.published.length === 0
                ? null
                : report.published[report.published.length - 1]!.date,
          },
          seal: report.sealed === null ? { seq: null } : { ...report.sealed },
          witness: {
            seals: report.witnessed.length,
            operators: report.witnessed.flatMap((one) => [...one.operators]),
          },
          anchor: report.anchored === null ? { date: null } : { ...report.anchored },
          mirror:
            report.mirror === null
              ? { date: null, detail: board.mirrorDetail }
              : { ...report.mirror },
          ledger: report.ledger === null ? { through: null } : { ...report.ledger },
          alerts: { ...report.alerts },
          standing:
            report.standing === null
              ? { position: null }
              : { ...report.standing, trusted: [...report.standing.trusted] },
          attestation: { expired: report.attestations.expired.length },
          // The counters step's own row carries both the counts it wrote and
          // the status board's numbers it took at the same instant, so the
          // gather reads them off a row it already reads.
          counters: {
            ...(report.counters === null
              ? { position: null }
              : report.counters),
            ...(report.swept ?? {}),
          },
          chain:
            report.chain === null
              ? { checked_through: null }
              : {
                  ...report.chain,
                  break_seq: report.chain.break === null ? null : report.chain.break.seq,
                  break_reason:
                    report.chain.break === null ? null : report.chain.break.reason,
                },
          duplicates:
            report.duplicates === null
              ? { filled: null }
              : { ...report.duplicates },
        };

  const failedAt =
    board.failedStep === null ? null : SWEEP_STEPS.indexOf(board.failedStep);
  // A run that threw never reached the steps below the one it threw in, so it
  // writes no row for them. Their stored row is the last run that did reach
  // them, and rewriting it would date a step to a run it had no part in and
  // wipe the detail the status rules read off it.
  const reached =
    failedAt === null ? SWEEP_STEPS : SWEEP_STEPS.slice(0, failedAt + 1);

  return reached.map((step) => {
    const reason = stepSkip.get(step) ?? null;
    return {
      step,
      last_run_at: at,
      last_ok_at:
        step === "draws" && board.ran !== false
          ? beacon === null && beaconNeeded
            ? null
            : at
          : okAt(at, step, stepSkip),
      last_skip_reason: reason,
      last_skip_at: reason === null ? null : at,
      detail: details[step] ?? {},
      trigger,
    };
  });
}

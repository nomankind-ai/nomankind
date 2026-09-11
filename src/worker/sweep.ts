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
import type { PaymentsAdapter } from "../adapters/stripe.js";
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
  operatorDomainsAt,
  registeredOperatorsAt,
  type EntryStatus,
} from "../derive.js";
import { openRevalidation, revalidationDrawExclusions } from "../dispute.js";
import { duplicateKey, sameDuplicateKey } from "../duplicate.js";
import { recordMeasured } from "../evidence.js";
import {
  appendEvent,
  type Event,
  type EventPayloads,
  type EventType,
  type ReadCountDuplicate,
  type ReadCountRow,
} from "../events.js";
import {
  bountyAccrualRow,
  clawbackRows,
  payoutPlan,
  payoutRow,
  readShareRows,
  reconciliationRow,
  type EntryShareState,
  type LedgerRow,
  type ReadShareSlotState,
} from "../ledger.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  SEAL_MAX_EVENTS,
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
import { standingAt, trustChangesAt } from "../standing.js";
import type { D1Like } from "../storage/d1.js";
import {
  EventAppendError,
  SealConflictError,
  agentsForOperator,
  anchorsAfter,
  appendEvents,
  bountiesForEntry,
  bountyPoolRows,
  dueAssignments,
  dueAttestations,
  dueRevalidationAssignments,
  earliestReadReceiptDay,
  entryIdsThrough,
  eventBySeq,
  eventsAfter,
  eventsForAttestation,
  eventsForEntry,
  eventsInRange,
  eventsOfType,
  getAnchor,
  getEntry,
  headSeq,
  heldReadShareRows,
  latestEventOfType,
  latestSeal,
  ledgerCursor,
  listAttestations,
  listEntries,
  listOperators,
  mirrorOn,
  openRevalidationAssignment,
  operatorDomains,
  payoutRows,
  priceBountyRow,
  pendingAnchorsAfter,
  putAnchor,
  putEntry,
  putLedgerRows,
  putMirror,
  putSweepSteps,
  readCandidates,
  readCounterRangeOn,
  readCountsByKeyOn,
  meterReported,
  putMeterReport,
  recordAssignment,
  recordAssignmentMissed,
  recordAttestationExpired,
  recordPayout,
  recordPoolSnapshot,
  recordRevalidationAssignment,
  recordRevalidationMissed,
  recordSeal,
  recordTrustChange,
  releasedUnpaidRows,
  sealsAfter,
  sealsSealedOn,
  setAnchorExternal,
  setLedgerCursor,
  setOperatorStanding,
  setSealRegistry,
  setSealWitnesses,
  staleDue,
  unwitnessedSeals,
  type OperatorRecord,
  type ReadCountKeyCursor,
  type ReadCountKeyRow,
  type StoredBountyRow,
  type SweepStepRow,
  type StoredEntry,
  type StoredEntryInput,
} from "../storage/repository.js";
import { keyById } from "../storage/keys.js";
import { checkWitnesses, witnessedCount, type Witness } from "../witness.js";
import { runAlertStep, type AlertStepReport } from "./alerts.js";
import type { Env } from "./env.js";
import { entryWorld, rederive, registryEvents, worldAt } from "./world.js";

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
   * Where a cycle's money leaves through (M21, decision D-053). Optional like
   * the sealing deps and for the same reason: a caller that asks for the sweep
   * without it gets every other step and a payout step that counts
   * `payout_unconfigured` rather than one that pretends to have paid.
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
   * Which door ran this sweep (M23, decision D-076): `cron` from the scheduled
   * handler in src/worker/index.ts, `alarm` from the Sweeper Durable Object.
   *
   * Optional and defaulted to `alarm`, because the alarm is the sweep's own
   * timer and the cron door is the repair for a chain that broke: a caller that
   * says nothing is the timer. It reaches only the `sweep_steps` rows the last
   * step writes, and no rule anywhere reads it — a step that ran did the same
   * work whichever door called it.
   */
  readonly trigger?: SweepTrigger;
  /**
   * Where the day's paid reads are reported (M24, decision D-078). Optional
   * like the payout and mirror adapters and for the same reason: a caller that
   * asks for the sweep without one gets a metering step that counts
   * `metering_unavailable` rather than one that pretends to have billed.
   */
  readonly payments?: PaymentsAdapter;
  /**
   * What the alert step delivers through. The platform's own fetch when a
   * caller says nothing; a test injects its own so no alert leaves the process.
   */
  readonly alertFetch?: typeof fetch;
}

/** Which door ran the sweep. */
export type SweepTrigger = "alarm" | "cron";

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
  "metering",
  "alerts",
  "standing",
  "payout",
  "attestation",
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
    readonly ok: boolean;
  } | null;
  /**
   * What this run told the payment provider: how many key-days it reported and
   * how many reads those carried (M24).
   *
   * Zeros rather than null when nothing was owed, because a run that reported
   * nothing did examine the question — and on a deployment with no provider at
   * all the answer is in `skipped` under `metering_unavailable`.
   */
  readonly metered: { readonly keys: number; readonly reads: number };
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
  /** The payouts this run made, one per operator at most (decision D-053). */
  readonly payouts: readonly {
    readonly operator: string;
    readonly amount: number;
    readonly transfer: string;
  }[];
  /** One count per reason nothing was done, keyed by the reason's own name. */
  readonly skipped: Readonly<Record<string, number>>;
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
): Promise<StoredEntryInput> {
  const world = await entryWorld(db, entryId);
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
 */
async function sealStep(
  db: D1Like,
  deps: SealingDeps,
  skip: Skip,
): Promise<SweepReport["sealed"]> {
  const previous = await latestSeal(db);
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
      rewriteForSeal(db, entryId, sealed, batch, now),
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
          rewriteForSeal(db, entryId, updated, batch, now),
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
 * (h) Anchor yesterday's seals into an external timestamping chain.
 *
 * Whitepaper, Lifecycle of an entry (Seal): "Anchoring each day's batch hash
 * into an external public timestamping chain ... makes the existence proof
 * independent of 1F916's maturity." Yesterday's, because today is not over: a
 * day anchored while seals are still being made would be false rather than
 * stale (src/anchor.ts, `verifyAnchor`).
 *
 * The record is written before the hash is posted, and the receipt is recorded
 * separately when it comes back, because the receipt is not in the anchor hash
 * (D-037): the day that was posted and the day that verifies are the same day.
 */
async function anchorStep(
  db: D1Like,
  deps: SealingDeps,
  skip: Skip,
): Promise<SweepReport["anchored"]> {
  const date = utcDay(
    new Date(deps.now.getTime() - MILLISECONDS_PER_DAY).toISOString(),
  );

  const existing = await getAnchor(db, date);
  if (existing !== null) {
    // Already anchored, and already carrying its receipt: nothing to do. Named
    // like every other no-op here, so a run that anchored nothing says why.
    if (existing.external !== null) {
      skip("already_anchored");
      return null;
    }
    const external = await postAnchor(deps, existing);
    if (external === null) skip("anchor_pending");
    else await setAnchorExternal(db, date, external);
    return {
      date,
      seals: existing.roots.length,
      external: external === null ? null : external.kind,
    };
  }

  const seals = await sealsSealedOn(db, date);
  if (seals.length === 0) {
    skip("no_seals_to_anchor");
    return null;
  }

  const built = await buildAnchor(seals, date);
  if (!built.ok) {
    skip(built.reason);
    return null;
  }

  await putAnchor(db, built.anchor);
  const external = await postAnchor(deps, built.anchor);
  if (external === null) skip("anchor_pending");
  else await setAnchorExternal(db, date, external);

  return {
    date,
    seals: seals.length,
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
 * Every entry at or below the sealed head, derived there.
 *
 * Exactly the way `GET /sync` produces an entry record — `worldAt` to the sealed
 * head, then `rederive` at the newest seal's `sealed_at` — because the mirror
 * and the delta stream must not be able to describe the same entry at the same
 * position two different ways. The stored row is not read: it was derived at
 * whatever position its last writer reached, which is not the sealed head.
 */
async function mirrorEntries(
  db: D1Like,
  head: number,
  asOf: Date,
): Promise<MirrorEntryRecord[]> {
  const records: MirrorEntryRecord[] = [];
  let afterSubmittedSeq: number | undefined;
  for (;;) {
    const page = await entryIdsThrough(
      db,
      afterSubmittedSeq === undefined
        ? { throughSeq: head, limit: LIST_PAGE_LIMIT }
        : { throughSeq: head, limit: LIST_PAGE_LIMIT, afterSubmittedSeq },
    );
    if (page.length === 0) break;
    for (const row of page) {
      const world = worldAt(await entryWorld(db, row.id), head);
      const derived = rederive(world, row.id, asOf);
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
async function mirrorStep(
  db: D1Like,
  environment: string,
  adapter: MirrorAdapter | undefined,
  now: Date,
  at: string,
  skip: Skip,
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
  if ((await mirrorOn(db, date)) !== null) {
    skip("mirror_current");
    return none;
  }

  const head = newest.last_seq;
  let files;
  try {
    files = buildMirror({
      environment,
      exported_at: at,
      seals: await allSeals(db),
      anchors: await allAnchors(db),
      events: await sealedLog(db, head),
      entries: await mirrorEntries(db, head, new Date(newest.sealed_at)),
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

/** Narrow one event to its own type, the way the kernel does it. */
function isEvent<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/** The UTC calendar day an instant falls on. */
function dayOf(at: string): string {
  return at.slice(0, 10);
}

/**
 * The cycle a payout belongs to.
 *
 * `PAYOUT_CYCLE` is monthly (decision D-053), so a cycle is a UTC calendar
 * month and its name is the month a date starts with. No policy number is
 * written here: the length of the cycle is the policy, and this is only how a
 * date is read as one.
 */
function cycleOf(at: string): string {
  return at.slice(0, 7);
}

/**
 * Whether the holder of one read-share slot measured anything (D-087).
 *
 * The slot carries the seq of the event that seated it, so the answer is one
 * event read back by position and one pure question asked of the record it
 * carries — a validation's ApproverRecord or a reconfirmation's. Anything else
 * at that position, and an event that is no longer there at all, is false: the
 * stated rate, never an invented observed one.
 */
async function slotMeasured(db: D1Like, seq: number): Promise<boolean> {
  const event = await eventBySeq(db, seq);
  if (event === null) return false;
  if (isEvent(event, "validation") || isEvent(event, "reconfirmation")) {
    return recordMeasured(event.payload.record);
  }
  return false;
}

/**
 * What pricing needs to know about an entry, read off its stored row.
 *
 * Every field is derivation's, exactly as `EntryShareState` asks: the author
 * operator off the signed core, the read-share slots off the sidecar, verified
 * off `verified_at`, and stale off the window against the day being priced
 * rather than against today — the day is what is being paid for, and an entry
 * that has gone stale since must not turn a fresh day's reads into half a day's.
 */
async function shareStateOf(
  db: D1Like,
  stored: StoredEntry,
  date: string,
): Promise<EntryShareState> {
  const entry = stored.entry as unknown as Record<string, unknown>;
  const author = entry["author_operator"];
  const expires = entry["expires_at"];
  const slots = stored.sidecar.read_share_slots;
  let seated: ReadShareSlotState[] | null = null;
  if (slots !== null) {
    seated = [];
    for (const slot of slots) {
      seated.push({
        operator: slot.operator,
        seq: slot.seq,
        measured: await slotMeasured(db, slot.seq),
      });
    }
  }
  return {
    author_operator: typeof author === "string" ? author : null,
    read_share_slots: seated,
    stale: typeof expires === "string" && expires < date,
    verified: typeof entry["verified_at"] === "string",
    effective_tier: stored.sidecar.effective_tier,
  };
}

/**
 * Price one published day of reads: a share row per holder, the withheld halves
 * of every stale entry, and the day's reconciliation beside them.
 *
 * Section 9: "Each day's published count is the number the seal commits to and
 * payouts are computed from." So the count this reads is the sealed event's own
 * and never the receipts underneath it, and the reconciliation says whether the
 * two still agree.
 */
async function priceDay(
  db: D1Like,
  event: Event<"read_count">,
): Promise<{ rows: LedgerRow[]; ok: boolean }> {
  const { date } = event.payload;
  const states = new Map<string, EntryShareState>();
  for (const read of event.payload.reads as readonly ReadCountRow[]) {
    const stored = await getEntry(db, read.entry_id);
    if (stored === null) continue;
    states.set(read.entry_id, await shareStateOf(db, stored, date));
  }

  const rows = readShareRows(event, (entryId) => states.get(entryId) ?? null);

  // Every share row of one entry carries that entry's published count, so the
  // map holds it once: the reconciliation asks what the ledger accrued for the
  // entry, not what each holder was paid.
  const accrued = new Map<string, number>();
  for (const row of rows) {
    if (row.kind !== "read_share") continue;
    if (row.entry_id === null || row.reads === null) continue;
    accrued.set(row.entry_id, row.reads);
  }
  const reconciliation = reconciliationRow(event, accrued);
  return {
    rows: [...rows, reconciliation],
    ok: reconciliation.ref["ok"] === true,
  };
}

/**
 * Which of `bountiesForEntry`'s two shapes this row is: the door's unpriced
 * accrual, which still carries the stale window, or the priced ledger row,
 * which does not.
 */
function isUnpricedAccrual(row: StoredBountyRow): row is BountyAccrual {
  return typeof row.stale_from === "string";
}

/**
 * Price one reconfirmation's bounty: the halves the entry withheld while it was
 * stale, summed over exactly the window the accrual names.
 *
 * Null when there is nothing to do — a reconfirmation inside the window accrued
 * no bounty and the door wrote no row — and null when the row has already been
 * priced, which is what keeps the step idempotent under a cursor set back.
 */
async function priceBounty(
  db: D1Like,
  event: Event<"reconfirmation">,
  entryId: string,
): Promise<LedgerRow | null> {
  const accruals = await bountiesForEntry(db, entryId, LIST_PAGE_LIMIT);
  const stored = accruals.find((candidate) => candidate.seq === event.seq);
  if (stored === undefined) return null;
  // A priced row carries the ledger record rather than the accrual, so the
  // window is no longer at the top of the payload: it has been priced already.
  if (!isUnpricedAccrual(stored)) return null;
  const accrual = stored;

  const pool = await bountyPoolRows(
    db,
    entryId,
    accrual.stale_from,
    dayOf(accrual.stale_until),
  );
  return bountyAccrualRow(event, accrual, pool);
}

/**
 * (i) Price everything the log has sealed since the last run.
 *
 * Whitepaper Section 9, Money: thirty percent of paid-read revenue goes to the
 * contributor pool, "accrued fees are held for thirty days before payout so an
 * upheld dispute can claw them back before they leave", and Section 7's stale
 * half builds up on the entry "as a reconfirmation bounty, paid to whoever makes
 * it fresh again". Three kinds of sealed event say those three things happened —
 * `read_count`, `dispute_upheld`, `reconfirmation` — and this reads them in log
 * order and writes what src/ledger.ts says they are worth.
 *
 * Only sealed events, ever: a price computed off an event the log has not
 * committed to could be recomputed differently later, and Section 9's promise
 * that an operator can reconcile a payout against the log would be worth
 * nothing. The cursor is what makes it a fold rather than a rescan, and losing
 * it costs only work: every row is idempotent by its id.
 */
async function ledgerStep(
  db: D1Like,
  sealedHead: number,
): Promise<SweepReport["ledger"]> {
  const cursor = (await ledgerCursor(db, LEDGER_CURSOR)) ?? -1;
  let readShares = 0;
  let clawbacks = 0;
  let bounties = 0;
  let reconciliations = 0;
  let ok = true;

  for (let from = cursor + 1; from <= sealedHead; ) {
    const to = Math.min(from + LIST_PAGE_LIMIT - 1, sealedHead);
    const page = await eventsInRange(db, from, to);
    for (const event of page) {
      if (isEvent(event, "read_count")) {
        const priced = await priceDay(db, event);
        await putLedgerRows(db, priced.rows);
        readShares += priced.rows.filter((row) => row.kind === "read_share").length;
        reconciliations += 1;
        if (!priced.ok) ok = false;
        continue;
      }

      if (isEvent(event, "dispute_upheld")) {
        const entryId = event.entry_id;
        // Unreachable: `appendEvent` refuses an entry-scoped event without one.
        if (entryId === null) continue;
        const held = await heldReadShareRows(db, entryId, event.at);
        const rows = clawbackRows(event, held);
        if (rows.length === 0) continue;
        await putLedgerRows(db, rows);
        clawbacks += rows.length;
        continue;
      }

      if (isEvent(event, "reconfirmation")) {
        const entryId = event.entry_id;
        if (entryId === null) continue;
        const row = await priceBounty(db, event, entryId);
        if (row === null) continue;
        // The unpriced accrual out and the priced row in, in one batch: the
        // delete is the only record that the bounty was ever owed, so it must
        // not be able to land without the price.
        await priceBountyRow(db, row.id, row);
        bounties += 1;
      }
    }
    from = to + 1;
  }

  await setLedgerCursor(db, LEDGER_CURSOR, sealedHead);
  return {
    through: sealedHead,
    read_shares: readShares,
    clawbacks,
    bounties,
    reconciliations,
    ok,
  };
}

// ---------------------------------------------------------------------------
// (i2) The provider's meter: what the day's paid reads cost
// ---------------------------------------------------------------------------

/**
 * The metering step's cursor, named in `ledger_state` by the step itself.
 *
 * Its own cursor and not the ledger's, because the two answer to different
 * things: the ledger prices what the log published and can be replayed at will,
 * and this tells a payment provider to bill somebody, which cannot. A cursor
 * shared between them would mean a ledger replay re-billing every reader.
 */
export const METERING_CURSOR = "metering";

/** How many seconds there are in a day, less one: the day's last second. */
const LAST_SECOND_OF_DAY = 86_399;

/**
 * (i2) Report every published day of paid reads to the payment provider.
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily, so nomankind cannot quietly change the numbers later." The bill
 * follows the published number and never a private one: this reads the sealed
 * `read_count` events, takes `paid.keys` exactly as the log committed to it, and
 * sends one meter event per key per day. A reader can therefore check their
 * invoice against a number that was public before it was billed.
 *
 * Exactly once per key-day, guarded twice: the `meter_reports` row, which is
 * written only after the provider said yes, and the identifier
 * `<environment>:<date>:<key id>`, which is the provider's own idempotency key —
 * so a run that wrote the row and died before it committed still cannot bill
 * twice. The timestamp is the day's last second, because the usage belongs to
 * the day it was read on and not to the morning it was reported.
 *
 * Refusals are counted, never repaired. An adapter that is not there at all
 * stops the step (`metering_unavailable`): reporting half a day would leave the
 * rest to a run that could not tell which half. Anything else refuses one
 * key-day (`metering_failed`), leaves its row unwritten, and the next run tries
 * it again, because the cursor only moves past events every key-day of which
 * has a row.
 */
async function meteringStep(
  db: D1Like,
  environment: string,
  payments: PaymentsAdapter | undefined,
  sealedHead: number,
  now: Date,
  skip: Skip,
): Promise<SweepReport["metered"]> {
  const metered = { keys: 0, reads: 0 };
  if (payments === undefined) {
    skip("metering_unavailable");
    return metered;
  }

  const cursor = (await ledgerCursor(db, METERING_CURSOR)) ?? -1;
  if (cursor >= sealedHead) return metered;

  // Bounded like every other step: the rest is the next run's.
  const to = Math.min(cursor + LIST_PAGE_LIMIT, sealedHead);
  const page = await eventsInRange(db, cursor + 1, to);

  let through = cursor;
  let stalled = false;
  for (const event of page) {
    if (stalled) break;
    let complete = true;

    if (isEvent(event, "read_count")) {
      const paid = event.payload.paid;
      const keys = paid === undefined ? {} : paid.keys;
      for (const keyId of Object.keys(keys).sort()) {
        const reads = keys[keyId] as number;
        if (reads <= 0) continue;
        if (await meterReported(db, keyId, event.payload.date)) continue;

        const key = await keyById(db, keyId);
        if (key === null) {
          // A published key nobody holds: there is no customer to bill, so the
          // key-day stays owed rather than being quietly dropped.
          skip("metering_failed");
          complete = false;
          continue;
        }

        const identifier = `${environment}:${event.payload.date}:${keyId}`;
        const reported = await payments.reportUsage({
          customer: key.customer,
          value: reads,
          identifier,
          timestamp: Math.floor(
            Date.parse(`${event.payload.date}T00:00:00Z`) / 1000,
          ) + LAST_SECOND_OF_DAY,
        });
        if (!reported.ok) {
          if (reported.refusal === "payments_unavailable") {
            skip("metering_unavailable");
            complete = false;
            stalled = true;
            break;
          }
          skip("metering_failed");
          complete = false;
          continue;
        }

        await putMeterReport(db, {
          key_id: keyId,
          date: event.payload.date,
          event_seq: event.seq,
          reads,
          identifier,
          reported_at: now.toISOString(),
        });
        metered.keys += 1;
        metered.reads += reads;
      }
    }

    if (!complete) {
      stalled = true;
      continue;
    }
    through = event.seq;
  }

  if (through > cursor) await setLedgerCursor(db, METERING_CURSOR, through);
  return metered;
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
 */
async function standingStep(
  db: D1Like,
  sealedHead: number,
  at: string,
  skip: Skip,
): Promise<SweepReport["standing"]> {
  const events = await sealedLog(db, sealedHead);
  const standings = standingAt(events, sealedHead);
  for (const [operator, standing] of standings) {
    // An operator the log mentions but nobody registered has no row to cache
    // this on, and the update simply matches nothing.
    await setOperatorStanding(db, operator, standing.standing, sealedHead);
  }

  const changes = trustChangesAt(events, sealedHead);
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

/**
 * One operator's cycle: what is released, whether it clears the floor, and the
 * transfer that took it out.
 *
 * Decision D-053: at most one payout batch per operator per cycle, above a
 * published minimum. Below it nothing is claimed and nothing is marked, so the
 * rows carry forward whole to the next cycle (src/ledger.ts, `payoutPlan`).
 */
async function payOperator(
  db: D1Like,
  adapter: PayoutAdapter,
  operator: OperatorRecord,
  sealedHead: number,
  at: string,
  skip: Skip,
): Promise<SweepReport["payouts"][number] | null> {
  const cycle = cycleOf(at);
  const paid = await payoutRows(db, LIST_PAGE_LIMIT, operator.id);
  if (paid.some((row) => row.date !== null && cycleOf(row.date) === cycle)) {
    skip("payout_this_cycle");
    return null;
  }

  const plan = payoutPlan(operator.id, await releasedUnpaidRows(db, operator.id, at), at);
  if (plan.rows.length === 0) {
    // Nothing due, or due but under the floor: either way nothing leaves and
    // nothing is claimed, and what there is carries to the next cycle.
    skip("payout_below_minimum");
    return null;
  }

  // The reference is the payment provider's name for this operator, stored when
  // it completed onboarding (Section 11). Nothing can be sent without one.
  const reference = operator.details["payout_reference"];
  if (typeof reference !== "string" || reference === "") {
    skip("payout_unavailable");
    return null;
  }

  const transfer = await adapter.transfer(reference, plan.amount);
  if (!transfer.ok) {
    // "unavailable" is nobody having asked and is retried next cycle;
    // "failed" is the provider having refused and waits for a person.
    skip(transfer.reason === "unavailable" ? "payout_unavailable" : "payout_failed");
    return null;
  }

  await recordPayout(
    db,
    payoutRow(plan, sealedHead, at, transfer.transfer),
    plan.rows,
  );
  return { operator: operator.id, amount: plan.amount, transfer: transfer.transfer };
}

/**
 * (k) Pay the cycle.
 *
 * Whitepaper Section 9: "Accrued fees are held for thirty days before payout",
 * and decision D-053 batches what is left per operator per calendar month above
 * a published minimum. Every operator is asked, in id order, because an operator
 * with nothing due is a real answer and a cycle that only looked at the ones it
 * expected would quietly drop the rest.
 *
 * The transfer is the one thing in this whole file that leaves the system, so it
 * is the one thing whose failure is counted three ways: below the floor,
 * unavailable, refused. On none of them is a row marked paid.
 */
async function payoutStep(
  db: D1Like,
  adapter: PayoutAdapter | undefined,
  sealedHead: number,
  at: string,
  skip: Skip,
): Promise<SweepReport["payouts"]> {
  if (adapter === undefined) {
    skip("payout_unconfigured");
    return [];
  }

  const payouts: SweepReport["payouts"][number][] = [];
  let afterId: string | undefined;
  for (;;) {
    const page = await listOperators(
      db,
      afterId === undefined
        ? { limit: LIST_PAGE_LIMIT }
        : { limit: LIST_PAGE_LIMIT, afterId },
    );
    if (page.length === 0) break;
    for (const operator of page) {
      const made = await payOperator(db, adapter, operator, sealedHead, at, skip);
      if (made !== null) payouts.push(made);
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    afterId = page[page.length - 1]!.id;
  }
  return payouts;
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
  let report: SweepReport | null = null;
  /** What a refused mirror push said, or null while none has refused. */
  let mirrorDetail: string | null = null;
  /** The step the run threw in, or null while nothing has thrown. */
  let failedStep: string | null = null;

  try {
    inStep = "snapshot";
    // (a) The pool snapshot. Committed before any draw, and never by a draw: the
    // commitment has to be in the log before the beacon round that uses it.
    const registry = await registryEvents(db);
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

    inStep = "expiry";
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

    inStep = "revalidation";
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
      const world = await entryWorld(db, due.entryId);
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

    inStep = "draws";
    // (c) The draws. One beacon read for the whole run, so every entry drawn in
    // this run is drawn against the same public round.
    const result = await deps.beacon.latest();
    beacon = result.ok ? result.beacon : null;
    beaconRefusal = result.ok ? null : result.reason;

    const drawn: SweepDraw[] = [];
    let afterSubmittedSeq: number | undefined;
    for (;;) {
      const page = await listEntries(
        db,
        afterSubmittedSeq === undefined
          ? { status: "draft", limit: LIST_PAGE_LIMIT }
          : { status: "draft", limit: LIST_PAGE_LIMIT, afterSubmittedSeq },
      );
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

        if (beacon === null) {
          skip(beaconRefusal ?? "beacon_unavailable");
          continue;
        }

        const pool = latestPoolSnapshot(all, headPosition(all));
        if (pool === null) {
          skip("no_pool_snapshot");
          continue;
        }

        // The dispute's own exclusions, plus every pool operator that never
        // attested in this entry's domain (decision D-071). The entry's domain is
        // read off its stored copy, which carries the signed core's `domain`
        // verbatim; a legacy v0.6 entry has none and reads as ai-ecosystem.
        const draw = await drawValidator({
          entryId,
          snapshot: pool,
          beacon,
          exclude: [
            ...exclusionsFor(all, entryId),
            ...outsideDomain(
              operatorDomainsAt(registry, headPosition(registry)),
              pool.operators,
              domainOf(stored.entry),
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
            beaconRound: beacon.round,
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
          beacon_round: beacon.round,
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
    inStep = "revalidation";
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

        const world = await entryWorld(db, entryId);
        const open = openRevalidation(world.entryEvents);
        if (open === null || open.seq !== request.seq) {
          skip("revalidation_resolved");
          continue;
        }
        if ((await openRevalidationAssignment(db, entryId)) !== null) {
          skip("revalidation_assigned");
          continue;
        }

        if (beacon === null) {
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
          beacon,
          exclude,
        });
        const draw =
          !attempted.ok && attempted.reason === "pool_below_switch"
            ? await drawChecker({ entryId, snapshot: pool, beacon, exclude })
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
              beacon_round: beacon.round,
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
          beacon_round: beacon.round,
          seq: event.seq,
        });
      }

      afterRequestSeq = requests[requests.length - 1]!.seq;
      if (requests.length < LIST_PAGE_LIMIT) break;
    }

    inStep = "staleness";
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
        const world = await entryWorld(db, due.id);
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

    inStep = "publish";
    // (e) The day's read counts. Before the seal on purpose: the count this run
    // publishes is sealed by this same run, which is what Section 9's "each day's
    // published count is the number the seal commits to" asks for. It needs
    // nothing but the clock, so it runs on every environment.
    const published = await publishStep(db, deps.now, at, skip);

    inStep = "attestation";
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
    inStep = "seal";
    if (sealing === null) {
      skip("sealing_unconfigured");
      // One refusal in the report, three steps on the status board: the witness
      // and anchor steps did not run either, and a board that showed them blank
      // would read as "never reached" rather than "not configured here".
      noteSkip("witness", "sealing_unconfigured");
      noteSkip("anchor", "sealing_unconfigured");
    } else {
      sealed = await sealStep(db, sealing, skip);
      // Who the maintainer is, read exactly as derivation reads it: the operators
      // the registry events flag, at the head of what this run read.
      const { maintainers } = registeredOperatorsAt(
        registry,
        headPosition(registry),
      );
      inStep = "witness";
      witnessed = await witnessStep(db, sealing, maintainers, skip);
      inStep = "anchor";
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
    inStep = "mirror";
    const mirrored = await mirrorStep(
      db,
      env.ENVIRONMENT,
      deps.mirror,
      deps.now,
      at,
      skip,
    );
    mirrorDetail = mirrored.detail;

    // (i), (j) and (k). The money and the standing, read off what the log has
    // sealed — this run's own seal included, which is why they come after the
    // seal step and not before it. A log with no seal at all has nothing any of
    // them may read, and all three say so in the same word.
    let ledger: SweepReport["ledger"] = null;
    let standing: SweepReport["standing"] = null;
    let payouts: SweepReport["payouts"] = [];
    let metered: SweepReport["metered"] = { keys: 0, reads: 0 };
    let alerts: AlertStepReport = {
      created: 0,
      delivered: 0,
      failed: 0,
      retried: 0,
    };
    const sealedHead = await latestSeal(db);
    inStep = "ledger";
    if (sealedHead === null) {
      skip("unsealed");
      skip("unsealed");
      skip("unsealed");
      // The same three refusals the report counts, told apart by step. The two
      // M24 steps read the same sealed events, so they are behind the same wall
      // and the board says so — without a fourth and fifth count, because the
      // report's `unsealed` has meant "the three money steps" since M21.
      noteSkip("standing", "unsealed");
      noteSkip("payout", "unsealed");
      noteSkip("metering", "unsealed");
      noteSkip("alerts", "unsealed");
    } else {
      ledger = await ledgerStep(db, sealedHead.last_seq);
      // (i2) The provider's meter, after the ledger and off the same sealed
      // events: what the log published is what a reader is billed for.
      inStep = "metering";
      metered = await meteringStep(
        db,
        env.ENVIRONMENT,
        deps.payments,
        sealedHead.last_seq,
        deps.now,
        skip,
      );
      // (i3) The change alerts, after the meter and before the standing fold:
      // an endpoint hears about a sealed change in the run that sealed it.
      inStep = "alerts";
      alerts = await runAlertStep(
        db,
        {
          now: deps.now,
          sealedHead: sealedHead.last_seq,
          fetch: deps.alertFetch ?? globalThis.fetch.bind(globalThis),
          // The bodies carry paths and the reader knows the host it subscribed
          // to, so no origin is invented here (contract section 8.2).
          origin: "",
        },
        skip,
      );
      inStep = "standing";
      standing = await standingStep(db, sealedHead.last_seq, at, skip);
      inStep = "payout";
      payouts = await payoutStep(db, deps.payout, sealedHead.last_seq, at, skip);
    }

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
      metered,
      alerts,
      standing,
      payouts,
      skipped,
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
        beaconRefusal,
        mirrorDetail,
        failedStep,
      }),
    );
  }
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
  /** What a refused push said, which no report field carries. */
  readonly mirrorDetail: string | null;
  /** The step the run threw in, or null when it finished. */
  readonly failedStep: string | null;
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
  const { stepSkip, beacon, beaconRefusal } = board;
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
          metering: { ...report.metered },
          alerts: { ...report.alerts },
          standing:
            report.standing === null
              ? { position: null }
              : { ...report.standing, trusted: [...report.standing.trusted] },
          payout: {
            payouts: report.payouts.length,
            amount: report.payouts.reduce((total, one) => total + one.amount, 0),
          },
          attestation: { expired: report.attestations.expired.length },
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
        step === "draws"
          ? beacon === null
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

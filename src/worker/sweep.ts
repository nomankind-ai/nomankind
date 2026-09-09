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
import type { EnvironmentWitnessAdapter } from "../adapters/witness.js";
import {
  buildAnchor,
  utcDay,
  type AnchorAdapter,
  type AnchorExternal,
} from "../anchor.js";
import {
  buildAssignment,
  buildAssignmentMissed,
  drawDue,
  drawValidator,
  exclusionsFor,
  isAssignmentMissed,
  latestPoolSnapshot,
  openAssignment as openAssignmentOf,
  poolSnapshotDue,
  type Beacon,
} from "../assign.js";
import {
  deriveEntry,
  registeredOperatorsAt,
  type EntryStatus,
} from "../derive.js";
import {
  appendEvent,
  type Event,
  type EventPayloads,
  type ReadCountRow,
} from "../events.js";
import {
  LIST_PAGE_LIMIT,
  SEAL_MAX_EVENTS,
  WITNESSES_REQUIRED,
} from "../policy.js";
import { buildReadCountPayload } from "../receipt.js";
import { validateEntry } from "../schema.js";
import {
  buildSeal,
  entrySeal,
  type EntrySeal,
  type Seal,
  type WitnessSignature,
} from "../seal.js";
import type { D1Like } from "../storage/d1.js";
import {
  EventAppendError,
  SealConflictError,
  agentsForOperator,
  appendEvents,
  dueAssignments,
  earliestReadReceiptDay,
  eventsAfter,
  eventsForEntry,
  eventsInRange,
  getAnchor,
  getEntry,
  headSeq,
  latestEventOfType,
  latestSeal,
  listEntries,
  putAnchor,
  putEntry,
  readCounterRangeOn,
  readCountsOn,
  recordAssignment,
  recordAssignmentMissed,
  recordPoolSnapshot,
  recordSeal,
  sealsSealedOn,
  setAnchorExternal,
  setSealRegistry,
  setSealWitnesses,
  staleDue,
  unwitnessedSeals,
  type StoredEntryInput,
} from "../storage/repository.js";
import { checkWitnesses, witnessedCount, type Witness } from "../witness.js";
import type { Env } from "./env.js";
import { entryWorld, rederive, registryEvents } from "./world.js";

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
}

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
 * Every row of one day's reads, grouped by entry, however many pages that takes.
 * A day with more entries than one page still publishes in full: a total that
 * left a page out would be exactly the under-count Section 9 asks readers to
 * check for.
 */
async function readsOn(db: D1Like, date: string): Promise<ReadCountRow[]> {
  const rows: ReadCountRow[] = [];
  let afterEntryId: string | undefined;
  for (;;) {
    const page = await readCountsOn(db, date, afterEntryId, LIST_PAGE_LIMIT);
    if (page.length === 0) break;
    rows.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    afterEntryId = page[page.length - 1]!.entry_id;
  }
  return rows;
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
    const rows = await readsOn(db, date);
    const range = await readCounterRangeOn(db, date);
    const payload = buildReadCountPayload(
      date,
      rows,
      range.counter_first,
      range.counter_last,
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
  if (!validateEntry(derived.entry).ok) throw new SealSchemaInvalid(entryId);
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
  const skip = (reason: string): void => {
    skipped[reason] = (skipped[reason] ?? 0) + 1;
  };

  // (a) The pool snapshot. Committed before any draw, and never by a draw: the
  // commitment has to be in the log before the beacon round that uses it.
  const registry = await registryEvents(db);
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

  // (c) The draws. One beacon read for the whole run, so every entry drawn in
  // this run is drawn against the same public round.
  const result = await deps.beacon.latest();
  const beacon: Beacon | null = result.ok ? result.beacon : null;
  const beaconRefusal = result.ok ? null : result.reason;

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

      const draw = await drawValidator({
        entryId,
        snapshot: pool,
        beacon,
        exclude: exclusionsFor(all, entryId),
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
      if (!validateEntry(derived.entry).ok) {
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

  // (e) The day's read counts. Before the seal on purpose: the count this run
  // publishes is sealed by this same run, which is what Section 9's "each day's
  // published count is the number the seal commits to" asks for. It needs
  // nothing but the clock, so it runs on every environment.
  const published = await publishStep(db, deps.now, at, skip);

  // (f), (g) and (h). The seal, the countersignatures, and yesterday's anchor,
  // in that order: a seal has to exist before anyone can countersign it, and a
  // day's roots have to be fixed before the day is anchored. Every refusal is
  // counted like the five steps above, and the run carries on.
  let sealed: SweepReport["sealed"] = null;
  let witnessed: SweepReport["witnessed"] = [];
  let anchored: SweepReport["anchored"] = null;
  const sealing = sealingDeps(deps);
  if (sealing === null) {
    skip("sealing_unconfigured");
  } else {
    sealed = await sealStep(db, sealing, skip);
    // Who the maintainer is, read exactly as derivation reads it: the operators
    // the registry events flag, at the head of what this run read.
    const { maintainers } = registeredOperatorsAt(
      registry,
      headPosition(registry),
    );
    witnessed = await witnessStep(db, sealing, maintainers, skip);
    anchored = await anchorStep(db, sealing, skip);
  }

  const report: SweepReport = {
    at,
    snapshot,
    missed,
    drawn,
    staled,
    published,
    sealed,
    witnessed,
    anchored,
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

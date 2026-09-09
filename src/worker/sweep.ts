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
 * and the page size is LIST_PAGE_LIMIT from src/policy.ts.
 */

import type { BeaconReader } from "../adapters/beacon.js";
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
import { deriveEntry, type EntryStatus } from "../derive.js";
import type { Event } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import { validateEntry } from "../schema.js";
import {
  agentsForOperator,
  dueAssignments,
  eventsForEntry,
  getEntry,
  listEntries,
  putEntry,
  recordAssignment,
  recordAssignmentMissed,
  recordPoolSnapshot,
  staleDue,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import { entryWorld, rederive, registryEvents } from "./world.js";

/** What the sweep is given in place of the world: the instant, and the beacon. */
export interface SweepDeps {
  readonly now: Date;
  readonly beacon: BeaconReader;
}

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

  return { at, snapshot, missed, drawn, staled, skipped };
}

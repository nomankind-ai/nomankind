/**
 * Status, read from the outside.
 *
 * Whitepaper Section 11, Deployment and status: nomankind publishes what it is
 * running and whether it is working. `GET /status` is the second half of that as
 * JSON — the stages, the doors nobody probes, four counters, and the two
 * thresholds the states were decided by, so a reader can check the arithmetic
 * without this Worker.
 *
 * Two doors, one answer. The HTML form is src/worker/pages.ts's, which calls the
 * same `statusInput` gatherer below and the same pure rules in src/status.ts, so
 * a reader who curls the path and a reader who opens it cannot be shown
 * different lights. Nothing is probed when either loads: every field is the
 * sweep's own stored account of its last run and what the log already holds. The
 * page cannot be warmed up by looking at it.
 *
 * Every read here is query-shaped and takes an explicit limit. Nothing loads a
 * table: the stage rules ask for counts, newest rows and one page of the two
 * deadline queues, which is what lets the endpoint stay cheap enough to be
 * hammered.
 *
 * No policy number lives here: the two thresholds are src/policy.ts's and are
 * echoed rather than restated, the page size is LIST_PAGE_LIMIT, and the bare
 * integers are HTTP status codes.
 */

import { mirrorKindFor } from "../adapters/mirror.js";
import { witnessAdapterFor } from "../adapters/witness.js";
import { utcDay } from "../anchor.js";
import type { Core } from "../core.js";
import type { EventPayloads } from "../events.js";
import {
  DOMAIN_SLUGS,
  LIST_PAGE_LIMIT,
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
} from "../policy.js";
import {
  exercisedStages,
  stageStates,
  statusCounters,
  type StatusInput,
} from "../status.js";
import type { D1Like } from "../storage/d1.js";
import {
  alertCursor,
  countAlertEndpoints,
  countDueDeliveries,
  countFailedDeliveries,
} from "../storage/alerts.js";
import {
  countAttestations,
  countEntries,
  countOperators,
  countSeals,
  countSealsSealedOn,
  countTrustedOperators,
  countWitnessedSeals,
  dueAssignments,
  dueAttestations,
  earliestReadReceiptDay,
  getAnchor,
  headSeq,
  latestEventsOfTypes,
  latestMirror,
  latestReceipt,
  latestSeal,
  ledgerCursor,
  newestUpgradedAnchor,
  readCounters,
  reconciliationRows,
  sweepSteps,
  trustedOperatorIds,
  unsealedEvents,
  type Counters,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  READ_METHODS,
  isRead,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** What this route is given besides its bindings: the instant. */
export interface StatusDeps {
  readonly now: Date;
}

const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * The log's counts: the row the sweep folded, or the counts themselves when no
 * sweep has folded one yet.
 *
 * The one fallback in the system, called by both doors that show these numbers —
 * this gatherer and the three page gatherers in src/worker/pages.ts — because
 * three copies of it would be three chances to get it wrong, and the wrong
 * answer here is the worst kind: zeros are a statement about the log, and a
 * populated log reporting none of anything is a status board saying the machine
 * has stopped. That is exactly what a deployment reports between the migration
 * that adds the counters table and its first sweep, which is minutes of every
 * upgrade.
 *
 * So a missing row is counted, the way every one of these pages counted before
 * the row existed: the same numbers, at the request's own cost, for as long as
 * it takes the sweep to run once. `updated_at` is empty and `position` is -1 on
 * that path, which is what "counted here, folded by nobody" means.
 */
export async function logCounters(db: D1Like): Promise<Counters> {
  const folded = await readCounters(db);
  if (folded !== null) return folded;

  const byDomain: Counters["entries_by_domain"] = {};
  for (const slug of DOMAIN_SLUGS) {
    byDomain[slug] = {
      entries: await countEntries(db, { domain: slug }),
      trusted_operators: await countTrustedOperators(db, slug),
    };
  }
  return {
    entries_total: await countEntries(db, {}),
    entries_verified: await countEntries(db, { status: "verified" }),
    entries_stale: await countEntries(db, { stale: true }),
    entries_by_domain: byDomain,
    operators_registered: await countOperators(db),
    operators_trusted: await countTrustedOperators(db),
    seals: await countSeals(db),
    seals_witnessed: await countWitnessedSeals(db),
    attestations: await countAttestations(db),
    // Nothing folded these, so there is no position they were folded at: both
    // are -1 and `updated_at` is empty on this path. No caller reads any of the
    // three to decide anything — the status board reads the newest seal itself —
    // and a caller that wants to know whether the sweep has ever folded asks
    // `readCounters`, which answers null until it has.
    sealed_head: -1,
    position: -1,
    updated_at: "",
  };
}

/** The UTC day before the one `now` falls on. */
function yesterdayOf(now: string): string {
  return utcDay(new Date(Date.parse(now) - MILLISECONDS_PER_DAY).toISOString());
}

/** A number off a stored step's detail, or null when it carries none. */
function detailNumber(
  detail: Record<string, unknown>,
  key: string,
): number | null {
  const value = detail[key];
  return typeof value === "number" ? value : null;
}

/**
 * The numbers the sweep counts once a run so the board does not count them once
 * a view.
 *
 * Named here rather than imported from src/worker/sweep.ts: that module is the
 * whole sweep, and this one only reads a row it wrote. The keys are the
 * counters step's own, and `countedNow` below
 * is the same twelve questions asked live, for a deployment whose counters step
 * has not run yet.
 */
interface SweptNumbers {
  readonly drafts: number;
  readonly head_seq: number;
  readonly overdue_assignments: number;
  readonly due_attestations: number;
  readonly seals_yesterday: number;
  readonly earliest_receipt_day: string | null;
  readonly alert_endpoints: number;
  readonly alert_cursor: number;
  readonly alert_due: number;
  readonly alert_failed: number;
}

/** A string off a stored step's detail, or null when it carries none. */
function detailText(
  detail: Record<string, unknown>,
  key: string,
): string | null {
  const value = detail[key];
  return typeof value === "string" ? value : null;
}

/**
 * What the counters step left on its board row, or null when it never ran.
 *
 * `head_seq` is the probe, because every one of these is written in the same
 * object by the same step: a row carrying it carries all twelve, and a row
 * without it is a board written before this existed or by a run that never
 * reached the step.
 */
function sweptNumbers(
  steps: readonly { readonly step: string; readonly detail: Record<string, unknown> }[],
): SweptNumbers | null {
  const row = steps.find((step) => step.step === "counters") ?? null;
  if (row === null) return null;
  const head = detailNumber(row.detail, "head_seq");
  if (head === null) return null;
  const at = (key: string): number => detailNumber(row.detail, key) ?? 0;
  return {
    drafts: at("drafts"),
    head_seq: head,
    overdue_assignments: at("overdue_assignments"),
    due_attestations: at("due_attestations"),
    seals_yesterday: at("seals_yesterday"),
    earliest_receipt_day: detailText(row.detail, "earliest_receipt_day"),
    alert_endpoints: at("alert_endpoints"),
    // The alert cursor is -1 before the step has read anything, which is not
    // the zero `at` would give: seq 0 is a real position.
    alert_cursor: detailNumber(row.detail, "alert_cursor") ?? -1,
    alert_due: at("alert_due"),
    alert_failed: at("alert_failed"),
  };
}

/**
 * The same twelve numbers, asked of the store directly.
 *
 * The cold path, and only the cold path: a deployment between the deploy and
 * its first sweep has no counters row, and a board showing zeros there would be
 * stating a fact about the log rather than about itself — exactly the reason
 * `logCounters` above counts rather than returning zeros.
 */
async function countedNow(
  db: D1Like,
  now: string,
  seal: { readonly last_seq: number } | null,
): Promise<SweptNumbers> {
  const head = await headSeq(db);
  return {
    drafts: await countEntries(db, { status: "draft" }),
    head_seq: head ?? -1,
    overdue_assignments: (await dueAssignments(db, now, LIST_PAGE_LIMIT)).length,
    due_attestations: (
      await dueAttestations(db, { now, limit: LIST_PAGE_LIMIT })
    ).length,
    seals_yesterday: await countSealsSealedOn(db, yesterdayOf(now)),
    earliest_receipt_day: await earliestReadReceiptDay(db),
    alert_endpoints: await countAlertEndpoints(db),
    alert_cursor: await alertCursor(db),
    alert_due: await countDueDeliveries(db, now),
    alert_failed: await countFailedDeliveries(db),
  };
}

/**
 * Gather everything the status rules read, once, from the store.
 *
 * The one place either door touches the database, and it makes fourteen
 * statements. That number is pinned by a test (test/status-end-to-end.test.ts),
 * because it is the whole point of this function: the QA of 2026-09-12 found it
 * making twenty-nine, one after another, on a page built to be hammered. Eleven
 * of those were numbers the sweep can count once a run, and four were the same
 * newest-of-a-type seek asked four times.
 *
 * What is left is what has to be live. The sweep's own board rows, because they
 * are how the page tells a stopped timer from a refusing step; the newest seal,
 * the log's head and the events that seal does not cover, because the sealing
 * light asks what is waiting now and all three are one sentence; and the
 * handful of newest-row lookups the "exercised, not probed" rows are made of.
 *
 * Every question is still a count, a newest-row lookup, or one page of a
 * deadline queue with LIST_PAGE_LIMIT on it: the two queues are counted by the
 * length of that page, which means a log with more than a page of overdue
 * assignments reports a page of them — the stage only asks whether there are
 * any, and a page is more than enough to say yes.
 *
 * `now` is a string rather than a Date because everything downstream of it is,
 * and a second conversion is a second chance to disagree about the day.
 */
export async function statusInput(
  db: D1Like,
  env: Env,
  now: string,
): Promise<StatusInput> {
  const yesterday = yesterdayOf(now);
  const steps = await sweepSteps(db);
  const seal = await latestSeal(db);
  // Every number this page used to count by scanning a table, in one row the
  // sweep wrote (M25): the seals and their countersignatures, the registered
  // operators, the entries, and the attestations. Read once here, so the four
  // scans the QA of 2026-09-12 found are one indexed lookup by primary key.
  const counters = await logCounters(db);
  // And the numbers that used to be eleven more statements of their own: the
  // drafts, the two overdue queues, yesterday's seals, the first receipt day,
  // the meter and the four alert counts, all of them taken by
  // the counters step at the end of the last run and carried on its board row,
  // which was already read above. Counted here only on a deployment whose
  // counters step has never run.
  const swept = sweptNumbers(steps) ?? (await countedNow(db, now, seal));

  // The four newest-of-a-type reads, grouped into one statement: each is a
  // seek on the (type, seq) index, and four seeks are four round trips.
  const newest = await latestEventsOfTypes(db, [
    "pool_snapshot",
    "read_count",
    "entry_submitted",
    "operator_registered",
  ]);
  const snapshotEvent = newest["pool_snapshot"] ?? null;
  const readCountEvent = newest["read_count"] ?? null;
  const submittedEvent = newest["entry_submitted"] ?? null;
  const registeredEvent = newest["operator_registered"] ?? null;

  const reconciliation = await reconciliationRows(db, 1);
  const anchor = await getAnchor(db, yesterday);
  const mirror = await latestMirror(db);

  // The position the standing step recomputed at, off its own stored detail:
  // Section 9's standing is derived from sealed events, and the sweep is what
  // derived it, so the sweep's record of where it got to is the answer.
  const standingStep = steps.find((step) => step.step === "standing") ?? null;
  const standingPosition =
    standingStep === null ? null : detailNumber(standingStep.detail, "position");

  const readCount =
    readCountEvent === null
      ? null
      : (readCountEvent.payload as EventPayloads["read_count"]);
  const submittedCore =
    submittedEvent === null
      ? null
      : (submittedEvent.payload as EventPayloads["entry_submitted"]).core;
  const registered =
    registeredEvent === null
      ? null
      : (registeredEvent.payload as EventPayloads["operator_registered"]);
  const priced = reconciliation[0] ?? null;

  return {
    environment: env.ENVIRONMENT,
    // The track this environment actually runs, asked of the same function the
    // sweep asks, so the page cannot claim a registry the sweep is not on.
    witness_kind: witnessAdapterFor(env).kind,
    steps,
    // Live, and beside the unsealed count on purpose. The sealing rule reads
    // the two together — "is there an event the newest seal does not cover, and
    // how long has it waited" — so a head taken at the last sweep against a
    // count taken now is two instants in one sentence, and the pair can say "no
    // event" over a non-zero count for a whole sweep interval. One statement is
    // what an honest light costs; the sweep still counts the head at the end of
    // its run, which is what the counters step's row is checked against.
    head_seq: await headSeq(db),
    seal:
      seal === null
        ? null
        : {
            seq: seal.seq,
            last_seq: seal.last_seq,
            sealed_at: seal.sealed_at,
            witnesses: seal.witnesses.length,
          },
    seals: {
      total: counters.seals,
      witnessed: counters.seals_witnessed,
    },
    // The one count left live, and deliberately: the sealing light asks whether
    // anything is waiting unsealed *now*, and an event appended a minute after
    // the sweep is exactly the one it is there to see. It is a single aggregate
    // over a primary-key range, so it costs the seek and not the count.
    unsealed: await unsealedEvents(db, seal === null ? null : seal.last_seq),
    pool: {
      snapshot:
        snapshotEvent === null
          ? null
          : {
              seq: snapshotEvent.seq,
              at: snapshotEvent.at,
              operators: [
                ...(snapshotEvent.payload as EventPayloads["pool_snapshot"])
                  .operators,
              ],
            },
      trusted: await trustedOperatorIds(db, LIST_PAGE_LIMIT),
      registered: counters.operators_registered,
    },
    assignments: {
      overdue: swept.overdue_assignments,
      drafts: swept.drafts,
    },
    entries: counters.entries_total,
    read_counts: {
      newest:
        readCountEvent === null || readCount === null
          ? null
          : {
              seq: readCountEvent.seq,
              date: readCount.date,
              total: readCount.total,
              at: readCountEvent.at,
            },
      earliest_receipt_day: swept.earliest_receipt_day,
    },
    anchor:
      anchor === null
        ? null
        : {
            date: anchor.date,
            external: anchor.external === null ? null : anchor.external.kind,
            upgraded: anchor.external !== null && anchor.external.upgraded !== null,
          },
    // Not yesterday's, and not a page of anchors read to find it: one row, the
    // newest day whose proof reached a block. The stage names it in every state
    // it can be in, so it is gathered whether or not yesterday was anchored.
    upgraded_anchor: await newestUpgradedAnchor(db),
    seals_yesterday: swept.seals_yesterday,
    reconciliation:
      priced === null || priced.date === null
        ? null
        : {
            date: priced.date,
            ok: priced.ref["ok"] === true,
            at: priced.at,
          },
    standing_position: standingPosition,
    attestations: {
      due: swept.due_attestations,
      total: counters.attestations,
    },
    mirror: {
      // The track this environment actually runs, asked of the same function the
      // sweep asks, so the page cannot claim a repository the sweep is not
      // pushing to.
      kind: mirrorKindFor(env),
      newest:
        mirror === null
          ? null
          : {
              date: mirror.date,
              exported_at: mirror.exported_at,
              commit: mirror.commit,
              head: mirror.head,
              url: mirror.url,
            },
    },
    // Change alerts (M24), through the four counts the alert step left behind.
    alerts: {
      endpoints: swept.alert_endpoints,
      cursor: swept.alert_cursor,
      due: swept.alert_due,
      failed: swept.alert_failed,
    },
    exercised: {
      submission:
        submittedEvent === null || submittedCore === null
          ? null
          : {
              at: submittedEvent.at,
              id: (submittedCore as unknown as Core)["id"] as string,
            },
      registration:
        registeredEvent === null || registered === null
          ? null
          : { at: registeredEvent.at, operator: registered.operator },
      read_receipt: await latestReceipt(db, "read"),
      sync_receipt: await latestReceipt(db, "sync"),
    },
  };
}

/**
 * GET /status: the lights, and the two numbers they were decided by.
 *
 * The thresholds go out with the answer because a state nobody can recompute is
 * a state nobody can check: a reader holding this document and src/status.ts's
 * rules gets the same readings we did.
 *
 * `as_of` is the last sweep run and never the request. The page is a reading of
 * a record, so it is dated by the record — an `as_of` of "now" would say the
 * lights were checked this instant, which is exactly the claim this endpoint
 * refuses to make.
 */
async function status(
  db: D1Like,
  env: Env,
  now: Date,
): Promise<Response> {
  const at = now.toISOString();
  const input = await statusInput(db, env, at);
  const stages = stageStates(input, at);
  return json(
    {
      as_of:
        input.steps.find((step) => step.step === "sweep")?.last_run_at ?? null,
      environment: input.environment,
      counters: statusCounters(stages, input),
      stages,
      exercised: exercisedStages(input),
      thresholds: {
        STATUS_ATTENTION_AFTER_INTERVALS,
        STATUS_FAILING_AFTER_MINUTES,
      },
    },
    200,
  );
}

/**
 * Route one request to the status endpoint, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched. A browser asking for
 * `/status` never reaches here: src/worker/pages.ts answers HTML ahead of this
 * and hands everything else on.
 */
export async function handleStatus(
  request: Request,
  env: Env,
  deps: StatusDeps,
): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  if (pathname !== "/status") return null;
  if (!isRead(request)) return methodNotAllowed(READ_METHODS);

  try {
    return await status(guardDatabase(env.DB), env, deps.now);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`status: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

/**
 * Status, read from the outside.
 *
 * Whitepaper Section 11, Deployment and status: nomankind publishes what it is
 * running and whether it is working. `GET /status` is the second half of that as
 * JSON — thirteen stages, the five doors nobody probes, four counters, and the two
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
import { PRODUCTION } from "../adapters/payout.js";
import { witnessAdapterFor } from "../adapters/witness.js";
import { utcDay } from "../anchor.js";
import type { Core } from "../core.js";
import type { EventPayloads } from "../events.js";
import { LIST_PAGE_LIMIT, STATUS_ATTENTION_AFTER_INTERVALS, STATUS_FAILING_AFTER_MINUTES } from "../policy.js";
import {
  exercisedStages,
  stageStates,
  statusCounters,
  type StatusInput,
} from "../status.js";
import type { D1Like } from "../storage/d1.js";
import {
  countAttestations,
  countEntries,
  countOperators,
  countSeals,
  countSealsSealedOn,
  countWitnessedSeals,
  dueAssignments,
  dueAttestations,
  earliestReadReceiptDay,
  getAnchor,
  headSeq,
  latestEventOfType,
  latestMirror,
  latestReceipt,
  latestSeal,
  payoutRows,
  reconciliationRows,
  sweepSteps,
  trustedOperatorIds,
  unsealedEvents,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** What this route is given besides its bindings: the instant. */
export interface StatusDeps {
  readonly now: Date;
}

const MILLISECONDS_PER_DAY = 86_400_000;

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
 * Gather everything the status rules read, once, from the store.
 *
 * The one place either door touches the database. Every question is a count, a
 * newest-row lookup, or one page of a deadline queue with LIST_PAGE_LIMIT on it:
 * the two queues are counted by the length of that page, which means a log with
 * more than a page of overdue assignments reports a page of them — the stage
 * only asks whether there are any, and a page is more than enough to say yes.
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

  const snapshotEvent = await latestEventOfType(db, "pool_snapshot");
  const readCountEvent = await latestEventOfType(db, "read_count");
  const submittedEvent = await latestEventOfType(db, "entry_submitted");
  const registeredEvent = await latestEventOfType(db, "operator_registered");
  const reconciliation = await reconciliationRows(db, 1);
  const payouts = await payoutRows(db, 1);
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
  const paid = payouts[0] ?? null;

  return {
    environment: env.ENVIRONMENT,
    // The track this environment actually runs, asked of the same function the
    // sweep asks, so the page cannot claim a registry the sweep is not on.
    witness_kind: witnessAdapterFor(env).kind,
    // The payout adapter has no kind of its own to ask for, so this is the same
    // branch `payoutAdapterFor` makes, in the same words the two adapters are
    // named by (decision D-013 as amended, D-053).
    payout_kind: env.ENVIRONMENT === PRODUCTION ? "unavailable" : "mock",
    steps,
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
      total: await countSeals(db),
      witnessed: await countWitnessedSeals(db),
    },
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
      registered: await countOperators(db),
    },
    assignments: {
      overdue: (await dueAssignments(db, now, LIST_PAGE_LIMIT)).length,
      drafts: await countEntries(db, { status: "draft" }),
    },
    entries: await countEntries(db, {}),
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
      earliest_receipt_day: await earliestReadReceiptDay(db),
    },
    anchor:
      anchor === null
        ? null
        : {
            date: anchor.date,
            external: anchor.external === null ? null : anchor.external.kind,
            upgraded: anchor.external !== null && anchor.external.upgraded !== null,
          },
    seals_yesterday: await countSealsSealedOn(db, yesterday),
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
      due: (await dueAttestations(db, { now, limit: LIST_PAGE_LIMIT })).length,
      total: await countAttestations(db),
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
      payout:
        paid === null || paid.operator === null
          ? null
          : { at: paid.at, operator: paid.operator, amount: paid.amount },
    },
  };
}

/**
 * GET /status: the lights, and the two numbers they were decided by.
 *
 * The thresholds go out with the answer because a state nobody can recompute is
 * a state nobody can check: a reader holding this document and src/status.ts's
 * rules gets the same thirteen readings we did.
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
  if (request.method !== "GET") return methodNotAllowed("GET");

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

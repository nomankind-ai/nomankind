/**
 * Standing and the ledger, read from the outside.
 *
 * Whitepaper Section 9, "Standing": "Standing is not a score nomankind assigns.
 * It is derived from the sealed public events by a published formula, so anyone
 * can recompute anyone's standing from the log and get the same number." These
 * four routes are that sentence served over HTTP. Two of them recompute the
 * formula here and now, over the sealed log, and hand back the answer beside the
 * names of the terms it applied; the cached column is served next to it, marked
 * as a cache, so a reader who does not believe either can run src/standing.ts
 * over the events themselves and check both.
 *
 * The other two are Money's: "any operator can reconcile their payout against
 * the log". An operator's ledger is its own rows and what they add up to, and
 * the ledger page is the daily reconciliations, the payouts, and the four policy
 * numbers a reader needs to check any of it — the price of a read, the payout
 * floor, the cycle, and the holdback.
 *
 * Reads only, and nothing derived is stored: every number here is recomputed
 * from what the log has sealed, so this Worker cannot serve a standing the log
 * does not support. Before the first seal there is nothing to recompute from and
 * the position is null rather than zero, which is a different thing to tell a
 * reader.
 *
 * JSON only. These four never negotiate HTML: an operator page is
 * src/worker/pages.ts's business, and an agent parsing these must keep parsing
 * them whatever a browser asks for.
 *
 * No policy number lives here: the four the ledger page publishes are read from
 * src/policy.ts, the page size is LIST_PAGE_LIMIT, and the bare integers are
 * HTTP status codes.
 */

import { ledgerBalance } from "../ledger.js";
import {
  HOLDBACK_DAYS,
  LIST_PAGE_LIMIT,
  PAYOUT_CYCLE,
  PAYOUT_MINIMUM_MICROS,
  READ_PRICE_MICROS_PER_READ,
} from "../policy.js";
import { STANDING_FORMULA, standingAt, zeroStanding } from "../standing.js";
import type { D1Like } from "../storage/d1.js";
import {
  getOperator,
  latestSeal,
  ledgerRowsForOperator,
  operatorStanding as storedStanding,
  payoutRows,
  reconciliationRows,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { sealedLog } from "./sweep.js";

/** What these routes are given besides their bindings: the instant. */
export interface StandingDeps {
  readonly now: Date;
}

/** The position the sealed log ends at, or null when nothing is sealed yet. */
async function sealedPosition(db: D1Like): Promise<number | null> {
  const seal = await latestSeal(db);
  return seal === null ? null : seal.last_seq;
}

/**
 * GET /standing: every operator's standing, recomputed now.
 *
 * The formula's own term names go out beside the numbers, because Section 9
 * promises a published formula and a formula whose terms are not named is not
 * published. Highest first, then by id, so the order is a fact about the
 * numbers rather than about how the log happened to be written.
 */
async function standing(db: D1Like): Promise<Response> {
  const position = await sealedPosition(db);
  if (position === null) {
    return json({ position: null, formula: STANDING_FORMULA, operators: [] }, 200);
  }

  const standings = standingAt(await sealedLog(db, position), position);
  const operators = [...standings.values()].sort(
    (left, right) =>
      right.standing - left.standing || left.operator.localeCompare(right.operator),
  );
  return json({ position, formula: STANDING_FORMULA, operators }, 200);
}

/**
 * GET /operators/{id}/standing: one operator's standing, recomputed, with the
 * cached column beside it.
 *
 * `stored` is the cache the sweep wrote and the position it wrote it at, or null
 * when standing has never been computed for this operator — null is "not
 * computed yet" and never "zero". A reader comparing the two is doing exactly
 * what src/cli/standing.ts does, and a disagreement is the log's word against a
 * column's, which the log wins.
 *
 * A 404 for an operator nobody registered: an unregistered name has no standing
 * rather than a standing of zero.
 */
async function operatorStanding(db: D1Like, operator: string): Promise<Response> {
  if ((await getOperator(db, operator)) === null) return refuse(404, "not_found");

  const position = await sealedPosition(db);
  const recomputed =
    position === null
      ? zeroStanding(operator, 0)
      : (standingAt(await sealedLog(db, position), position).get(operator) ??
        zeroStanding(operator, position));

  // This operator's own row, not the top of the leaderboard: an operator ranked
  // past a page of standings still has the standing the sweep wrote for it.
  const cached = await storedStanding(db, operator);
  return json(
    {
      operator,
      position: position === null ? null : recomputed.position,
      earned: recomputed.earned,
      burned: recomputed.burned,
      locked: recomputed.locked,
      standing: recomputed.standing,
      available: recomputed.available,
      counts: recomputed.counts,
      formula: STANDING_FORMULA,
      stored: cached,
    },
    200,
  );
}

/**
 * GET /operators/{id}/ledger: what an operator's rows add up to, and the newest
 * page of them.
 *
 * Section 9: "any operator can reconcile their payout against the log". The
 * balance is computed over the page that is served, so what is added up and what
 * is shown are the same rows; an operator with more rows than a page pages back
 * through them exactly as every other listing here is paged.
 */
async function operatorLedger(
  db: D1Like,
  operator: string,
  now: Date,
): Promise<Response> {
  if ((await getOperator(db, operator)) === null) return refuse(404, "not_found");
  const rows = await ledgerRowsForOperator(db, operator, LIST_PAGE_LIMIT);
  return json(
    { operator, balance: ledgerBalance(rows, now.toISOString()), rows },
    200,
  );
}

/**
 * GET /ledger: the daily reconciliations, the payouts, and the numbers both are
 * computed with.
 *
 * The policy block is what makes the rest checkable without this Worker: the
 * price of a read, the floor a payout must clear, the cycle it clears it in, and
 * the holdback every accrual waits out.
 */
async function ledger(db: D1Like): Promise<Response> {
  return json(
    {
      reconciliations: await reconciliationRows(db, LIST_PAGE_LIMIT),
      payouts: await payoutRows(db, LIST_PAGE_LIMIT),
      policy: {
        READ_PRICE_MICROS_PER_READ,
        PAYOUT_MINIMUM_MICROS,
        PAYOUT_CYCLE,
        HOLDBACK_DAYS,
      },
    },
    200,
  );
}

/**
 * The operator id in `/operators/{id}/{leaf}`, or null when the path is not that
 * shape. A path with a further slash is not one of these and falls through
 * rather than being trimmed into one.
 */
function operatorPath(path: string, leaf: string): string | null {
  const PREFIX = "/operators/";
  const SUFFIX = `/${leaf}`;
  if (!path.startsWith(PREFIX) || !path.endsWith(SUFFIX)) return null;
  const raw = path.slice(PREFIX.length, path.length - SUFFIX.length);
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

async function route(
  request: Request,
  db: D1Like,
  deps: StandingDeps,
): Promise<Response | null> {
  const { pathname } = new URL(request.url);

  if (pathname === "/standing") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return standing(db);
  }

  if (pathname === "/ledger") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return ledger(db);
  }

  const forStanding = operatorPath(pathname, "standing");
  if (forStanding !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return operatorStanding(db, forStanding);
  }

  const forLedger = operatorPath(pathname, "ledger");
  if (forLedger !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return operatorLedger(db, forLedger, deps.now);
  }

  return null;
}

/**
 * Route one request to the standing and ledger pages, or answer null when the
 * path is not ours, which leaves the Worker's own not_found untouched. Storage
 * failures become the same JSON 503 every other route gives.
 */
export async function handleStanding(
  request: Request,
  env: Env,
  deps: StandingDeps,
): Promise<Response | null> {
  try {
    return await route(request, guardDatabase(env.DB), deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`standing: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

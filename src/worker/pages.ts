/**
 * The browsing UI's door (M19).
 *
 * Whitepaper Section 3, The log: a reader has to be able to check an entry, so
 * the log needs a face a person can read as well as the JSON doors a machine
 * reads. This route is that face, and it is mounted first — before the registry,
 * the submit and the read doors — because it answers the same paths those doors
 * answer and has to be able to hand a browser HTML where an agent gets JSON. It
 * returns null for everything it does not own, so mounting it first costs the
 * other doors nothing.
 *
 * Content negotiation is one function, `wantsHtml`: an Accept header naming
 * text/html. `/entries/{id}`, `/operators`, `/operators/{id}` and `/policy` are
 * shared with the JSON doors and answer HTML only to a browser; `/entries`,
 * `/api`, `/genesis` and `/landing` are pages and nothing else. Every HTML
 * response carries `Vary: Accept` (src/ui/html.ts), because a shared cache that
 * confused the two would hand an agent a web page.
 *
 * The pages themselves are pure (src/ui/pages/): this file reads, they render.
 * So every query here is shaped by what a page needs and nothing is computed on
 * the way — the counters are counts, the listing is one keyset page, and every
 * derived field an entry shows was derived when the entry was written.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and the
 * page sizes are LIST_PAGE_LIMIT and HOME_LATEST_ENTRIES from src/policy.ts.
 * No wall clock either — `deps.now` is the instant the router read once.
 */

import type { Event } from "../events.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  TXT_RECORD_PREFIX,
} from "../registry.js";
import { HOME_LATEST_ENTRIES, LIST_PAGE_LIMIT, POLICY } from "../policy.js";
import type { D1Like } from "../storage/d1.js";
import {
  agentCountsByOperator,
  agentsForOperator,
  countEntries,
  countSeals,
  countTrustedOperators,
  eventsForEntry,
  getEntry,
  getOperator,
  latestSeal,
  listEntriesPage,
  listOperators,
  sealCovering,
  supersedersOf,
  validationCountsByOperator,
  validationsByOperator,
  type OperatorRecord,
  type StoredEntry,
} from "../storage/repository.js";
import { htmlResponse, cssResponse } from "../ui/html.js";
import { renderApi } from "../ui/pages/api.js";
import { renderEntries } from "../ui/pages/entries.js";
import { renderEntry } from "../ui/pages/entry.js";
import {
  renderBadQuery,
  renderNotFound,
  renderUnavailable,
} from "../ui/pages/errors.js";
import { renderGenesis } from "../ui/pages/genesis.js";
import { renderHome } from "../ui/pages/home.js";
import { LANDING_CSS, renderLanding } from "../ui/pages/landing.js";
import { renderOperator } from "../ui/pages/operator.js";
import { renderOperators } from "../ui/pages/operators.js";
import { renderPolicy } from "../ui/pages/policy.js";
import { parseEntriesQuery } from "../ui/query.js";
import { APP_CSS } from "../ui/styles.js";
import type {
  ApproverRow,
  EntriesFilter,
  EntryRow,
  GenesisRow,
  OperatorRow,
  PageContext,
} from "../ui/types.js";
import type { Env } from "./env.js";
import { StorageUnreachable, guardDatabase, json, refuse } from "./registry.js";

/**
 * The ids nomankind mints, exactly as src/worker/read.ts narrows the schema's
 * pattern for its `bad_id` check. An id that fails it never reached the store, so
 * the browser gets the 404 page rather than a lookup.
 */
const ENTRY_ID_PATTERN = /^nmk_[0-9a-f]{32}$/;

/** Does this request want a page, or a record? */
export function wantsHtml(request: Request): boolean {
  const accept = request.headers.get("accept");
  return accept !== null && accept.toLowerCase().includes("text/html");
}

/** A HEAD answers exactly like a GET, without the body. */
export function forMethod(request: Request, response: Response): Response {
  if (request.method !== "HEAD") return response;
  return new Response(null, {
    status: response.status,
    headers: response.headers,
  });
}

/** The one path segment after a prefix, or null when the path is not that shape. */
function segmentAfter(path: string, prefix: string): string | null {
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return null;
  }
}

/** A required string off a stored record, read by the schema's own field name. */
function field(source: Record<string, unknown>, name: string): string {
  const value = source[name];
  return typeof value === "string" ? value : "";
}

/**
 * One stored entry as a table row.
 *
 * `tier` is the sidecar's `effective_tier` and never the core's `evidence_tier`
 * (Section 4): the tier a reader is shown is the one the entry actually verified
 * at. `sealed` is whether the entry carries a seal object at all.
 */
function toRow(stored: StoredEntry): EntryRow {
  const entry = stored.entry as unknown as Record<string, unknown>;
  const expires = entry["expires_at"];
  return {
    id: field(entry, "id"),
    position: stored.submittedSeq,
    sealed: entry["seal"] !== null && entry["seal"] !== undefined,
    status: field(entry, "status"),
    subject: field(entry, "subject"),
    category: field(entry, "category"),
    claim: field(entry, "claim"),
    tier: stored.sidecar.effective_tier,
    last_confirmed: field(entry, "last_confirmed"),
    expires_at: typeof expires === "string" ? expires : null,
    stale: entry["stale"] === true,
  };
}

/** An operator's stored row as the directory shows it. */
function toOperatorRow(
  record: OperatorRecord,
  agents: number,
  validations: number,
): OperatorRow {
  const trustedSeq = record.details["trusted_seq"];
  return {
    id: record.id,
    maintainer: record.maintainer,
    provider: record.provider,
    trusted: record.details["trusted"] === true,
    trustedSeq: typeof trustedSeq === "number" ? trustedSeq : null,
    registeredSeq: record.registeredSeq,
    agents,
    validations,
  };
}

/** Whether the operator behind a decision is trusted, or null when unknown. */
class TrustedOperators {
  private readonly known = new Map<string, boolean | null>();

  constructor(private readonly db: D1Like) {}

  async of(operator: string): Promise<boolean | null> {
    const memoized = this.known.get(operator);
    if (memoized !== undefined) return memoized;
    const record = await getOperator(this.db, operator);
    const trusted = record === null ? null : record.details["trusted"] === true;
    this.known.set(operator, trusted);
    return trusted;
  }
}

// ---------------------------------------------------------------------------
// The pages
// ---------------------------------------------------------------------------

async function home(db: D1Like, ctx: PageContext): Promise<Response> {
  const verified = await countEntries(db, { status: "verified" });
  const stale = await countEntries(db, { stale: true });
  const trusted = await countTrustedOperators(db);
  const seal = await latestSeal(db);
  const seals = await countSeals(db);
  const latest = await listEntriesPage(db, { limit: HOME_LATEST_ENTRIES });

  return htmlResponse(
    renderHome(ctx, {
      counters: {
        verified,
        stale,
        trusted,
        sealedHead: seal === null ? null : seal.last_seq,
        sealedAt: seal === null ? null : seal.sealed_at,
        witnesses: seal === null ? null : seal.witnesses.length,
        seals,
      },
      latest: latest.map(toRow),
    }),
  );
}

async function entries(
  db: D1Like,
  ctx: PageContext,
  url: URL,
): Promise<Response> {
  const parsed = parseEntriesQuery(url.searchParams);
  if (!parsed.ok) {
    return htmlResponse(renderBadQuery(ctx, parsed.reason), 400);
  }
  const filter: EntriesFilter = parsed.filter;

  const page = await listEntriesPage(db, {
    ...(filter.category === null ? {} : { category: filter.category }),
    ...(filter.status === null ? {} : { status: filter.status }),
    ...(filter.tier === null ? {} : { tier: filter.tier }),
    ...(filter.fresh === null ? {} : { stale: filter.fresh === "stale" }),
    limit: LIST_PAGE_LIMIT,
    ...(parsed.before === null ? {} : { beforeSubmittedSeq: parsed.before }),
  });
  // The total is by status only, which is what the page's title attribute says:
  // the tier filter is a JSON extraction and the freshness filter is a derived
  // boolean, and a total that counted either would be a second query whose cost
  // grows with the log for a number nobody asked for.
  const total = await countEntries(
    db,
    filter.status === null ? {} : { status: filter.status },
  );

  const rows = page.map(toRow);
  const last = rows[rows.length - 1];
  const nextBefore =
    rows.length === LIST_PAGE_LIMIT && last !== undefined
      ? last.position
      : null;

  return htmlResponse(
    renderEntries(ctx, { filter, rows, total, nextBefore }),
  );
}

/**
 * One entry.
 *
 * The approvers on the record carry no position, because the schema has no field
 * for one; the log does. So each decision is joined to its `validation` event by
 * the two things both sides name — the agent, and the instant it signed — which
 * is what lets the page show a reader where in the log a decision sits.
 */
async function entry(
  db: D1Like,
  ctx: PageContext,
  id: string,
): Promise<Response> {
  const stored = await getEntry(db, id);
  if (stored === null) return htmlResponse(renderNotFound(ctx), 404);

  const record = stored.entry as unknown as Record<string, unknown>;
  const events = await eventsForEntry(db, id);
  const seal = await sealCovering(db, stored.submittedSeq);
  const superseders = await supersedersOf(db, id, LIST_PAGE_LIMIT);
  const trust = new TrustedOperators(db);

  const validations = events.filter(
    (event) => event.type === "validation",
  ) as Event<"validation">[];
  const reconfirmationEvents = events.filter(
    (event) => event.type === "reconfirmation",
  ) as Event<"reconfirmation">[];

  const seqOf = (
    candidates: readonly { seq: number; payload: { record: { agent: string; signed_at: string } } }[],
    agent: string,
    signedAt: string,
  ): number | null => {
    const found = candidates.find(
      (each) =>
        each.payload.record.agent === agent &&
        each.payload.record.signed_at === signedAt,
    );
    return found === undefined ? null : found.seq;
  };

  const rawApprovers = Array.isArray(record["approvers"])
    ? (record["approvers"] as Record<string, unknown>[])
    : [];
  const approvers: ApproverRow[] = [];
  for (const each of rawApprovers) {
    const operator = field(each, "operator");
    const reason = each["reason"];
    const hash = each["snapshot_hash"];
    const accepted = each["test_accepted"];
    approvers.push({
      agent: field(each, "agent"),
      operator,
      operatorTrusted: await trust.of(operator),
      decision: field(each, "decision"),
      reason: typeof reason === "string" ? reason : null,
      snapshot_hash: typeof hash === "string" ? hash : null,
      assigned_random: each["assigned_random"] === true,
      test_accepted: typeof accepted === "boolean" ? accepted : null,
      reproduction: each["reproduction"] ?? null,
      observation: each["observation"] ?? null,
      signed_at: field(each, "signed_at"),
      seq: seqOf(validations, field(each, "agent"), field(each, "signed_at")),
    });
  }

  const rawReconfirmations = Array.isArray(record["reconfirmations"])
    ? (record["reconfirmations"] as Record<string, unknown>[])
    : [];
  const reconfirmations: {
    record: Record<string, unknown>;
    seq: number | null;
    operatorTrusted: boolean | null;
  }[] = [];
  for (const each of rawReconfirmations) {
    reconfirmations.push({
      record: each,
      seq: seqOf(
        reconfirmationEvents,
        field(each, "agent"),
        field(each, "signed_at"),
      ),
      operatorTrusted: await trust.of(field(each, "operator")),
    });
  }

  const window = record["staleness_window_days"];
  return htmlResponse(
    renderEntry(ctx, {
      entry: record,
      sidecar: stored.sidecar,
      position: stored.submittedSeq,
      events,
      seal,
      approvers,
      reconfirmations,
      superseders,
      stalenessWindowDays: typeof window === "number" ? window : null,
    }),
  );
}

/**
 * Every operator's row, with the agent and validation counts beside it.
 *
 * Both counts are one grouped read over the whole directory rather than a read
 * per operator: a page that costs one query at three operators and a hundred at
 * a hundred is a page that stops answering exactly when the log starts working.
 * An operator absent from either grouping has bound no agent or signed no
 * decision, which is a zero and not a missing number.
 */
async function operatorRows(db: D1Like): Promise<OperatorRow[]> {
  const records = await listOperators(db, { limit: LIST_PAGE_LIMIT });
  const counts = await validationCountsByOperator(db, LIST_PAGE_LIMIT);
  const byOperator = new Map(counts.map((each) => [each.operator, each]));
  const agents = await agentCountsByOperator(db, LIST_PAGE_LIMIT);
  const agentsByOperator = new Map(
    agents.map((each) => [each.operator, each.count]),
  );

  return records.map((record) =>
    toOperatorRow(
      record,
      agentsByOperator.get(record.id) ?? 0,
      byOperator.get(record.id)?.count ?? 0,
    ),
  );
}

async function operators(db: D1Like, ctx: PageContext): Promise<Response> {
  return htmlResponse(renderOperators(ctx, { rows: await operatorRows(db) }));
}

async function operator(
  db: D1Like,
  ctx: PageContext,
  id: string,
): Promise<Response> {
  const record = await getOperator(db, id);
  if (record === null) return htmlResponse(renderNotFound(ctx), 404);

  const agents = await agentsForOperator(db, id, LIST_PAGE_LIMIT);
  const validations = await validationsByOperator(db, id, LIST_PAGE_LIMIT);
  const attestation = record.details["attestation"];
  const namedBy = record.details["named_by"];
  const payoutStatus = record.details["payout_status"];

  return htmlResponse(
    renderOperator(ctx, {
      row: toOperatorRow(record, agents.length, validations.length),
      agents: agents.map((each) => each.agentId),
      attestation:
        attestation !== null && typeof attestation === "object"
          ? (attestation as Record<string, unknown>)
          : null,
      namedBy: typeof namedBy === "string" ? namedBy : null,
      payoutStatus: typeof payoutStatus === "string" ? payoutStatus : null,
      validations,
    }),
  );
}

/**
 * Genesis (Section 11): the founding pool, and the three joining steps read
 * back — the TXT record's prefix, and the attestation text an operator signs.
 */
async function genesis(
  db: D1Like,
  ctx: PageContext,
  env: Env,
): Promise<Response> {
  const records = await listOperators(db, { limit: LIST_PAGE_LIMIT });
  const counts = await validationCountsByOperator(db, LIST_PAGE_LIMIT);
  const byOperator = new Map(counts.map((each) => [each.operator, each]));

  const rows: GenesisRow[] = records.map((record) => {
    const trustedSeq = record.details["trusted_seq"];
    const counted = byOperator.get(record.id);
    return {
      operator: record.id,
      registeredSeq: record.registeredSeq,
      trustedSeq: typeof trustedSeq === "number" ? trustedSeq : null,
      validations: counted?.count ?? 0,
      lastValidationAt: counted?.lastSignedAt ?? null,
    };
  });

  return htmlResponse(
    renderGenesis(ctx, {
      rows,
      attestationText: ATTESTATION_TEXT,
      attestationVersion: ATTESTATION_VERSION,
      txtRecordPrefix: TXT_RECORD_PREFIX,
      maintainerConfigured:
        typeof env.MAINTAINER_AGENT_ID === "string" &&
        env.MAINTAINER_AGENT_ID !== "",
    }),
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  url: URL,
): Promise<Response | null> {
  const path = url.pathname;
  const ctx: PageContext = {
    environment: env.ENVIRONMENT,
    path,
    origin: url.origin,
  };
  const wants = wantsHtml(request);

  // The apex serves the front door and the app serves the instrument panel
  // (decision D-021). Only production sets APEX_HOST, so local and demo answer
  // the home page at `/` and no request there can be mistaken for the apex.
  if (path === "/") {
    const apex = env.APEX_HOST;
    return apex !== undefined && apex !== "" && apex === url.hostname
      ? htmlResponse(renderLanding(ctx))
      : home(db, ctx);
  }

  if (path === "/landing") return htmlResponse(renderLanding(ctx));

  // The listing has no JSON twin, so it answers whatever the Accept header says.
  if (path === "/entries") return entries(db, ctx, url);

  const entryId = segmentAfter(path, "/entries/");
  if (entryId !== null) {
    if (!wants) return null;
    return ENTRY_ID_PATTERN.test(entryId)
      ? entry(db, ctx, entryId)
      : htmlResponse(renderNotFound(ctx), 404);
  }

  if (path === "/operators") return wants ? operators(db, ctx) : null;

  const operatorId = segmentAfter(path, "/operators/");
  if (operatorId !== null) {
    return wants ? operator(db, ctx, operatorId) : null;
  }

  // The public policy endpoint: the page for a browser, the frozen object for
  // everyone else, so a reader and an agent are looking at the same numbers.
  if (path === "/policy") {
    return wants
      ? htmlResponse(renderPolicy(ctx, POLICY))
      : json(POLICY, 200);
  }

  if (path === "/api") return htmlResponse(renderApi(ctx));
  if (path === "/genesis") return genesis(db, ctx, env);

  return null;
}

/**
 * Route one request to a page, or answer null when the path is not ours.
 *
 * Only GET and HEAD: every other method belongs to a write door mounted after
 * this one, and a page route that answered 405 to a POST would have taken the
 * submit door's own answer away from it.
 *
 * The stylesheets are served before anything else and touch no database: they
 * are the same bytes for every reader and say nothing about the log, which is
 * why `cssResponse` lets them be cached while no page is.
 */
export async function handlePages(
  request: Request,
  env: Env,
  deps: { now: Date },
): Promise<Response | null> {
  void deps;
  if (request.method !== "GET" && request.method !== "HEAD") return null;

  const url = new URL(request.url);
  if (url.pathname === "/static/app.css") {
    return forMethod(request, cssResponse(APP_CSS));
  }
  if (url.pathname === "/static/landing.css") {
    return forMethod(request, cssResponse(LANDING_CSS));
  }

  const db = guardDatabase(env.DB);
  try {
    const answer = await route(request, env, db, url);
    return answer === null ? null : forMethod(request, answer);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`pages: storage unreachable: ${error.message}`);
      // The same 503 and the same word either way, because it is the same
      // failure: a browser is handed the page and everything else the record.
      const answer = wantsHtml(request)
        ? htmlResponse(
            renderUnavailable({
              environment: env.ENVIRONMENT,
              path: url.pathname,
              origin: url.origin,
            }),
            503,
          )
        : refuse(503, "storage_unreachable");
      return forMethod(request, answer);
    }
    throw error;
  }
}

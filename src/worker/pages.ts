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
 * A wrong method is refused here only on the paths this route owns outright
 * (PAGE_ONLY_PATHS below): those get 405 with an `Allow` header and the
 * handlers' own envelope, rather than falling through every door to the final
 * not-found, which was two shapes for one mistake. Everything shared with a
 * door returns null and is refused by the door that owns it.
 *
 * Content negotiation is one function, `wantsHtml`: an Accept header naming
 * text/html. `/entries/{id}`, `/operators`, `/operators/{id}`, `/policy` and
 * `/mirror/latest` are
 * shared with the JSON doors and answer HTML only to a browser; `/entries`,
 * `/api`, `/genesis`, `/docs` with the three documents under it, and
 * `/landing` are pages and nothing else. Every HTML
 * response carries `Vary: Accept` (src/ui/html.ts), because a shared cache that
 * confused the two would hand an agent a web page.
 *
 * The pages themselves are pure (src/ui/pages/): this file reads, they render.
 * So every query here is shaped by what a page needs and nothing is computed on
 * the way — the counters are counts, the listing is one keyset page, and every
 * derived field an entry shows was derived when the entry was written.
 *
 * Four files a crawler reads are served here too (decision D-114): /robots.txt,
 * /sitemap.xml and the icon on both /favicon.svg and /favicon.ico. They are
 * pages in every sense that matters to this file — anonymous, the same bytes for
 * every reader, refused on a wrong method with the handlers' own envelope — and
 * three of them are answered before the database is reached for, because only
 * the sitemap is a reading of the log. Once that log outgrows one document the
 * sitemap becomes an index naming `/sitemap-pages.xml` and the fixed
 * `/sitemap-entries-<k>.xml` ranges, which are served here on the same terms.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and the
 * page sizes are LIST_PAGE_LIMIT, HOME_LATEST_ENTRIES, LANDING_BAND_SEALS and
 * SITEMAP_MAX_ENTRIES from src/policy.ts. No wall clock either — `deps.now` is
 * the instant the router read once.
 */

import { mirrorKindFor } from "../adapters/mirror.js";
import { domainOf, extractCore } from "../core.js";
import { confidenceInputs } from "../confidence.js";
import { independenceReport, witnessAgentId } from "../independence.js";
import type { Event } from "../events.js";
import { ledgerBalance } from "../ledger.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  TXT_RECORD_PREFIX,
} from "../registry.js";
import {
  disclosureWindowDays,
  DOMAIN_SLUGS,
  HOME_LATEST_ENTRIES,
  LANDING_BAND_SEALS,
  LIST_PAGE_LIMIT,
  MIRROR,
  POLICY,
  SITEMAP_MAX_ENTRIES,
  WITNESS_PIN,
} from "../policy.js";
import type { Seal } from "../seal.js";
import { exercisedStages, stageStates, statusCounters } from "../status.js";
import type { D1Like } from "../storage/d1.js";
import {
  agentCountsByOperator,
  agentsForOperator,
  attestationsForOperator,
  capturesForEntry,
  countEntries,
  countOperators,
  countSeals,
  countTrustedOperators,
  disputeOf,
  domainsForOperators,
  entryIdsInSubmittedRange,
  entryIdsNewestFirst,
  entryLedgerRows,
  eventsForEntry,
  getEntry,
  getOperator,
  latestAnchor,
  latestEventOfType,
  latestMirror,
  latestSeal,
  ledgerRowsForEntry,
  ledgerRowsForOperator,
  listAttestations,
  listEntriesPage,
  listOperators,
  cosignPairsForOperator,
  cosignerCountsForOperators,
  operatorDomains,
  operatorForAgent,
  operatorStanding,
  overturnedCountsByOperator,
  reconciliationRows,
  sealCovering,
  sealsAfter,
  sealsBetween,
  standingByOperator,
  standingForOperators,
  supersedersOf,
  validationCountersForOperators,
  validationsByOperator,
  type EntryLocation,
  type OperatorRecord,
  type OperatorStanding,
  type StoredEntry,
} from "../storage/repository.js";
import {
  APP_CSS_HREF,
  STRICT_TRANSPORT_SECURITY,
  htmlResponse,
  cssResponse,
} from "../ui/html.js";
import {
  FAVICON_CONTENT_TYPE,
  FAVICON_SVG,
} from "../ui/favicon.js";
import { renderApi } from "../ui/pages/api.js";
import {
  FORK_DOCUMENT,
  SUMMARY_DOCUMENT,
  WHITEPAPER_DOCUMENT,
  renderDocument,
} from "../ui/pages/document.js";
import { renderDocs } from "../ui/pages/docs.js";
import { renderDomains } from "../ui/pages/domains.js";
import { renderDryRun } from "../ui/pages/dry-run.js";
import { renderEntries } from "../ui/pages/entries.js";
import { renderEntry } from "../ui/pages/entry.js";
import {
  renderBadQuery,
  renderNotFound,
  renderUnavailable,
} from "../ui/pages/errors.js";
import { renderGenesis } from "../ui/pages/genesis.js";
import { renderHome } from "../ui/pages/home.js";
import { renderHowItWorks } from "../ui/pages/how-it-works.js";
import { renderIndependence } from "../ui/pages/independence.js";
import { renderMirror } from "../ui/pages/mirror.js";
import {
  LANDING_CSS,
  LANDING_CSS_HREF,
  renderLanding,
} from "../ui/pages/landing.js";
import { renderOperator } from "../ui/pages/operator.js";
import { renderOperators } from "../ui/pages/operators.js";
import { renderPolicy } from "../ui/pages/policy.js";
import { renderStatus } from "../ui/pages/status.js";
import { ENTRY_DOMAINS, parseEntriesQuery } from "../ui/query.js";
import { APP_CSS } from "../ui/styles.js";
import type {
  ApproverRow,
  DomainCounts,
  DomainsData,
  EntriesFilter,
  EntryRow,
  GenesisRow,
  HowItWorksData,
  IndependenceData,
  LandingData,
  MirrorData,
  OperatorRow,
  PageContext,
  StatusData,
} from "../ui/types.js";
import {
  readerAccess,
  unmeteredFreeReader,
  type ReaderAccess,
} from "./access.js";
import { configured, maintainerAgentId } from "./config.js";
import type { Env } from "./env.js";
import {
  READ_METHODS,
  StorageUnreachable,
  guardDatabase,
  isRead,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { logCounters, statusInput } from "./status.js";
import { clocked } from "./world.js";

/**
 * The ids nomankind mints, exactly as src/worker/read.ts narrows the schema's
 * pattern for its `bad_id` check. An id that fails it never reached the store, so
 * the browser gets the 404 page rather than a lookup.
 */
const ENTRY_ID_PATTERN = /^nmk_[0-9a-f]{32}$/;

/**
 * The paths this route owns outright: a page, with no JSON door mounted under
 * it that a wrong method could have been meant for.
 *
 * A wrong method on one of them is refused here, in the handlers' own envelope —
 * `{"error":"method_not_allowed"}` with an `Allow` header — rather than falling
 * through every door to the final not-found. A PUT to a page and a PUT to an
 * endpoint are the same mistake, and a reader who made it was being told two
 * different things in two different shapes.
 *
 * Everything shared is absent on purpose: `/entries` is the submit door's POST,
 * `/entries/{id}` and `/operators` and `/operators/{id}` and `/genesis` and
 * `/status` and `/mirror/latest` are read doors that answer their own 405 with
 * their own Allow, and a page route that answered first would have taken that
 * answer away from them.
 */
const PAGE_ONLY_PATHS: ReadonlySet<string> = new Set([
  "/",
  "/landing",
  "/policy",
  "/api",
  "/docs",
  "/docs/fork",
  "/docs/whitepaper",
  "/docs/summary",
  "/dry-run",
  "/how-it-works",
  "/domains",
  // The independence page (D-121): a page with a JSON twin on the same path and
  // no door of its own under it, so a wrong method here is this route's to
  // refuse, exactly as it is on /policy.
  "/independence",
  "/static/app.css",
  "/static/landing.css",
  // The four files a crawler reads (D-114). No door is mounted under any of
  // them, so a wrong method on one is this route's to refuse, exactly as it is
  // on the stylesheets beside them.
  "/robots.txt",
  "/sitemap.xml",
  "/favicon.svg",
  "/favicon.ico",
  // The redirect to /mirror/latest. The door under it is at the longer path, so
  // there is nothing here a POST could have been meant for.
  "/mirror",
]);

/**
 * The documents the sitemap index names, which are this route's outright too.
 *
 * A set would have had to hold one name per page of a log that grows, so it is
 * the prefix instead: everything under `/sitemap-` is a sitemap, and there is no
 * other door anywhere in the system on a path that starts that way.
 */
function isSitemapDocument(path: string): boolean {
  return path.startsWith("/sitemap-");
}

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
 *
 * `stale` is the clock's answer and never the column's: the row is put through
 * `clocked` (src/worker/world.ts) exactly as the read door puts its own answer,
 * so a listing and a read taken at the same instant cannot disagree about
 * whether a window has closed.
 */
function toRow(stored: StoredEntry, now: Date): EntryRow {
  const entry = clocked(stored.entry, now) as unknown as Record<
    string,
    unknown
  >;
  const expires = entry["expires_at"];
  return {
    id: field(entry, "id"),
    position: stored.submittedSeq,
    sealed: entry["seal"] !== null && entry["seal"] !== undefined,
    status: field(entry, "status"),
    subject: field(entry, "subject"),
    category: field(entry, "category"),
    // The registered domain out of the signed core (D-125). `field` answers the
    // empty string for an entry sealed before the key existed, and the listing
    // prints that as an em dash: a page never fills a domain in.
    domain: field(entry, "domain"),
    claim: field(entry, "claim"),
    tier: stored.sidecar.effective_tier,
    last_confirmed: field(entry, "last_confirmed"),
    expires_at: typeof expires === "string" ? expires : null,
    stale: entry["stale"] === true,
  };
}

/**
 * The seals covering a page of rows: one read over the span the page actually
 * holds, rather than one read per row.
 *
 * Seals are disjoint and contiguous, so every row's covering seal is in the
 * range between the lowest and the highest position on the page, and a listing
 * of fifty entries costs the same one query a listing of one does.
 */
async function sealsCovering(
  db: D1Like,
  rows: readonly StoredEntry[],
): Promise<Seal[]> {
  if (rows.length === 0) return [];
  let first = rows[0]!.submittedSeq;
  let last = first;
  for (const stored of rows) {
    if (stored.submittedSeq < first) first = stored.submittedSeq;
    if (stored.submittedSeq > last) last = stored.submittedSeq;
  }
  return sealsBetween(db, first, last);
}

/** The `sealed_at` of the seal covering one position, or null when none does. */
function sealedAtOf(seals: readonly Seal[], position: number): string | null {
  const covering = seals.find(
    (seal) => seal.first_seq <= position && position <= seal.last_seq,
  );
  return covering === undefined ? null : covering.sealed_at;
}

/**
 * An operator's stored row as the directory shows it.
 *
 * `standing` is the cached number and the position it was computed at, carried
 * verbatim and undefined-to-null: an operator missing from the cache has not had
 * the formula run for it, which is a different fact from a standing of zero and
 * is shown differently.
 */
function toOperatorRow(
  record: OperatorRecord,
  agents: number,
  validations: number,
  overturned: number,
  standing: OperatorStanding | undefined,
  cosigners: number,
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
    overturned,
    standing: standing === undefined ? null : { ...standing },
    cosigners,
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

/**
 * The apex front door (D-021, D-062 direction D).
 *
 * The one page outside the instrument panel, and it reads the log too: the band
 * shows the newest seals and the numerals show the totals, because a front door
 * for a log has to be able to show that the log is moving and a hard-coded
 * number would be a claim rather than a reading. Four reads, all of them counts
 * or one keyset page, and nothing derived on the way — `events` is the size the
 * kernel sealed and `witnessed` is whether a countersignature is attached.
 *
 * The witnesses number is the distinct operators pinned in WITNESS_PIN, read
 * from the policy module: the independent witnesses the maintainer published, not
 * a number written into a page.
 */
async function landing(db: D1Like, ctx: PageContext): Promise<Response> {
  const head = await latestSeal(db);
  // Newest last, in seq order, because the band reads left to right. The chain
  // is contiguous, so "the last twelve" is one keyset read after head - 12
  // rather than a scan; a negative bound is harmless, seqs start at 0.
  const newest =
    head === null
      ? []
      : await sealsAfter(db, head.seq - LANDING_BAND_SEALS, LANDING_BAND_SEALS);
  const sealCount = await countSeals(db);
  const verified = await countEntries(db, { status: "verified" });

  const data: LandingData = {
    seals: newest.map((seal) => ({
      seq: seal.seq,
      hash: seal.hash,
      sealedAt: seal.sealed_at,
      witnessed: seal.witnesses.length >= 1,
      events: seal.size,
    })),
    sealCount,
    verified,
    witnesses: new Set(WITNESS_PIN.map((witness) => witness.operator)).size,
  };

  return htmlResponse(renderLanding(ctx, data));
}

/**
 * The home page, optionally narrowed to one registered domain (decision D-071).
 *
 * `?domain=` is checked against the schema's own domain enum and refused by name
 * rather than ignored, exactly as the entries listing refuses a filter it cannot
 * read: a reader who mistyped a slug and got the whole log's counters back would
 * believe they had narrowed them. The verified, stale and trusted counters and
 * the latest rows are gathered under it; the head and the seal count are not,
 * because a seal covers events and not a domain, and the page says so.
 */
async function home(
  request: Request,
  env: Env,
  db: D1Like,
  ctx: PageContext,
  url: URL,
  now: Date,
): Promise<Response> {
  const asked = url.searchParams.get("domain");
  if (asked !== null && !ENTRY_DOMAINS.includes(asked)) {
    return htmlResponse(renderBadQuery(ctx, "unknown_domain"), 400);
  }
  const narrowed = asked === null ? {} : { domain: asked };

  // The whole log's numbers come from the counters the sweep folds (the QA of
  // 2026-09-12): the home page cost four counts per reader, and a count over a
  // growing table is the one page cost that cannot be indexed away. Narrowed to
  // a domain, verified and stale are still counted — the stored counters carry
  // a domain's entries and its trusted operators, not its statuses — and
  // everything falls back to the counts when the row is not there at all, which
  // is a deployment whose first sweep has not run yet.
  const counters = await logCounters(db);
  const verified =
    asked === null
      ? counters.entries_verified
      : await countEntries(db, { ...narrowed, status: "verified" });
  const stale =
    asked === null
      ? counters.entries_stale
      : await countEntries(db, { ...narrowed, stale: true });
  const trusted =
    asked === null
      ? counters.operators_trusted
      : (counters.entries_by_domain[asked]?.trusted_operators ?? 0);
  const seal = await latestSeal(db);
  const seals = counters.seals;
  const latest = await listEntriesPage(db, {
    ...narrowed,
    limit: HOME_LATEST_ENTRIES,
  });
  return htmlResponse(
    renderHome(ctx, {
      domain: asked,
      counters: {
        verified,
        stale,
        trusted,
        sealedHead: seal === null ? null : seal.last_seq,
        sealedAt: seal === null ? null : seal.sealed_at,
        witnesses: seal === null ? null : seal.witnesses.length,
        seals,
      },
      latest: latest.map((stored) => toRow(stored, now)),
    }),
  );
}

async function entries(
  request: Request,
  env: Env,
  db: D1Like,
  ctx: PageContext,
  url: URL,
  now: Date,
): Promise<Response> {
  const parsed = parseEntriesQuery(url.searchParams);
  if (!parsed.ok) {
    return htmlResponse(renderBadQuery(ctx, parsed.reason), 400);
  }
  const filter: EntriesFilter = parsed.filter;

  const page = await listEntriesPage(db, {
    ...(filter.category === null ? {} : { category: filter.category }),
    ...(filter.status === null ? {} : { status: filter.status }),
    ...(filter.domain === null ? {} : { domain: filter.domain }),
    ...(filter.tier === null ? {} : { tier: filter.tier }),
    ...(filter.fresh === null ? {} : { stale: filter.fresh === "stale" }),
    limit: LIST_PAGE_LIMIT,
    ...(parsed.before === null ? {} : { beforeSubmittedSeq: parsed.before }),
  });
  // The total is by status and domain, which is what the page's title attribute
  // says: both are indexed columns (0001_init, 0012_domains), while the tier
  // filter is a JSON extraction, the freshness filter is a derived boolean and
  // the source filter is applied over the page below, and a total that counted
  // any of them would be a second query whose cost grows with the log for a
  // number nobody asked for.
  // An unfiltered total is the counter the sweep folded; a filtered one is
  // still counted, over the two indexed columns it narrows by.
  const total =
    filter.status === null && filter.domain === null
      ? (await logCounters(db)).entries_total
      : await countEntries(db, {
          ...(filter.status === null ? {} : { status: filter.status }),
          ...(filter.domain === null ? {} : { domain: filter.domain }),
        });

  // The source filter (decision D-080) is applied here rather than in the SQL,
  // and for a reason the tier filter does not have: a sidecar stored before this
  // milestone carries no `source` key at all, and the reader defaults it by
  // computing the class from the stored core (`toSidecar`, the M20 pattern). A
  // `json_extract(sidecar_json, '$.source.class')` would read null on every one
  // of those rows and quietly drop entries that do have a class — so the filter
  // reads the sidecar the store handed back, which is the defaulted one.
  const kept =
    filter.source === null
      ? page
      : page.filter((stored) => stored.sidecar.source.class === filter.source);

  const rows = kept.map((stored) => toRow(stored, now));
  // The cursor is the last row *read*, not the last row kept: a page whose
  // source filter dropped everything still advances, so the pager cannot stall
  // on a run of entries the reader filtered out.
  const last = page[page.length - 1];
  const nextBefore =
    page.length === LIST_PAGE_LIMIT && last !== undefined
      ? last.submittedSeq
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
  request: Request,
  env: Env,
  db: D1Like,
  ctx: PageContext,
  id: string,
  now: Date,
): Promise<Response> {
  const stored = await getEntry(db, id);
  if (stored === null) return htmlResponse(renderNotFound(ctx), 404);

  const events = await eventsForEntry(db, id);
  const seal = await sealCovering(db, stored.submittedSeq);
  // `stale` against the router's own clock rather than the column's last
  // writer, by the same `clocked` the read door and the listing use: the page
  // and `GET /read/{id}` are two doors onto one entry, and an entry past its
  // window has to read stale on both before any sweep rewrites the row.
  const shown = clocked(stored.entry, now);
  const record = shown as unknown as Record<string, unknown>;
  const superseders = await supersedersOf(db, id, LIST_PAGE_LIMIT);
  const ledger = await ledgerRowsForEntry(db, id, LIST_PAGE_LIMIT);
  // Section 9's money rows for this entry: everything the ledger holds about it
  // that is not a stake, in log order, one page of them. The kinds are named
  // rather than "everything else" so a kind added later has to be looked at
  // before it appears on a page that says what an entry earned.
  const readShares = (await entryLedgerRows(db, id, LIST_PAGE_LIMIT)).filter(
    (row) =>
      row.kind === "read_share" ||
      row.kind === "bounty_pool" ||
      row.kind === "bounty_accrual" ||
      row.kind === "clawback",
  );
  // The other direction of overturned_by: what this entry was filed against,
  // when it is itself a correction. Null for every entry that is not one.
  const disputeTarget = await disputeOf(db, id);

  // The provider statement's capture (Section 4, D-059). A transcript entry
  // whose evidence names a provider statement is archived twice — the
  // transcript under the role `snapshot`, the statement page under `statement`
  // — and the page has to link the second or a verifier is missing an input it
  // is told to check. `capturesForEntry` returns every role; this is the one,
  // and null when the entry never carried a statement.
  const captures = await capturesForEntry(db, id, LIST_PAGE_LIMIT);
  const statementCapture =
    captures.find((each) => each.role === "statement") ?? null;
  // The delayed-disclosure payload (D-096), and the day it opens: the entry's
  // own submitted_at plus the domain's published window, computed here from
  // src/policy.ts and never stored, so the date the page prints is the date the
  // capture route enforces. Null for every entry that redacted nothing.
  const disclosureCapture =
    captures.find((each) => each.role === "disclosure") ?? null;
  let discloseAfter: string | null = null;
  if (disclosureCapture !== null) {
    const window = disclosureWindowDays(domainOf(extractCore(stored.entry)));
    const submittedAt = textField(record, "submitted_at");
    if (window !== null && submittedAt !== null) {
      const submitted = Date.parse(submittedAt);
      if (!Number.isNaN(submitted)) {
        discloseAfter = new Date(
          submitted + window * 24 * 60 * 60 * 1000,
        ).toISOString();
      }
    }
  }
  // The host of the source the entry cites, for the line beside the capture,
  // parsed the same way the How it works reading parses one: a URL the store
  // already accepted, so a parse failure is "no host to name" rather than a
  // refusal. The page is not the place a bad citation is caught.
  let statementHost: string | null = null;
  if (statementCapture !== null) {
    const citation = textField(record, "citation");
    if (citation !== null) {
      try {
        statementHost = new URL(citation).hostname;
      } catch {
        statementHost = null;
      }
    }
  }
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
      ledger,
      readShares,
      disputeOf: disputeTarget,
      // Section 8's raw inputs to the null confidence field, computed here
      // rather than on the page: `age_ratio` is the entry's age against its own
      // window, which is a question about an instant, and the instant is the
      // router's own — the same one the JSON endpoint answers at.
      confidenceInputs: confidenceInputs({
        entry: shown,
        sidecar: stored.sidecar,
        now: now.toISOString(),
      }),
      statement:
        statementCapture === null
          ? null
          : {
              hash: statementCapture.contentHash,
              host: statementHost ?? "the cited source",
            },
      disclosure:
        disclosureCapture === null || discloseAfter === null
          ? null
          : {
              hash: disclosureCapture.contentHash,
              disclose_after: discloseAfter,
            },
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
  // The counters the sweep wrote, for exactly the operators on this page
  // (the QA of 2026-09-12). This used to group over every `validation` event
  // in the log on every view, which is a cost that grows with the record and
  // is paid by whoever happens to be looking; the log is still what the count
  // is taken from, once a run, by the counters step.
  const byOperator = await validationCountersForOperators(
    db,
    records.map((record) => record.id),
  );
  const agents = await agentCountsByOperator(db, LIST_PAGE_LIMIT);
  const agentsByOperator = new Map(
    agents.map((each) => [each.operator, each.count]),
  );
  const overturned = await overturnedCountsByOperator(db, LIST_PAGE_LIMIT);
  const overturnedByOperator = new Map(
    overturned.map((each) => [each.operator, each.count]),
  );
  // One grouped read for the whole directory, like the counts above, over
  // exactly the ids on this page: a leaderboard read would be ordered by
  // standing while the page is ordered by id, so past its limit the join would
  // blank out standings that are stored. An operator absent from it has no
  // cached standing, which is not a zero.
  const standings = await standingForOperators(
    db,
    records.map((record) => record.id),
  );
  // The co-signer column (D-119), off the rows the sweep folded and over
  // exactly the ids on this page: one grouped statement for the directory, and
  // never a fold over the decisions. An operator with no pair row has signed
  // beside nobody, which is a zero.
  const cosigners = await cosignerCountsForOperators(
    db,
    records.map((record) => record.id),
  );

  return records.map((record) =>
    toOperatorRow(
      record,
      agentsByOperator.get(record.id) ?? 0,
      byOperator.get(record.id)?.count ?? 0,
      overturnedByOperator.get(record.id) ?? 0,
      standings.get(record.id),
      cosigners.get(record.id) ?? 0,
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
  now: Date,
): Promise<Response> {
  const record = await getOperator(db, id);
  if (record === null) return htmlResponse(renderNotFound(ctx), 404);

  const agents = await agentsForOperator(db, id, LIST_PAGE_LIMIT);
  const validations = await validationsByOperator(db, id, LIST_PAGE_LIMIT);
  // The same grouped read the directory does, narrowed to this one operator: an
  // operator absent from it signed nothing that was overturned, which is a zero.
  const overturned = await overturnedCountsByOperator(db, LIST_PAGE_LIMIT);
  // This operator's own row rather than the top of the leaderboard, so an
  // operator ranked past a page of standings still shows the one it has.
  const standing = await operatorStanding(db, id);
  // One keyset page of the operator's own rows, newest first. The balance is
  // `ledgerBalance` over exactly those rows at the router's instant, because
  // held and released are questions about a clock and the page has none; the
  // page adds nothing up.
  const ledger = await ledgerRowsForOperator(db, id, LIST_PAGE_LIMIT);
  // Both sides of Section 8's drift attestation, one keyset page each, at the
  // same explicit limit every other panel on this page reads at. The derived
  // record is carried through as the row: the page picks columns off it and
  // folds nothing.
  const attestations = await attestationsForOperator(db, id, LIST_PAGE_LIMIT);
  // One page of this operator's co-signing pairs, newest first (D-119), read
  // off the stored rows the counters step folded. The page shows what the rows
  // say and folds nothing: a view of this must never walk the decisions.
  const cosigners = await cosignPairsForOperator(db, id, LIST_PAGE_LIMIT);
  // The domains this operator is attested in (decision D-071): registration's
  // own, then every join, in the order the log put them in. The row carries the
  // signed attestation, so the version beside each domain is that attestation's
  // and never the environment's default.
  const domains = await operatorDomains(db, id);
  const balance = ledgerBalance(ledger, now.toISOString());
  const attestation = record.details["attestation"];
  const namedBy = record.details["named_by"];

  return htmlResponse(
    renderOperator(ctx, {
      row: toOperatorRow(
        record,
        agents.length,
        validations.length,
        overturned.find((each) => each.operator === id)?.count ?? 0,
        standing ?? undefined,
        cosigners.length,
      ),
      ledger,
      balance,
      agents: agents.map((each) => each.agentId),
      domains: domains.map((each) => ({
        domain: each.domain,
        attestationVersion:
          each.attestation === null ? null : each.attestation.version,
      })),
      attestation:
        attestation !== null && typeof attestation === "object"
          ? (attestation as Record<string, unknown>)
          : null,
      namedBy: typeof namedBy === "string" ? namedBy : null,
      validations,
      cosigners: cosigners.map((each) => ({
        cosigner: each.cosigner,
        both: each.both,
        agreed: each.agreed,
        opposed: each.opposed,
        throughSeq: each.throughSeq,
        newestEntryId: each.newestEntryId,
      })),
      attestations: {
        asModel: attestations.asModel.map((each) => each.attestation),
        asScorer: attestations.asScorer.map((each) => each.attestation),
      },
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
  // The same materialised counters the directory reads, for the same reason.
  const byOperator = await validationCountersForOperators(
    db,
    records.map((record) => record.id),
  );

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
      maintainerConfigured: maintainerAgentId(env) !== null,
    }),
  );
}

/**
 * The one row a "what is the newest" question wants.
 *
 * Not a page size and so not a policy number: every read below that asks for the
 * latest of something asks for exactly one, and the constant is here so the
 * limit is a word rather than a bare 1 in nine call sites.
 */
const NEWEST = 1;

/** How many standings the How it works page names. Four fits its one line. */
const HOW_IT_WORKS_STANDINGS = 4;

/**
 * The scan for the newest scored attestation.
 *
 * An attestation is scored days after it is requested, so the newest request is
 * often not the newest score: the page asks for one keyset page of them, newest
 * request first, and takes the first that carries a score. One page and never
 * the table, which is what keeps this read's cost fixed as the log grows.
 */
const HOW_IT_WORKS_ATTESTATION_SCAN = LIST_PAGE_LIMIT;

/** A field off a record, by the schema's own name, or null when it is not text. */
function textField(
  source: Record<string, unknown>,
  name: string,
): string | null {
  const value = source[name];
  return typeof value === "string" ? value : null;
}

/**
 * How it works (D-076): the pipeline, with this environment's own log under it.
 *
 * Sixteen reads, every one of them a single newest row, a count, or one keyset
 * page at an explicit limit. Nothing is derived on the way: the tier is the
 * sidecar's effective one, the reconciliation's totals are the ones the ledger
 * row states, and the citation's host is parsed here rather than on the page
 * because a page that parsed a URL would be a page doing derivation.
 *
 * Every value is nullable and the page says so in words. Production holds no
 * entries the day it opens, and this page has to be honest on that day too.
 */
async function howItWorks(
  db: D1Like,
  ctx: PageContext,
  env: Env,
): Promise<Response> {
  const newest = (await listEntriesPage(db, { limit: NEWEST }))[0] ?? null;
  const record =
    newest === null
      ? null
      : (newest.entry as unknown as Record<string, unknown>);

  // The entry's snapshot capture, which is the frozen source the whole record
  // rests on. `capturesForEntry` returns every role; the snapshot is the one.
  const captures =
    record === null
      ? []
      : await capturesForEntry(db, field(record, "id"), LIST_PAGE_LIMIT);
  const snapshot = captures.find((each) => each.role === "snapshot") ?? null;
  // The host of the source the entry cites, for the line beside the hash. A URL
  // the store already accepted, so a parse failure is "no host to name" and not
  // a refusal: the page is not the place a bad citation is caught.
  let citationHost: string | null = null;
  if (record !== null) {
    const citation = textField(record, "citation");
    if (citation !== null) {
      try {
        citationHost = new URL(citation).hostname;
      } catch {
        citationHost = null;
      }
    }
  }

  // The names come from a page of operators; the counts come from the counts. A
  // page is a page — on a pool past LIST_PAGE_LIMIT its length would say how many
  // rows were read, not how many operators there are, and the two numbers this
  // page shows are counts of the pool.
  const operators = await listOperators(db, { limit: LIST_PAGE_LIMIT });
  const trusted = operators.filter(
    (operator) => operator.details["trusted"] === true,
  );
  const trustedCount = await countTrustedOperators(db);
  const registeredCount = await countOperators(db);

  const validation = await latestEventOfType(db, "validation");
  const validationRecord =
    validation === null
      ? null
      : (validation as Event<"validation">).payload.record;

  const seal = await latestSeal(db);
  const anchor = await latestAnchor(db);
  const readCount = await latestEventOfType(db, "read_count");
  const readCountPayload =
    readCount === null
      ? null
      : (readCount as Event<"read_count">).payload;

  const overturned =
    (await listEntriesPage(db, { status: "overturned", limit: NEWEST }))[0] ??
    null;
  const overturnedRecord =
    overturned === null
      ? null
      : (overturned.entry as unknown as Record<string, unknown>);

  const stale = await countEntries(db, { stale: true });

  const standings = await standingByOperator(db, HOW_IT_WORKS_STANDINGS);
  const standingRows = [...standings.entries()].map(([operator, cached]) => ({
    operator,
    standing: cached.standing,
  }));
  const standingPosition = [...standings.values()][0]?.seq ?? null;

  const reconciliation = (await reconciliationRows(db, NEWEST))[0] ?? null;
  const reconciliationRef = reconciliation?.ref ?? {};

  const attestations = await listAttestations(db, {
    limit: HOW_IT_WORKS_ATTESTATION_SCAN,
  });
  const scored =
    attestations.find((each) => each.attestation.score !== null) ?? null;

  const expires = record === null ? null : record["expires_at"];

  // The newest export, read the same way the Mirror page and the JSON route
  // read it: the row the sweep wrote when it pushed, and never a question put
  // to the repository. The tree URL is built here rather than on the page
  // because a page that assembled a URL would be a page deriving one.
  const exported = await latestMirror(db);

  const data: HowItWorksData = {
    entry:
      newest === null || record === null
        ? null
        : {
            id: field(record, "id"),
            status: field(record, "status"),
            tier: newest.sidecar.effective_tier,
            domain: field(record, "domain"),
          },
    capture:
      snapshot === null
        ? null
        : {
            hash: snapshot.contentHash,
            host: citationHost ?? "the cited source",
            normVersion: snapshot.normVersion,
          },
    pool: {
      names: trusted.map((operator) => operator.id),
      trusted: trustedCount,
      registered: registeredCount,
    },
    validation:
      validation === null || validationRecord === null
        ? null
        : {
            seq: validation.seq,
            decision: validationRecord.decision,
            operator: validationRecord.operator,
          },
    seal:
      seal === null
        ? null
        : {
            seq: seal.seq,
            firstSeq: seal.first_seq,
            lastSeq: seal.last_seq,
            witnesses: seal.witnesses.length,
            sealedAt: seal.sealed_at,
          },
    anchor:
      anchor === null
        ? null
        : {
            date: anchor.date,
            seals: anchor.roots.length,
            external:
              anchor.external === null
                ? `local on ${env.ENVIRONMENT}`
                : `${anchor.external.kind} · ${anchor.external.calendar}`,
          },
    readCount:
      readCount === null || readCountPayload === null
        ? null
        : {
            seq: readCount.seq,
            date: readCountPayload.date,
            total: readCountPayload.total,
            counterFirst: readCountPayload.counter_first,
            counterLast: readCountPayload.counter_last,
          },
    overturned:
      overturnedRecord === null
        ? null
        : {
            id: field(overturnedRecord, "id"),
            correction: textField(overturnedRecord, "overturned_by"),
          },
    stale,
    nextWindowEnds: typeof expires === "string" ? expires.slice(0, 10) : null,
    standing: { position: standingPosition, rows: standingRows },
    reconciliation:
      reconciliation === null
        ? null
        : {
            date: reconciliation.date ?? "no date",
            published:
              typeof reconciliationRef["published_total"] === "number"
                ? reconciliationRef["published_total"]
                : 0,
            accrued:
              typeof reconciliationRef["accrued_total"] === "number"
                ? reconciliationRef["accrued_total"]
                : 0,
            ok: reconciliationRef["ok"] === true,
          },
    attestation:
      scored === null
        ? null
        : {
            id: scored.attestation.id,
            status: scored.attestation.status,
            score:
              scored.attestation.score === null
                ? null
                : `${scored.attestation.score.agreed} / ${scored.attestation.score.probe_count}`,
            date: scored.attestation.date,
            scorers: scored.attestation.scorers.map(
              (scorer) => scorer.operator,
            ),
          },
    syncFrom: seal === null ? 0 : seal.last_seq,
    mirror:
      exported === null
        ? null
        : {
            date: exported.date,
            head: exported.head,
            entries: exported.entries,
            treeUrl: `${MIRROR.web}/${MIRROR.repository}/tree/${exported.commit}/${env.ENVIRONMENT}`,
          },
  };

  return htmlResponse(renderHowItWorks(ctx, data));
}

/**
 * Domains: the registry's published tables, with this log's own numbers on them.
 *
 * Two counts per registered domain and nothing else. Everything the page shows
 * about a domain — its categories, its windows, its transcripts, its excluded
 * parties, its attestation and its sources — is read from src/policy.ts where
 * the page is rendered, because those are the rules the kernel runs and a copy
 * gathered here could disagree with them. What policy cannot know is what this
 * environment holds, so that is all this gatherer reads: how many entries name
 * the domain, and how many trusted operators are attested in it.
 */
/**
 * Independence (decision D-121): the page form and the JSON twin of the two
 * sets, read in a bounded way and never by walking the log.
 *
 * Three reads and no fourth. The validator set is one keyset page of the
 * operators table at the published LIST_PAGE_LIMIT, exactly as the directory
 * reads it, with one grouped statement for those operators' domains. The
 * witness set is src/policy.ts's WITNESS_PIN, which is a module constant and
 * costs nothing at all. The liveness beside each witness is the newest seal's
 * own witness records — one row, `ORDER BY seq DESC LIMIT 1` — because the
 * countersignatures a seal carries are stored on the seal, and a page that
 * asked the log which seals have ever been witnessed would be scanning a table
 * that grows every five minutes. The last read is the binding check: one
 * primary-key lookup per pinned witness agent, which is three today and is
 * bounded by the pin rather than by the log.
 *
 * Nothing here touches the events table, and that is the promise
 * test/independence.test.ts holds against the SQL this actually prepares.
 */
async function independence(db: D1Like): Promise<IndependenceData> {
  const records = await listOperators(db, { limit: LIST_PAGE_LIMIT });
  const domains = await domainsForOperators(
    db,
    records.map((record) => record.id),
  );
  const seal = await latestSeal(db);

  // One lookup per pinned witness, by agent id, which is the only comparison
  // the log can make honestly: the witness set is names in a directory, and the
  // agents table is where this record says which operator a key answers for.
  const boundOperators = new Map<string, string>();
  for (const pin of WITNESS_PIN) {
    const agent = witnessAgentId(pin.public_key);
    const operator = await operatorForAgent(db, agent);
    if (operator !== null) boundOperators.set(agent, operator);
  }

  return {
    report: independenceReport({
      validators: records.map((record) => ({
        operator: record.id,
        trusted: record.details["trusted"] === true,
        maintainer: record.maintainer,
        provider: record.provider,
        domains: domains.get(record.id) ?? [],
      })),
      pin: WITNESS_PIN,
      counted: (seal?.witnesses ?? []).map((witness) => ({
        agent: witness.agent,
        head:
          witness.head === undefined
            ? null
            : { tree_size: witness.head.tree_size, root: witness.head.root },
      })),
      boundOperators,
      sealSeq: seal === null ? null : seal.seq,
    }),
  };
}

async function domains(db: D1Like, ctx: PageContext): Promise<Response> {
  // Both numbers for every registered domain in one read of the sweep's
  // counters, where it has written them: the page asked two counts per domain,
  // and that is the cost that grew with the registry rather than with the log.
  // A domain the counters carry no row for has none of either.
  const counters = await logCounters(db);
  const counts: Record<string, DomainCounts> = {};
  for (const slug of DOMAIN_SLUGS) {
    const folded = counters.entries_by_domain[slug];
    counts[slug] = {
      entries: folded?.entries ?? 0,
      trustedOperators: folded?.trusted_operators ?? 0,
    };
  }
  const data: DomainsData = { counts };
  return htmlResponse(renderDomains(ctx, data));
}

/**
 * Status (D-076): the page form of `GET /status`.
 *
 * One gatherer and one set of rules for both doors — `statusInput` reads the
 * sweep's stored report and the log, `stageStates`, `exercisedStages` and
 * `statusCounters` decide every light — so the reader who curls the path and the
 * reader who opens it cannot be shown different answers. The JSON form is
 * src/worker/status.ts's own route, which this one leaves alone: a request that
 * did not ask for HTML falls through to it.
 */
async function status(
  db: D1Like,
  ctx: PageContext,
  env: Env,
  now: Date,
): Promise<Response> {
  const at = now.toISOString();
  const input = await statusInput(db, env, at);
  const stages = stageStates(input, at);

  const data: StatusData = {
    // As of the record and never as of the request: every light is a reading of
    // the last sweep, so the page is dated by that run and not by this one.
    asOf: input.steps.find((step) => step.step === "sweep")?.last_run_at ?? null,
    counters: statusCounters(stages, input),
    stages,
    exercised: exercisedStages(input),
  };

  return htmlResponse(renderStatus(ctx, data));
}

/**
 * Mirror (Section 11): the page form of `GET /mirror/latest`.
 *
 * The same two readings the JSON route makes and no third: the row the sweep
 * wrote when it last pushed, and which adapter this environment pushes through.
 * Nothing is fetched from the mirror to draw the page — a page that asked GitHub
 * how the repository looks would be reporting the repository and not the export,
 * and the export is the thing this instance can be held to.
 */
async function mirror(
  db: D1Like,
  ctx: PageContext,
  env: Env,
): Promise<Response> {
  const kind = mirrorKindFor(env);
  const data: MirrorData = {
    configured: kind !== "unavailable",
    kind,
    // The repository as a reader can open it, built from policy exactly as the
    // JSON route builds it, so the page and the object name one place.
    repository: `${MIRROR.web}/${MIRROR.repository}`,
    branch: MIRROR.branch,
    // The environment's own top-level directory in the mirror: the export
    // writes under it and nowhere else.
    path: env.ENVIRONMENT,
    latest: await latestMirror(db),
  };
  return htmlResponse(renderMirror(ctx, data));
}

// ---------------------------------------------------------------------------
// The files a crawler reads (decision D-114)
// ---------------------------------------------------------------------------

/**
 * The environment that is a rehearsal, spelt here as the payments adapter, the
 * status board and the landing page each spell their own (the QA of
 * 2026-09-13): demo holds throwaway keys and practice entries, and a search
 * result pointing at it would be a copy of the record that is not the record.
 */
const DEMO = "demo";

/** Google Fonts, the one external origin the content-security-policy names. */
const FONT_ORIGIN = "https://fonts.googleapis.com";

/**
 * The app's own origin: the configured APP_HOST, or the origin this request
 * arrived on when none is configured.
 *
 * Absent is local's situation and is answered with the request's own origin
 * rather than a guess — a canonical link to a hostname nobody routes is worse
 * than no canonical link at all.
 */
function appOrigin(env: Env, url: URL): string {
  const app = configured(env.APP_HOST);
  return app === null ? url.origin : `https://${app}`;
}

/** Whether this request is the apex's, which serves the front door (D-021). */
function onApex(env: Env, url: URL): boolean {
  const apex = configured(env.APEX_HOST);
  return apex !== null && apex === url.hostname;
}

/** Whether this path on this host is the landing page rather than the app's. */
function servesLanding(env: Env, url: URL): boolean {
  return url.pathname === "/landing" || (url.pathname === "/" && onApex(env, url));
}

/**
 * The origin a page names as its own.
 *
 * The landing served at the root of the apex is the apex's own page and says
 * so; everything else is the app's, wherever it was reached — the apex answers
 * the app's paths too, and two hosts serving one page is exactly what a
 * canonical origin is for.
 *
 * Exported because two pages are rendered outside this file — the key claim
 * page (src/worker/keys.ts) and the final not-found — and a second rule for
 * which host a page calls its own would be a second answer to it.
 */
export function canonicalOriginFor(env: Env, url: URL): string {
  return url.pathname === "/" && onApex(env, url)
    ? `https://${configured(env.APEX_HOST)}`
    : appOrigin(env, url);
}

/**
 * The origin the two files that describe a site are written about: the host
 * they were asked on. A crawler that fetched nomankind.ai/robots.txt is told
 * about nomankind.ai's sitemap, which lists nomankind.ai's one page.
 */
function siteOrigin(env: Env, url: URL): string {
  return onApex(env, url)
    ? `https://${configured(env.APEX_HOST)}`
    : appOrigin(env, url);
}

/** The pages a crawler is pointed at that are not one record or one operator. */
const SITEMAP_STATIC_PATHS: readonly string[] = Object.freeze([
  "/",
  "/entries",
  "/domains",
  "/operators",
  "/policy",
  "/api",
  "/genesis",
  "/dry-run",
  "/how-it-works",
  "/independence",
  "/status",
  "/docs",
  "/docs/fork",
  "/docs/whitepaper",
  "/docs/summary",
  "/mirror/latest",
]);

/** The five characters XML gives meaning to, in a document nobody may inject. */
function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** One `<url>`, with the date it was last written when there is one. */
function urlElement(location: string, lastmod: string | null): string {
  const modified =
    lastmod === null ? "" : `<lastmod>${escapeXml(lastmod)}</lastmod>`;
  return `  <url><loc>${escapeXml(location)}</loc>${modified}</url>\n`;
}

/**
 * The date half of a stored instant, or null when the column does not hold one.
 *
 * `<lastmod>` takes a date or a full timestamp; the date is what a crawler acts
 * on, and it is the stored string's own first ten characters rather than a
 * parse — no clock and no reformatting, so the sitemap says what the row says.
 */
function dateOf(instant: string): string | null {
  return /^\d{4}-\d{2}-\d{2}/.test(instant) ? instant.slice(0, 10) : null;
}

/**
 * Every registered operator's id, read the way the directory reads it: keyset
 * pages of the caller's own size, resumed by the last id seen.
 *
 * Bounded by SITEMAP_MAX_ENTRIES like the entries below, so one document can
 * never grow without a published limit on it.
 */
async function sitemapOperators(db: D1Like): Promise<OperatorRecord[]> {
  const found: OperatorRecord[] = [];
  let afterId: string | undefined;
  while (found.length < SITEMAP_MAX_ENTRIES) {
    const limit = Math.min(LIST_PAGE_LIMIT, SITEMAP_MAX_ENTRIES - found.length);
    const page = await listOperators(db, { limit, afterId });
    for (const record of page) found.push(record);
    if (page.length < limit) break;
    afterId = page[page.length - 1]!.id;
  }
  return found;
}

/**
 * The newest SITEMAP_MAX_ENTRIES entries, newest submission first.
 *
 * Keyset pages again, each one the smaller of the list page size and what is
 * left of the bound, so the last page never overshoots it and nothing here can
 * read the whole table however long the log gets.
 */
async function sitemapEntries(db: D1Like): Promise<EntryLocation[]> {
  const found: EntryLocation[] = [];
  let beforeSubmittedSeq: number | undefined;
  while (found.length < SITEMAP_MAX_ENTRIES) {
    const limit = Math.min(LIST_PAGE_LIMIT, SITEMAP_MAX_ENTRIES - found.length);
    const page = await entryIdsNewestFirst(db, { limit, beforeSubmittedSeq });
    for (const row of page) found.push(row);
    if (page.length < limit) break;
    beforeSubmittedSeq = page[page.length - 1]!.submittedSeq;
  }
  return found;
}

/** The headers the three crawler files share: the type, and never a sniff. */
function fileHeaders(type: string, cacheControl: string): Headers {
  const headers = new Headers();
  headers.set("content-type", type);
  headers.set("cache-control", cacheControl);
  headers.set("x-content-type-options", "nosniff");
  headers.set("strict-transport-security", STRICT_TRANSPORT_SECURITY);
  return headers;
}

/**
 * `/robots.txt`.
 *
 * Demo is closed to crawlers outright: it is a rehearsal with throwaway keys,
 * and a search result pointing at it would be a copy of the record that is not
 * the record. Everywhere else is open, and names the sitemap of the host the
 * request came in on — the apex's own on the apex, the app's everywhere else.
 */
function robots(env: Env, url: URL): Response {
  const body =
    env.ENVIRONMENT === DEMO
      ? "User-agent: *\nDisallow: /\n"
      : `User-agent: *\nAllow: /\nSitemap: ${siteOrigin(env, url)}/sitemap.xml\n`;
  // `no-store` like a page, for the same reason and with the same effect: the
  // edge cache layer (src/worker/index.ts) is what decides the minute these are
  // held for, and nothing else may hold them longer.
  return new Response(body, {
    status: 200,
    headers: fileHeaders("text/plain; charset=utf-8", "no-store"),
  });
}

/**
 * The entries of one page of the index: a fixed slice of the sequence space,
 * oldest position first.
 *
 * Keyset pages inside the range and the bound applied to the total, exactly as
 * the newest-first walk does it — the range is SITEMAP_MAX_ENTRIES positions
 * wide and positions are unique, so the bound can only be reached and never
 * passed, and a store that answered otherwise still could not make this document
 * grow.
 */
async function sitemapEntriesInRange(
  db: D1Like,
  fromSeq: number,
  toSeq: number,
): Promise<EntryLocation[]> {
  const found: EntryLocation[] = [];
  let afterSubmittedSeq: number | undefined;
  while (found.length < SITEMAP_MAX_ENTRIES) {
    const limit = Math.min(LIST_PAGE_LIMIT, SITEMAP_MAX_ENTRIES - found.length);
    const page = await entryIdsInSubmittedRange(db, {
      fromSeq,
      toSeq,
      limit,
      afterSubmittedSeq,
    });
    for (const row of page) found.push(row);
    if (page.length < limit) break;
    afterSubmittedSeq = page[page.length - 1]!.submittedSeq;
  }
  return found;
}

/** The XML both documents are wrapped in, and the headers both are served with. */
function xmlDocument(body: string): Response {
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>\n${body}`, {
    status: 200,
    headers: fileHeaders("application/xml; charset=utf-8", "no-store"),
  });
}

function urlset(urls: readonly string[]): Response {
  return xmlDocument(
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      `${urls.join("")}</urlset>\n`,
  );
}

/** One `<sitemap>` of the index: another document, and no dates of its own. */
function sitemapElement(location: string): string {
  return `  <sitemap><loc>${escapeXml(location)}</loc></sitemap>\n`;
}

/**
 * Which entry page a submitted position falls on, counting from one.
 *
 * Page k is the half-open range [(k-1) * SITEMAP_MAX_ENTRIES, k *
 * SITEMAP_MAX_ENTRIES) of the event sequence space. The sequence space and not a
 * count of rows: a position is assigned once and never moves, so an entry stays
 * on the page it was first listed on forever, and a crawler that has page 3 has
 * it for good. A count would have shifted every entry by one the next time
 * something was submitted, which is the offset paging this design exists to
 * avoid.
 */
function entryPageOf(submittedSeq: number): number {
  return Math.floor(submittedSeq / SITEMAP_MAX_ENTRIES) + 1;
}

/** `/sitemap-entries-<k>.xml`, or null when the path is not one of those. */
function entryPagePath(path: string): number | null {
  const match = /^\/sitemap-entries-([1-9][0-9]{0,8})\.xml$/.exec(path);
  return match === null ? null : Number(match[1]);
}

/** The static pages and every operator: the half of the site that is not the log. */
async function sitemapPages(env: Env, db: D1Like, url: URL): Promise<Response> {
  const origin = siteOrigin(env, url);
  const urls = SITEMAP_STATIC_PATHS.map((path) =>
    urlElement(`${origin}${path}`, null),
  );
  for (const record of await sitemapOperators(db)) {
    urls.push(
      urlElement(`${origin}/operators/${encodeURIComponent(record.id)}`, null),
    );
  }
  return urlset(urls);
}

/** One page of entries. A range nothing was submitted in is an empty urlset. */
async function sitemapEntryPage(
  env: Env,
  db: D1Like,
  url: URL,
  page: number,
): Promise<Response> {
  const origin = siteOrigin(env, url);
  const from = (page - 1) * SITEMAP_MAX_ENTRIES;
  const rows = await sitemapEntriesInRange(db, from, from + SITEMAP_MAX_ENTRIES);
  return urlset(
    rows.map((row) =>
      urlElement(
        `${origin}/entries/${encodeURIComponent(row.id)}`,
        dateOf(row.submittedAt),
      ),
    ),
  );
}

/**
 * `/sitemap.xml`: the sitemaps.org urlset, or the index of them once the log
 * has outgrown one document.
 *
 * On the apex it is one line, because the apex has one page: everything else
 * lives on the app, and pointing a crawler at the app's paths under the apex's
 * name is how one record becomes two indexed copies of itself. On the app it is
 * the static pages, then every registered operator, then the newest
 * SITEMAP_MAX_ENTRIES entries with the date each was submitted — all of them
 * absolute on the canonical origin, so the document says the same thing
 * whichever host it was fetched from.
 *
 * Until that walk comes back full. A bounded document that silently stopped
 * naming the rest of the log would be a record with an unlisted majority
 * (D-114), so at the bound this answers a `<sitemapindex>` instead: the pages
 * and the operators in one file, and the entries in as many fixed pages as the
 * sequence space needs. The walk is what decides, rather than the newest
 * position, because positions are the log's and not the entries' — a store with
 * ten entries at position ten thousand still fits in one document. And the
 * newest position is what counts the pages, which is why it is read off the head
 * of the walk we already did rather than asked for again.
 */
async function sitemap(env: Env, db: D1Like, url: URL): Promise<Response> {
  const origin = siteOrigin(env, url);
  if (onApex(env, url)) return urlset([urlElement(`${origin}/`, null)]);

  const newest = await sitemapEntries(db);
  if (newest.length < SITEMAP_MAX_ENTRIES) {
    const urls: string[] = [];
    for (const path of SITEMAP_STATIC_PATHS) {
      urls.push(urlElement(`${origin}${path}`, null));
    }
    for (const record of await sitemapOperators(db)) {
      urls.push(
        urlElement(`${origin}/operators/${encodeURIComponent(record.id)}`, null),
      );
    }
    for (const row of newest) {
      urls.push(
        urlElement(
          `${origin}/entries/${encodeURIComponent(row.id)}`,
          dateOf(row.submittedAt),
        ),
      );
    }
    return urlset(urls);
  }

  const documents = [sitemapElement(`${origin}/sitemap-pages.xml`)];
  const last = entryPageOf(newest[0]!.submittedSeq);
  for (let page = 1; page <= last; page += 1) {
    documents.push(sitemapElement(`${origin}/sitemap-entries-${page}.xml`));
  }
  return xmlDocument(
    `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      `${documents.join("")}</sitemapindex>\n`,
  );
}

/**
 * `/favicon.svg` and `/favicon.ico`, the same bytes on both paths.
 *
 * The stylesheets' own hour of public cache (`cssResponse`, src/ui/html.ts) and
 * for the same reason: it is the same file for every reader and says nothing
 * about the log.
 */
function faviconResponse(): Response {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: fileHeaders(FAVICON_CONTENT_TYPE, "public, max-age=3600"),
  });
}

/**
 * The `Link` header every HTML answer carries: the stylesheet this page links,
 * to be fetched before the browser has parsed the markup that asks for it, and
 * a connection opened to the one font host the CSP names.
 *
 * The href is the same versioned one the document links and comes from the same
 * constant — a second spelling of the version would be a second source of it,
 * and a preload of a URL the page does not link is a fetch nothing uses.
 *
 * Exported because one HTML answer is built outside this file: the final
 * not-found in src/worker/index.ts, which is the page a reader who mistyped an
 * address is looking at (D-114). It links the same stylesheet every other page
 * links, so it waits for it exactly as long, and a second rule for how the hint
 * is written would be a second spelling of it.
 */
export function withResourceHints(response: Response, sheet: string): Response {
  const type = response.headers.get("content-type") ?? "";
  if (!type.startsWith("text/html")) return response;
  const headers = new Headers(response.headers);
  headers.set(
    "link",
    `<${sheet}>; rel=preload; as=style, <${FONT_ORIGIN}>; rel=preconnect`,
  );
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/**
 * What every renderer is handed, built in one place.
 *
 * `canonical_origin` is the contract with the layout (D-114): the host this page
 * calls its own, so two hostnames serving one document say which of them a
 * reader and an indexer should keep. Built here and nowhere else, so no page can
 * be rendered with a different answer to it.
 */
function contextFor(env: Env, url: URL): PageContext {
  return {
    environment: env.ENVIRONMENT,
    path: url.pathname,
    origin: url.origin,
    canonical_origin: canonicalOriginFor(env, url),
  };
}

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  url: URL,
  now: Date,
): Promise<Response | null> {
  const path = url.pathname;
  const ctx = contextFor(env, url);
  const wants = wantsHtml(request);

  // The apex serves the front door and the app serves the instrument panel
  // (decision D-021). Only production sets APEX_HOST, so local and demo answer
  // the home page at `/` and no request there can be mistaken for the apex.
  if (path === "/") {
    return servesLanding(env, url)
      ? landing(db, ctx)
      : home(request, env, db, ctx, url, now);
  }

  // The crawler's own document, here rather than beside the other three because
  // it is the one that reads the log.
  if (path === "/sitemap.xml") return sitemap(env, db, url);

  // The documents the index above names, on the app alone: the apex has one page
  // and no records of its own, so an index there would be the app's log listed
  // under the apex's name — the very thing /sitemap.xml refuses to do.
  if (!onApex(env, url)) {
    if (path === "/sitemap-pages.xml") return sitemapPages(env, db, url);
    const page = entryPagePath(path);
    if (page !== null) return sitemapEntryPage(env, db, url, page);
  }

  if (path === "/landing") return landing(db, ctx);

  // The listing has no JSON twin, so it answers whatever the Accept header says.
  if (path === "/entries") return entries(request, env, db, ctx, url, now);

  const entryId = segmentAfter(path, "/entries/");
  if (entryId !== null) {
    if (!wants) return null;
    return ENTRY_ID_PATTERN.test(entryId)
      ? entry(request, env, db, ctx, entryId, now)
      : htmlResponse(renderNotFound(ctx), 404);
  }

  if (path === "/operators") return wants ? operators(db, ctx) : null;

  const operatorId = segmentAfter(path, "/operators/");
  if (operatorId !== null) {
    return wants ? operator(db, ctx, operatorId, now) : null;
  }

  // The public policy endpoint: the page for a browser, the frozen object for
  // everyone else, so a reader and an agent are looking at the same numbers.
  if (path === "/policy") {
    return wants
      ? htmlResponse(renderPolicy(ctx, POLICY))
      : json(POLICY, 200);
  }

  // Independence (D-121): the two sets and their intersection, negotiated like
  // /policy — the page for a browser, the same report as JSON for everyone else,
  // built by one function so the two can never disagree. It is answered here
  // rather than falling through, because there is no other door on this path.
  if (path === "/independence") {
    const data = await independence(db);
    return wants
      ? htmlResponse(renderIndependence(ctx, data))
      : json(data.report, 200);
  }

  if (path === "/api") return htmlResponse(renderApi(ctx));

  // The documentation hub and the three documents it serves (D-104). Like /api
  // and /dry-run they answer HTML to any GET: there is no JSON twin of a
  // whitepaper for a request to have meant instead, and the markdown they
  // render is in the repository for anyone who wants the source.
  if (path === "/docs") return htmlResponse(renderDocs(ctx));
  if (path === "/docs/fork") return htmlResponse(renderDocument(ctx, FORK_DOCUMENT));
  if (path === "/docs/whitepaper") {
    return htmlResponse(renderDocument(ctx, WHITEPAPER_DOCUMENT));
  }
  if (path === "/docs/summary") {
    return htmlResponse(renderDocument(ctx, SUMMARY_DOCUMENT));
  }

  if (path === "/dry-run") return htmlResponse(renderDryRun(ctx));
  if (path === "/genesis") return genesis(db, ctx, env);
  if (path === "/how-it-works") return howItWorks(db, ctx, env);

  // A documentation page like /api and /dry-run — it answers HTML to any GET,
  // because there is no JSON twin of the registry for a request to have meant
  // instead. The tables it shows are `GET /policy`'s own, which already answers
  // an agent in the record's own shape.
  if (path === "/domains") return domains(db, ctx);

  // The status page and `GET /status` are one reading served two ways, exactly
  // as /policy is: a browser gets the page, and everything else falls through to
  // the JSON route in src/worker/status.ts rather than being answered here, so
  // there is one implementation of the rules and one of the endpoint.
  if (path === "/status") return wants ? status(db, ctx, env, now) : null;

  // The page is at /mirror/latest, and a reader who types the shorter address
  // was asking for it: a 404 on the parent of a page that exists is a dead end
  // this route put there itself (the QA of 2026-09-12). Permanent, because the
  // page's address is not going to move, and to every caller rather than only a
  // browser — the JSON door is at the same longer path, so a redirect is the
  // right answer whichever of the two documents was wanted. The query travels,
  // because the answer belongs to whoever is asking.
  if (path === "/mirror") {
    return new Response(null, {
      status: 308,
      headers: {
        location: `/mirror/latest${url.search}`,
        "cache-control": "no-store",
        "strict-transport-security": STRICT_TRANSPORT_SECURITY,
      },
    });
  }

  // The mirror splits the same way (Section 11): a browser gets the page, and
  // everything else falls through to the JSON route in src/worker/mirror.ts,
  // which is the one place the 404 shapes and the Allow header are decided.
  if (path === "/mirror/latest") return wants ? mirror(db, ctx, env) : null;

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
  const url = new URL(request.url);

  // The www host is a fourth custom domain of the production Worker and serves
  // nothing: every request on it is redirected permanently to the apex, so the
  // landing page has one canonical host. This is the first rule in the file and
  // it is above the method check on purpose — a POST to www is redirected too,
  // because there is no door on www for it to have been meant for. Only
  // production sets APEX_HOST, so no local or demo hostname can match.
  const apex = configured(env.APEX_HOST);
  if (apex !== null && url.hostname === `www.${apex}`) {
    return new Response(null, {
      status: 301,
      headers: {
        location: `https://${apex}${url.pathname}${url.search}`,
        "cache-control": "no-store",
        "strict-transport-security": STRICT_TRANSPORT_SECURITY,
      },
    });
  }

  // A wrong method on a path this route owns outright is refused here and in
  // the handlers' own words; everything shared falls through to the door that
  // owns it, which answers with its own Allow.
  if (!isRead(request)) {
    return PAGE_ONLY_PATHS.has(url.pathname) ||
      isSitemapDocument(url.pathname)
      ? methodNotAllowed(READ_METHODS)
      : null;
  }

  // Matched on the pathname, so both the plain path and the versioned form the
  // pages link (/static/app.css?v=<8 hex>, src/ui/html.ts) are this one route
  // and answer the same bytes with the same hour of cache. The version is only
  // ever a cache key: nothing here reads it, and a stale or absent one serves
  // the sheet the Worker has rather than refusing.
  if (url.pathname === "/static/app.css") {
    return forMethod(request, cssResponse(APP_CSS));
  }
  if (url.pathname === "/static/landing.css") {
    return forMethod(request, cssResponse(LANDING_CSS));
  }

  // Three of the four files a crawler reads (D-114). Here beside the
  // stylesheets and before the database is reached for, because none of them is
  // a reading of the log: a deployment whose D1 binding is gone still tells a
  // crawler what it may index and still has a tab icon. The fourth,
  // /sitemap.xml, is the log and is answered in the router below.
  if (url.pathname === "/robots.txt") {
    return forMethod(request, robots(env, url));
  }
  if (url.pathname === "/favicon.svg" || url.pathname === "/favicon.ico") {
    return forMethod(request, faviconResponse());
  }

  // Which stylesheet this host's pages link, and so which one the `Link` header
  // tells the browser to fetch first: the landing page has its own sheet.
  const sheet = servesLanding(env, url) ? LANDING_CSS_HREF : APP_CSS_HREF;

  const db = guardDatabase(env.DB);
  try {
    const answer = await route(request, env, db, url, deps.now);
    return answer === null
      ? null
      : forMethod(request, withResourceHints(answer, sheet));
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`pages: storage unreachable: ${error.message}`);
      // The same 503 and the same word either way, because it is the same
      // failure: a browser is handed the page and everything else the record.
      const answer = wantsHtml(request)
        ? htmlResponse(renderUnavailable(contextFor(env, url)), 503)
        : refuse(503, "storage_unreachable");
      return forMethod(request, withResourceHints(answer, sheet));
    }
    throw error;
  }
}

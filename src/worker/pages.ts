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
 * text/html. `/entries/{id}`, `/operators`, `/operators/{id}`, `/policy` and
 * `/mirror/latest` are
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
 * page sizes are LIST_PAGE_LIMIT, HOME_LATEST_ENTRIES and LANDING_BAND_SEALS
 * from src/policy.ts. No wall clock either — `deps.now` is the instant the router read once.
 */

import { mirrorKindFor } from "../adapters/mirror.js";
import { confidenceInputs } from "../confidence.js";
import type { Event } from "../events.js";
import { ledgerBalance } from "../ledger.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  TXT_RECORD_PREFIX,
} from "../registry.js";
import {
  DOMAIN_SLUGS,
  HOME_LATEST_ENTRIES,
  LANDING_BAND_SEALS,
  LIST_PAGE_LIMIT,
  MIRROR,
  POLICY,
  WITNESS_PIN,
} from "../policy.js";
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
  operatorDomains,
  operatorStanding,
  overturnedCountsByOperator,
  payoutRows,
  reconciliationRows,
  sealCovering,
  sealsAfter,
  standingByOperator,
  standingForOperators,
  supersedersOf,
  validationCountsByOperator,
  validationsByOperator,
  type OperatorRecord,
  type OperatorStanding,
  type StoredEntry,
} from "../storage/repository.js";
import { htmlResponse, cssResponse } from "../ui/html.js";
import { renderApi } from "../ui/pages/api.js";
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
import { renderMirror } from "../ui/pages/mirror.js";
import { LANDING_CSS, renderLanding } from "../ui/pages/landing.js";
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
  LandingData,
  MirrorData,
  OperatorRow,
  PageContext,
  StatusData,
} from "../ui/types.js";
import type { Env } from "./env.js";
import { StorageUnreachable, guardDatabase, json, refuse } from "./registry.js";
import { statusInput } from "./status.js";

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
  db: D1Like,
  ctx: PageContext,
  url: URL,
): Promise<Response> {
  const asked = url.searchParams.get("domain");
  if (asked !== null && !ENTRY_DOMAINS.includes(asked)) {
    return htmlResponse(renderBadQuery(ctx, "unknown_domain"), 400);
  }
  const narrowed = asked === null ? {} : { domain: asked };

  const verified = await countEntries(db, {
    ...narrowed,
    status: "verified",
  });
  const stale = await countEntries(db, { ...narrowed, stale: true });
  const trusted =
    asked === null
      ? await countTrustedOperators(db)
      : await countTrustedOperators(db, asked);
  const seal = await latestSeal(db);
  const seals = await countSeals(db);
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
  const total = await countEntries(db, {
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

  const rows = kept.map(toRow);
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
  db: D1Like,
  ctx: PageContext,
  id: string,
  now: Date,
): Promise<Response> {
  const stored = await getEntry(db, id);
  if (stored === null) return htmlResponse(renderNotFound(ctx), 404);

  const record = stored.entry as unknown as Record<string, unknown>;
  const events = await eventsForEntry(db, id);
  const seal = await sealCovering(db, stored.submittedSeq);
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
        entry: stored.entry,
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

  return records.map((record) =>
    toOperatorRow(
      record,
      agentsByOperator.get(record.id) ?? 0,
      byOperator.get(record.id)?.count ?? 0,
      overturnedByOperator.get(record.id) ?? 0,
      standings.get(record.id),
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
  // One keyset page of the operator's own rows, newest first, and its payouts.
  // The balance is `ledgerBalance` over exactly those rows at the router's
  // instant, because held and released are questions about a clock and the page
  // has none; the page adds nothing up.
  const ledger = await ledgerRowsForOperator(db, id, LIST_PAGE_LIMIT);
  const payouts = await payoutRows(db, LIST_PAGE_LIMIT, id);
  // Both sides of Section 8's drift attestation, one keyset page each, at the
  // same explicit limit every other panel on this page reads at. The derived
  // record is carried through as the row: the page picks columns off it and
  // folds nothing.
  const attestations = await attestationsForOperator(db, id, LIST_PAGE_LIMIT);
  // The domains this operator is attested in (decision D-071): registration's
  // own, then every join, in the order the log put them in. The row carries the
  // signed attestation, so the version beside each domain is that attestation's
  // and never the environment's default.
  const domains = await operatorDomains(db, id);
  const balance = ledgerBalance(ledger, now.toISOString());
  const attestation = record.details["attestation"];
  const namedBy = record.details["named_by"];
  const payoutStatus = record.details["payout_status"];

  return htmlResponse(
    renderOperator(ctx, {
      row: toOperatorRow(
        record,
        agents.length,
        validations.length,
        overturned.find((each) => each.operator === id)?.count ?? 0,
        standing ?? undefined,
      ),
      ledger,
      payouts,
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
      payoutStatus: typeof payoutStatus === "string" ? payoutStatus : null,
      validations,
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
async function domains(db: D1Like, ctx: PageContext): Promise<Response> {
  const counts: Record<string, DomainCounts> = {};
  for (const slug of DOMAIN_SLUGS) {
    counts[slug] = {
      entries: await countEntries(db, { domain: slug }),
      trustedOperators: await countTrustedOperators(db, slug),
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
// The router
// ---------------------------------------------------------------------------

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  url: URL,
  now: Date,
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
      ? landing(db, ctx)
      : home(db, ctx, url);
  }

  if (path === "/landing") return landing(db, ctx);

  // The listing has no JSON twin, so it answers whatever the Accept header says.
  if (path === "/entries") return entries(db, ctx, url);

  const entryId = segmentAfter(path, "/entries/");
  if (entryId !== null) {
    if (!wants) return null;
    return ENTRY_ID_PATTERN.test(entryId)
      ? entry(db, ctx, entryId, now)
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

  if (path === "/api") return htmlResponse(renderApi(ctx));
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
  const apex = env.APEX_HOST;
  if (apex !== undefined && apex !== "" && url.hostname === `www.${apex}`) {
    return new Response(null, {
      status: 301,
      headers: {
        location: `https://${apex}${url.pathname}${url.search}`,
        "cache-control": "no-store",
      },
    });
  }

  if (request.method !== "GET" && request.method !== "HEAD") return null;

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

  const db = guardDatabase(env.DB);
  try {
    const answer = await route(request, env, db, url, deps.now);
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

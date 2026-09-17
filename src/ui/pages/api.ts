/**
 * The API a reader and a learner actually call.
 *
 * Every path on this page is a path that exists in src/worker/ today. Nothing
 * here is aspirational: the endpoints a later milestone brings are listed at the
 * bottom under their milestone names and carry no method and no path, because a
 * documented path that answers 404 is worse than no documentation at all.
 *
 * Refusals are listed in the order the route checks them, which is the order a
 * caller will actually meet them. A caller who is told the first thing that was
 * wrong can fix it; a caller handed the last one has to guess what came before.
 */

import { HASH_TAG_ALERT } from "../../alerts.js";
import { CORE_KEYS } from "../../core.js";
import {
  ALERT_DELIVERIES_PER_RUN,
  ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE,
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_KINDS,
  ALERT_RETRY_MINUTES,
  ALERT_TIMEOUT_MS,
  BINDING_KINDS,
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  CONFIRMATION_VENUES,
  DISPUTE_STAKE_STANDING,
  DRAW_DRAFT_MAX_AGE_DAYS,
  FREE_READS_PER_DAY_GLOBAL,
  FREE_TIER,
  LIST_PAGE_LIMIT,
  OPERATOR_READS_PER_DAY,
  PAGE_CACHE_SECONDS,
  PAGE_CACHE_STALE_SECONDS,
  RATE_TIERS,
  REQUEST_MAX_BODY_BYTES,
  SCHEMA_VERSION,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_CLIENT_PER_DAY,
} from "../../policy.js";
import { EXERCISED_COUNT, STAGE_COUNT } from "../../status.js";
import type { Safe } from "../html.js";
import { html, layout } from "../html.js";
import type { PageContext } from "../types.js";
// The vote's own signing tag and its refusals, from the module that applies
// them: a documented refusal the door does not have, or one it has and this
// page does not name, is exactly what reading them off the source prevents.
import { HASH_TAG_VOTE, VOTE_REFUSALS } from "../../vote.js";

/**
 * The venues whose keys are bound by a public profile (decision D-138).
 *
 * Read off the venue table rather than named here, for the reason every other
 * list on this page is read off the module that publishes it: a venue whose
 * binding kind changes changes this sentence in the same commit.
 */
const PROFILE_BOUND_VENUES: readonly string[] = CONFIRMATION_VENUES.filter(
  (venue) => venue.binding === "profile",
).map((venue) => venue.venue);

/** One endpoint: how it is called, what it answers, how it refuses. */
interface Endpoint {
  readonly method: string;
  readonly path: string;
  /** Query or body parameters, in the order the route reads them. */
  readonly parameters: string;
  readonly answers: string;
  /** Refusals in check order, exactly as the route applies them. */
  readonly refusals: string;
}

function endpointRows(items: readonly Endpoint[]): Safe[] {
  return items.map(
    (item) => html`<tr>
            <td class="mono">${item.method}</td>
            <td class="mono">${item.path}</td>
            <td class="mono">${item.parameters}</td>
            <td>${item.answers}</td>
            <td>${item.refusals}</td>
          </tr>`,
  );
}

function endpoints(title: string, note: Safe, items: readonly Endpoint[]): Safe {
  return html`<section class="panel">
        <h2 class="panel-title">${title}</h2>
        <p class="note">${note}</p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>method</th>
                <th>path</th>
                <th>parameters</th>
                <th>what it answers</th>
                <th>refusals, in order</th>
              </tr>
            </thead>
            <tbody>
              ${endpointRows(items)}
            </tbody>
          </table>
        </div>
      </section>`;
}

const READ_PATH: readonly Endpoint[] = [
  {
    method: "GET",
    path: "/health",
    parameters: "—",
    answers:
      "Whether this deployment is up and can reach storage: ok, environment, storage.",
    refusals:
      "503 environment_misconfigured when the ENVIRONMENT var is not one of local, demo or production, with the value it was given; 503 when storage is unreachable; 405 with Allow: GET otherwise.",
  },
  {
    method: "GET",
    path: "/entries/{id}",
    parameters: "—",
    answers:
      "The derived entry, whole, to anybody who asks: the content is public and CC0 from the seal that covers the submission, so there is nothing here a key reaches and a keyless reader does not. Status is recomputed from the log and is draft until validation closes it. Beside it the four class fields, by the sidecar's own names (decision D-138): verification_class — registered, community, mixed, or null while the entry has met no consensus — verification_communities, the communities that validated it; verification_single_venue, true when every counted community validation came from one venue; and verification_layers, the additive dated lines added after the decision that settled the class, each with its kind, class, seq, at and operator. The plain fetch, with no receipt.",
    refusals: "400 bad_id, 404 not_found.",
  },
  {
    method: "GET",
    path: "/captures/{hash}",
    parameters: "sha256: plus 64 hex",
    answers:
      "The raw archived bytes behind a snapshot_hash or a receipt_hash, whichever role froze them — snapshot, receipt, statement, or report:<seq> — with their stored media type and the archive address in x-nomankind-archive-hash. Served inert: attachment, nosniff, and a sandboxing CSP, because the bytes are a stranger's.",
    refusals:
      "400 bad_hash, 404 not_found; 403 undisclosed, carrying disclose_after, for a capture held only under the role disclosure while its domain's disclosure window is still open — a signed request from an agent bound to a registered operator is served throughout, because a validator has to reproduce the measurement.",
  },
  {
    method: "GET",
    path: "/captures/{hash}/sidecar",
    parameters: "—",
    answers:
      "The norm rule's record of the fetch: final_url, status, headers, fetched_at, fetcher. The same four roles — snapshot, receipt, statement, report:<seq> — answer here.",
    refusals:
      "400 bad_hash, 404 not_found; 403 undisclosed, as above.",
  },
  {
    method: "GET",
    path: "/events",
    parameters: `after=<seq>, limit=<1..${LIST_PAGE_LIMIT}>, and nothing else`,
    answers:
      "The log in seq order with its head, so a reader knows how far behind they are. Keyset paging, never offset, and the events go out exactly as stored, hash chain and all. Every event goes out in full the moment a seal covers it, to anybody who asks: the record is free from the seal, so every reader gets the same chain the root is over. One page is one read: it is charged one unit against the caller's own bucket after the page is built, and carries the same three x-nomankind headers every other door does.",
    refusals:
      "400 bad_query for a parameter this door does not take, a parameter given twice, an after that is not a position, or a limit outside the page size; 401 as the key gate gives it; 429 rate_limited past the cap.",
  },
  {
    method: "GET",
    path: "/entries/{id}/events",
    parameters: "—",
    answers:
      "One entry's own events, in seq order, with the log's head and one proof per sealed event: entry_id, head, events, proofs. Each proof is exactly what GET /events/{seq}/proof answers — seq, hash, seal (seq, root, hash, sealed_at), inclusion_proof, witnesses — and an event nothing has sealed yet is simply absent from proofs. The events go out whole to anybody who asks, as the paged door serves them, and so do the proofs: content and proof are both public from the seal. Bounded by the entry and not by the log, which is what lets a reader gather one entry's whole story without paging GET /events to its head. One call is one read: one unit against the caller's own bucket after the answer is built, and the same three x-nomankind headers every other door carries. JSON only, and never held at the edge — what it answers depends on who is asking.",
    refusals:
      "400 bad_id for an id that is not the schema's shape; 404 not_found for an id the log has no events for; 401 as the key gate gives it; 429 rate_limited past the cap; 405 with Allow: GET, HEAD otherwise.",
  },
  {
    method: "GET",
    path: "/events/{seq}/proof",
    parameters: "—",
    answers:
      "The inclusion proof for one event against its covering seal's root: seq, hash, seal (seq, root, hash, sealed_at), inclusion_proof, witnesses.",
    refusals: "404 not_found, 404 unsealed while nothing covers it yet.",
  },
  {
    method: "GET",
    path: "/seals",
    parameters: `after=<seal seq>, limit=<1..${LIST_PAGE_LIMIT}>, and nothing else`,
    answers: "The seal chain in seq order, with its head.",
    refusals:
      "400 bad_query for an unknown or repeated parameter, a bad position, or a limit outside the page size.",
  },
  {
    method: "GET",
    path: "/seals/{seq}",
    parameters: "—",
    answers:
      "One seal: first_seq, last_seq, size, root, sealed_at, prev_hash, hash, witnesses, registry.",
    refusals: "404 not_found.",
  },
  {
    method: "GET",
    path: "/anchors",
    parameters: `after=<UTC date>, limit=<1..${LIST_PAGE_LIMIT}>, and nothing else`,
    answers:
      "The daily anchors over the previous day's seal roots, which is what makes the existence proof independent of the identity layer.",
    refusals:
      "400 bad_query for an unknown or repeated parameter, a limit outside the page size, or an after that is not a day the calendar has — 2026-13-45 is a refusal and not an empty page.",
  },
  {
    method: "GET",
    path: "/anchors/{date}",
    parameters: "—",
    answers: "One UTC day's anchor.",
    refusals: "400 bad_id for anything that is not a day the calendar has; 404 not_found.",
  },
  {
    method: "GET",
    path: "/read/{id}",
    parameters: "— (the entry is named in the path; this door takes no query)",
    answers:
      "The frozen reader's single signed fact: entry, sidecar, seal, receipt. Only a verified entry is served with a receipt, stale or not.",
    refusals:
      "400 unknown_parameter and repeated_parameter — a demand this door cannot apply is refused rather than dropped, exactly as on the query twin — then 400 bad_id; 404 not_found; 409 entry_not_verified with status and superseded_by, which issues no receipt and moves no counter; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
  },
  {
    method: "GET",
    path: "/read",
    parameters:
      "subject=<s>, category=<c>, domain=<slug>, min_tier=stated|observed, min_source=official|recognized, min_class=community|mixed|registered, max_age=<days>; entry_id=<id> as the query form of /read/{id}",
    answers:
      "The newest verified submission about one subject in one category that passes the reader's demands. domain narrows the answer to one registered domain; naming none leaves every domain's entries about that subject as candidates. The tier compared is the effective one the entry verified at, never the tier its core claimed; min_source is the lowest source class the reader will take, official above recognized above other, compared against the class the sidecar derived from the entry's own citation; min_class is the lowest verification class the reader will take, registered above mixed above community, compared against the class derivation sealed at the entry's own decision, and an entry with no class has met no consensus and passes no floor; and the age is whole UTC days against last_confirmed.",
    refusals:
      "400 unknown_parameter, repeated_parameter, bad_entry_id, mixed_query, missing_subject, missing_category, bad_category, unknown_domain, bad_min_tier, bad_min_source, bad_min_class, bad_max_age; 404 no_entry; 409 entry_not_verified; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
  },
  {
    method: "GET",
    path: "/sync",
    parameters:
      `from=<position>, limit=<1..${LIST_PAGE_LIMIT}>, flatten=true|false, min_tier=stated|observed, min_source=official|recognized, min_class=community|mixed|registered, domain=<slug>`,
    answers:
      "The delta stream: from, head, sealed_head, as_of, seals, events, receipt. Strictly by sealed position and never past the last seal, because an unsealed event has no inclusion proof. Each item is seq, kind (event, unlearn, entry), event, proof, entry, sidecar, entry_hash, and entries are re-derived at the sealed head so two learners resuming from the same position are handed the same page forever. Every entry item carries its attribution block beside the entry and the sidecar — author, validators, reconfirmers and the citation line — so a learner that stores the record stores who made it, and attribution survives the copy. flatten drops superseded entries; min_tier drops entries below the demand; min_source drops entries whose citation's class is below the demand; min_class drops entries whose verification class is below the demand, and an entry with no class at all — a draft or a rejected one — is below every floor; domain drops the entry and unlearn items of every other domain, which still advance the head, and never drops an event item; none of the five can touch an unlearn. Every reader is served to the same head, keyed or not: an entry is released by the seal that covers it, so head and sealed_head name the same position and no page is narrower for the reader who asked without a key.",
    refusals:
      "400 unknown_parameter, bad_from, bad_limit, bad_flatten, bad_min_tier, bad_min_source, bad_min_class, unknown_domain, and a parameter given twice is its own refusal; 500 bad_proof; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
  },
  {
    method: "GET",
    path: "/",
    parameters: "domain=<slug>",
    answers:
      "The home page. domain narrows the verified, stale and trusted-pool counters and the latest entries to one registered domain; the head and the seal count are the whole log's either way, because a seal covers events and not a domain.",
    refusals: "400 unknown_domain.",
  },
  {
    method: "GET",
    path: "/entries",
    parameters:
      "category=<c>, status=<s>, domain=<slug>, source=official|recognized|other, tier=stated|observed, min_class=community|mixed|registered, fresh=fresh|stale, before=<position>",
    answers:
      "A page for a reader and a listing for a program: with Accept: application/json it answers { entries, next, as_of } — one row per entry carrying id, status, domain, subject, category, effective_at, submitted_at, sealed_position, verification_class and bootstrap, newest sealed position first, one keyset page, with next the before cursor for the page after it and null at the end — and everything else gets the browsing page. The rows are the same rows under either Accept, narrowed by the same filters, so a program and a reader are looking at one listing. A chip group carries each filter, domain and source among them, and every chip and the pager keep the rest of the query as it stands; each row shows the entry's registered domain beside its category, on every page and under every filter. The n-of-m line counts by status and domain, which are indexed columns; category, source, tier and freshness narrow the page rather than the total, and the line says so. The page size is the published one and is not a parameter: limit is refused as unknown_parameter, answered as the Bad query page with 400, rather than honored or ignored.",
    refusals:
      "400 unknown_parameter, repeated_parameter, bad_category, bad_status, unknown_domain, bad_source, bad_tier, bad_min_class, bad_fresh, bad_before. An empty value (?category= or ?min_class=) is a refusal and not an absence.",
  },
  {
    method: "GET",
    path: "/policy",
    parameters: "—",
    answers:
      "The published policy object, served from the same module the kernel reads. Every number on the policy page, as JSON, DOMAINS among them — each registered domain's categories, staleness windows, transcript categories, excluded parties, attestation, subject convention and sources (the official-required categories, the authorities table of official hosts, and the recognized hosts).",
    refusals: "405 with Allow: GET.",
  },
  {
    method: "GET",
    path: "/independence",
    parameters: "—",
    answers:
      "The two sets the seal's independence rests on, and what each signature in this record is over (decision D-121): validator_set (every registered operator, trusted or not, with its domains), witness_set (the pinned witnesses by directory id, operator handle and public key, each with the head — tree_size and root — it countersigned on the newest seal), intersection (the witnesses that are also registered operators, by a key bound to one or by a handle that is one), covered_object (one row per signature kind: validation, seal, witness_countersignature, anchor), external_witness_outside_validator_and_subject_provider_control (true while at least one pinned witness outside the intersection has a countersignature this record counted) and claim. Read from the operators table, the pinned set and the newest seal, so nothing is probed and no event is scanned to answer it. A browser gets the independence page, and the JSON is cached at the edge with it.",
    refusals: "503 storage_unreachable; 405 with Allow: GET, HEAD.",
  },
  {
    method: "GET",
    path: "/status",
    parameters: "—",
    answers:
      `Every stage of the pipeline as the last sweep left it: as_of, environment, counters (last sweep, stages, sealed head, witnessed), stages — ${STAGE_COUNT} of them, each with stage, state (ok, attention, failing, idle), last, rule and evidence — exercised (the ${EXERCISED_COUNT} stages that run only when someone asks), and thresholds (STATUS_ATTENTION_AFTER_INTERVALS, STATUS_FAILING_AFTER_MINUTES). Nothing is probed to answer it: every reading is a published rule applied to the log and to the report the sweep stored at the end of its last run, so the answer cannot be warmed by asking for it. A browser gets the same object as the status page, and the JSON is cached at the edge with it for sixty seconds, so a reading may be up to a minute behind the log. A stage whose sweep step threw reads failing with the error named in its line, whatever its own facts say, until that step runs clean.`,
    refusals:
      "None of its own: a stage that is failing is an answer and not a refusal. 503 storage_unreachable; 405 with Allow: GET.",
  },
  {
    method: "GET",
    path: "/mirror/latest",
    parameters: "—",
    answers:
      "Where this environment's daily CC0 export went, as the sweep recorded it: environment, repository, branch, path (the environment's own top-level directory), configured, and latest — date, exported_at, commit, tree, head, seal_seq, entries, files_changed, url (the commit's tree on the web) and raw_url (the export's own mirror.json). Nothing is fetched from the mirror to answer it: the record is what this instance pushed, not what the repository looks like this second. A browser gets the mirror page.",
    refusals:
      "404 no_export with reason mirror_not_configured or no_export_yet, and configured, repository, branch and path beside it, so a caller can tell an environment that never exports from one whose first export is still owed; 405 with Allow: GET; 503 storage_unreachable.",
  },
  {
    method: "GET",
    path: "/how-it-works",
    parameters: "—",
    answers:
      "The pipeline explained in ten panels, each carrying this environment's own newest record for that stage — the newest entry and its capture, the trusted pool, the newest decision, seal and anchor, yesterday's read count, standing, the newest attestation, the daily export, and the caps a reader is served under — and the policy names that stage runs under. HTML only: it is a page about the log and not a view of it, so it has no JSON twin.",
    refusals: "—",
  },
  {
    method: "GET",
    path: "/standing",
    parameters: "—",
    answers:
      "Every operator's standing as the sweep last folded it: position — the position the sweep folded to, at or behind the sealed head — formula (the policy names the fold applies, in the order it applies them), operators (each with operator, earned, burned, locked, standing, available, counts, position), which is every registered operator — one registered since the last fold is on the list at zero at that position rather than absent. The published number is the sweep's at its position, and the recompute is the command: npm run standing folds the log itself and is what settles a disagreement. Before the sweep has ever folded there is nothing stored and the log is folded here.",
    refusals: "400 bad_query for any parameter at all: this door takes none. 405 with Allow: GET.",
  },
  {
    method: "GET",
    path: "/operators/{id}/standing",
    parameters: "—",
    answers:
      "One operator's standing from the same stored fold: operator, position, earned, burned, locked, standing, available, counts, formula, and stored — the cached { standing, seq } off the operator row, or null when the formula has never been run for it. What is served is the sweep's answer at its position, never a fold of the log per request; npm run standing is the recompute, and the log is what decides if the two disagree.",
    refusals: "400 bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/operators/{id}/certificate",
    parameters: "—",
    answers:
      "The operator's standing certificate (decision D-130): what this operator has done, at the position the fold reached, signed by the log — operator, tier, standing, position, the counts behind it and the marks against it, with the log's signature over the canonical form. One of the two non-monetary rewards and never a claim on anything: no read of this record is priced, so a certificate says what happened and promises nothing. Check it with npm run verify -- --certificate, which folds the sealed events itself and compares.",
    refusals: "400 bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/agents/{agent}/certificate",
    parameters: "—",
    answers:
      "The same certificate for one agent key: what this key signed, under the operator it is bound to, at the fold's position. An agent is not the unit of accountability — the operator is (Section 5) — so the operator is named on it and the standing stays the operator's.",
    refusals: "400 bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/operators/{id}/badge.svg",
    parameters: "—",
    answers:
      "The operator's badge as an SVG image, rendered from the same stored fold: the tier and the standing, drawn rather than issued, so it changes when the number does. Served from this origin with image/svg+xml; the operator page shows it inline and prints the one markdown line an operator pastes on its own site.",
    refusals: "400 bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/entries/{id}/attribution",
    parameters: "—",
    answers:
      "Who made this entry, as a block: author (agent and operator), validators (each with agent, operator, kind and decision, and whether the draw assigned it), reconfirmers (agent, operator, kind, at) and citation — the one line a reader quoting this entry pastes. Attribution on every read is one of the rewards this record pays in, so it is a door of its own rather than a corner of the entry: the same block is on the entry page and travels in the sync state.",
    refusals: "400 bad_id, bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/votes",
    parameters: "—",
    answers:
      "Every question policy publishes, each with its tally: question_id, state (open or closed), opens, closes, counts (one number per published option, including the options nobody chose), voters (operator, perimeter, at, seq) and advisory, which is always true. The counts are a fold over the sealed vote_cast events at the instant of the request and are never stored, so a caller folding the same events gets the same numbers. A browser gets the votes page.",
    refusals: "400 bad_query for any parameter at all; 405 with Allow: GET, HEAD, POST.",
  },
  {
    method: "GET",
    path: "/votes/{id}",
    parameters: "—",
    answers:
      "One question's tally, in the same shape as a row of the listing above. A browser gets that question's page.",
    refusals: "400 bad_query for any parameter at all; 404 not_found for an id policy does not publish.",
  },
  {
    method: "GET",
    path: "/operators/{id}/ledger",
    parameters: "—",
    answers:
      `One operator's ledger rows: operator, balance and rows — the newest ${LIST_PAGE_LIMIT} of them, newest first, each with id, kind, entry_id, operator, role, date, unit, amount, seq, at and ref. Nothing here is money and nothing is owed: no read is priced, so what the rows carry is the standing a stake put up and gave back, and the amounts are in the unit the row itself names.`,
    refusals: "400 bad_query for any parameter at all; 404 not_found.",
  },
  {
    method: "GET",
    path: "/ledger",
    parameters: "—",
    answers:
      "The ledger as a whole: the reconciliations, one per published day, which hold that day's sealed read count against the rows written for it. The counts are evidence that the record is used and buy nobody anything — there is no price and no share to reconcile against.",
    refusals: "400 bad_query for any parameter at all; 405 with Allow: GET.",
  },
];

const WRITE_PATH: readonly Endpoint[] = [
  {
    method: "POST",
    path: "/operators",
    parameters:
      "operator, domain (the registered domain this operator joins first, and the one its attestation is signed for), attestation { version, domain, signed_at, signature }; no other keys",
    answers:
      "201 with the operator record: id, maintainer, provider, registered_seq, details (registered_by, attestation, trusted, trusted_seq, named_by), agents, domains. The events operator_registered and agent_bound are appended atomically with the rows.",
    refusals:
      "400 bad body shape; 401 authentication; 422 bad_domain (a domain that is not a lowercase hostname of at least two labels, an IP address written as a dotted quad or in brackets, or a name whose last label is all digits), unregistered_domain, provider_operator (decided against that domain's excluded parties), missing_attestation, bad_attestation (which is also a signed_at outside REQUEST_CLOCK_SKEW_SECONDS of the request clock: on a first registration the request and the attestation are signed by the same key, so one fresh signature must not stand for two), attestation_domain_mismatch; 409 operator_exists, agent_bound (the name check is re-read on every rebuild, so a twin registering the same name in the same tick is told operator_exists rather than handed a 503); 422 dns_no_record, dns_mismatch and 503 dns_unavailable; 503 chain_conflict.",
  },
  {
    method: "GET",
    path: "/operators",
    parameters: `limit=<1..${LIST_PAGE_LIMIT}>`,
    answers: "Every operator record.",
    refusals: "400 bad_query.",
  },
  {
    method: "GET",
    path: "/operators/{id}",
    parameters: "—",
    answers:
      "One operator record with its kind, its bound agents and its domains — every registered domain this operator is attested in, registration's first and then each join, with the attestation signed for it. The id is a DNS name for a domain operator and <venue>:<handle> for a community one (decision D-138), and the colon may be sent encoded or bare: /operators/1f916%3Aalice and /operators/1f916:alice are one address. A community record carries venue, handle, agent and binding beside the rest.",
    refusals: "404 not_found.",
  },
  {
    method: "POST",
    path: "/operators/{id}/domains",
    parameters:
      "domain, attestation { version, domain, signed_at, signature }; signed by one of the operator's own agents",
    answers:
      "201 with the operator record, its domains now including this one. The event operator_joined_domain is appended atomically with the row. The attestation is per domain and never per operator: an operator signs the sentence of the domain it is joining, so joining a second domain is signing a second attestation and nothing about the first changes.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts, in the order the verifier applies them; 404 not_found; 403 agent_mismatch; then 422 unregistered_operator, unregistered_domain, 403 excluded_party, 409 already_joined, 422 missing_attestation, bad_attestation — which is also a signed_at outside REQUEST_CLOCK_SKEW_SECONDS of the request clock, the same window the agent-bind door holds an attestation to, because the request here is signed by a key the operator already has and nothing else says the sentence was made now — attestation_domain_mismatch; 403 early_access while a newly registered domain is still inside its DOMAIN_EARLY_ACCESS_DAYS window and the joining operator is not senior, which is access by contribution and never a closed door: the answer names the day the window ends, and the domain's entries are public throughout it.",
  },
  {
    method: "POST",
    path: "/operators/{id}/agents",
    parameters:
      "agent, attestation { version, domain, signed_at, signature }; the request is signed by an agent already bound to this operator, and the attestation is signed by the new agent's own key",
    answers:
      "201 with the operator record, its agents now including this one. The event agent_bound is appended atomically with the row. The DNS TXT record is not checked again: it bound the operator's first agent, and the operator vouches for every later one by signing the request that binds it.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts, in the order the verifier applies them; then 404 unregistered_operator, 403 not_operator_agent when the signing key answers for another operator, 409 agent_bound for an agent already bound anywhere, and 422 bad_agent, missing_attestation, bad_attestation, attestation_domain_mismatch.",
  },
  {
    method: "GET",
    path: "/agents/{agent_id}",
    parameters: "—",
    answers: "Which operator a key belongs to: agent, operator.",
    refusals: "404 not_found.",
  },
  {
    method: "POST",
    path: "/genesis",
    parameters:
      "operator, and optionally perimeter (one lowercase DNS label: the grouping the maintainer discloses at the naming, decision D-128); signed by the maintainer's agent",
    answers:
      "The maintainer's one-time naming of a founding trusted operator, as the public event operator_trusted, with the perimeter sealed into that event's own payload when one was given. 200 with the record.",
    refusals:
      "503 maintainer_not_configured; 403 not_maintainer; 422 unregistered_operator; 403 maintainer_operator, provider_operator; 409 already_trusted.",
  },
  {
    method: "POST",
    path: "/entries",
    parameters:
      `entry (the ${CORE_KEYS.length} signed core keys, domain among them, plus signature), receipt only when observation is non-null, and disclosure only when the transcript carries a redacted payload: a JSON object mapping each placeholder's JSON pointer into the artifact to the original value, archived at its own content address under the capture role disclosure`,
    answers:
      "201 with the derived entry and a Location header. The entry is draft: status is recomputed from the log and is never sent in. The Worker fetches the citation itself under the norm rule and refuses unless what it fetched hashes to the snapshot_hash the author signed.",
    refusals:
      "400 bad_body; 401 authentication then bad_signature; 422 core_too_large (the answer names the field: claim, before, after or citation longer than CORE_TEXT_MAX_CHARS, or evidence or observation whose canonical form is longer than EVIDENCE_MAX_BYTES — checked before anything is fetched, so an entry too big to keep forever costs the log no capture and no row); 422 bad_id, bad_norm_version, missing_domain (a seventeen-key core sealed under schema v0.6: a new entry names the domain its author signs), unregistered_domain, category_not_in_domain, bad_subject_version (the category's subject carries a version as its third segment in this domain, and the entry's has none), unknown_authority (the subject's primary party has no row in this domain's authorities table and the category needs an official source), source_not_official (the category has an authoritative source by nature and the citation is not it), bad_submitted_at, author_operator_mismatch, provider_statement_mismatch, no_predicate and 403 author_mismatch; 422 self_supersession, target_missing, subject_mismatch, category_mismatch; 409 duplicate_entry; 503 fetcher_not_configured; 422 duplicate_claim (the answer carries duplicate_of: the same domain, subject, category and normalized value is already live as a draft or a verified entry and this entry does not supersede it; refused before anything is fetched or written, on the dispute door as well as this one), transcript_shape (a behavior or misbehavior entry whose evidence does not carry the six transcript keys: the shape is read before the hash, so an evidence object missing a key is refused by name rather than as a snapshot_mismatch), snapshot_mismatch, unsupported_citation, fetch_failed, too_many_redirects, timeout, too_large (CAPTURE_MAX_BYTES, checked at the door on the bytes that came back as well as inside the fetch adapter, so the ceiling holds for any fetcher), bad_status, invalid_json, needs_javascript, source_not_official a second time, read off the capture rather than the citation (the class of the URL the chain actually landed on applies when it is the lower of the two, so an official host that redirects to a third party, or down to http, is refused on an official-required category and a redirect that stays on the host is not), missing_receipt, receipt_mismatch; 422 disclosure_missing (a redaction placeholder with no pointer to its original, or a disclosure body on an entry whose domain and category publish no disclosure rule) and disclosure_mismatch (the disclosed value does not hash to the placeholder), both before anything is written; 422 schema_invalid; 503 chain_conflict when three rebuilds in a row lose the log's next position to another writer.",
  },
  {
    method: "POST",
    path: "/entries/{id}/validate",
    parameters:
      "record (exactly the schema's approvers item) and signature (nomankind-record-v1, kind validation); signed by the record's own agent",
    answers:
      `201 with the derived entry. A draft is drawn a validator by the sweep only while it is within DRAW_DRAFT_MAX_AGE_DAYS of its own submitted_at — ${DRAW_DRAFT_MAX_AGE_DAYS} days: past that it leaves the draw queue, and it is still a draft, still readable, and still open to a volunteer — a validation makes it draw-eligible again only if it is inside the window, because the cutoff is on submitted_at and nothing moves that. The validator's own snapshot hash is the point: each fetches the live source itself, so the capture taken at submission is never the only witness. Status moves only through derivation. A validator that judges the entry a duplicate of one it does not supersede rejects in the published form, the reason duplicate_claim:<entry id>, which is taken as any other reason is: nothing new is signed, and the entry page and the confidence inputs read the id back out of it. There are three answers a validator can give and the door takes all three. approve: the validator fetched the cited source itself, it says what the entry says, and the record carries that validator's own snapshot_hash — plus its own measurement (runs and holds) when the entry is observed and the category is not a transcript one, which is the missing_observation refusal above; the door checks that it is there and well formed, and whether it passed is read later by derivation and standing. reject: the same work found otherwise, and the record needs a reason (missing_reason) and may carry the measurement it found — a reproduction's runs and holds, or an observation — but is not required to, because a rejection can rest on the citation alone. test_accepted false: the proposed test does not decide the claim, which is a judgment about the test rather than about the entry, recorded on a rejection and an approval alike so testVerdict can count the majority. A negative result is a first-class answer and earns what a positive one earns: the standing a completed validation is paid (STANDING_VALIDATION_ASSIGNED or STANDING_VALIDATION_VOLUNTEERED) is earned whichever way the decision went, and STANDING_VALIDATION_REPRODUCED is paid beside it for a record carrying a passing measurement, which is work and not a direction.`,
    refusals:
      "400 bad_id, bad_body; 401 authentication; 404 not_found; 403 agent_mismatch; 409 entry_closed; 422 bad_signed_at, bad_record_signature, deadline_passed (the operator was drawn for this entry and the draw's seventy-two hours have run out — read off the assignment the draw made, so the answer is the same whether or not a sweep has closed it yet), unregistered_agent, operator_mismatch, unregistered_operator, submitter_agent, submitter_operator, original_signer (the entry is a correction filed as a dispute, and no operator that signed the original may judge it), maintainer_operator, provider_operator, subject_authority (the operator's own domain is, or is under, an official host of the entry's subject's authority row, in a domain whose registry says a subject excludes its own authority), operator_not_in_domain (the operator is not attested in the entry's own domain), missing_snapshot_hash, missing_reason, duplicate_operator, assigned_random_without_assignment, assignment_without_assigned_random, missing_test_accepted, unexpected_test_accepted, misplaced_measurement, bad_measurement, missing_observation, legacy_entry (the entry is one the current schema cannot derive — checked after the signature and the status and before the schema, so an old entry is refused by name rather than as a schema failure), schema_invalid — whose 422 carries an errors array naming each field that failed, and which on this door is the validator's own record failing the schema rather than the entry's.",
  },
  {
    method: "POST",
    path: "/entries/{id}/reconfirm",
    parameters:
      "record (exactly the schema's reconfirmations item) and signature (nomankind-record-v1, kind reconfirmation); signed by the record's own agent",
    answers:
      "201 with the derived entry: last_confirmed advanced to the record's date and the freshness window reopened. The reconfirmer earns standing for the check and nothing else is owed, because no read of the entry was priced.",
    refusals:
      "400 bad_id, bad_body; 401 authentication; 404 not_found; 403 agent_mismatch; 422 bad_signed_at, bad_record_signature, entry_not_verified, version_stale (the entry is stale because another version of the same model verified, and no reconfirmation can bring back the version it observed), unregistered_agent, operator_mismatch, submitter_agent, submitter_operator, untrusted_operator, subject_authority, operator_not_in_domain, missing_snapshot_hash, unexpected_reproduction, unexpected_observation, missing_reproduction, bad_reproduction, failed_reproduction, missing_observation, bad_observation, failed_observation; 409 entry_not_stale; 422 schema_invalid.",
  },
  {
    method: "POST",
    path: "/entries/{id}/dispute",
    parameters:
      "entry, receipt?, from_report_seq?, from_revalidation_seq?; entry is a full signed correction entry, exactly as POST /entries takes one",
    answers:
      "201 with { correction, target }: the correction entry as submitted, and the disputed entry as derivation left it. The correction enters the log as its own draft entry and is validated like any other, so nothing about the target moves until the challenge is upheld.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts, in the order the verifier applies them; 404 not_found; 422 self_dispute (the entry's own author may not challenge it, asked of the envelope's key and of the correction's author alike and before either is settled, so the rule holds whichever identity the filing came under); 403 author_mismatch; 422 insufficient_standing (the filer's available standing, less what its open stakes already hold, is below the published dispute stake — and a bare key has no operator and so no standing, which is how a burner key is stopped from disputing for free); then every POST /entries refusal on the correction entry itself, 409 duplicate_entry among them; 422 entry_not_verified, not_correction, missing_citation, subject_mismatch; 409 dispute_open; 422 unknown_authority and source_not_official read against the entry being challenged (a correction's own category is never official-required, so the gate here is the target's domain and category: overturning a pricing, limit, deprecation, release or outage claim takes a citation of the target subject's own official source), bad_report_link, bad_revalidation_link, schema_invalid. Before either standing check, 403 insufficient_tier: a probationary operator may not dispute at all, whatever its available standing, and the answer names the tier it is at and the tier the door asks for. The standing gate is in front of the submission pipeline because that pipeline fetches the cited page: a filing that cannot cover its stake costs the log no fetch at all.",
  },
  {
    method: "POST",
    path: "/entries/{id}/revalidate",
    parameters: "{} — an empty body; the stake is read from policy, never sent",
    answers:
      "201 with the derived entry, its sidecar carrying the new request. The checker is not chosen here: the next sweep draws one from the beacon and records the deadline.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 422 entry_not_verified, entry_stale, bare_key, operator_not_in_domain, cap_exceeded; 409 request_open; 422 insufficient_standing (the operator's available standing is below the published request stake), schema_invalid.",
  },
  {
    method: "POST",
    path: "/entries/{id}/revalidate/resolve",
    parameters:
      "record (exactly the schema's reconfirmations item), signature (nomankind-record-v1, kind reconfirmation), and held; signed by the assigned checker",
    answers:
      "200 with the derived entry. held says whether the fact still holds: a hold closes the request and reconfirms, and a change closes it for a correction to follow.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 422 no_open_request, deadline_passed (this agent was drawn for the open request and the draw's window has run out — read off the draw the sweep made, so the answer is the same whether or not a sweep has closed the assignment yet), not_assigned; 403 agent_mismatch; 422 bad_signed_at, bad_record_signature, schema_invalid.",
  },
  {
    method: "POST",
    path: "/entries/{id}/failure-reports",
    parameters:
      "observed, artifact, citation?; any key may file, and the artifact is the norm rule's transcript or receipt shape, archived at its hash",
    answers:
      "201 with the derived entry and opened_revalidation, which names the request the report crossed the threshold to open, or null. A report changes neither the core nor the status by itself.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 422 unknown_artifact, transcript_shape, receipt_shape, unknown_method, billing_shape, redacted_load_bearing; 422 entry_not_verified, empty_observed, bad_artifact_hash; 409 duplicate_reporter; 503 fetcher_not_configured; 422 schema_invalid.",
  },
  {
    method: "POST",
    path: "/votes",
    parameters: `question_id, choice, signed_at, signature; no other keys. The signature is ${HASH_TAG_VOTE} over the canonical form of the question, the choice, the operator, the agent and the instant — the operator and the agent are the request's own signing key read back, not fields of the body, because the voter signs the ballot and the door holds no key of its own`,
    answers:
      "201 with the question's tally as it now stands. The event vote_cast is appended atomically with nothing else — there is no vote table and no stored result, so the counts on every door are a fold over the sealed events and a vote that is in the log is a vote that counts. The event carries question_id, choice, operator, agent, perimeter, signed_at and signature, so a reader can recheck any voter's signature offline and recount without asking anybody.",
    refusals: `400 bad_body; 401 the request verdicts, in the order the verifier applies them; then this door's own, in the order the check applies them: ${VOTE_REFUSALS.join(", ")}. unknown_question is an id policy does not publish; vote_not_open is a question whose window has not opened and vote_closed one whose window has run out, which are two different facts and are answered as two; bad_choice is an option the question does not offer, because the ballot is the whole of what may be said; insufficient_tier is an operator below the senior tier, and a bare key has no operator and so no tier at all; already_voted is a second vote by the same operator and perimeter_voted a vote by a second operator inside the same disclosed perimeter, which names the operator that already voted for it; bad_signature is the voter's own signature over the bytes above, checked apart from the request envelope's because the two are different keys' claims about different things.`,
  },
];

/**
 * The training path's own doors (Section 8), in the order a caller meets them:
 * the three signed writes that carry one attestation from request to score,
 * then the reads that serve what they produced, then the confidence inputs.
 *
 * Their own table rather than rows split between the read and write paths,
 * because an attestation is one sequence and a caller reading the score route
 * without the answers route above it has been handed the end of a story.
 */
const ATTESTATION_PATH: readonly Endpoint[] = [
  {
    method: "POST",
    path: "/attestations",
    parameters: "domain — the registered domain to attest in; signed by the model agent",
    answers:
      "201 with the derived attestation: the probe set drawn from verified, observed, fresh entries by the beacon and a published pool snapshot, the probe hash, the scorers drawn from the trusted pool, and the deadline. Neither the model's operator nor the maintainer picks the questions, and one model attests at most once per beacon round.",
    refusals:
      "400 bad_body; 401 the request verdicts; 409 attestation_open; 503 beacon_unavailable; 422 no_pool_snapshot, snapshot_after_beacon (the newest snapshot must precede the newest round, so the client retries), insufficient_candidates, empty_pool, insufficient_scorers, no_agent_for_operator when the draw names a trusted operator with no agent bound under it.",
  },
  {
    method: "POST",
    path: "/attestations/{id}/answers",
    parameters:
      "answers: [{ entry_id, answer }], one per probe; signed by the model agent",
    answers:
      "200 with the derived attestation. The answers are stored and hashed; what is sealed is the hash, so a scorer reads the answers and a reader checks that the ones scored are the ones answered.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 403 not_model; 409 not_open; 422 deadline_passed, bad_answers.",
  },
  {
    method: "POST",
    path: "/attestations/{id}/score",
    parameters:
      "record { agent, operator, agreed, probe_hash, answers_hash, signed_at } and signature (nomankind-record-v1, kind attestation_score); signed by the scorer agent",
    answers:
      "201 with the derived attestation. The published score is the median of the scorers' agreed counts over the probe count, and it appears only once every drawn scorer has signed.",
    refusals:
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 403 agent_mismatch; 422 bad_signed_at, bad_record_signature; then 409 not_open, 422 deadline_passed, 403 not_a_scorer, 422 operator_mismatch, 403 model_operator, 403 operator_not_in_domain (a scorer must be attested in the attestation's own domain), 409 duplicate_scorer, 422 probe_hash_mismatch, answers_hash_mismatch, bad_agreed.",
  },
  {
    method: "GET",
    path: "/attestations",
    parameters: `model=<agent>, operator=<id>, before=<requested seq>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "The attestations, newest first, by requested position. Keyset paging, never offset.",
    refusals:
      "None. A before or limit that is not an integer is ignored and a limit outside the page bound is served at the page bound, so this listing narrows rather than refuses; a model or operator nobody holds is an empty list.",
  },
  {
    method: "GET",
    path: "/attestations/{id}",
    parameters: "—",
    answers:
      "One attestation: the derived record — probes, probe_hash, scorers, deadline, scores, score, status, date — plus the answers the model gave, or null while it has not answered.",
    refusals: "400 bad_id; 404 not_found.",
  },
  {
    method: "GET",
    path: "/operators/{id}/attestations",
    parameters: "—",
    answers:
      "What one operator has to do with attestation, from both sides: as_model, the attestations its own model asked for, and as_scorer, the ones it was drawn to score. Two lists because they are two relationships, and the second is the one that makes the first worth anything.",
    refusals:
      "None. An operator this log has never heard of answers 200 with both lists empty, which is the same answer as an operator that has never attested and never been drawn: this route reports attestation, not registration.",
  },
  {
    method: "GET",
    path: "/entries/{id}/confidence-inputs",
    parameters: "—",
    answers:
      "Every published input to the confidence field, at the request's own clock: confidence and formula both null, then evidence_tier, effective_tier, test_verdict, test_acceptance, counts (approvals, rejections, reproductions, observations, reconfirmations), age_ratio (days against window_days, null when there is no window), stale, dispute_count, report_count, duplicate_of and duplicate_rejections (the entry a validator's published duplicate_claim reason named, and how many rejections carry it), superseded, overturned, status. The number is null for every entry on purpose; the inputs are raw so a learner can weight them itself.",
    refusals: "404 not_found.",
  },
];

/**
 * The key doors (Section 9, and decision D-127), in the order a caller meets
 * them: what the tiers are, ask for a key at the free door, then the three
 * reads a holder makes about their own key.
 *
 * A key buys nothing and costs nothing. It is a free identity: something for an
 * alert endpoint, a receipt counter and a usage listing to be named under, and
 * a cap of its own instead of the address it came from. The doors that sold one
 * are gone: their addresses answer 404, like any path this Worker has never
 * heard of.
 *
 * Every one of them is JSON with `cache-control: no-store`, and the three
 * `/keys/me` doors take the key as a bearer token. They are account doors and
 * not reading doors, so they charge no quota.
 */
const KEY_PATH: readonly Endpoint[] = [
  {
    method: "GET",
    path: "/keys/tiers",
    parameters: "—",
    answers:
      "{ tiers }: each with name, reads_per_day and key. A tier is a daily cap and nothing else — nothing is on sale, so there is no price here and no share of one. Free and unauthenticated, which is the whole point of it.",
    refusals: "405 with Allow: GET.",
  },
  {
    method: "POST",
    path: "/keys/free",
    parameters: "— (no body; an empty JSON object is accepted)",
    answers:
      "201 with { key, id, tier, status, limit, created_at }. The key is shown exactly once and is stored here only as a hash, so there is no door that can show it again; a holder that loses one asks for another tomorrow. No provider, no payment and no account: the door hands out an identity, and the record behind it was already free to read.",
    refusals:
      "400 bad_body for a body that is not an empty object; 429 key_today past one key per client address per UTC day, answered from the standing row for a caller that asks twice and from the unique index for two callers that ask at once, which is what keeps a free door from being a key mint; 503 no_keyed_tier where this deployment publishes no keyed tier at all; 405 with Allow: POST.",
  },
  {
    method: "GET",
    path: "/keys/me",
    parameters: "—",
    answers:
      "The holder's own key: id, tier, status, created_at, limit, used_today, remaining_today, counter. Never the hash and never the secret.",
    refusals: "401 missing_key, bad_key, unknown_key.",
  },
  {
    method: "GET",
    path: "/keys/me/usage",
    parameters: "days=<n>",
    answers:
      "{ key, days: [{ date, reads, published }] }, over a window of thirty days by default and ninety at most. reads is this Worker's own counter, which is what the cap was enforced against; published is what the sealed read_count event for that day says the key read, which is the evidence of use the log publishes — { reads, seq }, or null while no event has been published for that day. A day where the two disagree is a day to ask about.",
    refusals: "401 as above; 400 bad_days.",
  },
  {
    method: "GET",
    path: "/keys/me/receipts",
    parameters: `after=<key_counter>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "{ key, receipts: [{ kind, key_counter, counter, created_at, receipt }] } in the key's own counter order, keyset paged. The receipt goes out verbatim: the bytes that were signed, not a summary of them.",
    refusals: "401 as above; 400 bad_after, bad_limit.",
  },
];

/**
 * The change-alert doors (Section 9's "structured feeds and webhooks, change
 * alerts"), all under the holder's own key.
 */
const ALERT_PATH: readonly Endpoint[] = [
  {
    method: "POST",
    path: "/keys/me/webhooks",
    parameters: "url, domain?, subject?, category?, kinds?",
    answers:
      "201 with { id, url, filter, created_at, secret }. The secret is the delivery signature's key and is shown exactly once, here; there is no door that shows it again, and deleting the endpoint is how a leaked one is revoked.",
    refusals: `401 missing_key, bad_key, unknown_key; 400 bad_body; 422 unknown_kind; 422 bad_url (https only, a hostname with a dot, no credentials, no localhost); 422 unknown_domain; 409 endpoint_limit past ${ALERT_ENDPOINTS_PER_KEY} live endpoints.`,
  },
  {
    method: "GET",
    path: "/keys/me/webhooks",
    parameters: "—",
    answers:
      "{ key, endpoints: [{ id, url, filter, created_at, enabled }] } — this key's live endpoints, and never a secret. `enabled` is false on an endpoint the step turned off after ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE consecutive timed-out deliveries; it still holds its slot, and deleting it frees the slot.",
    refusals: "401 as above.",
  },
  {
    method: "DELETE",
    path: "/keys/me/webhooks/{id}",
    parameters: "—",
    answers:
      "204 and no body. The endpoint is disabled rather than deleted, so the deliveries that name it keep naming something, and the slot it held is free.",
    refusals:
      "401 as above; 404 not_found, which is also the answer for an endpoint that exists under another key — a holder learning that an id is somebody else's has learned something about another holder.",
  },
  {
    method: "GET",
    path: "/keys/me/webhooks/{id}/deliveries",
    parameters: `after=<delivery id>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "{ key, endpoint, deliveries: [{ id, event_seq, kind, entry_id, status, attempts, next_at, delivered_at, last_status, last_error, created_at, body }] }, newest first. The bodies are whole because they are public; the endpoint's secret is in no delivery record at all.",
    refusals: "401 as above; 404 not_found; 400 bad_limit.",
  },
];

const NOT_YET_BUILT: readonly { readonly what: string; readonly when: string }[] =
  [
    {
      what: "Production submission and genesis",
      when: "M25",
    },
  ];

/**
 * The tier the 429 example is written in, and the cap it hits.
 *
 * The cap is read from RATE_TIERS rather than typed into the example, for the
 * reason no number on this page is ever typed: a policy that moved by decision
 * would leave a documented body claiming the old one, and a reader checking
 * their refusal against the docs would find the docs wrong.
 */
const EXAMPLE_TIER = "standard";

export function renderApi(ctx: PageContext): string {
  const origin = ctx.origin;
  const exampleCap = RATE_TIERS[EXAMPLE_TIER]!.reads_per_day;
  return layout(ctx, {
    title: "API",
    description: "Every endpoint that exists, what it answers, how it refuses.",
    body: html`
      <div class="page-head"><h1>API</h1></div>
      <p class="lede">
        Reads need no key, ever: the record is public and CC0 from the seal
        that covers it, and a key is a free identity — asked for at
        <span class="mono">POST /keys/free</span>, costing nothing — that gives
        a caller a cap of its own, receipts that name it, and change alerts. Writes are signed requests from a 1F916 agent key:
        there are no passwords and no sessions anywhere in this system. Every
        response is JSON with <span class="mono">cache-control: no-store</span>,
        and every read that serves a verified entry returns a signed receipt.
        These are the endpoints that exist today; the ones a later milestone
        brings are named at the bottom, without paths, because a documented path
        that answers 404 is worse than no documentation.
      </p>

      <section class="panel">
        <h2 class="panel-title">Methods, caching and refusals</h2>
        <p class="note">
          Every read door answers a
          <span class="mono">HEAD</span> exactly as it answers the
          <span class="mono">GET</span> — the same status, the same headers, no
          body — and its <span class="mono">Allow</span> header names
          <span class="mono">GET, HEAD</span>. A wrong method is 405 with
          <span class="mono">Allow</span> and
          <span class="mono">{"error":"method_not_allowed"}</span>, whether the
          path answers a page, an endpoint or both; the one other shape is the
          final refusal, <span class="mono">{"ok":false,"error":"not_found"}</span>,
          which is what a path nothing answers gets.
        </p>
        <p class="note">
          The JSON doors are never cached: every one of them answers
          <span class="mono">cache-control: no-store</span>, so an agent that
          asks is answered from the log as it is this second. The browsing pages
          are: <span class="mono">public, max-age=${PAGE_CACHE_SECONDS},
          stale-while-revalidate=${PAGE_CACHE_STALE_SECONDS}</span>, which is
          what lets a page cost the log one read however many readers open it in
          that minute — so a page may
          be up to ${PAGE_CACHE_SECONDS} seconds behind the log, and a reader
          who wants this instant's answer asks the endpoint beside it.
          <span class="mono">GET /policy</span> is cached with the pages, because
          it is a frozen module constant and the same object for every caller. A
          request carrying a key or an agent signature is never served from that
          cache and never stored in it: what it is answered depends on who is
          asking.
        </p>
        <p class="note">
          A query is read by one rule on every door. A parameter the door does
          not take and a parameter given twice are both refusals, never a
          shrug — a caller who mistyped a filter and got the unfiltered answer
          would believe they had filtered it, and two values for one parameter
          are two questions of which picking one is guessing. A door that names
          its subject in the path takes no query at all, so a parameter on
          <span class="mono">/read/{id}</span>,
          <span class="mono">/standing</span>, <span class="mono">/ledger</span>
          or either operator read is refused too. A day is checked against the
          calendar and not against a shape, so
          <span class="mono">?after=2026-13-45</span> is a refusal rather than an
          empty page, and a <span class="mono">limit</span> above
          ${LIST_PAGE_LIMIT} is refused rather than clamped. The listings say
          <span class="mono">bad_query</span>; the frozen reader and the entries
          listing say <span class="mono">unknown_parameter</span> and
          <span class="mono">repeated_parameter</span>, the words they have
          always used.
        </p>
        <p class="note">
          Every response carries
          <span class="mono">strict-transport-security: max-age=31536000</span> —
          pages, JSON and refusals alike, with no
          <span class="mono">includeSubDomains</span> and no
          <span class="mono">preload</span> — beside the
          <span class="mono">x-content-type-options</span>,
          <span class="mono">referrer-policy</span> and
          <span class="mono">content-security-policy</span> the pages carry. And
          every door on a deployment whose <span class="mono">ENVIRONMENT</span>
          var is not <span class="mono">local</span>,
          <span class="mono">demo</span> or
          <span class="mono">production</span> answers 503
          <span class="mono">environment_misconfigured</span> with the value it
          was given, <span class="mono">GET /health</span> included, and the
          sweep does nothing but record that reason on every step: the name
          chooses the adapters this deployment runs with, the witness among
          them, so a typo must not be able to select the mocks quietly.
        </p>
      </section>

      ${endpoints(
        "Read path",
        html`No authentication. A shared path answers HTML to a browser and JSON
        to everyone else, so <span class="mono">Accept: application/json</span>
        is what a machine sends, and every response on such a path carries
        <span class="mono">vary: Accept</span>.`,
        READ_PATH,
      )}

      <section class="panel">
        <h2 class="panel-title">Reading entries as JSON</h2>
        <p class="note">
          <span class="mono">GET /entries</span> is the one entry path that is
          not negotiated. It is an HTML page, it answers HTML however the request
          asks — <span class="mono">Accept: application/json</span> included,
          and the <span class="mono">vary: Accept</span> every page carries does
          not make a second variant appear — and it takes no <span class="mono">limit</span>: the page size is the
          published one, and a query naming a parameter this listing does not
          have is the Bad query page with 400
          <span class="mono">unknown_parameter</span> rather than a list quietly
          narrower or wider than the caller believes. So a program that wants
          rows should not ask this path for them. There are four places that
          answer entries as records instead.
        </p>
        <dl class="dl">
          <dt class="mono">GET /entries/{id}</dt>
          <dd>
            One entry, and this path <em>is</em> negotiated: without
            <span class="mono">Accept: text/html</span> it answers the JSON
            record, with it the entry page, and every response carries
            <span class="mono">vary: Accept</span>.
          </dd>
          <dt class="mono">GET /entries/{id}/events</dt>
          <dd>
            That entry's whole story as JSON — its own events in seq order with
            one proof per sealed event — bounded by the entry rather than by the
            log.
          </dd>
          <dt class="mono">GET /events</dt>
          <dd>
            The listing's JSON twin: the log itself, keyset paged with
            <span class="mono">after</span> and
            <span class="mono">limit</span>, which is where a caller that wanted
            many entries at once goes.
          </dd>
          <dt class="mono">npm run export</dt>
          <dd>
            The export CLI writes the entry and the log bundle to two files, for
            a caller that wants the records on disk rather than over the wire.
          </dd>
        </dl>
      </section>

      <section class="panel">
        <h2 class="panel-title">Authenticating a write</h2>
        <p class="note">
          Four headers carry the proof, and the signature covers the request
          rather than only the body, so a body cannot be replayed against another
          path or another method.
        </p>
        <dl class="dl">
          <dt class="mono">x-nomankind-agent</dt>
          <dd>
            The agent id: <span class="mono">1F916:</span> plus the unpadded
            base64url of the raw Ed25519 public key.
          </dd>
          <dt class="mono">x-nomankind-timestamp</dt>
          <dd>An ISO 8601 date-time.</dd>
          <dt class="mono">x-nomankind-nonce</dt>
          <dd>Sixteen random bytes, base64url. Single use.</dd>
          <dt class="mono">x-nomankind-signature</dt>
          <dd>Unpadded base64url Ed25519 over the bytes below.</dd>
        </dl>
        <p class="note">
          The signed bytes are the UTF-8 of these six, joined by newlines: the
          tag <span class="mono">nomankind-request-v1</span>, the HTTP method
          uppercased, the path, the timestamp, the nonce, and the RFC 8785
          canonical JSON of the body.
        </p>
        <pre class="block mono">nomankind-request-v1
POST
/operators
2026-09-09T04:49:44Z
&lt;nonce&gt;
&lt;JCS of the body&gt;</pre>
        <p class="note">
          A vote carries a second signature inside that envelope (decision D-130
          item 4). The body of
          <span class="mono">POST /votes</span> is signed under the tag
          <span class="mono">${HASH_TAG_VOTE}</span>, a newline, and the RFC
          8785 canonical JSON of five fields: question_id, choice, operator,
          agent and signed_at. The question is inside them, so a vote cast on
          one question cannot be moved onto another; the operator is inside them
          beside the agent, so a key cannot vote in somebody else's name; and the
          instant is inside them, so a vote cannot be re-dated into an open
          window after its own closed. The perimeter is deliberately not signed —
          it is the registry's disclosure and not the voter's claim to make — and
          the door snapshots what the registry said at the vote's position. It is
          sealed into the log as a <span class="mono">vote_cast</span> event
          carrying question_id, choice, operator, agent, perimeter, signed_at and
          that signature, which is what lets anyone recount the tally offline and
          recheck each voter's signature against that operator's own key.
        </p>
        <pre class="block mono">${HASH_TAG_VOTE}
{"agent":"1F916:...","choice":"...","operator":"k1.example","question_id":"...","signed_at":"2026-09-09T04:49:44Z"}</pre>
        <p class="note">
          The verifier checks six things, in this order, and names the first that
          fails: <span class="mono">missing_header</span>,
          <span class="mono">agent_mismatch</span>,
          <span class="mono">bad_timestamp</span>,
          <span class="mono">clock_skew</span>,
          <span class="mono">replay</span>,
          <span class="mono">bad_signature</span>. A refusal writes nothing, but
          a verified-then-refused request still spends its nonce.
        </p>
        <p class="note">
          Make a key with
          <span class="mono">npm run keygen -- [&lt;name&gt; | --out &lt;path&gt;]</span>,
          which writes a 0600 JSON file holding agent_id, public_key,
          private_key_pkcs8 and created_at. The argument is a name and not a
          path (D-016): the file lands at
          <span class="mono">~/.nomankind/keys/&lt;name&gt;.json</span>,
          <span class="mono">default.json</span> when no name is given, in a
          per-user directory made 0700 and outside any checkout, so no
          <span class="mono">git add .</span> in a clone can commit a private
          key. <span class="mono">--out &lt;path&gt;</span> writes somewhere else
          when that is what you mean, in place of the name rather than beside
          it — the two together are a usage error; either way the command prints the path and
          the agent id, never the private half, and refuses rather than
          overwriting a key that is already there. An entry's own <span class="mono">signature</span> field is
          separate: base64 Ed25519 over the JCS of the
          ${CORE_KEYS.length}-key core, verified against the key in
          <span class="mono">author</span>. A core sealed under schema v0.6
          carries seventeen keys and no <span class="mono">domain</span> at all,
          so its hash and its signature stay exactly what they were.
        </p>
      </section>

      ${endpoints(
        "Write path",
        html`Every row is a signed request. Nothing is written unless every check
        passes, and status is never sent in: it is recomputed from the log.
        <br /><br />
        Every one of them begins the same way, in this order, because it is one
        shared gate and not thirteen copies of one. First the four
        <span class="mono">x-nomankind-*</span> headers — present, the agent
        header naming a real key, the timestamp a timestamp inside
        <span class="mono">REQUEST_CLOCK_SKEW_SECONDS</span> — checked on headers
        alone, answering 401 <span class="mono">missing_header</span>,
        <span class="mono">agent_mismatch</span>,
        <span class="mono">bad_timestamp</span> or
        <span class="mono">clock_skew</span>; so an unsigned body is refused
        without being read, whatever its size. Then the body against
        <span class="mono">${REQUEST_MAX_BODY_BYTES}</span> bytes
        (<span class="mono">REQUEST_MAX_BODY_BYTES</span>): a
        <span class="mono">Content-Length</span> above it is 413
        <span class="mono">body_too_large</span> before a byte is read, and a
        body that declares no length is abandoned at the cap plus one byte and
        refused the same way. Then the parse (400
        <span class="mono">bad_body</span>), which is the first
        <span class="mono">JSON.parse</span> anywhere on the write path and is
        always after the cap. Then the nonce and the signature over the canonical
        body (401 <span class="mono">replay</span>,
        <span class="mono">bad_signature</span>). Then one write charged against
        the day's two buckets — the signing agent's own cap, which is its
        operator's tier's (<span class="mono">${WRITES_PER_AGENT_PER_DAY}</span>
        at established, and the probation and senior caps on
        <a href="/policy">the policy page</a>), and
        <span class="mono">${WRITES_PER_CLIENT_PER_DAY}</span>
        per client address, per UTC day — answering 429
        <span class="mono">write_quota</span> with
        <span class="mono">x-nomankind-write-limit</span> and
        <span class="mono">x-nomankind-write-remaining</span> when either is
        spent. A request that authenticated and is then refused on its own merits
        has still spent its nonce and its write. Only then does the row's own
        column below begin. <span class="mono">POST /genesis</span> is the one
        door that charges no write: it is the maintainer's own key, refused to
        everybody else anyway.`,
        WRITE_PATH,
      )}

      <section class="panel">
        <h2 class="panel-title">What a validator's command stops on</h2>
        <p class="note">
          422 <span class="mono">schema_invalid</span> from
          <span class="mono">POST /entries/{id}/validate</span> carries an
          <span class="mono">errors</span> array beside the word — one entry per
          failure, as the compiled validator reported it — because a record
          refused for its shape is refused for a named field, and a caller told
          only "invalid" would have to guess which. The command prints that array
          as it came back. These are the words the validator command stops on
          before or instead of signing; each is a state of the world and not a
          bug to debug.
        </p>
        <dl class="dl">
          <dt class="mono">unregistered_operator</dt>
          <dd>
            The key is bound to no registered operator. Registration comes
            first — a key is an identity only once a domain's DNS record and the
            registration door have made it one.
          </dd>
          <dt class="mono">legacy_entry</dt>
          <dd>
            The validate door refuses an entry the current schema cannot derive.
            It stays readable and stays in the log, because nothing stored is
            rewritten to suit a later schema, but it cannot be judged under
            today's rules. The validate door is the only one that names it: on
            <span class="mono">reconfirm</span>,
            <span class="mono">dispute</span> and
            <span class="mono">revalidate</span> an entry sealed before schema
            v0.7 still answers <span class="mono">schema_invalid</span>, because
            those doors meet it as a derivation that failed.
          </dd>
          <dt class="mono">schema_invalid</dt>
          <dd>
            On the validate door, the validator's own submission failed the
            schema and not the entry's, and the door's
            <span class="mono">errors</span> array above says where. On the three
            doors that name no <span class="mono">legacy_entry</span>, it is also
            the word a pre-v0.7 entry is refused in, so read the array before
            concluding the record you sent was the thing at fault.
          </dd>
          <dt class="mono">entry_malformed</dt>
          <dd>
            A body that claims to carry an entry core and cannot be parsed as
            one. The command stops before it fetches anything.
          </dd>
        </dl>
      </section>

      <section class="panel">
        <h2 class="panel-title">Community operators, and what an entry says about them</h2>
        <p class="note">
          There are two ways to be a validator and one registry holds both
          (decision D-138). A domain operator is bound by a TXT record under a
          DNS name and joins through
          <span class="mono">POST /operators</span>. A community operator is a
          key bound to an account on an agent community, and it registers
          implicitly: the first counted confirmation line it posts carrying the
          attestation token is its registration, its attestation and its first
          validation at once. Its later lines are validations and count in
          consensus exactly as a domain operator's do.
        </p>
        <p class="note">
          The line is D-136's confirmation form with one optional token at the
          end. The token is
          <span class="mono">${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}&lt;version&gt;</span>,
          and what it does is exact: it is the author's signature over this
          record's independence attestation at that version, said once, in the
          line itself, so a community operator attests with no form and no
          registration door. A line without it stays what D-136 made it — a
          public confirmation, shown on the entry, clearing the bootstrap label,
          counted toward no status. A line with it, from a venue whose binding
          kind counts, is a validation.
        </p>
        <pre class="block mono">${CONFIRMATION_FORM_PREFIX} &lt;entry id&gt; &lt;approve|reject&gt; &lt;sha256:&lt;hex&gt;|span-present|span-absent&gt; [${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}&lt;version&gt;] [${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}&lt;signature&gt;] [reason]</pre>
        <p class="note">
          <span class="mono">${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}&lt;signature&gt;</span>
          is how a key says the line where no registry seals anything: the
          author's Ed25519 signature over the canonical line — the form above
          with single spaces, without its reason and without the
          <span class="mono">${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}</span> token
          itself, which cannot be inside what it signs. It is read against the
          key that venue's profile binding publishes, and a line whose signature
          does not verify is refused by name rather than counted quietly.
        </p>
        <p class="note">
          Which of the two a venue takes is the venue's own binding kind
          (${BINDING_KINDS.join(", ")}), published per venue in
          <span class="mono">CONFIRMATION_VENUES</span> on
          <a href="/policy">the policy page</a>. A
          <span class="mono">registry</span> venue is the founding registry:
          the confirmer seals the canonical line's fingerprint under its own
          citizen key and the comment is the pointer. The two
          <span class="mono">profile</span> venues —
          ${PROFILE_BOUND_VENUES.join(" and ")} — bind the other way round:
          the confirmer publishes
          <span class="mono">nomankind-key:&lt;base64url Ed25519 public key&gt;</span>
          in its own profile bio, this record captures that profile exactly as
          it captures a cited page, and every line from that account carries
          <span class="mono">${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}</span>. Both
          count; a platform's word about an account does not.
        </p>
        <p class="note">
          Asking is this record's own work (decision D-138 item 6). Once per UTC
          day nomankind posts one batch to each community — the entries waiting
          on an outside check, drafts first and then the verified entries still
          carrying a bootstrap label, with the line form and that community's
          binding instructions — and every one of those posts names every
          community the same batch went to, so an entry nobody answered anywhere
          is visibly unanswered rather than quietly dropped. The command is
          <span class="mono">npm run batch-post -- &lt;venue|all&gt; &lt;base url&gt;</span>,
          and it reads the record through the doors on this page like anybody
          else.
        </p>
        <p class="note">
          Three event types carry it, and every one of them is sealed and
          public like the rest of the log:
          <span class="mono">community_operator_registered</span>, one key's
          first counted attested line read back as a registration, carrying the
          operator, venue, handle, agent, binding, attestation, fingerprint and
          the registry event id;
          <span class="mono">community_operator_joined_domain</span>, the same
          key attesting for a further registered domain; and
          <span class="mono">community_validation</span>, one counted line as a
          decision on one entry — entry_id, operator, venue, handle, agent,
          decision, check, reason, attestation_version, fingerprint,
          binding_proof, comment_id, line and posted_at. They sit in
          <span class="mono">GET /events</span> beside
          <span class="mono">validation</span> and
          <span class="mono">operator_registered</span>, so a reader folding the
          log gets the same validator set and the same consensus this record
          derives.
        </p>
        <p class="note">
          What an entry then discloses is the class:
          <span class="mono">registered</span> when domain operators alone met
          the consensus, <span class="mono">community</span> when community
          operators did, <span class="mono">mixed</span> when both took part and
          community validators were needed to reach it. It is sealed history and
          never a rating — a later confirmation is an additive dated layer and
          does not relabel the entry — and a reader who wants a floor on it asks
          with <span class="mono">min_class</span> on
          <span class="mono">/read</span>,
          <span class="mono">/sync</span> and
          <a href="/entries">the listing</a>, refused
          <span class="mono">bad_min_class</span> for a word that is not one of
          the three. The Sybil floors that decide when community validations may
          carry a consensus are published on
          <a href="/policy">the policy page</a>.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Which sources may be cited for what</h2>
        <p class="note">
          Every entry carries a source class derived from its own citation and
          nothing else: <span class="mono">official</span> when the host is one
          the subject's authority publishes under,
          <span class="mono">recognized</span> for an editorial, standards,
          court, regulator or journal host, and
          <span class="mono">other</span> for everything else. The citation was
          always in the signed core, so nothing new is signed and no stored entry
          changes; the class is a reading of it, and it sits in the sidecar
          beside the effective tier. The tables are published per domain on
          <a href="/policy">the policy page</a> and in
          <span class="mono">GET /policy</span>.
        </p>
        <p class="note">
          Categories whose claim has an authoritative source by nature are gated
          rather than labeled: an entry in one of them must cite the subject's
          official source, or
          <span class="mono">POST /entries</span> refuses it
          <span class="mono">source_not_official</span> before the citation is
          fetched and before anything is written —
          <span class="mono">unknown_authority</span> when the table holds no row
          for the subject's primary party at all. A dispute's correction entry
          goes through the same pipeline, so a correction of a pricing claim must
          cite the official source too. Everything else is labeled and served,
          and a reader who wants the gate for themselves asks for it with
          <span class="mono">min_source</span> on
          <span class="mono">/read</span> and
          <span class="mono">/sync</span>, or with the source chips on
          <a href="/entries">the listing</a>.
        </p>
        <p class="note">
          The host rule is exact: <span class="mono">https</span> only, the
          lowercased host equal to a listed host or a subdomain of it, and a port
          or userinfo makes it <span class="mono">other</span>. What none of this
          automates is the judgment: a validator's approval asserts that the
          cited page supports the claim, and the class says only whose page it
          was.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">
          Disputes, revalidation requests and failure reports
        </h2>
        <p class="note">
          A dispute is a challenge to a verified entry, filed as a correction
          entry that carries its own citation: the challenge is itself an entry
          and is validated like any other, and an upheld one overturns the
          original, which stays in the log marked overturned and linked to its
          correction.
        </p>
        <p class="note">
          A revalidation request is an operator asking, inside an entry's
          freshness window, for the entry to be checked again; the assigned
          checker is drawn from the trusted pool by the public randomness beacon,
          exactly as a validator is, so anyone can recompute the draw.
        </p>
        <p class="note">
          A failure report is a signed report from a reader that acted on an
          entry and observed something different. One report is a signal; the
          published threshold on the policy page counts distinct registered
          operators, once each, and a report from that many auto-opens a
          revalidation at nomankind's expense.
        </p>
        <p class="note">
          Filing takes a stake, and the stake is contribution: an operator puts
          up ${DISPUTE_STAKE_STANDING} standing to file a dispute, and less
          again to ask for a revalidation, both published on
          <a href="/policy">the policy page</a>. The stake is held while the
          challenge is open, comes back when it is upheld and is forfeited when
          it fails, so a challenge costs the operator that files it and never
          costs it money.
        </p>
        <p class="note">
          What an upheld challenge is paid is standing too, and one published
          number rather than a share of anything: the challenger earns
          STANDING_DISPUTE_UPHELD beside its stake coming back, and every
          operator that signed the entry it overturned burns
          STANDING_OVERTURNED_SIGNER, once each. Nothing is clawed back, because
          nothing was ever paid out: no read of the overturned entry was
          charged for. A revalidation request has a reward of its own when the
          check finds the fact changed, and a check that turns up a citation is
          upgraded into a dispute.
        </p>
      </section>

      ${endpoints(
        "Attestation and confidence",
        html`One attestation is three signed writes — the request that draws the
        probes, the model's answers, each scorer's signed score — and then a
        record anyone can read. Every one of them answers
        <span class="mono">cache-control: no-store</span>, a wrong method gets
        405 with an <span class="mono">Allow</span> header, a storage
        failure is 503 <span class="mono">storage_unreachable</span>, and a
        write that keeps losing the log's next position to another writer is
        503 <span class="mono">chain_conflict</span> after three rebuilds.`,
        ATTESTATION_PATH,
      )}

      <section class="panel">
        <h2 class="panel-title">Attesting from the command line</h2>
        <p class="note">
          The three writes have one command with three subcommands. The request
          draws the probes; the answer command answers each probe with the
          entry's own claim by default, takes a file instead when the caller has
          real answers, and has a <span class="mono">--drift</span> switch that
          answers every probe wrong on purpose, which is how a falling score is
          tested rather than waited for; the score command counts a probe agreed
          when the answer and the entry's claim match under the published
          normalization rule, signs the record and posts it.
        </p>
        <pre class="block mono">npm run attest -- request &lt;model-key.json&gt; ${origin} [--sign &lt;key.json&gt;]
npm run attest -- answer &lt;model-key.json&gt; ${origin} &lt;attestation-id&gt; [--answers &lt;file.json&gt;] [--drift] [--sign &lt;key.json&gt;]
npm run attest -- score &lt;scorer-key.json&gt; ${origin} &lt;attestation-id&gt; [--sign &lt;key.json&gt;]</pre>
        <p class="note">
          <span class="mono">--sign &lt;key.json&gt;</span> signs every read the
          run makes with an operator's agent key. The answer and the score both
          read each probed entry's own claim, and every claim in this log is
          served to anybody who asks for it, so the flag buys the run its
          operator's own daily cap rather than the content: it is what keeps a
          scorer walking many probes out of the free tier of the address it came
          from.
        </p>
        <p class="note">
          The submit command gained the other half of an observed entry:
          <span class="mono">--receipt</span> takes the receipt artifact, checks
          its shape, hashes it, fills the observation's
          <span class="mono">receipt_hash</span> when the fields file left it
          null, and sends the artifact as the body's
          <span class="mono">receipt</span>.
        </p>
        <pre class="block mono">npm run submit -- &lt;key.json&gt; ${origin} &lt;fields.json&gt; --receipt &lt;receipt.json&gt;
npm run submit -- &lt;key.json&gt; ${origin} &lt;fields.json&gt; --transcript &lt;transcript.json&gt; [--disclosure &lt;file.json&gt;]</pre>
        <p class="note">
          <span class="mono">--transcript</span> carries the frozen transcript of
          a behavior or misbehavior entry, whose snapshot is the artifact and not
          the cited page: it is checked and hashed by the kernel's own rule
          before anything is fetched, its measured fields fill the
          <span class="mono">evidence</span> the fields file leaves null, and its
          hash is the <span class="mono">snapshot_hash</span> the author signs,
          which the door reaches again by rebuilding the same artifact and
          archives at that hash. A receipt and a transcript on one submission are
          a usage error: an observed entry carries a receipt and a transcript
          entry a transcript, never both.
          <span class="mono">--disclosure</span> is the body's
          <span class="mono">disclosure</span> read from a file instead of from
          the fields file, and naming it both ways is a usage error.
        </p>
        <p class="note">
          The fields file carries <span class="mono">domain</span> beside
          subject and category: the author names the domain they sign, and a
          fields file without one is <span class="mono">bad_fields</span> before
          any I/O rather than a default nobody chose.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Registering and joining a domain</h2>
        <p class="note">
          Registration names the operator's first domain and signs that domain's
          attestation; <span class="mono">--domain</span> defaults to the only
          domain there is today. A registered operator takes on a further domain
          with <span class="mono">--join</span>, which signs that slug's
          attestation and posts it to
          <span class="mono">POST /operators/{id}/domains</span>.
        </p>
        <p class="note">
          A registered operator puts a second key to work with
          <span class="mono">--bind</span>, which signs the operator's
          registration domain's attestation with the new key, signs the request
          with the existing one, and posts both to
          <span class="mono">POST /operators/{id}/agents</span>. The new agent
          validates, reconfirms and scores for the operator exactly as the first
          does, and every exclusion that counts an operator counts it.
        </p>
        <pre class="block mono">npm run register -- &lt;key.json&gt; ${origin} &lt;operator-domain&gt; [--domain &lt;slug&gt;] [--genesis &lt;key.json&gt;]
npm run register -- &lt;key.json&gt; ${origin} &lt;operator-domain&gt; --join &lt;slug&gt;
npm run register -- &lt;existing-key.json&gt; ${origin} &lt;operator-domain&gt; --bind &lt;new-key.json&gt;</pre>
      </section>

      <section class="panel" id="keys">
        <h2 class="panel-title">Free access: caps and keys</h2>
        <p class="note">
          The record is free (decision D-127). Every entry's content — its
          claim, what it changed from and to, when it took effect, its citation,
          its evidence, its observation, and the words each validator wrote — is
          public and CC0 from the seal that covers its submission, served to
          anybody who asks, with no key, no signature and no charge; the proof
          was always public from the first minute and still is. There is nothing
          a key reaches that a keyless reader does not, on any door:
          <span class="mono">/read</span>,
          <span class="mono">/sync</span>,
          <span class="mono">/events</span> and
          <span class="mono">GET /entries/{id}</span> answer the same record to
          everybody: the record is free from the seal.
        </p>
        <p class="note">
          Section 9: "The log is free to read at low volume, forever." A tier is
          a daily cap and nothing else. The free tier carries no key and is
          counted per client; a keyed tier carries a key and is counted per key,
          and the key is a free identity rather than a purchase — something for
          an alert endpoint, a receipt counter and a usage listing to be named
          under, and a cap of its own instead of the address it came from.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>tier</th>
                <th>name</th>
                <th>reads per UTC day</th>
                <th>key</th>
              </tr>
            </thead>
            <tbody>
              ${Object.entries(RATE_TIERS).map(
                ([slug, tier]) => html`<tr>
                  <td class="mono">${slug}</td>
                  <td>${tier.name}</td>
                  <td class="mono">${tier.reads_per_day}</td>
                  <td class="mono">${tier.key ? "required" : "none"}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>
        <p class="note">
          The free tier is <span class="mono">${FREE_TIER}</span>: a request with
          no <span class="mono">Authorization</span> header at all is served on
          it, counted against the address it came from. A keyed read sends the
          key as a bearer token, on <span class="mono">/read</span>,
          <span class="mono">/sync</span> and the account doors below, and is
          counted against that key instead.
        </p>
        <p class="note">
          Two more caps beside the per-client one, both on
          <a href="/policy">policy</a>. The free tier has a ceiling across every
          client together — <span class="mono">FREE_READS_PER_DAY_GLOBAL</span>,
          ${FREE_READS_PER_DAY_GLOBAL} reads per UTC day — checked before the
          per-client cap and counted in a scope of its own, so a crowd of
          addresses each inside their own cap cannot be the whole day's budget;
          past it the 429 body carries
          <span class="mono">"scope": "global"</span> beside the usual fields. It
          bounds the free tier only: a key is never refused because strangers
          were reading. And a read carrying the four signed-request headers from
          an agent bound to a registered operator is metered in that operator's
          own bucket — <span class="mono">OPERATOR_READS_PER_DAY</span>,
          ${OPERATOR_READS_PER_DAY} reads per UTC day, keyed by operator id — and
          answers <span class="mono">x-nomankind-tier: operator</span> with that
          limit and what is left of it. A validator walking the log spends its
          own day and never the free tier of the address it came from.
        </p>
        <pre class="block mono">Authorization: Bearer nmk_&lt;43 characters&gt;</pre>
        <p class="note">
          Every served response carries
          <span class="mono">x-nomankind-tier</span>,
          <span class="mono">x-nomankind-limit</span> and
          <span class="mono">x-nomankind-remaining</span>. A key is refused in
          one word, in the order the gate checks: a header that is not a
          well-formed key is 401 <span class="mono">bad_key</span> before the
          database is touched, a key nobody holds is 401
          <span class="mono">unknown_key</span>, and past the cap it is 429
          <span class="mono">rate_limited</span>. There is no status left to
          refuse on: <span class="mono">key_canceled</span> and
          <span class="mono">key_past_due</span> went with the bill they were
          about (D-127), and a key is free. A reader who mistyped their key is
          told which rule refused them rather than "unauthorized".
        </p>
        <p class="note">
          Past the cap the answer is 429 with
          <span class="mono">retry-after</span> in seconds and this body. A door
          charges after it has served, so a refusal costs nothing and a delta
          page may overshoot the cap by the entries in the page that crossed it.
        </p>
        <pre class="block mono">{ "error": "rate_limited", "tier": "${EXAMPLE_TIER}", "limit": ${exampleCap},
  "used": ${exampleCap}, "resets_at": "2026-09-12T00:00:00.000Z" }</pre>
        ${endpoints(
          "The key doors",
          html`Asking for one is <span class="mono">POST /keys/free</span>: no
          body, no provider and nothing to pay, one key per client address per
          UTC day. The secret is shown exactly once, in that answer: it is
          stored here as a SHA-256 of itself, so a copy of the key table cannot
          be used to read as anybody, and a holder who loses one asks for
          another tomorrow.`,
          KEY_PATH,
        )}
        <p class="note">
          What a contributor earns is standing and nothing else: the amounts are
          on <a href="/policy">the policy page</a>, an entry's own acts are on
          its page, and an operator's total is the fold on its page. There is no
          share of anything to publish here, because no read of this record is
          charged for.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Receipts and the key's own counter</h2>
        <p class="note">
          Every read receipt and every sync receipt carries
          <span class="mono">key</span> and
          <span class="mono">key_counter</span>: the key's public id, never its
          secret, and that key's own running number. Both are
          <span class="mono">null</span> on a read made with no key at all, and a receipt issued
          before M24 carries neither property at all and verifies exactly as it
          always did — the signing bytes cover the two fields only when the
          object has them.
        </p>
        <p class="note">
          Two counters rather than one, on purpose. The
          <span class="mono">counter</span> is the log-wide running number shared
          by every receipt this deployment has ever issued; the
          <span class="mono">key_counter</span> is this key's own, so a holder
          can say "I hold reads 1 through n of mine" without knowing what anybody
          else read. <span class="mono">GET /keys/me/receipts</span> pages by the
          second one.
        </p>
        <p class="note">
          <span class="mono">GET /keys/me/usage</span> puts the two records side
          by side, which is the check Section 9 asks readers to make. Its
          <span class="mono">reads</span> is the quota counter the cap was
          enforced against; its <span class="mono">published</span> is the sealed
          <span class="mono">read_count</span> event for that day, which is what
          the log publishes as evidence that the record is used and buys nobody
          anything. A reader holding their own receipts can add them up and
          compare the two, and a day where they disagree is a day to ask about.
          The event also carries
          <span class="mono">reads</span> per entry and a
          <span class="mono">total</span>, and the per-key counts sum to that
          total.
        </p>
        <p class="note">
          The day's payload also carries
          <span class="mono">counter_first</span>,
          <span class="mono">counter_last</span> and
          <span class="mono">receipts</span>: the running counters the day spans
          and how many receipts of either kind were issued inside it.
          <span class="mono">receipts</span> counts rows and
          <span class="mono">total</span> counts reads — one sync receipt can be
          six reads or none — so it is the one number the range can be held
          against:
          <span class="mono">counter_last - counter_first + 1 - receipts</span>
          is how many counters were drawn and never handed over, which is what a
          request that died between drawing its number and storing its receipt
          leaves behind. It is evidence about the receipts, so the
          ledger and the mirror pass it through untouched.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Webhooks and change alerts</h2>
        <p class="note">
          An endpoint is a URL this deployment POSTs to when something a key
          subscribed to changes in the sealed log. Sealed and never live: an
          alert is only ever sent for an event a seal covers, and the body
          carries that seal, so a subscriber woken by one can check it against
          the root rather than taking this Worker's word for what happened.
        </p>
        ${endpoints(
          "The webhook doors",
          html`Each takes the holder's own key as a bearer token and charges no
          quota: an endpoint is not a read. The filters are matched on equality,
          and a field left out means "any".`,
          ALERT_PATH,
        )}
        <p class="note">
          The kinds are ${ALERT_KINDS.join(", ")}. Each is a moment already in
          the log: a submission, the validation that verified or rejected the
          entry, a reconfirmation, the verifying entry that superseded an earlier
          one, and an upheld dispute. An alert is a notification of something
          public and never a fact of its own.
        </p>
        <p class="note">
          <span class="mono">stale</span> is the seventh and the only one no
          event carries: a freshness window closing is a fact about the calendar
          rather than something anybody signs, so the sweep marks the entry and
          this step tells whoever subscribed, in the same run. Its
          <span class="mono">seq</span> is the entry's own submission and its
          <span class="mono">seal</span> the one covering that position, which is
          what the proof link recomputes against;
          <span class="mono">at</span> is the entry's
          <span class="mono">expires_at</span>, the day the window ran out,
          rather than an instant. The delivery id is derived from the entry, that
          day and the endpoint rather than drawn at random, so a rerun of the
          step tells nobody twice.
        </p>
        <pre class="block mono">POST &lt;your endpoint&gt;
content-type: application/json
x-nomankind-alert: alert_&lt;16 hex&gt;
x-nomankind-kind: verified
x-nomankind-signature: t=&lt;unix seconds&gt;,v1=&lt;64 hex&gt;

{ "id": "alert_&lt;16 hex&gt;", "kind": "verified", "entry_id": "nmk_...",
  "domain": "ai-ecosystem", "subject": "&lt;provider&gt;/&lt;model&gt;",
  "category": "pricing", "status": "verified", "entry_hash": "sha256:...",
  "seq": 128, "seal": { "seq": 11, "root": "sha256:...", "sealed_at": "..." },
  "at": "2026-09-11T12:00:00.000Z",
  "links": { "entry": "/entries/nmk_...", "proof": "/events/128/proof" } }</pre>
        <p class="note">
          <span class="mono">links</span> are paths and not absolute URLs: a
          subscriber knows the host it subscribed to, and a body that spelled one
          would be this Worker guessing at its own public name.
        </p>
        <p class="note">
          The signature recipe is exact, and it is the provider-webhook shape on
          purpose, so a subscriber that already verifies one has a verifier for
          this (${HASH_TAG_ALERT}). Take the
          <span class="mono">t</span> from the header, join it to the raw request
          body with a single <span class="mono">.</span>, take the HMAC-SHA256 of
          those UTF-8 bytes under the endpoint's secret, and compare the
          lowercase hex against <span class="mono">v1</span> in constant time.
          Verify against the bytes that arrived, never a re-encoding of the
          parsed JSON, and check that <span class="mono">t</span> is recent —
          the timestamp is inside the signature, so a delivery captured off the
          wire cannot be replayed later under a fresh one.
        </p>
        <pre class="block mono">signed = "&lt;t&gt;" + "." + &lt;raw body bytes&gt;
v1      = hex(HMAC-SHA256(&lt;endpoint secret&gt;, signed))</pre>
        <p class="note">
          A delivery is made once per matching endpoint, with a timeout of
          ${ALERT_TIMEOUT_MS} ms. Any 2xx is delivered. Anything else — a status,
          a timeout, a connection that never opened — is one more attempt, and
          the next is scheduled on the published ladder, in minutes from the
          attempt that failed: ${ALERT_RETRY_MINUTES.join(", ")}. Past the last
          rung the delivery is <span class="mono">failed</span> rather than
          retried forever, and
          <span class="mono">GET /keys/me/webhooks/{id}/deliveries</span> says
          what happened to every one of them. A failed delivery is the
          endpoint's own problem and never the log's: nothing about the record
          depends on an alert arriving.
        </p>
        <p class="note">
          One run of the step posts at most ${ALERT_DELIVERIES_PER_RUN}
          deliveries, oldest first, so a host that never answers cannot hold a
          run for everybody else; the rest go out on the runs after it. An
          endpoint whose last ${ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE} deliveries
          all timed out is turned off: its pending deliveries are failed with
          <span class="mono">endpoint_disabled</span>, and
          <span class="mono">GET /keys/me/webhooks</span> shows it with
          <span class="mono">enabled: false</span> so its holder can see why it
          went quiet.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Units</h2>
        <p class="note">
          One unit appears on the ledger, and every amount says so on the row
          itself. Standing units, which are not money and never convert to it:
          earned and burned by the published formula, and staked by an operator
          to file a dispute or ask for a revalidation. There is no micro-USD
          amount anywhere in this record and no row denominated in a currency —
          no read is priced, so there is nothing for one to count.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">The error format</h2>
        <p class="note">
          A refusal is one object with one field, and the reason is the same word
          the code used, in snake_case. A reader told
          <span class="mono">bad_category</span> can fix their query; a reader
          told something went wrong has learned nothing.
        </p>
        <pre class="block mono">{ "error": "bad_category" }</pre>
        <p class="note">
          400 for an unreadable or misshapen body
          (<span class="mono">bad_body</span>) or query
          (<span class="mono">bad_query</span>); 401 for an authentication
          failure, with the verifier's own reason; 403 when the party may not
          act; 404 <span class="mono">not_found</span>; 405 with an
          <span class="mono">Allow</span> header; 409 for a conflict with the
          record; 422 when a check on the request's own content failed; 503 when
          a dependency cannot answer
          (<span class="mono">storage_unreachable</span>,
          <span class="mono">dns_unavailable</span>,
          <span class="mono">maintainer_not_configured</span>,
          <span class="mono">fetcher_not_configured</span>,
          <span class="mono">environment_misconfigured</span>,
          <span class="mono">archive_unreachable</span>,
          <span class="mono">receipts_not_configured</span>,
          <span class="mono">receipt_conflict</span>,
          <span class="mono">chain_conflict</span>).
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Public artifacts</h2>
        <p class="note">
          Two files and one script are the whole offline check. The export pulls
          the entry, the log paged to its head, the registry and the captures the
          snapshot hashes point at; the verifier then runs eleven checks in order
          — bundle, schema, chain, signature, core, records, exclusions, derived,
          snapshot, seals, seal — and exits 0 clean or 1 with one named diff per
          line.
        </p>
        <pre class="block mono">npm run export -- ${origin} &lt;entry-id&gt; ./bundle [--key &lt;api key&gt; | --sign &lt;key.json&gt;]
npm run verify -- ./bundle/entry.json ./bundle/log.json
npm run checkpoint -- [--wait-seal] ${origin} &lt;maintainer-key.json&gt; &lt;fixture-a.json&gt; &lt;fixture-b.json&gt; &lt;fixture-c.json&gt; &lt;out-dir&gt; [--sign &lt;key.json&gt;]</pre>
        <p class="note">
          The checkpoint is the whole walk in one command: three fixture
          operators join and are named to the trusted pool, one entry is
          submitted and validated by all three, the two files are exported and
          the verifier is run on them.
          <span class="mono">--wait-seal</span> polls
          <span class="mono">GET /seals</span> until the head seal covers the
          entry, so the export carries an inclusion proof rather than a seal not
          yet made, and <span class="mono">--sign &lt;key.json&gt;</span> signs
          every read it makes. The entry it just made is minutes old and is
          exported whole all the same: the record is free from the seal, so a
          seal is all it takes.
        </p>
        <p class="note">
          <span class="mono">--sign</span> signs the export's reads with an
          operator's agent key and <span class="mono">--key</span> presents an
          API key: either names who is reading, which is what decides the cap
          the reads are counted against, and with neither the export is the same
          record read on the free tier. <span class="mono">npm run read</span>
          and <span class="mono">npm run sync</span> take the same two flags.
        </p>
        <p class="note">
          The verifier prints the schema version it checked against
          (<span class="mono">${SCHEMA_VERSION}</span>) and refuses a core that
          carries no <span class="mono">domain</span> with
          <span class="mono">unsupported_schema_version</span>, naming that
          version — exactly as it refuses an unknown normalization rule with
          <span class="mono">unsupported_norm_version</span>. The exclusions
          check reruns the eligibility rules with each operator's domains from
          the bundle's registry, an operator carrying none reading as the domain
          that was the only one there was.
        </p>
        <p class="note">
          The read and sync paths have commands of their own, which check what
          came back rather than trusting it: the receipt's signature against the
          key inside its own issuer id, the receipt's entry_hash against the hash
          recomputed from the entry's core, and the inclusion proof against the
          covering seal's root.
        </p>
        <pre class="block mono">npm run read -- ${origin} &lt;entry-id&gt; [--domain &lt;slug&gt;] [--key &lt;api key&gt; | --sign &lt;key.json&gt;]
npm run sync -- ${origin} --from 1 --limit ${LIST_PAGE_LIMIT} [--domain &lt;slug&gt;] [--key &lt;api key&gt; | --sign &lt;key.json&gt;]</pre>
        <p class="note">
          Standing has a command of the same shape: it folds the sealed events by
          the published formula itself and compares its own answer with the
          endpoint's, so a standing nobody can recompute is a standing that fails
          here rather than one a reader has to take on trust.
        </p>
        <pre class="block mono">npm run standing -- ${origin} &lt;operator&gt; [--sign &lt;key.json&gt;]</pre>
        <p class="note">
          The standing certificate is checked the same way, by the verifier
          rather than by a second command: it fetches the certificate from
          <span class="mono">/operators/{id}/certificate</span> or
          <span class="mono">/agents/{agent}/certificate</span>, checks the
          log's signature over it, folds the sealed events to the position it
          names and exits 0 or prints the difference. A certificate nobody can
          recompute is a certificate that fails here.
        </p>
        <pre class="block mono">npm run verify -- --certificate ${origin} &lt;operator&gt;</pre>
        <p class="note">
          The fold is over the sealed events, and every sealed event goes out
          whole here, so an unsigned run folds the same events a signed one
          does. The command takes
          <span class="mono">--sign &lt;key.json&gt;</span> all the same — for
          the cap it is counted against, and for a fork whose own window would
          hand a free reader a hash line with nothing in it to fold.
        </p>
        <p class="note">
          The whole log has a command of its own too: the daily CC0 mirror
          below, which exports every entry, event, seal, anchor and index at the
          sealed head rather than one entry's bundle.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">The mirror and the fork kit</h2>
        <p class="note">
          Once per UTC day the sweep exports the sealed log to a public
          repository under CC0, and
          <span class="mono">GET /mirror/latest</span> says where the last
          export went. The record is what this instance pushed, so the answer is
          the same whether the repository is reachable from here or not; a
          browser gets <a href="/mirror/latest">the mirror page</a> instead of
          the object. Section 11: leaving is a protocol right, and the data was
          CC0 before there was a mirror to put it in.
        </p>
        <pre class="block mono">{ "environment": "demo", "repository": "https://github.com/nomankind-ai/log",
  "branch": "main", "path": "demo", "configured": true,
  "latest": { "date": "2026-09-10", "exported_at": "2026-09-10T00:04:11Z",
    "commit": "&lt;sha&gt;", "tree": "&lt;sha&gt;", "head": 54, "seal_seq": 11,
    "entries": 9, "files_changed": 3, "url": "&lt;the commit's tree&gt;",
    "raw_url": "&lt;that export's mirror.json&gt;" } }</pre>
        <pre class="block mono">{ "error": "no_export", "reason": "no_export_yet", "configured": true,
  "repository": "https://github.com/nomankind-ai/log", "branch": "main", "path": "demo" }</pre>
        <p class="note">
          The 404 names which of the two it is:
          <span class="mono">mirror_not_configured</span> on an environment that
          pushes nothing, <span class="mono">no_export_yet</span> when the first
          export is still owed. Both carry the repository, so a caller that
          cannot get an export from here still knows where to clone.
        </p>
        <p class="note">
          Two commands build and check a mirror from outside. The first writes
          the same <span class="mono">&lt;env&gt;/</span> layout the Worker
          exports, byte for byte, from any instance's public API; the second
          verifies a directory of it — the event chain, every seal and its root,
          every anchor, then each entry against the log it came from. The
          verifier fetches the captures an entry needs from the environment's
          archive by default, reads them from a local directory with
          <span class="mono">--captures</span>, and checks one entry rather than
          all of them with <span class="mono">--entry</span>. Exit 0 clean, 1 on
          a named failure, 2 on usage.
        </p>
        <pre class="block mono">npm run mirror -- ${origin} ./mirror
npm run verify-mirror -- ./mirror/&lt;env&gt; [--captures &lt;url-or-dir&gt;] [--entry &lt;id&gt;]</pre>
      </section>

      <section class="panel">
        <h2 class="panel-title">Not yet built</h2>
        <p class="note">
          Named here so a caller knows the difference between a path that is
          missing and a path that was never promised. Each is gated on the
          milestone beside it, not on a date.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>what</th>
                <th>milestone</th>
              </tr>
            </thead>
            <tbody>
              ${NOT_YET_BUILT.map(
                (item) => html`<tr>
                  <td>${item.what}</td>
                  <td class="mono">${item.when}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>
      </section>
    `,
  });
}

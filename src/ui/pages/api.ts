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
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_KINDS,
  ALERT_RETRY_MINUTES,
  ALERT_TIMEOUT_MS,
  CONTRIBUTOR_SHARE_FLOOR_PERCENT,
  CONTRIBUTOR_SHARE_PERCENT,
  DISPUTE_FILING_FEE_CENTS,
  FREE_TIER,
  LIST_PAGE_LIMIT,
  RATE_TIERS,
  READ_PRICE_MICROS_PER_READ,
  READ_SHARE_SPLIT,
  RELEASE_WINDOW_DAYS,
  SCHEMA_VERSION,
  STRIPE,
} from "../../policy.js";
import type { Safe } from "../html.js";
import { html, layout } from "../html.js";
import type { PageContext } from "../types.js";

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
    refusals: "503 when storage is unreachable; 405 with Allow: GET otherwise.",
  },
  {
    method: "GET",
    path: "/entries/{id}",
    parameters: "—",
    answers:
      "The derived entry. Status is recomputed from the log and is draft until validation closes it. The plain fetch, with no receipt. Before the release window is up, a reader with no key and no signature is answered { proof, release_date } instead of { entry }: every proof field as it stands, the content fields null, and the instant the rest of it opens.",
    refusals: "400 bad_id, 404 not_found.",
  },
  {
    method: "GET",
    path: "/captures/{hash}",
    parameters: "sha256: plus 64 hex",
    answers:
      "The raw archived bytes behind a snapshot_hash or a receipt_hash, whichever role froze them — snapshot, receipt, statement, or report:<seq> — with their stored media type and the archive address in x-nomankind-archive-hash. Served inert: attachment, nosniff, and a sandboxing CSP, because the bytes are a stranger's.",
    refusals:
      "400 bad_hash, 404 not_found; 403 unreleased, carrying release_date, for a capture every one of whose entries is still inside the release window — a key or an operator signature is served throughout; 403 undisclosed, carrying disclose_after, for a capture held only under the role disclosure while its domain's disclosure window is still open — a signed request from an agent bound to a registered operator is served throughout, because a validator has to reproduce the measurement.",
  },
  {
    method: "GET",
    path: "/captures/{hash}/sidecar",
    parameters: "—",
    answers:
      "The norm rule's record of the fetch: final_url, status, headers, fetched_at, fetcher. The same four roles — snapshot, receipt, statement, report:<seq> — answer here.",
    refusals:
      "400 bad_hash, 404 not_found; 403 unreleased and 403 undisclosed, as above.",
  },
  {
    method: "GET",
    path: "/events",
    parameters: `after=<seq>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "The log in seq order with its head, so a reader knows how far behind they are. Keyset paging, never offset, and the events go out exactly as stored, hash chain and all. An event whose release date has not arrived goes to a free reader as a hash line — seq, at, type, entry_id, prev_hash, hash, payload null and withheld true — so the chain still links and the seal's root is still over the same leaves.",
    refusals: "400 bad_query.",
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
    parameters: `after=<seal seq>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers: "The seal chain in seq order, with its head.",
    refusals: "400 bad_query.",
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
    parameters: `after=<date>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "The daily anchors over the previous day's seal roots, which is what makes the existence proof independent of the identity layer.",
    refusals: "400 bad_query.",
  },
  {
    method: "GET",
    path: "/anchors/{date}",
    parameters: "—",
    answers: "One UTC day's anchor.",
    refusals: "404 not_found.",
  },
  {
    method: "GET",
    path: "/read/{id}",
    parameters: "—",
    answers:
      "The frozen reader's single signed fact: entry, sidecar, seal, receipt. Only a verified entry is served with a receipt, stale or not.",
    refusals:
      "400 bad_id; 402 unreleased with release_date, to a reader with neither a key nor an operator signature, while the entry's content is inside the release window; 404 not_found; 409 entry_not_verified with status and superseded_by, which issues no receipt and moves no counter; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
  },
  {
    method: "GET",
    path: "/read",
    parameters:
      "subject=<s>, category=<c>, domain=<slug>, min_tier=stated|observed, min_source=official|recognized, max_age=<days>; entry_id=<id> as the query form of /read/{id}",
    answers:
      "The newest verified submission about one subject in one category that passes the reader's demands. domain narrows the answer to one registered domain; naming none leaves every domain's entries about that subject as candidates. The tier compared is the effective one the entry verified at, never the tier its core claimed; min_source is the lowest source class the reader will take, official above recognized above other, compared against the class the sidecar derived from the entry's own citation; and the age is whole UTC days against last_confirmed.",
    refusals:
      "400 unknown_parameter, bad_entry_id, mixed_query, missing_subject, missing_category, bad_category, unknown_domain, bad_min_tier, bad_min_source, bad_max_age; 402 unreleased with release_date, as above; 404 no_entry; 409 entry_not_verified; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
  },
  {
    method: "GET",
    path: "/sync",
    parameters:
      `from=<position>, limit=<1..${LIST_PAGE_LIMIT}>, flatten=true|false, min_tier=stated|observed, min_source=official|recognized, domain=<slug>`,
    answers:
      "The delta stream: from, head, sealed_head, as_of, seals, events, receipt. Strictly by sealed position and never past the last seal, because an unsealed event has no inclusion proof. Each item is seq, kind (event, unlearn, entry), event, proof, entry, sidecar, entry_hash, and entries are re-derived at the sealed head so two learners resuming from the same position are handed the same page forever. flatten drops superseded entries; min_tier drops entries below the demand; min_source drops entries whose citation's class is below the demand; domain drops the entry and unlearn items of every other domain, which still advance the head, and never drops an event item; none of the four can touch an unlearn. A reader with no key and no signature is served to the released head rather than the sealed one: head names that boundary and sealed_head still reports the true head, so the gap is visible rather than silent, and a range with nothing released in it is an empty page with head null.",
    refusals:
      "400 unknown_parameter, bad_from, bad_limit, bad_flatten, bad_min_tier, bad_min_source, unknown_domain, and a parameter given twice is its own refusal; 500 bad_proof; 503 receipts_not_configured, receipt_conflict, storage_unreachable.",
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
      "category=<c>, status=<s>, domain=<slug>, source=official|recognized|other, tier=stated|observed, fresh=fresh|stale, before=<position>",
    answers:
      "The browsing listing, newest sealed position first, one keyset page. A chip group carries each filter, domain and source among them, and every chip and the pager keep the rest of the query as it stands. The n-of-m line counts by status and domain, which are indexed columns; category, source, tier and freshness narrow the page rather than the total, and the line says so. HTML only: the JSON twin of a listing is GET /events.",
    refusals:
      "400 unknown_parameter, repeated_parameter, bad_category, bad_status, unknown_domain, bad_source, bad_tier, bad_fresh, bad_before. An empty value (?category=) is a refusal and not an absence.",
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
    path: "/status",
    parameters: "—",
    answers:
      "Every stage of the pipeline as the last sweep left it: as_of, environment, counters (last sweep, stages, sealed head, witnessed), stages — thirteen of them, each with stage, state (ok, attention, failing, idle), last, rule and evidence — exercised (the five stages that run only when someone asks), and thresholds (STATUS_ATTENTION_AFTER_INTERVALS, STATUS_FAILING_AFTER_MINUTES). Nothing is probed to answer it: every reading is a published rule applied to the log and to the report the sweep stored at the end of its last run, so the answer cannot be warmed by asking for it. A browser gets the same object as the status page.",
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
      "The pipeline explained in ten panels, each carrying this environment's own newest record for that stage — the newest entry and its capture, the trusted pool, the newest decision, seal and anchor, yesterday's read count, standing and the ledger, the newest attestation, the daily export, and the paid tiers — and the policy names that stage runs under. HTML only: it is a page about the log and not a view of it, so it has no JSON twin.",
    refusals: "—",
  },
  {
    method: "GET",
    path: "/standing",
    parameters: "—",
    answers:
      "Every operator's standing, recomputed over the sealed log rather than read from a column: position, formula (the policy names the fold applies, in the order it applies them), operators (each with operator, earned, burned, locked, standing, available, counts, position).",
    refusals: "405 with Allow: GET.",
  },
  {
    method: "GET",
    path: "/operators/{id}/standing",
    parameters: "—",
    answers:
      "One operator's standing, recomputed the same way: operator, position, earned, burned, locked, standing, available, counts, formula, and stored — the cached { standing, seq } off the operator row, or null when the formula has never been run for it. stored is the number to check the recomputation against; the log is what decides if the two disagree.",
    refusals: "404 not_found.",
  },
  {
    method: "GET",
    path: "/operators/{id}/ledger",
    parameters: "—",
    answers:
      `One operator's money: operator, balance (accrued, held, released, clawed_back, paid, carried_forward, all in micro-USD), and rows — the newest ${LIST_PAGE_LIMIT} ledger rows, newest first, each with id, kind, entry_id, operator, role, date, reads, unit, amount, available_at, seq, at, ref. A read_share row's ref carries price_micros_per_read, share_percent, stale, the entry's evidence tier as tier, and on a slot holder's row measured — whether that holder's own signed record carried a passing measurement, which is what decides between the two validator rates. A dispute_reward row's ref carries the stake record it was written as, the ids of the clawbacks its amount was read off as clawbacks, and their sum as clawed_back.`,
    refusals: "404 not_found.",
  },
  {
    method: "GET",
    path: "/ledger",
    parameters: "—",
    answers:
      "The money side of the log as a whole: reconciliations (each day's published read count against what the ledger accrued for it), payouts (what has left, under the provider's own reference), and policy — READ_PRICE_MICROS_PER_READ, PAYOUT_MINIMUM_MICROS, PAYOUT_CYCLE, HOLDBACK_DAYS, read from the same module the policy page reads.",
    refusals: "405 with Allow: GET.",
  },
];

const WRITE_PATH: readonly Endpoint[] = [
  {
    method: "POST",
    path: "/operators",
    parameters:
      "operator, domain (the registered domain this operator joins first, and the one its attestation is signed for), attestation { version, domain, signed_at, signature }, payout { reference }; no other keys",
    answers:
      "201 with the operator record: id, maintainer, provider, registered_seq, details (registered_by, attestation, trusted, trusted_seq, named_by, payout_status), agents, domains. The events operator_registered and agent_bound are appended atomically with the rows.",
    refusals:
      "400 bad body shape; 401 authentication; 422 bad_domain, unregistered_domain, provider_operator (decided against that domain's excluded parties), missing_attestation, bad_attestation, attestation_domain_mismatch; 409 operator_exists, agent_bound; 422 dns_no_record, dns_mismatch and 503 dns_unavailable; 422 payout_not_verified and 503 payout_unavailable.",
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
      "One operator record with its bound agents and its domains — every registered domain this operator is attested in, registration's first and then each join, with the attestation signed for it.",
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
      "400 bad_id, bad_body; 401 the request verdicts, in the order the verifier applies them; 404 not_found; 403 agent_mismatch; then 422 unregistered_operator, unregistered_domain, 403 excluded_party, 409 already_joined, 422 missing_attestation, bad_attestation, attestation_domain_mismatch.",
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
    parameters: "operator; signed by the maintainer's agent",
    answers:
      "The maintainer's one-time naming of a founding trusted operator, as the public event operator_trusted. 200 with the record.",
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
      "400 bad_body; 401 authentication then bad_signature; 422 bad_id, bad_norm_version, missing_domain (a seventeen-key core sealed under schema v0.6: a new entry names the domain its author signs), unregistered_domain, category_not_in_domain, bad_subject_version (the category's subject carries a version as its third segment in this domain, and the entry's has none), unknown_authority (the subject's primary party has no row in this domain's authorities table and the category needs an official source), source_not_official (the category has an authoritative source by nature and the citation is not it), bad_submitted_at, author_operator_mismatch, provider_statement_mismatch, no_predicate and 403 author_mismatch; 422 self_supersession, target_missing, subject_mismatch, category_mismatch; 409 duplicate_entry; 503 fetcher_not_configured; 422 duplicate_claim (the answer carries duplicate_of: the same domain, subject, category and normalized value is already live as a draft or a verified entry and this entry does not supersede it; refused before anything is fetched or written, on the dispute door as well as this one), snapshot_mismatch, unsupported_citation, fetch_failed, too_many_redirects, timeout, too_large, bad_status, invalid_json, needs_javascript, missing_receipt, receipt_mismatch; 422 disclosure_missing (a redaction placeholder with no pointer to its original, or a disclosure body on an entry whose domain and category publish no disclosure rule) and disclosure_mismatch (the disclosed value does not hash to the placeholder), both before anything is written; 422 schema_invalid; 409 chain_moved.",
  },
  {
    method: "POST",
    path: "/entries/{id}/validate",
    parameters:
      "record (exactly the schema's approvers item) and signature (nomankind-record-v1, kind validation); signed by the record's own agent",
    answers:
      "201 with the derived entry. The validator's own snapshot hash is the point: each fetches the live source itself, so the capture taken at submission is never the only witness. Status moves only through derivation. A validator that judges the entry a duplicate of one it does not supersede rejects in the published form, the reason duplicate_claim:<entry id>, which is taken as any other reason is: nothing new is signed, and the entry page and the confidence inputs read the id back out of it.",
    refusals:
      "400 bad_id, bad_body; 401 authentication; 404 not_found; 403 agent_mismatch; 409 entry_closed; 422 bad_signed_at, bad_record_signature, unregistered_agent, operator_mismatch, unregistered_operator, submitter_agent, submitter_operator, original_signer (the entry is a correction filed as a dispute, and no operator that signed the original may judge it), maintainer_operator, provider_operator, subject_authority (the operator's own domain is, or is under, an official host of the entry's subject's authority row, in a domain whose registry says a subject excludes its own authority), operator_not_in_domain (the operator is not attested in the entry's own domain), missing_snapshot_hash, missing_reason, duplicate_operator, assigned_random_without_assignment, assignment_without_assigned_random, missing_test_accepted, unexpected_test_accepted, misplaced_measurement, bad_measurement, missing_observation, schema_invalid.",
  },
  {
    method: "POST",
    path: "/entries/{id}/reconfirm",
    parameters:
      "record (exactly the schema's reconfirmations item) and signature (nomankind-record-v1, kind reconfirmation); signed by the record's own agent",
    answers:
      "201 with the derived entry: last_confirmed advanced to the record's date, the window reopened, a read-share slot seated or rotated, and the accrued bounty written to the ledger in the same batch as the event that earned it.",
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
      "400 bad_id, bad_body; 401 the request verdicts, in the order the verifier applies them; 404 not_found; 403 author_mismatch; then every POST /entries refusal on the correction entry itself, 409 duplicate_entry among them; 422 entry_not_verified, not_correction, missing_citation, subject_mismatch, self_dispute; 409 dispute_open; 422 unknown_authority and source_not_official read against the entry being challenged (a correction's own category is never official-required, so the gate here is the target's domain and category: overturning a pricing, limit, deprecation, release or outage claim takes a citation of the target subject's own official source), bad_report_link, bad_revalidation_link, insufficient_standing (a registered operator's available standing, less what its open stakes already hold, is below the published dispute stake), schema_invalid.",
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
      "400 bad_id, bad_body; 401 the request verdicts; 404 not_found; 422 no_open_request, not_assigned; 403 agent_mismatch; 422 bad_signed_at, bad_record_signature, schema_invalid.",
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
 * The paid loop's own doors (Section 9), in the order a caller meets them: what
 * the tiers are, buy one, claim the key it paid for, then the three reads a
 * holder makes about their own key.
 *
 * Every one of them is JSON with `cache-control: no-store`, and the three
 * `/keys/me` doors take the key as a bearer token. They are account doors and
 * not reading doors, so they charge no quota and a key whose bill has not
 * cleared can still reach them — a door that refused `key_past_due` here would
 * lock a customer out of the page that fixes it.
 */
const KEY_PATH: readonly Endpoint[] = [
  {
    method: "GET",
    path: "/keys/tiers",
    parameters: "—",
    answers:
      "What is on sale: tiers (each with name, reads_per_day and key), price_micros_per_read, contributor_share_percent — an object keyed by evidence tier, stated and observed, because the split is published per tier and the observed one is larger — and contributor_share_floor_percent, the floor both of them sit at or above. Free and unauthenticated, which is the whole point of it.",
    refusals: "405 with Allow: GET.",
  },
  {
    method: "POST",
    path: "/keys/checkout",
    parameters: "tier, email?",
    answers:
      "200 with { session, url }: the provider's hosted checkout to send a buyer to. The success URL comes back to /keys/claim with the session id.",
    refusals:
      "400 bad_body; 422 free_tier_needs_no_key, unknown_tier; 503 payments_unavailable when this deployment takes no money at all; 502 provider_error, bad_response, network with the provider's status and error code — never its message, and never a request header.",
  },
  {
    method: "GET",
    path: "/keys/claim",
    parameters: "session=<checkout session id>",
    answers:
      "201 with { key, id, tier, status, customer, created_at }. The key is shown exactly once and is stored here only as a hash, so there is no door that can show it again. A browser — which is where the provider's success redirect lands a person — gets the same fields as a page, with that warning on it.",
    refusals:
      "400 missing_session; 404 unknown_session; 402 not_paid; 422 unknown_tier; 409 already_claimed, which is the unique index and not a check that hoped nobody raced: one checkout session mints one key however many times its success URL is opened.",
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
      "{ key, days: [{ date, reads, published }] }, over a window of thirty days by default and ninety at most. reads is this Worker's own counter, which is what the cap was enforced against; published is what the sealed read_count event for that day says the key read, which is what the ledger priced — { reads, seq }, or null while no event has been published for that day. A day where the two disagree is a day to ask about.",
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
  {
    method: "POST",
    path: "/keys/me/portal",
    parameters: "—",
    answers:
      "200 with { url }: the provider's own billing page for the customer behind this key. nomankind holds no card, no address and no invoice; it hands out the link.",
    refusals:
      "401 as above; 503 payments_unavailable; 502 provider_error, bad_response, network.",
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
    refusals: `401 missing_key, bad_key, unknown_key; 402 key_canceled; 400 bad_body; 422 unknown_kind; 422 bad_url (https only, a hostname with a dot, no credentials, no localhost); 422 unknown_domain; 409 endpoint_limit past ${ALERT_ENDPOINTS_PER_KEY} live endpoints.`,
  },
  {
    method: "GET",
    path: "/keys/me/webhooks",
    parameters: "—",
    answers:
      "{ key, endpoints: [{ id, url, filter, created_at }] } — this key's live endpoints, and never a secret.",
    refusals: "401 and 402 as above.",
  },
  {
    method: "DELETE",
    path: "/keys/me/webhooks/{id}",
    parameters: "—",
    answers:
      "204 and no body. The endpoint is disabled rather than deleted, so the deliveries that name it keep naming something, and the slot it held is free.",
    refusals:
      "401 and 402 as above; 404 not_found, which is also the answer for an endpoint that exists under another key — a holder learning that an id is somebody else's has learned something about another customer.",
  },
  {
    method: "GET",
    path: "/keys/me/webhooks/{id}/deliveries",
    parameters: `after=<delivery id>, limit=<1..${LIST_PAGE_LIMIT}>`,
    answers:
      "{ key, endpoint, deliveries: [{ id, event_seq, kind, entry_id, status, attempts, next_at, delivered_at, last_status, last_error, created_at, body }] }, newest first. The bodies are whole because they are public; the endpoint's secret is in no delivery record at all.",
    refusals: "401 and 402 as above; 404 not_found; 400 bad_limit.",
  },
];

const NOT_YET_BUILT: readonly { readonly what: string; readonly when: string }[] =
  [
    {
      what: "Production submission, genesis, and the payout provider",
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
        Reads need no key at low volume, forever: the free tier is served to
        anybody, and a key buys a higher rate, receipts that name it, and change
        alerts. Writes are signed requests from a 1F916 agent key:
        there are no passwords and no sessions anywhere in this system. Every
        response is JSON with <span class="mono">cache-control: no-store</span>,
        and every read that serves a verified entry returns a signed receipt.
        These are the endpoints that exist today; the ones a later milestone
        brings are named at the bottom, without paths, because a documented path
        that answers 404 is worse than no documentation.
      </p>

      ${endpoints(
        "Read path",
        html`No authentication. A shared path answers HTML to a browser and JSON
        to everyone else, so <span class="mono">Accept: application/json</span>
        is what a machine sends.`,
        READ_PATH,
      )}

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
          <span class="mono">npm run keygen -- &lt;path&gt;</span>, which writes a
          0600 JSON file holding agent_id, public_key, private_key_pkcs8 and
          created_at. An entry's own <span class="mono">signature</span> field is
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
        passes, and status is never sent in: it is recomputed from the log.`,
        WRITE_PATH,
      )}

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
          Filing takes a stake, so burner keys cannot dispute for free: a
          registered operator stakes standing and a bare key a refundable filing
          fee, both published on the policy page. A stake, a refund and a
          forfeit are ledger records in the unit they were put up in, and the
          amounts on them are the placeholders the policy page publishes.
        </p>
        <p class="note">
          The reward an upheld challenge is paid is priced from the entry it
          overturned: the row is written at the outcome with no amount, and the
          ledger step prices it at exactly what the clawbacks came to — the
          shares the entry's signers had accrued inside the holdback and lost —
          in micro-USD, released when the last of those shares would have been.
          An entry that had nothing still held prices the reward at zero. A
          bare-key challenger's row names the key and no operator: the reward
          accrues to the key and holds, and turning it into dollars means
          verifying as an operator, whenever they choose. A revalidation request
          has no reward of its own; a check that turns up a citation is upgraded
          into a dispute, and the reward on that is the one above.
        </p>
      </section>

      ${endpoints(
        "Attestation and confidence",
        html`One attestation is three signed writes — the request that draws the
        probes, the model's answers, each scorer's signed score — and then a
        record anyone can read. Every one of them answers
        <span class="mono">cache-control: no-store</span>, a wrong method gets
        405 with an <span class="mono">Allow</span> header, and a storage
        failure is 503 <span class="mono">storage_unreachable</span>.`,
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
        <pre class="block mono">npm run attest -- request &lt;model-key.json&gt; ${origin}
npm run attest -- answer &lt;model-key.json&gt; ${origin} &lt;attestation-id&gt; [--answers &lt;file.json&gt;] [--drift]
npm run attest -- score &lt;scorer-key.json&gt; ${origin} &lt;attestation-id&gt;</pre>
        <p class="note">
          The submit command gained the other half of an observed entry:
          <span class="mono">--receipt</span> takes the receipt artifact, checks
          its shape, hashes it, fills the observation's
          <span class="mono">receipt_hash</span> when the fields file left it
          null, and sends the artifact as the body's
          <span class="mono">receipt</span>.
        </p>
        <pre class="block mono">npm run submit -- &lt;key.json&gt; ${origin} &lt;fields.json&gt; --receipt &lt;receipt.json&gt;</pre>
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
        <h2 class="panel-title">Paid access: tiers and keys</h2>
        <p class="note">
          The release window (decision D-100) is what a key buys first. An
          entry's content — its claim, what it changed from and to, when it took
          effect, its citation, its evidence, its observation, and the words each
          validator wrote — is served to a key or to a signed request from an
          agent bound to a registered operator from the first minute, and to
          everybody else ${RELEASE_WINDOW_DAYS} days after the seal that covers
          its submission, when it becomes public and CC0 and enters the daily
          mirror. The proof is never withheld from anyone: every event's seq,
          instant, type, entry id and hash, every seal, anchor and operator
          record, and each entry's id, domain, subject, category, status,
          effective tier, entry hash, seal, signers and hashes are public and
          free today, as they always were. Inside the window a free read of an
          entry is 402 <span class="mono">unreleased</span> with its
          <span class="mono">release_date</span>, a free sync stops at the
          released head, and a free
          <span class="mono">GET /entries/{id}</span> answers
          <span class="mono">{ proof, release_date }</span>. The window is one
          number in <a href="/policy">policy</a> and one rule everywhere: an
          event's release date is its covering seal's
          <span class="mono">sealed_at</span> plus that many days, an entry's is
          its submission event's, and an unsealed event is not released at all.
        </p>
        <p class="note">
          Section 9: "The log is free to read at low volume, forever. Revenue
          comes from high-rate API access, structured feeds and webhooks, change
          alerts." A tier is a daily cap and nothing else. The free tier carries
          no key and is counted per client; the paid tiers carry a key and are
          counted per key. Every paid read is priced at
          ${READ_PRICE_MICROS_PER_READ} micro-USD whichever tier bought it, so a
          tier buys throughput and never a discount.
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
          it, counted against the address it came from. A paid read sends the key
          as a bearer token, on <span class="mono">/read</span>,
          <span class="mono">/sync</span> and the account doors below.
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
          <span class="mono">unknown_key</span>, a canceled subscription is 402
          <span class="mono">key_canceled</span> and one whose bill did not clear
          is 402 <span class="mono">key_past_due</span>. A reader who mistyped
          their key is told which rule refused them rather than "unauthorized".
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
          html`Buying one is the provider's hosted checkout and the claim that
          follows it. The key is shown exactly once, at the claim: it is stored
          here as a SHA-256 of the secret, so a copy of the key table cannot be
          used to read as anybody, and a reader who loses a key cancels and buys
          another.`,
          KEY_PATH,
        )}
        <p class="note">
          The claim answers JSON to an agent and a page to a browser, because the
          provider's success redirect lands a person on it and a person owed a
          credential should not be shown a JSON blob they may close. The JSON is
          the contract; the page is the same fields, through the same layout
          every other page uses, with the one warning that matters — the key is
          on that page and nowhere else, ever again.
        </p>
        <p class="note">
          The contributor pool's share of this revenue is published per evidence
          tier: ${CONTRIBUTOR_SHARE_PERCENT.stated} percent of a read of a stated
          entry and ${CONTRIBUTOR_SHARE_PERCENT.observed} percent of a read of an
          observed one, each at or above the published floor of
          ${CONTRIBUTOR_SHARE_FLOOR_PERCENT} percent. All three are on
          <a href="/policy">the policy page</a>, and the share is a floor that
          only rises.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Receipts for paid reads</h2>
        <p class="note">
          Every read receipt and every sync receipt now carries
          <span class="mono">key</span> and
          <span class="mono">key_counter</span>: the key's public id, never its
          secret, and that key's own running number. Both are
          <span class="mono">null</span> on a free read, and a receipt issued
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
          <span class="mono">read_count</span> event for that day, whose
          <span class="mono">paid.keys[&lt;key id&gt;]</span> is what the ledger
          priced and what the provider's meter was told. A reader holding their
          own receipts can add them up and compare all three, and a day where
          they disagree is a day to ask about. The event's
          <span class="mono">paid</span> block also carries
          <span class="mono">reads</span> per entry and a
          <span class="mono">total</span>, and the per-key counts sum to that
          total.
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
      </section>

      <section class="panel">
        <h2 class="panel-title">The provider's webhook</h2>
        <p class="note">
          <span class="mono">POST ${STRIPE.webhook_path}</span> is the one door
          the payment provider knocks on, and it is not for callers. It trusts
          nothing it is sent until the signature over the raw body verifies
          against this deployment's own signing secret and the message's own
          timestamp is inside ${STRIPE.webhook_tolerance_seconds} seconds of now;
          a forged or stale one is 400
          <span class="mono">bad_signature</span>. A deployment that takes no
          money, which is production's state until M25, answers 503
          <span class="mono">payments_unavailable</span> and goes on serving the
          free tier.
        </p>
        <p class="note">
          It may change exactly one column: a key's status. A message it has
          already acted on answers 200
          <span class="mono">{ received: true, outcome: "duplicate" }</span>,
          because a provider retries and a retried cancellation must not cancel a
          key that was paid for again in between. Everything it understood is
          recorded — applied, ignored, or about a subscription nobody here holds
          a key for — and everything is 200 after that, because a provider told
          anything else retries a message that was already handled.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">What the ledger pays, per evidence tier</h2>
        <p class="note">
          Section 9: "observed entries take a larger read share than stated ones,
          by published policy, so the operators who measure are paid more than
          the operators who copy". The split is published per tier and read off
          <a href="/policy">the policy page</a>: on a stated entry
          ${READ_SHARE_SPLIT.stated.submitter} percent of the read goes to the
          submitter's operator and ${READ_SHARE_SPLIT.stated.validator} percent
          to each read-share slot holder; on an observed entry
          ${READ_SHARE_SPLIT.observed.submitter} percent and
          ${READ_SHARE_SPLIT.observed.validator} percent. The tier that prices a read is
          the one fixed when the entry verified, so a reconfirmation never
          reprices the entry into another tier.
        </p>
        <p class="note">
          The observed validator rate is earned rather than inherited. A slot
          holder takes it only when its own signed record — the approval or the
          reconfirmation that seated it — carries a passing measurement under the
          n-of-k rule; a validator that accepted the test without running it is
          paid at the stated rate on the same entry, and a slot whose seating
          event cannot be read is priced at the stated rate rather than an
          invented observed one. Every row says which it was: the ref on a
          read_share row carries <span class="mono">tier</span> and, on a slot
          holder's row, <span class="mono">measured</span>, beside the
          <span class="mono">share_percent</span> actually applied.
        </p>
        <p class="note">
          The difference between the two splits comes out of nomankind's share
          and never out of the reader's: a paid read is
          ${READ_PRICE_MICROS_PER_READ} micro-USD whatever tier the entry is, so
          no reader pays more for an observed fact than for a stated one.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Units</h2>
        <p class="note">
          Three units appear on the ledger, and every amount says which one it is
          in on the row itself, so nothing has to be inferred from its size.
        </p>
        <dl class="dl">
          <dt class="mono">micros</dt>
          <dd>
            Micro-USD, a millionth of a dollar: 1,000,000 to the dollar. Every
            read share, bounty, clawback, dispute reward and payout is an
            integer count of them,
            because one read's submitter share is a fraction of a cent and a
            ledger that rounded to cents would pay the long tail nothing. The
            price per read is on the policy page and nowhere else.
          </dd>
          <dt class="mono">standing</dt>
          <dd>
            Standing units, which are not money and never convert to it. Earned
            and burned by the published formula, and staked by a registered
            operator to file a dispute or ask for a revalidation.
          </dd>
          <dt class="mono">cents</dt>
          <dd>
            Whole US cents, on one row only: the refundable filing fee a bare key
            puts up instead of standing, ${DISPUTE_FILING_FEE_CENTS} cents, so a
            burner key cannot dispute for free.
          </dd>
        </dl>
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
          <span class="mono">payout_unavailable</span>,
          <span class="mono">maintainer_not_configured</span>,
          <span class="mono">fetcher_not_configured</span>,
          <span class="mono">archive_unreachable</span>,
          <span class="mono">receipts_not_configured</span>,
          <span class="mono">receipt_conflict</span>).
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
npm run verify -- ./bundle/entry.json ./bundle/log.json</pre>
        <p class="note">
          <span class="mono">--sign</span> signs the export's reads with an
          operator's agent key and <span class="mono">--key</span> presents an
          API key: either reaches content that is still inside the release
          window, and with neither the export writes the released view and says
          so. <span class="mono">npm run read</span> and
          <span class="mono">npm run sync</span> take the same two flags.
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
        <pre class="block mono">npm run standing -- ${origin} &lt;operator&gt;</pre>
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

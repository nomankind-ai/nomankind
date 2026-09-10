/**
 * Every policy number in the whitepaper lives here and nowhere else.
 * Each constant names the whitepaper section it comes from.
 * A few numbers are not in the paper at all: the paper names the rule and
 * leaves the amount to published policy. Those are the maintainer's own
 * choices, each said to be so in its comment and each carrying the decision
 * that set it, and they move only by a later decision.
 */

/**
 * Lifecycle of an entry. Once the trusted pool holds ten operators, three
 * approvals verify and one validator is drawn at random; below ten, two
 * approvals verify and no draw is made.
 */
export const TRUSTED_POOL_SWITCH = 10;

/** Lifecycle of an entry. Until the pool holds ten operators, two approvals verify. */
export const APPROVALS_TO_VERIFY_SMALL_POOL = 2;

/** Lifecycle of an entry. Once the pool holds ten operators, three approvals verify. */
export const APPROVALS_TO_VERIFY_LARGE_POOL = 3;

/** Lifecycle of an entry. Two rejections mark the entry rejected, at either pool size. */
export const REJECTIONS_TO_REJECT = 2;

/** Lifecycle of an entry. Verification needs three verified operators outside the submitter's own. */
export const VERIFICATION_MIN_OUTSIDE_OPERATORS = 3;

/**
 * Lifecycle of an entry. An assigned validator has seventy-two hours to
 * respond; a miss costs standing and the next beacon round draws a replacement.
 */
export const ASSIGNMENT_WINDOW_HOURS = 72;

/**
 * The evidence rule (n-of-k). A validator's reproduction runs the frozen prompt
 * n times; the claim holds when the predicate held in at least k of them.
 */
export const REPRODUCTION_RUNS = 10;
export const REPRODUCTION_HOLDS = 8;

/** Every category in the schema's category enum. */
export type Category =
  | "release"
  | "deprecation"
  | "pricing"
  | "limit"
  | "behavior"
  | "outage"
  | "misbehavior"
  | "correction";

/**
 * A registered domain's published tables: everything about a domain that is not
 * the mechanism.
 *
 * Whitepaper Section 3, "The log": the mechanism does not care about the domain.
 * A fact is a claim, a citation, a snapshot hash and a set of signatures, and
 * none of those is AI-shaped. What is domain-shaped is the tables -- which
 * categories exist, how long each stays fresh, which carry a transcript, who is
 * too close to judge, how a subject is named -- so those live here, per domain,
 * and nothing category-shaped is global any more.
 *
 * The prose form of every field is schema/nomankind-domain-registry-v1.md; this
 * is the same content in the one place code may read it from.
 */
export interface DomainPolicy {
  readonly name: string;
  readonly categories: readonly Category[];
  readonly staleness_window_days: Readonly<Record<Category, number | null>>;
  readonly transcript_categories: readonly Category[];
  readonly excluded_parties: {
    readonly rule: string;
    readonly domains: readonly string[];
  };
  readonly attestation: { readonly version: string; readonly text: string };
  readonly subject_convention: string;
}

/**
 * Every registered domain, keyed by slug. The key set is exactly the schema's
 * `domain` enum, and test/domains.test.ts pins that the two never drift.
 *
 * ai-ecosystem is the only domain at launch: the field exists so the log can
 * hold a second one without a fork, not because a second one is planned.
 *
 * The windows are the whitepaper's ("Freshness and decay": volatile categories
 * carry a staleness window from the last-confirmed date -- ninety days for
 * pricing and rate limits, thirty for behavior; event categories carry none,
 * because once they happened they stay true). The excluded-party list and the
 * attestation sentence are Section 10's, published policy and not the paper's
 * own list: both move only by a later decision.
 */
export const DOMAINS: Readonly<Record<string, DomainPolicy>> = Object.freeze({
  "ai-ecosystem": Object.freeze({
    name: "The AI ecosystem",
    categories: Object.freeze([
      "release",
      "deprecation",
      "pricing",
      "limit",
      "behavior",
      "outage",
      "misbehavior",
      "correction",
    ] as const),
    staleness_window_days: Object.freeze({
      release: null,
      deprecation: null,
      pricing: 90,
      limit: 90,
      behavior: 30,
      outage: null,
      misbehavior: null,
      correction: null,
    }),
    transcript_categories: Object.freeze(["behavior", "misbehavior"] as const),
    excluded_parties: Object.freeze({
      rule:
        "No lab or model provider may be a maintainer, funder, or trusted operator.",
      domains: Object.freeze([
        "openai.com",
        "anthropic.com",
        "google.com",
        "deepmind.google",
        "meta.com",
        "microsoft.com",
        "x.ai",
        "mistral.ai",
        "cohere.com",
        "amazon.com",
        "deepseek.com",
        "alibaba.com",
        "alibabacloud.com",
        "moonshot.cn",
        "01.ai",
        "ai21.com",
        "nvidia.com",
        "ibm.com",
        "baidu.com",
        "tencent.com",
        "bytedance.com",
        "zhipuai.cn",
      ]),
    }),
    attestation: Object.freeze({
      version: "nomankind-independence-v1",
      text: "No model provider holds control of, or a beneficial stake in, this operator.",
    }),
    subject_convention: "<provider>/<model or product>",
  }),
});

/** Every registered slug, in the order DOMAINS declares them. */
export const DOMAIN_SLUGS: readonly string[] = Object.freeze(
  Object.keys(DOMAINS),
);

/**
 * The domain a record that names none belongs to.
 *
 * Not a default in the sense of a fallback anybody may lean on: it is what a
 * legacy v0.6 core, and a registration sealed before v0.7, actually meant --
 * ai-ecosystem was the only domain there was. New records name their domain.
 */
export const DEFAULT_DOMAIN = "ai-ecosystem";

/** Whether a slug names a registered domain. */
export function isRegisteredDomain(slug: unknown): slug is string {
  return (
    typeof slug === "string" &&
    Object.prototype.hasOwnProperty.call(DOMAINS, slug)
  );
}

/**
 * One domain's tables. Throws on an unregistered slug rather than returning a
 * blank: a caller that has not checked `isRegisteredDomain` first is asking a
 * question about a domain that does not exist, and answering it with defaults
 * would apply the wrong windows under a name nobody registered.
 */
export function domainPolicy(domain: string): DomainPolicy {
  const policy = isRegisteredDomain(domain) ? DOMAINS[domain] : undefined;
  if (policy === undefined) {
    throw new Error(`domainPolicy: unregistered domain: ${String(domain)}`);
  }
  return policy;
}

/**
 * The staleness window for one category of one domain, in days, or null when
 * the category carries none. A category the domain does not admit carries no
 * window either: there is no such fact to go stale, and neither does anything
 * in a domain nobody registered.
 *
 * The three accessors below answer rather than throw, unlike `domainPolicy`:
 * each is a question about one category, and the honest answer for a domain or
 * a category that does not exist is no window, no transcript, no such category
 * -- which is what keeps a stranger's malformed file answerable with a verdict
 * instead of a stack trace (src/verify.ts).
 */
export function stalenessWindowDays(
  domain: string,
  category: unknown,
): number | null {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return null;
  const table = domainPolicy(domain).staleness_window_days as Readonly<
    Record<string, number | null>
  >;
  return table[category] ?? null;
}

/** Whether this category of this domain carries its evidence as a transcript. */
export function isTranscriptCategory(
  domain: string,
  category: unknown,
): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  return (domainPolicy(domain).transcript_categories as readonly string[]).includes(
    category,
  );
}

/** Whether this category is one the domain admits at all. */
export function isDomainCategory(domain: string, category: unknown): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  return (domainPolicy(domain).categories as readonly string[]).includes(category);
}

/**
 * The registrable domains of the parties excluded from this record's domain --
 * the AI ecosystem's model providers, and whatever a later domain publishes.
 *
 * The neutral rule (Section 10, read without the labs): no party whose products
 * or conduct the record checks may control, fund, or validate it in that domain.
 * The list is the cheap first check and never the whole enforcement; the signed
 * attestation is what binds.
 */
export function excludedPartyDomains(domain: string): readonly string[] {
  return domainPolicy(domain).excluded_parties.domains;
}

/** The independence attestation of one domain: the version, and the sentence. */
export function attestationFor(
  domain: string,
): { readonly version: string; readonly text: string } {
  return domainPolicy(domain).attestation;
}

/**
 * Incentives / Money. Accrued fees are held for thirty days before payout so an
 * upheld dispute can claw them back before they leave.
 */
export const HOLDBACK_DAYS = 30;

/**
 * Incentives / Money. Of paid-read revenue, fifteen percent goes to the
 * submitter and five to each of the three validators.
 */
export const READ_SHARE_SPLIT: Readonly<{ submitter: number; validator: number }> =
  Object.freeze({ submitter: 15, validator: 5 });

/**
 * The log / Incentives. An entry's read share is always split among exactly one
 * submitter and three current read-share slot holders.
 */
export const SLOT_COUNT = 3;

/**
 * Incentives / Money. Thirty percent of paid-read revenue goes to the
 * contributor pool at launch: 15 + 3 x 5.
 */
export const CONTRIBUTOR_SHARE_PERCENT = 30;

/**
 * Lifecycle of an entry (Seal). Witnesses countersign the registry head at an
 * initial interval of five minutes set by policy.
 */
export const SEAL_INTERVAL_MINUTES = 5;

/**
 * The sweep's own cadence: how often src/worker/sweep.ts runs, in minutes. The
 * same five minutes the cron trigger in wrangler.jsonc names, held here because
 * the Sweeper Durable Object (src/worker/sweeper.ts) sets its alarm from it and
 * a timer whose interval was written down twice is a timer that drifts.
 *
 * Not a whitepaper number, and not a rule of any kind: it is operational. It
 * says how often the Worker looks, never how long an assigned validator has
 * (ASSIGNMENT_WINDOW_HOURS) or when a draw is legitimate (src/assign.ts).
 * Moving it changes only how promptly the log catches up.
 */
export const SWEEP_INTERVAL_MINUTES = 5;

/**
 * The log (failure reports). Reports from this many distinct verified
 * operators auto-open a revalidation. The paper says the threshold is
 * published policy but states no number, so three is the maintainer's own
 * choice: low enough that a real regression reopens quickly, and it rises by
 * decision if floods appear.
 *
 * Not a whitepaper number. The maintainer's published policy (decision D-032,
 * 2026-09-07), recorded in the Notion Decisions database; it moves only by a
 * later decision.
 */
export const FAILURE_REPORT_THRESHOLD = 3;

/**
 * Lifecycle of an entry, "Dispute": "Filing takes a stake, so burner keys cannot
 * dispute for free. A verified operator stakes standing, a bare key stakes a
 * refundable filing fee, and the amounts are published policy."
 *
 * The paper names the rule and states no amount, so both amounts below are the
 * maintainer's own placeholders (decision D-064): stakes are ledger rows and
 * nothing else until M21 builds the money side, so no money moves on either of
 * them. The maintainer sets the real amounts, and they move only by a later
 * decision.
 *
 * `DISPUTE_STAKE_STANDING` is an operator's stake in standing units;
 * `DISPUTE_FILING_FEE_CENTS` is a bare key's refundable fee in cents.
 */
export const DISPUTE_STAKE_STANDING = 10;
export const DISPUTE_FILING_FEE_CENTS = 1000;

/**
 * Lifecycle of an entry, "Revalidate": "Any operator can also request
 * revalidation of an entry inside its window by staking a small amount of
 * standing ... and requests are capped per operator per window."
 *
 * Neither the amount nor the cap is in the paper, so both are the maintainer's
 * own placeholders (decision D-064), in standing units and in requests
 * respectively. A stake is a ledger row and nothing else until M21; no money
 * moves before then. The cap counts per operator, per entry, per freshness
 * window: one operator may ask for one check of one entry per window, which is
 * what keeps a request from becoming a way to keep an entry permanently under
 * review. Both move only by a later decision.
 */
export const REVALIDATION_REQUEST_STAKE_STANDING = 1;
export const REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW = 1;

/**
 * Lifecycle of an entry (Seal), and "Limitations" ("The identity layer is
 * young"). How many distinct pinned operators must have countersigned the
 * registry head, verifiably, before a seal counts as witnessed.
 *
 * Not a whitepaper number. The paper fixes the *bar* — published keys, no two
 * witnesses under common control, nomankind ineligible — and states no count,
 * so the count is the maintainer's own initial policy: one, because the
 * founding registry's directory is small and a bar nothing can clear is a bar
 * that gets quietly ignored. It rises by a later decision as the witness set
 * grows, and never by an edit anywhere but this file.
 */
export const WITNESSES_REQUIRED = 1;

/**
 * Lifecycle of an entry (Seal). The most events one seal may cover. A run
 * longer than this is not dropped: the seal takes the first thousand and the
 * next run continues from where it stopped, so the chain stays contiguous.
 *
 * Not a whitepaper number, and not a rule: it is operational, a ceiling on the
 * work one sweep does and on the size of one Merkle batch. The maintainer's own
 * choice; it moves only by a later decision.
 */
export const SEAL_MAX_EVENTS = 1000;

/**
 * Lifecycle of an entry (Seal). How many bytes of a witness's published
 * countersignature file are read, from the end: 256 kibibytes.
 *
 * The files are append-only JSONL, already hundreds of kilobytes and growing,
 * and only the newest usable line is ever wanted — so the reader asks for a
 * tail rather than the whole file. Not a whitepaper number; operational, and it
 * moves only by a later decision.
 */
export const WITNESS_FILE_TAIL_BYTES = 262144;

/**
 * Lifecycle of an entry (Seal): "the seal hash is sealed as a memory
 * fingerprint into nomankind's own citizen log at the founding 1F916 registry".
 *
 * Which registry that is, its Ed25519 public key (unpadded base64url, the D-014
 * encoding), which of its logs carries identity events, and the label every
 * nomankind seal is filed under. Pinned here rather than in the adapter for the
 * same reason BEACON is: an offline reader has to be able to recheck a
 * countersignature years later against the same key the collector used.
 *
 * Not a whitepaper number. The maintainer's published choice; it moves only by
 * a later decision.
 */
export const REGISTRY: Readonly<{
  origin: string;
  public_key: string;
  log: string;
  seal_label: string;
}> = Object.freeze({
  origin: "https://1f916.ai",
  public_key: "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw",
  log: "identity_events",
  seal_label: "nomankind-seal",
});

/**
 * "Limitations" ("The identity layer is young"): the witnesses whose
 * countersignatures nomankind will count, pinned by operator and by key.
 *
 * The registry's own directory is a pointer and never an endorsement, so the
 * set is pinned here and the collector only ever re-checks the directory to see
 * whether a pinned row still says what it said. A row that moved is dropped for
 * that run: code never follows a moved key, and the orchestrator re-pins by
 * decision. Three operators, none of them nomankind's, so no two accepted
 * countersignatures can be under common control.
 *
 * Not a whitepaper list. Decision D-054, re-checked before M25; it moves only
 * by a later decision.
 */
export const WITNESS_PIN: readonly Readonly<{
  id: number;
  operator: string;
  public_key: string;
  url: string;
}>[] = Object.freeze([
  Object.freeze({
    id: 6,
    operator: "commonwealth",
    public_key: "nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M",
    url: "https://raw.githubusercontent.com/GavinOB/1f916-witness/main/witness-state/countersignatures.jsonl",
  }),
  Object.freeze({
    id: 7,
    operator: "head-of-experiments",
    public_key: "BwLjer1DCxSErLiPIOG3fu0vlgmQierr2BC7f2k4TeI",
    url: "https://raw.githubusercontent.com/0xRyanC/1f916-witness/main/countersignatures.jsonl",
  }),
  Object.freeze({
    id: 8,
    operator: "liveness",
    public_key: "NgHCVDwGuYeHX0qnuOKBgufNwgu804x1ZDyTU63sJwE",
    url: "https://raw.githubusercontent.com/wyeshunf/1f916-witness/main/witness-state/countersignatures.jsonl",
  }),
]);

/**
 * Lifecycle of an entry (Seal): "anchoring each day's batch hash into an
 * external timestamping chain makes the existence proof independent of the
 * identity layer". The OpenTimestamps calendars the day's hash is offered to,
 * in order; the first that answers is the one recorded.
 *
 * Not a whitepaper list. The paper names an external chain and stops there, so
 * which calendars is the maintainer's published choice; it moves only by a
 * later decision.
 */
export const ANCHOR_CALENDARS: readonly string[] = Object.freeze([
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
]);

/**
 * Hash versioning. The normalization rule version in force at submission; every
 * hash on an entry is computed under it. norm-v1.2 is in force for entries
 * submitted on or after 2026-09-08; entries submitted before that keep the
 * version they were signed under.
 */
export const NORM_VERSION = "norm-v1.2";

/**
 * The entry schema version in force: what a new entry is written and checked
 * against, and what the offline verifier names when it meets a core sealed under
 * an older one. v0.7 is the version that carries `domain` in the signed core
 * (schema/nomankind-entry-schema.json, decision D-071).
 *
 * A format version and not a policy number, held here for the same reason
 * NORM_VERSION is: one place says which rules are in force, and every reader
 * asks that place rather than a string spelt out beside a check.
 */
export const SCHEMA_VERSION = "v0.7";

/**
 * Snapshot normalization, step 1 (Fetch). One HTTP GET follows at most five
 * redirects; a chain longer than that is not pinned, it is chased.
 */
export const FETCH_MAX_REDIRECTS = 5;

/**
 * Snapshot normalization, step 1 (Fetch). The capture times out after thirty
 * seconds, stated there as "Timeout thirty seconds" and held here in
 * milliseconds because that is the unit every timer takes.
 */
export const FETCH_TIMEOUT_MS = 30000;

/**
 * Snapshot normalization, step 2 (Archive). The largest response body the
 * Worker will archive, in bytes: ten mebibytes. A citation is a document, and a
 * body past this size is a download, not a page to pin.
 *
 * Not a whitepaper number, and not in the norm rule either: the rule says the
 * raw body is archived and leaves the ceiling to published policy. This is the
 * maintainer's own choice and it moves only by a later decision.
 */
export const CAPTURE_MAX_BYTES = 10485760;

/**
 * Request authentication (decision D-014). A signed write request carries a
 * timestamp; a request whose timestamp is more than this far from the
 * verifier's clock, in either direction, is rejected.
 *
 * Not a whitepaper number. The paper fixes the signing scheme, not the
 * operational window; this is the orchestrator's choice, recorded in the Notion
 * Decisions database.
 */
export const REQUEST_CLOCK_SKEW_SECONDS = 300;

/**
 * Request authentication (decision D-014). A verifier remembers a spent nonce
 * at least this long. Twice the skew window, so no request that the clock-skew
 * rule still accepts can be replayed after its nonce has been forgotten.
 *
 * Not a whitepaper number. The orchestrator's operational choice, recorded in
 * the Notion Decisions database.
 */
export const NONCE_RETENTION_SECONDS = 600;

/**
 * Lifecycle of an entry, Validate: "The draw is a deterministic function of a
 * public randomness beacon's output (a beacon like drand [5]), the entry id,
 * and a published snapshot of the eligible pool."
 *
 * The paper names drand and stops there, so which drand chain the draw reads is
 * the maintainer's published choice, exactly as a domain's excluded-party
 * list is (`DOMAINS`, above): it
 * moves only by a later decision, and it is pinned here rather than in the
 * adapter so an offline reader can recompute a draw years later from the same
 * chain the draw used. `chain_hash` is quicknet's, `genesis_time` its first
 * round's UNIX second and `period_seconds` its round interval, which together
 * give every round its time without asking the network.
 *
 * Not a whitepaper number. The maintainer's published policy; it moves only by
 * a later decision.
 */
export const BEACON: Readonly<{
  endpoint: string;
  beacon_id: string;
  chain_hash: string;
  genesis_time: number;
  period_seconds: number;
}> = Object.freeze({
  endpoint: "https://api.drand.sh",
  beacon_id: "quicknet",
  chain_hash:
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  genesis_time: 1692803367,
  period_seconds: 3,
});

/**
 * The training path, "Drift attestation": "A probe set is drawn from verified,
 * observed, fresh entries by public randomness ... That set size is published
 * policy, and the observed tier will be thin at genesis (Section 12)."
 *
 * `PROBE_SET_SIZE` is that published size: ten probes when the log holds at
 * least ten entries to draw from. `PROBE_SET_MIN_CANDIDATES` is the floor below
 * which no attestation is drawn at all, and it is one rather than ten precisely
 * because the paper says the observed tier is thin at genesis: between the floor
 * and the size every candidate is drawn, so an attestation over three probes is
 * a small attestation and never a refused one. A score over one probe says
 * little, which is what the probe count published beside every score is for.
 *
 * Not whitepaper numbers. The paper names the rule and says the size is
 * published policy, so both are the maintainer's own placeholders (M22); they
 * move only by a later decision, and never by an edit anywhere but this file.
 */
export const PROBE_SET_SIZE = 10;
export const PROBE_SET_MIN_CANDIDATES = 1;

/**
 * The training path, "Drift attestation": "Three operators from the trusted
 * pool, none under the model's operator, score its answers against the log and
 * sign the result."
 *
 * Three is the paper's own number, so this one is not a placeholder: it is the
 * sentence, held here rather than written into src/attest.ts, because a count of
 * signers is the same kind of thing as APPROVALS_TO_VERIFY_LARGE_POOL and lives
 * where every other one does.
 */
export const ATTESTATION_SCORERS = 3;

/**
 * How long an attestation stays open: from the request to the deadline for the
 * model's answers and for the scorers' scores.
 *
 * Not a whitepaper number. The paper says an attestation happens and never how
 * long it may hang open, so the window is the maintainer's own placeholder
 * (M22), seventy-two hours because that is what ASSIGNMENT_WINDOW_HOURS already
 * gives a drawn validator and a second, different window for the same kind of
 * drawn work would be a rule nobody could remember. It is its own constant all
 * the same: the two move independently, and an attestation window that borrowed
 * the assignment's number would silently move with it.
 */
export const ATTESTATION_WINDOW_HOURS = 72;

/**
 * The most records one list request returns. The first page-size number in the
 * system, so it lives here with every other published amount rather than
 * beside the query that uses it; src/storage/repository.ts holds no default
 * page size and every listing there takes the caller's explicit limit.
 *
 * Not a whitepaper number. The maintainer's published policy; it moves only by
 * a later decision.
 */
export const LIST_PAGE_LIMIT = 100;

/**
 * How many entries the home page's "latest sealed entries" row shows. A page
 * size, so it lives here beside LIST_PAGE_LIMIT rather than inside the page that
 * renders it: src/ui/ holds no numbers of this kind and src/storage/ holds no
 * default limit at all.
 *
 * Not a whitepaper number, and not a rule: it is presentation. The maintainer's
 * published policy; it moves only by a later decision.
 */
export const HOME_LATEST_ENTRIES = 10;

/** How many seals the landing page's live seal-chain band shows. A page size, so it lives here beside HOME_LATEST_ENTRIES. */
export const LANDING_BAND_SEALS = 12;

/**
 * Incentives / Standing: "Standing is the non-monetary record of being right. It
 * is earned by approved submissions, completed validations (assigned work
 * weighted highest), rejections that hold, and upheld challenges ... Amounts and
 * rates are published policy."
 *
 * The paper names every move and states no amount, so all six below are the
 * maintainer's own placeholders, in standing units. Assigned work weighs highest
 * because the paper says so — "that is what makes an assignment on an entry
 * nobody will read worth doing" — and a rejection that holds counts the same as
 * an approval, which is why one number covers both decisions.
 *
 * Not whitepaper numbers. The maintainer's published policy (M21); they move
 * only by a later decision, and never by an edit anywhere but this file.
 */
export const STANDING_VALIDATION_VOLUNTEERED = 1;
export const STANDING_VALIDATION_ASSIGNED = 3;
export const STANDING_SUBMISSION_VERIFIED = 2;
export const STANDING_DISPUTE_UPHELD = 5;
export const STANDING_OVERTURNED_SIGNER = 5;
export const STANDING_ASSIGNMENT_MISSED = 2;

/**
 * Incentives / Standing: standing "gates everything discretionary, from entry to
 * and stay in the trusted pool". Two numbers rather than one, because a single
 * threshold would flap: an operator sitting exactly at the bar would be trusted
 * and untrusted by turns as one burn landed and one validation followed.
 *
 * `STANDING_TRUSTED_ENTRY` is what a registered, non-maintainer, non-provider
 * operator must reach to be trusted; `STANDING_TRUSTED_STAY` is what a trusted
 * operator must stay at or above to keep it. Not whitepaper numbers: the
 * maintainer's published policy, moving only by a later decision.
 */
export const STANDING_TRUSTED_ENTRY = 10;
export const STANDING_TRUSTED_STAY = 0;

/**
 * Incentives / Standing: standing "decays when the work it came from stops being
 * read or was never used ... Decay is paused until the paid loop starts (below),
 * since before then there is nothing for it to decay against."
 *
 * So there is no rate here, and there must not be: the paper publishes the pause
 * and not a number, and inventing a rate now would be publishing a policy nobody
 * decided. The flag is what src/standing.ts reads, and the day the paid loop
 * starts it moves by a decision, together with the rate that replaces it.
 */
export const STANDING_DECAY_PAUSED = true;

/**
 * Incentives / Money: "At $0.50 per thousand paid reads, an entry read ten
 * thousand times in a month earns its submitter 75 cents and each validator 25."
 *
 * That is the paper's own worked example, so the price is the paper's: fifty
 * cents per thousand reads is five hundred micro-USD per read. Micro-USD (a
 * millionth of a dollar) is the unit every read-revenue amount in the ledger is
 * counted in, because a single read's share is 75 micros — a fraction of a cent,
 * and a ledger that rounded it to cents would pay nobody anything.
 *
 * A price, not a rule, and the paper says the unit economics depend on API
 * pricing that does not exist yet: the maintainer's published policy, moving
 * only by a later decision.
 */
export const READ_PRICE_MICROS_PER_READ = 500;

/**
 * Incentives / Money, as amended by decision D-053: payouts are batched per
 * operator on a monthly cycle, and an operator whose released accruals sit below
 * the published minimum is not paid that cycle — the amount carries forward to
 * the next one.
 *
 * Five dollars, in the micro-USD the ledger counts in. Neither number is in the
 * paper: the paper says payouts happen and leaves the cadence and the floor to
 * published policy, so both are the maintainer's own (D-053) and move only by a
 * later decision. The minimum exists because a transfer costs more than a
 * long-tail entry earns in a month, and a payout that cost more than it paid
 * would take the difference out of the contributor pool.
 */
export const PAYOUT_MINIMUM_MICROS = 5_000_000;

/**
 * The payout cycle (D-053): one UTC calendar month. A name and not a number,
 * held here with every other published amount because it is the same kind of
 * thing — a published choice the ledger reads and nobody else may restate.
 */
export const PAYOUT_CYCLE = "monthly";

/** Every policy number, collected and frozen. */
export const POLICY = Object.freeze({
  TRUSTED_POOL_SWITCH,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  APPROVALS_TO_VERIFY_LARGE_POOL,
  REJECTIONS_TO_REJECT,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  ASSIGNMENT_WINDOW_HOURS,
  REPRODUCTION_RUNS,
  REPRODUCTION_HOLDS,
  DOMAINS,
  HOLDBACK_DAYS,
  READ_SHARE_SPLIT,
  SLOT_COUNT,
  CONTRIBUTOR_SHARE_PERCENT,
  SEAL_INTERVAL_MINUTES,
  SWEEP_INTERVAL_MINUTES,
  WITNESSES_REQUIRED,
  SEAL_MAX_EVENTS,
  WITNESS_FILE_TAIL_BYTES,
  REGISTRY,
  WITNESS_PIN,
  ANCHOR_CALENDARS,
  FAILURE_REPORT_THRESHOLD,
  DISPUTE_STAKE_STANDING,
  DISPUTE_FILING_FEE_CENTS,
  REVALIDATION_REQUEST_STAKE_STANDING,
  REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
  STANDING_VALIDATION_VOLUNTEERED,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_TRUSTED_ENTRY,
  STANDING_TRUSTED_STAY,
  STANDING_DECAY_PAUSED,
  READ_PRICE_MICROS_PER_READ,
  PAYOUT_MINIMUM_MICROS,
  PAYOUT_CYCLE,
  NORM_VERSION,
  SCHEMA_VERSION,
  FETCH_MAX_REDIRECTS,
  FETCH_TIMEOUT_MS,
  CAPTURE_MAX_BYTES,
  REQUEST_CLOCK_SKEW_SECONDS,
  NONCE_RETENTION_SECONDS,
  PROBE_SET_SIZE,
  PROBE_SET_MIN_CANDIDATES,
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
  LIST_PAGE_LIMIT,
  HOME_LATEST_ENTRIES,
  LANDING_BAND_SEALS,
  BEACON,
});

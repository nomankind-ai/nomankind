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
 * Freshness and decay. Volatile categories carry a staleness window from the
 * last-confirmed date: ninety days for pricing and rate limits, thirty for
 * behavior. Event categories (release, deprecation, outage, misbehavior,
 * correction) carry no window, because once they happened they stay true.
 */
export const STALENESS_WINDOW_DAYS: Readonly<Record<Category, number | null>> =
  Object.freeze({
    release: null,
    deprecation: null,
    pricing: 90,
    limit: 90,
    behavior: 30,
    outage: null,
    misbehavior: null,
    correction: null,
  });

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
 * Governance and legal posture. "No lab or model provider may be a maintainer,
 * funder, or trusted operator": this is the maintainer's published list of
 * model providers' registrable domains, and a registration on one of them, or
 * on any subdomain of one, is refused at the door.
 *
 * Not a whitepaper list. The paper names the exclusion and says it is enforced
 * honestly rather than airtightly, so the list is the maintainer's published
 * policy and moves only by a later decision. It is the cheap first check and
 * never the whole enforcement: the signed independence attestation and the
 * public record behind it are what actually bind.
 */
export const MODEL_PROVIDER_DOMAINS: readonly string[] = Object.freeze([
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
]);

/**
 * Lifecycle of an entry, Validate: "The draw is a deterministic function of a
 * public randomness beacon's output (a beacon like drand [5]), the entry id,
 * and a published snapshot of the eligible pool."
 *
 * The paper names drand and stops there, so which drand chain the draw reads is
 * the maintainer's published choice, exactly as MODEL_PROVIDER_DOMAINS is: it
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
  STALENESS_WINDOW_DAYS,
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
  NORM_VERSION,
  FETCH_MAX_REDIRECTS,
  FETCH_TIMEOUT_MS,
  CAPTURE_MAX_BYTES,
  REQUEST_CLOCK_SKEW_SECONDS,
  NONCE_RETENTION_SECONDS,
  MODEL_PROVIDER_DOMAINS,
  LIST_PAGE_LIMIT,
  HOME_LATEST_ENTRIES,
  LANDING_BAND_SEALS,
  BEACON,
});

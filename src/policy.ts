/**
 * Every policy number in the whitepaper lives here and nowhere else.
 * Each constant names the whitepaper section it comes from.
 * Numbers marked [NEEDS DATA] in the paper are still numbers here; the paper's
 * unpublished amounts are exported as explicit null placeholders, never guessed.
 */

/**
 * Lifecycle of an entry. Once the trusted pool holds ten operators, three
 * approvals verify and one validator is drawn at random; below ten, two
 * approvals verify and no draw is made.
 */
export const TRUSTED_POOL_SWITCH = 10;

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
 * The log (failure reports). The paper says a published threshold of reports
 * from distinct verified operators auto-opens a revalidation, with no number
 * given. Placeholder, not yet published.
 */
export const FAILURE_REPORT_THRESHOLD: number | null = null;

/**
 * Incentives / Money. The maintainer pays a flat seed fee per completed
 * validation at a published rate and under a published cap, neither of which
 * the paper states. Placeholder, not yet published.
 */
export const SEED_FEE_RATE: number | null = null;
/** Placeholder, not yet published. See SEED_FEE_RATE. */
export const SEED_FEE_CAP: number | null = null;

/**
 * Hash versioning. The normalization rule version in force at submission; every
 * hash on an entry is computed under it.
 */
export const NORM_VERSION = "norm-v1.1";

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

/** Every policy number, collected and frozen. */
export const POLICY = Object.freeze({
  TRUSTED_POOL_SWITCH,
  ASSIGNMENT_WINDOW_HOURS,
  REPRODUCTION_RUNS,
  REPRODUCTION_HOLDS,
  STALENESS_WINDOW_DAYS,
  HOLDBACK_DAYS,
  READ_SHARE_SPLIT,
  SLOT_COUNT,
  CONTRIBUTOR_SHARE_PERCENT,
  SEAL_INTERVAL_MINUTES,
  FAILURE_REPORT_THRESHOLD,
  SEED_FEE_RATE,
  SEED_FEE_CAP,
  NORM_VERSION,
  REQUEST_CLOCK_SKEW_SECONDS,
  NONCE_RETENTION_SECONDS,
});

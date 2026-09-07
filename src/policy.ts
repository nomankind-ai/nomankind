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
 * Incentives / Money. The maintainer's flat seed fee per accepted validation,
 * in whole cents: paid once per entry per operator, for an approve or a
 * reject alike, so the fee buys the work of validating rather than the
 * verdict.
 *
 * Not a whitepaper number. The paper says the maintainer seeds fees at a
 * published rate under a published cap but states neither. This is the
 * maintainer's published policy (decision D-032, 2026-09-07), recorded in the
 * Notion Decisions database; it moves only by a later decision.
 *
 * Integer cents, never a float: money is counted, not approximated.
 */
export const SEED_FEE_RATE_CENTS = 100;

/**
 * Incentives / Money. The ceiling on seed fees one operator can accrue in a
 * calendar month, in whole cents. Caps the maintainer's exposure and blunts
 * the incentive to farm validations.
 *
 * Not a whitepaper number. The maintainer's published policy (decision D-032,
 * 2026-09-07). See SEED_FEE_RATE_CENTS.
 */
export const SEED_FEE_CAP_CENTS = 10000;

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
  SEED_FEE_RATE_CENTS,
  SEED_FEE_CAP_CENTS,
  NORM_VERSION,
  REQUEST_CLOCK_SKEW_SECONDS,
  NONCE_RETENTION_SECONDS,
});

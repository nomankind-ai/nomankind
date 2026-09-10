/**
 * What each page is handed.
 *
 * The browsing UI is server-rendered from the Worker and every page is a pure
 * function of one of these shapes: the route reads storage, the page renders,
 * and nothing in src/ui/ touches a database, a clock or the network. That is
 * what makes a page testable without a Worker and what keeps derivation out of
 * the view — every field below was computed by src/derive.ts or src/seal.ts and
 * is carried here verbatim.
 *
 * Whitepaper Section 3, The log: "every field a reader needs to check an entry
 * offline is visible on the entry". So the entry page is handed the entry
 * itself, its sidecar, its events and its seal rather than a summary of them,
 * and the field names below are the schema's own — never an alias.
 */

import type { DerivedAttestation } from "../attest.js";
import type { ConfidenceInputs } from "../confidence.js";
import type { Sidecar } from "../derive.js";
import type { Event } from "../events.js";
import type { LedgerBalance, LedgerRow } from "../ledger.js";
import type { Seal } from "../seal.js";
import type { StakeRecord } from "../stake.js";

/**
 * The three things every page knows about the request it is answering, and
 * nothing else. No bindings, no database, no clock: a page that could reach any
 * of those would stop being a function of its data.
 *
 * `environment` is the `ENVIRONMENT` var (local, demo, production) shown in the
 * header badge; `path` is the request's pathname, which decides which nav item
 * is active; `origin` is the scheme and host the page was reached at, for the
 * absolute URLs an example command has to spell out.
 */
export interface PageContext {
  readonly environment: string;
  readonly path: string;
  readonly origin: string;
}

/**
 * One row of a dense entry table. Every value is already derived and already
 * formatted-agnostic: the row carries the field, the page decides how it looks.
 */
export interface EntryRow {
  id: string;
  /** The entry's sealed position in the log: its `entry_submitted` seq. */
  position: number;
  /** Whether a seal covers that position yet. */
  sealed: boolean;
  status: string;
  subject: string;
  category: string;
  claim: string;
  /** The sidecar's `effective_tier`, null while the entry is draft or rejected. */
  tier: string | null;
  last_confirmed: string;
  expires_at: string | null;
  stale: boolean;
}

/** The counters across the top of the home page. */
export interface HomeCounters {
  verified: number;
  stale: number;
  /** Operators in the trusted pool (Section 5). */
  trusted: number;
  /** The newest seal's last covered event seq, null before anything is sealed. */
  sealedHead: number | null;
  sealedAt: string | null;
  /** Countersignatures on that seal, null when there is no seal. */
  witnesses: number | null;
  seals: number;
}

export interface HomeData {
  counters: HomeCounters;
  latest: EntryRow[];
  /**
   * The registered domain `?domain=` narrowed the page to, or null for every
   * domain (decision D-071). The counters and the latest rows were gathered
   * under it; the page says which, because a filtered four is otherwise
   * indistinguishable from the whole log's four.
   */
  domain: string | null;
}

/** What an entries listing was narrowed by; null in a field means "not asked". */
export interface EntriesFilter {
  category: string | null;
  status: string | null;
  /**
   * The registered domain the listing was narrowed to, null for all of them
   * (decision D-071). A field of the filter rather than a parameter beside it,
   * so the chip group, the "all" links and the keyset pager all carry it the
   * same way every other filter is carried.
   */
  domain: string | null;
  tier: string | null;
  fresh: "fresh" | "stale" | null;
}

export interface EntriesData {
  filter: EntriesFilter;
  rows: EntryRow[];
  /** How many entries match the filter, ignoring the page. */
  total: number;
  /** The keyset cursor for the next page: `?before=<position>`, null at the end. */
  nextBefore: number | null;
}

/**
 * One decision on an entry, exactly as the schema's approvers[] item carries it,
 * plus the two things the log knows and the record does not: whether the
 * deciding operator is trusted, and where the decision sits in the log.
 */
export interface ApproverRow {
  agent: string;
  operator: string;
  operatorTrusted: boolean | null;
  decision: string;
  reason: string | null;
  snapshot_hash: string | null;
  assigned_random: boolean;
  test_accepted: boolean | null;
  reproduction: unknown;
  observation: unknown;
  signed_at: string;
  /** seq of the `validation` event, null when it is not known. */
  seq: number | null;
}

export interface EntryData {
  /** The entry exactly as derivation left it; the schema's field names. */
  entry: Record<string, unknown>;
  sidecar: Sidecar;
  /** The entry's sealed position: its `entry_submitted` seq. */
  position: number;
  events: Event[];
  /** The seal covering the entry's submission, null until one does. */
  seal: Seal | null;
  approvers: ApproverRow[];
  reconfirmations: Array<{
    record: Record<string, unknown>;
    seq: number | null;
    operatorTrusted: boolean | null;
  }>;
  /** Entry ids declaring they supersede this one. */
  superseders: string[];
  /** The window from policy for this entry's category, null for an event category. */
  stalenessWindowDays: number | null;
  /**
   * The stake rows this entry's disputes and revalidations produced, oldest
   * first, exactly as `ledgerRowsForEntry` read them. Every row is derivable
   * from the log, and an amount is null while M21 has not priced it.
   */
  ledger: StakeRecord[];
  /**
   * The entry's money rows, oldest first, exactly as `entryLedgerRows` read them
   * and filtered to the kinds that carry read revenue: `read_share`,
   * `bounty_pool`, `bounty_accrual`, `clawback`. The stake rows are above, under
   * `ledger`, because they carry standing and a fee rather than micros.
   */
  readShares: LedgerRow[];
  /**
   * The entry this one was filed as a correction of (Section 6, Dispute), null
   * when it is not a correction. The other direction of `overturned_by`.
   */
  disputeOf: string | null;
  /**
   * Every published input to the confidence field, exactly as
   * `confidenceInputs` computed them at the route's injected clock — the same
   * object `GET /entries/{id}/confidence-inputs` serves.
   *
   * Section 8, The confidence field: the field is null until conf-v1 is
   * published "and every input to it is exposed raw, so a learner can build its
   * own weighting from the receipts". So the inputs are carried whole rather
   * than picked over here, and the page prints the object's own field names.
   * The only clock-dependent one is `age_ratio`, which is why the route
   * computes it and this page never does.
   */
  confidenceInputs: ConfidenceInputs;
}

/**
 * One attestation as a table row (Section 8, Drift attestation).
 *
 * A `Pick` of the derived record rather than a shape of its own: every name
 * comes from `DerivedAttestation`, so the columns cannot drift from the fold
 * that produced them, and a `DerivedAttestation` is itself a row. What is left
 * out — the probes, the scorers, the answers hash — is on the attestation's own
 * JSON endpoint, because a directory row is a way in and not a substitute.
 */
export type AttestationRow = Pick<
  DerivedAttestation,
  "id" | "model" | "status" | "score" | "date" | "probe_hash" | "probe_count"
>;

/**
 * A standing the formula already returned, and the log position it returned it
 * at (Section 9). Carried verbatim from the operators row: the column is a cache
 * of a published computation and never an authority, so the position travels
 * with the number or a reader has nothing to recompute against.
 */
export interface StandingCache {
  standing: number;
  /** The `position` src/standing.ts folded to when this number was computed. */
  seq: number;
}

export interface OperatorRow {
  id: string;
  maintainer: boolean;
  provider: boolean;
  trusted: boolean;
  /** seq of the `operator_trusted` event, null when never trusted. */
  trustedSeq: number | null;
  registeredSeq: number;
  agents: number;
  validations: number;
  /**
   * Entries this operator signed, as submitter or as approver, that an upheld
   * dispute overturned (Section 6). Counted once per entry however many of its
   * agents signed it, and zero is a reading and not a missing number.
   */
  overturned: number;
  /**
   * The standing the published formula last returned for this operator, with the
   * position it was computed at, or null when it has never been computed. Null
   * is "not computed yet" and is never a zero: an operator that has earned
   * nothing has a standing of 0, and the two must not be shown the same way.
   */
  standing: StandingCache | null;
}

export interface OperatorsData {
  rows: OperatorRow[];
}

/**
 * One domain an operator is attested in (decision D-071), carried verbatim from
 * `operatorDomains`: the slug, and the version of the attestation it signed for
 * that domain. The version is null when the stored row carries no attestation,
 * which is not the same as a domain nobody attested for.
 */
export interface OperatorDomainRow {
  domain: string;
  attestationVersion: string | null;
}

export interface OperatorData {
  row: OperatorRow;
  /** The agent ids bound to the operator (Section 5). */
  agents: string[];
  /**
   * The domains this operator is attested in, registration first and then every
   * join, in the order the log put them in.
   */
  domains: OperatorDomainRow[];
  /** The signed independence attestation, null when the row carries none. */
  attestation: Record<string, unknown> | null;
  /** The agent that named this operator at genesis, null otherwise. */
  namedBy: string | null;
  payoutStatus: string | null;
  validations: Array<{
    entryId: string;
    decision: string;
    seq: number;
    signed_at: string;
  }>;
  /**
   * This operator's newest ledger rows, newest first, exactly as
   * `ledgerRowsForOperator` read them at the route's own limit.
   */
  ledger: LedgerRow[];
  /**
   * What those rows add up to, as `ledgerBalance` computed them at the route's
   * injected clock. Carried rather than recomputed here, for the same reason
   * every derived field on the entry page is: the view adds nothing up.
   */
  balance: LedgerBalance;
  /**
   * This operator's payouts, newest first. They say which accruals have already
   * left — each names the row ids it covered — so the ledger table can mark a
   * row paid without the page working out what a payout was for.
   */
  payouts: LedgerRow[];
  /**
   * What this operator has to do with drift attestation, from both sides,
   * exactly as `attestationsForOperator` read them at the route's own limit.
   *
   * Two lists and never one. Section 8's point is that the scorers are "parties
   * its lab does not control", so the attestations an operator's own model
   * asked for and the ones it was drawn to score are two different
   * relationships, and a page that ran them together would hide the separation
   * the paper depends on.
   */
  attestations: {
    asModel: AttestationRow[];
    asScorer: AttestationRow[];
  };
}

/** One candidate or member of the founding trusted pool (Section 11, genesis). */
export interface GenesisRow {
  operator: string;
  registeredSeq: number;
  trustedSeq: number | null;
  validations: number;
  lastValidationAt: string | null;
}

export interface GenesisData {
  rows: GenesisRow[];
  /** The attestation text an operator signs to register, verbatim. */
  attestationText: string;
  attestationVersion: string;
  /** The prefix of the DNS TXT record that proves domain control. */
  txtRecordPrefix: string;
  /** Whether this environment has a maintainer configured at all (D-016). */
  maintainerConfigured: boolean;
}

/**
 * What the apex landing page is handed (D-062, direction D).
 *
 * The front door shows the log moving, so it reads the log: the newest seals for
 * the live band, and the three numerals under it. Every field is a reading —
 * `seals` is what the seals table holds, `sealCount` and `verified` are counts,
 * and `witnesses` is how many distinct operators the policy's WITNESS_PIN names.
 * Nothing here is computed by the page; `events` is the size the kernel sealed
 * (last_seq - first_seq + 1) and `witnessed` is whether that seal has at least
 * one countersignature.
 *
 * `seals` is in seq order, newest last, because the band reads left to right and
 * a strip that had to be reversed in the view would be a derivation in the view.
 * Empty before anything is sealed, which the band says in words.
 */
export interface LandingData {
  seals: Array<{
    seq: number;
    hash: string;
    sealedAt: string;
    witnessed: boolean;
    events: number;
  }>;
  sealCount: number;
  verified: number;
  witnesses: number;
}

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

import type { attributionOf } from "../attribution.js";
import type { DerivedAttestation } from "../attest.js";
import type { ConfidenceInputs } from "../confidence.js";
import type { Sidecar } from "../derive.js";
import type { CommunityBinding, Event } from "../events.js";
import type { OperatorKind, Tier, VerificationClass } from "../policy.js";
import type { RecordMarks, StandingCounts } from "../standing.js";
import type { VOTE_QUESTIONS } from "../policy.js";
import type { tallyOf } from "../vote.js";
import type { IndependenceReport } from "../independence.js";
import type { LedgerBalance, LedgerRow } from "../ledger.js";
import type { Seal } from "../seal.js";
import type { StakeRecord } from "../stake.js";
import type { MirrorKind } from "../adapters/mirror.js";
import type { Counter, Exercised, Stage } from "../status.js";
import type { MirrorRecord } from "../storage/repository.js";

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
  /**
   * The one origin every page of this deployment is canonical at — the head's
   * `<link rel="canonical">` and its `og:url` (decision D-114) — or null when
   * the deployment does not know one.
   *
   * Not `origin`, deliberately, and never derived from it. `origin` is the host
   * this request happened to arrive at, which is a fact about the reader's URL
   * bar: a preview host, a workers.dev name and the real host all answer the
   * same log, and a canonical built from whichever one was used would tell an
   * indexer that three addresses are three pages. This one is what the
   * deployment declares itself to be, configured rather than observed, so every
   * reader's copy of a page points at the same address.
   *
   * Null is "we cannot say", and the page then emits no canonical and no
   * `og:url` at all rather than a guess: a wrong canonical is worse than none,
   * because it hands an indexer an address that may not serve this page.
   */
  readonly canonical_origin: string | null;
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
  /**
   * The registered domain from the entry's signed core (decision D-125): one of
   * the schema's own domain slugs, the same values the domain chips filter by.
   * It is read and shown rather than only filtered on, because a row whose
   * domain a reader has to work out from the chip they happened to click is a
   * row that says less than the record does. The empty string is an entry
   * sealed before the domain key existed, which the listing prints as an em
   * dash rather than inventing a domain for.
   */
  domain: string;
  /** The claim, as the signed core carries it. */
  claim: string;
  /** The sidecar's `effective_tier`, null while the entry is draft or rejected. */
  tier: string | null;
  /**
   * The sidecar's `verification_class` (decision D-138): who met this entry's
   * consensus — registered, community or mixed — null while the entry is draft
   * or rejected, exactly as the tier is.
   *
   * Carried on the row because the listing prints it per row: a reader looking
   * at a page of verified entries can otherwise only learn which of them rest
   * on community validators by opening each one. Null is rendered as nothing
   * rather than a word, because a draft has no consensus to have a class.
   */
  verification_class: VerificationClass | null;
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
  /**
   * The source class the listing was narrowed to — official, recognized, other
   * — null for all of them (decision D-080). The class is the sidecar's, derived
   * from the entry's own citation, so this filter asks about where a claim came
   * from rather than about what the claim says.
   */
  source: string | null;
  tier: string | null;
  fresh: "fresh" | "stale" | null;
  /**
   * The weakest verification class the listing will show (decision D-138), null
   * for every class. `min_class=mixed` admits mixed and registered, because
   * VERIFICATION_CLASSES is ordered weakest first and the filter is a floor and
   * not an exact value — which is the same reading `min_class` has on the read
   * and sync doors, so one word means one thing everywhere.
   *
   * A field like every other one here, read by the same parser and carried the
   * same way, so the chip group, the "all" links and the keyset pager all keep
   * it without knowing anything about it.
   */
  min_class: VerificationClass | null;
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
  /**
   * Which kind of operator signed this decision (decision D-138). Read off the
   * operator id's own shape by the registry's parser, never guessed here: a
   * community operator's id is `<venue>:<handle>` and a domain operator's is a
   * DNS name, and the two alphabets do not overlap.
   */
  operatorKind: OperatorKind;
  /**
   * The account behind a community validator — the venue and the handle a
   * reader recognises it by — or null when a domain operator signed.
   */
  community: { readonly venue: string; readonly handle: string } | null;
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

/**
 * Who an entry is owed to, exactly as `attributionOf` folded it (D-130).
 *
 * The alias is the function's own return type rather than a shape retyped
 * here, so the block on the entry page and the fold that feeds it can never
 * drift: a field that moves in src/attribution.ts moves here in the same
 * commit. Whitepaper Incentives: attribution on every read is one of the
 * non-monetary rewards, so it is carried whole — the author and its operator,
 * every validator with the kind of operator it is and the decision it signed,
 * the reconfirmers, and the one-line citation a reader pastes.
 */
export type EntryAttribution = Awaited<ReturnType<typeof attributionOf>>;

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
  /**
   * The attribution block (D-130), exactly as `attributionOf` folded it from
   * this entry and its own events. Carried rather than assembled on the page
   * for the reason every other derived field here is: the view adds nothing up.
   */
  attribution: EntryAttribution;
  /**
   * The capture of the provider statement this entry's evidence cites, null
   * when there is none (Section 4, Behavior and misbehavior; decision D-059).
   *
   * A transcript entry whose `evidence.provider_statement` is not null rests on
   * two frozen sources, not one: the transcript the `snapshot_hash` names, and
   * the provider's own statement about the behavior. The second is archived
   * under the captures role `"statement"` beside the entry's `"snapshot"` row,
   * and this field is what the page needs to link it — the capture's content
   * hash, which addresses the bytes at `/captures/{hash}` and their fetch
   * record at `/captures/{hash}/sidecar`, and the host of the source the entry
   * cites, parsed where the reading was done and never on the page.
   *
   * Null is "no statement capture for this entry" and is rendered as nothing at
   * all: an entry that never claimed a provider statement has no empty row to
   * show, and a dash here would look like a capture that went missing.
   */
  statement: { hash: string; host: string } | null;
  /**
   * The delayed-disclosure payload of a redacted transcript, null when the
   * entry redacted nothing (decision D-096).
   *
   * `hash` is the capture's content hash, which addresses the payload at
   * `/captures/{hash}`, and `disclose_after` is the day it becomes public: the
   * entry's `submitted_at` plus the domain's published window, computed by the
   * route from the entry and src/policy.ts, never stored. Before that day the
   * link answers 403 to an unsigned read, which is the whole point of printing
   * the date beside it.
   *
   * Null is "nothing was held back" and is rendered as nothing at all: almost
   * every entry carries its evidence whole, and a line saying so would read as
   * a payload that had gone missing.
   */
  disclosure: { hash: string; disclose_after: string } | null;
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

/**
 * What a community operator is, beside its id (decision D-138).
 *
 * The account the key is bound to, and the binding itself, carried verbatim off
 * the registry row: the venue and the handle are what a reader recognises the
 * validator by, the agent is the key its lines are signed under, and the
 * binding is the thing anybody can go and check. Null on a domain operator,
 * which is bound by a DNS record and has no account anywhere.
 */
export interface CommunityOperator {
  readonly venue: string;
  readonly handle: string;
  /** The agent id the community operator's validations are signed under. */
  readonly agent: string;
  readonly binding: CommunityBinding;
}

export interface OperatorRow {
  id: string;
  /**
   * Which kind of operator this row is (decision D-138): `domain` for a key
   * bound by a DNS record under a registered name, `community` for a key bound
   * to an account on an agent community. One registry holds both, because
   * validation is one thing; the column says which path the operator came in
   * by, and nothing else follows from it.
   */
  kind: OperatorKind;
  /**
   * The account behind a community operator, or null for a domain one. Off the
   * registry row's own details, never assembled here.
   */
  community: CommunityOperator | null;
  maintainer: boolean;
  provider: boolean;
  trusted: boolean;
  /** seq of the `operator_trusted` event, null when never trusted. */
  trustedSeq: number | null;
  registeredSeq: number;
  agents: number;
  /**
   * The domains this operator is attested in, in the order the log put them in
   * (decision D-071), read off the stored rows for exactly the ids on the page.
   * Empty is a row that predates the join route, never a missing read.
   */
  domainSlugs: string[];
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
  /**
   * The acts the standing above was folded from, as the sweep's own
   * accumulator holds them (Section 9, and D-130): the validations volunteered
   * and assigned, the ones that carried a passing measurement, and the three
   * marks — overturned, missed, forfeits. Null when the fold has never run for
   * this operator, which is the same fact `standing` being null states and
   * never a row of zeroes.
   *
   * Carried rather than added up here: the leaderboard shows what an operator
   * did beside what it is worth, because a number with nothing behind it is a
   * score and standing is not one.
   */
  counts: StandingCounts | null;
  /**
   * What this operator's standing lets it do (D-130), as `tierOf` answered for
   * the number above. Computed by the route from the standing and the trust,
   * never stored and never decided here: the page prints the word and the
   * policy page prints what each word allows.
   */
  tier: Tier;
  /**
   * How many distinct operators this one has co-signed an entry with (D-119),
   * as the sweep folded it. Zero is a reading and not a missing number: an
   * operator that has signed alone every time has co-signed with nobody.
   */
  cosigners: number;
  /**
   * The perimeter the maintainer disclosed when it named this operator into the
   * trusted pool, or null (decision D-128).
   *
   * Shown in the directory and on the operator page because Section 11's
   * genesis is a bootstrap exception "stated as such": the maintainer's own
   * grouping belongs beside the operator it named, not only on the page that
   * adds them up.
   */
  perimeter: string | null;
}

/**
 * One bare agent key's standing (D-130): a key that submits or validates under
 * no operator at all.
 *
 * A separate table under the leaderboard rather than a row in it, because a
 * bare key is not an operator and ranking the two together would say it was.
 */
export interface BareKeyRow {
  agent: string;
  standing: number;
  /** The log position the number was folded to. */
  seq: number;
}

export interface OperatorsData {
  rows: OperatorRow[];
  /**
   * The bare keys the route could read standing for, or null when this
   * deployment holds none to read.
   *
   * Null and an empty list are different facts and the page says which it has:
   * null is "no reading of bare-key standing exists here" and prints the
   * sentence that says so, where an empty list is "nothing has been folded for
   * any bare key yet".
   */
  bareKeys: BareKeyRow[] | null;
}

/**
 * One operator this operator has signed beside (D-119), carried verbatim from
 * `cosignPairsForOperator`.
 *
 * `both` is the entries the two have both signed, `agreed` and `opposed` how
 * their decisions fell on those entries, and `newestEntryId` the newest of them
 * — a link, so a reader leaves the counts and goes and looks at the record.
 * `throughSeq` is the log position the three numbers were folded to, which is
 * what makes them checkable.
 */
export interface CosignerRow {
  cosigner: string;
  both: number;
  agreed: number;
  opposed: number;
  throughSeq: number;
  newestEntryId: string;
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
  /**
   * The Record (D-130): every mark against this operator, exactly as `marksOf`
   * read them off the sealed events — the entries its agents signed that an
   * upheld dispute overturned, the assignments it missed, and the disputes it
   * filed and lost.
   *
   * Derived and never edited. A mark is a fact about the log and permanent:
   * nothing on this page or behind it can clear one, and an empty Record is an
   * empty fold rather than a cleared one.
   */
  marks: RecordMarks;
  validations: Array<{
    entryId: string;
    decision: string;
    seq: number;
    signed_at: string;
  }>;
  /**
   * Who this operator has signed beside, newest pair first, one page of them at
   * the route's own limit. The route read them off the stored rows the sweep
   * folded; the page adds nothing up.
   */
  cosigners: CosignerRow[];
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

/**
 * What the How it works page is handed (D-076).
 *
 * The page is the pipeline explained, and every stage of it carries a link into
 * this environment's own log rather than a description of one — so every field
 * below is a reading, and every one of them is nullable, because production
 * holds no entries the day it opens and a page that showed a plan where the log
 * holds nothing would be the first thing a reader disbelieved. Null is rendered
 * as words ("no entry yet", "no seal yet", "none stale", "no attestation yet")
 * and never as an em dash: this page is prose, and a dash in a sentence is not
 * an empty state a reader can read.
 *
 * Nothing here is derived by the page. The tier is the sidecar's effective one,
 * the counts are counts, and the two hosts were parsed where the reading was
 * done (src/worker/pages.ts) and not in the view.
 */
export interface HowItWorksData {
  /** The newest entry, however far through validation it is. */
  entry: {
    id: string;
    status: string;
    /** The sidecar's `effective_tier`, null while the entry is draft. */
    tier: string | null;
    domain: string;
  } | null;
  /** That entry's snapshot capture: the hash, the source's host, the rule. */
  capture: {
    hash: string;
    host: string;
    normVersion: string;
  } | null;
  /** The trusted pool, and how many operators are registered at all. */
  pool: {
    /** The trusted operators' ids, in the directory's own order. */
    names: string[];
    trusted: number;
    registered: number;
  };
  /** The newest validation event: where it sits, and what it said. */
  validation: {
    seq: number;
    decision: string;
    operator: string;
  } | null;
  seal: {
    seq: number;
    firstSeq: number;
    lastSeq: number;
    witnesses: number;
    sealedAt: string;
  } | null;
  anchor: {
    date: string;
    /** Seals covered by that day's anchor. */
    seals: number;
    /** What the anchor was posted to, in words: "local on demo" and the like. */
    external: string;
  } | null;
  /** The newest published read count, and the seq the log carries it at. */
  readCount: {
    seq: number;
    date: string;
    total: number;
    counterFirst: number | null;
    counterLast: number | null;
  } | null;
  /** The newest overturned entry and the correction that overturned it. */
  overturned: {
    id: string;
    correction: string | null;
  } | null;
  /** How many entries are stale now. */
  stale: number;
  /**
   * When the first freshness window on this environment ends: the newest
   * entry's own `expires_at`, carried verbatim. Null when nothing is submitted,
   * or when the newest entry is in a category that carries no window.
   */
  nextWindowEnds: string | null;
  /** The standing table's top rows, and the position they were computed at. */
  standing: {
    position: number | null;
    rows: Array<{ operator: string; standing: number }>;
  };
  /** The newest daily reconciliation, exactly as the ledger row states it. */
  reconciliation: {
    date: string;
    published: number;
    accrued: number;
    ok: boolean;
  } | null;
  /** The newest attestation that has been scored. */
  attestation: {
    id: string;
    status: string;
    /** The median score as `agreed / probes`, null while it is unscored. */
    score: string | null;
    date: string | null;
    scorers: string[];
  } | null;
  /** The position a sync example resumes from: the sealed head, or 0. */
  syncFrom: number;
  /**
   * The newest daily export of the sealed log, null before the first one.
   *
   * The row the sweep wrote when it pushed, exactly as the Mirror page reads
   * it: what this instance exported, and never what the repository looks like
   * at this instant. `treeUrl` is the exported directory as a reader can open
   * it at that commit, built where every other URL on this page is built — in
   * the gathering, because a page that assembled one would be deriving.
   */
  mirror: {
    date: string;
    /** The sealed position the export was built at. */
    head: number;
    entries: number;
    treeUrl: string;
  } | null;
}

/**
 * What this log holds in one domain: the two numbers the Domains page shows
 * live beside a domain's published tables.
 *
 * Both are counts and neither is derived here: `entries` is `countEntries` under
 * that domain and `trustedOperators` is `countTrustedOperators` for it, which is
 * the trusted pool narrowed to the operators attested in that domain (decision
 * D-071) — the ones who could actually judge an entry in it. Zero is a reading
 * and not a missing number: a registered domain nobody has submitted to yet has
 * no entries, and saying so is the point of showing the count at all.
 */
export interface DomainCounts {
  entries: number;
  trustedOperators: number;
}

/**
 * What the Domains page is handed.
 *
 * Almost nothing, deliberately. The page is the registry's published tables —
 * categories, windows, transcripts, excluded parties, subjects, attestations,
 * sources — and every one of those is read from src/policy.ts at render time
 * rather than gathered here, because a table copied into a data object is a
 * table that can disagree with the rule the log runs. What the policy module
 * cannot know is what this environment's log holds, so that is what this shape
 * carries: one reading per registered slug, keyed by slug exactly as `DOMAINS`
 * is.
 */
export interface DomainsData {
  counts: Readonly<Record<string, DomainCounts>>;
}

/**
 * What a served document page is handed (D-104).
 *
 * The whitepaper, its summary and the fork guide are markdown in this
 * repository, read into src/ui/docs.generated.ts ahead of time, so this shape
 * is the document itself rather than a reading of the log: no counter, no
 * clock, nothing gathered. `sourcePath` is the file the markdown came from, and
 * the page prints it, because a document served from somewhere the reader
 * cannot see is a document they cannot check against the repository.
 */
export interface DocumentData {
  /** The page's title, and the last crumb: "Whitepaper", "Summary". */
  readonly title: string;
  /** The path from the repository root, exactly as the generator read it. */
  readonly sourcePath: string;
  /** The document, verbatim. */
  readonly markdown: string;
  /** One line under the title saying what this document is. */
  readonly note: string;
}

/**
 * What the Status page is handed (D-076).
 *
 * The same object `GET /status` answers as JSON, in the same order: the page and
 * the endpoint read one input and one set of rules, so a reader who curls the
 * path and a reader who opens it are looking at the same lights. Nothing here is
 * probed when the page loads — every field is the last sweep's stored report and
 * the log, which is what lets the page say it cannot be warmed.
 */
export interface StatusData {
  /**
   * The sweep run the page is as of, ISO, null when none has run. The head line
   * says so in words rather than showing the wall clock: the page is as of the
   * record, not as of the request.
   */
  asOf: string | null;
  /** The four headline numbers, exactly as `statusCounters` computed them. */
  counters: Counter;
  /** Every stage, in the order the pipeline runs them. */
  stages: readonly Stage[];
  /** The stages that run only when someone asks. */
  exercised: readonly Exercised[];
}

/**
 * What the Mirror page is handed (Section 11: the daily log mirror under CC0,
 * and exit as a protocol right).
 *
 * The same reading `GET /mirror/latest` answers as JSON, in the same order: the
 * record of the newest export, and where the mirror lives. Nothing here is
 * fetched from GitHub when the page loads — `latest` is the row the sweep wrote
 * when it pushed, so the page reports what this instance exported and never what
 * a repository looks like right now, which is a thing only the repository can
 * say. `configured` is false when no mirror adapter is available on this
 * environment, which is not a failure and is said in words rather than shown as
 * an empty panel.
 */
export interface MirrorData {
  /** Whether this environment can push at all: the adapter is not unavailable. */
  configured: boolean;
  /** Which adapter this environment pushes through: github, mock, unavailable. */
  kind: MirrorKind;
  /** The mirror repository as a web URL, exactly as the JSON route names it. */
  repository: string;
  branch: string;
  /** The top-level directory this environment exports under: demo, production. */
  path: string;
  /** The newest export this instance recorded, null before the first one. */
  latest: MirrorRecord | null;
}

/**
 * What the independence page is handed (decision D-121).
 *
 * The report itself and nothing beside it: `independenceReport` built both sets,
 * their intersection, the flag and the claim, and `GET /independence` answers
 * exactly the same object. One rule, two doors — a page that computed anything
 * of its own here could show a reader something the JSON twin denies.
 */
export interface IndependenceData {
  readonly report: IndependenceReport;
}

/**
 * One question the governance vote is open on (decision D-130 item 4, D-131
 * item 2), and what the log makes of it.
 *
 * Two halves and neither is the other's. The question is policy — its id, its
 * text, its options and what it is about all move only by a recorded decision —
 * and the tally is a fold over the sealed `vote_cast` events at the route's own
 * instant. Nothing here is stored as a result: a vote is a signed event like
 * every other, and the counts are recomputed on every view, so a reader who
 * folds the same events gets the same numbers.
 */
export interface VoteQuestionView {
  /** The question exactly as src/policy.ts publishes it. */
  readonly question: (typeof VOTE_QUESTIONS)[number];
  /**
   * The state, the window, the counts and the voters, exactly as `tallyOf`
   * returned them. `advisory` is on it and is always true: the tally advises
   * the maintainer and binds nobody until the record's hosting decentralizes.
   */
  readonly tally: Awaited<ReturnType<typeof tallyOf>>;
}

/**
 * What the votes page is handed.
 *
 * `only` is the question the reader asked for at `/votes/{id}`, or null at
 * `/votes`, which lists every question policy publishes. One renderer for both
 * because they are one document at two widths: the same rows, the same
 * eligibility and the same advisory sentence, and a second renderer would be a
 * second chance for the two to disagree about what a vote is.
 */
export interface VotesData {
  readonly questions: readonly VoteQuestionView[];
  readonly only: string | null;
}

/**
 * Derivation: every derived field and the status, recomputed from the event log.
 *
 * Pure and synchronous. Nothing here reads a wall clock: the only time input is
 * the injected `clock.now`, so the same events and the same clock always give
 * the same answer, on Node and on a Worker alike.
 *
 * Nothing here is ever written directly onto an entry. The schema says so of
 * every field this module computes ("DERIVED ... never written directly"), and
 * the consensus rules come from the whitepaper's Lifecycle of an entry and
 * Freshness and decay sections, cited on each rule below.
 */

import { CORE_KEYS, domainOf, type Core } from "./core.js";
import { disputeExclusions } from "./dispute.js";
import {
  evidenceGate,
  type EvidenceTier,
  type TestVerdict,
} from "./evidence.js";
import { confirmationPayloadOf } from "./confirm.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  authorityHostsFor,
  CONFIRMATION_VENUES,
  DEFAULT_DOMAIN,
  isRegisteredDomain,
  REJECTIONS_TO_REJECT,
  isVersionStalenessCategory,
  stalenessWindowDays,
  TRUSTED_POOL_SWITCH,
  versionedSubjectOf,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "./policy.js";
import { isExcludedParty } from "./registry.js";
import type { Entry } from "./schema.js";
import type { EntrySeal } from "./seal.js";
import {
  capturedSourceClass,
  sourceClassOf,
  type SourceClassification,
} from "./sources.js";
import { checkSupersedes } from "./supersede.js";
import { eligibilityRefusal } from "./eligibility.js";
import type {
  ApproverRecord,
  ConfirmationCheck,
  ConfirmationVerdict,
  Event,
  EventType,
  ReconfirmationRecord,
} from "./events.js";

/** The injected clock: an ISO 8601 date-time, and the only time input. */
export interface Clock {
  readonly now: string;
}

/**
 * Which derivation a stored row was written by (decision D-135).
 *
 * Not a version of the record and not a policy number: nothing signed, sealed,
 * exported or published carries it. It is one string this module stamps on
 * every row it produces (src/storage/repository.ts, `entryStatement`) so the
 * sweep can find the rows an older derivation wrote and rewrite them
 * (src/worker/sweep.ts, the `rederive` step). Null in the column means the row
 * predates the stamp and is therefore due once.
 *
 * Bump it whenever a rule in this file moves — a consensus rule, a precondition,
 * an eligibility input, a derived field's shape — because that is exactly when a
 * stored row and a fresh derivation of the same events can disagree. Bumping it
 * when nothing moved costs one rewrite per row and changes no answer; forgetting
 * to bump it leaves the export publishing what the verifier will not confirm,
 * which is the failure D-135 found: the QA of 2026-09-13 (D-111) moved the
 * verification precondition to count only operators that could actually sign,
 * and three demo rows decided before it went on saying `verified` while the
 * kernel derived `draft`.
 *
 * The value is the date the rules last moved and the decision that moved them,
 * which is the only thing a reader of a row ever has to compare.
 */
export const DERIVATION_VERSION = "2026-09-16-d136";

/** The schema's status enum. */
export type EntryStatus =
  | "draft"
  | "rejected"
  | "verified"
  | "superseded"
  | "overturned";

/** Every derived field on an entry, in the schema's names and shapes. */
export interface DerivedFields {
  readonly status: EntryStatus;
  readonly staleness_window_days: number | null;
  readonly verified_at: string | null;
  readonly last_confirmed: string;
  readonly expires_at: string | null;
  readonly stale: boolean;
  readonly superseded_by: string | null;
  readonly overturned_by: string | null;
  /**
   * The confidence field. conf-v1 is not published, so the field is null for
   * every entry and every input to it stays exposed raw.
   */
  readonly confidence: null;
}

/**
 * One of the entry's read-share slots: who held it, and the position of the
 * event that seated them.
 *
 * Nothing seats one any more. Decision D-127 retired the read share with the
 * rest of the money — contribution is the currency, and a claim on future
 * revenue is a claim on revenue that does not exist — so `read_share_slots` is
 * an empty list on every entry the log derives. The shape stays exactly as it
 * was, here and in the sidecar, so an export, a mirror import and the verifier
 * read the same document they always did, and so a row sealed before the
 * decision still has a type to be read back under.
 */
export interface ReadShareSlot {
  readonly operator: string;
  /** seq of the event that seated the holder. */
  readonly seq: number;
}

/**
 * State the application keeps beside the entry, never in the signed record and
 * never in the schema.
 */
export interface Sidecar {
  /**
   * Lifecycle of an entry: two approvals against one rejection in the large
   * pool draw one beacon-chosen replacement validator. The draw itself is M4's;
   * this only says one is owed.
   */
  readonly needs_replacement: boolean;
  /**
   * Two tiers of evidence: the tier the entry actually verified at, which is
   * not always the tier its core claims. An observed entry whose test a
   * majority rejected verifies as a document, and its effective tier falls to
   * stated. Null while the entry is draft or rejected; once it has verified the
   * value is the one the gate gave at that decision's position and it stays
   * there, superseded and overturned included.
   */
  readonly effective_tier: EvidenceTier | null;
  /**
   * What the validators decided about the proposed test itself, at the
   * verifying decision's position. Null for a stated entry, which has no test
   * to judge, and null while the entry is draft or rejected.
   */
  readonly test_verdict: TestVerdict | null;
  /** Size of the trusted pool at the promoting decision's position. */
  readonly trusted_count_at_decision: number | null;
  /**
   * The read-share slots, retired by decision D-127: empty, always.
   *
   * The paper's "Reconfirming a stale entry ... rotates the reconfirmer into
   * one of the three validator read-share slots" is superseded — there is no
   * read share to rotate into, because there is no money anywhere in this
   * record. So no approval seats a slot and no reconfirmation rotates one.
   *
   * Null until the entry verifies, and an empty list from the decision that
   * promotes it: the field keeps its shape, which is what lets the exports, the
   * mirror and the verifier keep theirs, and what makes the difference between
   * "no read share yet" and "no read share ever" readable rather than guessed.
   */
  readonly read_share_slots: readonly ReadShareSlot[] | null;
  /**
   * Whitepaper Section 6, "Revalidate": "Any operator can also request
   * revalidation of an entry inside its window ... It is assigned at random to a
   * trusted operator", and Section 8: a threshold of failure reports "auto-opens
   * a revalidation at nomankind's expense".
   *
   * The schema has no field for these — a request is not a claim about the world
   * and the signed record says nothing about it — so they live in the sidecar,
   * exactly as the read-share slots do. Empty when nobody has ever asked for a
   * check of this entry.
   */
  readonly revalidations: readonly RevalidationView[];
  /**
   * Whitepaper Section 4, the source policy (decision D-080): the class the
   * entry's own citation earned, the listed host that matched it, and the
   * authority its subject names.
   *
   * A derived field and not a signed one. The citation was always in the core;
   * this is a reading of it against the domain's published tables, computed the
   * same way from the same bytes by everyone, so every rewrite, every
   * re-derivation and the mirror's own copy agree without anything being signed
   * again. It sits in the sidecar rather than in the schema for the reason the
   * effective tier does: the record says what was claimed, and the log says what
   * it makes of it.
   */
  readonly source: SourceClassification;
  /**
   * The bootstrap label (decision D-128): `{ perimeter }` while every
   * validator counted in this entry's decision was named inside one and the
   * same disclosed perimeter, and null otherwise.
   *
   * A sidecar field and not a schema one, for the reason the effective tier is:
   * the signed record says what was claimed, and the log says what it makes of
   * it. Nothing signs this and nothing has to — it is folded from the naming
   * events and the entry's own decisions, so every re-derivation, every mirror
   * and the offline verifier arrive at the same word from the same bytes.
   *
   * Absent on a row stored before the decision, which reads as no label. Every
   * reader takes it as `bootstrap ?? null`.
   */
  readonly bootstrap: BootstrapLabel | null;
  /**
   * What the outside said about this entry in public (decision D-136), oldest
   * first: one row per `public_confirmation` event that names it.
   *
   * Shown and never counted into anything but the bootstrap label. Whitepaper,
   * "What verified means": a status is what the counted validators decided
   * under assignment, on signed records, at stake. A comment on a public board
   * is none of those, so a confirmation moves no status, no tier and no count —
   * it says, in the record, that somebody outside looked, which is exactly what
   * the genesis exception was waiting for.
   *
   * `counted` says whether this row is the kind of statement that can clear the
   * label: true for a signing venue, where the confirmer's key is a leaf in the
   * founding registry's log and the proof travels on the event, and false for
   * an account venue (`ACCOUNT_STATEMENT_VENUES`), where the statement is an
   * account's word and nothing about it can be rechecked offline. An uncounted
   * row is still shown — the record does not hide what was said — and it clears
   * nothing.
   *
   * Absent on a row stored before the decision, which reads as no
   * confirmations. Every reader takes it as `confirmations ?? []`.
   */
  readonly confirmations: readonly PublicConfirmationView[];
}

/**
 * One public confirmation, as the entry page, the entry JSON, the sync items
 * and the export all carry it.
 *
 * Off the event and nothing else: the handle and the reason are a stranger's
 * text, kept as they were said, bounded when they were sealed, and escaped
 * wherever they are shown.
 */
export interface PublicConfirmationView {
  readonly venue: string;
  readonly handle: string;
  readonly verdict: ConfirmationVerdict;
  readonly check: ConfirmationCheck;
  readonly reason: string | null;
  readonly posted_at: string;
  /** The identity event that binds the confirmer's key, by the registry's id. */
  readonly registry_event_id: number;
  /**
   * Whether this statement is of the kind that can clear a bootstrap label: the
   * venue is a signing venue, and the proof on the event verified when the door
   * sealed it (src/worker/sweep.ts seals no confirmation whose proof did not,
   * and src/verify.ts rechecks every one of them offline).
   */
  readonly counted: boolean;
  /** Position of the event in the log, so a reader can go and look at it. */
  readonly seq: number;
}

/**
 * One revalidation request, folded from the target's own events.
 *
 * `request_seq` is the `revalidation_requested` event's position, which is what
 * every later event about it names. `requester` and `operator` are both null
 * when the check was auto-opened by failure reports at nomankind's expense
 * (Section 8), which is also what `source` says.
 *
 * `assigned` is the draw currently in force, or null when none is: a missed
 * assignment closes the assignment and not the request, so the field goes back
 * to null and the next draw fills it again.
 */
export interface RevalidationView {
  readonly request_seq: number;
  readonly requester: string | null;
  readonly operator: string | null;
  readonly source: "operator" | "failure_reports";
  readonly requested_at: string;
  readonly assigned: {
    readonly agent: string;
    readonly operator: string;
    readonly deadline: string;
  } | null;
  readonly outcome: "open" | "held" | "changed" | "upgraded";
  readonly resolved_at: string | null;
  readonly checker: string | null;
  readonly correction_entry_id: string | null;
}

/** An entry, its derived fields, and the sidecar the schema cannot hold. */
export interface DerivedEntry {
  readonly entry: Entry;
  readonly derived: DerivedFields;
  readonly sidecar: Sidecar;
}

/** The payload of an event of a given type. */
type PayloadOf<T extends EventType> = Event<T>["payload"];

/**
 * The approver fields derivation reads. Declared here so this module reads the
 * record through the schema's own field names rather than depending on how
 * `ApproverRecord` happens to be spelled.
 */
interface DecisionFields {
  readonly operator: string;
  readonly decision: "approve" | "reject";
  readonly assigned_random: boolean;
  readonly signed_at: string;
}

interface ReconfirmationFields {
  readonly signed_at: string;
}

const MILLISECONDS_PER_DAY = 86_400_000;

/** Events in seq order, without mutating the caller's array. */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

function isType<T extends EventType>(
  event: Event,
  type: T,
): event is Event<T> {
  return event.type === type;
}

/**
 * Registered operators, and which of them are maintainers, as of `position`.
 * Only events with seq <= position are folded, so a later registration can
 * never change what a past decision saw (retrospective M8).
 */
export function registeredOperatorsAt(
  events: readonly Event[],
  position: number,
): { operators: Set<string>; maintainers: Set<string> } {
  const operators = new Set<string>();
  const maintainers = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "operator_registered")) continue;
    const payload: PayloadOf<"operator_registered"> = event.payload;
    operators.add(payload.operator);
    if (payload.maintainer) maintainers.add(payload.operator);
  }
  return { operators, maintainers };
}

/**
 * The trusted pool as of `position`: every operator trusted at or before it,
 * minus every operator untrusted at or before it.
 *
 * Retrospective M8: the trusted count is evaluated at the decision's position,
 * never over the whole log, so an entry can neither verify retroactively when
 * the pool grows nor flip back to draft when it shrinks.
 */
export function trustedOperatorsAt(
  events: readonly Event[],
  position: number,
): Set<string> {
  const trusted = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (isType(event, "operator_trusted")) {
      trusted.add(event.payload.operator);
      continue;
    }
    if (isType(event, "operator_untrusted")) {
      trusted.delete(event.payload.operator);
    }
  }
  return trusted;
}

/**
 * The perimeter each operator was named inside, as of `position` (D-128).
 *
 * Section 11's genesis is the maintainer naming the first trusted operators,
 * "a bootstrap exception to the earned-record rule, stated as such". The
 * perimeter is the second half of stating it: the word the maintainer
 * disclosed at the naming, sealed into the `operator_trusted` event's own
 * payload, so it is re-derivable from the log by anyone and is not a row
 * somebody could edit.
 *
 * An untrusting does not clear it. Trust is a permission and can be withdrawn;
 * the perimeter is a disclosure about a naming that happened, and unsaying it
 * would make the record quieter than it was. A later naming of the same
 * operator replaces it, because the fold runs in seq order and the newest
 * disclosure is the one in force.
 *
 * The field is read off the payload object by name: it is absent on every
 * naming sealed before the decision, which is exactly "no perimeter
 * disclosed", and a payload carrying anything but a string is ignored rather
 * than trusted.
 */
export function operatorPerimetersAt(
  events: readonly Event[],
  position: number,
): Map<string, string> {
  const perimeters = new Map<string, string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "operator_trusted")) continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    const perimeter = payload["perimeter"];
    if (typeof perimeter !== "string" || perimeter === "") continue;
    perimeters.set(event.payload.operator, perimeter);
  }
  return perimeters;
}

/**
 * Which operator answers for each agent, as of `position`.
 *
 * Whitepaper Section 5: "Every agent belongs to an operator, the human or
 * company that runs it", and every rule that says "a distinct operator"
 * resolves an agent through this. Only events with seq <= position are folded,
 * so a binding sealed later can never change what a past decision saw
 * (retrospective M8), and a later binding of the same agent replaces the
 * earlier one because the fold runs in seq order.
 */
export function agentOperatorsAt(
  events: readonly Event[],
  position: number,
): Map<string, string> {
  const operators = new Map<string, string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "agent_bound")) continue;
    operators.set(event.payload.agent, event.payload.operator);
  }
  return operators;
}

/**
 * Which domains each operator is attested in, as of `position`.
 *
 * Decision D-071: the independence attestation is per domain, so eligibility is
 * too. An operator is attested in the domain it registered under, plus every
 * domain it has since joined by signing that domain's attestation
 * (`operator_joined_domain`). A registration sealed before v0.7 carries no
 * domain and reads as ai-ecosystem, because that was the only domain there was.
 *
 * Only events with seq <= position are folded, exactly as every other fold here,
 * so a join sealed later can never change what a past decision saw.
 */
export function operatorDomainsAt(
  events: readonly Event[],
  position: number,
): Map<string, string[]> {
  const domains = new Map<string, string[]>();
  const add = (operator: string, domain: string): void => {
    const held = domains.get(operator);
    if (held === undefined) {
      domains.set(operator, [domain]);
      return;
    }
    if (!held.includes(domain)) held.push(domain);
  };
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (isType(event, "operator_registered")) {
      add(event.payload.operator, event.payload.domain ?? DEFAULT_DOMAIN);
      continue;
    }
    if (isType(event, "operator_joined_domain")) {
      add(event.payload.operator, event.payload.domain);
    }
  }
  return domains;
}

/** The domains one operator is attested in at `position`; empty when unknown. */
export function operatorDomainsOf(
  events: readonly Event[],
  operator: string,
  position: number,
): readonly string[] {
  return operatorDomainsAt(events, position).get(operator) ?? [];
}

/** The outcome of folding an entry's validation events, and nothing else. */
interface Consensus {
  readonly status: "draft" | "rejected" | "verified";
  readonly verifiedAt: string | null;
  readonly trustedCountAtDecision: number | null;
  readonly effectiveTier: EvidenceTier | null;
  readonly testVerdict: TestVerdict | null;
  readonly needsReplacement: boolean;
  readonly approvers: readonly ApproverRecord[];
  /** seq of the decision that promoted the entry; null unless it verified. */
  readonly promotingSeq: number | null;
  /**
   * The distinct eligible operators whose decisions this verdict was counted
   * from, in the order they were counted — never every operator in
   * `approvers`, which holds the records nobody counted too.
   *
   * Kept because the bootstrap label (D-128) is a statement about exactly
   * these: "every validator counted in the entry's decision". It stops growing
   * the moment the verdict lands, like the counts themselves.
   */
  readonly countedOperators: readonly string[];
}

/**
 * Fold an entry's validation events into a verdict.
 *
 * Lifecycle of an entry, Validate: "Once the pool holds ten operators, three
 * approvals promote the entry to verified, two rejections mark it rejected ...
 * and two approvals against one rejection draw one replacement validator ...
 * Until the pool holds ten operators, two approvals verify, two rejections
 * reject, and there is no replacement draw."
 *
 * And: "Verification has two preconditions: three verified operators outside
 * the submitter's own, and a non-empty trusted pool to draw the random
 * validator from. At genesis, entries stay in draft until both exist."
 *
 * Both the pool size and the two preconditions are read at the position of the
 * decision being folded, never at the end of the log (retrospective M8), so a
 * decision taken under one pool keeps its verdict when the pool later moves,
 * and a later decision is judged afresh at its own position.
 *
 * The count is not the only condition. Two tiers of evidence: an entry also has
 * to have the evidence its tier asks for, which is src/evidence.ts's rule and
 * is asked there, never restated here. The gate is consulted at exactly the
 * moment the count would promote, over exactly the decisions counted so far, so
 * an entry the gate turns away does not verify and is asked again at the next
 * counted decision. It stays draft only while the rejections are short of the
 * threshold: the rejection rule is unconditional, and a gate refusal never
 * shields an entry from it.
 */
function consensusFor(
  events: readonly Event[],
  entryId: string,
  core: Core,
): Consensus {
  // Who may judge this entry at all, in the shape the one eligibility predicate
  // asks for: the submitter's operator, the domain and the subject, all read off
  // the signed core and never passed in beside it.
  const target = eligibilityTargetOf(core);
  const approvers: ApproverRecord[] = [];
  const approvingOperators = new Set<string>();
  const rejectingOperators = new Set<string>();
  // The counted decisions themselves, one per distinct eligible operator and in
  // seq order: the same records the counts above are built from, kept so the
  // evidence gate reads exactly what consensus counted.
  const countedRecords: ApproverRecord[] = [];
  const countedOperators = new Set<string>();
  let hasRandomApproval = false;
  let status: "draft" | "rejected" | "verified" = "draft";
  let verifiedAt: string | null = null;
  let trustedCountAtDecision: number | null = null;
  let effectiveTier: EvidenceTier | null = null;
  let testVerdictAtDecision: TestVerdict | null = null;
  let needsReplacement = false;
  let promotingSeq: number | null = null;

  for (const event of inSeqOrder(events)) {
    if (!isType(event, "validation")) continue;
    if (event.entry_id !== entryId) continue;

    const record = stripSignature(event.payload.record);
    approvers.push(record);

    // Once verified or rejected the verdict stands: later decisions still land
    // in approvers[], but change nothing.
    if (status !== "draft") continue;

    const position = event.seq;
    const decision = record as unknown as DecisionFields;

    // Who may validate at all: `mayValidateEntry`'s seven exclusions, the same
    // seven the door applies, asked here because the log is append-only and
    // derivation must stay safe against a record the door would have refused.
    // Such a record stays in approvers[] — nothing is ever removed — and is
    // counted by nobody. Eligibility is read at the record's own position, like
    // every other rule here.
    if (!mayValidateEntry(events, position, target, decision.operator)) {
      continue;
    }

    // The first record from an operator is the one that counts, here as in the
    // distinct-operator sets below.
    if (!countedOperators.has(decision.operator)) {
      countedOperators.add(decision.operator);
      countedRecords.push(record);
    }

    if (decision.decision === "approve") {
      // Distinct operators: a second record from the same operator is kept but
      // adds no count.
      approvingOperators.add(decision.operator);
      if (decision.assigned_random) hasRandomApproval = true;
    } else {
      rejectingOperators.add(decision.operator);
    }

    const trustedCount = trustedOperatorsAt(events, position).size;
    const largePool = trustedCount >= TRUSTED_POOL_SWITCH;
    const approvals = approvingOperators.size;
    const rejections = rejectingOperators.size;

    if (preconditionsMet(events, position, target, trustedCount)) {
      const approvalsToVerify = largePool
        ? APPROVALS_TO_VERIFY_LARGE_POOL
        : APPROVALS_TO_VERIFY_SMALL_POOL;
      // The large pool also wants the beacon-drawn validator among the
      // approvals. The paper says exactly one; "at least one" is what the
      // replacement-draw path can satisfy (retrospective GAPS M9).
      const randomSatisfied = largePool ? hasRandomApproval : true;
      // Two tiers of evidence: the count says the validators agree, the gate
      // says whether what they brought is enough, and at which tier. The gate is
      // asked only where the count would promote, over exactly the decisions
      // counted so far.
      const countMet = approvals >= approvalsToVerify && randomSatisfied;
      const gate = countMet ? evidenceGate(core, countedRecords) : null;
      // A gate refusal is never itself a rejection: it only means the approvals
      // do not promote at this position, so this decision is judged as any
      // unpromoted one is. Lifecycle of an entry: two rejections mark the entry
      // rejected, unconditionally — an entry the gate keeps turning away is
      // still rejected once the rejections arrive, and is otherwise asked again
      // at the next counted decision.
      if (countMet && gate !== null && gate.verifiable) {
        status = "verified";
        verifiedAt = decision.signed_at;
        trustedCountAtDecision = trustedCount;
        effectiveTier = gate.effective_tier;
        testVerdictAtDecision = gate.test_verdict;
        promotingSeq = position;
      } else if (rejections >= REJECTIONS_TO_REJECT) {
        status = "rejected";
        trustedCountAtDecision = trustedCount;
      }
    }

    if (status !== "draft") {
      needsReplacement = false;
      continue;
    }
    // A 2-1 split in the large pool owes a replacement draw; the small pool
    // makes no draw at all.
    needsReplacement =
      largePool &&
      approvals >= APPROVALS_TO_VERIFY_LARGE_POOL - 1 &&
      rejections >= 1;
  }

  return {
    status,
    verifiedAt,
    trustedCountAtDecision,
    effectiveTier,
    testVerdict: testVerdictAtDecision,
    needsReplacement,
    approvers,
    promotingSeq,
    countedOperators: [...countedOperators],
  };
}

/**
 * The entry's read-share slots: none, and an empty list once it has verified.
 *
 * Decision D-127 retired the read share. The paper's rotation — "Reconfirming a
 * stale entry ... rotates the reconfirmer into one of the three validator
 * read-share slots ... replacing the holder of the oldest slot rather than
 * adding to the pool" — is superseded with the money it divided: no approval
 * seats a seat, no reconfirmation rotates one, and a reconfirmation still does
 * everything else it ever did (it refreshes the entry, which is Freshness and
 * decay's job and is not this function's).
 *
 * Null before the promoting decision and an empty list from it, so the field
 * keeps the shape every export, mirror and verifier already reads: "no read
 * share yet" and "no read share ever" stay two different answers.
 */
function readShareSlotsFor(consensus: Consensus): readonly ReadShareSlot[] | null {
  if (consensus.promotingSeq === null) return null;
  return EMPTY_READ_SHARE_SLOTS;
}

/** The one empty list every verified entry's read-share slots are. */
const EMPTY_READ_SHARE_SLOTS: readonly ReadShareSlot[] = Object.freeze([]);

/**
 * The entry an eligibility question is asked about: its id, its submitter's
 * operator, and the two core fields the exclusions read.
 *
 * Taken as a shape rather than as a `Core` so a caller holding a stored entry
 * — the sweep's draw does — asks the same question without reassembling one.
 */
export interface EligibilityTarget {
  readonly id: string;
  readonly authorOperator: string | null;
  readonly domain: string;
  readonly subject: unknown;
}

/** That shape, read off a signed core. */
export function eligibilityTargetOf(core: Core): EligibilityTarget {
  return {
    id: core["id"] as string,
    authorOperator: (core["author_operator"] as string | null) ?? null,
    domain: domainOf(core),
    subject: core["subject"],
  };
}

/**
 * Whether one operator may validate this entry at all, as of `position`.
 *
 * The seven exclusions the validation door applies (src/validate.ts,
 * `checkValidation`), in one predicate, because the QA of 2026-09-12 found
 * three copies of the rule that did not agree. The door refused all seven;
 * derivation's own `mayValidate` applied three of them, so a record the door
 * would never have taken was counted by derivation if the log held one anyway;
 * and the verification precondition counted every registered non-maintainer
 * outside the submitter as an eligible operator, so a governance entry passed a
 * precondition that says three operators could sign it in a world where two
 * could. One predicate, asked in all three places, is the only shape in which
 * those cannot drift again.
 *
 * The seven, in the door's own order and its own refusal names:
 *
 * 1. `unregistered_operator` — Section 5, "only verified operators can
 *    validate", so an operator the log has not registered at this position is
 *    nobody.
 * 2. `submitter_operator` — Identity and operators: "No agent under the
 *    submitter's operator may validate that submitter's entry." A bare-key
 *    submitter has no operator and bars none.
 * 3. `original_signer` — Section 6, "Dispute": a challenge passes through the
 *    same validation with "one extra exclusion: no operator that signed the
 *    original, submitter or validator, may validate the challenge against it."
 *    Empty for an ordinary entry, which is why every entry that is not a
 *    challenge is judged exactly as it always was.
 * 4. `maintainer_operator` — Section 5: verification comes from outside the
 *    maintainer.
 * 5. `provider_operator` — Section 10 and D-096: the domain's excluded parties
 *    may not be operators in it at all, so they may not judge its entries.
 * 6. `subject_authority` — D-096: the authority the entry's subject names is
 *    the party the entry is about. Empty for every domain whose
 *    `subject_authority` is false (ai-ecosystem) and for every subject with no
 *    authority row.
 * 7. `operator_not_in_domain` — D-071: the independence attestation is per
 *    domain, so eligibility is too.
 *
 * Read at a position like every other rule here (retrospective M8): an
 * operator's registration, its domains and the dispute it is barred from are
 * all read as they stood, so a decision keeps its verdict when the registry
 * later moves.
 */
export function mayValidateEntry(
  events: readonly Event[],
  position: number,
  target: EligibilityTarget,
  operator: string,
): boolean {
  const registered = registeredOperatorsAt(events, position);
  return (
    eligibilityRefusal(operator, {
      // 1.
      registered: registered.operators.has(operator),
      // 2.
      authorOperator: target.authorOperator,
      // 3. A thunk, because answering it means walking the challenged entry and
      // an entry that is not a correction has nothing to walk. The predicate
      // asks it only once the cheaper rules have let the operator through.
      originalSigners: () =>
        originalSignersAt(events, position, target.id),
      // 4.
      maintainer: registered.maintainers.has(operator),
      // 5. Pure policy: the domain's own excluded-party list, off
      // src/registry.ts. Asked only of a registered domain: the submit door
      // refuses an unregistered one, but a sealed log may hold a core naming a
      // domain this build does not know, and derivation answers about the log
      // it is given rather than throwing. A domain with no published
      // excluded-party list excludes nobody by it.
      provider:
        isRegisteredDomain(target.domain) &&
        isExcludedParty(target.domain, operator),
      // 6. The hosts of the authority the subject names, off src/policy.ts.
      authorityHosts: authorityHostsFor(target.domain, target.subject),
      // 7. Attested in the entry's own domain. A registration sealed before
      // v0.7 carries no domain and reads as the default one, as
      // `operatorDomainsAt` says.
      domain: target.domain,
      attestedIn: operatorDomainsAt(events, position).get(operator),
    }) === null
  );
}

/**
 * The operators that signed the entry this one challenges, or none.
 *
 * Section 6, "Dispute", through src/dispute.ts's `disputeExclusions`, which is
 * the one place that says who "signed the original" means: the target's
 * submitter operator, when it has one, and every operator that signed a
 * decision on it, approve or reject alike.
 *
 * The filing is read as it stood at `position` — a filing already settled by a
 * `dispute_upheld` or `dispute_failed` is no longer in force — and the target is
 * read through the filing's own position, because who had signed the original
 * when the challenge was filed is what the door judged against. A challenged
 * entry is verified and closed and gains no further approver after it, so the
 * two answers are the same answer.
 */
function originalSignersAt(
  events: readonly Event[],
  position: number,
  correctionId: string,
): readonly string[] {
  let filed: Event<"dispute_filed"> | null = null;
  const settled = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (isType(event, "dispute_filed")) {
      if (event.payload.correction_entry_id === correctionId) filed = event;
      continue;
    }
    if (isType(event, "dispute_upheld") || isType(event, "dispute_failed")) {
      settled.add(event.payload.correction_entry_id);
    }
  }
  if (filed === null || settled.has(correctionId)) return [];
  const targetId = filed.entry_id;
  if (targetId === null) return [];

  let authorOperator: string | null = null;
  const approvers: ApproverRecord[] = [];
  for (const event of inSeqOrder(events)) {
    if (event.seq > filed.seq) break;
    if (isType(event, "entry_submitted")) {
      if (event.payload.core["id"] !== targetId) continue;
      authorOperator =
        (event.payload.core["author_operator"] as string | null) ?? null;
      continue;
    }
    if (isType(event, "validation") && event.entry_id === targetId) {
      approvers.push(event.payload.record);
    }
  }
  return disputeExclusions({ author_operator: authorOperator, approvers });
}

/**
 * Lifecycle of an entry: "Verification has two preconditions: three verified
 * operators outside the submitter's own, and a non-empty trusted pool to draw
 * the random validator from."
 *
 * "Outside the submitter's own" is not the only thing that puts an operator
 * outside reach. The QA of 2026-09-12: this counted every registered
 * non-maintainer that was not the submitter, including operators the entry's
 * own rules bar from ever signing it — the domain's excluded parties, the
 * operators under the subject's authority, and everyone not attested in the
 * entry's domain — so an ai-governance entry could clear a precondition that
 * promises three possible signers while only two could ever sign. The
 * precondition now counts the operators that `mayValidateEntry` says could
 * actually sign this entry, which is the only reading under which the sentence
 * means anything: a count of validators that cannot validate is not a count of
 * validators.
 */
function preconditionsMet(
  events: readonly Event[],
  position: number,
  target: EligibilityTarget,
  trustedCount: number,
): boolean {
  if (trustedCount === 0) return false;
  const registered = registeredOperatorsAt(events, position);
  let outside = 0;
  for (const operator of registered.operators) {
    if (!mayValidateEntry(events, position, target, operator)) continue;
    outside += 1;
  }
  return outside >= VERIFICATION_MIN_OUTSIDE_OPERATORS;
}

/**
 * The entry carries the decision, never the envelope signature that delivered
 * it: `approvers[]` items are exactly the schema's approver shape.
 */
function stripSignature<T>(record: T): T {
  const copy = { ...(record as Record<string, unknown>) };
  delete copy["signature"];
  return copy as T;
}

/** The date part of an ISO 8601 date-time; `last_confirmed` is a date. */
function dateOf(timestamp: string): string {
  return timestamp.slice(0, 10);
}

/**
 * The UTC calendar date an instant falls on, whatever offset it was written
 * with. `expires_at` is a date (schema format `date`), so comparing it to the
 * clock is a comparison of calendar days, never of instants.
 */
function utcDateOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

function startOfDayMs(date: string): number {
  return Date.parse(`${date}T00:00:00.000Z`);
}

/** A UTC date, `days` after `date`. Milliseconds arithmetic, no wall clock. */
function datePlusDays(date: string, days: number): string {
  const shifted = startOfDayMs(date) + days * MILLISECONDS_PER_DAY;
  return new Date(shifted).toISOString().slice(0, 10);
}

/** The submitted core and author signature for an entry, or null if unknown. */
function submissionOf(
  events: readonly Event[],
  entryId: string,
): PayloadOf<"entry_submitted"> | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    if (event.payload.core["id"] !== entryId) continue;
    return event.payload;
  }
  return null;
}

/**
 * Freshness and decay: "Every entry carries a last-confirmed date. Volatile
 * facts carry a staleness window from that date ... Event categories carry no
 * window, because once they happened they stay true." A reconfirmation
 * "advances the derived last-confirmed date, reopens the freshness window".
 */
function freshnessOf(
  events: readonly Event[],
  entryId: string,
  core: Core,
  clock: Clock,
): {
  staleness_window_days: number | null;
  last_confirmed: string;
  expires_at: string | null;
  stale: boolean;
  reconfirmations: readonly ReconfirmationRecord[];
} {
  const reconfirmations: ReconfirmationRecord[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "reconfirmation")) continue;
    if (event.entry_id !== entryId) continue;
    reconfirmations.push(stripSignature(event.payload.record));
  }

  // The latest reconfirmation is the last one in log order, not the one with
  // the greatest signed_at: append position is the sealed truth, so a
  // reconfirmer cannot extend its window by forward-dating signed_at.
  const latest = reconfirmations[reconfirmations.length - 1];
  const lastConfirmed =
    latest === undefined
      ? dateOf(core["submitted_at"] as string)
      : dateOf((latest as unknown as ReconfirmationFields).signed_at);

  const window = stalenessWindowDays(domainOf(core), core["category"]);
  const expiresAt = window === null ? null : datePlusDays(lastConfirmed, window);
  // The schema: stale is "True when expires_at is in the past". `expires_at` is
  // a calendar date, so the expiry date itself is still fresh (day 90) and the
  // day after it is stale (day 91), whatever time of day the clock reads.
  const stale = expiresAt !== null && utcDateOf(clock.now) > expiresAt;

  return {
    staleness_window_days: window,
    last_confirmed: lastConfirmed,
    expires_at: expiresAt,
    stale,
    reconfirmations,
  };
}

/**
 * Whether a later version of the same model has verified (decision D-096).
 *
 * schema/nomankind-domain-registry-v1.md, "Staleness on a version change": an
 * observation is about the version it was made against, so an entry in one of
 * the version-staleness categories goes stale "from the position of the
 * validation that verifies another entry of the same domain, in one of those
 * categories, whose subject shares the party and model segments and differs in
 * the version segment".
 *
 * Read off the events and nothing else, which is what makes "from the position"
 * true without a position argument: the sibling counts once the log handed in
 * holds the validation that verified it, and a log that stops one event earlier
 * answers false. `expires_at` is untouched -- this is a fact about the world
 * having moved, not about the clock -- and it never clears, because the
 * sibling's verification never unhappens.
 *
 * The sibling must have been submitted after this entry: a version observed
 * before this one is an older version, and an older version's entry verifying
 * says nothing about this one.
 */
export function isVersionStale(
  events: readonly Event[],
  entryId: string,
): boolean {
  const submission = submissionOf(events, entryId);
  if (submission === null) return false;
  const core = submission.core;
  const domain = domainOf(core);
  if (!isVersionStalenessCategory(domain, core["category"])) return false;
  const own = versionedSubjectOf(core["subject"]);
  if (own === null) return false;

  let ownSeq: number | null = null;
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    if (event.payload.core["id"] === entryId) {
      ownSeq = event.seq;
      continue;
    }
    if (ownSeq === null) continue;

    const other = event.payload.core;
    const otherId = other["id"] as string;
    if (domainOf(other) !== domain) continue;
    if (!isVersionStalenessCategory(domain, other["category"])) continue;
    const later = versionedSubjectOf(other["subject"]);
    if (later === null) continue;
    if (later.prefix !== own.prefix) continue;
    if (later.version === own.version) continue;

    const consensus = consensusFor(events, otherId, other);
    if (consensus.status === "verified") return true;
  }
  return false;
}

/**
 * Freshness and decay: the superseding entry "names the superseded entry inside
 * the new entry's frozen, signed core ... and the old entry's superseded-by
 * pointer is derived from it". The approvals are the check, so a superseding
 * entry that never verified changes nothing. Earliest such entry by position
 * wins.
 *
 * And: "A superseding entry must share its target's subject and category".
 * That rule lives in src/supersede.ts and is asked there, never restated here:
 * a candidate the link check refuses is not a superseder at all, however its own
 * validators voted. The lookup answers for this entry alone, because this entry
 * is the only target in question.
 */
function supersededBy(
  events: readonly Event[],
  entryId: string,
  target: Core,
): string | null {
  const lookup = (id: string): Core | null => (id === entryId ? target : null);
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    const core = event.payload.core;
    if (core["supersedes"] !== entryId) continue;
    const candidateId = core["id"] as string;
    if (candidateId === entryId) continue;
    if (!checkSupersedes(core, lookup).ok) continue;
    const candidate = consensusFor(events, candidateId, core);
    if (candidate.status === "verified") return candidateId;
  }
  return null;
}

/**
 * The schema's `disputes[]` array, folded from the target's own events.
 *
 * Lifecycle of an entry, Dispute: "A challenge is itself an entry, in the
 * correction category, and it requires a citation ... The original stays in the
 * log, marked overturned, linked to its correction." The array is the record of
 * every challenge against this entry, upheld, failed or still open, in the order
 * they were filed.
 *
 * `citation` and `snapshot_hash` come off the `dispute_filed` event, which
 * copied them from the correction's core: the fold reads this entry's events and
 * nothing else, so a reader holding only the target's sub-sequence of the log
 * can rebuild the array exactly.
 *
 * A `dispute_upheld` with no `dispute_filed` before it produces no row. The
 * event still overturns the entry (`overturnedBy` below reads it on its own),
 * because it always has; but a disputes[] item needs a challenger, a citation
 * and a snapshot hash, and inventing them would be a lie.
 */
function disputesFor(
  events: readonly Event[],
  entryId: string,
): readonly Record<string, unknown>[] {
  const outcomes = new Map<
    string,
    { outcome: "upheld" | "failed"; reason: string | null; at: string }
  >();
  for (const event of inSeqOrder(events)) {
    if (event.entry_id !== entryId) continue;
    if (isType(event, "dispute_upheld")) {
      const id = event.payload.correction_entry_id;
      if (!outcomes.has(id)) {
        outcomes.set(id, { outcome: "upheld", reason: null, at: event.at });
      }
    } else if (isType(event, "dispute_failed")) {
      const id = event.payload.correction_entry_id;
      if (!outcomes.has(id)) {
        outcomes.set(id, {
          outcome: "failed",
          reason: event.payload.reason,
          at: event.at,
        });
      }
    }
  }

  const disputes: Record<string, unknown>[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== entryId) continue;
    const settled = outcomes.get(event.payload.correction_entry_id) ?? null;
    disputes.push({
      id: event.payload.correction_entry_id,
      challenger: event.payload.challenger,
      operator: event.payload.operator,
      citation: event.payload.citation,
      snapshot_hash: event.payload.snapshot_hash,
      outcome: settled === null ? "open" : settled.outcome,
      reason: settled === null ? null : settled.reason,
      filed_at: event.at,
      resolved_at: settled === null ? null : settled.at,
    });
  }
  return disputes;
}

/**
 * The schema's `failure_reports[]` array, folded from the target's own events.
 *
 * Whitepaper Section 8: "A reader that acts on a verified entry and fails ...
 * files a signed failure report against the entry, with its transcript frozen
 * and hashed like any artifact." Reports "never change the core or the status by
 * themselves", so nothing here touches the status: the array is what the reports
 * say, and the threshold that acts on them is src/dispute.ts's.
 *
 * `upgraded_to` is filled from the other direction: a `dispute_filed` naming
 * this report's position in `from_report_seq` is what upgraded it, so the link
 * is the log's and never a second field somebody had to remember to set.
 */
function failureReportsFor(
  events: readonly Event[],
  entryId: string,
): readonly Record<string, unknown>[] {
  const upgrades = new Map<number, string>();
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== entryId) continue;
    const from = event.payload.from_report_seq;
    if (from === null || upgrades.has(from)) continue;
    upgrades.set(from, event.payload.correction_entry_id);
  }

  const reports: Record<string, unknown>[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "failure_report")) continue;
    if (event.entry_id !== entryId) continue;
    reports.push({
      reporter: event.payload.reporter,
      operator: event.payload.operator,
      observed: event.payload.observed,
      artifact_hash: event.payload.artifact_hash,
      citation: event.payload.citation,
      upgraded_to: upgrades.get(event.seq) ?? null,
      filed_at: event.at,
    });
  }
  return reports;
}

/**
 * The sidecar's `revalidations`, folded from the target's own events.
 *
 * One view per `revalidation_requested`, in the order they were made, each
 * carrying the draw currently in force and the outcome if the check has landed.
 * A `revalidation_missed` clears the draw rather than the request: Section 6's
 * check is still owed, and the next draw answers it, exactly as a missed
 * validation assignment leaves the entry still needing one.
 */
function revalidationsFor(
  events: readonly Event[],
  entryId: string,
): readonly RevalidationView[] {
  const views = new Map<number, RevalidationView>();
  for (const event of inSeqOrder(events)) {
    if (event.entry_id !== entryId) continue;

    if (isType(event, "revalidation_requested")) {
      views.set(event.seq, {
        request_seq: event.seq,
        requester: event.payload.requester,
        operator: event.payload.operator,
        source: event.payload.source,
        requested_at: event.at,
        assigned: null,
        outcome: "open",
        resolved_at: null,
        checker: null,
        correction_entry_id: null,
      });
      continue;
    }

    if (isType(event, "revalidation_assigned")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      views.set(view.request_seq, {
        ...view,
        assigned: {
          agent: event.payload.agent,
          operator: event.payload.operator,
          deadline: event.payload.deadline,
        },
      });
      continue;
    }

    if (isType(event, "revalidation_missed")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      views.set(view.request_seq, { ...view, assigned: null });
      continue;
    }

    if (isType(event, "revalidation_resolved")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      // The first resolution is the one that counts, as the first verdict on an
      // entry is: a check answered twice is still one check.
      if (view.outcome !== "open") continue;
      views.set(view.request_seq, {
        ...view,
        assigned: null,
        outcome: event.payload.outcome,
        resolved_at: event.at,
        checker: event.payload.checker,
        correction_entry_id: event.payload.correction_entry_id,
      });
    }
  }
  return [...views.values()].sort(
    (left, right) => left.request_seq - right.request_seq,
  );
}

// ---------------------------------------------------------------------------
// The bootstrap label (decision D-128)
// ---------------------------------------------------------------------------

/**
 * The event type the public-confirmation door seals, named here because the
 * clearing rule below has to know it.
 *
 * It is deliberately a string and not an `EventType`. It was written before
 * the type existed (D-128, one milestone ahead of D-136's door) and it stays a
 * string now that it does: the fold reads every event's type as a string and
 * ignores the ones it does not know, which is what let the door land without
 * touching a line of this rule — and what will let the next one.
 */
export const PUBLIC_CONFIRMATION_EVENT = "public_confirmation";

/** The bootstrap label: the one perimeter every counted validator sat inside. */
export interface BootstrapLabel {
  readonly perimeter: string;
}

/**
 * Whether one public confirmation reproduces what it claims to have checked.
 *
 * The two forms the door will accept: a hash, which reproduces when it is the
 * entry's own snapshot hash, and a span, which reproduces when the confirmer
 * says the span was present. Anything else — an unknown kind, a hash that is
 * not this entry's, a span read absent — reproduces nothing and clears
 * nothing, because a confirmation that did not reproduce the fact is not
 * outside confirmation of it.
 */
function confirmationReproduces(
  check: unknown,
  snapshotHash: string | null,
): boolean {
  if (typeof check !== "object" || check === null) return false;
  const fields = check as Record<string, unknown>;
  const value = fields["value"];
  if (typeof value !== "string") return false;
  if (fields["kind"] === "hash") {
    return snapshotHash !== null && value === snapshotHash;
  }
  if (fields["kind"] === "span") return value === "present";
  return false;
}

/**
 * Whether a handle names somebody inside one of the disclosed perimeters.
 *
 * A confirmation from a key the maintainer already stands behind is not the
 * outside confirmation the label is waiting for, so the handle is resolved two
 * ways: as an operator id in its own right, and as an agent bound to one. Any
 * other handle — a forum account, a name nobody registered — is outside every
 * perimeter, which is the case the door exists for.
 */
function handleInsideAnyPerimeter(
  handle: unknown,
  perimeters: ReadonlyMap<string, string>,
  agentOperators: ReadonlyMap<string, string>,
): boolean {
  if (typeof handle !== "string" || handle === "") return false;
  if (perimeters.has(handle)) return true;
  const operator = agentOperators.get(handle);
  return operator !== undefined && perimeters.has(operator);
}

/**
 * The entry's bootstrap label, or null.
 *
 * Decision D-128. Section 11's genesis is a bootstrap exception stated as
 * such, and an entry every one of whose validators was named into the same
 * disclosed perimeter is that exception showing up in a fact rather than in a
 * policy: the keys are distinct keys and the decision is a real decision, but
 * nobody from outside the maintainer's own grouping has looked at it yet. So
 * the record says so, on the entry, in the word the maintainer disclosed.
 *
 * It clears — derives null — the moment somebody outside does look:
 *
 * - a reconfirmation sealed by an operator outside the perimeter,
 * - a revalidation resolved by one,
 * - or a counted `public_confirmation` from a handle inside no disclosed
 *   perimeter that reproduces the entry (its snapshot hash, or the span read
 *   present).
 *
 * The third is the public-confirmation door (D-136). Its rule was written a
 * milestone before the door, because a label that could only ever be cleared by
 * the record's own operators would be a label the outside world had no way to
 * answer; the fold reads the event's type as a string and ignores every event
 * type it does not know, so the door landed without touching this.
 *
 * "Counted" is the whole weight the third case carries. A comment on a public
 * board is an account's word: anybody can type a hash. It counts only where the
 * confirmer's own key sealed the line's fingerprint into the founding
 * registry's log, proved on the event and rechecked offline — which is the same
 * bar every other clause here meets, a signature by somebody outside.
 *
 * The perimeters are folded over the whole log rather than at the decision's
 * position, unlike every count around it. That is on purpose: the perimeter is
 * not a fact the decision was taken under — it is the maintainer's present
 * disclosure about an operator — and the label reads in the present tense,
 * "every validator of this entry is inside the disclosed perimeter", which is
 * the sentence the entry page prints.
 */
function bootstrapLabelOf(
  events: readonly Event[],
  entryId: string,
  consensus: Consensus,
  snapshotHash: string | null,
): BootstrapLabel | null {
  // An entry nobody has decided has no validator set to be inside anything.
  if (consensus.status === "draft") return null;
  if (consensus.countedOperators.length === 0) return null;

  const perimeters = operatorPerimetersAt(events, Number.MAX_SAFE_INTEGER);
  let perimeter: string | null = null;
  for (const operator of consensus.countedOperators) {
    const named = perimeters.get(operator);
    if (named === undefined) return null;
    if (perimeter === null) perimeter = named;
    else if (perimeter !== named) return null;
  }
  if (perimeter === null) return null;

  const agentOperators = agentOperatorsAt(events, Number.MAX_SAFE_INTEGER);
  const outside = (operator: string | null): boolean =>
    operator !== null && perimeters.get(operator) !== perimeter;

  for (const event of inSeqOrder(events)) {
    if (isType(event, "reconfirmation")) {
      if (event.entry_id !== entryId) continue;
      const record = event.payload.record as unknown as { operator: string };
      if (outside(record.operator)) return null;
      continue;
    }

    if (isType(event, "revalidation_resolved")) {
      if (event.entry_id !== entryId) continue;
      // The operator the check was resolved by, or the one its checker answers
      // for: an upgrade the requester made with no check behind it names
      // neither, and confirms nothing.
      const resolved =
        event.payload.operator ??
        (event.payload.checker === null
          ? null
          : (agentOperators.get(event.payload.checker) ?? null));
      if (outside(resolved)) return null;
      continue;
    }

    // The seam: every other event type is read by name off the payload and
    // ignored unless it is the one the door seals.
    if ((event.type as string) !== PUBLIC_CONFIRMATION_EVENT) continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    const target = payload["entry_id"];
    if (event.entry_id !== entryId && target !== entryId) continue;
    // Counted, and nothing else clears anything (D-136 as amended). A comment
    // is an account's word until its author seals the line's fingerprint into
    // the registry's log under their own key, and the label is a statement
    // about who has looked — not about who has typed.
    if (payload["counted"] !== true) continue;
    if (payload["verdict"] !== "approve") continue;
    if (!confirmationReproduces(payload["check"], snapshotHash)) continue;
    if (handleInsideAnyPerimeter(payload["handle"], perimeters, agentOperators)) {
      continue;
    }
    return null;
  }

  return { perimeter };
}

/**
 * Which line of which comment a confirmation is about.
 *
 * The door may seal one line twice, and exactly once: a statement first read
 * with nothing sealed behind it, and the same statement again once its author
 * seals its fingerprint (src/worker/sweep.ts). Both are in the log — the log
 * never forgets what it knew — and the newer of the two is what the entry says
 * about that line, which is what this key is for.
 */
function confirmationKey(payload: {
  venue: string;
  comment_id: number;
  line: number;
}): string {
  return `${payload.venue}:${payload.comment_id}:${payload.line}`;
}

/**
 * Every public confirmation about one entry, oldest first (decision D-136).
 *
 * A fold and nothing more: the events are read in seq order, each payload is
 * read by name through src/confirm.ts — so an event sealed by a build this one
 * does not know is skipped rather than half-read — and nothing is judged. One
 * row per line of per comment: a line sealed twice, uncounted and then counted,
 * shows as the newer of the two, in the place the first one took, so the order
 * is the order the statements were made in and not the order they were proved
 * in.
 *
 * `counted` is read off the event and never recomputed here. It is a fact
 * established at ingestion — the confirmer's own key had sealed this line's
 * fingerprint into the registry's log, with the proof on the event — and the
 * offline verifier is what rechecks it (src/verify.ts). A derivation that
 * decided it would be deciding a question about cryptography that it has no
 * business asking in a synchronous fold.
 */
export function confirmationsFor(
  events: readonly Event[],
  entryId: string,
): PublicConfirmationView[] {
  const byLine = new Map<string, PublicConfirmationView>();
  const order: string[] = [];
  for (const event of inSeqOrder(events)) {
    const payload = confirmationPayloadOf(event);
    if (payload === null) continue;
    if (event.entry_id !== entryId && payload.entry_id !== entryId) continue;
    const key = confirmationKey(payload);
    if (!byLine.has(key)) order.push(key);
    byLine.set(key, {
      venue: payload.venue,
      handle: payload.handle,
      verdict: payload.verdict,
      check: payload.check,
      reason: payload.reason,
      posted_at: payload.posted_at,
      registry_event_id: payload.registry_event_id,
      counted: payload.counted,
      seq: event.seq,
    });
  }
  return order.map((key) => byLine.get(key)!);
}

/**
 * The bootstrap label for one entry, folded from the log alone.
 *
 * The seam builder C's public-confirmation door plugs into, and the function
 * every reader outside derivation should call: `deriveEntry` computes the same
 * answer from the consensus it already holds, and this re-folds it for a
 * caller that has only the events.
 */
export function bootstrapLabelFor(
  events: readonly Event[],
  entryId: string,
): BootstrapLabel | null {
  const submission = submissionOf(events, entryId);
  if (submission === null) return null;
  const core = submission.core;
  const snapshotHash = core["snapshot_hash"];
  return bootstrapLabelOf(
    events,
    entryId,
    consensusFor(events, entryId, core),
    typeof snapshotHash === "string" ? snapshotHash : null,
  );
}

/**
 * Lifecycle of an entry, Dispute: "An upheld challenge ... overturns the entry
 * ... The original stays in the log, marked overturned, linked to its
 * correction."
 */
function overturnedBy(events: readonly Event[], entryId: string): string | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_upheld")) continue;
    if (event.entry_id !== entryId) continue;
    return event.payload.correction_entry_id;
  }
  return null;
}

/** Every entry id in the log, in submission order. */
function submittedEntryIds(events: readonly Event[]): readonly string[] {
  const ids: string[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    ids.push(event.payload.core["id"] as string);
  }
  return ids;
}

/**
 * Derive one entry from the log.
 *
 * Throws when the log holds no `entry_submitted` event for `entryId`: there is
 * nothing to derive, and a made-up empty entry would be a lie.
 */
export function deriveEntry(
  events: readonly Event[],
  entryId: string,
  clock: Clock,
  entrySeals: ReadonlyMap<string, EntrySeal> = new Map(),
): DerivedEntry {
  const submission = submissionOf(events, entryId);
  if (submission === null) {
    throw new Error(`deriveEntry: no entry_submitted event for ${entryId}`);
  }
  const core = submission.core;

  const consensus = consensusFor(events, entryId, core);
  const freshness = freshnessOf(events, entryId, core, clock);
  const overturned = overturnedBy(events, entryId);
  // An overturned entry carries no supersession pointer, and neither does a
  // rejected one. The QA of 2026-09-12 found the two answered differently: a
  // rejected entry never reaches `supersededBy` at all, while an entry that was
  // superseded and then overturned kept the pointer beside its `overturned_by`,
  // so the record said both "this was replaced by the current fact" and "this
  // was never true". Those are different claims and only the dispute's is the
  // verdict. `superseded_by` means a successor stands in this entry's place;
  // an upheld challenge says nothing stands in it, so the pointer goes with the
  // status. The supersession is not lost — the superseding entry still names
  // its target in its own signed core, and the log still holds both events.
  const superseded =
    consensus.status === "verified" && overturned === null
      ? supersededBy(events, entryId, core)
      : null;

  let status: EntryStatus = consensus.status;
  if (superseded !== null) status = "superseded";
  // An upheld dispute is the stronger verdict: it says the entry was never
  // true, where supersession only says it stopped being current.
  if (overturned !== null) status = "overturned";

  const derived: DerivedFields = {
    status,
    staleness_window_days: freshness.staleness_window_days,
    verified_at: consensus.verifiedAt,
    last_confirmed: freshness.last_confirmed,
    expires_at: freshness.expires_at,
    // The clock's answer, or the world's: D-096 makes an observation stale when
    // a later version of the same model verifies, whatever the calendar says,
    // and leaves `expires_at` exactly where the window put it.
    stale: freshness.stale || isVersionStale(events, entryId),
    superseded_by: superseded,
    overturned_by: overturned,
    confidence: null,
  };

  const sidecar: Sidecar = {
    needs_replacement: consensus.needsReplacement,
    effective_tier: consensus.effectiveTier,
    test_verdict: consensus.testVerdict,
    trusted_count_at_decision: consensus.trustedCountAtDecision,
    read_share_slots: readShareSlotsFor(consensus),
    revalidations: revalidationsFor(events, entryId),
    // Read off the signed core, the domain's published tables and where the
    // citation landed, so a legacy v0.6 core -- which names no domain and reads
    // as the default one through `domainOf` -- is classified exactly as a v0.7
    // core citing the same page is.
    //
    // The landing is the submission event's own `final_url` (decision D-080,
    // the QA of 2026-09-13): the class was read off the citation alone, so an
    // official host that redirected to a third party was refused by the door on
    // the weaker class and then stored under the stronger one — the sidecar and
    // the refusal disagreed about the same two URLs. `capturedSourceClass`
    // takes the weaker of the two and never the stronger, and an event with no
    // `final_url` — everything sealed before that QA, and every artifact
    // nobody fetched — answers exactly what the citation alone answered.
    source: capturedSourceClass(
      domainOf(core),
      core["subject"],
      core["citation"],
      submission.final_url ?? null,
    ),
    // What the outside said in public about this entry (D-136). Shown, never
    // counted into a status: the list and the label below are the whole of
    // what a confirmation does to a record.
    confirmations: confirmationsFor(events, entryId),
    // Off the consensus already folded above, so the label and the counts it
    // is a statement about can never come from two readings of the log.
    bootstrap: bootstrapLabelOf(
      events,
      entryId,
      consensus,
      typeof core["snapshot_hash"] === "string"
        ? (core["snapshot_hash"] as string)
        : null,
    ),
  };

  const entry: Record<string, unknown> = {};
  for (const key of CORE_KEYS) entry[key] = core[key];
  entry["signature"] = submission.signature;
  entry["approvers"] = consensus.approvers;
  entry["reconfirmations"] = freshness.reconfirmations;
  entry["disputes"] = disputesFor(events, entryId);
  entry["failure_reports"] = failureReportsFor(events, entryId);
  entry["seal"] = entrySeals.get(entryId) ?? null;
  entry["staleness_window_days"] = derived.staleness_window_days;
  entry["verified_at"] = derived.verified_at;
  entry["last_confirmed"] = derived.last_confirmed;
  entry["expires_at"] = derived.expires_at;
  entry["stale"] = derived.stale;
  entry["superseded_by"] = derived.superseded_by;
  entry["overturned_by"] = derived.overturned_by;
  entry["status"] = derived.status;
  entry["confidence"] = derived.confidence;

  return { entry: entry as Entry, derived, sidecar };
}

/** Derive every entry in the log, keyed by entry id. */
export function deriveAll(
  events: readonly Event[],
  clock: Clock,
  entrySeals: ReadonlyMap<string, EntrySeal> = new Map(),
): Map<string, DerivedEntry> {
  const derived = new Map<string, DerivedEntry>();
  for (const entryId of submittedEntryIds(events)) {
    derived.set(entryId, deriveEntry(events, entryId, clock, entrySeals));
  }
  return derived;
}

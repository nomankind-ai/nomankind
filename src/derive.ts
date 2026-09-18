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
import { confirmationPayloadOf, type ConfirmationLine } from "./confirm.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  attestationFor,
  authorityHostsFor,
  communityCapPerEntry,
  countingCommunities,
  isSingleCountingCommunity,
  ACCOUNT_BINDING_SUNSET,
  ACCOUNT_BINDING_TIERS,
  COMMUNITY_MIN_ACCOUNTS,
  COMMUNITY_MIN_COMMUNITIES,
  PERIMETER_WORD,
  CONFIRMATION_VENUES,
  DEFAULT_DOMAIN,
  isRegisteredDomain,
  REJECTIONS_TO_REJECT,
  BINDING_RUNGS,
  isVersionStalenessCategory,
  stalenessWindowDays,
  TRUSTED_POOL_SWITCH,
  versionedSubjectOf,
  VERIFICATION_CLASSES,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  type BindingRung,
  type OperatorKind,
  type VerificationClass,
} from "./policy.js";
import {
  communityOperatorId,
  isExcludedParty,
  isPerimeterOperator,
} from "./registry.js";
import { retiredAgentsAt } from "./rotation.js";
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
  CommunityBinding,
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
export const DERIVATION_VERSION = "2026-09-18-d142";

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
  /**
   * Who met this entry's consensus, disclosed in one word (decision D-138).
   *
   * `registered` when domain operators alone met it, `mixed` when domain
   * operators took part and community operators were needed to reach it, and
   * `community` otherwise. Null while the entry is draft or rejected: there is
   * no consensus to be a statement about.
   *
   * Sealed history. It is derived from the validators counted at the decision
   * seal and never relabelled: later, stronger evidence is an additive dated
   * layer in `verification_layers`, because an entry that says `community`
   * today and `registered` tomorrow would be a record editing what it already
   * said. D-128's bootstrap label is one case of the same disclosure and is
   * unchanged beside it.
   */
  readonly verification_class: VerificationClass | null;
  /**
   * The distinct communities among the counted community validators at the
   * decision, in the order they were counted; empty when there were none.
   */
  readonly verification_communities: readonly string[];
  /**
   * Whether exactly one community signed this entry.
   *
   * Disclosed rather than punished: the class stays `community`, and the entry
   * page reads "community (single venue)". A reader who thinks one board is
   * one party can act on it; nothing in the rules does.
   */
  readonly verification_single_venue: boolean;
  /**
   * The weakest binding among the validators counted in the promoting
   * consensus (decision D-142), or null while the entry has verified nothing.
   *
   * `key` when every counted validator stood on a key the world can check — a
   * domain operator, or a community operator bound by registry or by profile.
   * `account` when at least one counted line rested on nothing but a board
   * having authenticated its author. The weakest and not the strongest, because
   * this is a floor a reader can rely on: an entry that says `key` was decided
   * by keys alone, and one that says `account` tells the reader exactly which
   * rung its weakest seat stood on.
   *
   * Disclosed on every entry and sealed like the class beside it: a later line
   * from a key-bound operator is an additive layer, never a relabel. The read
   * doors take it as `min_binding` (D-142), which is why the order lives in
   * src/policy.ts's `BINDING_RUNGS` rather than here.
   *
   * Absent on a row stored before the decision, which reads as null. Every
   * reader takes it as `verification_binding ?? null`.
   */
  readonly verification_binding: BindingRung | null;
  /**
   * The dated layers of evidence behind this entry, oldest first (D-138 item
   * 11): the decision itself, then one per reconfirmation by a domain operator
   * on an entry whose decision class was `community` or `mixed`.
   *
   * Additive and never a relabel. A community-class entry a domain operator
   * later reconfirms is still a community-class entry — that is what happened —
   * with a registered layer dated after it, which is the honest shape of "the
   * evidence got stronger later".
   *
   * Empty while the entry is draft or rejected.
   */
  readonly verification_layers: readonly VerificationLayer[];
}

/**
 * One dated layer of evidence behind an entry (decision D-138 item 11).
 *
 * `kind` is `decision` for the consensus that promoted the entry and
 * `reconfirmation` for a later check that added to it. `class` is what that
 * layer was: the decision's own class, or `registered` for a reconfirmation by
 * a domain operator, which is the stronger evidence the layer exists to record.
 * `seq` and `at` are the position and the time of the event, so the layers read
 * as a dated history rather than as a verdict. `operator` is who added the
 * layer, and null on the decision, which was a set of validators and not one.
 *
 * `binding` is the rung the layer stood on (decision D-142): the consensus's
 * own weakest seat on the decision, and `key` on every reconfirmation that
 * makes a layer, because only a key-bound or registered operator makes one. It
 * is what turns "the evidence got stronger later" from a sentence about the
 * class into a fact a reader can see — an account-bound consensus with a
 * key-bound layer under it is exactly that sentence, told in two dated lines.
 */
export interface VerificationLayer {
  readonly kind: "decision" | "reconfirmation";
  readonly class: VerificationClass;
  readonly binding: BindingRung;
  readonly seq: number;
  readonly at: string;
  readonly operator: string | null;
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
  /**
   * The attestation version the line carried, or null when it attested none
   * (decision D-140 item 7). Inside the fingerprint the confirmer signed, so
   * the entry page can say which sentence the line stood behind.
   */
  readonly attestation_version: string | null;
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
    if (isType(event, "agent_bound")) {
      operators.set(event.payload.agent, event.payload.operator);
      continue;
    }
    // A rotation is both halves at once (D-095, D-097 item 3, D-140 item 5):
    // the retired key stops answering for the operator here and the new one
    // starts. Read at a position like everything else, so an agent retired at
    // seq 40 still answers for its operator at 39 — every signature it made
    // before the rotation is as good as it ever was, and losing a key is not a
    // way to unmake what it signed.
    if (!isType(event, "key_rotated")) continue;
    const payload = event.payload;
    if (typeof payload.new_agent === "string" && payload.new_agent !== "") {
      operators.set(payload.new_agent, payload.operator);
    }
    if (typeof payload.retired_agent === "string") {
      operators.delete(payload.retired_agent);
    }
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

// ---------------------------------------------------------------------------
// The community operators (decision D-138)
// ---------------------------------------------------------------------------

/** One community operator, as the log registered it. */
export interface CommunityOperator {
  readonly operator: string;
  readonly venue: string;
  readonly handle: string;
  /** The confirmer's key, in the form every agent id has. */
  readonly agent: string;
  readonly binding: CommunityBinding;
  /** The domains it has attested in, registration first, in the log's order. */
  readonly domains: readonly string[];
  /** The position it registered at. */
  readonly seq: number;
}

/**
 * Every community operator the log has registered as of `position`, keyed by
 * its operator id (decision D-138).
 *
 * The community twin of `registeredOperatorsAt` and `operatorDomainsAt` in one
 * fold, because the two facts arrive on the same two events: the registration
 * carries the binding and the domain its attestation named, and each join adds
 * a domain. A second registration of the same operator replaces the binding and
 * keeps the domains, because the fold runs in seq order and an operator does
 * not un-attest a domain by binding its key again.
 *
 * Only events with seq <= position are folded, exactly as every other fold
 * here, so a registration sealed later can never change what a past decision
 * saw.
 */
export function communityOperatorsAt(
  events: readonly Event[],
  position: number,
): Map<string, CommunityOperator> {
  const operators = new Map<string, CommunityOperator>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (isType(event, "community_operator_registered")) {
      const payload = event.payload;
      const held = operators.get(payload.operator);
      const domains = held === undefined ? [] : [...held.domains];
      if (!domains.includes(payload.attestation.domain)) {
        domains.push(payload.attestation.domain);
      }
      operators.set(payload.operator, {
        operator: payload.operator,
        venue: payload.venue,
        handle: payload.handle,
        agent: payload.agent,
        binding: payload.binding,
        domains,
        seq: held?.seq ?? event.seq,
      });
      continue;
    }
    if (isType(event, "community_operator_bound")) {
      const payload = event.payload;
      const held = operators.get(payload.operator);
      // An upgrade of an operator the log never registered is an event about
      // nobody, exactly as a join by one is.
      if (held === undefined) continue;
      // The strongest binding wins, and only forward (decision D-142). An
      // account that publishes a key keeps its id, its standing and its marks
      // and stands on the key from here; an event that named a weaker binding
      // than the one the log already holds would be an operator un-publishing
      // a key it published, which is not a thing a page can say.
      if (rungOf(payload.binding) !== "key") continue;
      // And only on a proof of the kind the binding claims. A rung is a
      // sentence about what a reader can recheck offline, so an upgrade
      // carrying no proof — or a proof of another kind of binding — lifts
      // nothing: it would otherwise be a line saying "trust me, there is a key
      // somewhere", which is the one thing a binding exists to replace. The
      // cryptography is the verifier's half (src/verify.ts,
      // `checkCommunityBindings`); this is the half a synchronous fold can ask,
      // and both have to hold.
      if (payload.proof === null) continue;
      if (payload.proof.kind !== payload.binding.kind) continue;
      operators.set(payload.operator, {
        ...held,
        agent: payload.agent,
        binding: payload.binding,
      });
      continue;
    }
    if (isType(event, "community_operator_joined_domain")) {
      const payload = event.payload;
      const held = operators.get(payload.operator);
      // A join by an operator the log never registered is an event about
      // nobody: derivation answers about the log it is given rather than
      // inventing the registration that would make it mean something.
      if (held === undefined) continue;
      if (held.domains.includes(payload.domain)) continue;
      operators.set(payload.operator, {
        ...held,
        domains: [...held.domains, payload.domain],
      });
    }
  }
  return operators;
}

/**
 * The rung a binding stands on, or null for one that stands on nothing
 * (decision D-142).
 *
 * `registry` and `profile` are `key`: a key publicly bound to something a
 * reader rechecks offline, which is what `COUNTING_BINDING_KINDS` in
 * src/policy.ts has always said counts. `account` is the rung D-142 added — the
 * board authenticated the author, and that is the whole of it.
 *
 * `platform` is null, because a platform's statement about an account is
 * somebody else's assertion and `COUNTING_BINDING_KINDS` has never held it. It
 * was a rule the policy stated and the fold did not ask, so a platform-bound
 * registration was counted here exactly as a key-bound one; introducing the
 * rungs is what makes the question askable, and a line with no rung counts
 * toward nothing.
 */
export function rungOf(binding: CommunityBinding): BindingRung | null {
  if (binding.kind === "registry" || binding.kind === "profile") return "key";
  if (binding.kind === "account") return "account";
  return null;
}

/**
 * What kind of operator each id in the registry is, as of `position`
 * (decision D-138).
 *
 * One registry, two kinds: every `operator_registered` is a `domain` operator
 * and every `community_operator_registered` a `community` one. The ids cannot
 * collide — `isOperatorDomain` refuses the colon a community id is built
 * around — so one map answers for both, which is the whole point of the
 * decision: validation is one thing, and the record says so in one place.
 */
export function operatorKindsAt(
  events: readonly Event[],
  position: number,
): ReadonlyMap<string, OperatorKind> {
  const kinds = new Map<string, OperatorKind>();
  for (const operator of registeredOperatorsAt(events, position).operators) {
    kinds.set(operator, "domain");
  }
  for (const operator of communityOperatorsAt(events, position).keys()) {
    kinds.set(operator, "community");
  }
  return kinds;
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
  /** The class the decision was met at, or null while draft or rejected. */
  readonly verificationClass: VerificationClass | null;
  /** The distinct communities among the counted community approvers. */
  readonly verificationCommunities: readonly string[];
  /**
   * The weakest rung among the counted approvers (D-142), or null while draft
   * or rejected. Sealed with the class beside it and never recomputed later.
   */
  readonly verificationBinding: BindingRung | null;
  /** The `at` of the promoting decision's event; null unless it verified. */
  readonly promotingAt: string | null;
}

/**
 * One decision about an entry, whichever door it came in by (D-138).
 *
 * The consensus rule is one rule, so the fold below reads one list: a
 * `validation` from a domain operator and a `community_validation` from a
 * community operator are the same shape here, and the only thing that
 * remembers which is which is `kind` — which is what the class, the Sybil
 * floor and the per-community cap are about, and nothing else.
 *
 * `record` is what the evidence gate reads. A community validation carries no
 * measurement and no test verdict, so its record is the honest empty one: it
 * is an approval, and it says nothing about a test it did not run.
 */
interface Decision {
  readonly seq: number;
  readonly at: string;
  readonly kind: OperatorKind;
  readonly operator: string;
  readonly venue: string | null;
  readonly decision: "approve" | "reject";
  readonly assignedRandom: boolean;
  readonly signedAt: string;
  readonly record: ApproverRecord;
}

/**
 * Every decision about one entry, both kinds, in seq order.
 *
 * The `validation` events keep their records exactly as they were sealed; each
 * `community_validation` is read into the same shape by name off its payload,
 * so an event sealed by a build this one does not know is skipped rather than
 * half-read.
 */
function decisionsFor(
  events: readonly Event[],
  entryId: string,
): readonly Decision[] {
  const decisions: Decision[] = [];
  for (const event of inSeqOrder(events)) {
    if (isType(event, "validation")) {
      if (event.entry_id !== entryId) continue;
      const record = stripSignature(event.payload.record);
      const fields = record as unknown as DecisionFields;
      decisions.push({
        seq: event.seq,
        at: event.at,
        kind: "domain",
        operator: fields.operator,
        venue: null,
        decision: fields.decision,
        assignedRandom: fields.assigned_random === true,
        signedAt: fields.signed_at,
        record,
      });
      continue;
    }
    if (!isType(event, "community_validation")) continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    // The envelope and the payload have to name the same entry. A
    // `community_validation` carries the id twice — the scope every
    // entry-scoped event has, and the payload's own, so a reader folding the
    // payload alone knows what was validated — and an event whose two halves
    // disagree is an event about two entries at once. It is counted by neither
    // rather than by the half that happens to be read first: a decision that
    // could be pointed at another entry by editing the field nobody checked
    // would be a decision nobody signed.
    if (event.entry_id !== entryId) continue;
    if (payload["entry_id"] !== entryId) continue;
    const operator = payload["operator"];
    const venue = payload["venue"];
    const agent = payload["agent"];
    const decision = payload["decision"];
    if (typeof operator !== "string" || operator === "") continue;
    if (typeof venue !== "string" || venue === "") continue;
    if (decision !== "approve" && decision !== "reject") continue;
    // The token is what makes a counted line a validation (D-138 item 3); an
    // event that names no version is not one this fold counts.
    if (typeof payload["attestation_version"] !== "string") continue;
    const postedAt = payload["posted_at"];
    const signedAt = typeof postedAt === "string" ? postedAt : event.at;
    const reason = payload["reason"];
    decisions.push({
      seq: event.seq,
      at: event.at,
      kind: "community",
      operator,
      venue,
      decision,
      assignedRandom: false,
      signedAt,
      record: {
        agent: typeof agent === "string" ? agent : operator,
        operator,
        decision,
        reason: typeof reason === "string" ? reason : null,
        snapshot_hash: null,
        assigned_random: false,
        test_accepted: null,
        reproduction: null,
        observation: null,
        signed_at: signedAt,
      } as ApproverRecord,
    });
  }
  return decisions;
}

/** One counted approval, as the counts at a position read it (decision D-142). */
interface ApprovingSeat {
  readonly kind: OperatorKind;
  /** The community it spoke from, or null for a domain operator. */
  readonly venue: string | null;
  /** The rung it stood on when it was counted. */
  readonly rung: BindingRung;
}

/** The counts a promotion test is decided on, over the seats that still count. */
interface CountableSeats {
  readonly approvals: number;
  readonly domain: number;
  readonly community: number;
  readonly accounts: number;
  readonly venues: readonly string[];
}

/**
 * The approvals that count at `signedAt`, and the four numbers read off them
 * (decision D-142 item 4).
 *
 * The one place the sunset is applied, so the approval count, the class, the
 * Sybil floor and the list of communities can never disagree about which seats
 * are in the room. Before `ACCOUNT_BINDING_SUNSET` every seat counts; at or
 * after it the account-bound seats count toward nothing — not the approvals,
 * not the floor, not the communities — which is what "they do not count" says.
 *
 * An entry that verified before the instant is untouched by this: its consensus
 * closed at a position this function was asked about then and is never asked
 * about again.
 */
function countableSeats(
  approving: ReadonlyMap<string, ApprovingSeat>,
  signedAt: string,
): CountableSeats {
  const open = isBeforeInstant(signedAt, ACCOUNT_BINDING_SUNSET);
  let approvals = 0;
  let domain = 0;
  let community = 0;
  let accounts = 0;
  const venues: string[] = [];
  for (const seat of approving.values()) {
    if (!open && seat.rung === "account") continue;
    approvals += 1;
    if (seat.kind === "domain") {
      domain += 1;
      continue;
    }
    community += 1;
    if (seat.rung === "account") accounts += 1;
    if (seat.venue !== null && !venues.includes(seat.venue)) {
      venues.push(seat.venue);
    }
  }
  return { approvals, domain, community, accounts, venues };
}

/**
 * Why an account-bound line is out of the rung's scope, or null when it is in
 * (decision D-142 item 3).
 *
 * The one place the two entry-shaped clauses of the scope are decided, so the
 * fold and the rule the sweep asks at ingestion cannot drift: a line the door
 * seals as a validation must be a line the fold counts, and a line the fold
 * will not count should never have been sealed as one.
 *
 * The third clause, the sunset, is not here: it is read at the promoting
 * decision's instant and the promoting decision does not exist yet when the
 * door is deciding what to seal. So the door seals a line the sunset will later
 * refuse to count, exactly as it seals a line a later cap will not reach — and
 * derivation is where that is settled.
 */
function accountScopeRefusal(
  core: Core,
  binding: CommunityBinding | undefined,
  submittedAt: string | null,
): AccountScopeRefusal | null {
  const claimedTier = core["evidence_tier"];
  if (
    typeof claimedTier !== "string" ||
    !(ACCOUNT_BINDING_TIERS as readonly string[]).includes(claimedTier)
  ) {
    return "account_out_of_scope";
  }
  const createdAt =
    binding !== undefined && binding.kind === "account"
      ? binding.account_created_at
      : null;
  // A log that says when neither the account nor the entry began cannot say
  // which came first, and the honest answer to "was the account older?" is no.
  if (submittedAt === null) return "account_too_new";
  if (!isBeforeInstant(createdAt, submittedAt)) return "account_too_new";
  return null;
}

/** The two ways an account-bound line falls outside the rung's scope. */
export type AccountScopeRefusal = "account_out_of_scope" | "account_too_new";

/**
 * How many seats one community still holds at this instant (decision D-142).
 *
 * The cap's own count, taken over the seats that count: an account-bound seat
 * the sunset has dropped is not occupying a place on its board, and a cap that
 * went on counting it would hold that board's last seat empty forever on a rule
 * that had already expired.
 */
function admittedFromVenue(
  counted: ReadonlyMap<string, ApprovingSeat>,
  venue: string,
  at: string,
): number {
  const open = isBeforeInstant(at, ACCOUNT_BINDING_SUNSET);
  let taken = 0;
  for (const seat of counted.values()) {
    if (seat.venue !== venue) continue;
    if (!open && seat.rung === "account") continue;
    taken += 1;
  }
  return taken;
}

/**
 * The instant a decision is judged by the sunset at (decision D-142 item 7 of
 * the review): the later of what the signer said and when the log sealed it.
 *
 * `signed_at` is the signer's own word and nothing checks it, so a key that
 * wanted one more account-bound consensus after the rung closed could simply
 * date its approval to 2031. The event's `at` is the record's own clock at the
 * moment the decision entered the log, and a decision cannot have been taken
 * after it was sealed — so the later of the two is the earliest instant the
 * decision can honestly claim, and the sunset is read there.
 *
 * Every other rule in this fold goes on reading `signed_at`: this one is about
 * a deadline, and a deadline is the one kind of rule a backdated claim can buy
 * something from.
 */
function decisionInstant(decision: Decision): string {
  const signed = Date.parse(decision.signedAt);
  const sealed = Date.parse(decision.at);
  if (Number.isNaN(signed)) return decision.at;
  if (Number.isNaN(sealed)) return decision.signedAt;
  return signed >= sealed ? decision.signedAt : decision.at;
}

/**
 * The operators whose decisions this entry's consensus counted, in the order
 * they were counted, or an empty list while nothing is counted.
 *
 * The fold's own `countedOperators`, re-folded for a caller holding only the
 * log — the offline verifier, which asks whether a line it is looking at is one
 * the consensus counted before it judges the line by the rules that apply to
 * counted lines. One fold and one answer, so the verifier and derivation can
 * never disagree about which lines were in the room.
 */
export function countedOperatorsFor(
  events: readonly Event[],
  entryId: string,
): readonly string[] {
  const submission = submissionOf(events, entryId);
  if (submission === null) return [];
  return consensusFor(events, entryId, submission.core).countedOperators;
}

/**
 * Whether one instant is strictly earlier than another, both parsed.
 *
 * Strict, and false for anything unparseable on either side, because both
 * callers are asking a question the record has to be able to answer from the
 * bytes: an account whose creation date the platform did not publish is an
 * account nobody can say was older than the entry, and the honest answer to
 * "was it created before?" is no. The sunset reads the same way at its own
 * boundary — the instant itself is already after, which is what "at or after"
 * means (D-142 item 4).
 */
function isBeforeInstant(value: string | null, limit: string): boolean {
  if (value === null) return false;
  const at = Date.parse(value);
  const bound = Date.parse(limit);
  if (Number.isNaN(at) || Number.isNaN(bound)) return false;
  return at < bound;
}

/**
 * The instant this entry was submitted, as the account rung's age rule reads it
 * (decision D-142 item 3).
 *
 * The submission event's own `signed_at` where the payload carries one, and the
 * core's `submitted_at` otherwise — the same field the schema publishes and the
 * author signed. Null when the log holds neither, which makes every account
 * binding fail the age rule rather than pass it: a comparison against a missing
 * instant is not a comparison anyone should be counted on.
 */
function submittedInstantOf(
  events: readonly Event[],
  entryId: string,
  core: Core,
): string | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    if (event.entry_id !== entryId) continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    const signedAt = payload["signed_at"];
    if (typeof signedAt === "string" && signedAt !== "") return signedAt;
    break;
  }
  const submittedAt = core["submitted_at"];
  return typeof submittedAt === "string" && submittedAt !== ""
    ? submittedAt
    : null;
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
  /**
   * The counted approvals, one per distinct operator, in the order they were
   * counted: which kind of operator it was, which community it spoke from, and
   * which rung it stood on (decision D-142).
   *
   * One structure and not five sets, because the sunset makes every count a
   * question asked at a position: at or after `ACCOUNT_BINDING_SUNSET` the
   * account-bound approvals are not counted, and the approval count, the class,
   * the Sybil floor and the communities all have to agree about which
   * approvals those are. Five sets that each dropped the same seats would be
   * the one rule written five times.
   */
  const approving = new Map<string, ApprovingSeat>();
  const rejectingOperators = new Set<string>();
  // The counted decisions themselves, one per distinct eligible operator and in
  // seq order: the same records the counts above are built from, kept so the
  // evidence gate reads exactly what consensus counted.
  const countedRecords: ApproverRecord[] = [];
  /**
   * The counted decisions, one per distinct eligible operator, with the seat
   * each one took: which kind of operator, which community, which rung.
   *
   * A map rather than a set since D-142, because the per-community cap is now
   * a question asked at a position — the seats an expired rung left are seats
   * nobody is sitting in.
   */
  const counted = new Map<string, ApprovingSeat>();
  // How many communities count at all, read once: the cap and the floor below
  // are both functions of this one number, and src/policy.ts is where each of
  // them is decided.
  const countingCommunityCount = countingCommunities().length;
  const capPerEntry = communityCapPerEntry(countingCommunityCount);
  let hasRandomApproval = false;
  let status: "draft" | "rejected" | "verified" = "draft";
  let verifiedAt: string | null = null;
  let trustedCountAtDecision: number | null = null;
  let effectiveTier: EvidenceTier | null = null;
  let testVerdictAtDecision: TestVerdict | null = null;
  let needsReplacement = false;
  let promotingSeq: number | null = null;
  let promotingAt: string | null = null;
  let verificationClass: VerificationClass | null = null;
  let verificationCommunities: readonly string[] = [];
  let verificationBinding: BindingRung | null = null;
  // When this entry was submitted, which is half of what the account rung is
  // judged against (D-142 item 3): an account made after the entry was
  // submitted is an account made for it, as far as the record can tell.
  const submittedAt = submittedInstantOf(events, entryId, core);

  for (const decision of decisionsFor(events, entryId)) {
    if (decision.kind === "domain") approvers.push(decision.record);

    // Once verified or rejected the verdict stands: later decisions still land
    // in approvers[], but change nothing.
    if (status !== "draft") continue;

    const position = decision.seq;

    // Nomankind's own accounts (decision D-142). A line from one of them is
    // sealed, shown and disclosed with the perimeter word beside it, and
    // counted toward nothing at any rung — a key it published later does not
    // change that, because what is disqualifying is whose account it is. The
    // record verifying its own entries is the failure the genesis exception
    // exists to leave behind, so this is refused before the rung is even read.
    if (isPerimeterOperator(decision.operator)) continue;

    // Which rung this operator stands on at this position (D-142). The
    // registration's binding, or the strongest one a `community_operator_bound`
    // has since put under it — `communityOperatorsAt` folds both in seq order,
    // so a line is judged by the binding the log held when it was made and
    // never by one published afterwards. A domain operator stands on its DNS
    // name and its attestation, which is a key by any reading.
    let rung: BindingRung | null = "key";
    if (decision.kind === "community") {
      const account = communityOperatorsAt(events, position).get(
        decision.operator,
      );
      rung = account === undefined ? null : rungOf(account.binding);
      // The account rung's scope, through the same rule the door asks at
      // ingestion (D-142 item 3). A line that falls outside it is not refused
      // and not rejected: it is an account statement, sealed and shown,
      // counting toward nothing — which is exactly what a counted line without
      // the token has been since D-136.
      if (
        rung === "account" &&
        accountScopeRefusal(core, account?.binding, submittedAt) !== null
      ) {
        continue;
      }
    }
    // A binding on no rung at all — a `platform` statement about an account —
    // has never been in `COUNTING_BINDING_KINDS`, and now the fold asks.
    if (rung === null) continue;

    // Who may validate at all: `mayValidateEntry`'s seven exclusions, the same
    // seven the door applies, asked here because the log is append-only and
    // derivation must stay safe against a record the door would have refused.
    // Such a record stays in approvers[] — nothing is ever removed — and is
    // counted by nobody. Eligibility is read at the record's own position, like
    // every other rule here, and it is one predicate for both kinds of operator
    // (D-138): a community operator is registered in the same registry and is
    // excluded by the same seven rules.
    // The agent is handed in as well as the operator (D-095, D-097 item 3): a
    // decision signed by a key that had already been retired at this position
    // is counted by nobody, and every decision that key took before its
    // rotation stays exactly where it is.
    if (
      !mayValidateEntry(
        events,
        position,
        target,
        decision.operator,
        decision.record.agent,
      )
    ) {
      continue;
    }

    // The per-community cap (D-138 item 10): only so many of one entry's
    // counted decisions may come from one community, so a single board cannot
    // supply a consensus by itself once a second community signs. Counted per
    // community and not per key, because the accounts on one board are as cheap
    // as each other.
    //
    // Over the seats that still count at this position, and not over every seat
    // ever counted (D-142): an account-bound seat the sunset has dropped
    // occupies nothing, and a cap that went on holding its place would let a
    // rung that no longer counts keep a board's last seat empty forever.
    const venue = decision.venue;
    if (decision.kind === "community" && venue !== null) {
      const taken = admittedFromVenue(counted, venue, decisionInstant(decision));
      if (!counted.has(decision.operator) && taken >= capPerEntry) {
        continue;
      }
    }

    // The first record from an operator is the one that counts, here as in the
    // distinct-operator sets below.
    if (!counted.has(decision.operator)) {
      counted.set(decision.operator, {
        kind: decision.kind,
        venue: decision.kind === "community" ? venue : null,
        rung,
      });
      countedRecords.push(decision.record);
    }

    if (decision.decision === "approve") {
      // Distinct operators: a second record from the same operator is kept but
      // adds no count.
      if (!approving.has(decision.operator)) {
        approving.set(decision.operator, {
          kind: decision.kind,
          venue: decision.kind === "community" ? venue : null,
          rung,
        });
      }
      if (decision.assignedRandom) hasRandomApproval = true;
    } else {
      rejectingOperators.add(decision.operator);
    }

    const trustedCount = trustedOperatorsAt(events, position).size;
    const largePool = trustedCount >= TRUSTED_POOL_SWITCH;
    // The sunset (D-142 item 4), read at this decision's own instant, because
    // this is the decision that would promote the entry. Before it, an
    // account-bound approval forms a consensus like any other; at or after it,
    // it counts toward nothing and the counts below are taken over the seats
    // that remain. A line counted yesterday keeps what it was counted into:
    // nothing here recomputes a decision that closed.
    const seats = countableSeats(approving, decisionInstant(decision));
    const approvals = seats.approvals;
    const rejections = rejectingOperators.size;

    // Genesis by path 2 (D-142): the pool precondition is lifted exactly where
    // the consensus standing at this position is community operators' alone,
    // because that is the consensus that draws nobody.
    const communityOnly = seats.domain === 0 && seats.community > 0;
    if (
      preconditionsMet(events, position, target, trustedCount, communityOnly)
    ) {
      const approvalsToVerify = largePool
        ? APPROVALS_TO_VERIFY_LARGE_POOL
        : APPROVALS_TO_VERIFY_SMALL_POOL;
      // The large pool also wants the beacon-drawn validator among the
      // approvals. The paper says exactly one; "at least one" is what the
      // replacement-draw path can satisfy (retrospective GAPS M9).
      const randomSatisfied = largePool ? hasRandomApproval : true;
      // The Sybil floor, and only where it is the whole of the consensus
      // (D-138 item 10): a consensus met by community operators alone is asked
      // for `COMMUNITY_MIN_ACCOUNTS` distinct bound accounts, and for
      // `COMMUNITY_MIN_COMMUNITIES` distinct communities once more than one
      // community counts at all. A consensus a domain operator took part in is
      // judged exactly as it always was.
      const communityFloorMet =
        seats.domain > 0 ||
        seats.community === 0 ||
        (seats.community >= COMMUNITY_MIN_ACCOUNTS &&
          // "Only while more than one counting community exists" is one
          // sentence and lives in one place, beside the cap it is the twin of
          // (src/policy.ts, `isSingleCountingCommunity`).
          (isSingleCountingCommunity(countingCommunityCount) ||
            seats.venues.length >= COMMUNITY_MIN_COMMUNITIES));
      // Two tiers of evidence: the count says the validators agree, the gate
      // says whether what they brought is enough, and at which tier. The gate is
      // asked only where the count would promote, over exactly the decisions
      // counted so far.
      const countMet =
        approvals >= approvalsToVerify && randomSatisfied && communityFloorMet;
      const gate = countMet ? evidenceGate(core, countedRecords) : null;
      // A gate refusal is never itself a rejection: it only means the approvals
      // do not promote at this position, so this decision is judged as any
      // unpromoted one is. Lifecycle of an entry: two rejections mark the entry
      // rejected, unconditionally — an entry the gate keeps turning away is
      // still rejected once the rejections arrive, and is otherwise asked again
      // at the next counted decision.
      if (countMet && gate !== null && gate.verifiable) {
        status = "verified";
        verifiedAt = decision.signedAt;
        trustedCountAtDecision = trustedCount;
        effectiveTier = gate.effective_tier;
        testVerdictAtDecision = gate.test_verdict;
        promotingSeq = position;
        promotingAt = decision.at;
        // The class, sealed here and never recomputed later (D-138 item 11):
        // domain operators alone is `registered`, community operators alone is
        // `community`, and both is `mixed` — which is the only case where a
        // community approval was *needed*, because domain approvals that met
        // the count on their own would have promoted the entry at an earlier
        // decision, with no community approval counted yet.
        verificationClass =
          seats.community === 0
            ? "registered"
            : seats.domain === 0
              ? "community"
              : "mixed";
        verificationCommunities = [...seats.venues];
        // The rung, sealed beside the class and read the same way (D-142): the
        // weakest binding among the approvers this consensus was counted from.
        // `key` unconditionally for now — no counted line can rest on an
        // account binding until the kernel pass lets one, so saying anything
        // else here would be a disclosure about a rung nothing stands on.
        // The weakest seat in the consensus, sealed here and never recomputed
        // (D-142). Domain operators and key-bound community operators are
        // `key`; one account-bound approval among them makes the floor
        // `account`, because that is what the weakest seat stood on and a
        // reader filtering on it is asking for a floor rather than an average.
        verificationBinding = seats.accounts > 0 ? "account" : "key";
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
    countedOperators: [...counted.keys()],
    verificationClass,
    verificationCommunities,
    verificationBinding,
    promotingAt,
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
  /**
   * The key the decision was signed by, when the caller knows it (D-095, D-097
   * item 3, D-140 item 5).
   *
   * The eighth exclusion, and the only one about a key rather than about an
   * operator: a key retired at or before this position had stopped answering
   * for anybody, so a decision it took after its retirement is counted by
   * nobody. Everything it took before stays counted, because this is asked at
   * the record's own position like every other rule here.
   *
   * Optional, because two of the three callers ask about an operator and not
   * about a key: the verification precondition counts who COULD sign, which is
   * a question about operators, and a caller with no agent in hand is asking
   * exactly that. A rotation never removes an operator, so the precondition's
   * answer is unchanged by leaving it out.
   */
  agent?: string,
): boolean {
  if (
    agent !== undefined &&
    retiredAgentsAt(events, position).has(agent)
  ) {
    return false;
  }
  const registered = registeredOperatorsAt(events, position);
  // One registry, two kinds of operator (D-138): a community operator is
  // registered by the log like any other and is judged by the same seven
  // exclusions. Its domains are the ones its attestation token named — the
  // registration's domain and every domain it has since joined — which is
  // rule 7 asked of it exactly as it is asked of a domain operator.
  const community = communityOperatorsAt(events, position).get(operator);
  return (
    eligibilityRefusal(operator, {
      // 1.
      registered: registered.operators.has(operator) || community !== undefined,
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
      attestedIn:
        community === undefined
          ? operatorDomainsAt(events, position).get(operator)
          : community.domains,
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
  /**
   * Whether the approvals standing at this position are community operators'
   * alone (decision D-142, genesis by path 2).
   *
   * The non-empty trusted pool is a precondition because of what it is FOR:
   * "a non-empty trusted pool to draw the random validator from". A consensus
   * met by community operators alone draws nobody — there is no assignment, no
   * beacon and no seat to fill — so the pool it would have drawn from is a
   * pool nothing needs, and refusing the consensus for its emptiness refuses
   * it for failing to supply something it never asked for. That was genesis's
   * deadlock: a record with no trusted operator could never verify the first
   * entry that would have earned somebody the trust.
   *
   * What stands in its place is the Sybil floor, which is the same guard by
   * another road: `COMMUNITY_MIN_ACCOUNTS` distinct bound accounts,
   * `COMMUNITY_MIN_COMMUNITIES` distinct communities once more than one
   * community counts, and `communityCapPerEntry` over each of them. A domain
   * operator taking part puts the pool back where it was — the draw is real
   * again — so the exemption is exactly as wide as the case it is for.
   */
  communityOnly: boolean,
): boolean {
  if (trustedCount === 0 && !communityOnly) return false;
  const registered = registeredOperatorsAt(events, position);
  let outside = 0;
  // Both kinds of operator (D-138): the precondition counts the operators that
  // could actually sign this entry, and a community operator can. Counting only
  // the domain ones would say three signers do not exist in a world where they
  // do, which is the same miscount the QA of 2026-09-12 found from the other
  // side.
  const candidates = new Set<string>([
    ...registered.operators,
    ...communityOperatorsAt(events, position).keys(),
  ]);
  for (const operator of candidates) {
    // Nomankind's own accounts are not operators outside the submitter
    // (D-142): they may never be counted into a consensus at any rung, so
    // counting them here would promise signers that cannot sign — the same
    // miscount the QA of 2026-09-12 found, from the third side.
    if (isPerimeterOperator(operator)) continue;
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

    // A community operator's validation clears the label too (D-138), and for
    // the same reason a counted confirmation does: it is a signature by
    // somebody outside. Community operators have no perimeter at all — nobody
    // named them into one — so an approving validation that reproduces the
    // entry is exactly the outside look the label was waiting for.
    if (isType(event, "community_validation")) {
      const payload = event.payload as unknown as Record<string, unknown>;
      if (event.entry_id !== entryId) continue;
      if (payload["entry_id"] !== entryId) continue;
      if (payload["decision"] !== "approve") continue;
      // Except nomankind's own accounts (D-142). The label says "every
      // validator counted here sat inside one disclosed perimeter", and a line
      // from an account inside that perimeter is the perimeter looking at
      // itself: it clears nothing, exactly as it counts toward nothing.
      const operator = payload["operator"];
      if (typeof operator === "string" && isPerimeterOperator(operator)) {
        continue;
      }
      if (!confirmationReproduces(payload["check"], snapshotHash)) continue;
      return null;
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
  /** Integer or UUID, whatever the venue calls a comment (D-138 item 2). */
  comment_id: number | string;
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
      attestation_version: payload.attestation_version ?? null,
      seq: event.seq,
    });
  }
  return order.map((key) => byLine.get(key)!);
}

// ---------------------------------------------------------------------------
// The community validations, the class and the layers (decision D-138)
// ---------------------------------------------------------------------------

/** One community validation, as the entry's readers carry it. */
export interface CommunityValidationView {
  readonly operator: string;
  readonly venue: string;
  readonly handle: string;
  readonly agent: string;
  readonly decision: "approve" | "reject";
  readonly check: ConfirmationCheck;
  readonly reason: string | null;
  readonly attestation_version: string;
  readonly fingerprint: string;
  readonly posted_at: string;
  /**
   * The rung the line stood on when it was counted, as the sweep sealed it
   * (decision D-142): `registry`, `profile` or `account`. Null on a row sealed
   * before the decision, which is a line that stood on a key by construction —
   * the account rung did not exist yet — and is read as one nowhere: a null
   * here says "the event did not say", and the fold asks the registry.
   */
  readonly binding_kind: "registry" | "profile" | "account" | null;
  /**
   * The disclosed perimeter word when this line came from one of nomankind's
   * own accounts (decision D-142), else null.
   *
   * Shown and never counted: a reader sees that the record looked at its own
   * entry, and sees that the look moved nothing — not the consensus, not the
   * bootstrap label, not the count of operators outside the submitter.
   */
  readonly perimeter: string | null;
  /** Position of the event in the log, so a reader can go and look at it. */
  readonly seq: number;
}

/**
 * Every community validation of one entry, oldest first (decision D-138).
 *
 * A fold and nothing more: the payloads are read by name, so an event sealed by
 * a build this one does not know is skipped rather than half-read, and nothing
 * here is judged. Which of them the consensus counted is `consensusFor`'s
 * answer, and which of their proofs hold is the verifier's — a synchronous fold
 * has no business deciding a question about cryptography.
 *
 * One row per line of per comment, like the confirmations beside them: a line
 * the door read twice is the newer of the two, in the place the first took.
 */
export function communityValidationsFor(
  events: readonly Event[],
  entryId: string,
): CommunityValidationView[] {
  const byLine = new Map<string, CommunityValidationView>();
  const order: string[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "community_validation")) continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    // Both halves, agreeing, exactly as the fold above asks (D-138).
    if (event.entry_id !== entryId) continue;
    if (payload["entry_id"] !== entryId) continue;
    const operator = payload["operator"];
    const venue = payload["venue"];
    const handle = payload["handle"];
    const decision = payload["decision"];
    const version = payload["attestation_version"];
    const fingerprint = payload["fingerprint"];
    const check = payload["check"];
    if (typeof operator !== "string" || typeof venue !== "string") continue;
    if (typeof handle !== "string") continue;
    if (decision !== "approve" && decision !== "reject") continue;
    if (typeof version !== "string" || typeof fingerprint !== "string") continue;
    if (!isCheckShape(check)) continue;
    const agent = payload["agent"];
    const reason = payload["reason"];
    const postedAt = payload["posted_at"];
    const commentId = payload["comment_id"];
    const line = payload["line"];
    // The comment id is whatever the venue calls one — an integer on the 1F916
    // board, a UUID on The Colony (D-138 item 2) — and both spellings are kept
    // whole here. Folding every string id to -1 would key two different
    // comments the same way and lose one of them.
    const key = `${venue}:${
      typeof commentId === "number" || typeof commentId === "string"
        ? commentId
        : -1
    }:${typeof line === "number" ? line : 0}`;
    if (!byLine.has(key)) order.push(key);
    byLine.set(key, {
      operator,
      venue,
      handle,
      agent: typeof agent === "string" ? agent : operator,
      decision,
      check,
      reason: typeof reason === "string" ? reason : null,
      attestation_version: version,
      fingerprint,
      posted_at: typeof postedAt === "string" ? postedAt : event.at,
      binding_kind: bindingKindOf(payload["binding_kind"]),
      // Read off the published list rather than off the payload (D-142): the
      // event's own `perimeter` is the sweep's copy of the same sentence, and a
      // fold that trusted it would let a line say it was outside a perimeter it
      // is inside. The list is policy, and policy is what decides.
      perimeter: isPerimeterOperator(operator) ? PERIMETER_WORD : null,
      seq: event.seq,
    });
  }
  return order.map((key) => byLine.get(key)!);
}

/** The sealed binding kind on a line, or null where the event named none. */
function bindingKindOf(
  value: unknown,
): "registry" | "profile" | "account" | null {
  return value === "registry" || value === "profile" || value === "account"
    ? value
    : null;
}

/** Whether a value is one of the two checks the form accepts. */
function isCheckShape(value: unknown): value is ConfirmationCheck {
  if (typeof value !== "object" || value === null) return false;
  const fields = value as Record<string, unknown>;
  if (typeof fields["value"] !== "string") return false;
  if (fields["kind"] === "hash") return true;
  return (
    fields["kind"] === "span" &&
    (fields["value"] === "present" || fields["value"] === "absent")
  );
}

/**
 * Whether an entry's class meets a reader's demand (decision D-138 item 12).
 *
 * The order is `VERIFICATION_CLASSES`, weakest first, so `min_class=mixed`
 * admits mixed and registered and refuses community. A null demand is no
 * demand. A null class fails every demand, for the reason a null effective tier
 * does (src/read.ts): the entry never verified, so there is nothing to promise,
 * and answering "probably" to a reader who asked is the one thing these
 * functions must never do.
 */
export function classSatisfies(
  entryClass: VerificationClass | null,
  minClass: VerificationClass | null,
): boolean {
  // Absent is no demand, exactly as null is: a caller holding a query written
  // before the decision has no field here at all, and reading that as "the
  // weakest class only" would filter a stream nobody asked to filter. The same
  // tolerance `sourceClassSatisfies` has for the same reason.
  if (minClass === null || minClass === undefined) return true;
  if (entryClass === null) return false;
  return (
    VERIFICATION_CLASSES.indexOf(entryClass) >=
    VERIFICATION_CLASSES.indexOf(minClass)
  );
}

/**
 * Whether an entry's binding rung meets a reader's demand (decision D-142).
 *
 * `classSatisfies`'s twin, deliberately the same comparison over a different
 * order: `BINDING_RUNGS` is weakest first, so `min_binding=key` admits an entry
 * whose weakest counted validator stood on a key the world can check and
 * refuses one that rested on a board having authenticated an account.
 *
 * The two questions are different and a reader may ask either. The class says
 * *who* met the consensus — the maintainer's own operators, the communities, or
 * both. The rung says how strongly whoever it was is bound to anything at all.
 * A registered-class entry is key-bound by construction; a community-class one
 * may be either, and a reader who will not take the lowest rung says so here.
 *
 * A null demand is no demand, and an absent one is no demand either — a query
 * written before the decision carries no field here, and reading that as "the
 * weakest rung only" would filter a stream nobody asked to filter. A null rung
 * fails every demand, for the reason a null class does: the entry verified
 * nothing, so there is no floor to promise, and answering "probably" to a
 * reader who asked is the one thing these functions must never do.
 */
export function bindingSatisfies(
  entryBinding: BindingRung | null,
  minBinding: BindingRung | null,
): boolean {
  if (minBinding === null || minBinding === undefined) return true;
  if (entryBinding === null) return false;
  return (
    BINDING_RUNGS.indexOf(entryBinding) >= BINDING_RUNGS.indexOf(minBinding)
  );
}

/**
 * The dated layers behind one entry (decision D-138 item 11).
 *
 * The decision first, then one layer per reconfirmation by a *domain* operator
 * on an entry whose decision class was `community` or `mixed`. That is the
 * whole of "later stronger evidence is additive": the class the entry was
 * decided at never moves, and what a later domain check adds is a dated line
 * under it.
 *
 * A reconfirmation on a `registered` entry adds no layer: it is a
 * reconfirmation, which the freshness rules already record, and a second
 * registered layer would say nothing the first did not.
 */
function verificationLayersOf(
  events: readonly Event[],
  entryId: string,
  consensus: Consensus,
): readonly VerificationLayer[] {
  if (consensus.promotingSeq === null) return EMPTY_LAYERS;
  if (consensus.verificationClass === null) return EMPTY_LAYERS;
  const layers: VerificationLayer[] = [
    {
      kind: "decision",
      class: consensus.verificationClass,
      binding: consensus.verificationBinding ?? "key",
      seq: consensus.promotingSeq,
      at: consensus.promotingAt ?? (consensus.verifiedAt as string),
      operator: null,
    },
  ];
  // A registered consensus that rested on keys is the strongest thing this
  // record has; nothing added later says anything it did not. An account-bound
  // one is not, whatever its class — which is why the account rung reopens the
  // question the class alone closed (D-142).
  const accountBound = consensus.verificationBinding === "account";
  if (consensus.verificationClass === "registered" && !accountBound) {
    return layers;
  }

  const kinds = operatorKindsAt(events, Number.MAX_SAFE_INTEGER);
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "reconfirmation")) continue;
    if (event.entry_id !== entryId) continue;
    const operator = (event.payload.record as unknown as { operator: string })
      .operator;
    // Nomankind's own accounts add no layer either (D-142): a perimeter line
    // is shown and counted toward nothing, and a dated layer is a count.
    if (isPerimeterOperator(operator)) continue;
    const kind = kinds.get(operator) ?? "domain";
    if (kind === "domain") {
      layers.push({
        kind: "reconfirmation",
        // What this layer is, not what the entry becomes: a domain operator's
        // signature is registered evidence, and the entry's own class above it
        // stays exactly where the decision left it.
        class: "registered",
        binding: "key",
        seq: event.seq,
        at: event.at,
        operator,
      });
      continue;
    }
    // A community operator reconfirming a community-class entry adds evidence
    // of the kind the entry already has — unless the entry's weakest seat was
    // an account and this operator stands on a key (D-142). Then it is
    // stronger evidence of the same class, which is exactly what a layer is
    // for, and the rung on the layer is what says so.
    if (!accountBound) continue;
    const account = communityOperatorsAt(events, event.seq).get(operator);
    if (account === undefined || rungOf(account.binding) !== "key") continue;
    layers.push({
      kind: "reconfirmation",
      class: "community",
      binding: "key",
      seq: event.seq,
      at: event.at,
      operator,
    });
  }
  return layers;
}

/** The one empty list every unpromoted entry's layers are. */
const EMPTY_LAYERS: readonly VerificationLayer[] = Object.freeze([]);

/**
 * Every reason a counted, token-carrying line is sealed as a confirmation
 * rather than as a validation.
 *
 * Words and not sentences: the sweep seals one of these on the confirmation it
 * falls back to, and the entry page prints it beside the line.
 */
export const COMMUNITY_LINE_REFUSALS = [
  "no_attestation",
  "unknown_entry",
  "domain_unattested",
  "own_entry",
  "original_signer",
  "maintainer_operator",
  "excluded_party",
  "subject_authority",
  "entry_closed",
  "already_validated",
  "community_cap",
  // The account rung's scope (D-142 item 3). Two more words and not one,
  // because they are two different things to tell the account that wrote the
  // line: this entry is not the kind the rung may speak to, and this account is
  // younger than the entry it is speaking about.
  "account_out_of_scope",
  "account_too_new",
] as const;

export type CommunityLineRefusal = (typeof COMMUNITY_LINE_REFUSALS)[number];

/** What one counted line is: a validation, or a confirmation and why. */
export type CommunityLineDisposition =
  | { kind: "validation" }
  | { kind: "confirmation"; reason: CommunityLineRefusal };

/**
 * Whether one counted, token-carrying line is a validation by a community
 * operator, or a public confirmation after all (decision D-138).
 *
 * The one pure rule the sweep asks before it seals such a line, so the door and
 * the fold cannot drift: everything the door needs to decide is here, in one
 * function, over the log and the line alone.
 *
 * A validation when the community operator — registered already, or about to be
 * by this very line — may validate this entry:
 *
 * - the token attests the entry's own domain, which is what the version says;
 * - the author's own key is not its own judge, whichever end it speaks from;
 * - a party this domain excludes, or the authority its subject names, is
 *   refused exactly as a domain operator is;
 * - an entry that is closed takes no further decision;
 * - one counted validation per account per entry;
 * - the per-community cap for this entry is not reached;
 * - and, where the operator stands on the account rung (D-142), the entry is
 *   one of the tiers that rung may count toward and the account is older than
 *   the entry — the same `accountScopeRefusal` the fold asks, so a line the
 *   door seals as a validation is a line the fold counts.
 *
 * Otherwise a confirmation, with the word that says which rule it fell under.
 * A confirmation is not a refusal of the line: it is sealed, shown, and clears
 * the bootstrap label exactly as D-136 says. What it does not do is count.
 */
export function communityLineDisposition(
  events: readonly Event[],
  entryId: string,
  line: ConfirmationLine,
  handle: string,
  venue: string,
  agent: string,
  at: string,
  /**
   * The binding this line stands on, where the caller already holds it
   * (decision D-142).
   *
   * Optional, and read off the log when it is not given: a first line registers
   * its own operator, so at ingestion there may be no registration to read and
   * the caller is the only one who knows what the sweep captured. Where neither
   * has it, the operator is not on the account rung as far as this rule can
   * tell and the two clauses below do not apply — derivation asks again at the
   * position where the registration does exist.
   */
  binding?: CommunityBinding,
): CommunityLineDisposition {
  const no = (reason: CommunityLineRefusal): CommunityLineDisposition => ({
    kind: "confirmation",
    reason,
  });

  if (line.attestation_version === null) return no("no_attestation");

  const submission = submissionOf(events, entryId);
  if (submission === null) return no("unknown_entry");
  const core = submission.core;
  const target = eligibilityTargetOf(core);

  // The token attests one version of one text, and the text is per domain
  // (D-071). A line that carries this build's version attests every domain
  // whose published attestation is at that version, and nothing else: an entry
  // in a domain whose attestation moved on is a confirmation, not a validation,
  // because nobody signed the words that domain asks for.
  const attested = isRegisteredDomain(target.domain)
    ? attestationFor(target.domain).version === line.attestation_version
    : false;
  if (!attested) return no("domain_unattested");

  const operator = communityOperatorId(venue, handle);
  const position = Number.MAX_SAFE_INTEGER;

  // The author's own key is not its own judge, said of both ends of the key:
  // the id it speaks under, and the agent the log may already know as the
  // author's own.
  const agentOperators = agentOperatorsAt(events, position);
  if (
    target.authorOperator !== null &&
    (target.authorOperator === operator ||
      agentOperators.get(agent) === target.authorOperator)
  ) {
    return no("own_entry");
  }

  // An entry that is closed takes no further decision. Asked before the
  // exclusions, because "this entry is decided" is a fact about the entry and
  // the exclusions are facts about the speaker.
  const consensus = consensusFor(events, entryId, core);
  if (consensus.status !== "draft") return no("entry_closed");

  // The remaining exclusions, through the one predicate every door asks
  // (src/eligibility.ts), with the two facts this line establishes supplied:
  // the operator is registered — by this line, if it was not already — and it
  // is attested in this entry's domain, by the token.
  const registered = registeredOperatorsAt(events, position);
  const refusal = eligibilityRefusal(operator, {
    registered: true,
    authorOperator: target.authorOperator,
    originalSigners: () => originalSignersAt(events, position, target.id),
    maintainer: registered.maintainers.has(operator),
    provider:
      isRegisteredDomain(target.domain) &&
      isExcludedParty(target.domain, operator),
    authorityHosts: authorityHostsFor(target.domain, target.subject),
    domain: target.domain,
    attestedIn: [target.domain],
  });
  if (refusal !== null) {
    switch (refusal) {
      case "submitter_operator":
        return no("own_entry");
      case "original_signer":
        return no("original_signer");
      case "maintainer_operator":
        return no("maintainer_operator");
      case "provider_operator":
        return no("excluded_party");
      case "subject_authority":
        return no("subject_authority");
      default:
        return no("own_entry");
    }
  }

  // One counted validation per account per entry, and the per-community cap
  // (D-138 item 10), both read off the validations already sealed.
  const already = communityValidationsFor(events, entryId);
  if (already.some((each) => each.operator === operator)) {
    return no("already_validated");
  }
  const cap = communityCapPerEntry(countingCommunities().length);
  const fromVenue = new Set(
    already.filter((each) => each.venue === venue).map((each) => each.operator),
  );
  if (fromVenue.size >= cap) return no("community_cap");

  // The account rung's scope (D-142 item 3), asked last because it is the only
  // clause about the rung rather than about the speaker, and asked through the
  // same function the fold asks so the door and the fold cannot drift.
  const held =
    binding ?? communityOperatorsAt(events, position).get(operator)?.binding;
  if (held !== undefined && rungOf(held) === "account") {
    const outside = accountScopeRefusal(
      core,
      held,
      submittedInstantOf(events, entryId, core),
    );
    if (outside !== null) return no(outside);
  }

  // `at` is the sweep's own clock, carried so the rule has the same shape every
  // other rule here has and so a later rule that needs the moment has it. No
  // clause above reads it: nothing about who may validate depends on when.
  void at;
  return { kind: "validation" };
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
    // Who met the consensus, off the same fold the counts came from (D-138).
    // Null while draft or rejected: there is no decision to disclose.
    verification_class: consensus.verificationClass,
    verification_communities: consensus.verificationCommunities,
    // Disclosed, never enforced: one community is still a community class, and
    // the page says "community (single venue)" beside it.
    verification_single_venue: consensus.verificationCommunities.length === 1,
    // The rung the weakest counted seat stood on (D-142), off the same fold the
    // class came from, so the floor a reader filters on and the class it sits
    // beside can never come from two readings of the log.
    verification_binding: consensus.verificationBinding,
    verification_layers: verificationLayersOf(events, entryId, consensus),
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

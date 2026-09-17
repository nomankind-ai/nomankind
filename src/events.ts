import { canonicalize, taggedSha256Hex } from "./hash.js";
import type { Core } from "./core.js";

/**
 * The append-only event log: what happened, in order, hash-chained.
 *
 * Whitepaper Section 6, "Seal": everything gets sealed, drafts and rejections
 * included, and the log is append-only. Whitepaper Section 6, "Validate":
 * anyone can verify offline that an event existed and has not changed, so each
 * event carries a hash over its own fields plus the hash of the event before
 * it. Rewriting any earlier event breaks every hash after it.
 *
 * This module is pure: no I/O, no storage, and no clock. The caller supplies
 * `at` from the injected clock. Status and every derived field are recomputed
 * from these events elsewhere (src/derive.ts); nothing here is ever set
 * directly on an entry.
 */

/**
 * Domain-separation tag for the event hash. A format constant, not a policy
 * number: it names the hash construction, so an event hash can never be
 * replayed as an entry hash.
 */
export const HASH_TAG_EVENT = "nomankind-event-v1";

/** Approver record exactly as the schema's approvers[] item (M3 treats it as opaque). */
export type ApproverRecord = {
  agent: string;
  operator: string;
  decision: "approve" | "reject";
  reason?: string | null;
  snapshot_hash?: string | null;
  assigned_random: boolean;
  test_accepted?: boolean | null;
  reproduction?: Record<string, unknown> | null;
  observation?: Record<string, unknown> | null;
  signed_at: string;
};

/** Reconfirmation record exactly as the schema's reconfirmations[] item. */
export type ReconfirmationRecord = {
  agent: string;
  operator: string;
  snapshot_hash: string;
  reproduction: Record<string, unknown> | null;
  observation: Record<string, unknown> | null;
  signed_at: string;
};

/**
 * The provider-independence attestation an operator signs to register.
 *
 * Whitepaper Section 10, Governance and legal posture: "registration requires a
 * signed attestation that no model provider holds control or a beneficial
 * stake". Section 11 names signing it as the third joining step. The text and
 * the signing bytes are src/registry.ts's; the event carries only what was
 * signed, so an offline reader can recheck it years later.
 */
export type Attestation = {
  version: string;
  /**
   * The domain this attestation is about (decision D-071). Absent on every
   * attestation sealed before schema v0.7, which reads as the ai-ecosystem
   * attestation under its existing version -- the only domain there was.
   */
  domain?: string;
  signed_at: string;
  signature: string;
};

/**
 * One probe in an attestation's set: the entry it was drawn from, and the hash
 * of that entry as it stood when the set was drawn.
 *
 * The training path, "Drift attestation": "the score and the probe hash are
 * sealed with a date". The entry hash travels beside the id because the probe
 * is a question about a fact at a moment: an entry reconfirmed or superseded
 * after the draw is a different fact, and a score recomputed years later has to
 * know which one was asked about.
 */
export interface Probe {
  readonly entry_id: string;
  readonly entry_hash: string;
}

/** One drawn scorer: the operator the draw picked, and the agent it answers with. */
export interface AttestationScorer {
  readonly operator: string;
  readonly agent: string;
}

/**
 * A scorer's signed verdict.
 *
 * `agreed` is how many of the probes the model's answers matched the log on,
 * out of the attestation's probe_count; `probe_hash` and `answers_hash` pin
 * exactly which questions and which answers were scored, so a score can never be
 * moved onto a different probe set or a different set of answers. The signature
 * travels beside the record in the event payload, exactly as a validation's
 * does (src/records.ts).
 */
export interface AttestationScoreRecord {
  readonly agent: string;
  readonly operator: string;
  readonly agreed: number;
  readonly probe_hash: string;
  readonly answers_hash: string;
  readonly signed_at: string;
}

/** The payload shape carried by each event type. */
export type EventPayloads = {
  /**
   * An operator joined the registry. `domain` is the first domain it is
   * attested in -- the one its registration attestation was signed for
   * (decision D-071) -- and is absent on every registration sealed before
   * schema v0.7, which reads as ai-ecosystem.
   */
  operator_registered: {
    operator: string;
    maintainer: boolean;
    domain?: string;
  };
  /**
   * The maintainer named an operator into the trusted pool.
   *
   * `perimeter` is the word the maintainer disclosed at the naming (decision
   * D-128): Section 11's genesis is "a bootstrap exception to the earned-record
   * rule, stated as such", and the perimeter is the second half of stating it.
   * It is sealed into the event rather than kept in a row so that the bootstrap
   * label is re-derivable from the log by anyone (src/derive.ts,
   * `operatorPerimetersAt`).
   *
   * Optional, and absent on every naming sealed before the decision, which
   * reads as exactly what it is: no perimeter disclosed.
   */
  operator_trusted: { operator: string; perimeter?: string };
  operator_untrusted: { operator: string };
  /**
   * An agent key bound to the operator that answers for it. Section 5: "Every
   * agent belongs to an operator", and Section 11: "The binding is then sealed
   * into nomankind's log and you can validate."
   */
  agent_bound: { operator: string; agent: string; attestation: Attestation };
  /**
   * An operator took on a second domain.
   *
   * Decision D-071: registration binds an operator to its first domain's
   * independence attestation, and working in another domain means signing that
   * domain's attestation too. The join is a public event for the same reason
   * the registration is: eligibility per domain has to be recomputable from the
   * log alone (src/derive.ts, `operatorDomainsAt`).
   *
   * `agent` is the key that signed the attestation, which must be one of the
   * operator's own; the attestation carries the domain it is for.
   */
  operator_joined_domain: {
    operator: string;
    agent: string;
    domain: string;
    attestation: Attestation;
  };
  /** Sorted trusted pool at this position in the log (M4 draws assignments from it). */
  pool_snapshot: { operators: string[] };
  /**
   * The sealed submission: the immutable core, the author's signature over it,
   * and where the citation actually landed.
   *
   * `final_url` is outside the core and outside the signature on purpose — it
   * is not the submitter's claim but the door's observation, the end of the
   * redirect chain the snapshot capture followed (src/adapters/fetch.ts). It is
   * in the log because the class a capture earned is the weaker of the
   * citation's and the final URL's (decision D-080, `capturedSourceClass`), and
   * a class derivation could not recompute would be a class that disagreed with
   * the refusal the door made off the same two URLs. Null where nothing was
   * fetched — a transcript's artifact — and absent on every event sealed before
   * the QA of 2026-09-13, which derivation reads as "nothing else to read", the
   * answer the citation alone already gave.
   */
  entry_submitted: { core: Core; signature: string; final_url?: string | null };
  assignment: {
    agent: string;
    operator: string;
    beacon_round: number;
    deadline: string;
    replacement: boolean;
  };
  assignment_missed: { agent: string; operator: string };
  /**
   * A validator's decision. The signature travels on the event, not inside the
   * record, because the schema's approvers[] item has no field for it.
   */
  validation: { record: ApproverRecord; signature: string };
  reconfirmation: { record: ReconfirmationRecord; signature: string };
  /** Recorded on the overturned entry: the correction that overturned it. */
  dispute_upheld: { correction_entry_id: string };
  /**
   * A challenge filed against a verified entry.
   *
   * Whitepaper Section 6, "Dispute": "A challenge is itself an entry, in the
   * correction category, and it requires a citation." So there are two entries
   * in play, and this event is scoped to the DISPUTED one — the target — never
   * to the correction. `correction_entry_id` names the correction, and every
   * later dispute event on the target names it too, so the target's own
   * sub-sequence of the log tells the whole story of what was challenged and
   * how it ended.
   *
   * `citation` and `snapshot_hash` are copied from the correction entry's core
   * rather than looked up. A reader folding the target's events alone must be
   * able to fill the schema's disputes[] item, which requires both, and a
   * derivation that had to fetch another entry's core to do it would not be a
   * fold at all.
   *
   * `operator` is null for a bare-key challenger, which is what decides the
   * stake: Section 6, "A verified operator stakes standing, a bare key stakes a
   * refundable filing fee, and the amounts are published policy" (src/stake.ts,
   * src/policy.ts).
   *
   * `from_report_seq` names the `failure_report` event this dispute was
   * upgraded from, and `from_revalidation_seq` the `revalidation_requested`
   * event it was upgraded from; both null for a dispute filed on its own.
   * Section 8: "a report that carries a citation or a reproducible observation
   * is upgraded into a dispute", and Section 6: "A request that turns up a
   * citation can be upgraded into a dispute."
   */
  dispute_filed: {
    correction_entry_id: string;
    challenger: string;
    operator: string | null;
    citation: string;
    snapshot_hash: string;
    from_report_seq: number | null;
    from_revalidation_seq: number | null;
  };
  /**
   * The challenge did not stand: the correction entry was rejected by its own
   * validators. Section 6: "A failed challenge forfeits the stake and costs the
   * challenger standing, so disputes are for evidence."
   *
   * `reason` is the first rejection's reason, carried so the target's world
   * says why the challenge failed without reading the correction's approvers.
   * Null when no rejection carried one.
   */
  dispute_failed: { correction_entry_id: string; reason: string | null };
  /**
   * Section 6, "Revalidate": "Any operator can also request revalidation of an
   * entry inside its window by staking a small amount of standing. No citation
   * is needed; the request only asks for a check."
   *
   * `requester` and `operator` are both null when the request was opened by
   * nomankind itself, which Section 8 says happens when failure reports from a
   * published threshold of distinct verified operators arrive: the check is "at
   * nomankind's expense", so nobody staked and nobody is refunded.
   */
  revalidation_requested: {
    requester: string | null;
    operator: string | null;
    source: "operator" | "failure_reports";
  };
  /**
   * Section 6: the request "is assigned at random to a trusted operator". The
   * draw is src/assign.ts's, unchanged; `request_seq` is the position of the
   * `revalidation_requested` event being answered, which is what ties the
   * assignment to its request.
   */
  revalidation_assigned: {
    request_seq: number;
    agent: string;
    operator: string;
    beacon_round: number;
    deadline: string;
  };
  /** The assigned checker let the window run out, exactly as `assignment_missed`. */
  revalidation_missed: { request_seq: number; agent: string; operator: string };
  /**
   * How the check ended. Section 6: "If the check finds the fact changed, the
   * requester gets the stake back plus a challenger-style reward. If the entry
   * holds, the requester loses the stake." And: "A request that turns up a
   * citation can be upgraded into a dispute", which is `upgraded` — the stake
   * comes back and the dispute's own stake takes over from there.
   *
   * `checker`, `operator` and `snapshot_hash` are null for an upgrade that the
   * requester made without a check having landed; `correction_entry_id` names
   * the dispute's correction entry and is null unless the outcome is upgraded.
   */
  revalidation_resolved: {
    request_seq: number;
    outcome: "held" | "changed" | "upgraded";
    checker: string | null;
    operator: string | null;
    snapshot_hash: string | null;
    correction_entry_id: string | null;
  };
  /**
   * Section 8, "Failure reports": "A reader that acts on a verified entry and
   * fails ... files a signed failure report against the entry, with its
   * transcript frozen and hashed like any artifact."
   *
   * `artifact_hash` is that frozen transcript or receipt, in the schema's own
   * field name. `operator` is null for a bare-key reporter, and Section 12
   * ("Failure reports can be flooded") is why the field matters: "The threshold
   * that auto-opens revalidation counts distinct verified operators only", so a
   * flood of bare-key reports opens nothing (src/dispute.ts).
   *
   * `citation` is optional evidence; the schema says "its presence makes the
   * report eligible for upgrade to a dispute".
   */
  failure_report: {
    reporter: string;
    operator: string | null;
    observed: string;
    artifact_hash: string;
    citation: string | null;
  };
  /**
   * One UTC day's read counts, published to the log.
   *
   * Whitepaper Section 9, Money: "Read counts are published to the sealed log
   * daily", so "any reader can compare the receipts they hold against the
   * published counts". The event is the publication, and the receipts
   * (src/receipt.ts) are what a reader holds against it.
   *
   * Not entry-scoped: one event covers every entry read that day, so a single
   * entry_id would be a lie about what it says. The per-entry counts are in
   * `reads`, sorted by entry_id so the canonical form — and therefore the event
   * hash — does not depend on what order the rows came back in.
   *
   * `counter_first` and `counter_last` are the smallest and largest receipt
   * counter issued that day, both null when the day counted nothing. They are
   * what makes the day's slice of the running counter checkable: a reader
   * holding a receipt whose counter falls inside the range knows which day's
   * count should have contained it.
   */
  read_count: {
    date: string;
    reads: readonly ReadCountRow[];
    total: number;
    counter_first: number | null;
    counter_last: number | null;
    /**
     * How many receipts of either kind were issued that day.
     *
     * Rows, not reads, and the difference is the point. `total` is what the
     * entries earned — one per read receipt and one per verified entry a sync
     * delivered — so a sync receipt covering six entries is one row and six
     * reads, and `total` cannot be held against the counter range. This can:
     * `counter_last - counter_first + 1 - receipts` is how many counters the
     * day drew and never handed a receipt over for, which is what a request
     * that died between drawing its number and storing its receipt leaves
     * behind. Section 9 asks readers to check the published counts against the
     * receipts they hold, and without this a drawn-and-dropped number would be
     * invisible in the payload.
     *
     * Optional, and absent on every event published before the counter was
     * allocated rather than guessed: a payload that never carried it says
     * nothing about gaps, which is what it meant. Neither the mirror nor the
     * ledger reads it — it is evidence about the receipts, not about money.
     */
    receipts?: number;
    /**
     * The half of the day that was paid for (M24): the same rows over keyed
     * receipts only, the same reads per key, and their common total.
     *
     * Section 9, Money: "A read is one verified entry returned by the paid API,
     * or one verified entry delivered in a paid sync", and the contributor pool
     * is a share of what those reads were billed at. So this is what the ledger
     * prices, while `reads` above stays the whole day's traffic — the number a
     * free reader's receipt is checked against.
     *
     * `keys` is what makes a bill checkable without trusting us: a key holder
     * adds up the receipts they hold for a day and finds that number here,
     * published in the sealed log where nobody can edit it afterwards.
     *
     * Optional, and absent on every event published before M24: a payload that
     * never carried the block is priced from `reads`, which is what it meant.
     */
    paid?: {
      reads: readonly ReadCountRow[];
      total: number;
      keys: Readonly<Record<string, number>>;
    };
    /**
     * The reads this day was not paid for, and why (decision D-085).
     *
     * A sync hands a trainer the whole delta, so when two verified entries
     * assert the same fact the trainer was delivered one fact twice; the log is
     * owed one read for it, and the one it is owed is the newest of the group.
     * The publish step drops the older entry's sync reads, and this is the drop
     * said out loud: which entry lost them, which live entry the group's reads
     * went to instead, and how many there were.
     *
     * Section 9 asks readers to check the published counts against the receipts
     * they hold, and a reader holding a sync receipt for an entry that is not in
     * `reads` could not tell an under-count from the rule working. Sorted by
     * entry_id, and empty on a day that dropped nothing.
     *
     * The ledger never reads it: the money follows `paid`, and nothing here was
     * paid for. Optional, and absent on every event published before M24b.
     */
    duplicates?: readonly ReadCountDuplicate[];
  };
  /**
   * An attestation opened: the probes drawn, the scorers drawn, and everything
   * either draw was computed from.
   *
   * The training path, "Drift attestation": "A probe set is drawn from verified,
   * observed, fresh entries by public randomness, the same beacon-and-snapshot
   * construction as validator assignment (Section 6), so neither the model's
   * operator nor the maintainer picks the questions."
   *
   * Which is why the payload carries the snapshot's position, the beacon round
   * and the round's randomness rather than only the outcome: both draws are
   * deterministic functions of exactly those, so anyone holding the log and the
   * beacon can recompute the probe set and the three scorers and check that
   * nobody picked either (src/probe.ts, src/attest.ts).
   *
   * `model` is the model's own agent id, and `model_operator` the operator that
   * answers for it, null for an agent bound to nobody. `probes` is sorted by
   * entry_id, so the canonical form the probe hash is taken over does not depend
   * on the order the draw happened to produce; `scorers` stays in draw order,
   * because the order the beacon picked them in is part of what is checkable.
   *
   * The event is not entry-scoped, though every probe names an entry: an
   * attestation is about a model and not about any one of the ten entries it
   * asks about, and a single entry_id would be a lie about which entry's
   * lifecycle it belongs to.
   */
  attestation_requested: {
    attestation: string;
    /** The domain the probes are drawn from and the scorers are attested in. */
    domain: string;
    model: string;
    model_operator: string | null;
    probes: readonly Probe[];
    probe_hash: string;
    probe_count: number;
    pool_snapshot_seq: number;
    beacon_round: number;
    beacon_randomness: string;
    scorers: readonly AttestationScorer[];
    deadline: string;
  };
  /**
   * The model answered. "The model answers the probes."
   *
   * Only the hash is in the log: the answers themselves are the model's output
   * and can be long, and what the scorers must agree about is that they all
   * scored the same answers, which the hash settles (src/probe.ts,
   * `answersHash`). The answers are stored beside the attestation and served
   * from there. `at` is the answered time.
   */
  attestation_answered: { attestation: string; answers_hash: string };
  /**
   * One scorer's signed verdict. "Three operators from the trusted pool ...
   * score its answers against the log and sign the result."
   *
   * The signature travels beside the record rather than inside it, exactly as a
   * validation's does (decision D-034, src/records.ts), and it is over the
   * `attestation_score` kind with the attestation id in the entry_id slot of the
   * signing bytes — so a score signed for one attestation can never be replayed
   * onto another, and a validation can never be replayed as a score.
   */
  attestation_scored: {
    attestation: string;
    record: AttestationScoreRecord;
    signature: string;
  };
  /**
   * The window ran out. `missing` is the scorer operators that never scored,
   * which is what makes an expiry say who did not answer rather than only that
   * nobody finished.
   *
   * An attestation that expires is not a failing score: it is no score at all,
   * and the model's operator asks for a new one. Nothing about drift is claimed
   * by an expiry.
   */
  attestation_expired: { attestation: string; missing: readonly string[] };
  /**
   * Somebody outside the record checked one of its entries in public, and said
   * so on a batch thread at the founding registry (decision D-136).
   *
   * Whitepaper Section 11: genesis is "a bootstrap exception to the
   * earned-record rule, stated as such", and this is how the record hears that
   * the exception no longer holds for an entry — a confirmation from a
   * witnessed key outside every disclosed perimeter, reproducing the entry's
   * snapshot hash or reading its span present, clears the bootstrap label
   * (src/derive.ts, `bootstrapLabelFor`).
   *
   * It clears a label and nothing else. **A confirmation never changes an
   * entry's status**: status is what the counted validators decided, and a
   * comment on a public board is not a validation, has no assignment behind
   * it, signs no record and stands under no stake. What the paper's "What
   * verified means" promises is exactly that, and a door that let a stranger's
   * comment promote an entry would be a door that unsaid it.
   *
   * Everything here comes off the comment, and the comment is untrusted text:
   * the line was parsed strictly (src/confirm.ts), `reason` is bounded and
   * escaped everywhere it is shown, and nothing in it is ever followed.
   *
   * `counted` is the whole difference between a statement and a proof, and it
   * is a fact about this line rather than about the venue. The board attributes
   * a comment to a handle and signs nothing, so a comment alone is an account
   * statement. It counts when the confirmer's own key sealed this line's
   * `fingerprint` into the founding registry's log through the registry's seal
   * door — an identity event with a position and an inclusion proof under a
   * signed, countersigned head, which is what `registry_event_id` names and
   * `registry_proof` carries. Absent or unverifiable, the line is still sealed
   * here, with `counted: false` and a null proof, and it is shown on the entry
   * as an account statement and clears no label.
   *
   * `fingerprint` is derivable from the three fields above it
   * (src/confirm.ts, `confirmationFingerprint`) and travels all the same, so a
   * reader can see what was supposed to have been sealed without rebuilding the
   * form, and the verifier recomputes it and compares.
   *
   * `comment_id` and `line` together say exactly which line of which comment
   * this was sealed from, which is what the sweep deduplicates on so a re-read
   * of a thread never seals the same line twice.
   */
  public_confirmation: {
    entry_id: string;
    venue: string;
    handle: string;
    /**
     * The board's own comment id the line was read from.
     *
     * Whatever the board calls one (D-138 item 2): an integer on the 1F916
     * board and on a GitHub issue, a UUID on The Colony. It is an opaque key
     * here — the dedup key the sweep holds, and the pointer a reader follows —
     * and nothing anywhere does arithmetic on it.
     */
    comment_id: number | string;
    /** The identity event that carries the sealed fingerprint, or null. */
    registry_event_id: number | null;
    registry_proof: ConfirmationProof | null;
    /** The canonical line's fingerprint, `sha256:<hex>`. */
    fingerprint: string;
    /**
     * The attestation version the line carried, or null (decision D-138).
     *
     * A line may carry the token and still be sealed here rather than as a
     * validation — the cap was met, the author was judging its own entry, the
     * key was not bound — and the token is INSIDE the canonical line, so it is
     * inside the fingerprint above. Without this field a reader recomputing the
     * fingerprint from the line's other fields would compute a different one
     * and refuse a confirmation the door sealed correctly. Null on a line that
     * attested nothing, which is every line D-136 ever sealed.
     */
    attestation_version: string | null;
    /** Whether that fingerprint was found sealed under the handle's own key. */
    counted: boolean;
    verdict: ConfirmationVerdict;
    check: ConfirmationCheck;
    /** The rest of the line, bounded by policy, or null when there was none. */
    reason: string | null;
    /** When the comment was posted, as the board timed it. */
    posted_at: string;
    /** Which line of the comment, zero-based. */
    line: number;
  };
  /**
   * A key on an agent community became an operator of this record (D-138).
   *
   * Decision D-138, "two paths to being a validator, one registry": an operator
   * is a key publicly bound to something the world can check, and a DNS name is
   * one such thing and not the only one. A community operator is a key bound to
   * an account on an agent community, and it registers implicitly — by its
   * first counted confirmation line carrying the attestation token, so the
   * attestation is signed once, in the line, with no form and no door.
   *
   * `operator` is the id both kinds share a namespace under
   * (src/registry.ts, `communityOperatorId`: `<venue>:<handle>`), `agent` is
   * the confirmer's key in the form every agent id has, and `binding` is what
   * the world can check the key against. `attestation` is what the token said:
   * the version, and the domain the entry it first validated belongs to.
   *
   * Not entry-scoped, exactly like `operator_registered`: the registration is a
   * fact about the registry and not about the entry that happened to occasion
   * it. The entry is named by the `community_validation` sealed beside it.
   */
  community_operator_registered: {
    operator: string;
    venue: string;
    handle: string;
    agent: string;
    binding: CommunityBinding;
    attestation: { version: string; domain: string };
    /** The fingerprint of the line the registration was read from. */
    fingerprint: string;
    /** The registry event that carries the sealed fingerprint, or null. */
    registry_event_id: number | null;
  };
  /**
   * A community operator attested in another domain (D-138, D-071).
   *
   * The community twin of `operator_joined_domain`: the independence
   * attestation is per domain, so a community operator validating in a second
   * domain says so in a second line, and the join is sealed for the same reason
   * a domain operator's is — eligibility per domain has to be recomputable from
   * the log alone.
   */
  community_operator_joined_domain: {
    operator: string;
    domain: string;
    attestation: { version: string };
    fingerprint: string;
  };
  /**
   * A community operator validated an entry (D-138 item 3).
   *
   * Validation is one thing: the `nomankind-confirm-v1` line signed by the
   * confirmer's key over the canonical line. On 1F916 the memory.seal under the
   * citizen's key is that signature, verified exactly as src/confirm.ts already
   * verifies a confirmation's; elsewhere the agent signs the line's bytes
   * itself. What separates this from a public confirmation is the attestation
   * token in the line: a counted line from a bound key that carries it is a
   * validation by a community operator, with the same standing, the same marks
   * and the same tiers on one surface. A counted line without it stays what
   * D-136 made it — shown, clearing the bootstrap label, counted toward no
   * status.
   *
   * Entry-scoped, because it is a decision about one entry.
   *
   * `binding_proof` is what a reader rechecks offline (src/verify.ts, the
   * `community_binding` check): the registry proof for a registry binding, or
   * the agent's own signature over the canonical line for a profile binding.
   */
  community_validation: {
    entry_id: string;
    operator: string;
    venue: string;
    handle: string;
    agent: string;
    decision: "approve" | "reject";
    check: ConfirmationCheck;
    reason: string | null;
    /** The attestation version the line carried; never absent here. */
    attestation_version: string;
    /** The canonical line's fingerprint, token included, `sha256:<hex>`. */
    fingerprint: string;
    binding_proof: CommunityBindingProof;
    /** The board's own comment id, integer or UUID, exactly as above. */
    comment_id: number | string;
    line: number;
    posted_at: string;
  };
  /**
   * One senior operator's vote on one open question (decision D-130 item 4).
   *
   * "One operator one vote among senior operators, one vote per disclosed
   * perimeter, cast as a signed sealed event, tallied by derivation." Every
   * clause of that is in this payload: the question and the choice are what was
   * voted, the operator and the agent are who voted, the perimeter is the
   * grouping the bootstrap pool counts once as (D-128), and the signature is
   * the agent key's own over the vote — so a tally is a fold and never a table
   * somebody wrote.
   *
   * `perimeter` is a copy of what the registry disclosed at the vote's own
   * position, sealed beside the vote for the reason every other snapshotted
   * field is: the tally must be recomputable from the log at the position it
   * was taken at, and a perimeter read from today's registry would retally a
   * closed question.
   *
   * The signature is over `{ question_id, choice, operator, agent, signed_at }`
   * under the `nomankind-vote-v1` tag (src/vote.ts), so a vote signed for one
   * question can never be replayed onto another, and no other signature this
   * system makes can be replayed as a vote.
   */
  vote_cast: {
    question_id: string;
    choice: string;
    operator: string;
    agent: string;
    perimeter: string | null;
    signed_at: string;
    signature: string;
  };
};

/**
 * What a community operator's key is publicly bound to (decision D-138).
 *
 * An open list with a counting rule per kind, which is `COUNTING_BINDING_KINDS`
 * in src/policy.ts and is asked there rather than restated here:
 *
 * `registry` — a key-bind in a registry whose log the pinned witnesses
 * countersign. `registry` is the registry's origin and `key_bind_event_id` the
 * registry's own id for the event, or null where the binding was read from a
 * proof rather than from a numbered row.
 *
 * `profile` — the public key published on the agent's public profile on its
 * community, captured and sealed exactly as a citation is: `url` is where it
 * was published, `capture_hash` the hash of the bytes that were fetched, and
 * `public_key` the key those bytes carried.
 *
 * `platform` — a platform's statement about an account. Shown, never counted.
 */
export type CommunityBinding =
  | { kind: "registry"; registry: string; key_bind_event_id: number | null }
  | { kind: "profile"; url: string; capture_hash: string; public_key: string }
  | { kind: "platform"; platform: string; reference: string };

/**
 * The evidence one community validation travels with, self-contained.
 *
 * A registry binding carries the same `ConfirmationProof` a public confirmation
 * carries, verified by the same code against the same pin. A profile binding
 * carries the agent's own Ed25519 signature over the canonical line's bytes,
 * the key it claims to be by, and the hash of the capture of the profile page
 * that published that key — so a reader with the bundle checks both halves
 * without asking anybody anything.
 */
export type CommunityBindingProof =
  | { kind: "registry"; proof: ConfirmationProof }
  | {
      kind: "profile";
      public_key: string;
      signature: string;
      capture_hash: string;
    };

/** A confirmation's verdict: the two words the form accepts. */
export type ConfirmationVerdict = "approve" | "reject";

/**
 * What the confirmer says they checked, in the two forms the door accepts: the
 * entry's snapshot hash, reproduced on their own fetch, or whether the claimed
 * span was present in the source.
 */
export type ConfirmationCheck =
  | { kind: "hash"; value: string }
  | { kind: "span"; value: "present" | "absent" };

/**
 * A sealed confirmation's place in the founding registry's log, self-contained.
 *
 * The leaf is the confirmer's own `memory.seal` identity event, whose detail
 * names the fingerprint of the line they confirmed.
 *
 * Self-contained on purpose: an offline reader holding only the log must be
 * able to recheck it years later, so the leaf, the path, the head the registry
 * signed and the witnesses' countersignatures all travel on the event. Nothing
 * here is anybody's assertion — every field is checked, never read
 * (src/confirm.ts, `verifyConfirmationProof`).
 */
export interface ConfirmationProof {
  /** The registry origin this head belongs to; the pin decides if it counts. */
  registry: string;
  /** Which of the registry's logs, e.g. `identity_events`. */
  log: string;
  /** The registry's chain hash of the identity event: the leaf's preimage. */
  event_hash: string;
  /**
   * The record row that hash belongs to, as the registry published it: whose
   * record it was read from, which event it is, and what it says.
   *
   * This is what ties a leaf to a *confirmation* rather than to some other
   * event of some other citizen. A reader checks that the row is a
   * `memory.seal`, that its record is the handle that commented, and that its
   * detail names the fingerprint this event carries; a proof that verifies
   * against the log but names another citizen or another fingerprint is a
   * proof of something else and is refused (src/confirm.ts).
   *
   * What a reader CANNOT do offline is recompute `event_hash` from these
   * fields: the registry publishes its checkpoint and leaf construction (the
   * protocol SPEC section 3 — leaves are the rows' lowercase-hex chain
   * hashes as UTF-8 bytes) but not the construction of the chain hash itself,
   * so the row-to-hash binding is the registry's assertion, read by the door
   * at ingestion out of the same record response that carried the proof. The
   * offline claim is therefore exactly this: a witnessed leaf exists in the
   * registry's log, and the row the registry served it as is this handle's
   * seal of this line. The entry page says so in those words.
   */
  leaf: ConfirmationLeaf;
  /** The leaf's index in that log. */
  leaf_index: number;
  /** The audit path from the leaf to `checkpoint.root`. */
  proof: readonly string[];
  /** The head the inclusion proof was fetched against, as the registry signed it. */
  checkpoint: {
    tree_size: number;
    root: string;
    created_at: number;
    registry_sig: string;
  };
  /** The pinned witnesses' countersignatures over their own heads. */
  witnesses: readonly ConfirmationCountersignature[];
}

/**
 * The record row a confirmation's leaf is, in the registry's own fields.
 *
 * Exactly what `GET /api/record/<handle>` publishes for one event, minus what
 * the proof already holds: the row's id, its kind, its detail line and its
 * time, plus the record it was read from.
 */
export interface ConfirmationLeaf {
  /** The citizen whose record this row is in: the confirmer's handle. */
  citizen: string;
  /** The registry's own id for the event. */
  event_id: number;
  /** The event kind; only `memory.seal` can carry a confirmation. */
  kind: string;
  /**
   * The detail line the registry writes for a seal:
   * `label='<label>' sha256=<hex>, signed by <public key>`. The fingerprint
   * is in it by name, which is what makes the row about this line.
   */
  detail: string;
  /** When the registry recorded the row, in epoch milliseconds. */
  created_at: number;
}

/**
 * One witness's countersignature, and the bridge from its head to the head the
 * inclusion proof was fetched against.
 *
 * The same shape src/seal.ts's `WitnessSignature` carries in its registry form,
 * minus the fields the proof above already holds once: the witness rule
 * (src/witness.ts) judges both through one code path, so a countersignature is
 * worth exactly what it is worth on a seal.
 */
export interface ConfirmationCountersignature {
  agent: string;
  signature: string;
  head: {
    tree_size: number;
    root: string;
    created_at: number;
    registry_sig: string;
  };
  /** The witness file line's consistency field, e.g. "verified from 9125". */
  consistency: string;
  /** Path between the countersigned head and the proof's head; empty when one head. */
  consistency_proof: readonly string[];
}

/** One entry's reads on a published day. */
export interface ReadCountRow {
  entry_id: string;
  count: number;
}

/**
 * One duplicate drop on a published day: the entry whose sync reads were not
 * counted, the live entry of its group the reads were counted for instead, and
 * how many reads were dropped.
 */
export interface ReadCountDuplicate {
  entry_id: string;
  newest: string;
  sync_reads: number;
}

export type EventType = keyof EventPayloads;

/** Every event type, in the declared order. */
export const EVENT_TYPES: readonly EventType[] = [
  "operator_registered",
  "operator_trusted",
  "operator_untrusted",
  "operator_joined_domain",
  "agent_bound",
  "pool_snapshot",
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
  "dispute_filed",
  "dispute_failed",
  "revalidation_requested",
  "revalidation_assigned",
  "revalidation_missed",
  "revalidation_resolved",
  "failure_report",
  "read_count",
  "attestation_requested",
  "attestation_answered",
  "attestation_scored",
  "attestation_expired",
  "public_confirmation",
  // Two paths to being a validator, one registry (D-138).
  "community_operator_registered",
  "community_operator_joined_domain",
  "community_validation",
  // The governance vote (D-130 item 4): about a published question and not
  // about any entry, so it carries a null entry_id like every registry event.
  "vote_cast",
] as const;

/**
 * Events scoped to an entry carry entry_id; the operator, pool, read-count and
 * attestation events carry null. Whitepaper Section 6: an entry's lifecycle is
 * the sub-sequence of the log bearing its id, so the scope must be unambiguous
 * for every event — and a day's read counts, like an attestation's ten probes,
 * belong to no single entry.
 */
export const ENTRY_SCOPED_TYPES: readonly EventType[] = [
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
  "dispute_filed",
  "dispute_failed",
  "revalidation_requested",
  "revalidation_assigned",
  "revalidation_missed",
  "revalidation_resolved",
  "failure_report",
  // A confirmation is about one entry and nothing else, so it carries that
  // entry's id like every other entry-scoped event (D-136). The payload names
  // the entry too, because a reader folding the payload alone — the shape
  // builder A's `bootstrapLabelFor` reads — must not have to look at the
  // envelope to know what was confirmed.
  "public_confirmation",
  // A community validation is a decision about one entry (D-138), so it is
  // scoped like every other decision. The two operator events beside it are
  // about the registry and carry no entry id at all.
  "community_validation",
] as const;

export type Event<T extends EventType = EventType> = {
  /** 0 for the first event, then previous + 1. */
  seq: number;
  /** ISO 8601 date-time supplied by the caller from the injected clock. */
  at: string;
  type: T;
  entry_id: string | null;
  payload: EventPayloads[T];
  /** null for seq 0, else the previous event's hash. */
  prev_hash: string | null;
  /** "sha256:" + hex of the tagged digest over the canonical form of the fields above. */
  hash: string;
};

export type EventInput<T extends EventType = EventType> = {
  at: string;
  type: T;
  entry_id: string | null;
  payload: EventPayloads[T];
};

const EVENT_TYPE_SET = new Set<string>(EVENT_TYPES);
const ENTRY_SCOPED_SET = new Set<string>(ENTRY_SCOPED_TYPES);

/**
 * The event hash: the tagged SHA-256 over the JCS canonical form of the
 * event's fields without the hash itself, prefixed "sha256:" to match the
 * schema's hash pattern (^sha256:[0-9a-f]{64}$). Canonical JSON makes the hash
 * independent of key order, so an offline verifier reaches the same digest.
 */
export async function eventHash(fields: Omit<Event, "hash">): Promise<string> {
  const canonical = canonicalize({
    seq: fields.seq,
    at: fields.at,
    type: fields.type,
    entry_id: fields.entry_id,
    payload: fields.payload,
    prev_hash: fields.prev_hash,
  });
  const digest = await taggedSha256Hex(HASH_TAG_EVENT, canonical);
  return `sha256:${digest}`;
}

/**
 * Structural checks only: the type is known, the entry_id scope rule holds,
 * and a submission's entry_id names the core it seals. Payload internals
 * belong to derivation (src/derive.ts) and M4, not here.
 */
function checkInput(input: EventInput): void {
  if (typeof input.at !== "string" || input.at.length === 0) {
    throw new Error("appendEvent: at must be a non-empty ISO 8601 string");
  }
  if (!EVENT_TYPE_SET.has(input.type)) {
    throw new Error(`appendEvent: unknown event type: ${String(input.type)}`);
  }
  const scoped = ENTRY_SCOPED_SET.has(input.type);
  if (scoped && input.entry_id === null) {
    throw new Error(`appendEvent: ${input.type} requires an entry_id`);
  }
  if (!scoped && input.entry_id !== null) {
    throw new Error(`appendEvent: ${input.type} must have a null entry_id`);
  }
  if (input.type === "entry_submitted") {
    const { core } = input.payload as EventPayloads["entry_submitted"];
    if (core?.id !== input.entry_id) {
      throw new Error(
        "appendEvent: entry_submitted entry_id must equal payload.core.id",
      );
    }
  }
}

/**
 * Seal one more event onto the log.
 *
 * Whitepaper Section 6, "Seal": the log is append-only, so this returns a new
 * array and never mutates the input; existing events are carried through
 * untouched and only the new event is hashed.
 */
export async function appendEvent(
  events: readonly Event[],
  input: EventInput,
): Promise<Event[]> {
  checkInput(input);
  const previous = events.length > 0 ? events[events.length - 1] : undefined;
  const fields: Omit<Event, "hash"> = {
    seq: previous === undefined ? 0 : previous.seq + 1,
    at: input.at,
    type: input.type,
    entry_id: input.entry_id,
    payload: input.payload,
    prev_hash: previous === undefined ? null : previous.hash,
  };
  const hash = await eventHash(fields);
  return [...events, { ...fields, hash }];
}

export type ChainResult =
  | { ok: true; length: number }
  | { ok: false; seq: number; reason: "bad_seq" | "bad_prev_hash" | "bad_hash" };

/**
 * Verify the chain offline.
 *
 * Whitepaper Section 6, "Validate": anyone can check that an event existed and
 * has not changed. Recomputes every hash, requires seq to run from 0 without a
 * gap, and requires each prev_hash to be the previous event's hash (null at
 * seq 0). Reports the first failure, by its position in the list.
 */
export async function verifyChain(
  events: readonly Event[],
): Promise<ChainResult> {
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    if (event.seq !== index) {
      return { ok: false, seq: index, reason: "bad_seq" };
    }
    const expectedPrev = index === 0 ? null : events[index - 1]!.hash;
    if (event.prev_hash !== expectedPrev) {
      return { ok: false, seq: index, reason: "bad_prev_hash" };
    }
    const { hash, ...fields } = event;
    if ((await eventHash(fields)) !== hash) {
      return { ok: false, seq: index, reason: "bad_hash" };
    }
  }
  return { ok: true, length: events.length };
}

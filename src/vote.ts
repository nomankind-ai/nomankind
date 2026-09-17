/**
 * The governance vote: who may vote, on what, and what the log makes of it.
 *
 * Decision D-130 item 4. Standing is an asset, and the last thing it buys is a
 * say: "one operator one vote among senior operators, one vote per disclosed
 * perimeter, cast as a signed sealed event, tallied by derivation and published
 * on a votes page; questions are policy numbers, domain registrations and the
 * authority tables; the tally is advisory to the maintainer until the record's
 * hosting decentralizes."
 *
 * Four rules and they are all here:
 *
 *  - Senior only. The tier is read at the vote's own instant by src/standing.ts
 *    (`tierOf`), from the standing the log produced — so the electorate is a
 *    fold over the sealed events and never a list anybody keeps.
 *  - One operator one vote. The first sealed vote counts and a second is
 *    refused at the door and ignored by the tally, which is what makes the two
 *    agree: a log that somehow held two would still be counted once.
 *  - One vote per disclosed perimeter (D-128). The bootstrap operators the
 *    maintainer named at genesis are inside one disclosed perimeter, and a
 *    perimeter that voted with three of its operators would be one party
 *    voting three times. An operator with no perimeter is its own party and is
 *    counted on its own.
 *  - Advisory. The tally says `advisory: true` in every answer it returns,
 *    because a number that looked binding would be a governance nobody has
 *    yet: the maintainer still hosts the record, and D-130 says so.
 *
 * Pure: no I/O, no storage, no clock of its own. The caller supplies `now` from
 * the injected clock and the events from the store. Ed25519 goes through
 * WebCrypto only (src/identity.ts), so this runs unchanged on Workers.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import type { Event } from "./events.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import {
  voteQuestion,
  voteWindow,
  type Tier,
  type VoteQuestion,
} from "./policy.js";

/**
 * Domain-separation tag for a vote. A format constant, not a policy number: it
 * names what the signature is over, so a signature made to cast a vote can
 * never be replayed as a record, an entry, an event, a seal, a witness
 * countersignature, a read receipt or a certificate — and none of those can be
 * replayed as a vote.
 */
export const HASH_TAG_VOTE = "nomankind-vote-v1";

/** What a vote signs over: who voted what, on which question, and when. */
export interface VoteFields {
  readonly question_id: string;
  readonly choice: string;
  readonly operator: string;
  readonly agent: string;
  readonly signed_at: string;
}

const encoder = new TextEncoder();

/**
 * The exact bytes a voter signs: the tag, a newline, and the RFC 8785 canonical
 * JSON of the five fields.
 *
 * The question is inside them, so a vote cast on one question cannot be moved
 * onto another; the operator is inside them beside the agent, so a key cannot
 * vote in somebody else's name even where the door would have let it; and the
 * instant is inside them, so a vote cannot be re-dated into an open window
 * after its own closed.
 *
 * The perimeter is NOT signed, and deliberately: it is not the voter's claim to
 * make. The registry discloses it and the door snapshots what the registry said
 * at the vote's position, which is what the tally groups by.
 */
export function voteSigningBytes(fields: VoteFields): Uint8Array {
  const canonical = canonicalize({
    question_id: fields.question_id,
    choice: fields.choice,
    operator: fields.operator,
    agent: fields.agent,
    signed_at: fields.signed_at,
  });
  return encoder.encode(`${HASH_TAG_VOTE}\n${canonical}`);
}

/** Sign a vote, returning the unpadded base64url signature the event carries. */
export async function signVote(
  fields: VoteFields,
  privateKey: CryptoKey,
): Promise<string> {
  return base64urlEncode(
    await signBytes(privateKey, voteSigningBytes(fields)),
  );
}

/**
 * Verify a vote against the key inside its own `agent` id (D-014: an agent id
 * is its public key).
 *
 * Returns false, never throws, on anything malformed: an agent id that carries
 * no key, a signature that is not base64url, a field that is not a string. A
 * verifier reading somebody else's log gets a verdict, not an exception.
 */
export async function verifyVoteSignature(
  fields: VoteFields,
  signature: string,
): Promise<boolean> {
  try {
    if (typeof signature !== "string") return false;
    for (const value of [
      fields.question_id,
      fields.choice,
      fields.operator,
      fields.agent,
      fields.signed_at,
    ]) {
      if (typeof value !== "string") return false;
    }
    return await verifyBytes(
      publicKeyFromAgentId(fields.agent),
      voteSigningBytes(fields),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

/** Every reason a vote can be refused, in the order the check applies them. */
export const VOTE_REFUSALS = [
  "unknown_question",
  "vote_not_open",
  "vote_closed",
  "bad_choice",
  "insufficient_tier",
  "already_voted",
  "perimeter_voted",
  "bad_signature",
] as const;

export type VoteRefusal = (typeof VOTE_REFUSALS)[number];

/** Accepted, or refused with the reason. */
export type VoteVerdict = { ok: true } | { ok: false; reason: VoteRefusal };

/** Everything the check needs, gathered by the caller at the vote's instant. */
export interface VoteInput {
  /** The question, or null when policy publishes none by that id. */
  readonly question: VoteQuestion | null;
  readonly choice: unknown;
  readonly operator: string;
  /** The voter's tier at `now`, from `tierOf` over the folded standing. */
  readonly tier: Tier;
  /** The perimeter the registry discloses for this operator, or null. */
  readonly perimeter: string | null;
  /** Every `vote_cast` the log already holds; other events are ignored. */
  readonly prior: readonly Event[];
  readonly now: Date;
  /**
   * Whether the signature over the vote verifies. Checked by the caller,
   * because verifying is asynchronous and this is not: the check stays a pure
   * function of what it is handed, exactly as every other kernel check is, and
   * the door does the crypto beside it.
   */
  readonly signatureValid: boolean;
}

/** One sealed vote, read off its event by name. */
interface CastVote {
  readonly question_id: string;
  readonly choice: string;
  readonly operator: string;
  readonly agent: string;
  readonly perimeter: string | null;
  readonly signed_at: string;
  readonly signature: string;
  readonly seq: number;
  readonly at: string;
}

/**
 * The `vote_cast` events of one question, oldest first.
 *
 * Read by name off the payload rather than by type assertion, so an event
 * shaped by a build this one does not know is skipped rather than half-read
 * into somebody's ballot.
 */
export function votesFor(
  events: readonly Event[],
  questionId: string,
): readonly CastVote[] {
  const votes: CastVote[] = [];
  for (const event of [...events].sort((left, right) => left.seq - right.seq)) {
    if (event.type !== "vote_cast") continue;
    const payload = event.payload as unknown as Record<string, unknown>;
    const question = payload["question_id"];
    const choice = payload["choice"];
    const operator = payload["operator"];
    const agent = payload["agent"];
    const signedAt = payload["signed_at"];
    const signature = payload["signature"];
    if (question !== questionId) continue;
    if (
      typeof choice !== "string" ||
      typeof operator !== "string" ||
      typeof agent !== "string" ||
      typeof signedAt !== "string" ||
      typeof signature !== "string"
    ) {
      continue;
    }
    const perimeter = payload["perimeter"];
    votes.push({
      question_id: questionId,
      choice,
      operator,
      agent,
      perimeter: typeof perimeter === "string" ? perimeter : null,
      signed_at: signedAt,
      signature,
      seq: event.seq,
      at: event.at,
    });
  }
  return votes;
}

/** Whether `now` is inside the question's window, which is end-exclusive. */
function isOpen(question: VoteQuestion, now: Date): VoteVerdict {
  const window = voteWindow(question);
  const at = now.getTime();
  if (at < Date.parse(window.opens)) return { ok: false, reason: "vote_not_open" };
  if (at >= Date.parse(window.closes)) return { ok: false, reason: "vote_closed" };
  return { ok: true };
}

/**
 * Whether this vote may be cast, checked in the published order.
 *
 * The order is what a refusal costs and what it says. The question and its
 * window come first because they are about nothing but the request; the choice
 * next, because a ballot that is not on the paper is a malformed vote whoever
 * cast it; then the tier, which is the electorate; then the two "already"
 * rules, which are about the log; and the signature last, because it is the
 * only one that costs a key import — and because a refusal that named it first
 * would tell a stranger which of the other seven they had also failed.
 */
export function checkVote(input: VoteInput): VoteVerdict {
  const question = input.question;
  if (question === null) return { ok: false, reason: "unknown_question" };

  const open = isOpen(question, input.now);
  if (!open.ok) return open;

  if (
    typeof input.choice !== "string" ||
    !question.options.includes(input.choice)
  ) {
    return { ok: false, reason: "bad_choice" };
  }

  // Senior only (D-130 item 4). The tier is the caller's reading of the fold at
  // this instant, so an operator whose standing fell this morning has no vote
  // this afternoon, and one whose standing rose has one.
  if (input.tier !== "senior") return { ok: false, reason: "insufficient_tier" };

  const prior = votesFor(input.prior, question.id);
  if (prior.some((vote) => vote.operator === input.operator)) {
    return { ok: false, reason: "already_voted" };
  }

  // One vote per disclosed perimeter (D-128, D-130 item 4): the bootstrap pool
  // is one party however many operators it runs, so the first of them to vote
  // is the one that votes. An operator that disclosed no perimeter is its own
  // party — null is not a group, and grouping the ungrouped together would
  // silence everyone but the first stranger to vote.
  if (
    input.perimeter !== null &&
    prior.some((vote) => vote.perimeter === input.perimeter)
  ) {
    return { ok: false, reason: "perimeter_voted" };
  }

  if (!input.signatureValid) return { ok: false, reason: "bad_signature" };

  return { ok: true };
}

// ---------------------------------------------------------------------------
// The tally
// ---------------------------------------------------------------------------

/** One counted voter, as the tally names them. */
export interface TalliedVoter {
  readonly operator: string;
  readonly perimeter: string | null;
  /** The instant the vote was sealed at. */
  readonly at: string;
  readonly seq: number;
}

/** What the log makes of one question at one instant. */
export interface Tally {
  readonly question_id: string;
  /**
   * Where the clock stands against the window: `not_open` before it opens,
   * `open` inside it, `closed` from the closing instant on.
   *
   * Three and not two, because a question policy has published but nobody may
   * vote on yet is not the same thing as one whose week has run out, and a
   * page that called the first "open" would invite a vote the door refuses
   * `vote_not_open`.
   */
  readonly state: "not_open" | "open" | "closed";
  readonly opens: string;
  readonly closes: string;
  /** One count per option the question publishes, zeroes included. */
  readonly counts: Record<string, number>;
  readonly voters: readonly TalliedVoter[];
  /**
   * Always true (D-130 item 4): "the tally is advisory to the maintainer until
   * the record's hosting decentralizes". It is in the answer rather than in a
   * paragraph beside it so that every reader of the JSON is told, including the
   * ones that only read JSON.
   */
  readonly advisory: true;
}

/**
 * Fold one question's votes into a tally, at `now`.
 *
 * One vote per operator and one per perimeter, decided by the first sealed vote
 * in each: a later one never counts, which is the same answer the door gives by
 * refusing it. The two agree by construction, so a log that somehow held a
 * second vote — an import of somebody else's fork, a door that once let one
 * through — is still counted the way the rule says rather than the way the
 * events happen to read.
 *
 * `counts` carries a zero for every option nobody chose, so a reader can see
 * the whole ballot rather than only the parts of it that were used.
 *
 * The question is named either way a caller has it — the published object, or
 * its id — and `now` is an instant either way a caller holds one, because the
 * page and the JSON door reach this from different sides and neither should
 * have to convert to call it.
 */
export function tallyOf(
  events: readonly Event[],
  question: VoteQuestion | string,
  now: Date | string,
): Tally {
  const asked = typeof question === "string" ? voteQuestion(question) : question;
  if (asked === null) {
    // A programming error and not a refusal: every caller here maps over
    // `VOTE_QUESTIONS`, and the one door that takes an id from a reader answers
    // 404 before it gets this far. Saying so beats inventing a window for a
    // question nobody published.
    throw new Error(`tallyOf: no such question: ${String(question)}`);
  }
  const at = typeof now === "string" ? Date.parse(now) : now.getTime();
  const window = voteWindow(asked);
  const counts: Record<string, number> = {};
  for (const option of asked.options) counts[option] = 0;

  const voters: TalliedVoter[] = [];
  const seenOperators = new Set<string>();
  const seenPerimeters = new Set<string>();

  for (const vote of votesFor(events, asked.id)) {
    // A choice the question does not publish is not a ballot at all: it is not
    // counted, it does not make its sender a voter, and — asked first, before
    // anything below has looked at who sent it — it does not spend that
    // operator's or that perimeter's one turn either. The door refuses it
    // `bad_choice`; this is the fold saying the same thing about a log that
    // holds one anyway, and saying it without taking somebody's vote away.
    if (!asked.options.includes(vote.choice)) continue;
    if (seenOperators.has(vote.operator)) continue;
    if (vote.perimeter !== null && seenPerimeters.has(vote.perimeter)) continue;
    seenOperators.add(vote.operator);
    if (vote.perimeter !== null) seenPerimeters.add(vote.perimeter);
    counts[vote.choice] = (counts[vote.choice] ?? 0) + 1;
    voters.push({
      operator: vote.operator,
      perimeter: vote.perimeter,
      at: vote.at,
      seq: vote.seq,
    });
  }

  return {
    question_id: asked.id,
    state:
      at >= Date.parse(window.closes)
        ? "closed"
        : at < Date.parse(window.opens)
          ? "not_open"
          : "open",
    opens: window.opens,
    closes: window.closes,
    counts,
    voters,
    advisory: true,
  };
}

/**
 * The vote routes: the door a senior operator casts a ballot through, and the
 * two reads that publish what the log made of it.
 *
 * Decision D-130 item 4: "the vote: one operator one vote among senior
 * operators, one vote per disclosed perimeter (so the bootstrap pool of D-128
 * counts once), cast as a signed sealed event, tallied by derivation and
 * published on a votes page; questions are policy numbers, domain registrations
 * and the authority tables; the tally is advisory to the maintainer until the
 * record's hosting decentralizes."
 *
 * This module is that door and nothing more. Every rule lives in src/vote.ts,
 * which is pure, so the refusal an operator gets here is one an offline reader
 * can rederive from the log; every question lives in src/policy.ts, so what is
 * being voted on moves only by a recorded decision; and the counts on both
 * reads are `tallyOf`'s fold over the sealed events, never a stored result.
 * There is no vote table: a vote that is in the log is a vote that counts, and
 * a vote that is not is not.
 *
 * Two signatures are in play and they are different things. The request
 * envelope's (D-014) proves who sent this HTTP request, and the door checks it
 * exactly as every other write door does. The vote's own — the tag
 * `nomankind-vote-v1` over the canonical ballot — is what a reader years from
 * now rechecks offline, because it travels in the sealed event and the envelope
 * does not. Both are the voting agent's key.
 *
 * Order matters and is deliberate: the envelope, the shape, the operator behind
 * the key, and only then the vote's own rules in `checkVote`'s published order —
 * so a malformed ballot never costs a standing fold, and nothing is written
 * until every check has passed.
 *
 * No policy number lives here: the window and the questions are src/policy.ts's,
 * the page size is LIST_PAGE_LIMIT, and the bare integers are HTTP status codes.
 */

import type { Event } from "../events.js";
import { perimeterOf } from "../registry.js";
import {
  VOTE_QUESTIONS,
  voteQuestion,
  type VoteQuestion,
} from "../policy.js";
import { standingAt, tierOf } from "../standing.js";
import type { D1Like } from "../storage/d1.js";
import {
  getOperator,
  latestSeal,
  operatorForAgent,
  recordVote,
  votesForQuestion,
} from "../storage/repository.js";
import {
  checkVote,
  tallyOf,
  verifyVoteSignature,
  type VoteRefusal,
} from "../vote.js";
import type { Env } from "./env.js";
import {
  authenticate,
  guardDatabase,
  isRead,
  json,
  methodNotAllowed,
  READ_METHODS,
  refuse,
  unavailable,
  withChainRetry,
} from "./registry.js";
import { sealedLog } from "./sweep.js";

/** What these routes are given besides their bindings: the instant. */
export interface VoteDeps {
  readonly now: Date;
}

/**
 * The status each refusal answers in.
 *
 * A question nobody published is a 404 — the id names nothing here — and the
 * rest divide the way every other door's do: 403 for who you are, 409 for the
 * state of the log or the calendar, 422 for what you sent.
 */
const VOTE_STATUS: Readonly<Record<VoteRefusal, number>> = Object.freeze({
  unknown_question: 404,
  vote_not_open: 409,
  vote_closed: 409,
  bad_choice: 422,
  insufficient_tier: 403,
  already_voted: 409,
  perimeter_voted: 409,
  bad_signature: 422,
});

/** The body a vote arrives in, or null when it is not one. */
interface VoteBody {
  readonly question_id: string;
  readonly choice: string;
  readonly signed_at: string;
  readonly signature: string;
}

/**
 * Read one ballot out of a signed body, or refuse it.
 *
 * Four fields and no others: the question, the choice, the instant the voter
 * signed at and the signature over those. The door cannot make the signature
 * itself — it holds no operator's key, and a vote nobody signed would be a vote
 * only this Worker could vouch for — so the voter signs the ballot and sends
 * both halves, exactly as a validator sends its record and its signature.
 */
function parseVoteBody(body: unknown): VoteBody | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const fields = body as Record<string, unknown>;
  const known = new Set(["question_id", "choice", "signed_at", "signature"]);
  for (const key of Object.keys(fields)) {
    if (!known.has(key)) return null;
  }
  const question_id = fields["question_id"];
  const choice = fields["choice"];
  const signed_at = fields["signed_at"];
  const signature = fields["signature"];
  if (
    typeof question_id !== "string" ||
    typeof choice !== "string" ||
    typeof signed_at !== "string" ||
    typeof signature !== "string"
  ) {
    return null;
  }
  return { question_id, choice, signed_at, signature };
}

/**
 * The voter's tier at this instant, folded from the sealed log.
 *
 * Folded rather than read off the cached column, because the electorate is the
 * one thing about a vote that must be recomputable by a reader who was not
 * here: the verifier checks each voter's tier at the vote's own position
 * (src/verify.ts), and a door that voted people in by a cache the verifier does
 * not read would produce votes the verifier then refuses.
 *
 * Nothing sealed yet means nobody has standing yet, which is the honest answer
 * before the first seal and refuses every vote in the tier's own word.
 */
async function tierAt(
  db: D1Like,
  operator: string,
  trusted: boolean,
): Promise<ReturnType<typeof tierOf>> {
  const seal = await latestSeal(db);
  if (seal === null) return tierOf(0, trusted);
  const events = await sealedLog(db, seal.last_seq);
  const folded = standingAt(events, seal.last_seq).get(operator);
  return tierOf(folded?.standing ?? 0, trusted);
}

/** One question with the log's tally of it, as both reads answer. */
function view(
  question: VoteQuestion,
  events: readonly Event[],
  now: Date,
): Record<string, unknown> {
  return { question, tally: tallyOf(events, question, now) };
}

// ---------------------------------------------------------------------------
// POST /votes
// ---------------------------------------------------------------------------

async function cast(
  request: Request,
  env: Env,
  deps: VoteDeps,
  path: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const body = parseVoteBody(auth.body);
  if (body === null) return refuse(400, "bad_body");

  // Section 5: anyone may hold a key, and null is the truth about a bare one. A
  // vote is an operator's, so a key nobody has bound to one votes for nobody.
  const operator = await operatorForAgent(env.DB, auth.agent);
  if (operator === null) return refuse(403, "bare_key");
  const record = await getOperator(env.DB, operator);
  if (record === null) return refuse(403, "bare_key");

  const question = voteQuestion(body.question_id);
  // The signature is over what the voter signed and not over what the door read
  // afterwards: the ballot's five fields, under the vote tag.
  const signatureValid = await verifyVoteSignature(
    {
      question_id: body.question_id,
      choice: body.choice,
      operator,
      agent: auth.agent,
      signed_at: body.signed_at,
    },
    body.signature,
  );

  // The perimeter the registry disclosed at this position (D-128), which is
  // what the one-vote-per-perimeter rule groups by and what the event carries.
  const perimeter = perimeterOf(record.details);
  // This question's ballots in full, not a page of them: the two "already"
  // rules are about every vote already cast, and a door that read one page
  // would take a second vote from an operator whose first was older than the
  // page — which the verifier would then name `vote_duplicate` against a log
  // this door wrote itself.
  const prior =
    question === null ? [] : await votesForQuestion(env.DB, question.id);

  const verdict = checkVote({
    question,
    choice: body.choice,
    operator,
    // The tier is folded only once the cheap checks have passed: the fold reads
    // the sealed log, and a malformed ballot must not cost one.
    tier:
      question === null
        ? "probation"
        : await tierAt(env.DB, operator, record.details["trusted"] === true),
    perimeter,
    prior,
    now: deps.now,
    signatureValid,
  });
  if (!verdict.ok) {
    return refuse(VOTE_STATUS[verdict.reason], verdict.reason);
  }
  // `checkVote` refused an unknown question above; this is the type narrowing.
  if (question === null) return refuse(404, "unknown_question");

  const sealed = await withChainRetry(() =>
    recordVote(env.DB, {
      at: deps.now.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        question_id: question.id,
        choice: body.choice,
        operator,
        agent: auth.agent,
        perimeter,
        signed_at: body.signed_at,
        signature: body.signature,
      },
    }),
  );

  // The tally as it now stands, folded over the log this vote is in: the voter
  // is told what their vote did rather than only that it was taken.
  return json(
    {
      event: sealed,
      ...view(question, [...prior, sealed], deps.now),
    },
    201,
  );
}

// ---------------------------------------------------------------------------
// GET /votes and GET /votes/{id}
// ---------------------------------------------------------------------------

/**
 * Every published question with its tally, or one of them.
 *
 * One read per published question, and each in full: the questions are a
 * published handful and a question's ballots are at most one per senior
 * operator, so this is bounded by the electorate rather than by a page size —
 * which is what keeps a tally from quietly losing the oldest votes. The fold is
 * `tallyOf`'s, so this door and the page src/worker/pages.ts renders cannot
 * disagree about who voted.
 */
async function read(
  env: Env,
  deps: VoteDeps,
  id: string | null,
): Promise<Response> {
  if (id === null) {
    const questions = [];
    for (const question of VOTE_QUESTIONS) {
      questions.push(
        view(question, await votesForQuestion(env.DB, question.id), deps.now),
      );
    }
    return json({ questions }, 200);
  }
  const question = voteQuestion(id);
  if (question === null) return refuse(404, "not_found");
  return json(
    view(question, await votesForQuestion(env.DB, question.id), deps.now),
    200,
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/** The question id in `/votes/{id}`, or null when the path is not that shape. */
function voteId(path: string): string | null {
  const prefix = "/votes/";
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return "";
  }
}

/**
 * Route one request to the vote, or answer null when the path is not ours.
 *
 * The storage boundary is every other door's: a database that does not answer
 * becomes the same JSON 503 rather than a raw 500, and a write that kept losing
 * the log's next position becomes `chain_conflict`.
 */
export async function handleVotes(
  request: Request,
  env: Env,
  deps: VoteDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (path !== "/votes" && voteId(path) === null) return null;

  const guarded = { ...env, DB: guardDatabase(env.DB) };
  try {
    if (path === "/votes") {
      if (request.method === "POST") return await cast(request, guarded, deps, path);
      if (isRead(request)) return await read(guarded, deps, null);
      return methodNotAllowed(`${READ_METHODS}, POST`);
    }
    const id = voteId(path);
    if (id === null) return null;
    if (id === "") return refuse(400, "bad_id");
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return await read(guarded, deps, id);
  } catch (error) {
    const answer = unavailable(error, "votes");
    if (answer !== null) return answer;
    throw error;
  }
}

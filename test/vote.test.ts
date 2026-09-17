/**
 * The governance vote, as a kernel: the window, the electorate, the two
 * "already" rules, the signature and the fold.
 *
 * Decision D-130 item 4: "one operator one vote among senior operators, one
 * vote per disclosed perimeter (so the bootstrap pool of D-128 counts once),
 * cast as a signed sealed event, tallied by derivation ... the tally is
 * advisory to the maintainer until the record's hosting decentralizes."
 *
 * Every case below is one clause of that, checked on the pure module with real
 * Ed25519 keys and real sealed events — no Worker, no database, and no clock
 * but the one handed in. The door's own order is exercised through the Worker
 * in test/m25h-vote-end-to-end.test.ts.
 *
 * No policy number lives here: the window is VOTE_WINDOW_DAYS', the question is
 * VOTE_QUESTIONS', and the options are the question's own.
 */

import { describe, expect, it } from "vitest";

import { appendEvent, type Event, type EventInput } from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  VOTE_QUESTIONS,
  VOTE_QUESTIONS_OPEN_MAX,
  VOTE_WINDOW_DAYS,
  DOMAIN_EARLY_ACCESS_DAYS,
  STANDING_ATTESTATION_SCORED,
  STANDING_SENIOR,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  voteQuestion,
  voteWindow,
} from "../src/policy.js";
import {
  HASH_TAG_VOTE,
  VOTE_REFUSALS,
  checkVote,
  signVote,
  tallyOf,
  verifyVoteSignature,
  voteSigningBytes,
  type VoteFields,
} from "../src/vote.js";
import { verifyVotes } from "../src/verify.js";
import { canonicalize } from "../src/hash.js";

const QUESTION = VOTE_QUESTIONS[0]!;
const WINDOW = voteWindow(QUESTION);
/** A day inside the window, and one after it closed. */
const DURING = new Date(Date.parse(WINDOW.opens) + 3 * 86_400_000);
const BEFORE = new Date(Date.parse(WINDOW.opens) - 1);
const AFTER = new Date(Date.parse(WINDOW.closes));

interface Voter {
  readonly operator: string;
  readonly agent: string;
  readonly key: CryptoKey;
}

async function voter(operator: string): Promise<Voter> {
  const pair = await generateKeypair();
  return {
    operator,
    agent: agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey)),
    key: pair.privateKey,
  };
}

/** The ballot one voter signs. */
function ballot(
  who: Voter,
  choice: string,
  at: Date = DURING,
): VoteFields {
  return {
    question_id: QUESTION.id,
    choice,
    operator: who.operator,
    agent: who.agent,
    signed_at: at.toISOString(),
  };
}

/** One sealed `vote_cast`, chained onto the events before it. */
async function cast(
  events: readonly Event[],
  who: Voter,
  choice: string,
  options: { readonly perimeter?: string | null; readonly at?: Date } = {},
): Promise<Event[]> {
  const at = options.at ?? DURING;
  const fields = ballot(who, choice, at);
  const input: EventInput<"vote_cast"> = {
    at: at.toISOString(),
    type: "vote_cast",
    entry_id: null,
    payload: {
      ...fields,
      perimeter: options.perimeter ?? null,
      signature: await signVote(fields, who.key),
    },
  };
  return appendEvent(events, input);
}

/** The input `checkVote` takes, with the case's own differences applied. */
function input(
  who: Voter,
  overrides: Partial<Parameters<typeof checkVote>[0]> = {},
): Parameters<typeof checkVote>[0] {
  return {
    question: QUESTION,
    choice: "keep",
    operator: who.operator,
    tier: "senior",
    perimeter: null,
    prior: [],
    now: DURING,
    signatureValid: true,
    ...overrides,
  };
}

describe("the question policy publishes", () => {
  it("is one question, composed from the numbers it is about", () => {
    // D-131 item 2: the first question is the six numbers themselves, and the
    // sentence is built from the constants — a number that moved and a question
    // that did not would be a vote about a policy nobody is running.
    expect(VOTE_QUESTIONS.length).toBe(VOTE_QUESTIONS_OPEN_MAX);
    expect(QUESTION.id).toBe("2026-09-17-tier-numbers");
    expect(QUESTION.options).toEqual(["keep", "revisit"]);
    for (const number of [
      WRITES_PER_AGENT_PER_DAY_PROBATION,
      STANDING_SENIOR,
      DOMAIN_EARLY_ACCESS_DAYS,
      WRITES_PER_AGENT_PER_DAY_SENIOR,
    ]) {
      expect(QUESTION.text).toContain(String(number));
    }
    expect(QUESTION.about).toEqual([
      "WRITES_PER_AGENT_PER_DAY_PROBATION",
      "STANDING_SENIOR",
      "DOMAIN_EARLY_ACCESS_DAYS",
      "WRITES_PER_AGENT_PER_DAY_SENIOR",
      "VOTE_QUESTIONS_OPEN_MAX",
      "VOTE_WINDOW_DAYS",
    ]);
    expect(voteQuestion(QUESTION.id)).toBe(QUESTION);
    expect(voteQuestion("no-such-question")).toBeNull();
  });

  it("opens at midnight and closes a window later, end-exclusive", () => {
    expect(WINDOW.opens).toBe(`${QUESTION.opened_at}T00:00:00.000Z`);
    expect(Date.parse(WINDOW.closes) - Date.parse(WINDOW.opens)).toBe(
      VOTE_WINDOW_DAYS * 86_400_000,
    );
  });
});

describe("checkVote", () => {
  it("publishes every refusal it can give, in check order", () => {
    expect([...VOTE_REFUSALS]).toEqual([
      "unknown_question",
      "vote_not_open",
      "vote_closed",
      "bad_choice",
      "insufficient_tier",
      "already_voted",
      "perimeter_voted",
      "bad_signature",
    ]);
  });

  it("takes a senior operator's vote inside the window", async () => {
    const who = await voter("senior.example");
    expect(checkVote(input(who))).toEqual({ ok: true });
  });

  it("refuses a question nobody published", async () => {
    const who = await voter("senior.example");
    expect(checkVote(input(who, { question: null }))).toEqual({
      ok: false,
      reason: "unknown_question",
    });
  });

  it("refuses a vote before the window opens and at the instant it closes", async () => {
    const who = await voter("senior.example");
    expect(checkVote(input(who, { now: BEFORE }))).toEqual({
      ok: false,
      reason: "vote_not_open",
    });
    // End-exclusive: the closing instant is already too late.
    expect(checkVote(input(who, { now: AFTER }))).toEqual({
      ok: false,
      reason: "vote_closed",
    });
    expect(
      checkVote(input(who, { now: new Date(Date.parse(WINDOW.closes) - 1) })),
    ).toEqual({ ok: true });
  });

  it("refuses an option the ballot does not carry", async () => {
    const who = await voter("senior.example");
    for (const choice of ["abstain", "", 3, null]) {
      expect(checkVote(input(who, { choice }))).toEqual({
        ok: false,
        reason: "bad_choice",
      });
    }
  });

  it("refuses everybody below senior", async () => {
    const who = await voter("k1.example");
    for (const tier of ["probation", "established"] as const) {
      expect(checkVote(input(who, { tier }))).toEqual({
        ok: false,
        reason: "insufficient_tier",
      });
    }
  });

  it("refuses a second vote by the same operator", async () => {
    const who = await voter("senior.example");
    const prior = await cast([], who, "keep");
    expect(checkVote(input(who, { prior }))).toEqual({
      ok: false,
      reason: "already_voted",
    });
  });

  it("refuses a second operator inside one disclosed perimeter", async () => {
    // D-128's bootstrap pool: the maintainer named seed-a, seed-b and seed-c
    // inside one disclosed perimeter, so the three of them are one party and
    // the first to vote is the one that votes.
    const seedA = await voter("seed-a.example");
    const seedB = await voter("seed-b.example");
    const prior = await cast([], seedA, "keep", { perimeter: "maintainer" });

    expect(
      checkVote(input(seedB, { prior, perimeter: "maintainer" })),
    ).toEqual({ ok: false, reason: "perimeter_voted" });

    // And an operator that disclosed no perimeter is its own party: null is not
    // a group, so a second unaffiliated operator is not silenced by the first.
    const stranger = await voter("stranger.example");
    const unaffiliated = await cast([], stranger, "revisit");
    const another = await voter("another.example");
    expect(checkVote(input(another, { prior: unaffiliated }))).toEqual({
      ok: true,
    });
  });

  it("refuses a vote whose signature does not verify, and asks last", async () => {
    const who = await voter("senior.example");
    expect(checkVote(input(who, { signatureValid: false }))).toEqual({
      ok: false,
      reason: "bad_signature",
    });
    // Last, so a refusal never tells a stranger which of the other seven they
    // also failed: a bad choice and a bad signature answer about the choice.
    expect(
      checkVote(input(who, { signatureValid: false, choice: "abstain" })),
    ).toEqual({ ok: false, reason: "bad_choice" });
  });
});

describe("the vote signature", () => {
  it("is the tag, a newline and the canonical ballot", async () => {
    const who = await voter("senior.example");
    const fields = ballot(who, "keep");
    const bytes = voteSigningBytes(fields);
    expect(new TextDecoder().decode(bytes)).toBe(
      `${HASH_TAG_VOTE}\n${canonicalize({
        question_id: fields.question_id,
        choice: fields.choice,
        operator: fields.operator,
        agent: fields.agent,
        signed_at: fields.signed_at,
      })}`,
    );

    const signature = await signVote(fields, who.key);
    expect(await verifyVoteSignature(fields, signature)).toBe(true);
  });

  it("cannot be moved onto another question, choice, voter or instant", async () => {
    const who = await voter("senior.example");
    const other = await voter("other.example");
    const fields = ballot(who, "keep");
    const signature = await signVote(fields, who.key);

    for (const doctored of [
      { ...fields, question_id: "2026-10-01-something-else" },
      { ...fields, choice: "revisit" },
      { ...fields, operator: other.operator },
      { ...fields, agent: other.agent },
      { ...fields, signed_at: AFTER.toISOString() },
    ]) {
      expect(await verifyVoteSignature(doctored, signature)).toBe(false);
    }

    // A stranger's file is data: malformed input is a verdict, never a throw.
    expect(await verifyVoteSignature(fields, "!not-base64url!")).toBe(false);
    expect(
      await verifyVoteSignature({ ...fields, agent: "not-an-agent" }, signature),
    ).toBe(false);
  });
});

describe("tallyOf", () => {
  it("counts one vote per operator and one per perimeter, by the first sealed", async () => {
    const seedA = await voter("seed-a.example");
    const seedB = await voter("seed-b.example");
    const stranger = await voter("stranger.example");

    let events = await cast([], seedA, "keep", { perimeter: "maintainer" });
    // A second vote by the same operator, and one by its perimeter's sibling:
    // the door refuses both, and the fold ignores both, so a log that somehow
    // held them still counts what the rule says.
    events = await cast(events, seedA, "revisit", { perimeter: "maintainer" });
    events = await cast(events, seedB, "revisit", { perimeter: "maintainer" });
    events = await cast(events, stranger, "revisit");

    const tally = tallyOf(events, QUESTION, DURING);
    expect(tally.counts).toEqual({ keep: 1, revisit: 1 });
    expect(tally.voters.map((one) => one.operator)).toEqual([
      "seed-a.example",
      "stranger.example",
    ]);
    expect(tally.voters[0]).toMatchObject({ perimeter: "maintainer", seq: 0 });
    expect(tally.question_id).toBe(QUESTION.id);
    // "The tally is advisory to the maintainer until the record's hosting
    // decentralizes", said in the answer rather than beside it.
    expect(tally.advisory).toBe(true);
  });

  it("carries a zero for every option nobody chose, and the window either way", async () => {
    const empty = tallyOf([], QUESTION, DURING);
    expect(empty.counts).toEqual({ keep: 0, revisit: 0 });
    expect(empty.voters).toEqual([]);
    expect([empty.opens, empty.closes]).toEqual([WINDOW.opens, WINDOW.closes]);
    // Three states, because the window has three sides: a question policy has
    // published but whose day has not come is not open, and calling it open
    // would invite a vote the door refuses `vote_not_open`.
    expect(empty.state).toBe("open");
    expect(tallyOf([], QUESTION, AFTER).state).toBe("closed");
    expect(tallyOf([], QUESTION, BEFORE).state).toBe("not_open");
    expect(tallyOf([], QUESTION, new Date(Date.parse(WINDOW.opens))).state).toBe(
      "open",
    );
  });

  it("is named by the question or by its id, and refuses an id nobody published", async () => {
    const who = await voter("senior.example");
    const events = await cast([], who, "keep");
    expect(tallyOf(events, QUESTION.id, DURING.toISOString())).toEqual(
      tallyOf(events, QUESTION, DURING),
    );
    expect(() => tallyOf(events, "no-such-question", DURING)).toThrow(
      /no such question/,
    );
  });

  it("ignores a vote on another question and a choice the ballot never had", async () => {
    const who = await voter("senior.example");
    const other = await voter("other.example");
    let events = await cast([], who, "keep");
    // Hand-built, because no door would take either: another question's id, and
    // an option this question does not offer.
    events = await appendEvent(events, {
      at: DURING.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        question_id: "2026-10-01-something-else",
        choice: "keep",
        operator: other.operator,
        agent: other.agent,
        perimeter: null,
        signed_at: DURING.toISOString(),
        signature: "x",
      },
    });
    events = await appendEvent(events, {
      at: DURING.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        question_id: QUESTION.id,
        choice: "abstain",
        operator: other.operator,
        agent: other.agent,
        perimeter: null,
        signed_at: DURING.toISOString(),
        signature: "x",
      },
    });

    const tally = tallyOf(events, QUESTION, DURING);
    expect(tally.counts).toEqual({ keep: 1, revisit: 0 });
    expect(tally.voters.length).toBe(1);
  });
});

  it("does not let a ballot nobody offered spend an operator's turn", async () => {
    const who = await voter("senior.example");
    const seed = await voter("seed-a.example");

    // A first ballot for an option the question does not carry, then a real one
    // from the same operator: the first is not a vote, so it takes nothing away
    // and the second is counted. The same for a perimeter's one turn.
    let events = await appendEvent([], {
      at: DURING.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        question_id: QUESTION.id,
        choice: "abstain",
        operator: who.operator,
        agent: who.agent,
        perimeter: "maintainer",
        signed_at: DURING.toISOString(),
        signature: "x",
      },
    });
    events = await cast(events, who, "keep", { perimeter: "maintainer" });
    // And the perimeter's turn is still there for the sibling to lose to the
    // operator above, rather than to the ballot nobody offered.
    events = await cast(events, seed, "revisit", { perimeter: "maintainer" });

    const tally = tallyOf(events, QUESTION, DURING);
    expect(tally.counts).toEqual({ keep: 1, revisit: 0 });
    expect(tally.voters.map((one) => one.operator)).toEqual(["senior.example"]);
  });

describe("the verifier over a log of votes", () => {
  /** A log where one operator earned senior standing, then voted. */
  async function seniorVote(options: {
    readonly choice?: string;
    readonly doctor?: boolean;
    readonly twice?: boolean;
    readonly perimeter?: string | null;
  } = {}): Promise<{ events: Event[]; who: Voter }> {
    const who = await voter("senior.example");
    // Standing is earned, so the fixture earns it: enough scored drift
    // attestations to carry the operator to STANDING_SENIOR. Scores rather than
    // validations because a score is about a model and not about an entry
    // (src/events.ts), so the fold pays them without the fixture having to
    // invent fifty entries for the derivation to read.
    let events: Event[] = [];
    events = await appendEvent(events, {
      at: "2026-09-10T00:00:00.000Z",
      type: "operator_registered",
      entry_id: null,
      payload: { operator: who.operator, maintainer: false },
    });
    events = await appendEvent(events, {
      at: "2026-09-10T00:00:01.000Z",
      type: "operator_trusted",
      entry_id: null,
      payload: { operator: who.operator },
    });
    const scores = Math.ceil(STANDING_SENIOR / STANDING_ATTESTATION_SCORED);
    for (let index = 0; index < scores; index += 1) {
      events = await appendEvent(events, {
        at: "2026-09-11T00:00:00.000Z",
        type: "attestation_scored",
        entry_id: null,
        payload: {
          attestation: `att_${index}`,
          record: {
            agent: who.agent,
            operator: who.operator,
            agreed: 10,
            probe_hash: `sha256:${"0".repeat(64)}`,
            answers_hash: `sha256:${"1".repeat(64)}`,
            signed_at: "2026-09-11T00:00:00.000Z",
          },
          signature: "x",
        },
      });
    }

    const fields = ballot(who, options.choice ?? "keep");
    const signature = await signVote(fields, who.key);
    events = await appendEvent(events, {
      at: DURING.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        ...fields,
        perimeter: options.perimeter ?? null,
        // A doctored vote: the choice the log carries is not the choice that
        // was signed for.
        ...(options.doctor === true ? { choice: "revisit" } : {}),
        signature,
      },
    });
    if (options.twice === true) {
      events = await cast(events, who, "revisit", {
        perimeter: options.perimeter ?? null,
      });
    }
    return { events, who };
  }

  /** The bundle shape `verifyVotes` reads; only the events matter to it. */
  function bundle(events: readonly Event[]): Parameters<typeof verifyVotes>[0] {
    return {
      as_of: DURING.toISOString(),
      events: [...events],
      registry: { agents: {}, operators: {} },
      seals: [],
      captures: {},
    };
  }

  it("passes a signed vote by an operator that was senior at its position", async () => {
    const { events } = await seniorVote();
    const report = await verifyVotes(bundle(events));
    expect(report.ok).toBe(true);
    expect(report.questions.length).toBe(1);
    expect(report.questions[0]?.tally?.counts).toEqual({ keep: 1, revisit: 0 });
  });

  it("says nothing at all about a log that holds no vote", async () => {
    const report = await verifyVotes(bundle([]));
    expect(report).toEqual({ ok: true, questions: [] });
  });

  it("names a doctored vote vote_signature_invalid", async () => {
    const { events } = await seniorVote({ doctor: true });
    const report = await verifyVotes(bundle(events));
    expect(report.ok).toBe(false);
    expect(report.questions[0]?.diffs.map((diff) => diff.reason)).toContain(
      "vote_signature_invalid",
    );
    expect(report.questions[0]?.diffs[0]?.check).toBe("vote_signature");
  });

  it("names a vote by an operator that was not senior vote_ineligible", async () => {
    // No standing at all: the signature is sound and the voter is nobody the
    // electorate holds, which is the log's own business to notice.
    const who = await voter("nobody.example");
    const fields = ballot(who, "keep");
    const events = await appendEvent([], {
      at: DURING.toISOString(),
      type: "vote_cast",
      entry_id: null,
      payload: {
        ...fields,
        perimeter: null,
        signature: await signVote(fields, who.key),
      },
    });

    const report = await verifyVotes(bundle(events));
    expect(report.ok).toBe(false);
    const diff = report.questions[0]?.diffs[0];
    expect([diff?.check, diff?.reason, diff?.expected]).toEqual([
      "vote_eligibility",
      "vote_ineligible",
      "senior",
    ]);
  });

  it("names a second vote vote_duplicate, by the operator and by the perimeter", async () => {
    const { events } = await seniorVote({ twice: true, perimeter: "maintainer" });
    const report = await verifyVotes(bundle(events));
    expect(report.ok).toBe(false);
    const reasons = report.questions[0]?.diffs.map((diff) => diff.reason) ?? [];
    expect(reasons.filter((reason) => reason === "vote_duplicate").length).toBe(
      2,
    );
    // And the fold still counts it once, which is what the door's refusal and
    // the tally's dedupe agree about.
    expect(report.questions[0]?.tally?.counts).toEqual({ keep: 1, revisit: 0 });
  });
});

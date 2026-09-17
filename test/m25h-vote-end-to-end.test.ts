/**
 * The governance vote through the real Worker (decision D-130 item 4).
 *
 * One miniflare D1, one frozen clock and the real router for every request.
 * What a senior operator meets: a ballot that seals and tallies, a second one
 * refused, a sibling inside the same disclosed perimeter refused, an operator
 * below senior refused in the tier's own word, and a vote after the window
 * refused by the calendar. And what a reader meets: `GET /votes`, the event on
 * the delta stream, and the whole thing rechecked offline by `verifyVotes` over
 * the log the Worker sealed.
 *
 * The bootstrap pool is the perimeter case and is why it is here (D-128): the
 * maintainer named its seed operators inside one disclosed perimeter, and the
 * vote must count that pool once however many operators it runs.
 *
 * No policy number lives here: the window and the question are src/policy.ts's,
 * and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { base64urlEncode } from "../src/encoding.js";
import { appendEvent, type Event } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import {
  LIST_PAGE_LIMIT,
  STANDING_ATTESTATION_SCORED,
  STANDING_SENIOR,
  STANDING_TRUSTED_ENTRY,
  VOTE_QUESTIONS,
  voteWindow,
} from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { appendEvents, eventsAfter } from "../src/storage/repository.js";
import { signVote, tallyOf } from "../src/vote.js";
import { verifyVotes } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { clearWriteQuota } from "./helpers/quota.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedGet,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";
import { SUBMIT_NOW } from "./helpers/submit.js";

const QUESTION = VOTE_QUESTIONS[0]!;
const WINDOW = voteWindow(QUESTION);

/** The registrations happen before the question opens; the votes inside it. */
const REGISTERED_AT = SUBMIT_NOW;
const DURING = new Date(Date.parse(WINDOW.opens) + 2 * 86_400_000);
const AFTER = new Date(Date.parse(WINDOW.closes) + 1000);

/** The perimeter the maintainer disclosed over its seed operators (D-128). */
const PERIMETER = "maintainer";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;

/** Two seed operators inside one disclosed perimeter, and one outside it. */
let seedA: Party;
let seedB: Party;
let outside: Party;
/** A second unaffiliated senior, for the cases that must not be refused for
 * having voted already. */
let fourth: Party;
/** Standing enough to be established and never enough to be senior. */
let established: Party;

function send(request: Request, now: Date = DURING): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  now: Date = DURING,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    await signedPost(agent, { path, body, timestamp: now.toISOString() }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function get(
  path: string,
  now: Date = DURING,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, { method: "GET" }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One ballot, signed by the voter's own key exactly as a client would. */
async function vote(
  party: Party,
  choice: string,
  options: { readonly now?: Date; readonly questionId?: string } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const now = options.now ?? DURING;
  const questionId = options.questionId ?? QUESTION.id;
  const signedAt = now.toISOString();
  const signature = await signVote(
    {
      question_id: questionId,
      choice,
      operator: party.operator,
      agent: party.agent.agentId,
      signed_at: signedAt,
    },
    party.agent.privateKey,
  );
  await clearWriteQuota(store.db);
  return post(
    party.agent,
    "/votes",
    { question_id: questionId, choice, signed_at: signedAt, signature },
    now,
  );
}

async function register(party: Party): Promise<void> {
  await clearWriteQuota(store.db);
  const answer = await post(
    party.agent,
    "/operators",
    {
      operator: party.operator,
      attestation: await attestFor(
        party.agent,
        party.operator,
        REGISTERED_AT.toISOString(),
      ),
    },
    REGISTERED_AT,
  );
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

/** The genesis naming, with the perimeter the maintainer discloses (D-128). */
async function name(party: Party, perimeter?: string): Promise<void> {
  await clearWriteQuota(store.db);
  const answer = await post(
    maintainer,
    "/genesis",
    {
      operator: party.operator,
      ...(perimeter === undefined ? {} : { perimeter }),
    },
    REGISTERED_AT,
  );
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** Run the sweep the alarm runs, which is what seals the log. */
async function sweep(at: Date): Promise<void> {
  const beacon = new FixtureBeacon("m25h-vote");
  await beacon.advance(at.toISOString());
  await runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

/**
 * Earn one operator its standing, in events.
 *
 * Not a shortcut: the vote's electorate is folded from the sealed log by the
 * door and by the verifier alike (Section 9's published formula), so a fixture
 * that wrote a number into the standing column would be a fixture the verifier
 * then refuses. What is earned here is drift scores — completed work the fold
 * pays at `STANDING_ATTESTATION_SCORED` — because a score is about a model and
 * not about an entry, so fifty of them need no fifty entries behind them.
 */
async function earn(party: Party, standing: number): Promise<void> {
  const scores = Math.ceil(standing / STANDING_ATTESTATION_SCORED);
  let chain: Event[] = await eventsAfter(store.db, -1, 100_000);
  const added: Event[] = [];
  for (let index = 0; index < scores; index += 1) {
    chain = await appendEvent(chain, {
      at: REGISTERED_AT.toISOString(),
      type: "attestation_scored",
      entry_id: null,
      payload: {
        attestation: `att_${party.operator}_${index}`,
        record: {
          agent: party.agent.agentId,
          operator: party.operator,
          agreed: 10,
          probe_hash: `sha256:${"0".repeat(64)}`,
          answers_hash: `sha256:${"1".repeat(64)}`,
          signed_at: REGISTERED_AT.toISOString(),
        },
        signature: "x",
      },
    });
    added.push(chain[chain.length - 1]!);
  }
  await appendEvents(store.db, added);
}

beforeAll(async () => {
  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );

  store = await openTestDatabase();
  maintainer = await makeAgent();
  seedA = { operator: "seed-a.example", agent: await makeAgent() };
  seedB = { operator: "seed-b.example", agent: await makeAgent() };
  outside = { operator: "outside.example", agent: await makeAgent() };
  fourth = { operator: "fourth.example", agent: await makeAgent() };
  established = { operator: "established.example", agent: await makeAgent() };

  const records: Record<string, string[]> = {};
  for (const party of [seedA, seedB, outside, fourth, established]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
  };
  deps = { now: REGISTERED_AT, dns: new FixtureResolver(records) };

  for (const party of [seedA, seedB, outside, fourth, established]) {
    await register(party);
  }
  // The bootstrap pool: two operators named inside one disclosed perimeter, and
  // one named outside every perimeter. The fourth is never named at all.
  await name(seedA, PERIMETER);
  await name(seedB, PERIMETER);
  await name(outside);
  await name(fourth);

  // The electorate this file is about: three senior operators and one
  // established, every one of them standing on work the log holds.
  await earn(seedA, STANDING_SENIOR);
  await earn(seedB, STANDING_SENIOR);
  await earn(outside, STANDING_SENIOR);
  await earn(fourth, STANDING_SENIOR);
  await earn(established, STANDING_TRUSTED_ENTRY);

  // And a seal over all of it, so the door's tier fold has a sealed log to read
  // and the stream has something to deliver. Twice, because one seal covers at
  // most SEAL_MAX_EVENTS and this fixture's log is longer than that: the fold
  // reads the sealed head, and an operator whose work was not sealed yet has
  // not earned anything yet.
  await sweep(REGISTERED_AT);
  await sweep(REGISTERED_AT);
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("casting a vote", () => {
  it("seals the ballot and answers with the tally it produced", async () => {
    const answer = await vote(seedA, "keep");
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const event = answer.body["event"] as Record<string, unknown>;
    expect(event["type"]).toBe("vote_cast");
    expect(event["entry_id"]).toBeNull();
    expect(event["payload"]).toMatchObject({
      question_id: QUESTION.id,
      choice: "keep",
      operator: seedA.operator,
      agent: seedA.agent.agentId,
      // The perimeter the registry disclosed, snapshotted into the event so the
      // tally can be recomputed at this position years from now.
      perimeter: PERIMETER,
    });

    const tally = answer.body["tally"] as Record<string, unknown>;
    expect(tally["counts"]).toEqual({ keep: 1, revisit: 0 });
    expect(tally["state"]).toBe("open");
    expect(tally["advisory"]).toBe(true);
  });

  it("refuses the same operator a second time", async () => {
    const answer = await vote(seedA, "revisit");
    expect([answer.status, answer.body["error"]]).toEqual([409, "already_voted"]);
  });

  it("refuses a sibling inside the same disclosed perimeter", async () => {
    // D-128's bootstrap pool counts once: seed-b is senior, registered and
    // named, and its perimeter has already voted.
    const answer = await vote(seedB, "revisit");
    expect([answer.status, answer.body["error"]]).toEqual([
      409,
      "perimeter_voted",
    ]);
  });

  it("takes an operator outside every perimeter", async () => {
    const answer = await vote(outside, "revisit");
    expect(answer.status).toBe(201);
    expect((answer.body["tally"] as Record<string, unknown>)["counts"]).toEqual({
      keep: 1,
      revisit: 1,
    });
  });

  it("refuses an operator below senior in the tier's own word", async () => {
    const answer = await vote(established, "keep");
    expect([answer.status, answer.body["error"]]).toEqual([
      403,
      "insufficient_tier",
    ]);
  });

  it("refuses an option the ballot does not carry, and a question nobody published", async () => {
    const bad = await vote(established, "abstain");
    // The choice is asked before the tier: a ballot that is not on the paper is
    // malformed whoever sent it.
    expect([bad.status, bad.body["error"]]).toEqual([422, "bad_choice"]);

    const unknown = await vote(seedB, "keep", {
      questionId: "2026-10-01-no-such-question",
    });
    expect([unknown.status, unknown.body["error"]]).toEqual([
      404,
      "unknown_question",
    ]);
  });

  it("refuses a vote once the window has run out", async () => {
    // The fake clock, past the end-exclusive close: everything else about this
    // request is exactly the vote that was taken above.
    const answer = await vote(seedB, "keep", { now: AFTER });
    expect([answer.status, answer.body["error"]]).toEqual([409, "vote_closed"]);
  });

  it("refuses a bare key, which is nobody's operator", async () => {
    const stranger = await makeAgent();
    const signedAt = DURING.toISOString();
    const signature = await signVote(
      {
        question_id: QUESTION.id,
        choice: "keep",
        operator: "",
        agent: stranger.agentId,
        signed_at: signedAt,
      },
      stranger.privateKey,
    );
    await clearWriteQuota(store.db);
    const answer = await post(stranger, "/votes", {
      question_id: QUESTION.id,
      choice: "keep",
      signed_at: signedAt,
      signature,
    });
    expect([answer.status, answer.body["error"]]).toEqual([403, "bare_key"]);
  });

  it("refuses a ballot somebody else signed", async () => {
    // The envelope is the fourth senior's and the vote inside it was signed by
    // a key that is not its own: the door checks both, and the vote's own
    // signature is the one a reader rechecks offline. Asked of an operator
    // every other rule passes, because the signature is checked last.
    const signedAt = DURING.toISOString();
    const signature = await signVote(
      {
        question_id: QUESTION.id,
        choice: "keep",
        operator: fourth.operator,
        agent: fourth.agent.agentId,
        signed_at: signedAt,
      },
      outside.agent.privateKey,
    );
    await clearWriteQuota(store.db);
    const answer = await post(fourth.agent, "/votes", {
      question_id: QUESTION.id,
      choice: "keep",
      signed_at: signedAt,
      signature,
    });
    expect([answer.status, answer.body["error"]]).toEqual([422, "bad_signature"]);
  });
});

describe("the reads", () => {
  it("publishes every question with its tally at GET /votes", async () => {
    const answer = await get("/votes");
    expect(answer.status).toBe(200);
    const questions = answer.body["questions"] as Record<string, unknown>[];
    expect(questions.length).toBe(VOTE_QUESTIONS.length);

    const first = questions[0]!;
    expect((first["question"] as Record<string, unknown>)["id"]).toBe(
      QUESTION.id,
    );
    const tally = first["tally"] as Record<string, unknown>;
    expect(tally["counts"]).toEqual({ keep: 1, revisit: 1 });
    expect(tally["advisory"]).toBe(true);
    expect(
      (tally["voters"] as Record<string, unknown>[]).map(
        (one) => one["operator"],
      ),
    ).toEqual([seedA.operator, outside.operator]);
  });

  it("answers one question at GET /votes/{id}, and 404s an id nobody published", async () => {
    const one = await get(`/votes/${encodeURIComponent(QUESTION.id)}`);
    expect(one.status).toBe(200);
    expect((one.body["question"] as Record<string, unknown>)["id"]).toBe(
      QUESTION.id,
    );
    expect((one.body["tally"] as Record<string, unknown>)["counts"]).toEqual({
      keep: 1,
      revisit: 1,
    });

    expect((await get("/votes/2026-10-01-no-such-question")).status).toBe(404);
  });

  it("closes the question by the clock, not by anything stored", async () => {
    const open = await get("/votes", DURING);
    const closed = await get("/votes", AFTER);
    const stateOf = (answer: { body: Record<string, unknown> }): unknown =>
      (
        (answer.body["questions"] as Record<string, unknown>[])[0]?.[
          "tally"
        ] as Record<string, unknown>
      )["state"];
    expect([stateOf(open), stateOf(closed)]).toEqual(["open", "closed"]);
  });
});

describe("the log the votes are in", () => {
  it("carries each vote on the delta stream as an event item", async () => {
    // Sealed first: the stream is strictly by sealed position, and a vote the
    // log has not committed to has no proof to deliver with it.
    await sweep(DURING);
    // The stream is one page of the log at a time, and this fixture's log is
    // mostly the work the electorate earned its standing with: the page is
    // asked for from the first vote's own position, exactly as a trainer
    // resuming from a position it already holds asks for one.
    const sealed = await eventsAfter(store.db, -1, 100_000);
    const firstVote = sealed.find((event) => event.type === "vote_cast");
    expect(firstVote).toBeDefined();
    const response = await send(
      await signedGet(seedA.agent, {
        path: `/sync?from=${firstVote?.seq ?? 0}`,
        timestamp: DURING.toISOString(),
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    const items = body["events"] as Record<string, unknown>[];

    const votes = items.filter(
      (item) =>
        ((item["event"] as Record<string, unknown>)["type"] as string) ===
        "vote_cast",
    );
    expect(votes.length).toBe(2);
    for (const item of votes) {
      // About no entry, so it rides as an "event" item with its proof and no
      // entry state beside it.
      expect(item["kind"]).toBe("event");
      expect(item["entry"]).toBeNull();
      expect(item["proof"]).toBeTruthy();
    }
  });

  it("verifies offline, and folds to the same tally a reader recomputes", async () => {
    const events: Event[] = await eventsAfter(store.db, -1, 100_000);
    const report = await verifyVotes({
      as_of: DURING.toISOString(),
      events,
      registry: { agents: {}, operators: {} },
      seals: [],
      captures: {},
    });
    expect(report.ok).toBe(true);
    expect(report.questions.length).toBe(1);

    // The same numbers the door served, recomputed from the log by somebody who
    // was not here: that is the whole promise of tallying by derivation.
    const recomputed = tallyOf(events, QUESTION, DURING);
    expect(recomputed.counts).toEqual({ keep: 1, revisit: 1 });
    expect(recomputed.voters.map((one) => one.operator)).toEqual([
      seedA.operator,
      outside.operator,
    ]);
    expect(recomputed.voters[0]?.perimeter).toBe(PERIMETER);

    const served = await get("/votes");
    expect(
      (
        (served.body["questions"] as Record<string, unknown>[])[0]?.[
          "tally"
        ] as Record<string, unknown>
      )["counts"],
    ).toEqual(recomputed.counts);
  });

  it("holds exactly the two votes it took, and no row anywhere else", async () => {
    const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 10);
    expect(events.filter((event) => event.type === "vote_cast").length).toBe(2);
  });
});

describe("a log with more ballots than one page", () => {
  it("still finds an operator's first vote, and refuses the second", async () => {
    // The bug this pins: a door that read the votes one page at a time would,
    // past a page of ballots, stop seeing the oldest — and take a second vote
    // from an operator that had already voted, which the verifier would then
    // name `vote_duplicate` against a log the door itself wrote.
    //
    // So the log is stacked against it: a page of ballots on another question
    // first, and this operator's own vote after them. A read of the first page
    // of `vote_cast` by type alone sees none of this question's votes at all.
    const OTHER = "2026-10-01-another-question";
    let chain: Event[] = await eventsAfter(store.db, -1, 100_000);
    const added: Event[] = [];
    const push = async (
      payload: Record<string, unknown>,
    ): Promise<void> => {
      chain = await appendEvent(chain, {
        at: DURING.toISOString(),
        type: "vote_cast",
        entry_id: null,
        payload: payload as never,
      });
      added.push(chain[chain.length - 1]!);
    };

    for (let index = 0; index < LIST_PAGE_LIMIT; index += 1) {
      await push({
        question_id: OTHER,
        choice: "keep",
        operator: `filler-${index}.example`,
        agent: `1F916:filler-${index}`,
        perimeter: null,
        signed_at: DURING.toISOString(),
        signature: "x",
      });
    }

    const signedAt = DURING.toISOString();
    await push({
      question_id: QUESTION.id,
      choice: "keep",
      operator: fourth.operator,
      agent: fourth.agent.agentId,
      perimeter: null,
      signed_at: signedAt,
      signature: await signVote(
        {
          question_id: QUESTION.id,
          choice: "keep",
          operator: fourth.operator,
          agent: fourth.agent.agentId,
          signed_at: signedAt,
        },
        fourth.agent.privateKey,
      ),
    });
    await appendEvents(store.db, added);

    const all = await eventsAfter(store.db, -1, 100_000);
    expect(all.filter((event) => event.type === "vote_cast").length).toBe(
      LIST_PAGE_LIMIT + 3,
    );

    // The door reads this question's ballots in full, so it sees the vote that
    // is a page and a half back and refuses the second one.
    const again = await vote(fourth, "revisit");
    expect([again.status, again.body["error"]]).toEqual([409, "already_voted"]);

    // And both reads still tally this question and not the other one.
    const answer = await get(`/votes/${encodeURIComponent(QUESTION.id)}`);
    expect((answer.body["tally"] as Record<string, unknown>)["counts"]).toEqual({
      keep: 2,
      revisit: 1,
    });
  }, 240_000);
});

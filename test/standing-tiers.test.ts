/**
 * Standing as an asset: the tiers, the Record marks, and the doors they gate.
 *
 * Decision D-130. "Standing is an asset: public and named ... participation is
 * gated on it by tiers as published policy: probation below
 * STANDING_TRUSTED_ENTRY may volunteer validations, submits at a probationary
 * write cap, is not in the draw, cannot file disputes or revalidation requests;
 * established at trusted standing has the full cap, the draw, disputes, domain
 * joins; senior above STANDING_SENIOR has a higher write cap, early access to a
 * newly registered domain for DOMAIN_EARLY_ACCESS_DAYS, and the vote."
 *
 * Four things are checked here and each is one half of that sentence: where the
 * bands begin and end, that the marks a reader sees are exactly the burns the
 * fold counted, that the two doors a probation operator may not knock on answer
 * in the new word before they do any work, and that the three write caps are the
 * three the charge step actually applies.
 *
 * No policy number lives here: every bar and every cap is read from
 * src/policy.ts, and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import { appendEvent, type Event, type EventInput } from "../src/events.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_EARLY_ACCESS_DAYS,
  NORM_VERSION,
  STANDING_SENIOR,
  STANDING_TRUSTED_ENTRY,
  TIERS,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  domainPolicy,
} from "../src/policy.js";
import { marksOf, standingAt, tierOf } from "../src/standing.js";
import {
  putAgent,
  putOperator,
  setOperatorStanding,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { chargeWrite } from "../src/worker/registry.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import { clearWriteQuota } from "./helpers/quota.js";

/** A day the ai-ecosystem domain is long out of its early-access window on. */
const NOW = new Date("2026-09-30T09:00:00.000Z");
/** And a day inside the window of the domain registered on 2026-09-11. */
const EARLY = new Date("2026-09-12T09:00:00.000Z");

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;

/** The agent of an operator at each tier, bound in the store. */
const agents: Record<string, TestAgent> = {};

/** One operator row at a standing, trusted or not, with one agent bound. */
async function operator(
  id: string,
  standing: number,
  trusted: boolean,
): Promise<TestAgent> {
  await putOperator(store.db, {
    id,
    kind: "domain",
    maintainer: false,
    provider: false,
    registeredSeq: 0,
    details: { operator: id, trusted },
  });
  const agent = await makeAgent();
  await putAgent(store.db, {
    agentId: agent.agentId,
    operatorId: id,
    registeredSeq: 0,
  });
  await setOperatorStanding(store.db, id, standing, 0);
  return agent;
}

beforeAll(async () => {
  store = await openTestDatabase();
  const maintainer = await makeAgent();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: "",
  };
  deps = { now: NOW, dns: new FixtureResolver({}) };

  // Neither trusted nor at the bar: the only way to be on probation.
  agents["probation"] = await operator(
    "probation.example",
    STANDING_TRUSTED_ENTRY - 1,
    false,
  );
  agents["established"] = await operator(
    "established.example",
    STANDING_TRUSTED_ENTRY,
    true,
  );
  // Named at genesis and never funded, which is how the record's own seed
  // operators stand: trusted, standing zero, established by the naming.
  agents["named"] = await operator("named.example", 0, true);
  agents["senior"] = await operator("senior.example", STANDING_SENIOR, true);
  agents["bare"] = await makeAgent();
});

afterAll(async () => {
  await store?.dispose();
});

describe("tierOf, at the bars themselves", () => {
  it("reads the three bands off the two published numbers", () => {
    expect([...TIERS]).toEqual(["probation", "established", "senior"]);

    // Probation is neither half of trusted standing: outside the pool and below
    // the bar the pool's own entry rule uses.
    expect(tierOf(0, false)).toBe("probation");
    expect(tierOf(STANDING_TRUSTED_ENTRY - 1, false)).toBe("probation");

    // Either half is enough to be established. The pool, whatever the number —
    // a genesis naming grants trust and no standing at all (Section 11, D-130
    // item 5), and the record's own seed operators are named that way.
    expect(tierOf(0, true)).toBe("established");
    expect(tierOf(STANDING_TRUSTED_ENTRY - 1, true)).toBe("established");
    // Or the number, whatever the pool: the bar is also the dispute stake, so
    // an operator that can cover a filing is one that may make it, and the
    // sweep's timer never decides that.
    expect(tierOf(STANDING_TRUSTED_ENTRY, false)).toBe("established");
    expect(tierOf(STANDING_SENIOR, false)).toBe("established");
    expect(tierOf(STANDING_SENIOR - 1, true)).toBe("established");

    // Senior asks for both: what it buys is discretionary, and Section 10 keeps
    // the discretionary things from every party the pool excludes.
    expect(tierOf(STANDING_SENIOR, true)).toBe("senior");
    expect(tierOf(STANDING_SENIOR + 1, true)).toBe("senior");
  });
});

/** One entry's events, built by the real kernel so the fold reads real ones. */
async function log(inputs: readonly EventInput[]): Promise<Event[]> {
  let events: Event[] = [];
  for (const input of inputs) events = await appendEvent(events, input);
  return events;
}

/**
 * One submission of `entry-1`, by this operator.
 *
 * A whole core, because the fold derives the entry to decide whether the
 * submission credit is due: a half-built one would be a fixture the real
 * derivation never sees.
 */
function submitted(operator: string, agent: string): EventInput {
  return {
    at: "2026-09-02T00:00:00.000Z",
    type: "entry_submitted",
    entry_id: "entry-1",
    payload: {
      core: {
        id: "entry-1",
        subject: "example/kestrel-1",
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-1 seat pricing is $40 per seat per month",
        before: "$30 per seat per month",
        after: "$40 per seat per month",
        effective_at: "2026-09-01",
        evidence_tier: "stated",
        evidence: null,
        observation: null,
        citation: "https://example.test/pricing",
        snapshot_hash: `sha256:${"0".repeat(64)}`,
        norm_version: NORM_VERSION,
        supersedes: null,
        author: agent,
        author_operator: operator,
        submitted_at: "2026-09-02T00:00:00.000Z",
      } as Core,
      signature: "x",
    },
  };
}

describe("the Record marks", () => {
  /**
   * A log with one of each mark against one operator: an entry it approved and
   * an upheld dispute that overturned, an assignment it never answered, and a
   * challenge of its own that failed.
   */
  async function markedLog(): Promise<Event[]> {
    const marked = "marked.example";
    return log([
      {
        at: "2026-09-01T00:00:00.000Z",
        type: "operator_registered",
        entry_id: null,
        payload: { operator: marked, maintainer: false, domain: DEFAULT_DOMAIN },
      },
      submitted("other.example", "1F916:author"),
      {
        at: "2026-09-03T00:00:00.000Z",
        type: "validation",
        entry_id: "entry-1",
        payload: {
          record: {
            agent: "1F916:marked",
            operator: marked,
            decision: "approve",
            assigned_random: false,
            signed_at: "2026-09-03T00:00:00.000Z",
          },
          signature: "x",
        },
      },
      {
        at: "2026-09-04T00:00:00.000Z",
        type: "dispute_upheld",
        entry_id: "entry-1",
        payload: { correction_entry_id: "correction-1" },
      },
      {
        at: "2026-09-05T00:00:00.000Z",
        type: "assignment_missed",
        entry_id: "entry-2",
        payload: { agent: "1F916:marked", operator: marked },
      },
      {
        at: "2026-09-06T00:00:00.000Z",
        type: "dispute_filed",
        entry_id: "entry-3",
        payload: {
          correction_entry_id: "correction-2",
          challenger: "1F916:marked",
          operator: marked,
          citation: "https://example.test/page",
          snapshot_hash: null,
        },
      },
      {
        at: "2026-09-07T00:00:00.000Z",
        type: "dispute_failed",
        entry_id: "entry-3",
        payload: { correction_entry_id: "correction-2", reason: null },
      },
    ]);
  }

  it("names exactly the burns the fold counted", async () => {
    const events = await markedLog();
    const position = events[events.length - 1]!.seq;
    const folded = standingAt(events, position).get("marked.example");
    const marks = marksOf(events, "marked.example");

    // The pin: a mark per burn and no mark without one. A reader adding up the
    // rows on the operator page gets the counts beside them.
    expect(marks.overturned.length).toBe(folded?.counts.overturned);
    expect(marks.missed.length).toBe(folded?.counts.missed);
    expect(marks.failed_disputes.length).toBe(folded?.counts.forfeits);

    expect(marks.overturned[0]).toMatchObject({
      entry_id: "entry-1",
      role: "validator",
      agent: "1F916:marked",
      correction_entry_id: "correction-1",
    });
    expect(marks.missed[0]).toMatchObject({ entry_id: "entry-2" });
    expect(marks.failed_disputes[0]).toMatchObject({
      correction_entry_id: "correction-2",
    });
  });

  it("marks an operator once for an entry, as the fold burns it once", async () => {
    // The same entry overturned again: nothing more was lost, so nothing more
    // is marked.
    const events = await appendEvent(await markedLog(), {
      at: "2026-09-08T00:00:00.000Z",
      type: "dispute_upheld",
      entry_id: "entry-1",
      payload: { correction_entry_id: "correction-3" },
    });
    const marks = marksOf(events, "marked.example");
    const position = events[events.length - 1]!.seq;
    expect(marks.overturned.length).toBe(
      standingAt(events, position).get("marked.example")?.counts.overturned,
    );
    expect(marks.overturned.length).toBe(1);
  });

  it("names the role the operator signed in: submitter, validator, reconfirmer", async () => {
    // One entry, signed three ways by three operators, and one upheld dispute
    // that overturns it: each signer carries a mark, and each mark says how it
    // signed. The role is what makes the Record readable — "an entry you filed"
    // and "an entry you approved" are different sentences about the same burn.
    const events = await log([
      submitted("author.example", "1F916:author"),
      {
        at: "2026-09-03T00:00:00.000Z",
        type: "validation",
        entry_id: "entry-1",
        payload: {
          record: {
            agent: "1F916:validator",
            operator: "validator.example",
            decision: "approve",
            assigned_random: false,
            signed_at: "2026-09-03T00:00:00.000Z",
          },
          signature: "x",
        },
      },
      {
        at: "2026-09-04T00:00:00.000Z",
        type: "reconfirmation",
        entry_id: "entry-1",
        payload: {
          record: {
            agent: "1F916:reconfirmer",
            operator: "reconfirmer.example",
            snapshot_hash: `sha256:${"3".repeat(64)}`,
            reproduction: null,
            observation: null,
            signed_at: "2026-09-04T00:00:00.000Z",
          },
          signature: "x",
        },
      },
      {
        at: "2026-09-05T00:00:00.000Z",
        type: "dispute_upheld",
        entry_id: "entry-1",
        payload: { correction_entry_id: "correction-1" },
      },
    ]);

    for (const [operator, role, agent] of [
      ["author.example", "submitter", "1F916:author"],
      ["validator.example", "validator", "1F916:validator"],
      ["reconfirmer.example", "reconfirmer", "1F916:reconfirmer"],
    ] as const) {
      const marks = marksOf(events, operator);
      expect([operator, marks.overturned.length]).toEqual([operator, 1]);
      expect(marks.overturned[0]).toMatchObject({
        entry_id: "entry-1",
        role,
        agent,
        correction_entry_id: "correction-1",
      });
      // And the mark is the burn the fold counted, for each of the three.
      const position = events[events.length - 1]!.seq;
      expect(marks.overturned.length).toBe(
        standingAt(events, position).get(operator)?.counts.overturned,
      );
    }
  });

  it("says nothing about an operator the log has never burned", async () => {
    const marks = marksOf(await markedLog(), "spotless.example");
    expect(marks.overturned.length).toBe(0);
    expect(marks.missed.length).toBe(0);
    expect(marks.failed_disputes.length).toBe(0);
  });
});

describe("the write cap the charge step applies", () => {
  /** How many writes this agent is allowed today, read off its first refusal. */
  async function capFor(agent: TestAgent): Promise<number> {
    await clearWriteQuota(store.db);
    const request = new Request(`${TEST_ORIGIN}/entries`, { method: "POST" });
    let spent = 0;
    for (;;) {
      const charged = await chargeWrite(
        store.db,
        request,
        agent.agentId,
        NOW,
      );
      if (charged.ok) {
        spent += 1;
        // A guard, so a cap that stopped working fails here rather than looping
        // until the suite times out.
        expect(spent).toBeLessThanOrEqual(WRITES_PER_AGENT_PER_DAY_SENIOR);
        continue;
      }
      const body = (await charged.response.json()) as Record<string, unknown>;
      expect([charged.response.status, body["bucket"]]).toEqual([429, "agent"]);
      return body["limit"] as number;
    }
  }

  it("charges a bare key and a probation operator the probationary cap", async () => {
    expect(await capFor(agents["bare"]!)).toBe(
      WRITES_PER_AGENT_PER_DAY_PROBATION,
    );
    expect(await capFor(agents["probation"]!)).toBe(
      WRITES_PER_AGENT_PER_DAY_PROBATION,
    );
  });

  it("charges an established operator the full cap and a senior one more", async () => {
    expect(await capFor(agents["established"]!)).toBe(WRITES_PER_AGENT_PER_DAY);
    // And a genesis-named operator that has earned nothing yet writes at the
    // full cap too (D-130 item 5): the naming is what established it, and a
    // seed operator on ten writes a day could not seed anything.
    expect(await capFor(agents["named"]!)).toBe(WRITES_PER_AGENT_PER_DAY);
    expect(await capFor(agents["senior"]!)).toBe(
      WRITES_PER_AGENT_PER_DAY_SENIOR,
    );
    expect(WRITES_PER_AGENT_PER_DAY_SENIOR).toBeGreaterThan(
      WRITES_PER_AGENT_PER_DAY,
    );
    expect(WRITES_PER_AGENT_PER_DAY_PROBATION).toBeLessThan(
      WRITES_PER_AGENT_PER_DAY,
    );
  });
});

describe("the domain join door", () => {
  /** A signed join of `domain` by this operator's agent, at `at`. */
  async function join(
    agent: TestAgent,
    operatorId: string,
    domain: string,
    at: Date,
  ): Promise<{ status: number; error: unknown }> {
    await clearWriteQuota(store.db);
    const path = `/operators/${encodeURIComponent(operatorId)}/domains`;
    const request = await signedPost(agent, {
      path,
      body: {
        domain,
        attestation: await attestFor(
          agent,
          operatorId,
          at.toISOString(),
          domain,
        ),
      },
      timestamp: at.toISOString(),
    });
    const response = await handleRequest(request, env, { ...deps, now: at });
    const body = (await response.json()) as Record<string, unknown>;
    return { status: response.status, error: body["error"] };
  }

  /** The domain registered on a date, and one registered long before it. */
  const RECENT = "ai-governance";

  it("refuses a probation operator, in the tier's own word", async () => {
    expect(
      await join(
        agents["probation"]!,
        "probation.example",
        RECENT,
        NOW,
      ),
    ).toEqual({ status: 403, error: "insufficient_tier" });
  });

  it("keeps a domain inside its window for senior operators alone", async () => {
    // The window runs from the domain's own published registration date for
    // DOMAIN_EARLY_ACCESS_DAYS, and `EARLY` is inside it.
    const registered = Date.parse(`${domainPolicy(RECENT).registered_at}T00:00:00.000Z`);
    expect(EARLY.getTime() - registered).toBeLessThan(
      DOMAIN_EARLY_ACCESS_DAYS * 86_400_000,
    );
    expect(EARLY.getTime() - registered).toBeGreaterThanOrEqual(0);

    expect(
      await join(agents["established"]!, "established.example", RECENT, EARLY),
    ).toEqual({ status: 403, error: "early_access" });

    // The senior operator is let in, and the join is refused for nothing at
    // all: the answer is the door's own 201.
    expect(
      (await join(agents["senior"]!, "senior.example", RECENT, EARLY)).status,
    ).toBe(201);
  });

  it("opens the same domain to an established operator once the window closes", async () => {
    const answer = await join(
      agents["established"]!,
      "established.example",
      RECENT,
      NOW,
    );
    expect([answer.status, answer.error ?? null]).toEqual([201, null]);
  });
});

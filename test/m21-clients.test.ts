/**
 * The standing command, driven in process against the real Worker.
 *
 * Whitepaper Section 9, "Standing": "It is derived from the sealed public events
 * by a published formula, so anyone can recompute anyone's standing from the log
 * and get the same number." A promise like that is only worth what somebody can
 * check, so this file checks it the way an operator would: it stands up a real
 * world on a real miniflare D1, seals it with a real sweep, and then runs
 * src/cli/standing.ts against the router with no network in between — folding
 * the log it fetched with the same kernel the Worker folds it with, and
 * comparing six numbers with what the endpoint said.
 *
 * And it checks that the check can fail. A serving side that quietly adds one to
 * the number it publishes is exactly what recomputation exists to catch, so one
 * test puts such a serving side in front of the command and asks for the
 * failure: a run that could not tell a tampered answer from a true one would be
 * a run worth nothing.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { runStanding } from "../src/cli/standing.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m21";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PAGE_URL = "https://kestrel.example/pricing";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let author: Party;
let first: Party;
let second: Party;
let pageHashValue = "";

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const request = await signedPost(agent, { path, body, timestamp: AT });
  const response = await send(request);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    return send(request);
  }
}

/**
 * The same, with one number quietly changed on the way out: a serving side that
 * publishes a standing the log does not support.
 */
class TamperingHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    const response = await send(request);
    const { pathname } = new URL(request.url);
    if (!pathname.startsWith("/operators/") || !pathname.endsWith("/standing")) {
      return response;
    }
    const body = (await response.json()) as Record<string, unknown>;
    return new Response(
      JSON.stringify({ ...body, standing: (body["standing"] as number) + 1 }),
      { status: response.status, headers: { "content-type": "application/json" } },
    );
  }
}

/** What one run printed, and what it exited with. */
function recorder(): { io: ValidatorIo; out: string[] } {
  const out: string[] = [];
  return {
    io: { stdout: (line: string) => out.push(line), stderr: (line: string) => out.push(line) },
    out,
  };
}

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    attestation: await attestFor(party.agent, party.operator, AT),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

function proposal(): Omit<SubmissionProposal, "author"> {
  return {
    author_operator: author.operator,
    subject: "example/kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-1 seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PAGE_URL,
    snapshot_hash: pageHashValue,
    supersedes: null,
  };
}

async function approve(entryId: string, party: Party): Promise<void> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pageHashValue,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  };
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(party.agent, `/entries/${entryId}/validate`, {
    record,
    signature,
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);
  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = { operator: "author.example", agent: await makeAgent() };
  first = { operator: "first.example", agent: await makeAgent() };
  second = { operator: "second.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [author, first, second, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
    fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
  };

  for (const party of [author, first, second]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  const core: Core = await submittedCore(author.agent, proposal());
  const submitted = await send(await submission(author.agent, { core }));
  expect(submitted.status).toBe(201);
  const id = core["id"] as string;
  await approve(id, first);
  await approve(id, second);

  // The command folds the SEALED log, so there has to be a seal.
  const at = new Date(NOW.getTime() + HOUR_MS);
  const beacon = new FixtureBeacon("m21-clients");
  await beacon.advance(at.toISOString());
  const report = await runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout: new MockPayoutAdapter(),
  });
  expect(report.standing).not.toBeNull();
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the standing command", () => {
  it("recomputes the served standing from the log and agrees", async () => {
    const { io, out } = recorder();
    const code = await runStanding(
      [TEST_ORIGIN, first.operator],
      new InProcessHttp(),
      io,
    );

    expect([code, out]).toEqual([
      0,
      [expect.stringContaining(`ok ${first.operator}`) as unknown as string],
    ]);
    // The number is the one the fold produced, not a word about it.
    expect(out[0]).toMatch(/standing \d+ available \d+ position \d+$/);
  }, 240_000);

  it("answers for an operator that has done nothing yet", async () => {
    const { io, out } = recorder();
    const code = await runStanding(
      [TEST_ORIGIN, "maintainer.example"],
      new InProcessHttp(),
      io,
    );

    expect([code, out[0]]).toEqual([
      0,
      expect.stringContaining("standing 0") as unknown as string,
    ]);
  }, 240_000);

  it("fails when the endpoint's number is not the log's", async () => {
    const { io, out } = recorder();
    const code = await runStanding(
      [TEST_ORIGIN, first.operator],
      new TamperingHttp(),
      io,
    );

    expect(code).toBe(1);
    // The field that disagrees is named, with both numbers beside it.
    expect(out).toEqual([expect.stringMatching(/^standing local \d+ served \d+$/)]);
  }, 240_000);

  it("refuses arguments that are not a standing check", async () => {
    const { io, out } = recorder();
    expect(await runStanding([TEST_ORIGIN], new InProcessHttp(), io)).toBe(2);
    expect(await runStanding([], new InProcessHttp(), io)).toBe(2);
    expect(out).toEqual([
      "usage: standing <base-url> <operator>",
      "usage: standing <base-url> <operator>",
    ]);
  });

  it("refuses an operator the registry does not know", async () => {
    const { io, out } = recorder();
    const code = await runStanding(
      [TEST_ORIGIN, "nobody.example"],
      new InProcessHttp(),
      io,
    );

    expect([code, out]).toEqual([1, ["refused 404 not_found"]]);
  }, 240_000);
});

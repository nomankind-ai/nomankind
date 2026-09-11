/**
 * A second agent under an operator, end to end, through the real Worker.
 *
 * Whitepaper Section 5, Identity and operators: "An operator runs agents", and
 * "every agent under an operator counts as one for validation" — so an operator
 * with more than one key is the ordinary case, and until now the only way to
 * seal a second binding was to write the event by hand beside the door. This
 * file walks the door instead: POST /operators/{id}/agents, signed by a key the
 * operator already has, carrying the independence attestation the new key signed
 * for the domain the operator registered under.
 *
 * Section 11's three joining steps are not rerun. The DNS TXT record proved
 * control of the domain when the first key was bound and payout onboarding was
 * checked then too; what is new here is the key, and the operator vouches for it
 * by signing. Nothing in this file reaches outside the process.
 *
 * The rule the whole thing is for is Section 5's other sentence — "no agent
 * under the submitter's operator may validate its entry" — so the new keys are
 * put in front of the validate door and in front of the offline verifier, which
 * resolves them through the bundle's own registry.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with every migration applied, every key is generated through
 * WebCrypto and every signature is made by it. Only the DNS resolver, the
 * payment provider, the page fetch, the beacon, the witness and the anchor are
 * injected, because only those are not ours to run in a test.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and the
 * window an attestation is signed inside is REQUEST_CLOCK_SKEW_SECONDS.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildExport } from "../src/cli/export.js";
import {
  registerPlan,
  runBind,
  type RegisterDeps,
} from "../src/cli/register.js";
import type { HttpClient, ValidatorIo, ValidatorKey } from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  LIST_PAGE_LIMIT,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import {
  AGENT_BIND_REFUSALS,
  checkAgentBind,
  signAttestation,
  txtRecordName,
} from "../src/registry.js";
import { signCore } from "../src/sign.js";
import {
  agentsForOperator,
  eventBySeq,
  headSeq,
  operatorForAgent,
} from "../src/storage/repository.js";
import type { LogBundle } from "../src/verify.js";
import { verifyOffline } from "../src/verify.js";
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
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

/** The instant every request in this file is served at. No wall clock anywhere. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

const VERIFIED_REFERENCE = "mock-verified-agents";

const SUBJECT = "example/kestrel-1";
const CATEGORY = "pricing";
const PAGE_URL = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
/** The operator whose agent submits: its own keys are the excluded ones. */
let submitter: Party;
/** The three outside operators the preconditions ask for. */
let v1: Party;
let v2: Party;
let v3: Party;
/** The second keys, bound through the door under test. */
let submitterSecond: TestAgent;
let v1Second: TestAgent;

let pageHashValue = "";
let entryId = "";

const beacon = new FixtureBeacon("agents");
const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    return send(request);
  }
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const request = await signedPost(agent, {
    path,
    body,
    timestamp: now.toISOString(),
  });
  const response = await send(request, now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function getJson(
  path: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(new Request(`${TEST_ORIGIN}${path}`));
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** The log's head, so a refusal can be shown to have written nothing. */
function head(): Promise<number | null> {
  return headSeq(store.db);
}

/** The bind path for one operator. */
function agentsPath(operator: string): string {
  return `/operators/${encodeURIComponent(operator)}/agents`;
}

/** One bind request, signed by `signer` and carrying `bound`'s own sentence. */
async function bind(
  signer: TestAgent,
  operator: string,
  bound: TestAgent,
  options: {
    attestation?: unknown;
    agent?: string;
    signedAt?: string;
    now?: Date;
  } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const attestation =
    options.attestation === undefined
      ? await attestFor(
          bound,
          operator,
          options.signedAt ?? AT,
          DEFAULT_DOMAIN,
        )
      : options.attestation;
  return post(
    signer,
    agentsPath(operator),
    { agent: options.agent ?? bound.agentId, attestation },
    options.now ?? NOW,
  );
}

/** Send a bind that must be refused, and prove it wrote nothing. */
async function refused(
  answer: { status: number; body: Record<string, unknown> },
  status: number,
  error: string,
  before: number | null,
): Promise<void> {
  expect([answer.status, answer.body["error"]]).toEqual([status, error]);
  expect(await head()).toBe(before);
}

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    domain: DEFAULT_DOMAIN,
    attestation: await attestFor(party.agent, party.operator, AT, DEFAULT_DOMAIN),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** One approval on one entry, signed by one key and answering for one operator. */
async function approve(
  agent: TestAgent,
  operator: string,
  id: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const record = {
    agent: agent.agentId,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pageHashValue,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  } as unknown as ApproverRecord;
  const signature = await signRecord(id, "validation", record, agent.privateKey);
  return post(agent, `/entries/${id}/validate`, { record, signature });
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  submitter = { operator: "submitter.example", agent: await makeAgent() };
  v1 = { operator: "v1.example", agent: await makeAgent() };
  v2 = { operator: "v2.example", agent: await makeAgent() };
  v3 = { operator: "v3.example", agent: await makeAgent() };
  submitterSecond = await makeAgent();
  v1Second = await makeAgent();
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [submitter, v1, v2, v3, maintainerParty]) {
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
    payout,
    fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
    beacon,
  };

  // Three registered operators outside the submitter's own, which is what
  // verification's preconditions ask for, and all three trusted, which keeps the
  // pool under the switch so two approvals verify.
  await register(submitter);
  for (const party of [v1, v2, v3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

describe("POST /operators/{id}/agents", () => {
  it("binds a second key the operator asked for, and lists it", async () => {
    const before = (await head()) as number;
    const answer = await bind(v1.agent, v1.operator, v1Second);

    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    expect(answer.body["id"]).toBe(v1.operator);
    expect(answer.body["agents"]).toEqual([v1.agent.agentId, v1Second.agentId]);
    expect(answer.body["domains"]).toEqual([DEFAULT_DOMAIN]);

    // One event, and it is the binding: the event is the record and the row is
    // the index into it, both written in the one batch.
    const seq = (await head()) as number;
    expect(seq).toBe(before + 1);
    const event = (await eventBySeq(store.db, seq)) as Event<"agent_bound">;
    expect(event.type).toBe("agent_bound");
    expect(event.at).toBe(AT);
    expect(event.payload.operator).toBe(v1.operator);
    expect(event.payload.agent).toBe(v1Second.agentId);
    // Exactly what was signed, and nothing the request also carried.
    expect(Object.keys(event.payload.attestation).sort()).toEqual([
      "domain",
      "signature",
      "signed_at",
      "version",
    ]);

    expect(await operatorForAgent(store.db, v1Second.agentId)).toBe(v1.operator);
    const rows = await agentsForOperator(store.db, v1.operator, LIST_PAGE_LIMIT);
    expect(rows.map((row) => row.agentId)).toEqual([
      v1.agent.agentId,
      v1Second.agentId,
    ]);
    expect(rows[1]?.registeredSeq).toBe(seq);
  });

  it("shows both agents on the operator's own page", async () => {
    const { status, body } = await getJson(
      `/operators/${encodeURIComponent(v1.operator)}`,
    );
    expect([status, body["id"]]).toEqual([200, v1.operator]);
    expect(body["agents"]).toEqual([v1.agent.agentId, v1Second.agentId]);
  });

  it("answers GET /agents/{id} with the operator behind the new key", async () => {
    const { status, body } = await getJson(`/agents/${v1Second.agentId}`);
    expect(status).toBe(200);
    expect((body["operator"] as { id: string }).id).toBe(v1.operator);
  });

  it("lets the new key bind the next one, because it is an agent now", async () => {
    // The rule is "an agent the operator already has", not "the first one".
    const third = await makeAgent();
    const answer = await bind(v1Second, v1.operator, third);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    expect(answer.body["agents"]).toEqual([
      v1.agent.agentId,
      v1Second.agentId,
      third.agentId,
    ]);
  });

  it("refuses a request signed by an agent of another operator", async () => {
    const before = await head();
    const stranger = await makeAgent();
    await refused(
      await bind(v2.agent, v1.operator, stranger),
      403,
      "not_operator_agent",
      before,
    );
  });

  it("refuses a key that is already bound", async () => {
    const before = await head();
    // The very same agent a second time: it answers for this operator already.
    await refused(
      await bind(v1.agent, v1.operator, v1Second),
      409,
      "agent_bound",
      before,
    );
    // And a key bound to somebody else is refused for the same reason.
    await refused(
      await bind(v1.agent, v1.operator, v2.agent),
      409,
      "agent_bound",
      before,
    );
  });

  it("refuses an operator the registry does not hold", async () => {
    const before = await head();
    const stranger = await makeAgent();
    await refused(
      await bind(v1.agent, "nobody.example", stranger),
      404,
      "unregistered_operator",
      before,
    );
  });

  it("refuses an agent id that spells no key", async () => {
    const before = await head();
    const stranger = await makeAgent();
    await refused(
      await bind(v1.agent, v1.operator, stranger, { agent: "1F916:zzz" }),
      422,
      "bad_agent",
      before,
    );
  });

  it("refuses a body with no attestation at all, by name", async () => {
    const before = await head();
    const stranger = await makeAgent();
    await refused(
      await post(v1.agent, agentsPath(v1.operator), {
        agent: stranger.agentId,
      }),
      422,
      "missing_attestation",
      before,
    );
  });

  it("refuses a sentence the new key did not sign", async () => {
    const before = await head();
    const stranger = await makeAgent();
    // Signed by the key that asked rather than by the key being bound: the new
    // key has to make Section 10's statement itself.
    await refused(
      await bind(v1.agent, v1.operator, stranger, {
        attestation: await attestFor(v1.agent, v1.operator, AT, DEFAULT_DOMAIN),
      }),
      422,
      "bad_attestation",
      before,
    );
    // And the right key for the wrong operator is no better.
    await refused(
      await bind(v1.agent, v1.operator, stranger, {
        attestation: await attestFor(stranger, v2.operator, AT, DEFAULT_DOMAIN),
      }),
      422,
      "bad_attestation",
      before,
    );
  });

  it("refuses a sentence signed outside the request window", async () => {
    const before = await head();
    const stranger = await makeAgent();
    const stale = new Date(
      NOW.getTime() - (REQUEST_CLOCK_SKEW_SECONDS + 60) * 1000,
    ).toISOString();
    await refused(
      await bind(v1.agent, v1.operator, stranger, { signedAt: stale }),
      422,
      "bad_attestation",
      before,
    );
  });

  it("pins attestation_domain_mismatch on the check's own context", async () => {
    // Three domains are registered (src/policy.ts, D-096). The refusal is
    // pinned here on the check's own context -- a registration domain the
    // registry does not hold, which no bound agent's sentence can be for.
    expect([...DOMAIN_SLUGS]).toEqual([
      DEFAULT_DOMAIN,
      "ai-governance",
      "ai-safety",
    ]);
    const stranger = await makeAgent();
    const verdict = await checkAgentBind({
      operator: v1.operator,
      signer: v1.agent.agentId,
      agent: stranger.agentId,
      attestation: await attestFor(stranger, v1.operator, AT, DEFAULT_DOMAIN),
      registered: true,
      registrationDomain: "biotech",
      agents: [v1.agent.agentId],
      agentOperator: null,
      now: NOW,
    });
    expect(verdict.ok ? null : verdict.reason).toBe(
      "attestation_domain_mismatch",
    );
    expect([...AGENT_BIND_REFUSALS]).toEqual([
      "unregistered_operator",
      "not_operator_agent",
      "agent_bound",
      "bad_agent",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
    ]);
  });

  it("refuses a body carrying anything else", async () => {
    const before = await head();
    const stranger = await makeAgent();
    await refused(
      await post(v1.agent, agentsPath(v1.operator), {
        agent: stranger.agentId,
        attestation: await attestFor(stranger, v1.operator, AT, DEFAULT_DOMAIN),
        operator: v1.operator,
      }),
      400,
      "bad_body",
      before,
    );
  });

  it("answers 405 with an Allow header on another method", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}${agentsPath(v1.operator)}`),
    );
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  });
});

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

describe("npm run register -- ... --bind <new-key.json>", () => {
  const good = ["key.json", TEST_ORIGIN, "v3.example"];

  it("reads the key file --bind names", () => {
    expect(registerPlan([...good, "--bind", "new.json"])?.bindKeyPath).toBe(
      "new.json",
    );
    expect(registerPlan(good)?.bindKeyPath).toBeNull();
  });

  for (const args of [
    [...good, "--bind"],
    [...good, "--bind", "a.json", "--bind", "b.json"],
    // A bind is the whole run: there is no registration for --genesis to follow
    // and no join to make in the same breath.
    [...good, "--bind", "new.json", "--genesis", "m.json"],
    [...good, "--bind", "new.json", "--join", DEFAULT_DOMAIN],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args.slice(3))}`, () => {
      expect(registerPlan(args)).toBeNull();
    });
  }

  it("signs the attestation with the new key and the request with the old", async () => {
    const out: string[] = [];
    const io: ValidatorIo = {
      stdout: (line: string) => out.push(line),
      stderr: (line: string) => out.push(line),
    };
    const keyOf = (agent: TestAgent): ValidatorKey => ({
      agentId: agent.agentId,
      privateKey: agent.privateKey,
    });
    const cliDeps: RegisterDeps = {
      http: new InProcessHttp(),
      now: NOW,
      io,
    };
    const fresh = await makeAgent();

    const run = await runBind({
      key: keyOf(v3.agent),
      newKey: keyOf(fresh),
      baseUrl: TEST_ORIGIN,
      domain: v3.operator,
      recordDomain: DEFAULT_DOMAIN,
      deps: cliDeps,
    });

    expect([run.ok, run.status, run.error]).toEqual([true, 201, null]);
    expect(out).toContain(`bind ${v3.operator} ${fresh.agentId} 201`);
    expect(await operatorForAgent(store.db, fresh.agentId)).toBe(v3.operator);

    // Rerunning it is a repeat, not a failure: the key is bound already.
    const again = await runBind({
      key: keyOf(v3.agent),
      newKey: keyOf(fresh),
      baseUrl: TEST_ORIGIN,
      domain: v3.operator,
      recordDomain: DEFAULT_DOMAIN,
      deps: cliDeps,
    });
    expect([again.ok, again.status, again.error, again.already]).toEqual([
      true,
      409,
      "agent_bound",
      true,
    ]);
  });

  it("never puts a private key on the wire", async () => {
    // What travels is the new agent's id and the signature it made; the key
    // file itself is read and never printed.
    const fresh = await makeAgent();
    const attestation = await signAttestation(fresh.privateKey, {
      operator: v3.operator,
      agent: fresh.agentId,
      domain: DEFAULT_DOMAIN,
      signed_at: AT,
    });
    expect(Object.keys(attestation).sort()).toEqual([
      "domain",
      "signature",
      "signed_at",
      "version",
    ]);
  });
});

// ---------------------------------------------------------------------------
// What a second agent may and may not judge
// ---------------------------------------------------------------------------

describe("a second agent at the validate door (Section 5)", () => {
  let core: Core;

  beforeAll(async () => {
    // The submitter's own second key, bound through the door under test: this
    // is the key the exclusion has to cover.
    const bound = await bind(
      submitter.agent,
      submitter.operator,
      submitterSecond,
    );
    expect([bound.status, bound.body["error"] ?? null]).toEqual([201, null]);

    // An entry submitted by the submitter operator's first key, so the entry
    // names that operator and both of its keys are inside it.
    core = await submittedCore(submitter.agent, {
      subject: SUBJECT,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
      claim: "example/kestrel-1 seat pricing is $40 per seat per month",
      before: "$35 per seat per month",
      after: "$40 per seat per month",
      effective_at: "2026-09-01",
      citation: PAGE_URL,
      snapshot_hash: pageHashValue,
      author_operator: submitter.operator,
    });
    const signature = await signCore(core, submitter.agent.privateKey);
    const submitted = await post(submitter.agent, "/entries", {
      entry: { ...core, signature },
    });
    expect([submitted.status, submitted.body["error"] ?? null]).toEqual([
      201,
      null,
    ]);
    entryId = core["id"] as string;
  }, 600_000);

  it("refuses the submitter operator's second key", async () => {
    const before = await head();
    const answer = await approve(
      submitterSecond,
      submitter.operator,
      entryId,
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "submitter_operator",
    ]);
    expect(await head()).toBe(before);
  });

  it("counts an outside operator's second key as that operator's approval", async () => {
    const answer = await approve(v1Second, v1.operator, entryId);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const { body } = await getJson(`/entries/${encodeURIComponent(entryId)}`);
    const approvers = body["approvers"] as { agent: string; operator: string }[];
    expect(approvers).toHaveLength(1);
    expect([approvers[0]?.agent, approvers[0]?.operator]).toEqual([
      v1Second.agentId,
      v1.operator,
    ]);
  });

  it("refuses v1's first key next: one operator, one decision", async () => {
    // Section 5 again, read the other way: the second key counted as v1, so v1
    // has spoken and its first key cannot speak again.
    const answer = await approve(v1.agent, v1.operator, entryId);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "duplicate_operator",
    ]);
  });

  it("verifies the entry on the second approval, from another operator", async () => {
    const answer = await approve(v2.agent, v2.operator, entryId);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const { body } = await getJson(`/entries/${encodeURIComponent(entryId)}`);
    expect(body["status"]).toBe("verified");
  });
});

// ---------------------------------------------------------------------------
// The offline verifier, over a registry carrying two agents for one operator
// ---------------------------------------------------------------------------

describe("the offline verifier, with two agents under one operator", () => {
  let exported: { entry: unknown; bundle: LogBundle };

  beforeAll(async () => {
    // One sweep, so the bundle has a seal over the decisions above.
    await runSweep(env, {
      now: new Date(NOW.getTime() + HOUR_MS),
      beacon,
      witness: new FakeWitnessAdapter(),
      pinned: pinnedSet([]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
      payout,
    });

    exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId,
      http: new InProcessHttp(),
      now: new Date(NOW.getTime() + HOUR_MS),
    });
  }, 600_000);

  it("carries both of the operator's agents in the bundle's registry", () => {
    expect(exported.bundle.registry.agents[v1.agent.agentId]).toBe(v1.operator);
    expect(exported.bundle.registry.agents[v1Second.agentId]).toBe(v1.operator);
    expect(exported.bundle.registry.agents[submitterSecond.agentId]).toBe(
      submitter.operator,
    );
  });

  it("answers ok with zero diffs on an approval by the second key", async () => {
    const report = await verifyOffline(exported.entry, exported.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(entryId);
  });

  it("refuses the same approval when the registry forgets the key", async () => {
    // The mapping is load-bearing: without the second binding the verifier
    // cannot resolve the approver to an operator at all, and says so rather
    // than letting the decision stand.
    const agents = { ...exported.bundle.registry.agents };
    delete agents[v1Second.agentId];
    const report = await verifyOffline(exported.entry, {
      ...exported.bundle,
      registry: { ...exported.bundle.registry, agents },
    });

    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "exclusions" && diff.reason === "unregistered_agent",
      ),
    ).toBe(true);
  });
});

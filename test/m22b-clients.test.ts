/**
 * The commands an operator, an author and a trainer run once entries have a
 * domain, driven in process against the real Worker.
 *
 * Decision D-071 gives four of them something new to say and one of them a
 * refusal to make before it touches anything:
 *
 *   - `npm run register -- ... --domain <slug>` signs that domain's own
 *     attestation and binds the registration to it, and `--join <slug>` is the
 *     separate signed act that takes on a later one;
 *   - `npm run submit` will not send a fields file that does not name a domain,
 *     and says so before the citation is fetched or the registry is asked;
 *   - `npm run read -- --domain` and `npm run sync -- --domain` carry the filter
 *     through to the doors, and a slug nobody registered is refused by name;
 *   - `npm run verify` says which schema version it checked against.
 *
 * No network anywhere: the http client routes straight into `handleRequest`,
 * the fetcher reads a fixture page, and the clock is injected.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  registerPlan,
  runJoin,
  runRegister,
  type RegisterDeps,
} from "../src/cli/register.js";
import { runRead } from "../src/cli/read.js";
import { runSubmit } from "../src/cli/submit.js";
import { runSync, syncPlan } from "../src/cli/sync.js";
import { verify } from "../src/cli/verify.js";
import type {
  HttpClient,
  ValidatorIo,
  ValidatorKey,
} from "../src/cli/validator.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { DEFAULT_DOMAIN, SCHEMA_VERSION, attestationFor } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { verifyAttestation } from "../src/registry.js";
import { operatorDomains } from "../src/storage/repository.js";
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
  signingHttp,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  type FixturePage,
} from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

const VERIFIED_REFERENCE = "mock-verified-m22b-clients";
const UNREGISTERED = "biotech";

const SUBJECT = "example/kestrel-1";
const CATEGORY = "pricing";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PAGE_URL = "https://kestrel.example/pricing";

/** The example the README points at, checked by the one script. */
const EXAMPLE_ENTRY = "schema/examples/checkpoint/entry.json";
const EXAMPLE_LOG = "schema/examples/checkpoint/log.json";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let author: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;
/** Registered by the command under test rather than by hand. */
let joiner: Party;

let pageHashValue = "";
let entryId = "";

const beacon = new FixtureBeacon("m22b-clients");
const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  calls = 0;
  async fetch(request: Request): Promise<Response> {
    this.calls += 1;
    return send(request);
  }
}

/** What one run printed. */
function recorder(): { io: ValidatorIo; out: string[] } {
  const out: string[] = [];
  return {
    io: {
      stdout: (line: string) => out.push(line),
      stderr: (line: string) => out.push(line),
    },
    out,
  };
}

/** A TestAgent is exactly what a key file gives a command: an id and a key. */
function keyOf(agent: TestAgent): ValidatorKey {
  return { agentId: agent.agentId, privateKey: agent.privateKey };
}

function cliDeps(io: ValidatorIo, http: HttpClient): RegisterDeps {
  return { http, now: NOW, io };
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

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    domain: DEFAULT_DOMAIN,
    attestation: await attestFor(
      party.agent,
      party.operator,
      AT,
      DEFAULT_DOMAIN,
    ),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

async function approve(party: Party, id: string): Promise<void> {
  const record = {
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
  } as unknown as ApproverRecord;
  const signature = await signRecord(
    id,
    "validation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(party.agent, `/entries/${id}/validate`, {
    record,
    signature,
  });
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
}

/** The fields file an author writes, with `domain` in it. */
function fieldsFor(overrides: Record<string, unknown> = {}): Record<
  string,
  unknown
> {
  return {
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: "example/kestrel-1 seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PAGE_URL,
    ...overrides,
  };
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  joiner = { operator: "k9.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, joiner, maintainerParty]) {
    records[`_nomankind.${party.operator}`] = [party.agent.agentId];
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

  await register(k1);
  await name(k1);
  await register(k2);
  await name(k2);
  await register(k3);
  await name(k3);
  await register(maintainerParty);

  // The entry the readers below ask about, submitted through the command with
  // a fields file that names its domain, and verified by the two named
  // operators (the pool is below the switch, so two approvals verify).
  const io = recorder();
  const submitted = await runSubmit({
    key: keyOf(author),
    baseUrl: TEST_ORIGIN,
    fields: fieldsFor(),
    deps: {
      http: new InProcessHttp(),
      fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
      now: NOW,
      io: io.io,
    },
  });
  expect([submitted.code, submitted.error]).toEqual([0, null]);
  entryId = submitted.entryId ?? "";

  await approve(k1, entryId);
  await approve(k2, entryId);

  // One sweep, so the readers have a seal and a receipt to check against.
  await runSweep(env, {
    now: new Date(NOW.getTime() + HOUR_MS),
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });
});

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

describe("register: --domain and --join", () => {
  const good = ["key.json", TEST_ORIGIN, "k9.example"];

  it("defaults --domain to the one domain there was", () => {
    expect(registerPlan(good)?.recordDomain).toBe(DEFAULT_DOMAIN);
    expect(registerPlan(good)?.join).toBeNull();
  });

  it("reads the slug --domain names", () => {
    const plan = registerPlan([...good, "--domain", DEFAULT_DOMAIN]);
    expect([plan?.recordDomain, plan?.join]).toEqual([DEFAULT_DOMAIN, null]);
  });

  it("reads the slug --join names", () => {
    expect(registerPlan([...good, "--join", DEFAULT_DOMAIN])?.join).toBe(
      DEFAULT_DOMAIN,
    );
  });

  for (const args of [
    [...good, "--domain"],
    [...good, "--domain", "--genesis"],
    [...good, "--domain", "a", "--domain", "b"],
    // A join is the whole run: there is no registration for --domain to name
    // and no first membership for --genesis to follow.
    [...good, "--join", DEFAULT_DOMAIN, "--domain", DEFAULT_DOMAIN],
    [...good, "--join", DEFAULT_DOMAIN, "--genesis", "m.json"],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args.slice(3))}`, () => {
      expect(registerPlan(args)).toBeNull();
    });
  }

  it("registers into the domain it was given, and the record says so", async () => {
    const io = recorder();
    const run = await runRegister({
      key: keyOf(joiner.agent),
      baseUrl: TEST_ORIGIN,
      domain: joiner.operator,
      recordDomain: DEFAULT_DOMAIN,
      deps: cliDeps(io.io, new InProcessHttp()),
    });
    expect([run.ok, run.status, run.error]).toEqual([true, 201, null]);
    expect(io.out).toContain(
      `register ${joiner.operator} ${DEFAULT_DOMAIN} 201`,
    );

    const rows = await operatorDomains(store.db, joiner.operator);
    expect(rows.map((row) => row.domain)).toEqual([DEFAULT_DOMAIN]);
    // And the attestation it signed is that domain's own sentence.
    expect(rows[0]?.attestation?.version).toBe(
      attestationFor(DEFAULT_DOMAIN).version,
    );
    expect(
      await verifyAttestation(
        joiner.operator,
        joiner.agent.agentId,
        rows[0]?.attestation,
        DEFAULT_DOMAIN,
      ),
    ).toBe(true);
  });

  it("signs the joined domain's attestation and posts it", async () => {
    const io = recorder();
    const run = await runJoin({
      key: keyOf(joiner.agent),
      baseUrl: TEST_ORIGIN,
      domain: joiner.operator,
      join: DEFAULT_DOMAIN,
      deps: cliDeps(io.io, new InProcessHttp()),
    });
    // ai-ecosystem is the one registered domain, and registration already put
    // this operator in it, so `already_joined` is the honest answer and the
    // command treats a repeat as a repeat rather than a failure.
    expect([run.ok, run.status, run.error, run.already]).toEqual([
      true,
      409,
      "already_joined",
      true,
    ]);
    expect(io.out).toContain(
      `join ${joiner.operator} ${DEFAULT_DOMAIN} 409 already_joined`,
    );
  });
});

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------

describe("submit: the fields file names the domain", () => {
  it("refuses a file without one, before any I/O", async () => {
    const fetcher = new FixtureFetcher({ [PAGE_URL]: PAGE });
    const http = new InProcessHttp();
    const io = recorder();

    const fields = fieldsFor();
    delete fields["domain"];

    const run = await runSubmit({
      key: keyOf(author),
      baseUrl: TEST_ORIGIN,
      fields,
      deps: { http, fetcher, now: NOW, io: io.io },
    });

    expect([run.code, run.error, run.entryId]).toEqual([2, "bad_fields", null]);
    // Nothing was fetched and nothing was asked of the log.
    expect([fetcher.requests, http.calls]).toEqual([[], 0]);
    expect(io.out.some((line) => line.includes("domain"))).toBe(true);
  });

  it("refuses a domain that is not a string, before any I/O", async () => {
    const fetcher = new FixtureFetcher({ [PAGE_URL]: PAGE });
    const http = new InProcessHttp();
    const io = recorder();

    const run = await runSubmit({
      key: keyOf(author),
      baseUrl: TEST_ORIGIN,
      fields: fieldsFor({ domain: 7 }),
      deps: { http, fetcher, now: NOW, io: io.io },
    });

    expect([run.code, run.error]).toEqual([2, "bad_fields"]);
    expect([fetcher.requests, http.calls]).toEqual([[], 0]);
  });
});

// ---------------------------------------------------------------------------
// read and sync
// ---------------------------------------------------------------------------

describe("read: --domain", () => {
  it("puts the filter in the query it sends", async () => {
    const io = recorder();
    // Read through a signing client, which is what `--sign <key.json>` builds:
    // the entry is minutes old and the release window has not opened on it
    // (decision D-100), and what this test is about is the domain filter.
    const code = await runRead(
      [
        TEST_ORIGIN,
        "--subject",
        SUBJECT,
        "--category",
        CATEGORY,
        "--domain",
        DEFAULT_DOMAIN,
      ],
      signingHttp((request) => send(request), k1.agent, NOW),
      io.io,
    );
    expect(code).toBe(0);
    expect(io.out.join("\n")).toContain(`ok ${entryId}`);
  });

  it("is refused by name for a domain nobody registered", async () => {
    const io = recorder();
    const code = await runRead(
      [
        TEST_ORIGIN,
        "--subject",
        SUBJECT,
        "--category",
        CATEGORY,
        "--domain",
        UNREGISTERED,
      ],
      new InProcessHttp(),
      io.io,
    );
    expect(code).toBe(1);
    expect(io.out.join("\n")).toContain("unknown_domain");
  });

  it("refuses an unknown flag before any I/O", async () => {
    const io = recorder();
    const http = new InProcessHttp();
    const code = await runRead(
      [TEST_ORIGIN, "--subject", SUBJECT, "--domains", DEFAULT_DOMAIN],
      http,
      io.io,
    );
    expect([code, http.calls]).toEqual([2, 0]);
  });
});

describe("sync: --domain", () => {
  it("puts the filter in the path it asks for", () => {
    const plan = syncPlan([TEST_ORIGIN, "--domain", DEFAULT_DOMAIN]);
    expect(plan?.path).toBe(`/sync?domain=${DEFAULT_DOMAIN}`);
  });

  it("streams that domain and every check holds", async () => {
    const io = recorder();
    const code = await runSync(
      [TEST_ORIGIN, "--domain", DEFAULT_DOMAIN],
      new InProcessHttp(),
      io.io,
    );
    expect([code, io.out.length]).toEqual([0, 1]);
    expect(io.out[0]).toContain("ok from 0");
  });

  it("is refused by name for a domain nobody registered", async () => {
    const io = recorder();
    const code = await runSync(
      [TEST_ORIGIN, "--domain", UNREGISTERED],
      new InProcessHttp(),
      io.io,
    );
    expect(code).toBe(1);
    expect(io.out.join("\n")).toContain("unknown_domain");
  });

  it("refuses a repeated --domain before any I/O", () => {
    expect(
      syncPlan([TEST_ORIGIN, "--domain", DEFAULT_DOMAIN, "--domain", "other"]),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

describe("verify: the schema version it checked against", () => {
  it("prints it first, then the verdict", async () => {
    const io = recorder();
    const code = await verify(EXAMPLE_ENTRY, EXAMPLE_LOG, io.io);
    expect([code, io.out[0]]).toEqual([0, `schema ${SCHEMA_VERSION}`]);
    expect(io.out[1]).toMatch(/^ok nmk_[0-9a-f]{32}$/);
  });
});

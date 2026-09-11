/**
 * The two new domains, end to end, through the real Worker on a real miniflare
 * D1 (decision D-096).
 *
 * M22b could only pin the per-domain rules at the kernel: ai-ecosystem was the
 * one registered domain, so every registered operator was attested in every
 * domain there was, and `attestation_domain_mismatch` was unreachable through
 * any door. Three domains are registered now, so the doors themselves can be
 * walked -- an operator attested in one domain and refused in another, a join
 * signed with the wrong domain's sentence, a governance instrument that must
 * cite the issuing body's own gazette -- and that is what this file does.
 *
 * Four of the rules it walks are the kernel's newest: the subject's own
 * authority excluded from judging an entry about it, a transcript payload
 * archived redacted and disclosed on a published window, an observation retired
 * by a later version of the same model, and the submit refusal that keeps a
 * version-shaped subject from arriving without one. Each is named here by the
 * contract's own name for it.
 *
 * No policy number lives here: the slugs are DOMAIN_SLUGS', the categories and
 * hosts are read from `domainPolicy`, the disclosure window is policy's own,
 * and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildTranscriptArtifact, transcriptArtifactHash } from "../src/artifact.js";
import { type Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import { canonicalize, sha256Hex } from "../src/hash.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  LIST_PAGE_LIMIT,
  domainPolicy,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { signCore } from "../src/sign.js";
import { entryIdFor } from "../src/submit.js";
import type { ApproverRecord } from "../src/events.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedHeaders,
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

const VERIFIED_REFERENCE = "mock-verified-m24c";

const GOVERNANCE = "ai-governance";
const SAFETY = "ai-safety";

/** The instrument every governance entry here is about, named the domain's way. */
const INSTRUMENT = "example/ai-act";
/** A real jurisdiction's instrument, for the one rule that needs a real authority. */
const EU_INSTRUMENT = "eu/ai-act";
/** The commitment every safety entry here is about. */
const COMMITMENT = "example/usage-policy";
/** The model an evaluation is about, one version at a time. */
const EVALUATED = "example/kestrel-1";
/** The model the redacted transcript was measured against. */
const PROBED = "example/kestrel-9/2026-08";

const ECOSYSTEM_SUBJECT = "example/kestrel-1";

function page(body: string): FixturePage {
  return {
    body: `<!doctype html><html><body><main>${body}</main></body></html>`,
    contentType: "text/html; charset=utf-8",
  };
}

/** Official for the `example` authority: `gazette.example` is under `example`. */
const GAZETTE_URL = "https://gazette.example/ai-act";
const GUIDANCE_URL = "https://gazette.example/ai-act/guidance";
/** Official for `eu`, which is a real authority row and not a fixture one. */
const EUR_LEX_URL = "https://eur-lex.europa.eu/eli/reg/2024/1689";
/** Official for `example` in the safety domain. */
const POLICY_URL = "https://policies.example/usage-policy";
/** A tracker: recognized at best, and never the issuing body's own gazette. */
const TRACKER_URL = "https://tracker.example.org/ai-act";
const EVAL_AUGUST_URL = "https://evals.example/kestrel-1/2026-08";
const EVAL_SEPTEMBER_URL = "https://evals.example/kestrel-1/2026-09";
const PRICING_URL = "https://kestrel.example/pricing";

const PAGES: Record<string, FixturePage> = {
  [GAZETTE_URL]: page("<h1>AI Act</h1><p>in force from 2026-08-01</p>"),
  [GUIDANCE_URL]: page("<h1>Guidance under the AI Act</h1><p>issued</p>"),
  [EUR_LEX_URL]: page("<h1>Regulation 2024/1689</h1><p>in force</p>"),
  [POLICY_URL]: page("<h1>Usage policy</h1><p>published 2026-09-01</p>"),
  [TRACKER_URL]: page("<h1>AI Act tracker</h1><p>in force, they say</p>"),
  [EVAL_AUGUST_URL]: page("<h1>August evaluation</h1><p>refused 4 of 10</p>"),
  [EVAL_SEPTEMBER_URL]: page("<h1>September evaluation</h1><p>refused 9 of 10</p>"),
  [PRICING_URL]: page("<h1>Kestrel pricing</h1><p>$40 per seat per month</p>"),
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
/** A bare key, registered to nobody: every entry below is submitted with it. */
let author: TestAgent;
/** Registered into ai-governance, and trusted: the two that judge there. */
let g1: Party;
let g2: Party;
/** Registered into ai-safety, and trusted: the two that judge there. */
let s1: Party;
let s2: Party;
/** Attested in ai-ecosystem alone, which is what makes it refusable elsewhere. */
let eco: Party;
/** Registered in ai-ecosystem and joined to both new domains afterwards. */
let joiner: Party;
/** An operator whose own domain is an official host of the `eu` authority. */
let authority: Party;

const hashes: Record<string, string> = {};

/** The entries the world is built out of, by the name the tests call them. */
const ids: Record<string, string> = {};

const beacon = new FixtureBeacon("m24c");
const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
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

/**
 * One GET, signed by an agent bound to a registered operator.
 *
 * The entries in this file are read at the instant they were written, inside
 * the release window (decision D-100), where a free reader is handed the proof
 * and a release date rather than the content. What is under test here is the
 * domains and the disclosure rule, so the reads are made the way a validator's
 * client makes them; the window's own answers are in test/m24d-doors.test.ts.
 */
async function getJson(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await getSigned(g1.agent, path, now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** A GET carrying the M2 signed-request headers, which is what a validator sends. */
async function getSigned(
  agent: TestAgent,
  path: string,
  now: Date = NOW,
): Promise<Response> {
  // The signature is over the pathname with no query string, which is the one
  // form both the disclosure gate and `readerAccess` verify.
  const url = new URL(`${TEST_ORIGIN}${path}`);
  const headers = await signedHeaders(agent, {
    method: "GET",
    path: url.pathname,
    body: null,
    timestamp: now.toISOString(),
  });
  return send(new Request(url.toString(), { headers }), now);
}

/** The log's head, so a refusal can be shown to have written nothing. */
async function head(): Promise<number> {
  const { body } = await getJson("/health");
  const log = body["log"] as { head?: number } | undefined;
  return log?.head ?? 0;
}

async function register(
  party: Party,
  domain: string = DEFAULT_DOMAIN,
): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    domain,
    attestation: await attestFor(party.agent, party.operator, AT, domain),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

/** One operator taking on a later domain, by signing that domain's own sentence. */
async function join(party: Party, domain: string): Promise<void> {
  const answer = await post(
    party.agent,
    `/operators/${encodeURIComponent(party.operator)}/domains`,
    {
      domain,
      attestation: await attestFor(party.agent, party.operator, AT, domain),
    },
  );
  expect([answer.status, `${party.operator} in ${domain}`]).toEqual([
    201,
    `${party.operator} in ${domain}`,
  ]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** One approval on one entry, signed by one party's own key. */
async function approve(
  party: Party,
  id: string,
  snapshotHash: string,
  extra: Record<string, unknown> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: snapshotHash,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
    ...extra,
  } as unknown as ApproverRecord;
  const signature = await signRecord(
    id,
    "validation",
    record,
    party.agent.privateKey,
  );
  return post(party.agent, `/entries/${id}/validate`, { record, signature });
}

/** Submit one signed core through the real door. */
async function submit(
  agent: TestAgent,
  core: Core,
  body: Record<string, unknown> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const signature = await signCore(core, agent.privateKey);
  return post(agent, "/entries", { entry: { ...core, signature }, ...body });
}

/** A stated proposal, ready for `submittedCore`. */
function stated(input: {
  readonly domain: string;
  readonly subject: string;
  readonly category: string;
  readonly claim: string;
  readonly url: string;
  readonly before?: string;
  readonly after?: string;
}): Record<string, unknown> {
  return {
    subject: input.subject,
    category: input.category,
    domain: input.domain,
    claim: input.claim,
    before: input.before ?? "not recorded",
    after: input.after ?? "recorded",
    effective_at: "2026-09-01",
    citation: input.url,
    snapshot_hash: hashes[input.url] ?? "",
  };
}

/** Submit a stated entry and verify it with the two operators attested there. */
async function verified(
  proposal: Record<string, unknown>,
  approvers: readonly Party[],
): Promise<string> {
  const core = await submittedCore(author, proposal as never);
  const answer = await submit(author, core);
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
  const id = core["id"] as string;
  for (const party of approvers) {
    const judged = await approve(party, id, proposal["snapshot_hash"] as string);
    expect([judged.status, judged.body["error"] ?? null]).toEqual([201, null]);
  }
  return id;
}

/** The `sha256:` address of a value's JCS bytes: what an archived object is at. */
async function jcsHash(value: unknown): Promise<string> {
  return `sha256:${await sha256Hex(canonicalize(value))}`;
}

// ---------------------------------------------------------------------------
// The redacted transcript
// ---------------------------------------------------------------------------

/** The payload the observation was made with, held back until the window opens. */
const PAYLOAD = [
  { role: "system", content: "You are a helpful assistant." },
  { role: "user", content: "the working jailbreak, in full" },
];

/** The evidence of the redacted transcript entry, once its placeholder is in. */
let redactedEvidence: Record<string, unknown> = {};
/** The disclosure body: the pointer into the artifact, and the value it replaced. */
let disclosureBody: Record<string, unknown> = {};
let disclosureHash = "";
let transcriptHash = "";

beforeAll(async () => {
  for (const url of Object.keys(PAGES)) {
    hashes[url] = await pageHash(PAGES[url]!);
  }

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  g1 = { operator: "g1.example", agent: await makeAgent() };
  g2 = { operator: "g2.example", agent: await makeAgent() };
  s1 = { operator: "s1.example", agent: await makeAgent() };
  s2 = { operator: "s2.example", agent: await makeAgent() };
  eco = { operator: "k3.example", agent: await makeAgent() };
  joiner = { operator: "k1.example", agent: await makeAgent() };
  // Its registrable domain is an official host of the `eu` authority row, which
  // is the whole point of it: it is a party this record checks.
  authority = { operator: "europa.eu", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };
  const parties = [g1, g2, s1, s2, eco, joiner, authority, maintainerParty];

  const records: Record<string, string[]> = {};
  for (const party of parties) {
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
    fetcher: new FixtureFetcher(PAGES),
    beacon,
  };

  // Each pair registers straight into the domain it judges in, which is what
  // an operator joining a registered domain does today; `eco` stays in
  // ai-ecosystem, which is what makes it refusable in the other two.
  for (const [party, domain] of [
    [g1, GOVERNANCE],
    [g2, GOVERNANCE],
    [s1, SAFETY],
    [s2, SAFETY],
    [eco, DEFAULT_DOMAIN],
    [joiner, DEFAULT_DOMAIN],
    // Registered in the domain whose record it is a party to: the subject's own
    // authority is an exclusion per entry, never per domain, so nothing stops
    // it registering here.
    [authority, GOVERNANCE],
  ] as const) {
    await register(party, domain);
    await name(party);
  }
  await register(maintainerParty);

  // And one operator takes a later domain on the other way, by signing that
  // domain's own sentence at POST /operators/{id}/domains.
  await join(joiner, GOVERNANCE);

  // One verified entry per domain, from the same bare key, so every trusted
  // operator is outside the submitter.
  ids["governance"] = await verified(
    stated({
      domain: GOVERNANCE,
      subject: INSTRUMENT,
      category: "in_force",
      claim: "the AI Act is in force from 2026-08-01",
      url: GAZETTE_URL,
    }),
    [g1, g2],
  );
  ids["safety"] = await verified(
    stated({
      domain: SAFETY,
      subject: COMMITMENT,
      category: "commitment_published",
      claim: "the usage policy published on 2026-09-01 forbids weapons development",
      url: POLICY_URL,
    }),
    [s1, s2],
  );

  // An ai-ecosystem entry left in draft, so the operator attested only there
  // can be seen judging where it is eligible.
  const ecosystem = await submittedCore(
    author,
    stated({
      domain: DEFAULT_DOMAIN,
      subject: ECOSYSTEM_SUBJECT,
      category: "pricing",
      claim: "example/kestrel-1 seat pricing is $40 per seat per month",
      url: PRICING_URL,
      before: "$35 per seat per month",
      after: "$40 per seat per month",
    }) as never,
  );
  expect((await submit(author, ecosystem)).status).toBe(201);
  ids["ecosystem"] = ecosystem["id"] as string;

  // A governance entry left in draft, so the same operator can be seen refused
  // where it is not: a verified entry would be refused `entry_closed` first.
  const draft = await submittedCore(
    author,
    stated({
      domain: GOVERNANCE,
      subject: INSTRUMENT,
      category: "guidance_issued",
      claim: "guidance under the AI Act was issued on 2026-09-01",
      url: GUIDANCE_URL,
    }) as never,
  );
  expect((await submit(author, draft)).status).toBe(201);
  ids["governanceDraft"] = draft["id"] as string;

  // And one about a real jurisdiction, for the subject-authority rule: the
  // `example` row is a fixture and never triggers it.
  const eu = await submittedCore(
    author,
    stated({
      domain: GOVERNANCE,
      subject: EU_INSTRUMENT,
      category: "in_force",
      claim: "Regulation 2024/1689 is in force",
      url: EUR_LEX_URL,
    }) as never,
  );
  expect((await submit(author, eu)).status).toBe(201);
  ids["eu"] = eu["id"] as string;

  // One sweep, so everything above is under a seal and the sync door has
  // something to hand out.
  await runSweep(env, {
    now: hour(1),
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });

  // The redacted transcript, built last because its hashes are what the
  // disclosure tests address.
  // The payload sits under `parameters.request`, which is where the schema
  // leaves room for it: `prompt` is a string by the schema and `parameters` is
  // the exact settings the run was made at, the API request among them. The
  // redaction rule asks only that a placeholder stand inside a `request` and
  // outside its headers.
  redactedEvidence = {
    model: "example/kestrel-9",
    prompt: "see parameters.request",
    parameters: {
      temperature: 0,
      request: {
        model: "kestrel-9",
        messages: { "[REDACTED]": await jcsHash(PAYLOAD) },
      },
    },
    output: "Sure. Here is how to do it.",
    predicate: "the model complies with the prohibited request",
    observed_at: "2026-09-07",
    provider_statement: null,
  };
  const artifact = buildTranscriptArtifact(
    redactedEvidence,
    redactedEvidence["output"] as string,
    redactedEvidence["observed_at"] as string,
  );
  const hashed = await transcriptArtifactHash(artifact);
  if (!hashed.ok) throw new Error(`m24c: the transcript is refused: ${hashed.reason}`);
  transcriptHash = hashed.hash;
  disclosureBody = { "/parameters/request/messages": PAYLOAD };
  disclosureHash = await jcsHash(disclosureBody);
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// Three domains, and an entry in each
// ---------------------------------------------------------------------------

describe("the registry holds three domains, and the log holds an entry in each", () => {
  it("serves three domains from GET /policy", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/policy`, {
        headers: { accept: "application/json" },
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    const domains = body["DOMAINS"] as Record<string, unknown>;
    expect(Object.keys(domains)).toEqual([...DOMAIN_SLUGS]);
    expect(Object.keys(domains)).toEqual([DEFAULT_DOMAIN, GOVERNANCE, SAFETY]);
  });

  it("verifies a governance instrument and a safety commitment", async () => {
    for (const [slug, id] of [
      [GOVERNANCE, ids["governance"]!],
      [SAFETY, ids["safety"]!],
    ] as const) {
      const { status, body } = await getJson(`/entries/${id}`);
      expect([status, body["status"], body["domain"]]).toEqual([
        200,
        "verified",
        slug,
      ]);
    }
  });

  it("hashes the same fact differently in a different domain", async () => {
    // `domain` is a key of the frozen core, so the id covers it: the same
    // claim filed in another domain is another entry, and no door can move one.
    for (const id of [ids["governance"]!, ids["safety"]!]) {
      const { body } = await getJson(`/entries/${id}`);
      const core: Record<string, unknown> = {};
      for (const key of Object.keys(body)) core[key] = body[key];
      delete core["signature"];
      const rehomed = await entryIdFor({
        ...core,
        domain: DEFAULT_DOMAIN,
      } as unknown as Core);
      expect(rehomed).not.toBe(id);
    }
  });
});

// ---------------------------------------------------------------------------
// Eligibility, through the doors this time
// ---------------------------------------------------------------------------

describe("an operator judges only where it is attested", () => {
  it("refuses one attested in ai-ecosystem alone from judging a governance entry", async () => {
    const answer = await approve(
      eco,
      ids["governanceDraft"]!,
      hashes[GUIDANCE_URL]!,
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "operator_not_in_domain",
    ]);
  });

  it("lets the same operator judge in the domain it did attest in", async () => {
    const answer = await approve(eco, ids["ecosystem"]!, hashes[PRICING_URL]!);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
  });

  it("lets an operator judge in a domain it joined after registering", async () => {
    // The other way into a domain: `POST /operators/{id}/domains`, which is
    // what an operator already in the registry uses. Eligibility follows the
    // attestation however it was signed, so a joined domain judges exactly as
    // a registered one does.
    const record = await getJson(
      `/operators/${encodeURIComponent(joiner.operator)}`,
    );
    expect(record.body["domains"]).toEqual([DEFAULT_DOMAIN, GOVERNANCE]);

    const answer = await approve(
      joiner,
      ids["governanceDraft"]!,
      hashes[GUIDANCE_URL]!,
    );
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
  });

  it("refuses a join carrying another domain's sentence", async () => {
    // Reachable only now that more than one domain is registered: both the
    // domain asked for and the domain the attestation declares have to exist.
    const answer = await post(
      eco.agent,
      `/operators/${encodeURIComponent(eco.operator)}/domains`,
      {
        domain: SAFETY,
        attestation: await attestFor(eco.agent, eco.operator, AT, GOVERNANCE),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "attestation_domain_mismatch",
    ]);
    const record = await getJson(
      `/operators/${encodeURIComponent(eco.operator)}`,
    );
    expect(record.body["domains"]).toEqual([DEFAULT_DOMAIN]);
  });
});

// ---------------------------------------------------------------------------
// The source policy, in a domain whose authorities are states
// ---------------------------------------------------------------------------

describe("a governance instrument cites the body that issued it", () => {
  it("refuses an in_force entry citing a tracker rather than the gazette", async () => {
    const before = await head();
    const core = await submittedCore(
      author,
      stated({
        domain: GOVERNANCE,
        subject: INSTRUMENT,
        category: "in_force",
        claim: "the AI Act is in force, according to a tracker",
        url: TRACKER_URL,
      }) as never,
    );
    const answer = await submit(author, core);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    expect(await head()).toBe(before);
  });

  it("keeps the gate on exactly the categories policy names", () => {
    const sources = domainPolicy(GOVERNANCE).sources;
    expect([...sources.official_required]).toContain("in_force");
    expect([...sources.official_required]).not.toContain("enforcement_action");
  });
});

// ---------------------------------------------------------------------------
// Readers and trainers, per domain
// ---------------------------------------------------------------------------

describe("a reader and a trainer may ask for one domain", () => {
  it("answers each new domain's own entry", async () => {
    const governance = await getJson(
      `/read?domain=${GOVERNANCE}&subject=${encodeURIComponent(INSTRUMENT)}` +
        `&category=in_force`,
    );
    expect(governance.status).toBe(200);
    expect(
      (governance.body["entry"] as Record<string, unknown>)["id"],
    ).toBe(ids["governance"]);

    const safety = await getJson(
      `/read?domain=${SAFETY}&subject=${encodeURIComponent(COMMITMENT)}` +
        `&category=commitment_published`,
    );
    expect(safety.status).toBe(200);
    expect((safety.body["entry"] as Record<string, unknown>)["id"]).toBe(
      ids["safety"],
    );
  });

  it("does not answer one domain's question out of another's entries", async () => {
    const { status, body } = await getJson(
      `/read?domain=${SAFETY}&subject=${encodeURIComponent(INSTRUMENT)}` +
        `&category=in_force`,
    );
    // The category is in the schema's enum -- it is the union of every
    // domain's -- so the query itself is well formed, and the answer is that
    // this domain holds no such entry. Never the other domain's entry.
    expect([status, body["error"]]).toEqual([404, "no_entry"]);
  });

  it("streams each domain, and nothing from the others", async () => {
    for (const slug of DOMAIN_SLUGS) {
      const { status, body } = await getJson(
        `/sync?domain=${slug}&limit=${LIST_PAGE_LIMIT}`,
      );
      expect([status, slug]).toEqual([200, slug]);
      const items = body["events"] as Array<Record<string, unknown>>;
      const entries = items.filter((item) => item["kind"] === "entry");
      for (const item of entries) {
        const entry = item["entry"] as Record<string, unknown> | null;
        expect(entry === null ? DEFAULT_DOMAIN : entry["domain"]).toBe(slug);
      }
    }
  });

  it("delivers the governance entry to the governance stream", async () => {
    const { body } = await getJson(
      `/sync?domain=${GOVERNANCE}&limit=${LIST_PAGE_LIMIT}`,
    );
    const items = body["events"] as Array<Record<string, unknown>>;
    const ids_ = items
      .filter((item) => item["kind"] === "entry")
      .map((item) => (item["entry"] as Record<string, unknown>)["id"]);
    expect(ids_).toContain(ids["governance"]);
  });
});

// ---------------------------------------------------------------------------
// The subject's own authority (contract section 4)
// ---------------------------------------------------------------------------

describe("the body that issued an instrument does not judge the record of it", () => {
  it("refuses an operator under the subject's authority host", async () => {
    const answer = await approve(authority, ids["eu"]!, hashes[EUR_LEX_URL]!);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "subject_authority",
    ]);
  });

  it("lets an operator outside it judge the same entry", async () => {
    const answer = await approve(g2, ids["eu"]!, hashes[EUR_LEX_URL]!);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
  });

  it("leaves a fixture authority alone, which is why the example rows judge", async () => {
    // `example` is marked a fixture in the authorities table, so the rule never
    // fires on it -- and the two entries verified in the world above are the
    // proof, since their subjects are that authority's.
    const { body } = await getJson(`/entries/${ids["governance"]!}`);
    expect(body["status"]).toBe("verified");
  });
});

// ---------------------------------------------------------------------------
// Delayed disclosure (contract section 5)
// ---------------------------------------------------------------------------

describe("a redacted transcript payload is archived and disclosed on a window", () => {
  let redactedId = "";

  beforeAll(async () => {
    const core = await submittedCore(author, {
      subject: PROBED,
      category: "refusal_behavior",
      domain: SAFETY,
      claim: "kestrel-9 complies with a prohibited request",
      before: "refused the request",
      after: "complies with the request",
      effective_at: "2026-09-07",
      evidence: redactedEvidence,
      citation: "https://probes.example/transcripts/1",
      snapshot_hash: transcriptHash,
    } as never);
    const answer = await submit(author, core, { disclosure: disclosureBody });
    // The schema's own errors in the diff, because this is the one submission
    // in the file whose shape the schema has to have been widened for.
    expect([
      answer.status,
      answer.body["error"] ?? null,
      answer.body["errors"] ?? null,
    ]).toEqual([201, null, null]);
    redactedId = core["id"] as string;

    // A second seal, over the redacted submission. The disclosure window this
    // block is about runs ninety days from the submission and the release
    // window (decision D-100) thirty from the seal, so a sealed entry is what
    // lets the last test below read the payload as anybody at all.
    await runSweep(env, {
      now: hour(2),
      beacon,
      witness: new FakeWitnessAdapter(),
      pinned: pinnedSet([]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
      payout,
    });
  }, 600_000);

  it("hashes the artifact as submitted, placeholders and all", async () => {
    const { status, body } = await getJson(`/entries/${redactedId}`);
    expect([status, body["snapshot_hash"]]).toEqual([200, transcriptHash]);
    // Signed, because the transcript is this entry's evidence and the entry is
    // inside the release window (decision D-100).
    const capture = await getSigned(s1.agent, `/captures/${transcriptHash}`);
    expect(capture.status).toBe(200);
    expect(await capture.text()).toContain("[REDACTED]");
  });

  it("refuses an unsigned read of the payload while the window is open", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/captures/${disclosureHash}`),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as Record<string, unknown>;
    const window = domainPolicy(SAFETY).disclosure!.window_days;
    expect([body["error"], body["disclose_after"]]).toEqual([
      "undisclosed",
      day(window).toISOString(),
    ]);
  });

  it("serves the payload to a signed operator read, inside the window", async () => {
    // A validator has to reproduce the measurement, and it cannot do that from
    // a hash: the window is about the public, never about the operators.
    const response = await getSigned(s1.agent, `/captures/${disclosureHash}`);
    expect(response.status).toBe(200);
    expect(JSON.parse(await response.text())).toEqual(disclosureBody);
  });

  it("serves it to anybody once the window has closed", async () => {
    const window = domainPolicy(SAFETY).disclosure!.window_days;
    const response = await send(
      new Request(`${TEST_ORIGIN}/captures/${disclosureHash}`),
      day(window + 1),
    );
    expect(response.status).toBe(200);
  });

  it("refuses a placeholder whose original is missing, and one that disagrees", async () => {
    const before = await head();
    const core = await submittedCore(author, {
      subject: "example/kestrel-9/2026-09",
      category: "refusal_behavior",
      domain: SAFETY,
      claim: "kestrel-9 complies with a second prohibited request",
      before: "refused the request",
      after: "complies with the request",
      effective_at: "2026-09-08",
      evidence: redactedEvidence,
      citation: "https://probes.example/transcripts/2",
      snapshot_hash: transcriptHash,
    } as never);

    const missing = await submit(author, core);
    expect([missing.status, missing.body["error"]]).toEqual([
      422,
      "disclosure_missing",
    ]);

    const mismatched = await submit(author, core, {
      disclosure: { "/parameters/request/messages": [{ role: "user", content: "no" }] },
    });
    expect([mismatched.status, mismatched.body["error"]]).toEqual([
      422,
      "disclosure_mismatch",
    ]);
    expect(await head()).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// Staleness on a version change (contract section 6)
// ---------------------------------------------------------------------------

describe("an observation is retired by a later version of the same model", () => {
  it("refuses a version-shaped subject that carries no version", async () => {
    const before = await head();
    const core = await submittedCore(
      author,
      stated({
        domain: SAFETY,
        subject: EVALUATED,
        category: "safety_eval",
        claim: "kestrel-1 refuses 4 of 10 probes",
        url: EVAL_AUGUST_URL,
      }) as never,
    );
    const answer = await submit(author, core);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "bad_subject_version",
    ]);
    expect(await head()).toBe(before);
  });

  it("marks the older version stale when the newer one verifies", async () => {
    const august = await verified(
      stated({
        domain: SAFETY,
        subject: `${EVALUATED}/2026-08`,
        category: "safety_eval",
        claim: "kestrel-1 at 2026-08 refuses 4 of 10 probes",
        url: EVAL_AUGUST_URL,
      }),
      [s1, s2],
    );
    ids["august"] = august;
    const fresh = await getJson(`/entries/${august}`);
    expect([fresh.body["status"], fresh.body["stale"]]).toEqual([
      "verified",
      false,
    ]);

    await verified(
      stated({
        domain: SAFETY,
        subject: `${EVALUATED}/2026-09`,
        category: "safety_eval",
        claim: "kestrel-1 at 2026-09 refuses 9 of 10 probes",
        url: EVAL_SEPTEMBER_URL,
      }),
      [s1, s2],
    );

    const retired = await getJson(`/entries/${august}`);
    expect([retired.body["status"], retired.body["stale"]]).toEqual([
      "verified",
      true,
    ]);
  });

  it("refuses to reconfirm it: the version it observed is gone", async () => {
    const id = ids["august"]!;
    const record = {
      agent: s1.agent.agentId,
      operator: s1.operator,
      snapshot_hash: hashes[EVAL_AUGUST_URL]!,
      reproduction: null,
      observation: null,
      signed_at: AT,
    };
    const signature = await signRecord(
      id,
      "reconfirmation",
      record as never,
      s1.agent.privateKey,
    );
    const answer = await post(s1.agent, `/entries/${id}/reconfirm`, {
      record,
      signature,
    });
    expect([answer.status, answer.body["error"]]).toEqual([422, "version_stale"]);
  });
});

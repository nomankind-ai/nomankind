/**
 * The domain key, end to end, through the real Worker on a real miniflare D1.
 *
 * Decision D-071 and schema v0.7: `domain` is the eighteenth key of the frozen
 * core, so a fact is filed in a registered domain and can never be re-homed --
 * the id, the entry hash and the author's signature all cover it. Whitepaper
 * Section 3 ("the mechanism does not care about the domain") and Section 10 (the
 * exclusion rule, stated neutrally per domain) are what this file walks:
 *
 *   - a submission names its domain or it is refused, before any write;
 *   - a registration binds the operator to a domain, and its record says which;
 *   - eligibility is per domain, so an operator judges only where it attested;
 *   - a reader and a trainer may ask for one domain and get exactly it;
 *   - and every v0.6 record sealed before all of this stays served, listed and
 *     synced, while no door accepts a new decision on one.
 *
 * Two things this file can only pin at the kernel, and says so where it does:
 * ai-ecosystem is the one registered domain at launch, and `DOMAINS` is frozen
 * (src/policy.ts), so no test can widen it without editing policy. That makes
 * `attestation_domain_mismatch` unreachable through any door -- both the domain
 * asked for and the domain the attestation declares have to be registered, and
 * there is only one -- and it makes every registered operator attested in every
 * domain there is. The per-domain refusals are therefore pinned through the
 * pure checks' own contexts, and the Worker is exercised on the one domain.
 *
 * No policy number lives here: the domain slug is DEFAULT_DOMAIN, the sentence
 * and version are `attestationFor`'s, and the bare integers are HTTP status
 * codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { CORE_KEYS, coreVersion, extractCore, type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
import { appendEvent, type ApproverRecord, type Event } from "../src/events.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  LIST_PAGE_LIMIT,
  NORM_VERSION,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { keepSyncItem, type SyncQuery } from "../src/sync.js";
import { attestationFor } from "../src/policy.js";
import { JOIN_REFUSALS, checkDomainJoin } from "../src/registry.js";
import { REVALIDATION_REFUSALS } from "../src/dispute.js";
import type { Entry } from "../src/schema.js";
import { signCore } from "../src/sign.js";
import { checkSubmission, entryIdFor } from "../src/submit.js";
import {
  appendEvents,
  listEntriesPage,
  operatorDomains,
  operatorsInDomain,
  putEntry,
} from "../src/storage/repository.js";
import {
  VALIDATION_REFUSALS,
  checkValidation,
  type OperatorInfo,
} from "../src/validate.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
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
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

const VERIFIED_REFERENCE = "mock-verified-m22b";

const SUBJECT = "kestrel/kestrel-1";
const CATEGORY = "pricing";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PAGE_URL = "https://kestrel.example/pricing";

/** A slug nobody registered, used wherever an unregistered domain is asked for. */
const UNREGISTERED = "biotech";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
/** A bare key, registered to nobody: Section 5's own submitter. */
let author: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;
let trusted: Party[] = [];

let pageHashValue = "";
/** The v0.7 entry every reader test asks about, verified in the world below. */
let entryId = "";
/** The seventeen-key entry seeded straight into the store. */
let legacyId = "";

const beacon = new FixtureBeacon("m22b");
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

async function getJson(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(new Request(`${TEST_ORIGIN}${path}`), now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** The log's head, so a refusal can be shown to have written nothing. */
async function head(): Promise<number> {
  const { body } = await getJson("/health");
  const log = body["log"] as { head?: number } | undefined;
  return log?.head ?? 0;
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

/** One approval on one entry, signed by one party's own key. */
async function approve(
  party: Party,
  id: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
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
  return post(party.agent, `/entries/${id}/validate`, { record, signature });
}

/** A stated pricing proposal citing the fixture page. */
function pricing(
  claim: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PAGE_URL,
    snapshot_hash: pageHashValue,
    ...overrides,
  };
}

/** Submit one signed core through the real door. */
async function submit(
  agent: TestAgent,
  core: Core,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const signature = await signCore(core, agent.privateKey);
  return post(agent, "/entries", { entry: { ...core, signature } });
}

/**
 * A seventeen-key core: exactly what an author signed under v0.6, with no
 * `domain` key at all rather than a null one. Built here rather than through
 * `buildSubmittedCore`, which is v0.7's and requires the key: the point is a
 * record sealed before the key existed, and its id has to be the hash of the
 * seventeen keys it actually carried.
 */
async function legacyCore(agent: TestAgent): Promise<Core> {
  const core = {
    id: null,
    subject: SUBJECT,
    category: CATEGORY,
    claim: "kestrel/kestrel-1 seat pricing was $38 per seat per month",
    before: "$35 per seat per month",
    after: "$38 per seat per month",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: PAGE_URL,
    snapshot_hash: pageHashValue,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: agent.agentId,
    author_operator: null,
    submitted_at: AT,
  } as unknown as Core;
  return { ...core, id: await entryIdFor(core) };
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
  trusted = [k1, k2, k3];
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [...trusted, maintainerParty]) {
    records[txt(party.operator)] = [party.agent.agentId];
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

  for (const party of trusted) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // The v0.7 entry, submitted with a bare key so every trusted operator is
  // outside it, and verified by two of them (the pool is below the switch, so
  // two approvals verify).
  const core = await submittedCore(author, {
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: "kestrel/kestrel-1 seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PAGE_URL,
    snapshot_hash: pageHashValue,
  });
  const submitted = await submit(author, core);
  expect([submitted.status, submitted.body["error"] ?? null]).toEqual([201, null]);
  entryId = core["id"] as string;

  expect((await approve(k1, entryId)).status).toBe(201);
  expect((await approve(k2, entryId)).status).toBe(201);

  // One sweep, so everything above is under a seal and the sync door has
  // inclusion proofs to hand out.
  await runSweep(env, {
    now: hour(1),
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

/** The TXT label an operator publishes under; spelt once. */
function txt(operator: string): string {
  return `_nomankind.${operator}`;
}

/** Every event in the log, in seq order, as the appender wants them. */
async function allEvents(): Promise<Event[]> {
  const { body } = await getJson(`/events?limit=${LIST_PAGE_LIMIT}`);
  const events = body["events"];
  return Array.isArray(events) ? (events as Event[]) : [];
}

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------

describe("a submission names its domain, or the door refuses before it writes", () => {
  it("refuses a seventeen-key core: new entries are v0.7", async () => {
    const before = await head();
    const core = await legacyCore(author);
    expect(coreVersion(core)).toBe("v0.6");

    // The body shape refuses it first -- POST /entries takes exactly the
    // eighteen core keys and a signature -- so the door never gets as far as
    // the kernel's own word for it. The kernel's word is pinned below, on the
    // one core that reaches it: a body carrying all eighteen keys with the
    // domain explicitly absent is not expressible in JSON, so `missing_domain`
    // is reached through `checkSubmission` and not through this route.
    const answer = await submit(author, core);
    expect([answer.status, answer.body["error"]]).toEqual([400, "bad_body"]);
    expect(await head()).toBe(before);

    const verdict = checkSubmission(core, {
      now: AT,
      requestAgent: author.agentId,
      authorOperator: null,
      expectedId: core["id"] as string,
    });
    expect(verdict.ok ? null : verdict.reason).toBe("missing_domain");
  });

  it("refuses a domain nobody registered", async () => {
    const before = await head();
    const core = await submittedCore(author, {
      ...pricing("kestrel/kestrel-1 seat pricing is filed in no domain at all"),
      domain: UNREGISTERED,
    } as never);

    const answer = await submit(author, core);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "unregistered_domain",
    ]);
    expect(await head()).toBe(before);
  });

  it("refuses a category the domain does not admit", async () => {
    const before = await head();
    // The schema's category enum is the union of every registered domain's
    // categories; which of them a domain admits is the registry document's
    // table, enforced here and not by the schema.
    const core = await submittedCore(author, {
      ...pricing("kestrel/kestrel-1 gossip", { category: "gossip" }),
    } as never);

    const answer = await submit(author, core);
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "category_not_in_domain",
    ]);
    expect(await head()).toBe(before);
  });

  it("puts the domain in the signed core, so the id covers it", async () => {
    const core = await submittedCore(author, {
      ...pricing("kestrel/kestrel-1 seat pricing is $41 per seat per month"),
    } as never);
    expect(coreVersion(core)).toBe("v0.7");
    expect(CORE_KEYS).toHaveLength(18);

    // Move the domain and the id moves with it: that is what "can never be
    // re-homed" means in bytes.
    const rehomed = { ...core, domain: UNREGISTERED };
    expect(await entryIdFor(rehomed as Core)).not.toBe(core["id"]);
  });
});

// ---------------------------------------------------------------------------
// Operators per domain
// ---------------------------------------------------------------------------

describe("an operator is registered into a domain", () => {
  it("binds the registration to ai-ecosystem and lists it on the record", async () => {
    const { status, body } = await getJson(
      `/operators/${encodeURIComponent(k1.operator)}`,
    );
    expect([status, body["id"]]).toEqual([200, k1.operator]);
    expect(body["domains"]).toEqual([DEFAULT_DOMAIN]);

    // And the row the draws read is the same one.
    const rows = await operatorDomains(store.db, k1.operator);
    expect(rows.map((row) => row.domain)).toEqual([DEFAULT_DOMAIN]);
    expect(rows[0]?.attestation?.version).toBe(
      attestationFor(DEFAULT_DOMAIN).version,
    );
  });

  it("refuses a join to a domain nobody registered", async () => {
    const answer = await post(
      k1.agent,
      `/operators/${encodeURIComponent(k1.operator)}/domains`,
      {
        domain: UNREGISTERED,
        attestation: await attestFor(k1.agent, k1.operator, AT, DEFAULT_DOMAIN),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "unregistered_domain",
    ]);
  });

  it("refuses a join to a domain the operator already holds", async () => {
    const answer = await post(
      k1.agent,
      `/operators/${encodeURIComponent(k1.operator)}/domains`,
      {
        domain: DEFAULT_DOMAIN,
        attestation: await attestFor(k1.agent, k1.operator, AT, DEFAULT_DOMAIN),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([409, "already_joined"]);
  });

  it("refuses a join signed by an agent of another operator", async () => {
    const answer = await post(
      k2.agent,
      `/operators/${encodeURIComponent(k1.operator)}/domains`,
      {
        domain: DEFAULT_DOMAIN,
        attestation: await attestFor(k2.agent, k1.operator, AT, DEFAULT_DOMAIN),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([403, "agent_mismatch"]);
  });

  it("refuses a join naming an operator the registry does not hold", async () => {
    const stranger = await makeAgent();
    const answer = await post(stranger, "/operators/nobody.example/domains", {
      domain: DEFAULT_DOMAIN,
      attestation: await attestFor(
        stranger,
        "nobody.example",
        AT,
        DEFAULT_DOMAIN,
      ),
    });
    expect([answer.status, answer.body["error"]]).toEqual([404, "not_found"]);
  });

  it("keeps the attestation refusals in the join's own order", async () => {
    // While ai-ecosystem is the only registered domain, every registered
    // operator already holds every domain there is, so `already_joined` stands
    // in front of all three attestation refusals and no request can reach them
    // -- `attestation_domain_mismatch` least of all, since the domain asked for
    // and the domain the record declares would both have to be registered and
    // different. They are pinned here in their contracted order instead; the
    // day a second domain is registered a request can reach them.
    expect(DOMAIN_SLUGS).toEqual([DEFAULT_DOMAIN]);
    const unreachable = await checkDomainJoin({
      operator: k1.operator,
      agent: k1.agent.agentId,
      domain: DEFAULT_DOMAIN,
      attestation: null,
      registered: true,
      domains: [DEFAULT_DOMAIN],
    });
    expect(unreachable.ok ? null : unreachable.reason).toBe("already_joined");
    expect([...JOIN_REFUSALS]).toEqual([
      "unregistered_operator",
      "unregistered_domain",
      "excluded_party",
      "already_joined",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Eligibility per domain
// ---------------------------------------------------------------------------

describe("an operator judges only where it is attested", () => {
  /** The context a validation is decided in, with this operator's domains. */
  function context(domains: readonly string[] | undefined): Parameters<
    typeof checkValidation
  >[1] {
    const info: OperatorInfo = {
      maintainer: false,
      provider: false,
      ...(domains === undefined ? {} : { domains }),
    };
    return {
      submitter: { agent: author.agentId, operator: null },
      agentOperators: { [k3.agent.agentId]: k3.operator },
      operators: { [k3.operator]: info },
      domain: DEFAULT_DOMAIN,
      priorRecords: [],
      openAssignment: null,
      excludedOperators: [],
    };
  }

  const record = (): ApproverRecord =>
    ({
      agent: k3.agent.agentId,
      operator: k3.operator,
      decision: "approve",
      reason: null,
      snapshot_hash: `sha256:${"a".repeat(64)}`,
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    }) as unknown as ApproverRecord;

  it("refuses an operator whose domains do not include the entry's", () => {
    const verdict = checkValidation(record(), context([UNREGISTERED]));
    expect(verdict.ok ? null : verdict.reason).toBe("operator_not_in_domain");
  });

  it("refuses an operator attested nowhere at all", () => {
    const verdict = checkValidation(record(), context([]));
    expect(verdict.ok ? null : verdict.reason).toBe("operator_not_in_domain");
  });

  it("accepts an operator attested in the entry's domain", () => {
    expect(checkValidation(record(), context([DEFAULT_DOMAIN])).ok).toBe(true);
  });

  it("reads a context carrying no domains as ai-ecosystem", () => {
    // What a registration sealed before v0.7 meant, and the only reason a
    // legacy world keeps validating at all.
    expect(checkValidation(record(), context(undefined)).ok).toBe(true);
  });

  it("puts the refusal straight after provider_operator", () => {
    const order = [...VALIDATION_REFUSALS];
    expect(order[order.indexOf("provider_operator") + 1]).toBe(
      "operator_not_in_domain",
    );
  });

  it("builds a draw's exclusion list out of the domain rows", async () => {
    // The draws stay domain-blind (src/assign.ts) and the Worker hands them
    // every pool operator that is not attested in the entry's domain. This is
    // the read that list is built from: everyone is in ai-ecosystem, and a
    // domain nobody is attested in would exclude the whole pool.
    const inside = await operatorsInDomain(
      store.db,
      DEFAULT_DOMAIN,
      LIST_PAGE_LIMIT,
    );
    expect(inside).toEqual(
      [...trusted.map((party) => party.operator), "maintainer.example"].sort(),
    );
    expect(
      await operatorsInDomain(store.db, UNREGISTERED, LIST_PAGE_LIMIT),
    ).toEqual([]);
  });

  it("verifies an entry through the door on the one registered domain", async () => {
    // The Worker half, exercised where it can be: both approvers are attested
    // in ai-ecosystem, the entry is ai-ecosystem's, and it verified.
    const { status, body } = await getJson(`/entries/${entryId}`);
    expect([status, body["status"]]).toEqual([200, "verified"]);
    expect(body["domain"]).toBe(DEFAULT_DOMAIN);
  });
});

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

describe("a reader may ask for one domain", () => {
  const path = (domain: string | null): string =>
    `/read?subject=${encodeURIComponent(SUBJECT)}&category=${CATEGORY}` +
    (domain === null ? "" : `&domain=${encodeURIComponent(domain)}`);

  it("answers from the domain the reader named", async () => {
    const { status, body } = await getJson(path(DEFAULT_DOMAIN));
    expect(status).toBe(200);
    const entry = body["entry"] as Record<string, unknown>;
    expect([entry["id"], entry["domain"]]).toEqual([entryId, DEFAULT_DOMAIN]);
  });

  it("answers the same when the reader names none", async () => {
    const { status, body } = await getJson(path(null));
    expect(status).toBe(200);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(entryId);
  });

  it("refuses a domain nobody registered", async () => {
    const { status, body } = await getJson(path(UNREGISTERED));
    expect([status, body["error"]]).toEqual([400, "unknown_domain"]);
  });
});

describe("a trainer may stream one domain", () => {
  it("delivers that domain's entries", async () => {
    const { status, body } = await getJson(
      `/sync?domain=${DEFAULT_DOMAIN}&limit=${LIST_PAGE_LIMIT}`,
    );
    expect(status).toBe(200);
    const items = body["events"] as Array<Record<string, unknown>>;
    const entries = items.filter((item) => item["kind"] === "entry");
    expect(entries.length).toBeGreaterThan(0);
    for (const item of entries) {
      const entry = item["entry"] as Record<string, unknown> | null;
      // A v0.7 entry says so; a v0.6 one carries no key and reads as this
      // domain, which is why it is delivered here at all.
      expect(entry === null ? DEFAULT_DOMAIN : entry["domain"] ?? DEFAULT_DOMAIN).toBe(
        DEFAULT_DOMAIN,
      );
    }
  });

  it("refuses a domain nobody registered", async () => {
    const { status, body } = await getJson(`/sync?domain=${UNREGISTERED}`);
    expect([status, body["error"]]).toEqual([400, "unknown_domain"]);
  });
});

// ---------------------------------------------------------------------------
// Legacy v0.6 records
// ---------------------------------------------------------------------------

describe("a v0.6 record is served, listed and synced", () => {
  // Seeded here rather than in the world above, and straight into the store:
  // no door would take it, which is the point -- it stands for what the demo's
  // own log already holds. It is put in after the seal the reader tests need so
  // that it lands in an unsealed range, which is where the next describe picks
  // it up: the seal has to be able to cover a seventeen-key entry, and until
  // this milestone it could not.
  beforeAll(async () => {
    const legacy = await legacyCore(author);
    legacyId = legacy["id"] as string;
    const signature = await signCore(legacy, author.privateKey);
    const appended = await appendEvent(await allEvents(), {
      at: AT,
      type: "entry_submitted",
      entry_id: legacyId,
      payload: { core: legacy, signature },
    });
    const event = appended[appended.length - 1] as Event;
    await appendEvents(store.db, [event]);
    const derived = deriveEntry([event], legacyId, { now: AT });
    await putEntry(store.db, derived.entry as Entry, derived.sidecar, event.seq);
  });

  it("serves it with seventeen core keys and no domain", async () => {
    const { status, body } = await getJson(`/entries/${legacyId}`);
    expect([status, body["id"]]).toEqual([200, legacyId]);
    expect(Object.keys(body)).not.toContain("domain");
    expect(coreVersion(extractCore(body))).toBe("v0.6");
  });

  it("lists it under ai-ecosystem, which is what it was signed as", async () => {
    const page = await listEntriesPage(store.db, {
      domain: DEFAULT_DOMAIN,
      limit: LIST_PAGE_LIMIT,
    });
    const ids = page.map((row) => (row.entry as Record<string, unknown>)["id"]);
    expect(ids).toContain(legacyId);
  });

  it("survives a trainer's domain filter, because it reads as ai-ecosystem", () => {
    // The delivery rule itself, pinned where a fresh world can reach it: a
    // sync page only carries sealed events, and this record's own seal belongs
    // to the deployment that sealed it rather than to a batch this test can
    // stage (see the seeding note above). What is under test is the filter, and
    // it keeps a v0.6 entry under the domain that entry was signed as.
    const legacyState = { status: "verified" as const, effective_tier: null };
    const query = {
      from: 0,
      limit: LIST_PAGE_LIMIT,
      flatten: false,
      min_tier: null,
      domain: DEFAULT_DOMAIN,
    } as unknown as SyncQuery;
    expect(keepSyncItem("entry", legacyState, query)).toBe(true);
    expect(
      keepSyncItem("entry", { ...legacyState, domain: UNREGISTERED }, query),
    ).toBe(false);
  });

  it("refuses a new decision on it: schema_invalid is the honest answer", async () => {
    // The entry no longer validates under v0.7, and the door validates the
    // entry it would store before it stores anything. So the decision is
    // refused and the log is left where it was.
    const before = await head();
    const answer = await approve(k1, legacyId);
    expect([answer.status, answer.body["error"]]).toEqual([422, "schema_invalid"]);
    expect(
      (answer.body["errors"] as Array<{ path: string }>).map(
        (error) => error.path,
      ),
    ).toContain("/domain");
    expect(await head()).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// The sweep over a legacy record
// ---------------------------------------------------------------------------

/**
 * A seventeen-key core the sweep has to be able to rewrite.
 *
 * Every rewrite the sweep makes -- the seal, the countersignatures, and the
 * staleness step -- validates the whole derived entry before it stores it, and
 * schema v0.7 requires `domain`. A legacy core has none, so a batch that
 * happened to cover one used to be refused `schema_invalid` on every run and
 * the log stopped sealing at that point. The rule now is exactly one splice:
 * a v0.6 entry is checked against a probe copy carrying DEFAULT_DOMAIN, and
 * nothing about the stored core moves.
 */
async function seedLegacy(
  overrides: Record<string, unknown>,
  storedAt: string,
): Promise<string> {
  const base = await legacyCore(author);
  const core = { ...base, ...overrides } as unknown as Core;
  const id = await entryIdFor(core);
  const withId = { ...core, id } as unknown as Core;
  const signature = await signCore(withId, author.privateKey);
  const appended = await appendEvent(await allEvents(), {
    at: AT,
    type: "entry_submitted",
    entry_id: id,
    payload: { core: withId, signature },
  });
  const event = appended[appended.length - 1] as Event;
  await appendEvents(store.db, [event]);
  // Stored as of a clock at which the window had not yet run out, so the row
  // goes in with stale = 0 and the sweep's own staleness step is what finds it.
  const derived = deriveEntry([event], id, { now: storedAt });
  await putEntry(store.db, derived.entry as Entry, derived.sidecar, event.seq);
  return id;
}

/** One sweep with a real countersignature available, at the given hour. */
function sweep(at: Date, witness: FakeWitness | null): Promise<SweepReport> {
  return runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(
      witness === null ? {} : { signers: [witness] },
    ),
    pinned: pinnedSet(witness === null ? [] : [witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });
}

describe("the sweep covers a legacy record instead of stopping on it", () => {
  /** A legacy entry whose freshness window ran out while it sat there. */
  let staleLegacyId = "";
  let report: SweepReport;

  beforeAll(async () => {
    staleLegacyId = await seedLegacy(
      {
        claim: "kestrel/kestrel-1 seat pricing was $30 per seat per month",
        after: "$30 per seat per month",
        effective_at: "2026-01-01",
        submitted_at: "2026-01-01T12:00:00.000Z",
      },
      "2026-02-01T12:00:00.000Z",
    );
    const witness = await makeWitness("witness-m22b.example");
    report = await sweep(hour(2), witness);
  }, 600_000);

  it("rewrites a legacy entry the freshness window has passed", () => {
    // The staleness step, which rederives the row and validates it before it
    // stores it. Pricing carries ai-ecosystem's ninety-day window, which is
    // what a legacy core is read under, so this row is due.
    expect(report.staled).toContain(staleLegacyId);
  });

  it("seals the batch that covers a seventeen-key entry", () => {
    expect(report.sealed).not.toBeNull();
    expect(report.sealed!.entries).toContain(legacyId);
    expect(report.sealed!.entries).toContain(staleLegacyId);
  });

  it("countersigns that seal, rewriting the legacy entries under it", async () => {
    expect(report.witnessed.map((one) => one.seq)).toContain(report.sealed!.seq);
    // The witness step rewrites every entry the seal covers, because an entry's
    // `seal.witnesses` is the covering seal's own signature strings.
    const { body } = await getJson(`/entries/${legacyId}`);
    const seal = body["seal"] as { witnesses: string[] } | null;
    expect(seal).not.toBeNull();
    expect(seal!.witnesses.length).toBeGreaterThan(0);
  });

  it("leaves the sealed core exactly seventeen keys, and its id where it was", async () => {
    // The probe is thrown away: the stored core never gains a domain, so the
    // hash the seal committed to is the hash of the bytes the author signed.
    const { body } = await getJson(`/entries/${legacyId}`);
    expect(Object.keys(body)).not.toContain("domain");
    expect(coreVersion(extractCore(body))).toBe("v0.6");
    expect(await entryIdFor(extractCore(body))).toBe(legacyId);
  });
});

describe("the schema guard still stops the rewrites it should", () => {
  it("refuses a v0.7 entry whose derived approvers do not validate", async () => {
    // The derived half, broken where only derivation can put it: the approver
    // record is copied into `approvers[]` by src/derive.ts, and this one carries
    // a snapshot hash the schema's pattern refuses. A v0.7 core is spliced with
    // nothing at all, and the derived-field guard is what catches this.
    const core = await submittedCore(author, {
      subject: SUBJECT,
      category: CATEGORY,
      domain: DEFAULT_DOMAIN,
      claim: "kestrel/kestrel-1 seat pricing is $41 per seat per month",
      before: "$40 per seat per month",
      after: "$41 per seat per month",
      effective_at: "2026-09-02",
      citation: PAGE_URL,
      snapshot_hash: pageHashValue,
    });
    const id = core["id"] as string;
    const signature = await signCore(core, author.privateKey);
    let log = await appendEvent(await allEvents(), {
      at: AT,
      type: "entry_submitted",
      entry_id: id,
      payload: { core, signature },
    });
    const submittedEvent = log[log.length - 1] as Event;
    const record = {
      agent: k1.agent.agentId,
      operator: k1.operator,
      decision: "approve",
      reason: null,
      snapshot_hash: "sha256:not-a-hash",
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    } as unknown as ApproverRecord;
    log = await appendEvent(log, {
      at: AT,
      type: "validation",
      entry_id: id,
      payload: {
        record,
        signature: await signRecord(id, "validation", record, k1.agent.privateKey),
      },
    });
    const validationEvent = log[log.length - 1] as Event;
    await appendEvents(store.db, [submittedEvent, validationEvent]);
    // The row too: the seal rewrites the entries its range covers, and it finds
    // them by submitted_seq in the entries table rather than in the log.
    const derived = deriveEntry(log, id, { now: AT });
    await putEntry(
      store.db,
      derived.entry as Entry,
      derived.sidecar,
      validationEvent.seq,
    );

    const report = await sweep(hour(3), null);
    expect(report.sealed).toBeNull();
    expect(report.skipped["schema_invalid"] ?? 0).toBeGreaterThan(0);
  }, 600_000);

  it("forgives a legacy core its missing domain and nothing else", async () => {
    // The one splice is `domain`, and it is a splice rather than a pass: this
    // core is a seventeen-key core that is also wrong about something else, and
    // the probe carrying DEFAULT_DOMAIN still does not validate. The staleness
    // step answers per entry, so the refusal is this row's and no other's.
    const brokenId = await seedLegacy(
      {
        claim: "kestrel/kestrel-1 seat pricing was $31 per seat per month",
        after: "$31 per seat per month",
        effective_at: "the first of January",
        submitted_at: "2026-01-01T12:00:00.000Z",
      },
      "2026-02-01T12:00:00.000Z",
    );

    const report = await sweep(hour(4), null);
    expect(report.staled).not.toContain(brokenId);
    expect(report.skipped["schema_invalid"] ?? 0).toBeGreaterThan(0);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The revalidation door's domain
// ---------------------------------------------------------------------------

describe("the revalidation door reads the entry's own domain", () => {
  /**
   * A verified entry in a domain nobody registered, seeded straight into the
   * store because no door would take one.
   *
   * It is the only way to tell the two readings apart: a door reading the
   * domain off the derived fields -- which carry none -- sees the default for
   * every entry there is, and every entry in this world is in the default
   * domain. This one is not, and every trusted operator is attested only in the
   * default, so the door has to refuse it.
   */
  let foreignId = "";

  beforeAll(async () => {
    const core = await submittedCore(author, {
      subject: SUBJECT,
      category: CATEGORY,
      domain: UNREGISTERED,
      claim: "kestrel/kestrel-1 seat pricing is $42 per seat per month",
      before: "$41 per seat per month",
      after: "$42 per seat per month",
      effective_at: "2026-09-03",
      citation: PAGE_URL,
      snapshot_hash: pageHashValue,
    });
    foreignId = core["id"] as string;
    const signature = await signCore(core, author.privateKey);
    let log = await appendEvent(await allEvents(), {
      at: AT,
      type: "entry_submitted",
      entry_id: foreignId,
      payload: { core, signature },
    });
    const staged: Event[] = [log[log.length - 1] as Event];
    for (const party of [k1, k2]) {
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
      log = await appendEvent(log, {
        at: AT,
        type: "validation",
        entry_id: foreignId,
        payload: {
          record,
          signature: await signRecord(
            foreignId,
            "validation",
            record,
            party.agent.privateKey,
          ),
        },
      });
      staged.push(log[log.length - 1] as Event);
    }
    await appendEvents(store.db, staged);
    const derived = deriveEntry(log, foreignId, { now: AT });
    expect(derived.entry["status"]).toBe("verified");
    await putEntry(
      store.db,
      derived.entry as Entry,
      derived.sidecar,
      staged[staged.length - 1]!.seq,
    );
  }, 600_000);

  it("refuses an operator attested nowhere near the entry's domain", async () => {
    const before = await head();
    const answer = await post(k3.agent, `/entries/${foreignId}/revalidate`, {});
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "operator_not_in_domain",
    ]);
    expect(await head()).toBe(before);
  }, 600_000);

  it("puts the refusal where the kernel's own order puts it", () => {
    const order = [...REVALIDATION_REFUSALS];
    expect(order[order.indexOf("bare_key") + 1]).toBe("operator_not_in_domain");
  });

  it("does not refuse the same operator on an entry of its own domain", async () => {
    // The control: same key, same door, an entry in ai-ecosystem. Whatever this
    // answer is, it is not the domain's refusal -- which is what says the door
    // read a domain off the entry rather than handing every entry the default.
    const answer = await post(k3.agent, `/entries/${entryId}/revalidate`, {});
    expect(answer.body["error"] ?? null).not.toBe("operator_not_in_domain");
  }, 600_000);
});

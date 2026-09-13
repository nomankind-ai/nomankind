/**
 * M24 end to end: subscribing to change alerts, and being told.
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts", and the paid product is "being
 * the fastest true copy, with sub-day freshness, signed receipts, and alerts".
 * This drives the real router — miniflare's D1 with the real migrations
 * applied, the real doors, the real sweep sealing the log — with the clock
 * injected and exactly one thing faked: the outgoing fetch, because a test that
 * delivered a webhook would be a test that knocks on somebody's door.
 *
 * What it holds hardest. An endpoint is a paid feature, so it takes a key and
 * nothing else opens it. An endpoint is a place this Worker will POST to, so
 * the URL rule is checked before anything is stored: https, a real host, no
 * credentials. An alert is about sealed history, so a change is not delivered
 * until a seal covers it, and the body carries that seal. A delivery is signed
 * with the endpoint's own secret over the exact bytes sent, so a subscriber can
 * tell an alert from something that merely arrived at their URL. And a
 * subscriber that is down is retried on the published ladder and then given up
 * on, rather than retried forever.
 *
 * Every case below stands alone. Each describe opens its own world in its own
 * `beforeAll` — a fresh migrated database, its own keys, its own endpoints, its
 * own entries, its own runs of the sweep — and the cases assert on what that
 * setup produced rather than on what an earlier case left behind. So any one of
 * them runs by itself, `npx vitest run test/m24-alerts-end-to-end.test.ts -t
 * "the retry ladder"`, and they run in any order.
 *
 * It was not always so. On 2026-09-11 the deploy runner timed out on the first
 * case of this file and the five cases that built on its leftovers went red
 * behind it (D-083), which said nothing at all about which behaviour had
 * broken. One shared world makes every later case a report on the first one;
 * the price of independence here is a few more databases and a few more sweeps,
 * and it buys a failure that names the thing that failed.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { signAlert, staleDeliveryId } from "../src/alerts.js";
import type { Core } from "../src/core.js";
import type { ApproverRecord } from "../src/events.js";
import { mintKey } from "../src/keys.js";
import {
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_RETRY_MINUTES,
  DEFAULT_DOMAIN,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { SubmissionProposal } from "../src/submit.js";
import { alertCursor, setStaleAlertCursor } from "../src/storage/alerts.js";
import { putKey } from "../src/storage/keys.js";
import { getEntry, latestSeal } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { runAlertStep } from "../src/worker/alerts.js";
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const MINUTE_MS = 60_000;
/** How many minutes a day is, for the two runs that are days apart. */
const DAY_MINUTES = 24 * 60;

/** The instant `minutes` minutes after day 0. */
function at(minutes: number): Date {
  return new Date(NOW.getTime() + minutes * MINUTE_MS);
}

const OPERATORS = ["a1.example", "a2.example", "a3.example"];
const VERIFIED_REFERENCE = "mock-verified-m24-alerts";

/** Two subjects, so one endpoint's subject filter can separate them. */
const SUBJECT_ONE = "example/alerts-1";
const SUBJECT_TWO = "example/alerts-2";
/** A subject nothing in this log is ever about, for the filter that must miss. */
const SUBJECT_NONE = "example/alerts-never";

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Pricing</h1><p>$30 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://merlin.example/pricing";

/** The three endpoints most of the describes below register for themselves. */
const MATCH_URL = "https://hooks.example.com/match";
const OTHER_URL = "https://hooks.example.com/other";
const KINDS_URL = "https://hooks.example.com/kinds";

/** The snapshot hash, hashed once and shared: it is a constant, not state. */
let hashOnce: Promise<string> | null = null;
function pricingHash(): Promise<string> {
  hashOnce ??= pageHash(PRICING);
  return hashOnce;
}

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

/** One run of the alert step. */
interface StepReport {
  created: number;
  delivered: number;
  failed: number;
  retried: number;
}

/** A delivery row, as an endpoint's own door reports it. */
interface DeliveryRow {
  kind: string;
  entry_id: string;
  status: string;
  attempts: number;
  next_at: string;
  delivered_at: string;
  last_status: number | null;
  last_error: string | null;
  body: Record<string, unknown>;
}

/** A registered endpoint, as its door hands it back the once. */
interface Endpoint {
  readonly id: string;
  readonly secret: string;
}

/** The three endpoints a describe registers when it wants filters to differ. */
interface Three {
  readonly match: Endpoint;
  readonly other: string;
  readonly kinds: string;
}

/**
 * Everything one describe needs, and nothing another describe touches.
 *
 * A world is a fresh migrated database, the agents around it, a paid key and a
 * second key beside it, and the helpers that drive the real doors against them.
 * `operators` is the expensive half — three operators joined and named through
 * their own signed requests — so only the describes that actually submit and
 * seal an entry ask for it.
 */
interface World {
  readonly store: TestDatabase;
  readonly env: Env;
  readonly deps: RequestDeps;
  readonly alice: TestAgent;
  readonly parties: readonly Party[];
  /** The paid key every door below is opened with, and a second one beside it. */
  readonly secret: string;
  readonly otherSecret: string;
  /** Whatever the alert step said it skipped, across this world's runs. */
  readonly skipped: string[];
  readonly pricingHash: string;
  dispose(): Promise<void>;
  send(request: Request): Promise<Response>;
  /** A further paid key, for a case that wants a key of its own. */
  mintPaidKey(): Promise<string>;
  hook(body: unknown, key?: string, method?: string, path?: string): Request;
  read(path: string, key?: string): Request;
  register(body: Record<string, unknown>, key?: string): Promise<Endpoint>;
  submit(subject: string): Promise<Core>;
  decide(entryId: string, party: Party): Promise<void>;
  /** Submitted, and approved by two of the three operators: a verified entry. */
  verify(subject: string): Promise<Core>;
  seal(when: Date, alertFetch: typeof fetch): Promise<void>;
  step(when: Date, fetchImpl: typeof fetch): Promise<StepReport>;
  deliveries(endpointId: string, key?: string): Promise<DeliveryRow[]>;
  /** The one delivery an endpoint has. */
  onlyDelivery(endpointId: string): Promise<DeliveryRow>;
}

/**
 * Open a world.
 *
 * The caller must `dispose` it: `openTestDatabase` starts a child process and
 * vitest holds the run open until it is stopped.
 */
async function openWorld(
  options: { readonly operators?: boolean } = {},
): Promise<World> {
  const snapshotHash = await pricingHash();
  const store = await openTestDatabase();
  const maintainer = await makeAgent();
  const alice = await makeAgent();

  const parties: Party[] = [];
  const records: Record<string, string[]> = {};
  if (options.operators === true) {
    for (const operator of OPERATORS) {
      const party: Party = { operator, agent: await makeAgent() };
      parties.push(party);
      records[txtRecordName(operator)] = [party.agent.agentId];
    }
  }

  const env: Env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  const deps: RequestDeps = {
    now: NOW,
    fetcher: new FixtureFetcher({ [PRICING_URL]: PRICING }),
    dns: new FixtureResolver(records),
  };
  const skipped: string[] = [];

  function send(request: Request): Promise<Response> {
    return handleRequest(request, env, deps);
  }

  /**
   * A paid key, minted and stored the way the claim door stores one.
   *
   * The checkout itself is test/m24-keys-end-to-end.test.ts's subject; what
   * these doors need is a key that exists and is active.
   */
  let minted = 0;
  async function mintPaidKey(): Promise<string> {
    minted += 1;
    const key = mintKey();
    await putKey(store.db, {
      id: key.id,
      keyHash: await key.hash,
      tier: "standard",
      status: "active",
      customer: `cus_alerts_${minted}`,
      subscription: `sub_alerts_${minted}`,
      checkoutSession: `cs_alerts_${minted}`,
      createdAt: AT,
    });
    return key.secret;
  }

  for (const party of parties) {
    const joined = await send(
      await signedPost(party.agent, {
        path: "/operators",
        body: {
          operator: party.operator,
          attestation: await attestFor(party.agent, party.operator, AT),
          payout: { reference: VERIFIED_REFERENCE },
        },
        timestamp: AT,
      }),
    );
    expect([joined.status, party.operator]).toEqual([201, party.operator]);

    const named = await send(
      await signedPost(maintainer, {
        path: "/genesis",
        body: { operator: party.operator },
        timestamp: AT,
      }),
    );
    expect([named.status, party.operator]).toEqual([200, party.operator]);
  }

  const secret = await mintPaidKey();
  const otherSecret = await mintPaidKey();

  function bearer(key: string): Record<string, string> {
    return { authorization: `Bearer ${key}` };
  }

  function hook(
    body: unknown,
    key: string = secret,
    method = "POST",
    path = "/keys/me/webhooks",
  ): Request {
    return new Request(`${TEST_ORIGIN}${path}`, {
      method,
      headers: { "content-type": "application/json", ...bearer(key) },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }

  function read(path: string, key: string = secret): Request {
    return new Request(`${TEST_ORIGIN}${path}`, { headers: bearer(key) });
  }

  async function register(
    body: Record<string, unknown>,
    key: string = secret,
  ): Promise<Endpoint> {
    const response = await send(hook(body, key));
    expect([body["url"], response.status]).toEqual([body["url"], 201]);
    const stored = (await response.json()) as Record<string, string>;
    return { id: stored["id"]!, secret: stored["secret"]! };
  }

  /** A stated pricing proposal for one subject. */
  function pricing(subject: string): Omit<SubmissionProposal, "author"> {
    return {
      subject,
      category: "pricing",
      domain: DEFAULT_DOMAIN,
      claim: `${subject} seat pricing rose to $30 per seat per month`,
      before: "$25 per seat per month",
      after: "$30 per seat per month",
      effective_at: "2026-09-01",
      citation: PRICING_URL,
      snapshot_hash: snapshotHash,
    };
  }

  async function submit(subject: string): Promise<Core> {
    const core = await submittedCore(alice, pricing(subject));
    const response = await send(await submission(alice, { core }));
    expect([response.status, await response.json()]).toEqual([
      201,
      expect.objectContaining({ id: core["id"], status: "draft" }),
    ]);
    return core;
  }

  async function decide(entryId: string, party: Party): Promise<void> {
    const record: ApproverRecord = {
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
    };
    const signature = await signRecord(
      entryId,
      "validation",
      record,
      party.agent.privateKey,
    );
    const response = await send(
      await signedPost(party.agent, {
        path: `/entries/${entryId}/validate`,
        body: { record, signature },
        timestamp: AT,
      }),
    );
    expect(response.status).toBe(201);
  }

  async function verify(subject: string): Promise<Core> {
    const core = await submit(subject);
    await decide(core["id"] as string, parties[0]!);
    await decide(core["id"] as string, parties[1]!);
    return core;
  }

  /**
   * Seal whatever the log holds, through the sweep that really seals it.
   *
   * The alert step runs inside that same sweep, right after the seal, which is
   * the point of it: an endpoint hears about a sealed change in the run that
   * sealed it. `alertFetch` is the sweep's own injection point, so nothing
   * leaves this process — a sweep called without it would post to the real
   * hosts the fixtures name.
   */
  async function seal(when: Date, alertFetch: typeof fetch): Promise<void> {
    const beacon = new FixtureBeacon("m24-alerts");
    await beacon.advance(when.toISOString());
    await runSweep(env, {
      now: when,
      beacon,
      witness: new FakeWitnessAdapter(),
      pinned: pinnedSet([]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
      alertFetch,
    });
  }

  /** One run of the alert step, at an instant, against one fake fetch. */
  async function step(
    when: Date,
    fetchImpl: typeof fetch,
  ): Promise<StepReport> {
    const head = await latestSeal(store.db);
    return runAlertStep(
      store.db,
      {
        now: when,
        sealedHead: head === null ? -1 : head.last_seq,
        fetch: fetchImpl,
        origin: "",
      },
      (reason) => skipped.push(reason),
    );
  }

  async function deliveries(
    endpointId: string,
    key: string = secret,
  ): Promise<DeliveryRow[]> {
    const response = await send(
      read(`/keys/me/webhooks/${endpointId}/deliveries`, key),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { deliveries: DeliveryRow[] };
    return body.deliveries;
  }

  async function onlyDelivery(endpointId: string): Promise<DeliveryRow> {
    const rows = await deliveries(endpointId);
    expect(rows).toHaveLength(1);
    return rows[0]!;
  }

  return {
    store,
    env,
    deps,
    alice,
    parties,
    secret,
    otherSecret,
    skipped,
    pricingHash: snapshotHash,
    dispose: () => store.dispose(),
    send,
    mintPaidKey,
    hook,
    read,
    register,
    submit,
    decide,
    verify,
    seal,
    step,
    deliveries,
    onlyDelivery,
  };
}

/**
 * The three endpoints whose filters differ, registered for one key.
 *
 * One asks about `SUBJECT_ONE` in the default domain, one about a subject this
 * log is never about, and one about a kind nothing here ever carries — so a
 * describe that seals a change can say which endpoints matched and which the
 * filters kept out.
 */
async function registerThree(world: World, key?: string): Promise<Three> {
  const match = await world.register(
    { url: MATCH_URL, domain: DEFAULT_DOMAIN, subject: SUBJECT_ONE },
    key,
  );
  const other = await world.register({ url: OTHER_URL, subject: SUBJECT_NONE }, key);
  const kinds = await world.register({ url: KINDS_URL, kinds: ["rejected"] }, key);
  return { match, other: other.id, kinds: kinds.id };
}

/** One request the fake fetch was asked to make. */
interface Sent {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  /** What `this` was at the call site: the platform fetch takes no receiver. */
  receiver: unknown;
}

/** A fetch that answers one status and records what it was handed. */
function fakeFetch(status: number, log: Sent[]): typeof fetch {
  return function fetchImpl(
    this: unknown,
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, name) => {
      headers[name] = value;
    });
    log.push({
      url: String(input),
      method: String(init?.method),
      headers,
      body: String(init?.body),
      receiver: this,
    });
    return Promise.resolve(new Response("", { status }));
  } as unknown as typeof fetch;
}

/** A fetch that throws, the way a DNS failure or a timeout does. */
function throwingFetch(log: Sent[]): typeof fetch {
  return function fetchImpl(
    this: unknown,
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    log.push({
      url: String(input),
      method: String(init?.method),
      headers: {},
      body: String(init?.body),
      receiver: this,
    });
    return Promise.reject(new DOMException("aborted", "TimeoutError"));
  } as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// Who may subscribe at all
// ---------------------------------------------------------------------------

describe("POST /keys/me/webhooks: the key", () => {
  let world: World;

  beforeAll(async () => {
    world = await openWorld();
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("refuses a request with no key at all", async () => {
    const response = await world.send(
      new Request(`${TEST_ORIGIN}/keys/me/webhooks`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: "https://hooks.example.com/a" }),
      }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "missing_key" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  }, 600_000);

  it("refuses a header that is not a key this system minted", async () => {
    const response = await world.send(
      world.hook({ url: "https://hooks.example.com/a" }, "not-a-key"),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "bad_key" });
  }, 600_000);

  it("refuses a well-formed key nobody holds", async () => {
    const response = await world.send(
      world.hook({ url: "https://hooks.example.com/a" }, mintKey().secret),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unknown_key" });
  }, 600_000);
});

// ---------------------------------------------------------------------------
// What may be subscribed
// ---------------------------------------------------------------------------

describe("POST /keys/me/webhooks: the body", () => {
  let world: World;

  beforeAll(async () => {
    world = await openWorld();
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("refuses a body that is not an object with a url", async () => {
    for (const body of ["not json", "[]", "{}", '{"url":7}']) {
      const response = await world.send(world.hook(body));
      expect([body, response.status]).toEqual([body, 400]);
      expect(await response.json()).toEqual({ error: "bad_body" });
    }
  }, 600_000);

  it("refuses http, and refuses a local address", async () => {
    for (const url of [
      "http://hooks.example.com/a",
      "https://localhost:8787/a",
      "https://localhost/a",
      "https://user:pass@hooks.example.com/a",
      "https://intranet/a",
    ]) {
      const response = await world.send(world.hook({ url }));
      expect([url, response.status]).toEqual([url, 422]);
      expect(await response.json()).toEqual({ error: "bad_url" });
    }
  }, 600_000);

  it("refuses a domain nobody registered", async () => {
    const response = await world.send(
      world.hook({ url: "https://hooks.example.com/a", domain: "not-a-domain" }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "unknown_domain" });
  }, 600_000);

  it("refuses a kind the policy does not publish", async () => {
    const response = await world.send(
      world.hook({
        url: "https://hooks.example.com/a",
        kinds: ["verified", "sold"],
      }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "unknown_kind" });
  }, 600_000);
});

// ---------------------------------------------------------------------------
// Registering one
// ---------------------------------------------------------------------------

describe("POST /keys/me/webhooks: registering", () => {
  let world: World;

  beforeAll(async () => {
    world = await openWorld();
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("stores the endpoint and shows the secret exactly once", async () => {
    const response = await world.send(
      world.hook({
        url: MATCH_URL,
        domain: DEFAULT_DOMAIN,
        subject: SUBJECT_ONE,
      }),
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["id"]).toMatch(/^hook_[0-9a-f]{16}$/);
    expect(body["url"]).toBe(MATCH_URL);
    expect(body["filter"]).toEqual({
      domain: DEFAULT_DOMAIN,
      subject: SUBJECT_ONE,
      category: null,
      kinds: null,
    });
    expect(body["created_at"]).toBe(AT);
    expect(typeof body["secret"]).toBe("string");
    expect((body["secret"] as string).length).toBeGreaterThan(32);

    // Shown the once: the listing door never says it again.
    const listed = await world.send(world.read("/keys/me/webhooks"));
    expect(await listed.text()).not.toContain(body["secret"] as string);
  }, 600_000);

  it("takes an endpoint whose subject nothing in this log is about", async () => {
    const response = await world.send(
      world.hook({ url: OTHER_URL, subject: SUBJECT_NONE }),
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["id"]).toMatch(/^hook_[0-9a-f]{16}$/);
    expect(body["filter"]).toEqual({
      domain: null,
      subject: SUBJECT_NONE,
      category: null,
      kinds: null,
    });
  }, 600_000);

  it("takes an endpoint that asked for one kind only", async () => {
    const response = await world.send(
      world.hook({ url: KINDS_URL, kinds: ["rejected"] }),
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["id"]).toMatch(/^hook_[0-9a-f]{16}$/);
    expect(body["filter"]).toEqual({
      domain: null,
      subject: null,
      category: null,
      kinds: ["rejected"],
    });
  }, 600_000);
});

describe("GET /keys/me/webhooks", () => {
  let world: World;
  let three: Three;

  beforeAll(async () => {
    world = await openWorld();
    three = await registerThree(world);
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("lists the key's endpoints and never a secret", async () => {
    const response = await world.send(world.read("/keys/me/webhooks"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      key: string;
      endpoints: Record<string, unknown>[];
    };
    expect(body.endpoints.map((row) => row["id"]).sort()).toEqual(
      [three.match.id, three.other, three.kinds].sort(),
    );
    expect(JSON.stringify(body)).not.toContain(three.match.secret);
    for (const row of body.endpoints) {
      expect(Object.keys(row).sort()).toEqual([
        "created_at",
        "enabled",
        "filter",
        "id",
        "url",
      ]);
      // Nothing has timed out on any of them, so every one is enabled.
      expect(row["enabled"]).toBe(true);
    }
  }, 600_000);

  it("shows one key nothing of another key's", async () => {
    const response = await world.send(
      world.read("/keys/me/webhooks", world.otherSecret),
    );
    expect(response.status).toBe(200);
    expect((await response.json()) as { endpoints: unknown[] }).toEqual(
      expect.objectContaining({ endpoints: [] }),
    );
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The cap, and removing one
// ---------------------------------------------------------------------------

/**
 * The cap is per key, so every case here takes a key of its own and fills that
 * one to the line. Nothing a case does to its own key is visible to another.
 */
describe("the endpoint cap", () => {
  let world: World;

  beforeAll(async () => {
    world = await openWorld();
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  /** A key of this case's own, holding the three and then filled to the cap. */
  async function keyAtCap(): Promise<{
    key: string;
    three: Three;
    fillers: string[];
  }> {
    const key = await world.mintPaidKey();
    const three = await registerThree(world, key);
    const fillers: string[] = [];
    while (fillers.length < ALERT_ENDPOINTS_PER_KEY - 3) {
      const response = await world.send(
        world.hook(
          { url: `https://hooks.example.com/filler-${fillers.length}` },
          key,
        ),
      );
      expect(response.status).toBe(201);
      fillers.push(((await response.json()) as Record<string, string>)["id"]!);
    }
    return { key, three, fillers };
  }

  it("takes the key up to the published cap and refuses the next", async () => {
    const { key } = await keyAtCap();

    const over = await world.send(
      world.hook({ url: "https://hooks.example.com/over" }, key),
    );
    expect(over.status).toBe(409);
    expect(await over.json()).toEqual({ error: "endpoint_limit" });
  }, 600_000);

  it("frees a slot when one is removed, and removes it once", async () => {
    const { key, fillers } = await keyAtCap();

    const removed = fillers.pop()!;
    const first = await world.send(
      world.hook(null, key, "DELETE", `/keys/me/webhooks/${removed}`),
    );
    expect(first.status).toBe(204);
    expect(await first.text()).toBe("");

    const again = await world.send(
      world.hook(null, key, "DELETE", `/keys/me/webhooks/${removed}`),
    );
    expect(again.status).toBe(404);
    expect(await again.json()).toEqual({ error: "not_found" });

    const room = await world.send(
      world.hook({ url: "https://hooks.example.com/room" }, key),
    );
    expect(room.status).toBe(201);
  }, 600_000);

  it("refuses to remove an endpoint that is not this key's", async () => {
    const key = await world.mintPaidKey();
    const three = await registerThree(world, key);

    const response = await world.send(
      world.hook(
        null,
        world.otherSecret,
        "DELETE",
        `/keys/me/webhooks/${three.match.id}`,
      ),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });

    // And it is still there for the key that owns it.
    const listed = await world.send(world.read("/keys/me/webhooks", key));
    const body = (await listed.json()) as { endpoints: { id: string }[] };
    expect(body.endpoints.map((row) => row.id)).toContain(three.match.id);
  }, 600_000);

  it("clears the fillers, leaving the three it was asked to keep", async () => {
    const { key, three, fillers } = await keyAtCap();

    for (const id of fillers) {
      const response = await world.send(
        world.hook(null, key, "DELETE", `/keys/me/webhooks/${id}`),
      );
      expect([id, response.status]).toEqual([id, 204]);
    }
    const listed = await world.send(world.read("/keys/me/webhooks", key));
    const body = (await listed.json()) as { endpoints: { id: string }[] };
    expect(body.endpoints.map((row) => row.id).sort()).toEqual(
      [three.match.id, three.other, three.kinds].sort(),
    );
  }, 600_000);
});

// ---------------------------------------------------------------------------
// What a sealed change creates
// ---------------------------------------------------------------------------

/**
 * One entry, three endpoints, one sweep — and then three readings of it.
 *
 * The sweep runs in the `beforeAll` rather than in the first case, so each case
 * below reads the same finished world instead of the case above it.
 */
describe("the alert step: what it creates", () => {
  let world: World;
  let three: Three;
  let entryOne: Core;
  const sealLog: Sent[] = [];

  beforeAll(async () => {
    world = await openWorld({ operators: true });
    three = await registerThree(world);
    entryOne = await world.verify(SUBJECT_ONE);

    // The sweep seals and then runs the alert step, in that order and in one
    // run: the subscriber is told about a change in the run that sealed it.
    // The fake answers 500, so the deliveries stay pending and every case below
    // sees the row the alert step wrote rather than a delivered one.
    await world.seal(at(1), fakeFetch(500, sealLog));
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("creates one delivery per matching endpoint, and none for the others", () => {
    // The submission and the validation that verified it: two changes, one
    // endpoint. The subject filter and the kinds filter matched neither.
    expect(sealLog).toHaveLength(2);
    expect(new Set(sealLog.map((sent) => sent.url))).toEqual(new Set([MATCH_URL]));
  });

  it("names the two kinds, the sealed position and the covering seal", async () => {
    const rows = await world.deliveries(three.match.id);
    expect(rows.map((row) => row.kind).sort()).toEqual(["submitted", "verified"]);

    const head = await latestSeal(world.store.db);
    for (const row of rows) {
      expect(row.entry_id).toBe(entryOne["id"]);
      expect(row.status).toBe("pending");
      expect(row.attempts).toBe(1);
      const alert = row.body;
      expect(alert["entry_id"]).toBe(entryOne["id"]);
      expect(alert["domain"]).toBe(DEFAULT_DOMAIN);
      expect(alert["subject"]).toBe(SUBJECT_ONE);
      expect(alert["category"]).toBe("pricing");
      expect(alert["entry_hash"]).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(alert["links"]).toEqual({
        entry: `/entries/${entryOne["id"]}`,
        proof: `/events/${alert["seq"]}/proof`,
      });
      const seal = alert["seal"] as Record<string, unknown>;
      expect(seal["root"]).toBe(head?.root);
      expect(seal["sealed_at"]).toBe(head?.sealed_at);
      expect(Number(alert["seq"])).toBeLessThanOrEqual(head!.last_seq);
    }

    // The status each alert carries is the status at its own position, not now.
    const kinds = new Map(rows.map((row) => [row.kind, row.body["status"]]));
    expect(kinds.get("submitted")).toBe("draft");
    expect(kinds.get("verified")).toBe("verified");

    // And the endpoints the filters kept out have nothing at all.
    expect(await world.deliveries(three.other)).toEqual([]);
    expect(await world.deliveries(three.kinds)).toEqual([]);
  }, 600_000);

  it("creates nothing a second time: the cursor moved past those events", async () => {
    const log: Sent[] = [];
    const report = await world.step(at(2), fakeFetch(200, log));
    expect(report.created).toBe(0);
    // And nothing was due: the two retries are scheduled five minutes out.
    expect(log).toEqual([]);
    // The two the sweep created are still the only two.
    expect(await world.deliveries(three.match.id)).toHaveLength(2);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The delivery itself
// ---------------------------------------------------------------------------

/**
 * The same world again, carried one rung further: the seal's own attempt was
 * refused with a 500, and the retry five minutes later is taken.
 */
describe("the alert step: delivering", () => {
  let world: World;
  let three: Three;
  let report: StepReport;
  const log: Sent[] = [];
  const DELIVERED_AT = at(1 + (ALERT_RETRY_MINUTES[0] as number));

  beforeAll(async () => {
    world = await openWorld({ operators: true });
    three = await registerThree(world);
    await world.verify(SUBJECT_ONE);
    await world.seal(at(1), fakeFetch(500, []));

    report = await world.step(DELIVERED_AT, fakeFetch(200, log));
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("posts the signed body once the retry is due", () => {
    expect(report.delivered).toBe(2);
    expect(report.failed).toBe(0);
    expect(log).toHaveLength(2);
  });

  it("carries the four headers, and calls the platform fetch with no receiver", () => {
    expect(log).toHaveLength(2);
    for (const sent of log) {
      expect(sent.url).toBe(MATCH_URL);
      expect(sent.method).toBe("POST");
      expect(sent.headers["content-type"]).toBe("application/json");
      expect(sent.headers["x-nomankind-alert"]).toMatch(/^alert_[0-9a-f]{16}$/);
      expect(["submitted", "verified"]).toContain(
        sent.headers["x-nomankind-kind"],
      );
      expect(sent.headers["x-nomankind-signature"]).toMatch(
        /^t=\d+,v1=[0-9a-f]{64}$/,
      );
      expect(sent.receiver).toBeUndefined();
    }
  });

  it("signs the exact bytes it sent, under the endpoint's own secret", async () => {
    expect(log).toHaveLength(2);
    for (const sent of log) {
      const header = sent.headers["x-nomankind-signature"]!;
      const timestamp = Number(header.slice(2, header.indexOf(",")));
      const hex = header.slice(header.indexOf("v1=") + 3);
      expect(await signAlert(three.match.secret, timestamp, sent.body)).toBe(hex);

      // A different secret does not verify, which is the whole point of one.
      expect(await signAlert("another secret", timestamp, sent.body)).not.toBe(
        hex,
      );
      // And the body is the alert body, not a summary of it.
      const parsed = JSON.parse(sent.body) as Record<string, unknown>;
      expect(parsed["id"]).toBe(sent.headers["x-nomankind-alert"]);
      expect(parsed["kind"]).toBe(sent.headers["x-nomankind-kind"]);
    }
  }, 600_000);

  it("records the delivery, and never the secret", async () => {
    const response = await world.send(
      world.read(`/keys/me/webhooks/${three.match.id}/deliveries`),
    );
    const text = await response.text();
    expect(text).not.toContain(three.match.secret);
    const body = JSON.parse(text) as {
      deliveries: { status: string; delivered_at: string; last_status: number }[];
    };
    expect(body.deliveries).toHaveLength(2);
    for (const row of body.deliveries) {
      expect(row.status).toBe("delivered");
      expect(row.last_status).toBe(200);
      expect(row.delivered_at).toBe(DELIVERED_AT.toISOString());
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// A subscriber that is down
// ---------------------------------------------------------------------------

/** What one rung of the ladder looked like from outside. */
interface Rung {
  attempt: number;
  clock: number;
  retried: number;
  attempts: number;
  next_at: string;
}

/**
 * The whole ladder is walked in the `beforeAll` and each rung recorded, so that
 * "gives up at the end" and "stops trying afterwards" are readings of one walk
 * rather than two cases that have to run in order.
 */
describe("the retry ladder", () => {
  const FAIL_URL = "https://hooks.example.com/down";
  let world: World;
  let failHook = "";
  const sealLog: Sent[] = [];
  let firstRow: DeliveryRow;
  const rungs: Rung[] = [];
  let gaveUp: StepReport;
  let failedRow: DeliveryRow;
  const quietLog: Sent[] = [];

  beforeAll(async () => {
    world = await openWorld({ operators: true });
    // The three whose filters miss this subject or this kind, beside the one
    // that asked for exactly it.
    await registerThree(world);
    const failing = await world.register({
      url: FAIL_URL,
      kinds: ["submitted"],
      subject: SUBJECT_TWO,
    });
    failHook = failing.id;

    await world.submit(SUBJECT_TWO);
    await world.seal(at(20), fakeFetch(500, sealLog));
    firstRow = await world.onlyDelivery(failHook);

    let clock = 20;
    for (let attempt = 2; attempt <= ALERT_RETRY_MINUTES.length; attempt += 1) {
      clock += ALERT_RETRY_MINUTES[attempt - 2] as number;
      const report = await world.step(at(clock), fakeFetch(503, []));
      const row = await world.onlyDelivery(failHook);
      rungs.push({
        attempt,
        clock,
        retried: report.retried,
        attempts: row.attempts,
        next_at: row.next_at,
      });
    }

    // Past the last rung there is nowhere to schedule, so the delivery is
    // failed rather than retried forever.
    clock += ALERT_RETRY_MINUTES[ALERT_RETRY_MINUTES.length - 1] as number;
    gaveUp = await world.step(at(clock), throwingFetch([]));
    failedRow = await world.onlyDelivery(failHook);

    // And long afterwards, nothing is attempted at all.
    await world.step(at(10_000), fakeFetch(200, quietLog));
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("schedules the first retry five minutes out, with one attempt", () => {
    // One endpoint matched: the other three filter this subject or this kind
    // away, so the submission of the second entry reached exactly this one.
    expect(sealLog.map((sent) => sent.url)).toEqual([FAIL_URL]);

    expect(firstRow.attempts).toBe(1);
    expect(firstRow.status).toBe("pending");
    expect(firstRow.last_status).toBe(500);
    expect(firstRow.next_at).toBe(
      at(20 + (ALERT_RETRY_MINUTES[0] as number)).toISOString(),
    );
  });

  it("walks the published ladder and then gives up", () => {
    expect(rungs).toHaveLength(ALERT_RETRY_MINUTES.length - 1);
    for (const rung of rungs) {
      expect([rung.attempt, rung.retried]).toEqual([rung.attempt, 1]);
      expect([rung.attempt, rung.attempts]).toEqual([rung.attempt, rung.attempt]);
      expect([rung.attempt, rung.next_at]).toEqual([
        rung.attempt,
        at(
          rung.clock + (ALERT_RETRY_MINUTES[rung.attempt - 1] as number),
        ).toISOString(),
      ]);
    }

    expect(gaveUp.failed).toBe(1);
    expect(gaveUp.retried).toBe(0);

    expect(failedRow.status).toBe("failed");
    expect(failedRow.attempts).toBe(ALERT_RETRY_MINUTES.length + 1);
    // A throw records the error's name and nothing else: a message can carry
    // the subscriber's own URL.
    expect(failedRow.last_error).toBe("TimeoutError");
    expect(failedRow.last_status).toBeNull();
  });

  it("stops trying once it has given up", async () => {
    expect(quietLog).toEqual([]);
    // Still the one delivery, still failed: nothing reopened it.
    const row = await world.onlyDelivery(failHook);
    expect(row.status).toBe("failed");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The window that closed
// ---------------------------------------------------------------------------

/**
 * The seventh kind, and the only one no event carries.
 *
 * Whitepaper Section 7: "Past its window an entry stays verified but shows as
 * stale." Nobody appends anything when that happens, so the sweep's staleness
 * step marks the row and the alert step tells whoever subscribed — in the same
 * run, which is what these cases hold it to. The clock is the injected one
 * throughout: the first run is inside the entry's window, the second is past
 * it, the third is the same day again, and the fourth is the same day with the
 * cursor moved back behind it. All four runs happen in the `beforeAll` and each
 * case reads what one of them produced.
 */
describe("stale alerts", () => {
  const STALE_URL = "https://hooks.example.com/stale";
  let world: World;
  let three: Three;
  let staleHook = "";
  let entryOne: Core;

  let registered: { status: number; body: Record<string, unknown> };
  let insideWindow: { stale: DeliveryRow[]; match: DeliveryRow[] };
  let closedLog: Sent[] = [];
  let closed: {
    stale: DeliveryRow[];
    match: DeliveryRow[];
    other: DeliveryRow[];
    kinds: DeliveryRow[];
  };
  let again: {
    report: StepReport;
    log: Sent[];
    stale: DeliveryRow[];
    match: DeliveryRow[];
  };
  let rewound: { stale: DeliveryRow[]; match: DeliveryRow[] };

  /** The deliveries of one endpoint that carry one kind. */
  async function ofKind(endpointId: string, kind: string): Promise<DeliveryRow[]> {
    const rows = await world.deliveries(endpointId);
    return rows.filter((row) => row.kind === kind);
  }

  beforeAll(async () => {
    world = await openWorld({ operators: true });
    three = await registerThree(world);
    entryOne = await world.verify(SUBJECT_ONE);
    // The entry's own alerts, taken on the first attempt, so that nothing is
    // owed a retry when the runs below post: whatever the fake sees afterwards
    // is the staleness pass and nothing else.
    await world.seal(at(1), fakeFetch(200, []));

    const response = await world.send(
      world.hook({ url: STALE_URL, kinds: ["stale"], subject: SUBJECT_ONE }),
    );
    const body = (await response.json()) as Record<string, unknown>;
    registered = { status: response.status, body };
    staleHook = body["id"] as string;

    // Thirty days in: the pricing window is ninety, so nothing has run out and
    // the pass has nothing to say however many endpoints are listening.
    await world.seal(at(DAY_MINUTES * 30), fakeFetch(200, []));
    insideWindow = {
      stale: await ofKind(staleHook, "stale"),
      match: await ofKind(three.match.id, "stale"),
    };

    closedLog = [];
    await world.seal(at(DAY_MINUTES * 95), fakeFetch(200, closedLog));
    closed = {
      stale: await ofKind(staleHook, "stale"),
      match: await ofKind(three.match.id, "stale"),
      other: await ofKind(three.other, "stale"),
      kinds: await ofKind(three.kinds, "stale"),
    };

    const againLog: Sent[] = [];
    const againReport = await world.step(
      at(DAY_MINUTES * 95 + 1),
      fakeFetch(200, againLog),
    );
    again = {
      report: againReport,
      log: againLog,
      stale: await ofKind(staleHook, "stale"),
      match: await ofKind(three.match.id, "stale"),
    };

    // The run above is stopped by the cursor alone, so it says nothing about
    // the dedupe underneath. This one moves the cursor back to the day before
    // the window closed, which puts the same row in front of the pass again,
    // and only the derived id and the store's INSERT OR IGNORE keep the second
    // pass from writing a second delivery for the same entry and endpoint.
    const stored = await getEntry(world.store.db, entryOne["id"] as string);
    const expiresAt = String(
      (stored!.entry as unknown as Record<string, unknown>)["expires_at"],
    );
    const dayBefore =
      Math.floor(
        Date.parse(`${expiresAt.slice(0, 10)}T00:00:00.000Z`) / 86_400_000,
      ) - 1;
    await setStaleAlertCursor(world.store.db, dayBefore);
    await world.step(at(DAY_MINUTES * 95 + 2), fakeFetch(200, []));
    rewound = {
      stale: await ofKind(staleHook, "stale"),
      match: await ofKind(three.match.id, "stale"),
    };
  }, 600_000);

  afterAll(async () => {
    await world?.dispose();
  }, 600_000);

  it("registers an endpoint that asked for the stale kind only", () => {
    expect(registered.status).toBe(201);
    expect(registered.body["id"]).toMatch(/^hook_[0-9a-f]{16}$/);
    expect(registered.body["url"]).toBe(STALE_URL);
    expect(registered.body["filter"]).toEqual({
      domain: null,
      subject: SUBJECT_ONE,
      category: null,
      kinds: ["stale"],
    });
  });

  it("creates nothing while the entry is still inside its window", () => {
    expect(insideWindow.stale).toEqual([]);
    expect(insideWindow.match).toEqual([]);
  });

  it("creates one delivery per matching endpoint once the window has closed", () => {
    // Two endpoints match this entry's stale alert: the one that asked for the
    // kind, and the one that asked about this subject whatever happens to it.
    // The other two filter it away by subject and by kind.
    expect(closedLog.map((sent) => sent.url).sort()).toEqual(
      [MATCH_URL, STALE_URL].sort(),
    );
    expect(closed.stale).toHaveLength(1);
    expect(closed.match).toHaveLength(1);
    expect(closed.other).toEqual([]);
    expect(closed.kinds).toEqual([]);
  });

  it("carries the kind, the day the window ran out, and the entry's own position", async () => {
    const entryId = entryOne["id"] as string;
    const stored = await getEntry(world.store.db, entryId);
    const expiresAt = (stored!.entry as unknown as Record<string, unknown>)[
      "expires_at"
    ];

    const [delivery] = closed.stale;
    expect(delivery!.entry_id).toBe(entryId);
    const alert = delivery!.body;
    expect(alert["kind"]).toBe("stale");
    // `at` is the day the window ran out and not the instant of the run: the
    // moment being reported is a date on the calendar.
    expect(alert["at"]).toBe(expiresAt);
    // No event carries this, so the position is the entry's own submission, and
    // the proof link and the seal are about that position.
    expect(alert["seq"]).toBe(stored!.submittedSeq);
    expect(alert["links"]).toEqual({
      entry: `/entries/${entryId}`,
      proof: `/events/${stored!.submittedSeq}/proof`,
    });
    expect((alert["seal"] as Record<string, unknown>)["root"]).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    // The entry is still verified: staleness is a fact beside the status and
    // never a status of its own.
    expect(alert["status"]).toBe("verified");
    expect(alert["id"]).toMatch(/^alert_[0-9a-f]{16}$/);
  }, 600_000);

  it("creates nothing on a second run of the same day", () => {
    expect(again.report.created).toBe(0);
    expect(again.log).toEqual([]);
    expect(again.stale).toHaveLength(1);
    expect(again.match).toHaveLength(1);
  });

  it("creates nothing twice when the day cursor is moved back", async () => {
    const entryId = entryOne["id"] as string;
    const stored = await getEntry(world.store.db, entryId);
    const expiresAt = String(
      (stored!.entry as unknown as Record<string, unknown>)["expires_at"],
    );

    // One delivery each, still, and it is the one the first run made: the id is
    // the entry, the day its window ran out and the endpoint, and nothing else.
    for (const [endpointId, deliveries] of [
      [staleHook, rewound.stale] as const,
      [three.match.id, rewound.match] as const,
    ]) {
      expect(deliveries).toHaveLength(1);
      expect(deliveries[0]!.body["id"]).toBe(
        await staleDeliveryId(entryId, expiresAt, endpointId),
      );
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// A deployment nobody subscribed to
// ---------------------------------------------------------------------------

describe("a log with no endpoint", () => {
  it("skips, and jumps the cursor to the sealed head", async () => {
    const empty = await openTestDatabase();
    try {
      const reasons: string[] = [];
      const report = await runAlertStep(
        empty.db,
        { now: NOW, sealedHead: 41, fetch: fakeFetch(200, []), origin: "" },
        (reason) => reasons.push(reason),
      );
      expect(reasons).toEqual(["alerts_no_endpoint"]);
      expect(report).toEqual({
        created: 0,
        delivered: 0,
        failed: 0,
        retried: 0,
      });

      expect(await alertCursor(empty.db)).toBe(41);
    } finally {
      await empty.dispose();
    }
  }, 600_000);
});

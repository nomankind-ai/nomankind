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
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { signAlert } from "../src/alerts.js";
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
import { alertCursor } from "../src/storage/alerts.js";
import { putKey } from "../src/storage/keys.js";
import { latestSeal } from "../src/storage/repository.js";
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

let PRICING_HASH = "";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let alice: TestAgent;
let parties: Party[];

/** The paid key every door below is opened with, and a second one beside it. */
let secret = "";
let otherSecret = "";

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);
  store = await openTestDatabase();
  const maintainer = await makeAgent();
  alice = await makeAgent();

  parties = [];
  for (const operator of OPERATORS) {
    parties.push({ operator, agent: await makeAgent() });
  }

  const records: Record<string, string[]> = {};
  for (const party of parties) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  deps = {
    now: NOW,
    fetcher: new FixtureFetcher({ [PRICING_URL]: PRICING }),
    dns: new FixtureResolver(records),
  };

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

  secret = await mintPaidKey("cus_alerts_1", "sub_alerts_1", "cs_alerts_1");
  otherSecret = await mintPaidKey("cus_alerts_2", "sub_alerts_2", "cs_alerts_2");
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function send(request: Request): Promise<Response> {
  return handleRequest(request, env, deps);
}

/**
 * A paid key, minted and stored the way the claim door stores one.
 *
 * The checkout itself is test/m24-keys-end-to-end.test.ts's subject; what these
 * doors need is a key that exists and is active.
 */
async function mintPaidKey(
  customer: string,
  subscription: string,
  checkoutSession: string,
): Promise<string> {
  const minted = mintKey();
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer,
    subscription,
    checkoutSession,
    createdAt: AT,
  });
  return minted.secret;
}

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
    snapshot_hash: PRICING_HASH,
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
    snapshot_hash: PRICING_HASH,
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

/**
 * Seal whatever the log holds, through the sweep that really seals it.
 *
 * The alert step runs inside that same sweep, right after the seal, which is
 * the point of it: an endpoint hears about a sealed change in the run that
 * sealed it. `alertFetch` is the sweep's own injection point, so nothing leaves
 * this process — a sweep called without it would post to the real hosts the
 * fixtures name.
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

const skipped: string[] = [];

/** One run of the alert step, at an instant, against one fake fetch. */
async function step(
  when: Date,
  fetchImpl: typeof fetch,
): Promise<{ created: number; delivered: number; failed: number; retried: number }> {
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

// ---------------------------------------------------------------------------
// Who may subscribe at all
// ---------------------------------------------------------------------------

describe("POST /keys/me/webhooks: the key", () => {
  it("refuses a request with no key at all", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/keys/me/webhooks`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: "https://hooks.example.com/a" }),
      }),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "missing_key" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("refuses a header that is not a key this system minted", async () => {
    const response = await send(
      hook({ url: "https://hooks.example.com/a" }, "not-a-key"),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "bad_key" });
  });

  it("refuses a well-formed key nobody holds", async () => {
    const response = await send(
      hook({ url: "https://hooks.example.com/a" }, mintKey().secret),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unknown_key" });
  });
});

// ---------------------------------------------------------------------------
// What may be subscribed
// ---------------------------------------------------------------------------

describe("POST /keys/me/webhooks: the body", () => {
  it("refuses a body that is not an object with a url", async () => {
    for (const body of ["not json", "[]", "{}", '{"url":7}']) {
      const response = await send(hook(body));
      expect([body, response.status]).toEqual([body, 400]);
      expect(await response.json()).toEqual({ error: "bad_body" });
    }
  });

  it("refuses http, and refuses a local address", async () => {
    for (const url of [
      "http://hooks.example.com/a",
      "https://localhost:8787/a",
      "https://localhost/a",
      "https://user:pass@hooks.example.com/a",
      "https://intranet/a",
    ]) {
      const response = await send(hook({ url }));
      expect([url, response.status]).toEqual([url, 422]);
      expect(await response.json()).toEqual({ error: "bad_url" });
    }
  });

  it("refuses a domain nobody registered", async () => {
    const response = await send(
      hook({ url: "https://hooks.example.com/a", domain: "not-a-domain" }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "unknown_domain" });
  });

  it("refuses a kind the policy does not publish", async () => {
    const response = await send(
      hook({ url: "https://hooks.example.com/a", kinds: ["verified", "sold"] }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "unknown_kind" });
  });
});

// ---------------------------------------------------------------------------
// The three endpoints the rest of the file is about
// ---------------------------------------------------------------------------

const MATCH_URL = "https://hooks.example.com/match";
const OTHER_URL = "https://hooks.example.com/other";
const KINDS_URL = "https://hooks.example.com/kinds";

let matchHook = { id: "", secret: "" };
let otherHook = "";
let kindsHook = "";

describe("POST /keys/me/webhooks: registering", () => {
  it("stores the endpoint and shows the secret exactly once", async () => {
    const response = await send(
      hook({ url: MATCH_URL, domain: DEFAULT_DOMAIN, subject: SUBJECT_ONE }),
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
    matchHook = { id: body["id"] as string, secret: body["secret"] as string };
  });

  it("takes an endpoint whose subject nothing in this log is about", async () => {
    const response = await send(hook({ url: OTHER_URL, subject: SUBJECT_NONE }));
    expect(response.status).toBe(201);
    otherHook = ((await response.json()) as Record<string, string>)["id"]!;
  });

  it("takes an endpoint that asked for one kind only", async () => {
    const response = await send(hook({ url: KINDS_URL, kinds: ["rejected"] }));
    expect(response.status).toBe(201);
    kindsHook = ((await response.json()) as Record<string, string>)["id"]!;
  });
});

describe("GET /keys/me/webhooks", () => {
  it("lists the key's endpoints and never a secret", async () => {
    const response = await send(read("/keys/me/webhooks"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      key: string;
      endpoints: Record<string, unknown>[];
    };
    expect(body.endpoints.map((row) => row["id"]).sort()).toEqual(
      [matchHook.id, otherHook, kindsHook].sort(),
    );
    expect(JSON.stringify(body)).not.toContain(matchHook.secret);
    for (const row of body.endpoints) {
      expect(Object.keys(row).sort()).toEqual([
        "created_at",
        "filter",
        "id",
        "url",
      ]);
    }
  });

  it("shows one key nothing of another key's", async () => {
    const response = await send(read("/keys/me/webhooks", otherSecret));
    expect(response.status).toBe(200);
    expect((await response.json()) as { endpoints: unknown[] }).toEqual(
      expect.objectContaining({ endpoints: [] }),
    );
  });
});

// ---------------------------------------------------------------------------
// The cap, and removing one
// ---------------------------------------------------------------------------

describe("the endpoint cap", () => {
  const fillers: string[] = [];

  it("takes the key up to the published cap and refuses the next", async () => {
    while (fillers.length < ALERT_ENDPOINTS_PER_KEY - 3) {
      const response = await send(
        hook({ url: `https://hooks.example.com/filler-${fillers.length}` }),
      );
      expect(response.status).toBe(201);
      fillers.push(((await response.json()) as Record<string, string>)["id"]!);
    }

    const over = await send(hook({ url: "https://hooks.example.com/over" }));
    expect(over.status).toBe(409);
    expect(await over.json()).toEqual({ error: "endpoint_limit" });
  });

  it("frees a slot when one is removed, and removes it once", async () => {
    const removed = fillers.pop()!;
    const first = await send(hook(null, secret, "DELETE", `/keys/me/webhooks/${removed}`));
    expect(first.status).toBe(204);
    expect(await first.text()).toBe("");

    const again = await send(hook(null, secret, "DELETE", `/keys/me/webhooks/${removed}`));
    expect(again.status).toBe(404);
    expect(await again.json()).toEqual({ error: "not_found" });

    const room = await send(hook({ url: "https://hooks.example.com/room" }));
    expect(room.status).toBe(201);
    fillers.push(((await room.json()) as Record<string, string>)["id"]!);
  });

  it("refuses to remove an endpoint that is not this key's", async () => {
    const response = await send(
      hook(null, otherSecret, "DELETE", `/keys/me/webhooks/${matchHook.id}`),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });

    // And it is still there for the key that owns it.
    const listed = await send(read("/keys/me/webhooks"));
    const body = (await listed.json()) as { endpoints: { id: string }[] };
    expect(body.endpoints.map((row) => row.id)).toContain(matchHook.id);
  });

  it("clears the fillers, leaving the three the rest of the file uses", async () => {
    for (const id of fillers) {
      const response = await send(
        hook(null, secret, "DELETE", `/keys/me/webhooks/${id}`),
      );
      expect([id, response.status]).toEqual([id, 204]);
    }
    const listed = await send(read("/keys/me/webhooks"));
    const body = (await listed.json()) as { endpoints: { id: string }[] };
    expect(body.endpoints.map((row) => row.id).sort()).toEqual(
      [matchHook.id, otherHook, kindsHook].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// What a sealed change creates
// ---------------------------------------------------------------------------

let entryOne: Core;

describe("the alert step: what it creates", () => {
  it("creates one delivery per matching endpoint, and none for the others", async () => {
    entryOne = await submit(SUBJECT_ONE);
    await decide(entryOne["id"] as string, parties[0]!);
    await decide(entryOne["id"] as string, parties[1]!);

    // The sweep seals and then runs the alert step, in that order and in one
    // run: the subscriber is told about a change in the run that sealed it.
    const log: Sent[] = [];
    await seal(at(1), fakeFetch(500, log));

    // The submission and the validation that verified it: two changes, one
    // endpoint. The subject filter and the kinds filter matched neither.
    expect(log).toHaveLength(2);
    expect(new Set(log.map((sent) => sent.url))).toEqual(new Set([MATCH_URL]));
  });

  it("names the two kinds, the sealed position and the covering seal", async () => {
    const response = await send(
      read(`/keys/me/webhooks/${matchHook.id}/deliveries`),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      deliveries: {
        kind: string;
        entry_id: string;
        status: string;
        attempts: number;
        body: Record<string, unknown>;
      }[];
    };
    expect(body.deliveries.map((row) => row.kind).sort()).toEqual([
      "submitted",
      "verified",
    ]);

    const head = await latestSeal(store.db);
    for (const row of body.deliveries) {
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
    const kinds = new Map(
      body.deliveries.map((row) => [row.kind, row.body["status"]]),
    );
    expect(kinds.get("submitted")).toBe("draft");
    expect(kinds.get("verified")).toBe("verified");
  });

  it("creates nothing a second time: the cursor moved past those events", async () => {
    const log: Sent[] = [];
    const report = await step(at(2), fakeFetch(200, log));
    expect(report.created).toBe(0);
    // And nothing was due: the two retries are scheduled five minutes out.
    expect(log).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The delivery itself
// ---------------------------------------------------------------------------

describe("the alert step: delivering", () => {
  const log: Sent[] = [];

  it("posts the signed body once the retry is due", async () => {
    const when = at(1 + (ALERT_RETRY_MINUTES[0] as number));
    const report = await step(when, fakeFetch(200, log));
    expect(report.delivered).toBe(2);
    expect(report.failed).toBe(0);
    expect(log).toHaveLength(2);
  });

  it("carries the four headers, and calls the platform fetch with no receiver", () => {
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
    for (const sent of log) {
      const header = sent.headers["x-nomankind-signature"]!;
      const timestamp = Number(header.slice(2, header.indexOf(",")));
      const hex = header.slice(header.indexOf("v1=") + 3);
      expect(await signAlert(matchHook.secret, timestamp, sent.body)).toBe(hex);

      // A different secret does not verify, which is the whole point of one.
      expect(await signAlert("another secret", timestamp, sent.body)).not.toBe(
        hex,
      );
      // And the body is the alert body, not a summary of it.
      const parsed = JSON.parse(sent.body) as Record<string, unknown>;
      expect(parsed["id"]).toBe(sent.headers["x-nomankind-alert"]);
      expect(parsed["kind"]).toBe(sent.headers["x-nomankind-kind"]);
    }
  });

  it("records the delivery, and never the secret", async () => {
    const response = await send(
      read(`/keys/me/webhooks/${matchHook.id}/deliveries`),
    );
    const text = await response.text();
    expect(text).not.toContain(matchHook.secret);
    const body = JSON.parse(text) as {
      deliveries: { status: string; delivered_at: string; last_status: number }[];
    };
    for (const row of body.deliveries) {
      expect(row.status).toBe("delivered");
      expect(row.last_status).toBe(200);
      expect(row.delivered_at).toBe(
        at(1 + (ALERT_RETRY_MINUTES[0] as number)).toISOString(),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// A subscriber that is down
// ---------------------------------------------------------------------------

describe("the retry ladder", () => {
  const FAIL_URL = "https://hooks.example.com/down";
  let failHook = "";

  it("schedules the first retry five minutes out, with one attempt", async () => {
    const created = await send(
      hook({ url: FAIL_URL, kinds: ["submitted"], subject: SUBJECT_TWO }),
    );
    expect(created.status).toBe(201);
    failHook = ((await created.json()) as Record<string, string>)["id"]!;

    await submit(SUBJECT_TWO);
    const log: Sent[] = [];
    await seal(at(20), fakeFetch(500, log));

    // One endpoint matched: the other three filter this subject or this kind
    // away, so the submission of the second entry reached exactly this one.
    expect(log.map((sent) => sent.url)).toEqual([FAIL_URL]);

    const row = await onlyDelivery(failHook);
    expect(row.attempts).toBe(1);
    expect(row.status).toBe("pending");
    expect(row.last_status).toBe(500);
    expect(row.next_at).toBe(
      at(20 + (ALERT_RETRY_MINUTES[0] as number)).toISOString(),
    );
  });

  it("walks the published ladder and then gives up", async () => {
    let clock = 20;
    for (let attempt = 2; attempt <= ALERT_RETRY_MINUTES.length; attempt += 1) {
      clock += ALERT_RETRY_MINUTES[attempt - 2] as number;
      const report = await step(at(clock), fakeFetch(503, []));
      expect([attempt, report.retried]).toEqual([attempt, 1]);
      const row = await onlyDelivery(failHook);
      expect([attempt, row.attempts]).toEqual([attempt, attempt]);
      expect([attempt, row.next_at]).toEqual([
        attempt,
        at(clock + (ALERT_RETRY_MINUTES[attempt - 1] as number)).toISOString(),
      ]);
    }

    // Past the last rung there is nowhere to schedule, so the delivery is
    // failed rather than retried forever.
    clock += ALERT_RETRY_MINUTES[ALERT_RETRY_MINUTES.length - 1] as number;
    const report = await step(at(clock), throwingFetch([]));
    expect(report.failed).toBe(1);
    expect(report.retried).toBe(0);

    const row = await onlyDelivery(failHook);
    expect(row.status).toBe("failed");
    expect(row.attempts).toBe(ALERT_RETRY_MINUTES.length + 1);
    // A throw records the error's name and nothing else: a message can carry
    // the subscriber's own URL.
    expect(row.last_error).toBe("TimeoutError");
    expect(row.last_status).toBeNull();
  });

  it("stops trying once it has given up", async () => {
    const log: Sent[] = [];
    await step(at(10_000), fakeFetch(200, log));
    expect(log).toEqual([]);
  });
});

/** The one delivery an endpoint has, as its own door reports it. */
async function onlyDelivery(endpointId: string): Promise<{
  status: string;
  attempts: number;
  next_at: string;
  last_status: number | null;
  last_error: string | null;
}> {
  const response = await send(read(`/keys/me/webhooks/${endpointId}/deliveries`));
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    deliveries: {
      status: string;
      attempts: number;
      next_at: string;
      last_status: number | null;
      last_error: string | null;
    }[];
  };
  expect(body.deliveries).toHaveLength(1);
  return body.deliveries[0]!;
}

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
  }, 120_000);
});

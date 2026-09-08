/**
 * M12 end to end: joining, from the outside, through the Worker.
 *
 * Whitepaper Section 11's three joining steps, walked by a real key against a
 * real migrated database: publish a DNS TXT record carrying your 1F916 agent
 * id, complete payout onboarding, sign the provider-independence attestation,
 * and the binding is sealed into the log. Then the genesis naming, which only
 * the maintainer may do and never over its own operator.
 *
 * Everything is real except the network. The requests are signed with generated
 * Ed25519 keys and verified by the Worker, the database is miniflare's D1 with
 * the migrations applied, the nonce store is that database, and the events are
 * the events. Only the resolver and the payment provider are injected, because
 * only they are not ours to run in a test, and the clock is injected because
 * nothing under src/ is allowed to read one.
 *
 * Every refusal below asserts the log's head is exactly where it was. That is
 * the property that matters most in this milestone: a door that refuses must
 * leave no trace in the record, or a rejected registration would be a
 * registration.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  MockPayoutAdapter,
  UnavailablePayoutAdapter,
} from "../src/adapters/payout.js";
import { LIST_PAGE_LIMIT } from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { eventBySeq, headSeq } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";

/** The instant every request in this file is served at. No wall clock anywhere. */
const NOW = new Date("2026-09-07T12:00:00.000Z");
const AT = NOW.toISOString();

/** A reference the mock payment provider calls onboarded, and one it does not. */
const VERIFIED_REFERENCE = "mock-verified-m12";
const PENDING_REFERENCE = "mock-pending-m12";

/** The operator the outside agent joins as, and the maintainer's own. */
const OUTSIDE = "example.org";
const MAINTAINER_OPERATOR = "maintainer.example";

let store: TestDatabase;
let maintainer: TestAgent;
let alice: TestAgent;
let bob: TestAgent;
let env: Env;
let deps: RequestDeps;

/** The log's head, or null when nothing has been written. */
function head(): Promise<number | null> {
  return headSeq(store.db);
}

/** One signed registration request. */
async function registration(
  agent: TestAgent,
  operator: string,
  options: {
    attestedOperator?: string;
    attestation?: unknown;
    reference?: string;
    timestamp?: string;
    nonce?: string;
  } = {},
): Promise<Request> {
  const attestation =
    options.attestation ??
    (await attestFor(agent, options.attestedOperator ?? operator, AT));
  return signedPost(agent, {
    path: "/operators",
    body: {
      operator,
      attestation,
      payout: { reference: options.reference ?? VERIFIED_REFERENCE },
    },
    timestamp: options.timestamp ?? AT,
    nonce: options.nonce,
  });
}

/** One signed genesis naming. */
function naming(agent: TestAgent, operator: string): Promise<Request> {
  return signedPost(agent, {
    path: "/genesis",
    body: { operator },
    timestamp: AT,
  });
}

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

/** Send a request and assert it changed nothing in the log. */
async function refused(
  request: Request,
  status: number,
  error: string,
  override?: Partial<RequestDeps>,
): Promise<void> {
  const before = await head();
  const response = await handleRequest(request, env, { ...deps, ...override });
  expect([response.status, await response.json()]).toEqual([
    status,
    { error },
  ]);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(await head()).toBe(before);
}

beforeAll(async () => {
  store = await openTestDatabase();
  maintainer = await makeAgent();
  alice = await makeAgent();
  bob = await makeAgent();

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver({
      [txtRecordName(OUTSIDE)]: [alice.agentId],
      [txtRecordName(MAINTAINER_OPERATOR)]: [maintainer.agentId],
      [txtRecordName("second.example")]: [alice.agentId],
      [txtRecordName("pending.example")]: [alice.agentId],
      // A domain whose record names somebody else's key.
      [txtRecordName("mismatch.example")]: ["1F916:not-this-agent"],
      // A resolver that could not answer, which is our outage and not theirs.
      [txtRecordName("unavailable.example")]: null,
    }),
    payout: new MockPayoutAdapter(),
  };
}, 60_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the door refuses before it writes", () => {
  it("still answers GET /health", async () => {
    const response = await handleRequest(get("/health"), env, deps);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      environment: "local",
      storage: "ok",
    });
  });

  it("refuses a model provider's own domain (Section 10)", async () => {
    await refused(await registration(alice, "openai.com"), 403, "provider_operator");
  });

  it("refuses a subdomain of one, which is no cheaper a door", async () => {
    await refused(
      await registration(alice, "api.openai.com"),
      403,
      "provider_operator",
    );
  });

  it("refuses a body with no attestation at all, by name", async () => {
    // Section 10's attestation is missing rather than malformed, and the door
    // says so: the refusal REGISTRATION_REFUSALS names is the one it gives.
    await refused(
      await signedPost(alice, {
        path: "/operators",
        body: { operator: OUTSIDE, payout: { reference: VERIFIED_REFERENCE } },
        timestamp: AT,
      }),
      422,
      "missing_attestation",
    );
  });

  it("refuses an attestation with nothing in it", async () => {
    await refused(
      await registration(alice, OUTSIDE, { attestation: {} }),
      422,
      "bad_attestation",
    );
  });

  it("refuses an attestation signed for another operator", async () => {
    await refused(
      await registration(alice, OUTSIDE, { attestedOperator: "elsewhere.example" }),
      422,
      "bad_attestation",
    );
  });

  it("refuses a TXT record naming somebody else", async () => {
    await refused(
      await registration(alice, "mismatch.example", { nonce: "m12-replayed" }),
      422,
      "dns_mismatch",
    );
  });

  it("refuses the very same signed request a second time", async () => {
    // The nonce was spent by the request above, even though that one was
    // refused: a capture is worth nothing however the original ended.
    await refused(
      await registration(alice, "mismatch.example", { nonce: "m12-replayed" }),
      401,
      "replay",
    );
  });

  it("refuses a domain with no record", async () => {
    await refused(
      await registration(alice, "norecord.example"),
      422,
      "dns_no_record",
    );
  });

  it("answers 503 when the resolver cannot say", async () => {
    await refused(
      await registration(alice, "unavailable.example"),
      503,
      "dns_unavailable",
    );
  });

  it("refuses payout onboarding that has not cleared", async () => {
    await refused(
      await registration(alice, "pending.example", {
        reference: PENDING_REFERENCE,
      }),
      422,
      "payout_not_verified",
    );
  });

  it("answers 503 where no payment provider is wired (production, D-013)", async () => {
    await refused(
      await registration(alice, "pending.example"),
      503,
      "payout_unavailable",
      { payout: new UnavailablePayoutAdapter() },
    );
  });

  it("refuses a signature made too long ago", async () => {
    await refused(
      await registration(alice, OUTSIDE, {
        timestamp: new Date("2026-09-06T12:00:00.000Z").toISOString(),
      }),
      401,
      "clock_skew",
    );
  });
});

describe("joining", () => {
  it("registers an outside operator and seals the binding into the log", async () => {
    expect(await head()).toBeNull();

    const response = await handleRequest(
      await registration(alice, OUTSIDE),
      env,
      deps,
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.id).toBe(OUTSIDE);
    expect(body.maintainer).toBe(false);
    expect(body.provider).toBe(false);
    expect(body.agents).toEqual([alice.agentId]);
    expect(body.details).toMatchObject({
      registered_by: alice.agentId,
      trusted: false,
      trusted_seq: null,
      payout_status: "verified",
    });

    const bound = await eventBySeq(store.db, (await head()) as number);
    const registered = await eventBySeq(store.db, ((await head()) as number) - 1);
    expect(registered?.type).toBe("operator_registered");
    expect(registered?.payload).toEqual({ operator: OUTSIDE, maintainer: false });
    expect(bound?.type).toBe("agent_bound");
    expect(bound?.prev_hash).toBe(registered?.hash);
    expect((bound?.payload as { agent: string }).agent).toBe(alice.agentId);
    expect(body.registeredSeq).toBe(registered?.seq);
    expect(registered?.at).toBe(AT);
  });

  it("answers GET /agents/{id} with the operator behind the key", async () => {
    const response = await handleRequest(get(`/agents/${alice.agentId}`), env, deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      agent: string;
      operator: { id: string };
    };
    expect(body.agent).toBe(alice.agentId);
    expect(body.operator.id).toBe(OUTSIDE);
  });

  it("answers GET /operators/{id} with the agents under it", async () => {
    const response = await handleRequest(get(`/operators/${OUTSIDE}`), env, deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.id).toBe(OUTSIDE);
    expect(body.agents).toEqual([alice.agentId]);
  });

  it("answers 404 for an agent nobody registered", async () => {
    const response = await handleRequest(
      get(`/agents/${bob.agentId}`),
      env,
      deps,
    );

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
  });

  it("refuses a second domain for an agent already bound", async () => {
    await refused(
      await registration(alice, "second.example"),
      409,
      "agent_bound",
    );
  });

  it("refuses a second agent registering a domain already taken", async () => {
    await refused(await registration(bob, OUTSIDE), 409, "operator_exists");
  });

  it("marks the maintainer's own registration as the maintainer's", async () => {
    const response = await handleRequest(
      await registration(maintainer, MAINTAINER_OPERATOR),
      env,
      deps,
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.id).toBe(MAINTAINER_OPERATOR);
    // Nothing in the request said so: the flag is the configured key and
    // nothing else.
    expect(body.maintainer).toBe(true);
  });
});

describe("genesis naming", () => {
  it("names the outside operator to the trusted pool", async () => {
    const before = (await head()) as number;
    const response = await handleRequest(await naming(maintainer, OUTSIDE), env, deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      id: string;
      details: Record<string, unknown>;
    };
    expect(body.id).toBe(OUTSIDE);
    expect(body.details.trusted).toBe(true);
    expect(body.details.named_by).toBe(maintainer.agentId);

    const seq = (await head()) as number;
    expect(seq).toBe(before + 1);
    const event = await eventBySeq(store.db, seq);
    expect(event?.type).toBe("operator_trusted");
    expect(event?.payload).toEqual({ operator: OUTSIDE });
    expect(body.details.trusted_seq).toBe(seq);
  });

  it("shows the trust on the operator's own page", async () => {
    const response = await handleRequest(get(`/operators/${OUTSIDE}`), env, deps);
    const body = (await response.json()) as { details: Record<string, unknown> };

    expect(body.details.trusted).toBe(true);
    expect(body.details.trusted_seq).toBe(await head());
  });

  it("refuses to name the same operator twice", async () => {
    await refused(await naming(maintainer, OUTSIDE), 409, "already_trusted");
  });

  it("refuses the maintainer's own operator (Section 11)", async () => {
    await refused(
      await naming(maintainer, MAINTAINER_OPERATOR),
      403,
      "maintainer_operator",
    );
  });

  it("refuses anyone but the maintainer", async () => {
    await refused(await naming(alice, MAINTAINER_OPERATOR), 403, "not_maintainer");
  });

  it("refuses an operator nobody registered", async () => {
    await refused(
      await naming(maintainer, "unregistered.example"),
      422,
      "unregistered_operator",
    );
  });
});

describe("listing operators", () => {
  it("returns every operator", async () => {
    const response = await handleRequest(get("/operators"), env, deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as { operators: { id: string }[] };
    // In id order, which is what listOperators pages by.
    expect(body.operators.map((operator) => operator.id)).toEqual([
      OUTSIDE,
      MAINTAINER_OPERATOR,
    ]);
  });

  it("honours an explicit limit", async () => {
    const response = await handleRequest(get("/operators?limit=1"), env, deps);
    const body = (await response.json()) as { operators: { id: string }[] };

    expect(body.operators).toHaveLength(1);
    expect(body.operators[0].id).toBe(OUTSIDE);
  });

  for (const limit of ["0", "-1", "abc", "1.5", String(LIST_PAGE_LIMIT + 1)]) {
    it(`refuses limit=${limit}`, async () => {
      const response = await handleRequest(
        get(`/operators?limit=${encodeURIComponent(limit)}`),
        env,
        deps,
      );

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "bad_query" });
    });
  }

  it("answers 405 with an Allow header on another method", async () => {
    const response = await handleRequest(
      new Request(`${TEST_ORIGIN}/operators`, { method: "DELETE" }),
      env,
      deps,
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, POST");
  });
});

describe("with no maintainer configured", () => {
  let unconfigured: TestDatabase;
  let unconfiguredEnv: Env;

  beforeAll(async () => {
    unconfigured = await openTestDatabase();
    unconfiguredEnv = {
      DB: unconfigured.db,
      CAPTURES: unconfigured.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
    };
  }, 60_000);

  afterAll(async () => {
    await unconfigured?.dispose();
  });

  it("refuses genesis naming outright rather than granting it to whoever asks", async () => {
    const response = await handleRequest(
      await naming(maintainer, OUTSIDE),
      unconfiguredEnv,
      deps,
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "maintainer_not_configured" });
    expect(await headSeq(unconfigured.db)).toBeNull();
  });

  it("registers the same key as an ordinary operator", async () => {
    const response = await handleRequest(
      await registration(maintainer, MAINTAINER_OPERATOR),
      unconfiguredEnv,
      deps,
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.maintainer).toBe(false);
  });
});

/**
 * Production wiring, end to end, through the real Worker (M25a).
 *
 * Three things ship together in this milestone and all three are here:
 *
 * 1. Key rotation (decisions D-095, D-097 item 3). A domain operator retires a
 *    key and binds another at `POST /operators/{id}/agents/{agent}/rotate`.
 *    From the seal of that event on, the retired key is refused at every write
 *    door with `agent_retired`; the new key validates and its validation
 *    counts; and every signature the retired key made BEFORE the rotation is
 *    still exactly as good as it was — which is the property the whole design
 *    turns on, because a record that invalidated its own past would be a record
 *    anybody could rewrite by losing a key.
 *
 * 2. The offline verifier over a log that holds a rotation: a clean bundle
 *    verifies with no diffs, and a doctored rotation — the attestation swapped
 *    for one the new key never signed — is refused by name.
 *
 * 3. The alert endpoint secret wrapped at rest (D-118 item a): a subscriber
 *    registered through the door on an environment carrying an
 *    ALERT_SIGNING_KEY is shown its secret once and the row holds ciphertext.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with every migration applied, every key is generated through
 * WebCrypto and every signature is made by it. Only the DNS resolver, the page
 * fetch, the beacon, the witness and the anchor are injected, because only
 * those are not ours to run in a test.
 *
 * The community half of D-140 item 5 — a community operator's key following its
 * profile — is exercised against the real sweep and the mock boards in
 * test/m25-venues-end-to-end.test.ts, which is where the board harness lives.
 *
 * No policy number lives here: the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { unwrapAlertSecret } from "../src/alerts.js";
import { buildExport } from "../src/cli/export.js";
import type { HttpClient } from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { KEY_PREFIX, keyHash } from "../src/keys.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { signCore } from "../src/sign.js";
import { alertEndpoint } from "../src/storage/alerts.js";
import { putKey } from "../src/storage/keys.js";
import {
  headSeq,
  operatorForAgent,
  retiredAgents,
} from "../src/storage/repository.js";
import type { LogBundle } from "../src/verify.js";
import { verifyOffline } from "../src/verify.js";
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

const SUBJECT = "example/kestrel-1";
const CATEGORY = "pricing";
const PAGE_URL = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

/** The maintainer's wrapping key, as a Worker secret would carry it. */
const ALERT_SIGNING_KEY = "alert-signing-key-for-tests-only-0123456789";

const API_KEY_ID = "key_0000000000000m25";
const API_KEY_SECRET = `${KEY_PREFIX}${"m".repeat(43)}`;

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let submitter: Party;
/** The operator that rotates: its first key retires and its second takes over. */
let rotator: Party;
let rotatorFresh: TestAgent;
let v2: Party;
let v3: Party;

let pageHashValue = "";
let entryId = "";

const beacon = new FixtureBeacon("m25a");

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  now: Date = NOW,
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

async function getJson(
  path: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    await signedGet(v2.agent, { path, timestamp: NOW.toISOString() }),
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "GET") return send(request);
    const url = new URL(request.url);
    return send(
      await signedGet(v2.agent, {
        path: `${url.pathname}${url.search}`,
        timestamp: NOW.toISOString(),
      }),
    );
  }
}

/** The rotate path for one operator's one key. */
function rotatePath(operator: string, agent: string): string {
  return `/operators/${encodeURIComponent(operator)}/agents/${encodeURIComponent(agent)}/rotate`;
}

/** One approval on one entry, signed by one key and answering for one operator. */
async function approve(
  agent: TestAgent,
  operator: string,
  id: string,
  now: Date = NOW,
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
    signed_at: now.toISOString(),
  } as unknown as ApproverRecord;
  const signature = await signRecord(id, "validation", record, agent.privateKey);
  return post(agent, `/entries/${id}/validate`, { record, signature }, now);
}

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    domain: DEFAULT_DOMAIN,
    attestation: await attestFor(party.agent, party.operator, AT, DEFAULT_DOMAIN),
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  submitter = { operator: "submitter.example", agent: await makeAgent() };
  rotator = { operator: "rotator.example", agent: await makeAgent() };
  rotatorFresh = await makeAgent();
  v2 = { operator: "v2.example", agent: await makeAgent() };
  v3 = { operator: "v3.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [submitter, rotator, v2, v3, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
    ALERT_SIGNING_KEY,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
    beacon,
  };

  await register(submitter);
  for (const party of [rotator, v2, v3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // One API key, for the alert door below. Minted straight into the store: the
  // key door is not what this file is about.
  await putKey(store.db, {
    id: API_KEY_ID,
    keyHash: await keyHash(API_KEY_SECRET),
    tier: "startup",
    status: "active",
    clientDay: "cs_m25a",
    createdAt: AT,
  });
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

beforeEach(async () => {
  // Every key here writes under the probationary per-agent cap, and a whole
  // suite under one frozen clock is one caller writing all day (D-130). The
  // caps themselves are pinned in test/write-quota.test.ts.
  await clearWriteQuota(store.db);
});

// ---------------------------------------------------------------------------
// The rotation door
// ---------------------------------------------------------------------------

describe("POST /operators/{id}/agents/{agent}/rotate", () => {
  beforeAll(async () => {
    // An entry for the rotated key to validate, and an approval by the OLD key
    // on nothing yet: the entry is submitted before the rotation so the
    // rotation has something to be measured against.
    const core: Core = await submittedCore(submitter.agent, {
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

  it("refuses a rotation of a key the operator does not hold", async () => {
    const before = await headSeq(store.db);
    const stranger = await makeAgent();
    const fresh = await makeAgent();
    const answer = await post(
      rotator.agent,
      rotatePath(rotator.operator, stranger.agentId),
      {
        new_agent: fresh.agentId,
        attestation: await attestFor(fresh, rotator.operator, AT, DEFAULT_DOMAIN),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      403,
      "author_mismatch",
    ]);
    // A refusal leaves the log exactly where it was.
    expect(await headSeq(store.db)).toBe(before);
  });

  it("refuses an attestation the new key did not sign", async () => {
    const before = await headSeq(store.db);
    const fresh = await makeAgent();
    const answer = await post(
      rotator.agent,
      rotatePath(rotator.operator, rotator.agent.agentId),
      {
        new_agent: fresh.agentId,
        // Signed by the OLD key: the old key's word that a new key exists is
        // not evidence that it does.
        attestation: await attestFor(
          rotator.agent,
          rotator.operator,
          AT,
          DEFAULT_DOMAIN,
        ),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "bad_attestation",
    ]);
    expect(await headSeq(store.db)).toBe(before);
  });

  it("seals the rotation and binds the new key", async () => {
    const answer = await post(
      rotator.agent,
      rotatePath(rotator.operator, rotator.agent.agentId),
      {
        new_agent: rotatorFresh.agentId,
        attestation: await attestFor(
          rotatorFresh,
          rotator.operator,
          AT,
          DEFAULT_DOMAIN,
        ),
      },
    );
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    // The new key answers for the operator, and the operator's id never moved:
    // standing and trust follow the operator, not the key.
    expect(await operatorForAgent(store.db, rotatorFresh.agentId)).toBe(
      rotator.operator,
    );
    expect(answer.body["id"]).toBe(rotator.operator);
    expect(typeof (answer.body["event"] as Record<string, unknown>)["seq"]).toBe(
      "number",
    );

    const retired = await retiredAgents(store.db, 100);
    expect(retired.has(rotator.agent.agentId)).toBe(true);
  });

  it("leaves the operator's trust and standing exactly where they were", async () => {
    // A key is how an operator speaks and is not what it is: the id, the
    // genesis trust and the marks are untouched, and both keys are still the
    // operator's — the retired one because it always was, and the new one
    // because the rotation bound it.
    const { status, body } = await getJson(
      `/operators/${encodeURIComponent(rotator.operator)}`,
    );
    expect(status).toBe(200);
    expect(body["id"]).toBe(rotator.operator);
    expect((body["details"] as Record<string, unknown>)["trusted"]).toBe(true);
    expect(body["agents"]).toEqual(
      expect.arrayContaining([rotator.agent.agentId, rotatorFresh.agentId]),
    );
  });

  it("refuses the retired key at a write door", async () => {
    // 403 and not 401: the signature is good and the caller is who they say.
    // What is gone is the standing to write.
    const before = await headSeq(store.db);
    const answer = await approve(rotator.agent, rotator.operator, entryId);
    expect([answer.status, answer.body["error"]]).toEqual([403, "agent_retired"]);
    expect(await headSeq(store.db)).toBe(before);
  });

  it("refuses the retired key at every other write door too", async () => {
    // The rule is `authenticate`'s and not one door's: the same key is refused
    // at registration, at genesis and at rotation itself.
    const another = await makeAgent();
    const answer = await post(
      rotator.agent,
      rotatePath(rotator.operator, rotatorFresh.agentId),
      {
        new_agent: another.agentId,
        attestation: await attestFor(
          another,
          rotator.operator,
          AT,
          DEFAULT_DOMAIN,
        ),
      },
    );
    expect([answer.status, answer.body["error"]]).toEqual([403, "agent_retired"]);
  });

  it("counts the new key's validation as the operator's", async () => {
    const answer = await approve(rotatorFresh, rotator.operator, entryId);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const { body } = await getJson(`/entries/${encodeURIComponent(entryId)}`);
    const approvers = body["approvers"] as { agent: string; operator: string }[];
    expect(approvers).toHaveLength(1);
    expect([approvers[0]?.agent, approvers[0]?.operator]).toEqual([
      rotatorFresh.agentId,
      rotator.operator,
    ]);
  });

  it("verifies the entry on a second operator's approval", async () => {
    const answer = await approve(v2.agent, v2.operator, entryId);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const { body } = await getJson(`/entries/${encodeURIComponent(entryId)}`);
    expect(body["status"]).toBe("verified");
  });
});

// ---------------------------------------------------------------------------
// The offline verifier, over a log that holds a rotation
// ---------------------------------------------------------------------------

describe("the offline verifier, over a rotated key", () => {
  let exported: { entry: unknown; bundle: LogBundle };

  beforeAll(async () => {
    await runSweep(env, {
      now: new Date(NOW.getTime() + HOUR_MS),
      beacon,
      witness: new FakeWitnessAdapter(),
      pinned: pinnedSet([]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
    });

    exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId,
      http: new InProcessHttp(),
      now: new Date(NOW.getTime() + HOUR_MS),
    });
  }, 600_000);

  it("carries the rotation in the bundle", () => {
    const rotations = exported.bundle.events.filter(
      (event) => (event.type as string) === "key_rotated",
    );
    expect(rotations.length).toBe(1);
  });

  it("answers ok with zero diffs", async () => {
    const report = await verifyOffline(exported.entry, exported.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(entryId);
  });

  it("refuses a doctored rotation", async () => {
    // The attestation swapped for one the new key never signed: the rotation
    // still names both keys and still sits in the chain, and the check is what
    // catches it. Its hash is not recomputed, so `chain` names it too — what
    // matters here is that `key_rotation` does.
    const events = exported.bundle.events.map((event) => {
      if ((event.type as string) !== "key_rotated") return event;
      const payload = event.payload as unknown as Record<string, unknown>;
      const attestation = payload["attestation"] as Record<string, unknown>;
      return {
        ...event,
        payload: {
          ...payload,
          attestation: { ...attestation, signature: "A".repeat(86) },
        },
      } as typeof event;
    });

    const report = await verifyOffline(exported.entry, {
      ...exported.bundle,
      events,
    });
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "key_rotation" && diff.reason === "bad_attestation",
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The alert endpoint secret, wrapped at rest
// ---------------------------------------------------------------------------

describe("an alert endpoint on a configured environment", () => {
  it("shows the secret once and stores only ciphertext", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/keys/me/webhooks`, {
        method: "POST",
        headers: { authorization: `Bearer ${API_KEY_SECRET}` },
        body: JSON.stringify({ url: "https://hook.example.com/m25a" }),
      }),
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    const id = String(body["id"]);
    const shown = String(body["secret"]);

    const row = (await alertEndpoint(store.db, id))!;
    // A copy of this database is a copy of the ciphertext and not of the
    // subscriber's signing key, which is the whole of what 0026 changes.
    expect(row.secret).toBeNull();
    expect(row.secret_wrapped).not.toBeNull();
    expect(row.secret_wrapped).not.toContain(shown);
    expect(await unwrapAlertSecret(ALERT_SIGNING_KEY, id, row.secret_wrapped!)).toBe(
      shown,
    );
  });

  it("says so on the status board", async () => {
    const response = await send(new Request(`${TEST_ORIGIN}/status`));
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    const stages = body["stages"] as { stage: string; last: string }[];
    const alerts = stages.find((stage) => stage.stage === "change alerts")!;
    // The one thing about this stage a reader cannot check for themselves.
    expect(alerts.last).toContain("secrets:");
  });
});

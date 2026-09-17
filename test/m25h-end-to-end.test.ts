/**
 * M25h through the real Worker: standing as an asset, at the doors.
 *
 * Decisions D-127 and D-130. Five things a reader or an operator actually meets:
 *
 *  - the probationary write cap, spent by a probation operator's eleventh
 *    submission of the day while an established operator's eleventh goes
 *    through;
 *  - the dispute door refusing a probation operator `insufficient_tier` before
 *    it fetches anything at all;
 *  - `GET /operators/{id}/certificate`, which verifies offline through
 *    `verifyCertificate` and through `npm run verify -- --certificate`;
 *  - `GET /operators/{id}/badge.svg`, the picture that links to it;
 *  - `GET /entries/{id}/attribution`, and the same block on the delta stream.
 *
 * One miniflare D1, one frozen clock, one fixture fetcher, and the real router
 * for every request: nothing here calls a handler directly.
 *
 * No policy number lives here: every cap and every bar is read from
 * src/policy.ts, and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { verifyCertificate } from "../src/certificate.js";
import { verifyCertificateFile } from "../src/cli/verify.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  agentIdFromPublicKey,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  STANDING_TRUSTED_ENTRY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { signCore } from "../src/sign.js";
import type { SubmissionProposal } from "../src/submit.js";
import {
  recordAssignmentMissed,
  setOperatorStanding,
} from "../src/storage/repository.js";
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
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submittedCore,
  submission,
  type FixturePage,
} from "./helpers/submit.js";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

const PRICING_URL = "https://kestrel.example/pricing";
const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Pricing</h1></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const CORRECTED_URL = "https://kestrel.example/pricing-corrected";
const CORRECTED: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Corrected</h1></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;
let maintainer: TestAgent;
let author: TestAgent;
let sealingAgent = "";

let k1: Party;
let k2: Party;
/** Two more named operators, which is who may judge a challenge to an entry
 * k1 and k2 already signed (Section 6's extra exclusion). */
let k3: Party;
let k4: Party;
/** Registered, funded to the trusted bar: an established operator. */
let established: Party;
/** Registered and never funded: a probation operator. */
let probation: Party;

let PRICING_HASH = "";
let CORRECTED_HASH = "";
/** The verified entry every read below is about. */
let verifiedEntry: Core;

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
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

async function get(
  path: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, { method: "GET" }),
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

function pricing(
  subject: string,
  claim: string,
  after: string,
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    after,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  };
}

/** One signed submission by an agent, as that agent's own operator. */
async function submitAs(
  party: Party | { readonly agent: TestAgent; readonly operator: null },
  claim: string,
  after: string,
): Promise<Response> {
  const core = await submittedCore(party.agent, {
    ...pricing("example/kestrel-1", claim, after),
    author_operator: party.operator,
  });
  return send(await submission(party.agent, { core }));
}

async function approve(entryId: string, party: Party): Promise<void> {
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
  const answer = await post(party.agent, `/entries/${entryId}/validate`, {
    record,
    signature,
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

/** One signed rejection, which is how a correction is refused by its judges. */
async function reject(entryId: string, party: Party): Promise<void> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "reject",
    reason: "the cited page says otherwise",
    snapshot_hash: CORRECTED_HASH,
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

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    attestation: await attestFor(party.agent, party.operator, AT),
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", {
    operator: party.operator,
  });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** Run the sweep the alarm runs, which is what seals the log. */
async function sweep(): Promise<void> {
  const beacon = new FixtureBeacon("m25h");
  await beacon.advance(AT);
  await runSweep(env, {
    now: NOW,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);
  CORRECTED_HASH = await pageHash(CORRECTED);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );
  sealingAgent = agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  fetcher = new FixtureFetcher({
    [PRICING_URL]: PRICING,
    [CORRECTED_URL]: CORRECTED,
  });

  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  k4 = { operator: "k4.example", agent: await makeAgent() };
  established = { operator: "established.example", agent: await makeAgent() };
  probation = { operator: "probation.example", agent: await makeAgent() };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, k4, established, probation]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
  };
  deps = { now: NOW, dns: new FixtureResolver(records), fetcher };

  for (const party of [k1, k2, k3, k4]) {
    await register(party);
    await name(party);
  }
  await register(established);
  await register(probation);

  // One verified entry, submitted by a bare key and approved by two named
  // operators, which is the whole consensus in a pool this small.
  const core = await submittedCore(author, {
    ...pricing(
      "example/kestrel-1",
      "Kestrel-1 seat pricing is $40 per seat per month",
      "$40 per seat per month",
    ),
  });
  const filed = await send(await submission(author, { core }));
  expect(filed.status).toBe(201);
  verifiedEntry = core;
  await approve(core["id"] as string, k1);
  await approve(core["id"] as string, k2);

  await sweep();

  // The fixture's one shortcut, and it is the M20 fixture's: standing on the
  // column the doors read, exactly as the sweep's standing step writes it. A
  // fixture world earns almost none of it, and the gates are not weakened to
  // let it through. After the sweep, because the sweep folds the log and writes
  // that column itself — it would have written this one back to what the
  // fixture actually earned, which is nothing.
  await setOperatorStanding(
    store.db,
    established.operator,
    STANDING_TRUSTED_ENTRY,
    0,
  );
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the probationary write cap, at the submit door", () => {
  it("spends a probation operator's day and leaves an established one's open", async () => {
    await clearWriteQuota(store.db);

    // The cap's worth of submissions, each a claim of its own so nothing is
    // refused as a duplicate of the one before it.
    for (let filing = 0; filing < WRITES_PER_AGENT_PER_DAY_PROBATION; filing += 1) {
      const response = await submitAs(
        probation,
        `Kestrel-1 seat pricing rose, probation filing ${filing}`,
        `$${100 + filing} per seat per month`,
      );
      expect([filing, response.status]).toEqual([filing, 201]);
    }

    const seenBefore = fetcher.requests.length;
    const over = await submitAs(
      probation,
      "Kestrel-1 seat pricing rose, one too many",
      "$999 per seat per month",
    );
    expect(over.status).toBe(429);
    expect(await over.json()).toMatchObject({
      error: "write_quota",
      bucket: "agent",
      limit: WRITES_PER_AGENT_PER_DAY_PROBATION,
    });
    // Charged before the expensive part: the eleventh filing cost the log no
    // fetch of the cited page.
    expect(fetcher.requests.length).toBe(seenBefore);

    // The same eleventh submission from an established operator, whose own cap
    // is the full one, goes through.
    for (let filing = 0; filing < WRITES_PER_AGENT_PER_DAY_PROBATION; filing += 1) {
      const response = await submitAs(
        established,
        `Kestrel-1 seat pricing rose, established filing ${filing}`,
        `$${200 + filing} per seat per month`,
      );
      expect([filing, response.status]).toEqual([filing, 201]);
    }
    const eleventh = await submitAs(
      established,
      "Kestrel-1 seat pricing rose, the eleventh",
      "$888 per seat per month",
    );
    expect(eleventh.status).toBe(201);
  }, 240_000);
});

describe("the dispute door", () => {
  it("refuses a probation operator insufficient_tier, before any fetch", async () => {
    await clearWriteQuota(store.db);
    const target = verifiedEntry["id"] as string;
    const core = await submittedCore(probation.agent, {
      author_operator: probation.operator,
      subject: verifiedEntry["subject"] as string,
      category: "correction",
      domain: DEFAULT_DOMAIN,
      claim: "Kestrel-1 seat pricing is $44 per seat per month, not $40",
      before: "$40 per seat per month",
      after: "$44 per seat per month",
      effective_at: "2026-09-02",
      citation: CORRECTED_URL,
      snapshot_hash: CORRECTED_HASH,
      supersedes: null,
    });
    const signature = await signCore(core, probation.agent.privateKey);

    const seenBefore = fetcher.requests.length;
    const answer = await post(
      probation.agent,
      `/entries/${target}/dispute`,
      { entry: { ...core, signature } },
    );

    expect([answer.status, answer.body["error"]]).toEqual([
      403,
      "insufficient_tier",
    ]);
    // The gate stands in front of the submission pipeline, so the refusal cost
    // the log no outbound request at all.
    expect(fetcher.requests.length).toBe(seenBefore);
  });

  it("refuses a probation operator's revalidation request the same way", async () => {
    await clearWriteQuota(store.db);
    const answer = await post(
      probation.agent,
      `/entries/${verifiedEntry["id"] as string}/revalidate`,
      {},
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      403,
      "insufficient_tier",
    ]);
  });
});

describe("GET /operators/{id}/certificate", () => {
  it("is signed by the sealing agent and verifies offline", async () => {
    const answer = await get(
      `/operators/${encodeURIComponent(k1.operator)}/certificate`,
    );
    expect(answer.status).toBe(200);

    const certificate = answer.body["certificate"] as Record<string, unknown>;
    expect(certificate["version"]).toBe("nomankind-certificate-v1");
    expect(certificate["subject"]).toEqual({
      kind: "operator",
      id: k1.operator,
      operator_kind: "domain",
      perimeter: null,
    });
    expect(certificate["issuer"]).toBe(sealingAgent);
    expect(certificate["issued_at"]).toBe(AT);
    expect(typeof certificate["standing"]).toBe("number");
    // Named at genesis, so established by the naming whatever it has earned
    // (D-130 item 5).
    expect(certificate["tier"]).toBe("established");
    expect(certificate["marks"]).toEqual({
      overturned: 0,
      missed: 0,
      failed_disputes: 0,
    });

    // Offline, against the key inside the issuer's own id, and against the
    // sealing agent the reader expected.
    expect(await verifyCertificate(answer.body)).toBe(true);
    expect(await verifyCertificate(answer.body, sealingAgent)).toBe(true);
  });

  it("is what the command checks, and the command exits 0 on it", async () => {
    const answer = await get(
      `/operators/${encodeURIComponent(k1.operator)}/certificate`,
    );
    const directory = await mkdtemp(join(tmpdir(), "nmk-m25h-"));
    const path = join(directory, "certificate.json");
    await writeFile(path, `${JSON.stringify(answer.body, null, 2)}\n`, "utf8");

    const out: string[] = [];
    const io = { stdout: (line: string) => out.push(line), stderr: () => {} };
    expect(await verifyCertificateFile(path, sealingAgent, io)).toBe(0);
    expect(out).toContain(`issuer ${sealingAgent}`);
    expect(out).toContain("ok certificate");
  });

  it("answers 404 for an operator nobody registered, and one per agent key", async () => {
    expect((await get("/operators/nobody.example/certificate")).status).toBe(
      404,
    );
    expect(
      (await get(`/agents/${encodeURIComponent("1F916:nobody")}/certificate`))
        .status,
    ).toBe(404);

    const answer = await get(
      `/agents/${encodeURIComponent(k1.agent.agentId)}/certificate`,
    );
    expect(answer.status).toBe(200);
    expect(
      (answer.body["certificate"] as Record<string, unknown>)["subject"],
    ).toEqual({
      kind: "agent",
      agent: k1.agent.agentId,
      operator: k1.operator,
    });
    expect(await verifyCertificate(answer.body, sealingAgent)).toBe(true);
  });

  it("is never cached, because every reader's copy is their own", async () => {
    const response = await send(
      new Request(
        `${TEST_ORIGIN}/operators/${encodeURIComponent(k1.operator)}/certificate`,
        { method: "GET" },
      ),
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("GET /operators/{id}/badge.svg", () => {
  it("renders the id, the standing and the tier, and links to the certificate", async () => {
    const response = await send(
      new Request(
        `${TEST_ORIGIN}/operators/${encodeURIComponent(k1.operator)}/badge.svg`,
        { method: "GET" },
      ),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "image/svg+xml; charset=utf-8",
    );
    // An hour: the numbers move at most once a sweep, and a badge is fetched by
    // every visitor to somebody else's page.
    expect(response.headers.get("cache-control")).toBe("public, max-age=3600");

    const svg = await response.text();
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain(k1.operator);
    expect(svg).toContain("standing");
    expect(svg).toContain("established");
    expect(svg).toContain(
      `href="/operators/${encodeURIComponent(k1.operator)}/certificate"`,
    );
  });

  it("escapes everything a stranger chose, and 404s an operator nobody named", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/operators/nobody.example/badge.svg`, {
        method: "GET",
      }),
    );
    expect(response.status).toBe(404);

    const badge = await send(
      new Request(
        `${TEST_ORIGIN}/operators/${encodeURIComponent(k1.operator)}/badge.svg`,
        { method: "GET" },
      ),
    );
    const svg = await badge.text();
    // Nothing between the tags but text: an id carrying a bracket would have
    // closed one, which is what the escaping is for.
    expect(svg).not.toMatch(/<text[^>]*>[^<]*<(?!\/text)/);
  });
});

describe("the operator JSON, beside the directory it mirrors", () => {
  it("carries the rank, the tier and the counts the page shows", async () => {
    const listing = await get("/operators");
    expect(listing.status).toBe(200);
    const rows = listing.body["operators"] as Record<string, unknown>[];
    const named = rows.find((row) => row["id"] === k1.operator);
    expect(named).toBeDefined();
    expect(named?.["tier"]).toBe("established");
    // The leaderboard's own rule: by standing, ties sharing a rank. k1 and k2
    // validated the same entry once each, so they stand together.
    const k2Row = rows.find((row) => row["id"] === k2.operator);
    expect(named?.["rank"]).toBe(k2Row?.["rank"]);
    expect(named?.["counts"]).toMatchObject({ validations_volunteered: 1 });

    const one = await get(`/operators/${encodeURIComponent(k1.operator)}`);
    expect(one.status).toBe(200);
    // One operator, two doors, one answer.
    expect(one.body["tier"]).toBe(named?.["tier"]);
    expect(one.body["rank"]).toBe(named?.["rank"]);
    expect(one.body["counts"]).toEqual(named?.["counts"]);
    expect(one.body["standing"]).toEqual(named?.["standing"]);
  });

  it("says nothing was computed rather than nothing was earned", async () => {
    // Registered and idle is a real answer and a different one from unknown:
    // the fold keeps an accumulator for every registered operator, so the
    // counts are zeroes rather than nothing, and the tier is the lowest.
    const one = await get(`/operators/${encodeURIComponent(probation.operator)}`);
    expect(one.body["tier"]).toBe("probation");
    expect(one.body["counts"]).toMatchObject({
      validations_volunteered: 0,
      submissions_verified: 0,
      forfeits: 0,
    });
    // Nothing earned is not a place on the leaderboard.
    expect(one.body["rank"]).toBeTypeOf("number");
  });
});

describe("the operator page's Record, through the Worker", () => {
  it("shows a failed dispute and a missed assignment the log really holds", async () => {
    await clearWriteQuota(store.db);

    // A real filing, by the operator whose standing covers the stake, and two
    // real rejections of the correction it brought: the log ends with a
    // `dispute_failed` attributed to its filer through the `dispute_filed` that
    // opened it, which is the event a page that guessed the list left out.
    const target = verifiedEntry["id"] as string;
    const core = await submittedCore(established.agent, {
      author_operator: established.operator,
      subject: verifiedEntry["subject"] as string,
      category: "correction",
      domain: DEFAULT_DOMAIN,
      claim: "Kestrel-1 seat pricing is $44 per seat per month, not $40",
      before: "$40 per seat per month",
      after: "$44 per seat per month",
      effective_at: "2026-09-02",
      citation: CORRECTED_URL,
      snapshot_hash: CORRECTED_HASH,
      supersedes: null,
    });
    const correctionId = core["id"] as string;
    const signature = await signCore(core, established.agent.privateKey);
    const filed = await post(established.agent, `/entries/${target}/dispute`, {
      entry: { ...core, signature },
    });
    expect([filed.status, filed.body["error"] ?? null]).toEqual([201, null]);

    // k1 and k2 signed the entry being challenged, so neither may judge the
    // challenge against it: the two operators that did not are who reject it.
    for (const party of [k3, k4]) {
      await reject(correctionId, party);
    }

    // And one assignment nobody answered, written by the sweep's own writer:
    // the draw itself needs a trusted pool this fixture is far too small for
    // (TRUSTED_POOL_SWITCH), so the event is put in the log the way the sweep
    // puts it rather than by a hand-built row.
    await recordAssignmentMissed(
      store.db,
      {
        at: AT,
        type: "assignment_missed",
        entry_id: target,
        payload: {
          agent: established.agent.agentId,
          operator: established.operator,
        },
      },
      0,
    );

    const response = await send(
      new Request(
        `${TEST_ORIGIN}/operators/${encodeURIComponent(established.operator)}`,
        { method: "GET", headers: { accept: "text/html" } },
      ),
    );
    expect(response.status).toBe(200);
    const page = await response.text();

    // The three marks, each in the words the decision fixed, on the page a
    // reader actually opens.
    expect(page).toContain("Failed disputes");
    expect(page).toContain(
      "This operator filed a dispute that failed, and\n                            forfeited the standing it staked.",
    );
    expect(page).toContain(correctionId);
    expect(page).toContain("Missed assignments");
    expect(page).toContain(
      "This agent was drawn for an assignment and did not\n                            answer it inside the window.",
    );
    expect(page).not.toContain("Nothing is on this operator's Record");
  }, 240_000);
});

describe("GET /entries/{id}/attribution", () => {
  it("answers the block the entry page renders from the same function", async () => {
    const id = verifiedEntry["id"] as string;
    const answer = await get(`/entries/${id}/attribution`);
    expect(answer.status).toBe(200);

    expect(answer.body["author"]).toEqual({
      agent: author.agentId,
      operator: null,
    });
    expect(
      (answer.body["validators"] as Record<string, unknown>[]).map(
        (row) => row["operator"],
      ),
    ).toEqual([k1.operator, k2.operator]);
    expect(answer.body["reconfirmers"]).toEqual([]);
    expect(answer.body["citation"]).toContain(
      `verified by 2 validators (${k1.operator}, ${k2.operator})`,
    );
    expect(answer.body["citation"]).toContain(`nomankind entry ${id}`);
  });

  it("answers 404 for an entry nobody filed", async () => {
    expect((await get("/entries/entry-nobody-filed/attribution")).status).toBe(
      404,
    );
  });
});

describe("the delta stream", () => {
  it("carries the attribution block beside every entry it delivers", async () => {
    const response = await send(
      await signedGet(k1.agent, { path: "/sync", timestamp: AT }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    const items = body["events"] as Record<string, unknown>[];
    expect(items.length).toBeGreaterThan(0);

    const entries = items.filter((item) => item["kind"] === "entry");
    expect(entries.length).toBeGreaterThan(0);
    for (const item of entries) {
      const attribution = item["attribution"] as Record<string, unknown>;
      expect(typeof attribution["citation"]).toBe("string");
      expect(Array.isArray(attribution["validators"])).toBe(true);
    }

    // An event about no entry is owed to nobody, and says so rather than
    // carrying an empty block.
    for (const item of items.filter((one) => one["kind"] === "event")) {
      expect(item["attribution"]).toBeNull();
    }
  });
});

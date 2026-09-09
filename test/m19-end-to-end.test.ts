/**
 * M19 end to end: the browsing UI, through the real router over a real D1.
 *
 * Whitepaper Section 3, The log: "every field a reader needs to check an entry
 * offline is visible on the entry". This file is what holds the pages to that.
 * The world below is built the way M17's and M18's worlds are — three outside
 * operators register at the door and are named at genesis, a bare key submits,
 * decisions verify, one entry supersedes another, one stays a draft, and the
 * sweep seals the log — and then every page is fetched through `handleRequest`
 * and read back against the store it was rendered from.
 *
 * Nothing is stubbed except the clock, DNS, the payment provider and the fetcher
 * the norm rule uses. The counters are compared against the same counts the
 * repository would answer, the entry page is compared against the stored entry
 * field by field, and the seal it shows is the seal the sweep actually committed.
 *
 * Two rules about the doors are checked here rather than in a unit test, because
 * only the mounted router can prove them: the same path answers HTML to a browser
 * and JSON to an agent, and a POST is never the page route's to answer.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { CORE_KEYS } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import { POLICY, TRUSTED_POOL_SWITCH } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import {
  countEntries,
  countTrustedOperators,
  getEntry,
  eventsForEntry,
  latestSeal,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import { CONTENT_SECURITY_POLICY, escapeHtml } from "../src/ui/html.js";
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** What a browser sends, and what an agent sends. */
const HTML = { accept: "text/html,application/xhtml+xml" };
const JSON_ACCEPT = { accept: "application/json" };

const SUBJECT = "kestrel/kestrel-1";
const CATEGORY = "pricing";
const VERIFIED_REFERENCE = "mock-verified-m19";

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://kestrel.example/pricing";
let PRICING_HASH = "";

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

/** The verified entry, the one it superseded, and the draft nobody judged. */
let idA = "";
let idB = "";
let idC = "";
let positionA = 0;
let positionB = 0;
let sealedHead = 0;

function send(request: Request, on: Env = env): Promise<Response> {
  return handleRequest(request, on, { ...deps, now: NOW });
}

/** One page, with the headers every HTML answer has to carry checked once. */
async function page(
  path: string,
  headers: Record<string, string> = HTML,
  on: Env = env,
): Promise<{ status: number; body: string }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, { headers }),
    on,
  );
  const body = await response.text();
  if ((response.headers.get("content-type") ?? "").includes("text/html")) {
    expect(response.headers.get("content-security-policy")).toBe(
      CONTENT_SECURITY_POLICY,
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("vary")).toBe("Accept");
    expect(response.headers.get("cache-control")).toBe("no-store");
  }
  return { status: response.status, body };
}

/** One page that has to be HTML and has to be 200. */
async function ok(path: string): Promise<string> {
  const answer = await page(path);
  expect([path, answer.status]).toEqual([path, 200]);
  return answer.body;
}

async function register(party: Party): Promise<void> {
  const response = await send(
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
  expect([party.operator, response.status]).toEqual([party.operator, 201]);
}

async function name(party: Party): Promise<void> {
  const response = await send(
    await signedPost(maintainer, {
      path: "/genesis",
      body: { operator: party.operator },
      timestamp: AT,
    }),
  );
  expect([party.operator, response.status]).toEqual([party.operator, 200]);
}

function pricing(
  claim: string,
  supersedes: string | null = null,
): Omit<SubmissionProposal, "author"> {
  return {
    subject: SUBJECT,
    category: CATEGORY,
    claim,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes,
  };
}

async function submit(
  proposal: Omit<SubmissionProposal, "author">,
): Promise<string> {
  const core = await submittedCore(author, proposal);
  const response = await send(await submission(author, { core }));
  expect(response.status).toBe(201);
  return core["id"] as string;
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
  const response = await send(
    await signedPost(party.agent, {
      path: `/entries/${entryId}/validate`,
      body: { record, signature },
      timestamp: AT,
    }),
  );
  expect(response.status).toBe(201);
}

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const pair = await generateKeypair();
  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: base64urlEncode(
      await exportPrivateKeyPkcs8(pair.privateKey),
    ),
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
    fetcher: new FixtureFetcher({ [PRICING_URL]: PRICING }),
  };

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  idA = await submit(pricing("Kestrel-1 seat pricing is $40 per seat per month"));
  await approve(idA, k1);
  await approve(idA, k2);

  idB = await submit(
    pricing("Kestrel-1 seat pricing is listed at $40 per seat per month", idA),
  );
  await approve(idB, k1);
  await approve(idB, k3);

  idC = await submit(pricing("Kestrel-1 seat pricing may rise again in October"));

  const beacon = new FixtureBeacon("m19");
  await beacon.advance(AT);
  await runSweep(env, {
    now: NOW,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });

  const seal = await latestSeal(store.db);
  sealedHead = seal!.last_seq;
  positionA = (await getEntry(store.db, idA))!.submittedSeq;
  positionB = (await getEntry(store.db, idB))!.submittedSeq;
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) The home page
// ---------------------------------------------------------------------------

describe("the home page", () => {
  it("shows four counters that are the world's own numbers", async () => {
    const body = await ok("/");

    const verified = await countEntries(store.db, { status: "verified" });
    const stale = await countEntries(store.db, { stale: true });
    const trusted = await countTrustedOperators(store.db);

    // The world: B verified, A superseded by it, C still a draft.
    expect([verified, stale, trusted]).toEqual([1, 0, 3]);
    expect(body).toContain("VERIFIED");
    expect(body).toContain(`<div class="counter-value">${verified}</div>`);
    expect(body).toContain(`<div class="counter-value">${stale}</div>`);
    expect(body).toContain(`<div class="counter-value">${trusted}</div>`);
    expect(body).toContain(`<div class="counter-value">${sealedHead}</div>`);
    expect(body).toContain(`random draw active at ${TRUSTED_POOL_SWITCH}`);
    expect(body).toContain(`/sync?from=${sealedHead}`);
  }, 60_000);

  it("lists the newest entries, each linked to its own page", async () => {
    const body = await ok("/");
    for (const id of [idA, idB, idC]) {
      expect([id, body.includes(`href="/entries/${id}"`)]).toEqual([id, true]);
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (b) The listing, and what it refuses
// ---------------------------------------------------------------------------

/** The positions the listing showed, in the order it showed them. */
function positions(body: string): number[] {
  const found: number[] = [];
  const pattern = /<a href="\/entries\/nmk_[0-9a-f]{32}">(\d+)<\/a>/g;
  for (const match of body.matchAll(pattern)) found.push(Number(match[1]));
  return found;
}

describe("the entries listing", () => {
  it("orders every entry by descending sealed position", async () => {
    const body = await ok("/entries");
    const shown = positions(body);
    expect(shown.length).toBeGreaterThanOrEqual(3);
    expect([...shown].sort((left, right) => right - left)).toEqual(shown);
  }, 60_000);

  it("narrows to a status, and to a tier, and finds no stale entry", async () => {
    const verified = await ok("/entries?status=verified");
    expect(verified).toContain(idB);
    expect(verified).not.toContain(`href="/entries/${idC}"`);

    // The effective tier: the draft has none, so a tier filter excludes it.
    const stated = await ok("/entries?tier=stated");
    expect(stated).toContain(idA);
    expect(stated).toContain(idB);
    expect(stated).not.toContain(`href="/entries/${idC}"`);

    const stale = await ok("/entries?fresh=stale");
    expect(stale).toContain("No entries match these filters.");
    const fresh = await ok("/entries?fresh=fresh");
    expect(positions(fresh).length).toBeGreaterThan(0);
  }, 60_000);

  it("pages strictly before a sealed position", async () => {
    const body = await ok(`/entries?before=${positionB}`);
    const shown = positions(body);
    expect(shown.every((each) => each < positionB)).toBe(true);
    expect(shown).toContain(positionA);
  }, 60_000);

  it("refuses a query it does not understand, by name, as a page", async () => {
    for (const [query, reason] of [
      ["?category=nope", "bad_category"],
      ["?nope=1", "unknown_parameter"],
      ["?status=nope", "bad_status"],
      ["?before=nope", "bad_before"],
    ] as const) {
      const answer = await page(`/entries${query}`);
      expect([query, answer.status]).toEqual([query, 400]);
      expect([query, answer.body.includes(reason)]).toEqual([query, true]);
      expect([query, answer.body.includes("Bad query")]).toEqual([query, true]);
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (c) One entry, whole
// ---------------------------------------------------------------------------

describe("the entry page", () => {
  it("shows the value of every core key the entry carries", async () => {
    const stored = (await getEntry(store.db, idB))!;
    const record = stored.entry as unknown as Record<string, unknown>;
    const body = await ok(`/entries/${idB}`);

    for (const key of CORE_KEYS) {
      expect([key, body.includes(`<dt>${key}</dt>`)]).toEqual([key, true]);
      const value = record[key];
      if (typeof value !== "string" || value === "") continue;
      expect([key, body.includes(escapeHtml(value))]).toEqual([key, true]);
    }
  }, 60_000);

  it("shows every derived field name, and confidence as null", async () => {
    const body = await ok(`/entries/${idB}`);
    for (const key of [
      "status",
      "staleness_window_days",
      "verified_at",
      "last_confirmed",
      "expires_at",
      "stale",
      "superseded_by",
      "overturned_by",
      "confidence",
    ]) {
      expect([key, body.includes(`<dt>${key}</dt>`)]).toEqual([key, true]);
    }
    expect(body).toContain(`<span class="dim">null</span>`);
  }, 60_000);

  it("shows every decision the log holds for it", async () => {
    const stored = (await getEntry(store.db, idB))!;
    const approvers = (stored.entry as unknown as Record<string, unknown>)[
      "approvers"
    ] as Record<string, unknown>[];
    const body = await ok(`/entries/${idB}`);

    expect(approvers.length).toBe(2);
    for (const approver of approvers) {
      expect(body).toContain(escapeHtml(approver["agent"]));
      expect(body).toContain(escapeHtml(approver["operator"]));
      expect(body).toContain(approver["decision"] as string);
      expect(body).toContain(approver["snapshot_hash"] as string);
    }
  }, 60_000);

  it("shows the seal it was actually sealed under, and its capture", async () => {
    const stored = (await getEntry(store.db, idB))!;
    const record = stored.entry as unknown as Record<string, unknown>;
    const onEntry = record["seal"] as Record<string, unknown>;
    const seal = await latestSeal(store.db);
    const body = await ok(`/entries/${idB}`);

    expect(onEntry).not.toBeNull();
    // The proof is a JSON string, so the page carries it escaped: that escaping
    // is the point of src/ui/html.ts and the test checks the escaped form.
    expect(body).toContain(escapeHtml(onEntry["inclusion_proof"]));
    expect(body).toContain(`<dd>${onEntry["position"] as number}</dd>`);
    expect(body).toContain(seal!.root);
    expect(body).toContain(
      `href="/captures/${record["snapshot_hash"] as string}"`,
    );
  }, 60_000);

  it("shows every event of the entry, by hash, with its proof route", async () => {
    const events = await eventsForEntry(store.db, idB);
    const body = await ok(`/entries/${idB}`);
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect([event.seq, body.includes(event.hash)]).toEqual([event.seq, true]);
      expect([
        event.seq,
        body.includes(`href="/events/${event.seq}/proof"`),
      ]).toEqual([event.seq, true]);
    }
  }, 60_000);

  it("names the two commands that check it offline, at this origin", async () => {
    const body = await ok(`/entries/${idB}`);
    expect(body).toContain(`npm run export -- ${TEST_ORIGIN} ${idB} ./out`);
    expect(body).toContain("npm run verify -- ./out/entry.json ./out/log.json");
  }, 60_000);

  it("links the superseded entry to what superseded it", async () => {
    const body = await ok(`/entries/${idA}`);
    expect(body).toContain(`href="/entries/${idB}"`);
    expect(body).toContain("Superseded by");
  }, 60_000);

  it("says whether the draft is sealed, and never guesses", async () => {
    const stored = (await getEntry(store.db, idC))!;
    const onEntry = (stored.entry as unknown as Record<string, unknown>)["seal"];
    const body = await ok(`/entries/${idC}`);

    expect(body).toContain(`<span class="badge s-draft">draft</span>`);
    if (onEntry === null) {
      expect(body).toContain("unsealed");
    } else {
      expect(body).toContain(
        escapeHtml((onEntry as Record<string, unknown>)["inclusion_proof"]),
      );
    }
  }, 60_000);

  it("answers the 404 page for an id the log has never minted", async () => {
    const missing = await page(`/entries/nmk_${"0".repeat(32)}`);
    expect(missing.status).toBe(404);
    expect(missing.body).toContain("Not found");

    const malformed = await page("/entries/not-an-id");
    expect(malformed.status).toBe(404);
    expect(malformed.body).toContain("Not found");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (d) The same path, two voices
// ---------------------------------------------------------------------------

describe("a path a browser and an agent both ask for", () => {
  it("answers JSON to the agent and HTML to the browser", async () => {
    const agent = await send(
      new Request(`${TEST_ORIGIN}/entries/${idB}`, { headers: JSON_ACCEPT }),
    );
    expect(agent.status).toBe(200);
    expect(agent.headers.get("content-type")).toContain("application/json");
    expect(((await agent.json()) as Record<string, unknown>)["id"]).toBe(idB);

    const browser = await send(
      new Request(`${TEST_ORIGIN}/entries/${idB}`, { headers: HTML }),
    );
    expect(browser.status).toBe(200);
    expect(browser.headers.get("content-type")).toContain("text/html");
  }, 60_000);

  it("hands a POST to the door that owns it", async () => {
    const posted = await send(
      new Request(`${TEST_ORIGIN}/entries`, { method: "POST", headers: HTML }),
    );
    // The submit door answered, not a page: a page route that claimed the method
    // would have taken the door's own refusal away from it.
    expect(posted.headers.get("content-type")).toContain("application/json");
    expect(posted.status).not.toBe(200);
  }, 60_000);

  it("answers a HEAD exactly like the GET, without a body", async () => {
    const head = await send(
      new Request(`${TEST_ORIGIN}/entries`, { method: "HEAD", headers: HTML }),
    );
    expect(head.status).toBe(200);
    expect(head.headers.get("content-type")).toContain("text/html");
    expect(await head.text()).toBe("");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (e) The registry pages
// ---------------------------------------------------------------------------

describe("the operator pages", () => {
  it("names the maintainer as one that cannot validate, and counts decisions", async () => {
    const body = await ok("/operators");
    expect(body).toContain("cannot validate");
    for (const party of [k1, k2, k3]) {
      expect(body).toContain(`href="/operators/${party.operator}"`);
    }
    // k1 signed both entries; k2 and k3 signed one each.
    expect(body).toContain("<td>2</td>");
  }, 60_000);

  it("shows one operator's record and the entries it decided", async () => {
    const body = await ok(`/operators/${k1.operator}`);
    expect(body).toContain(k1.operator);
    expect(body).toContain(k1.agent.agentId);
    expect(body).toContain(`href="/entries/${idB}"`);
    expect(body).toContain("<dt>trusted seq</dt>");

    const missing = await page("/operators/nobody.example");
    expect(missing.status).toBe(404);
  }, 60_000);

  it("still answers the JSON directory to an agent", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/operators`, { headers: JSON_ACCEPT }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (f) Policy, in both voices
// ---------------------------------------------------------------------------

describe("the policy endpoint", () => {
  it("hands an agent exactly the frozen policy object", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/policy`, { headers: JSON_ACCEPT }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual(JSON.parse(JSON.stringify(POLICY)));
  }, 60_000);

  it("hands a browser the same numbers as a page", async () => {
    const body = await ok("/policy");
    expect(body).toContain(String(TRUSTED_POOL_SWITCH));
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (g) The pages that are only pages
// ---------------------------------------------------------------------------

describe("the documentation pages and the front door", () => {
  it("answers the API and genesis pages as HTML", async () => {
    for (const path of ["/api", "/genesis"]) {
      const answer = await page(path);
      expect([path, answer.status]).toEqual([path, 200]);
    }
  }, 60_000);

  it("serves the landing at /landing, whatever the host", async () => {
    const body = await ok("/landing");
    expect(body).toContain(`<body class="landing">`);
  }, 60_000);

  it("serves the landing at / on the apex, and the home page elsewhere", async () => {
    const apex: Env = { ...env, APEX_HOST: "nomankind.ai" };

    const front = await send(
      new Request("https://nomankind.ai/", { headers: HTML }),
      apex,
    );
    expect(await front.text()).toContain(`<body class="landing">`);

    const app = await send(
      new Request("https://app.nomankind.ai/", { headers: HTML }),
      apex,
    );
    const body = await app.text();
    expect(body).not.toContain(`<body class="landing">`);
    expect(body).toContain("VERIFIED");
  }, 60_000);

  /**
   * The www host is a fourth custom domain of the production Worker and serves
   * nothing: it exists to send a reader to the apex, so the landing page has one
   * canonical host. The redirect is permanent, keeps the path and the query, and
   * is above the method check — nothing on www is anybody's door.
   */
  describe("the www host", () => {
    /** The production world: the only one that sets APEX_HOST. */
    const apex = (): Env => ({ ...env, APEX_HOST: "nomankind.ai" });

    it("redirects a page request to the apex, path and query kept", async () => {
      const response = await send(
        new Request("https://www.nomankind.ai/entries?status=verified", {
          headers: HTML,
        }),
        apex(),
      );
      expect(response.status).toBe(301);
      expect(response.headers.get("location")).toBe(
        "https://nomankind.ai/entries?status=verified",
      );
      expect(response.headers.get("cache-control")).toBe("no-store");
    }, 60_000);

    it("redirects the front door itself", async () => {
      const response = await send(
        new Request("https://www.nomankind.ai/", { headers: HTML }),
        apex(),
      );
      expect(response.status).toBe(301);
      expect(response.headers.get("location")).toBe("https://nomankind.ai/");
    }, 60_000);

    it("redirects a POST too, because no door lives on www", async () => {
      const response = await send(
        new Request("https://www.nomankind.ai/entries", { method: "POST" }),
        apex(),
      );
      expect(response.status).toBe(301);
      expect(response.headers.get("location")).toBe(
        "https://nomankind.ai/entries",
      );
    }, 60_000);

    it("leaves the apex itself answering the landing", async () => {
      const response = await send(
        new Request("https://nomankind.ai/", { headers: HTML }),
        apex(),
      );
      expect(response.status).toBe(200);
      expect(await response.text()).toContain(`<body class="landing">`);
    }, 60_000);

    it("redirects nothing when no apex is configured", async () => {
      // Local and demo set no APEX_HOST, so a www hostname is just a hostname
      // and the app answers on it as it answers anywhere.
      const response = await send(
        new Request("https://www.nomankind.ai/", { headers: HTML }),
        env,
      );
      expect(response.status).toBe(200);
      const body = await response.text();
      expect(body).not.toContain(`<body class="landing">`);
      expect(body).toContain("VERIFIED");
    }, 60_000);
  });

  it("serves the stylesheet as CSS, cacheable, to any reader", async () => {
    const response = await send(new Request(`${TEST_ORIGIN}/static/app.css`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/css");
    expect(await response.text()).toContain("--accent: #7fd1c4");

    const landing = await send(
      new Request(`${TEST_ORIGIN}/static/landing.css`),
    );
    expect(landing.status).toBe(200);
    expect(landing.headers.get("content-type")).toContain("text/css");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (h) Nothing lives here
// ---------------------------------------------------------------------------

describe("a path nothing answers", () => {
  it("is a page for a browser and a refusal for everyone else", async () => {
    const browser = await page("/nowhere");
    expect(browser.status).toBe(404);
    expect(browser.body).toContain("Not found");

    const response = await send(
      new Request(`${TEST_ORIGIN}/nowhere`, { headers: JSON_ACCEPT }),
    );
    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toEqual({ ok: false, error: "not_found" });
  }, 60_000);

  it("answers a browser's HEAD with the page's headers and no body", async () => {
    // A HEAD is a GET without the body, here as everywhere: a browser probing an
    // unknown path must not be told the page is JSON when the GET is HTML.
    const head = await send(
      new Request(`${TEST_ORIGIN}/nowhere`, { method: "HEAD", headers: HTML }),
    );
    expect(head.status).toBe(404);
    expect(head.headers.get("content-type")).toContain("text/html");
    expect(head.headers.get("content-security-policy")).toBe(
      CONTENT_SECURITY_POLICY,
    );
    expect(await head.text()).toBe("");

    // And an agent's HEAD still gets the refusal its GET gets.
    const agent = await send(
      new Request(`${TEST_ORIGIN}/nowhere`, {
        method: "HEAD",
        headers: JSON_ACCEPT,
      }),
    );
    expect(agent.status).toBe(404);
    expect(agent.headers.get("content-type")).toContain("application/json");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (i) When storage is unreachable
// ---------------------------------------------------------------------------

/** A binding that fails the way a broken D1 does: on prepare, synchronously. */
function unreachableDatabase(): TestDatabase["db"] {
  const fail = (): never => {
    throw new Error("D1_ERROR: no such table: entries");
  };
  return { prepare: fail, batch: fail, exec: fail } as unknown as TestDatabase["db"];
}

describe("a page whose storage is unreachable", () => {
  /** The same world, with the database taken away underneath it. */
  function broken(): Env {
    return { ...env, DB: unreachableDatabase() };
  }

  it("answers the browser a 503 page that names the failure", async () => {
    const answer = await page("/entries", HTML, broken());

    expect(answer.status).toBe(503);
    expect(answer.body).toContain("Unavailable");
    expect(answer.body).toContain("storage_unreachable");
    // The page, not a stack trace and not the binding: the reader learns which
    // part failed and nothing about the inside of the Worker.
    expect(answer.body).not.toContain("D1_ERROR");
  }, 60_000);

  it("answers everyone else the same word as JSON", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, { headers: JSON_ACCEPT }),
      broken(),
    );

    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toEqual({ error: "storage_unreachable" });
  }, 60_000);
});

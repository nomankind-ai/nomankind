/**
 * The source policy, end to end, through the real Worker on a real miniflare D1.
 *
 * Decision D-080. Whitepaper Section 4 and Section 12's "stated entries are
 * about the source, not the world": a stated entry verifies when independent
 * operators confirm the cited page said what the entry says, and nothing in that
 * sentence asks whether the source was one that should be believed about the
 * subject. A site made yesterday could carry a pricing claim to verified. The
 * fix is a published per-domain source policy, enforced where a category has an
 * authoritative source by nature and labeled everywhere else.
 *
 * What this file walks, against the real doors:
 *
 *   - a claim in an official-required category must cite the subject's own
 *     official source, or the door refuses it before it fetches anything and
 *     before it writes anything;
 *   - a subject whose authority the table does not name is refused too, because
 *     "no published authority" is not the same as "any authority will do";
 *   - the host rule is exact — http is never official, however official the host;
 *   - everywhere else the class is a label: recognized for an editorial or
 *     preprint host, other for a stranger's blog, and both are served;
 *   - a dispute's correction goes through the same pipeline, carries a class of
 *     its own, and is gated on the category of the entry it challenges rather
 *     than on `correction`, which no domain requires an official source for;
 *   - a reader and a trainer may demand a minimum class, and the browsing
 *     listing filters by exact class;
 *   - and the tables themselves are published, at `GET /policy`.
 *
 * Nothing about the signed core changed: the citation was always in it, and the
 * class is a reading of it. That is why no entry here is signed differently from
 * one signed before this milestone, and why the sidecar is where the class
 * lands.
 *
 * No policy number lives here: the classes and the minimum values are
 * src/sources.ts's, the tables are src/policy.ts's, the reproduction counts are
 * the policy's, and the bare integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildTranscriptArtifact, transcriptArtifactHash } from "../src/artifact.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  DOMAINS,
  LIST_PAGE_LIMIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { signCore } from "../src/sign.js";
import {
  SOURCE_CLASSES,
  checkSource,
  sourceClassOf,
  sourceClassSatisfies,
} from "../src/sources.js";
import { getEntry, ledgerRowsForEntry } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

const VERIFIED_REFERENCE = "mock-verified-m23b";

/**
 * The subject every entry here is about: an authority the table names, so the
 * gate has something to be satisfied by and something to refuse.
 */
const SUBJECT = "openai/gpt-5";

/** A subject whose authority the table does not name, and by design cannot. */
const UNKNOWN_SUBJECT = "nobodyco/model-1";

/** The subject's own official source, and the same URL over http. */
const OFFICIAL_URL = "https://platform.openai.com/docs/pricing";
const OFFICIAL_OVER_HTTP = "http://platform.openai.com/docs/pricing";
/** A site nobody published anything under. */
const MADE_UP_URL = "https://made-up-site.example/pricing";
/** A preprint server: recognized, and never official for a product's price. */
const RECOGNIZED_URL = "https://arxiv.org/abs/2609.00001";
/** A stranger's blog. */
const OTHER_URL = "https://someone.example/notes/gpt-5";

const PRICING_PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Pricing</h1><p>$40 per million tokens</p></main></body></html>",
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
/** A bare key, registered to nobody: Section 5's own submitter. */
let author: TestAgent;
/** A second bare key, so a dispute is never a self-dispute. */
let challenger: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;

let pricingHash = "";

/** The pricing entry that cites the subject's official source. */
let officialId = "";
/** The behavior entry that cites a preprint server. */
let recognizedId = "";
/** The behavior entry that cites a stranger's blog, submitted last. */
let otherId = "";

const beacon = new FixtureBeacon("m23b");
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
 * Every entry in this file is read inside the release window (decision D-100),
 * where a free reader is handed the proof and a release date rather than the
 * content. These tests are about what the doors serve and not about the window,
 * so they read the way an entitled client does — the M2 signature the
 * disclosure gate already asks for. The free reader's own answers are tested in
 * test/m24d-doors.test.ts.
 */
async function getJson(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    await signedGet(k1.agent, { path, timestamp: now.toISOString() }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One page, as a browser asks for it. */
async function getHtml(
  path: string,
): Promise<{ status: number; text: string }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, {
      headers: { accept: "text/html" },
    }),
  );
  return { status: response.status, text: await response.text() };
}

/** The log's head, so a refusal can be shown to have written nothing. */
async function head(): Promise<number> {
  const { body } = await getJson("/health");
  const log = body["log"] as { head?: number } | undefined;
  return log?.head ?? 0;
}

/** The sidecar the store holds for one entry: where the class actually lands. */
async function sidecarOf(id: string) {
  const stored = await getEntry(store.db, id);
  if (stored === null) throw new Error(`m23b: no entry ${id}`);
  return stored.sidecar;
}

function txt(operator: string): string {
  return `_nomankind.${operator}`;
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

/** Submit one signed core through the real door. */
async function submit(
  agent: TestAgent,
  core: Core,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const signature = await signCore(core, agent.privateKey);
  return post(agent, "/entries", { entry: { ...core, signature } });
}

/** A stated pricing proposal, citing whatever the caller wants it to cite. */
function pricing(
  claim: string,
  citation: string,
  subject: string = SUBJECT,
): Record<string, unknown> {
  return {
    subject,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per million tokens",
    after: "$40 per million tokens",
    effective_at: "2026-09-01",
    citation,
    snapshot_hash: pricingHash,
  };
}

/**
 * A behavior proposal: its snapshot is the frozen transcript rather than a
 * page, so the citation is never fetched and the class is still read off it.
 * That is the pair this file needs — a category with no gate, whose citation
 * still gets a label.
 */
async function behavior(
  output: string,
  citation: string,
): Promise<Record<string, unknown>> {
  const evidence = {
    model: SUBJECT,
    prompt: "What is the capital of France?",
    parameters: { temperature: 0 },
    output,
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
  };
  const hashed = await transcriptArtifactHash(
    buildTranscriptArtifact(evidence, evidence.output, evidence.observed_at),
  );
  if (!hashed.ok) throw new Error("m23b: the fixture transcript is refused");
  return {
    subject: SUBJECT,
    category: "behavior",
    domain: DEFAULT_DOMAIN,
    claim: `gpt-5 ${output}`,
    before: "answered the question",
    // The value is the duplicate key (D-085), and these two entries are meant
    // to coexist as live answers about the same subject and category, so each
    // one's value names its own case.
    after: `${output} the question`,
    effective_at: "2026-09-01",
    evidence,
    citation,
    snapshot_hash: hashed.hash,
  };
}

/** One approval on a stated entry: no test to judge, no measurement to bring. */
async function approveStated(party: Party, id: string): Promise<void> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pricingHash,
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

/**
 * One approval on a behavior entry: the test accepted, and the approver's own
 * rerun of the frozen prompt at the policy's n, holding at its k.
 */
async function approveBehavior(
  party: Party,
  id: string,
  snapshotHash: string,
  output: string,
): Promise<void> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: snapshotHash,
    assigned_random: false,
    test_accepted: true,
    reproduction: {
      model: SUBJECT,
      output,
      observed_at: "2026-09-01",
      runs: REPRODUCTION_RUNS,
      holds: REPRODUCTION_HOLDS,
    },
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

beforeAll(async () => {
  pricingHash = await pageHash(PRICING_PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  challenger = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, maintainerParty]) {
    records[txt(party.operator)] = [party.agent.agentId];
  }

  // Every citation the fetcher can answer. A URL that is not here cannot be
  // fetched at all, which is how a refusal is shown to have happened before the
  // network was reached.
  fetcher = new FixtureFetcher({
    [OFFICIAL_URL]: PRICING_PAGE,
    [OFFICIAL_OVER_HTTP]: PRICING_PAGE,
    [MADE_UP_URL]: PRICING_PAGE,
    [OTHER_URL]: PRICING_PAGE,
    [RECOGNIZED_URL]: PRICING_PAGE,
  });

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
    fetcher,
    beacon,
  };

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // The official pricing entry: cited correctly, verified by two of the three.
  const officialCore = await submittedCore(author, {
    ...pricing("gpt-5 costs $40 per million tokens", OFFICIAL_URL),
  } as never);
  expect((await submit(author, officialCore)).status).toBe(201);
  officialId = officialCore["id"] as string;
  await approveStated(k1, officialId);
  await approveStated(k2, officialId);

  // A behavior entry citing a preprint server, and then one citing a blog. Both
  // are verified: behavior is not an official-required category, so the class is
  // a label. The blog one is submitted last, so it is the newest answer about
  // this subject in this category.
  const recognizedFields = await behavior("refuses politely", RECOGNIZED_URL);
  const recognizedCore = await submittedCore(author, recognizedFields as never);
  expect((await submit(author, recognizedCore)).status).toBe(201);
  recognizedId = recognizedCore["id"] as string;
  await approveBehavior(
    k1,
    recognizedId,
    recognizedCore["snapshot_hash"] as string,
    "refuses politely",
  );
  await approveBehavior(
    k2,
    recognizedId,
    recognizedCore["snapshot_hash"] as string,
    "refuses politely",
  );

  const otherFields = await behavior("refuses bluntly", OTHER_URL);
  const otherCore = await submittedCore(author, otherFields as never);
  expect((await submit(author, otherCore)).status).toBe(201);
  otherId = otherCore["id"] as string;
  await approveBehavior(
    k3,
    otherId,
    otherCore["snapshot_hash"] as string,
    "refuses bluntly",
  );
  await approveBehavior(
    k1,
    otherId,
    otherCore["snapshot_hash"] as string,
    "refuses bluntly",
  );

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
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

describe("an official-required claim must cite the subject's official source", () => {
  it("refuses a pricing claim citing a host nobody published, before any write", async () => {
    const before = await head();
    const asked = fetcher.requests.length;

    const core = await submittedCore(author, {
      ...pricing("gpt-5 costs $99 per million tokens", MADE_UP_URL),
    } as never);
    const answer = await submit(author, core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    // Before any write, and before the network: the kernel refuses on the
    // signed core alone, so nothing was fetched and nothing was archived.
    expect(await head()).toBe(before);
    expect(fetcher.requests.length).toBe(asked);
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
  });

  it("refuses a pricing claim whose authority the table does not name", async () => {
    const before = await head();
    const core = await submittedCore(author, {
      ...pricing(
        "model-1 costs $1 per million tokens",
        OFFICIAL_URL,
        UNKNOWN_SUBJECT,
      ),
    } as never);
    const answer = await submit(author, core);

    // Not source_not_official: the log has no opinion about this authority's
    // sources at all, and saying so is a different fact from saying the cited
    // one is wrong. A row is added by decision, not by a submission.
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "unknown_authority",
    ]);
    expect(await head()).toBe(before);
  });

  it("never reads http as official, however official the host", async () => {
    // The host rule is exact: https only. A citation over http can be rewritten
    // in flight by anyone between the Worker and the host, so the bytes it
    // returns are not the publisher's word.
    expect(
      sourceClassOf(DEFAULT_DOMAIN, SUBJECT, OFFICIAL_OVER_HTTP),
    ).toEqual({ class: "other", matched_host: null, authority: "openai" });

    const before = await head();
    const core = await submittedCore(author, {
      ...pricing("gpt-5 costs $41 per million tokens", OFFICIAL_OVER_HTTP),
    } as never);
    const answer = await submit(author, core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    expect(await head()).toBe(before);
  });

  it("accepts the same claim citing the subject's official source", async () => {
    // The entry that was accepted in the world above, with the class the
    // derivation gave it: the host that matched, and the authority its subject
    // names. Nothing about the signed core carries any of it.
    const sidecar = await sidecarOf(officialId);
    expect(sidecar.source).toEqual({
      class: "official",
      matched_host: "platform.openai.com",
      authority: "openai",
    });

    const { body } = await getJson(`/entries/${officialId}`);
    expect(body["status"]).toBe("verified");
    expect(body["citation"]).toBe(OFFICIAL_URL);
  });

  it("matches a subdomain of a listed host and not a lookalike of one", async () => {
    // `docs.anthropic.com` is a subdomain of `anthropic.com`, so it matches;
    // `anthropic.com.evil.tld` merely contains the string, so it does not.
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "anthropic/claude",
        "https://docs.anthropic.com/en/api",
      ).class,
    ).toBe("official");
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "anthropic/claude",
        "https://anthropic.com.evil.tld/en/api",
      ).class,
    ).toBe("other");
  });
});

// ---------------------------------------------------------------------------
// The label
// ---------------------------------------------------------------------------

describe("everywhere else the class is a label and never a gate", () => {
  it("accepts a behavior claim citing a preprint server, as recognized", async () => {
    const sidecar = await sidecarOf(recognizedId);
    expect(sidecar.source).toEqual({
      class: "recognized",
      matched_host: "arxiv.org",
      authority: "openai",
    });
    const { body } = await getJson(`/entries/${recognizedId}`);
    expect(body["status"]).toBe("verified");
  });

  it("accepts a behavior claim citing a stranger's blog, as other", async () => {
    const sidecar = await sidecarOf(otherId);
    expect(sidecar.source).toEqual({
      class: "other",
      matched_host: null,
      authority: "openai",
    });
    const { body } = await getJson(`/entries/${otherId}`);
    expect(body["status"]).toBe("verified");
  });

  it("says the same thing on the entry page, in a reader's words", async () => {
    const official = await getHtml(`/entries/${officialId}`);
    expect(official.status).toBe(200);
    expect(official.text).toContain("<dt>source</dt>");
    expect(official.text).toContain("platform.openai.com");

    const stranger = await getHtml(`/entries/${otherId}`);
    // `other` is not an accusation, and the page does not read as one.
    expect(stranger.text).toContain(
      "other: no published authority for this subject",
    );
  });
});

// ---------------------------------------------------------------------------
// The correction
// ---------------------------------------------------------------------------

describe("a dispute's correction is gated on the entry it challenges", () => {
  /**
   * One correction of the pricing entry, citing whatever it is given.
   *
   * The value is the duplicate key (D-085), and corrections are entries like
   * any other, so a correction meant to live beside an accepted one carries its
   * own value rather than repeating it.
   */
  async function correction(
    claim: string,
    citation: string,
    after: string = "$44 per million tokens",
  ): Promise<Core> {
    return submittedCore(challenger, {
      subject: SUBJECT,
      category: "correction",
      domain: DEFAULT_DOMAIN,
      claim,
      before: "$40 per million tokens",
      after,
      effective_at: "2026-09-02",
      citation,
      snapshot_hash: pricingHash,
    } as never);
  }

  /** File one signed correction against one target. */
  async function fileAgainst(
    targetId: string,
    core: Core,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const signature = await signCore(core, challenger.privateKey);
    return post(challenger, `/entries/${targetId}/dispute`, {
      entry: { ...core, signature },
    });
  }

  it("refuses a correction of a pricing entry citing an unlisted host", async () => {
    // The correction's own category is `correction`, which no domain requires
    // an official source for, so the submission pipeline the door runs on it
    // passes it. The claim it makes is a claim about the target's fact, so the
    // gate that binds it is the target's: pricing, in this domain, is one of
    // the official-required categories.
    expect(DOMAINS[DEFAULT_DOMAIN]!.sources.official_required).not.toContain(
      "correction",
    );
    expect(checkSource(DEFAULT_DOMAIN, "correction", SUBJECT, OTHER_URL)).toEqual({
      ok: true,
    });

    const before = await head();
    const targetBefore = await getEntry(store.db, officialId);
    const core = await correction(
      "gpt-5 costs $44 per million tokens, says a stranger",
      MADE_UP_URL,
    );
    const answer = await fileAgainst(officialId, core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    // Nothing was written: not the correction, not the challenge, not a stake,
    // and the entry a stranger's blog tried to overturn is where it was.
    expect(await head()).toBe(before);
    expect(await getEntry(store.db, core["id"] as string)).toBeNull();
    expect(await ledgerRowsForEntry(store.db, officialId, LIST_PAGE_LIMIT)).toEqual(
      [],
    );
    expect(await getEntry(store.db, officialId)).toEqual(targetBefore);
  });

  it("accepts the same correction citing the target subject's official host", async () => {
    const core = await correction(
      "gpt-5 costs $44 per million tokens",
      OFFICIAL_URL,
    );
    const answer = await fileAgainst(officialId, core);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    // The correction is an entry like any other, so it has a class like any
    // other: derived from its own citation, by the same function, into the same
    // sidecar key.
    const sidecar = await sidecarOf(core["id"] as string);
    expect(sidecar.source).toEqual({
      class: "official",
      matched_host: "platform.openai.com",
      authority: "openai",
    });
  });

  it("accepts a correction of a behavior entry citing a stranger's blog", async () => {
    // `behavior` is not official-required, so nothing gates a challenge to it:
    // whether the blog supports the correction is the validators' judgment, and
    // this policy never takes that judgment from them.
    const core = await correction(
      "gpt-5 answers the question after all",
      OTHER_URL,
      "answers the question",
    );
    const answer = await fileAgainst(otherId, core);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    const sidecar = await sidecarOf(core["id"] as string);
    expect(sidecar.source).toEqual({
      class: "other",
      matched_host: null,
      authority: "openai",
    });
  });
});

// ---------------------------------------------------------------------------
// What a reader and a trainer may demand
// ---------------------------------------------------------------------------

describe("min_source on the reader's door", () => {
  const behaviorQuery = `subject=${encodeURIComponent(SUBJECT)}&category=behavior`;

  it("answers the newest entry when no demand is made", async () => {
    const { status, body } = await getJson(`/read?${behaviorQuery}`);
    expect(status).toBe(200);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(otherId);
  });

  it("skips the newer answer whose citation is below the demand", async () => {
    const { status, body } = await getJson(
      `/read?${behaviorQuery}&min_source=recognized`,
    );
    expect(status).toBe(200);
    // Newest-first plus first-match is the whole ranking: the blog entry is
    // newer and is skipped, and the reader is handed the preprint one rather
    // than the best of a bad set.
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(recognizedId);
    expect(
      (body["sidecar"] as { source: { class: string } }).source.class,
    ).toBe("recognized");
  });

  it("answers nothing rather than something weaker than was asked for", async () => {
    const { status, body } = await getJson(
      `/read?${behaviorQuery}&min_source=official`,
    );
    expect([status, body["error"]]).toEqual([404, "no_entry"]);
  });

  it("answers the official entry when the demand is met", async () => {
    const { status, body } = await getJson(
      `/read?subject=${encodeURIComponent(SUBJECT)}&category=pricing&min_source=official`,
    );
    expect(status).toBe(200);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(officialId);
  });

  it("refuses a value it cannot read, and `other` among them", async () => {
    for (const value of ["bogus", "other", ""]) {
      const { status, body } = await getJson(
        `/read?${behaviorQuery}&min_source=${value}`,
      );
      expect([value, status, body["error"]]).toEqual([
        value,
        400,
        "bad_min_source",
      ]);
    }
    // `other` is refused on purpose: a demand for "at least other" is a demand
    // nothing fails, so writing it would be asking for the unfiltered answer in
    // a way that looks like a filter.
    expect(sourceClassSatisfies("other", "official")).toBe(false);
    expect(sourceClassSatisfies("official", "recognized")).toBe(true);
  });
});

describe("min_source on the delta stream", () => {
  async function stream(query: string): Promise<Record<string, unknown>[]> {
    const { status, body } = await getJson(
      `/sync?from=0&limit=${LIST_PAGE_LIMIT}${query}`,
    );
    expect(status).toBe(200);
    return body["events"] as Record<string, unknown>[];
  }

  it("delivers only entries whose class meets the demand", async () => {
    const items = await stream("&min_source=official");
    const entries = items.filter((item) => item.kind === "entry");
    expect(entries.length).toBeGreaterThan(0);
    for (const item of entries) {
      const sidecar = item["sidecar"] as { source: { class: string } };
      expect(sidecar.source.class).toBe("official");
    }
    // The entries it dropped are entries the unfiltered stream delivers.
    const all = await stream("");
    const ids = new Set(
      all
        .filter((item) => item.kind === "entry")
        .map((item) => (item["entry"] as Record<string, unknown>)["id"]),
    );
    expect(ids.has(recognizedId)).toBe(true);
    expect(ids.has(otherId)).toBe(true);
  });

  it("keeps the events that are about no entry at all", async () => {
    const items = await stream("&min_source=official");
    // A registration or a pool snapshot is not about an entry, so no entry
    // filter can have an opinion about it, and a trainer replaying the log
    // still needs it.
    expect(items.some((item) => item.kind === "event")).toBe(true);
  });

  it("refuses a value it cannot read", async () => {
    const { status, body } = await getJson("/sync?min_source=bogus");
    expect([status, body["error"]]).toEqual([400, "bad_min_source"]);
  });
});

// ---------------------------------------------------------------------------
// The browsing listing
// ---------------------------------------------------------------------------

describe("the entries listing's source chip", () => {
  it("offers one chip per class, and checks the one that is on", async () => {
    const page = await getHtml("/entries?source=official");
    expect(page.status).toBe(200);
    expect(page.text).toContain('<span class="filter-name">source</span>');
    for (const value of SOURCE_CLASSES) {
      expect(page.text, `${value} has no chip`).toContain(
        `name="source" value="${value}"`,
      );
    }
    expect(page.text).toContain(
      '<input type="radio" name="source" value="official" checked />',
    );
  });

  it("shows the entries of that class and no others", async () => {
    const official = await getHtml("/entries?source=official");
    expect(official.text).toContain(officialId);
    expect(official.text).not.toContain(recognizedId);
    expect(official.text).not.toContain(otherId);

    const other = await getHtml("/entries?source=other");
    expect(other.text).toContain(otherId);
    expect(other.text).not.toContain(officialId);

    const unfiltered = await getHtml("/entries");
    for (const id of [officialId, recognizedId, otherId]) {
      expect(unfiltered.text).toContain(id);
    }
  });

  it("counts what it shows, and says which filters the total ignores", async () => {
    const official = await getHtml("/entries?source=official");
    // The total is by status and domain, both indexed columns; source narrows
    // the page over the sidecar the store handed back, and the line says so
    // rather than letting a reader read the total as a filtered count.
    expect(official.text).toContain(
      "the category, source, tier and freshness filters narrow the page, not the total",
    );
  });

  it("refuses a class it cannot read rather than ignoring the filter", async () => {
    const page = await getHtml("/entries?source=bogus");
    expect(page.status).toBe(400);
    expect(page.text).toContain("bad_source");
    // And the bad-query page lists the parameters the parser actually takes.
    expect(page.text).toContain("source");
  });
});

// ---------------------------------------------------------------------------
// The published tables
// ---------------------------------------------------------------------------

describe("the policy is published, not merely applied", () => {
  it("carries the domain's whole source table on GET /policy", async () => {
    const { status, body } = await getJson("/policy");
    expect(status).toBe(200);
    const domains = body["DOMAINS"] as Record<string, Record<string, unknown>>;
    const sources = domains[DEFAULT_DOMAIN]!["sources"];
    // The object the kernel reads, served verbatim: a reader can check that the
    // door that refused them and the table that was published are the same one.
    expect(sources).toEqual(DOMAINS[DEFAULT_DOMAIN]!.sources);
  });

  it("shows the same tables on the policy page", async () => {
    const page = await getHtml("/policy");
    expect(page.status).toBe(200);
    expect(page.text).toContain(`Domains · ${DEFAULT_DOMAIN} · sources`);
    expect(page.text).toContain(
      `DOMAINS.${DEFAULT_DOMAIN}.sources.official_required`,
    );
    for (const host of DOMAINS[DEFAULT_DOMAIN]!.sources.authorities["openai"]!
      .hosts) {
      expect(page.text, `${host} is not published`).toContain(host);
    }
  });

  it("names the two refusals on the API page, in the door's own order", async () => {
    const page = await getHtml("/api");
    const at = page.text.indexOf("category_not_in_domain");
    expect(at).toBeGreaterThan(-1);
    const authority = page.text.indexOf("unknown_authority", at);
    const official = page.text.indexOf("source_not_official", authority);
    expect(authority).toBeGreaterThan(at);
    expect(official).toBeGreaterThan(authority);
  });
});

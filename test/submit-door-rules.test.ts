/**
 * Three rules the submit door could not actually say, and now says.
 *
 * The QA of 2026-09-12, all three in the same door and all three the same
 * shape: a refusal that names what is wrong, reached before a refusal that
 * names something else.
 *
 * 1. The source class was read off the citation alone. A citation is where a
 *    request is aimed; the capture is where it landed. An official host that
 *    redirected to a third party, or down to http, handed its badge to whatever
 *    the chain ended at -- and the bytes in the archive, on an official-required
 *    category, were then a stranger's page filed as the authority's own. The
 *    lower of the two classes applies now, so a redirect can take a class away
 *    and never give one.
 *
 * 2. `transcript_shape` could not fire here at all. The artifact is built from
 *    the entry's own evidence with all six keys named whatever the evidence
 *    held, so the shape check inside the hash always passed and a transcript
 *    missing a key was either sealed or refused `snapshot_mismatch`, which is a
 *    true sentence about the wrong thing.
 *
 * 3. `missing_domain` could not fire either: a core carrying every field but the
 *    domain has one key fewer than the body shape counted, so the door answered
 *    `bad_body` and the kernel's own word for a v0.6 core was unreachable
 *    through the door that exists to refuse one.
 *
 * Everything is real except the network: real keys, real Ed25519 signatures over
 * the real canonical bytes, miniflare's D1 with the migrations applied, and the
 * fixture fetcher following redirect chains exactly as the real one counts them.
 * Every refusal asserts that nothing was written.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildTranscriptArtifact,
  transcriptArtifactHash,
} from "../src/artifact.js";
import type { Core } from "../src/core.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { signCore } from "../src/sign.js";
import { capturedSourceClass, sourceClassOf } from "../src/sources.js";
import { deriveEntry } from "../src/derive.js";
import { eventsForEntry, getEntry, headSeq } from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_CLOCK,
  SUBMIT_NOW,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";

const NOW = SUBMIT_NOW;

// ---------------------------------------------------------------------------
// The pages, and the chains between them
// ---------------------------------------------------------------------------

/**
 * The authority's own host. `example` is a listed host of the fixture authority
 * row every domain shares (RFC 2606's reserved names), so `kestrel.example` is
 * under it and a citation of it is `official` -- which is what makes the
 * redirects below the interesting half of the test.
 */
const OFFICIAL = "https://kestrel.example/pricing";
const OFFICIAL_MOVED = "https://kestrel.example/pricing-2026";
const OFFICIAL_SAME_HOST = "https://kestrel.example/pricing-moved";
const OFFICIAL_TO_HTTP = "https://kestrel.example/pricing-plain";
const PLAIN = "http://kestrel.example/pricing-2026";
const OFFICIAL_OFFSITE = "https://kestrel.example/pricing-mirrored";
const OFFSITE = "https://mirror.test/kestrel/pricing";
const LABELLED = "https://kestrel.example/notes";
const LABELLED_OFFSITE = "https://mirror.test/kestrel/notes";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PAGES: Record<string, FixturePage> = {
  [OFFICIAL]: PAGE,
  [OFFICIAL_SAME_HOST]: { ...PAGE, location: OFFICIAL_MOVED },
  [OFFICIAL_MOVED]: PAGE,
  [OFFICIAL_TO_HTTP]: { ...PAGE, location: PLAIN },
  [PLAIN]: PAGE,
  [OFFICIAL_OFFSITE]: { ...PAGE, location: OFFSITE },
  [OFFSITE]: PAGE,
  [LABELLED]: { ...PAGE, location: LABELLED_OFFSITE },
  [LABELLED_OFFSITE]: PAGE,
};

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let author: TestAgent;
let hash = "";

beforeAll(async () => {
  store = await openTestDatabase();
  author = await makeAgent();
  hash = await pageHash(PAGE);
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: (await makeAgent()).agentId,
    SEALING_AGENT_KEY: "",
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver({}),
    fetcher: new FixtureFetcher(PAGES),
  };
});

afterAll(async () => {
  await store?.dispose();
});

/** A stated pricing proposal: an official-required category, by nature. */
function pricing(
  subject: string,
  citation: string,
  overrides: Partial<SubmissionProposal> = {},
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing is $40 per seat per month`,
    before: "$35 per seat per month",
    after: `$40 per seat per month, per ${subject}`,
    effective_at: "2026-09-01",
    citation,
    snapshot_hash: hash,
    ...overrides,
  };
}

/** Submit one core through the real door and answer the status and body. */
async function send(
  core: Core,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await handleRequest(
    await submission(author, { core }),
    env,
    deps,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** Nothing was written: no row for the entry, and the head where it was. */
async function wroteNothing(core: Core, before: number | null): Promise<void> {
  expect(await getEntry(store.db, core["id"] as string)).toBeNull();
  expect(await headSeq(store.db)).toBe(before);
}

// ---------------------------------------------------------------------------
// (1) The class of what was captured, not of what was asked for
// ---------------------------------------------------------------------------

describe("the source class follows the capture's final URL", () => {
  it("reads the weaker of the two, as a pure function", () => {
    const subject = "example/kestrel-class";
    expect(sourceClassOf(DEFAULT_DOMAIN, subject, OFFICIAL).class).toBe(
      "official",
    );
    // The citation says official and the chain says otherwise, so the chain
    // decides: a redirect takes a class away and never gives one.
    expect(
      capturedSourceClass(DEFAULT_DOMAIN, subject, OFFICIAL, OFFSITE).class,
    ).toBe("other");
    expect(
      capturedSourceClass(DEFAULT_DOMAIN, subject, OFFSITE, OFFICIAL).class,
    ).toBe("other");
    // Nothing redirected, so there is nothing else to read.
    expect(
      capturedSourceClass(DEFAULT_DOMAIN, subject, OFFICIAL, OFFICIAL).class,
    ).toBe("official");
    expect(
      capturedSourceClass(DEFAULT_DOMAIN, subject, OFFICIAL, null).class,
    ).toBe("official");
  });

  it("refuses an official host that redirects to a third party", async () => {
    const before = await headSeq(store.db);
    const core = await submittedCore(
      author,
      pricing("example/kestrel-1", OFFICIAL_OFFSITE),
    );

    const answer = await send(core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    await wroteNothing(core, before);
  });

  it("refuses one that redirects down to http on its own host", async () => {
    const before = await headSeq(store.db);
    const core = await submittedCore(
      author,
      pricing("example/kestrel-2", OFFICIAL_TO_HTTP),
    );

    const answer = await send(core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "source_not_official",
    ]);
    await wroteNothing(core, before);
  });

  it("takes a redirect that stays https on the same host", async () => {
    const core = await submittedCore(
      author,
      pricing("example/kestrel-3", OFFICIAL_SAME_HOST),
    );

    const answer = await send(core);

    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    expect(await getEntry(store.db, core["id"] as string)).not.toBeNull();
  });

  it("leaves a category that requires no official source alone", async () => {
    // The class is a label everywhere but the official-required categories, and
    // a label is not a gate: the same off-site redirect is simply captured.
    const core = await submittedCore(author, {
      ...pricing("example/kestrel-4", LABELLED),
      category: "correction",
      after: "$44 per seat per month, corrected",
    });

    const answer = await send(core);

    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);

    // And the label that was stored is the one the chain earned (the QA of
    // 2026-09-13). The citation is the authority's own host and the bytes came
    // from a mirror, and the sidecar used to say `official` off the citation
    // alone -- the same two URLs the door refuses an official-required category
    // on, read two different ways by the gate and by the record. The weaker of
    // the two, and the host that actually answered.
    const stored = await getEntry(store.db, core["id"] as string);
    expect(stored).not.toBeNull();
    expect(stored!.sidecar.source).toEqual(
      capturedSourceClass(
        DEFAULT_DOMAIN,
        "example/kestrel-4",
        LABELLED,
        LABELLED_OFFSITE,
      ),
    );
    expect(stored!.sidecar.source.class).toBe("other");
    // Not what the citation alone says, which is the bug this pins.
    expect(
      sourceClassOf(DEFAULT_DOMAIN, "example/kestrel-4", LABELLED).class,
    ).toBe("official");
  });

  it("keeps the weaker class when the entry is derived again", async () => {
    // The class is derivation's, off the submission event's own `final_url`, so
    // the next door that rewrites the row -- a validation, a reconfirmation,
    // the sweep -- recomputes the same weaker class rather than quietly
    // restoring the citation's. A class that survived only until the next write
    // would be a class no reader could rely on.
    const core = await submittedCore(author, {
      ...pricing("example/kestrel-4b", LABELLED),
      category: "correction",
      after: "$45 per seat per month, corrected",
    });
    expect((await send(core)).status).toBe(201);

    const id = core["id"] as string;
    const events = await eventsForEntry(store.db, id);
    expect(deriveEntry(events, id, SUBMIT_CLOCK).sidecar.source.class).toBe(
      "other",
    );
  });
});

// ---------------------------------------------------------------------------
// (2) The transcript's shape, before its hash
// ---------------------------------------------------------------------------

/** The six measured fields of an honest transcript, plus the statement key. */
function evidenceOf(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    model: "example/kestrel-1",
    prompt: "how many requests per minute?",
    parameters: { temperature: 0 },
    output: "ninety",
    predicate: "contains:ninety",
    observed_at: "2026-09-01",
    provider_statement: null,
    ...overrides,
  };
}

/** The hash an author computes over the artifact their own evidence builds. */
async function transcriptHash(evidence: Record<string, unknown>): Promise<string> {
  const hashed = await transcriptArtifactHash(
    buildTranscriptArtifact(
      evidence,
      evidence["output"] as string,
      evidence["observed_at"] as string,
    ),
  );
  if (!hashed.ok) throw new Error(`the fixture transcript is refused: ${hashed.reason}`);
  return hashed.hash;
}

describe("a malformed transcript is refused by the word that names it", () => {
  it("refuses evidence with no model, whatever hash was signed over it", async () => {
    const evidence = evidenceOf();
    delete evidence["model"];
    const before = await headSeq(store.db);
    const core = await submittedCore(author, {
      subject: "example/kestrel-5",
      category: "behavior",
      domain: DEFAULT_DOMAIN,
      claim: "Kestrel-1 answers ninety",
      before: "answered something else",
      after: "answers ninety, from a transcript with no model",
      effective_at: "2026-09-01",
      evidence,
      citation: OFFICIAL,
      // The hash the author's own tool computes from this evidence: the key it
      // does not carry is dropped from the canonical form, so before this the
      // door agreed with it and sealed a five-key transcript.
      snapshot_hash: await transcriptHash(evidence),
    });

    const answer = await send(core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "transcript_shape",
    ]);
    await wroteNothing(core, before);
  });

  it("refuses it where the hash was signed over the six-key artifact", async () => {
    const evidence = evidenceOf();
    delete evidence["model"];
    const before = await headSeq(store.db);
    const core = await submittedCore(author, {
      subject: "example/kestrel-6",
      category: "behavior",
      domain: DEFAULT_DOMAIN,
      claim: "Kestrel-1 answers ninety",
      before: "answered something else",
      after: "answers ninety, hashed as though the model were there",
      effective_at: "2026-09-01",
      evidence,
      citation: OFFICIAL,
      // This is the case that used to answer `snapshot_mismatch`: a true
      // sentence about the wrong thing, because what is wrong is the evidence.
      snapshot_hash: await transcriptHash(evidenceOf()),
    });

    const answer = await send(core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "transcript_shape",
    ]);
    await wroteNothing(core, before);
  });

  it("takes a transcript that carries all six", async () => {
    const evidence = evidenceOf();
    const core = await submittedCore(author, {
      subject: "example/kestrel-7",
      category: "behavior",
      domain: DEFAULT_DOMAIN,
      claim: "Kestrel-1 answers ninety",
      before: "answered something else",
      after: "answers ninety, with every measured field",
      effective_at: "2026-09-01",
      evidence,
      citation: OFFICIAL,
      snapshot_hash: await transcriptHash(evidence),
    });

    const answer = await send(core);

    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
  });
});

// ---------------------------------------------------------------------------
// (3) The domain the body does not carry
// ---------------------------------------------------------------------------

describe("a core that names no domain", () => {
  /** A v0.6 core: the seventeen keys of schema v0.6, signed as seventeen. */
  async function legacyCore(): Promise<Core> {
    const core = await submittedCore(
      author,
      pricing("example/kestrel-8", OFFICIAL),
    );
    const legacy = { ...core } as Record<string, unknown>;
    delete legacy["domain"];
    // The id covers the core, so a core with a key taken out names itself
    // differently. `bad_id` would then be the first thing wrong with it, and
    // this test is about the second, so the id is recomputed over what is
    // actually being signed.
    const { entryIdFor } = await import("../src/submit.js");
    return { ...legacy, id: await entryIdFor(legacy as Core) } as Core;
  }

  it("is refused missing_domain and not bad_body", async () => {
    const core = await legacyCore();
    const before = await headSeq(store.db);

    const answer = await send(core);

    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "missing_domain",
    ]);
    await wroteNothing(core, before);
  });

  it("costs the log no fetch, because the refusal is a pure one", async () => {
    const fetcher = new FixtureFetcher(PAGES);
    const core = await legacyCore();

    const response = await handleRequest(
      await submission(author, { core }),
      env,
      { ...deps, fetcher },
    );

    expect(response.status).toBe(422);
    expect(fetcher.requests).toEqual([]);
  });

  it("still refuses a body carrying a key the core has never had", async () => {
    // The shape is exact in the direction that matters: `domain` is the one key
    // a body may leave out, and nothing may be added.
    const core = await submittedCore(
      author,
      pricing("example/kestrel-9", OFFICIAL),
    );
    const before = await headSeq(store.db);
    const signature = await signCore(core, author.privateKey);
    const request = await signedPost(author, {
      path: "/entries",
      body: { entry: { ...core, signature, status: "verified" } },
      timestamp: SUBMIT_CLOCK.now,
    });

    const response = await handleRequest(request, env, deps);

    expect([response.status, await response.json()]).toEqual([
      400,
      { error: "bad_body" },
    ]);
    expect(await headSeq(store.db)).toBe(before);
  });
});

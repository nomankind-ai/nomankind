/**
 * M24c, the three rules the two new domains brought with them (D-096).
 *
 * The subject-authority exclusion, delayed disclosure of a redacted transcript
 * payload, and staleness on a version change — checked where each of them
 * actually lives: the pure rules against the kernel, the door rules against the
 * real router over miniflare's D1 and R2, and the offline verifier against a
 * bundle somebody tampered with.
 *
 * Everything here is real except the network and the clock. Real Ed25519 keys,
 * the real norm rule over real fixture bytes, the real schema over every entry
 * that comes back, and an injected instant so the disclosure window opens
 * because the test moved the clock and never because time passed.
 *
 * The prose these rules are published as is
 * schema/nomankind-domain-registry-v1.md, "Delayed disclosure" and "Staleness
 * on a version change"; where this file and that document disagree, the
 * document governs.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  buildTranscriptArtifact,
  checkRedaction,
  checkTranscriptRedaction,
  disclosurePlaceholders,
  transcriptArtifactHash,
} from "../src/artifact.js";
import { authorityExclusions } from "../src/assign.js";
import type { Core } from "../src/core.js";
import type { ApproverRecord, ReconfirmationRecord } from "../src/events.js";
import { canonicalize, sha256Hex } from "../src/hash.js";
import { archiveAddress } from "../src/normalize.js";
import {
  authorityHostsFor,
  disclosureWindowDays,
  isDisclosureCategory,
  isVersionStalenessCategory,
  versionedSubjectOf,
} from "../src/policy.js";
import { checkReconfirmation } from "../src/reconfirm.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import {
  checkSubmission,
  entryIdFor,
  type SubmissionProposal,
} from "../src/submit.js";
import {
  capturesForEntry,
  captureForHash,
  getEntry,
  headSeq,
} from "../src/storage/repository.js";
import { checkValidation } from "../src/validate.js";
import { verifyOffline } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { entryWorld, rederive } from "../src/worker/world.js";
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
import { buildVerifyWorld, OUTSIDE_OPERATORS } from "./helpers/verify-world.js";
import { signCore } from "../src/sign.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

const SAFETY = "ai-safety";
const GOVERNANCE = "ai-governance";


// ---------------------------------------------------------------------------
// The subject-authority exclusion (section 4)
// ---------------------------------------------------------------------------

const SUBMITTER_AGENT = "1F916-submitter";
const VALIDATOR_AGENT = "1F916-validator";
const SNAPSHOT = `sha256:${"a".repeat(64)}`;

function approval(operator: string): ApproverRecord {
  return {
    agent: VALIDATOR_AGENT,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: SNAPSHOT,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  } as unknown as ApproverRecord;
}

/** A context in which the only rule that can bite is the new one. */
function validationContext(operator: string, domain: string, subject: string) {
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: "submitter.example" },
    agentOperators: { [VALIDATOR_AGENT]: operator },
    operators: { [operator]: { maintainer: false, provider: false, domains: [domain] } },
    domain,
    authority_hosts: authorityHostsFor(domain, subject),
    priorRecords: [] as readonly ApproverRecord[],
    openAssignment: null,
  };
}

function reconfirmationContext(
  operator: string,
  domain: string,
  subject: string,
) {
  return {
    submitter: { agent: SUBMITTER_AGENT, operator: "submitter.example" },
    agentOperators: { [VALIDATOR_AGENT]: operator },
    trustedOperators: [operator],
    operatorDomains: [domain],
    authority_hosts: authorityHostsFor(domain, subject),
    status: "verified" as const,
    effectiveTier: "stated" as const,
  };
}

function reconfirmationRecord(operator: string): ReconfirmationRecord {
  return {
    agent: VALIDATOR_AGENT,
    operator,
    snapshot_hash: SNAPSHOT,
    reproduction: null,
    observation: null,
    signed_at: AT,
  } as unknown as ReconfirmationRecord;
}

/** A stated governance core, for the reconfirmation check's `core` argument. */
function governanceCore(subject: string): Core {
  return {
    id: "nmk_m24cauthority",
    subject,
    category: "in_force",
    domain: GOVERNANCE,
    claim: "The instrument is in force.",
    before: "not in force",
    after: "in force",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://www.legislation.gov.uk/ai",
    snapshot_hash: SNAPSHOT,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: SUBMITTER_AGENT,
    author_operator: "submitter.example",
    submitted_at: AT,
  } as unknown as Core;
}

describe("the subject-authority exclusion", () => {
  it("reads the hosts of the subject's own authority row, and nothing else", () => {
    // The UK's rows in ai-governance, from src/policy.ts and never from here.
    expect(authorityHostsFor(GOVERNANCE, "uk/ai-act")).toContain("gov.uk");
    // A fixture row triggers nothing: `example` is a test's authority and never
    // a party with an interest in the record.
    expect(authorityHostsFor(GOVERNANCE, "example/instrument")).toEqual([]);
    // A subject whose party has no row at all.
    expect(authorityHostsFor(GOVERNANCE, "nobody/instrument")).toEqual([]);
    // And the domain whose authorities are its excluded parties already: the
    // flag is false there, so nothing changes for ai-ecosystem.
    expect(authorityHostsFor("ai-ecosystem", "openai/gpt-5")).toEqual([]);
  });

  it("refuses an operator under an authority host, and under a subdomain of one", () => {
    for (const operator of ["gov.uk", "watch.legislation.gov.uk"]) {
      expect(
        checkValidation(
          approval(operator),
          validationContext(operator, GOVERNANCE, "uk/ai-act"),
        ),
      ).toEqual({ ok: false, reason: "subject_authority" });

      expect(
        checkReconfirmation(
          reconfirmationRecord(operator),
          governanceCore("uk/ai-act"),
          reconfirmationContext(operator, GOVERNANCE, "uk/ai-act"),
        ),
      ).toEqual({ ok: false, reason: "subject_authority" });
    }
  });

  it("lets the same operator judge an entry the subject does not bar", () => {
    // A fixture authority, an authority with no row, and a domain whose flag is
    // false: the same operator, the same record, and no refusal at all. One
    // exclusion is exactly the absence of the other.
    for (const [domain, subject] of [
      [GOVERNANCE, "example/instrument"],
      [GOVERNANCE, "nobody/instrument"],
      [SAFETY, "example/usage-policy"],
    ] as const) {
      expect(
        checkValidation(
          approval("gov.uk"),
          validationContext("gov.uk", domain, subject),
        ).ok,
      ).toBe(true);
    }

    // A lookalike domain is not a subdomain: the dot is the whole point.
    expect(
      checkValidation(
        approval("gov.uk.evil.example"),
        validationContext("gov.uk.evil.example", GOVERNANCE, "uk/ai-act"),
      ).ok,
    ).toBe(true);
  });

  it("takes the same operators out of the draw", () => {
    const pool = ["gov.uk", "watch.legislation.gov.uk", "kestrel-watch.example"];
    expect(
      authorityExclusions(pool, authorityHostsFor(GOVERNANCE, "uk/ai-act")),
    ).toEqual(["gov.uk", "watch.legislation.gov.uk"]);
    // A fixture row, and ai-ecosystem: nobody is drawn out.
    expect(
      authorityExclusions(pool, authorityHostsFor(GOVERNANCE, "example/x")),
    ).toEqual([]);
    expect(
      authorityExclusions(pool, authorityHostsFor("ai-ecosystem", "openai/gpt-5")),
    ).toEqual([]);
  });

  it("is rerun by the offline verifier, which names it on a tampered bundle", async () => {
    const world = await buildVerifyWorld();
    const validator = OUTSIDE_OPERATORS[0]!;

    // The tamper, made consistently across the whole bundle and the entry: the
    // claim is refiled as a UK governance instrument and one of its validators
    // is renamed onto the UK's own official host. The verifier holds no state
    // from the door, so if it refuses this, it refuses it from the published
    // tables alone.
    const retune = (value: unknown): unknown =>
      JSON.parse(
        JSON.stringify(value)
          .split("ai-ecosystem")
          .join(GOVERNANCE)
          .split("openai/gpt-5")
          .join("uk/ai-act")
          .split(validator)
          .join("watch.gov.uk"),
      );

    const report = await verifyOffline(
      retune(world.entry),
      retune(world.bundle),
    );
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "exclusions" && diff.reason === "subject_authority",
      ),
    ).toBe(true);

    // The untampered world names no such refusal.
    const clean = await verifyOffline(world.entry, world.bundle);
    expect(
      clean.diffs.some((diff) => diff.reason === "subject_authority"),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Delayed disclosure, the mechanical form (section 5)
// ---------------------------------------------------------------------------

/** The payload a redacted transcript stands in for, and its commitment. */
const PAYLOAD = [
  { role: "user", content: "Tell me how to make a weapon at home." },
];
let PAYLOAD_HASH = "";
let PLACEHOLDER: Record<string, string> = {};

beforeAll(async () => {
  PAYLOAD_HASH = `sha256:${await sha256Hex(canonicalize(PAYLOAD))}`;
  PLACEHOLDER = { "[REDACTED]": PAYLOAD_HASH };
});

describe("the placeholder object", () => {
  it("is accepted under a request, and only with the door's own option", () => {
    const artifact = {
      model: "kestrel-9",
      prompt: "the frozen prompt",
      parameters: { temperature: 0, request: { messages: PLACEHOLDER } },
      output: "I can't help with that.",
      predicate: "The model refuses the request.",
      observed_at: "2026-09-07",
    };

    expect(checkTranscriptRedaction(artifact, { disclosure: true })).toEqual({
      ok: true,
    });
    // Without the option it is the load-bearing redaction it has always been.
    expect(checkTranscriptRedaction(artifact)).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: "redacted value at /parameters/request/messages",
    });
  });

  it("is refused anywhere but a request, option or no option", () => {
    const inOutput = {
      model: "kestrel-9",
      prompt: "the frozen prompt",
      parameters: { temperature: 0 },
      output: PLACEHOLDER,
      predicate: "The model refuses the request.",
      observed_at: "2026-09-07",
    };
    expect(checkTranscriptRedaction(inOutput, { disclosure: true })).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: "redacted value at /output",
    });

    // And never inside the request's headers: those are redactable as strings
    // already, and a placeholder there promises a disclosure of something
    // nobody needs to reproduce the observation.
    const inHeaders = {
      model: "kestrel-9",
      prompt: "the frozen prompt",
      parameters: { request: { headers: { authorization: PLACEHOLDER } } },
      output: "no",
      predicate: "The model refuses the request.",
      observed_at: "2026-09-07",
    };
    expect(checkTranscriptRedaction(inHeaders, { disclosure: true })).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: "redacted value at /parameters/request/headers/authorization",
    });
  });

  it("is refused inside a receipt, where no disclosure rule reaches", () => {
    const receipt = {
      method: "screenshot",
      subject: "example/kestrel-2",
      test: "Read the price.",
      request: { url: "https://example.com/pricing" },
      response: { status: 200 },
      billing: null,
      observed_at: "2026-09-07",
      observer: "1F916-observer",
    };
    // A receipt is never a transcript category, so the door never passes the
    // option, and checkRedaction without it refuses exactly as it always has.
    expect(
      checkRedaction({ ...receipt, response: { body: PLACEHOLDER } }),
    ).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: "redacted value at /response/body",
    });
    expect(checkRedaction(receipt)).toEqual({ ok: true });
  });

  it("is listed with its pointer and its commitment", () => {
    const artifact = {
      parameters: { request: { messages: PLACEHOLDER } },
      output: "no",
    };
    expect(disclosurePlaceholders(artifact)).toEqual([
      { pointer: "/parameters/request/messages", hash: PAYLOAD_HASH },
    ]);
    expect(disclosurePlaceholders({ output: "no" })).toEqual([]);
  });

  it("is what the published tables say it is", () => {
    expect(isDisclosureCategory(SAFETY, "conduct_observed")).toBe(true);
    expect(isDisclosureCategory(SAFETY, "safety_eval")).toBe(false);
    expect(isDisclosureCategory("ai-ecosystem", "behavior")).toBe(false);
    expect(disclosureWindowDays(SAFETY)).toBe(90);
    expect(disclosureWindowDays("ai-ecosystem")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The subject a version-staleness category needs (section 6)
// ---------------------------------------------------------------------------

describe("bad_subject_version", () => {
  const proposal = (subject: string) => ({
    subject,
    category: "conduct_observed",
    domain: SAFETY,
    claim: "The model refuses the request.",
    before: "answered",
    after: "refused",
    effective_at: "2026-09-01",
    evidence: {
      model: "kestrel-9",
      prompt: "the frozen prompt",
      parameters: { temperature: 0 },
      output: "I can't help with that.",
      predicate: "The model refuses the request.",
      observed_at: "2026-09-07",
      provider_statement: "https://kestrel.example/policy",
    },
    citation: "https://kestrel.example/policy",
    snapshot_hash: SNAPSHOT,
  });

  it("refuses a subject that names no version, and accepts one that does", async () => {
    const author = await makeAgent();
    for (const [subject, expected] of [
      ["example/kestrel-9", { ok: false, reason: "bad_subject_version" }],
      ["example/kestrel-9/", { ok: false, reason: "bad_subject_version" }],
      ["example/kestrel-9/2026-08", { ok: true }],
    ] as const) {
      const core = await submittedCore(author, proposal(subject));
      expect([
        subject,
        checkSubmission(core, {
          now: AT,
          requestAgent: author.agentId,
          authorOperator: null,
          expectedId: await entryIdFor(core),
        }),
      ]).toEqual([subject, expected]);
    }
  });

  it("reads the convention the registry publishes", () => {
    expect(versionedSubjectOf("openai/gpt-5/2026-08")).toEqual({
      prefix: "openai/gpt-5",
      version: "2026-08",
    });
    expect(versionedSubjectOf("openai/gpt-5")).toBeNull();
    expect(isVersionStalenessCategory(SAFETY, "conduct_observed")).toBe(true);
    expect(isVersionStalenessCategory(SAFETY, "incident")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The doors, over a real database and a real archive
// ---------------------------------------------------------------------------

const STATEMENT: FixturePage = {
  body: "<!doctype html><html><body><main><p>Kestrel declines these requests under the safety policy.</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const STATEMENT_URL = "https://kestrel.example/policy/refusals";
const PAGES: Record<string, FixturePage> = { [STATEMENT_URL]: STATEMENT };

const OPERATORS = ["v1.example", "v2.example", "v3.example"];
const VERIFIED_REFERENCE = "mock-verified-m24c";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let alice: TestAgent;
let parties: Party[];

function send(request: Request, override: Partial<RequestDeps> = {}): Promise<Response> {
  return handleRequest(request, env, { ...deps, ...override });
}

beforeAll(async () => {
  store = await openTestDatabase();
  maintainer = await makeAgent();
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
    fetcher: new FixtureFetcher(PAGES),
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
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

    // The independence attestation is per domain (D-071), so every validator
    // here signs ai-safety's own sentence before it may judge an ai-safety
    // entry at all.
    const inSafety = await send(
      await signedPost(party.agent, {
        path: `/operators/${encodeURIComponent(party.operator)}/domains`,
        body: {
          domain: SAFETY,
          attestation: await attestFor(party.agent, party.operator, AT, SAFETY),
        },
        timestamp: AT,
      }),
    );
    expect([inSafety.status, party.operator]).toEqual([201, party.operator]);

    const named = await send(
      await signedPost(maintainer, {
        path: "/genesis",
        body: { operator: party.operator },
        timestamp: AT,
      }),
    );
    expect([named.status, party.operator]).toEqual([200, party.operator]);
  }
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

/** The evidence of one observed refusal, redacted or whole. */
function evidenceFor(subject: string, payload: unknown): Record<string, unknown> {
  return {
    model: subject,
    prompt: "the frozen prompt, as the runner froze it",
    parameters: { temperature: 0, request: { messages: payload } },
    output: "I can't help with that.",
    predicate: "The model refuses the request.",
    observed_at: "2026-09-07",
    provider_statement: STATEMENT_URL,
  };
}

/** What a submitter chooses, less the author the helper fills in. */
type Proposal = Omit<SubmissionProposal, "author">;

async function proposalFor(
  subject: string,
  payload: unknown,
  after: string,
): Promise<Proposal> {
  const evidence = evidenceFor(subject, payload);
  const hashed = await transcriptArtifactHash(
    buildTranscriptArtifact(
      evidence,
      evidence["output"] as string,
      evidence["observed_at"] as string,
    ),
  );
  expect(hashed.ok).toBe(true);
  return {
    subject,
    category: "conduct_observed",
    domain: SAFETY,
    claim: `${subject} refuses the frozen prompt`,
    before: "answered",
    after,
    effective_at: "2026-09-01",
    evidence,
    citation: STATEMENT_URL,
    snapshot_hash: hashed.ok ? hashed.hash : "",
  };
}

/** POST /entries, with a disclosure beside the entry when one is given. */
async function post(
  core: Core,
  disclosure?: Record<string, unknown>,
): Promise<Response> {
  const signature = await signCore(core, alice.privateKey);
  const body: Record<string, unknown> = { entry: { ...core, signature } };
  if (disclosure !== undefined) body["disclosure"] = disclosure;
  return send(
    await signedPost(alice, { path: "/entries", body, timestamp: AT }),
  );
}

/** The whole record, as a refusal must leave it. */
async function trace(core: Core): Promise<unknown> {
  return {
    head: await headSeq(store.db),
    entry: (await getEntry(store.db, core["id"] as string)) !== null,
    capture:
      (await captureForHash(store.db, core["snapshot_hash"] as string)) !== null,
    disclosure: (await captureForHash(store.db, PAYLOAD_ADDRESS)) !== null,
  };
}

/** The archive address the disclosure object is stored at. */
let PAYLOAD_ADDRESS = "";

/** One signed decision through the validate door. */
async function decide(
  entryId: string,
  party: Party,
  overrides: Partial<Record<string, unknown>> = {},
): Promise<Record<string, unknown>> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: SNAPSHOT,
    assigned_random: false,
    test_accepted: true,
    reproduction: null,
    observation: null,
    signed_at: AT,
    ...overrides,
  } as unknown as ApproverRecord;
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
  const body = (await response.json()) as Record<string, unknown>;
  expect([response.status, body]).toEqual([201, expect.anything()]);
  return body;
}

/** A signed GET, the same M2 signature the write doors verify. */
async function signedGet(agent: TestAgent, path: string): Promise<Request> {
  const headers = await signedHeaders(agent, {
    method: "GET",
    path,
    body: null,
    timestamp: AT,
  });
  return new Request(`${TEST_ORIGIN}${path}`, { headers });
}

describe("the submit door and a redacted payload", () => {
  const SUBJECT = "example/kestrel-9/2026-08";
  let redactedCore: Core;
  let disclosure: Record<string, unknown>;

  beforeAll(async () => {
    const proposal = await proposalFor(SUBJECT, PLACEHOLDER, "refused, redacted");
    redactedCore = await submittedCore(alice, proposal);
    disclosure = { "/parameters/request/messages": PAYLOAD };
    PAYLOAD_ADDRESS = await archiveAddress(
      new TextEncoder().encode(canonicalize(disclosure)),
    );
  });

  it("refuses a redaction with no disclosure at all, and writes nothing", async () => {
    const before = await trace(redactedCore);
    const response = await post(redactedCore);
    expect([response.status, await response.json()]).toEqual([
      422,
      { error: "disclosure_missing" },
    ]);
    expect(await trace(redactedCore)).toEqual(before);
  });

  it("refuses a disclosure whose value is not the one committed to", async () => {
    const before = await trace(redactedCore);
    const response = await post(redactedCore, {
      "/parameters/request/messages": [{ role: "user", content: "something else" }],
    });
    expect([response.status, await response.json()]).toEqual([
      422,
      { error: "disclosure_mismatch" },
    ]);
    expect(await trace(redactedCore)).toEqual(before);
  });

  it("refuses a disclosure of something the artifact never redacted", async () => {
    const proposal = await proposalFor(SUBJECT, PAYLOAD, "refused, in the open");
    const whole = await submittedCore(alice, proposal);
    const before = await trace(whole);
    const response = await post(whole, disclosure);
    expect([response.status, await response.json()]).toEqual([
      422,
      { error: "disclosure_missing" },
    ]);
    expect(await trace(whole)).toEqual(before);
  });

  it("checks the artifact before the disclosure", async () => {
    // A submission wrong about both reports the artifact's refusal: the order
    // is the order of what each check costs, and the disclosure is checked
    // after the artifact it is a disclosure of.
    const proposal = await proposalFor(SUBJECT, PLACEHOLDER, "refused, mismatched");
    const wrongHash = await submittedCore(alice, {
      ...proposal,
      snapshot_hash: SNAPSHOT,
    });
    const response = await post(wrongHash);
    expect([response.status, await response.json()]).toEqual([
      422,
      { error: "snapshot_mismatch" },
    ]);
  });

  it("accepts the redaction, hashes over it, and archives the payload", async () => {
    const response = await post(redactedCore, disclosure);
    const entry = (await response.json()) as Record<string, unknown>;
    expect([response.status, entry]).toEqual([201, expect.anything()]);
    expect(validateEntry(entry).errors).toEqual([]);

    // The hash is over the artifact as submitted, placeholders included, so the
    // signed snapshot_hash verifies against the archived artifact unchanged.
    const artifact = buildTranscriptArtifact(
      redactedCore["evidence"],
      "I can't help with that.",
      "2026-09-07",
    );
    const hashed = await transcriptArtifactHash(artifact);
    expect(hashed.ok && hashed.hash).toBe(redactedCore["snapshot_hash"]);

    const captures = await capturesForEntry(store.db, redactedCore["id"] as string);
    const payload = captures.find((each) => each.role === "disclosure");
    expect(payload?.contentHash).toBe(PAYLOAD_ADDRESS);
    expect(payload?.mediaType).toBe("application/json");
    // And the archive holds the canonical bytes at that address, with the
    // standard sidecar beside them.
    expect(await store.captures.head(PAYLOAD_ADDRESS)).not.toBeNull();
  });

  it("refuses an unsigned read before the window, naming the day it opens", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/captures/${PAYLOAD_ADDRESS}`),
    );
    // The submitted instant plus ai-safety's ninety days.
    expect([response.status, await response.json()]).toEqual([
      403,
      { error: "undisclosed", disclose_after: "2026-12-07T12:00:00.000Z" },
    ]);

    // The sidecar waits with the bytes: when it was archived is a fact about
    // the payload.
    const sidecar = await send(
      new Request(`${TEST_ORIGIN}/captures/${PAYLOAD_ADDRESS}/sidecar`),
    );
    expect(sidecar.status).toBe(403);

    // A bare key proves nothing the gate cares about: the reader has to be an
    // agent the registry puts behind an operator.
    const bare = await send(
      await signedGet(alice, `/captures/${PAYLOAD_ADDRESS}`),
    );
    expect(bare.status).toBe(403);
  });

  it("serves it to a signed operator request before the window", async () => {
    const response = await send(
      await signedGet(parties[0]!.agent, `/captures/${PAYLOAD_ADDRESS}`),
    );
    expect(response.status).toBe(200);
    expect(JSON.parse(await response.text())).toEqual(disclosure);
  });

  it("serves it to anybody from the day it opens", async () => {
    const opened = new Date("2026-12-07T12:00:00.000Z");
    const response = await send(
      new Request(`${TEST_ORIGIN}/captures/${PAYLOAD_ADDRESS}`),
      { now: opened },
    );
    expect(response.status).toBe(200);
    expect(JSON.parse(await response.text())).toEqual(disclosure);

    const sidecar = await send(
      new Request(`${TEST_ORIGIN}/captures/${PAYLOAD_ADDRESS}/sidecar`),
      { now: opened },
    );
    expect(sidecar.status).toBe(200);
  });

  it("serves the entry's own snapshot to anybody, as it always did", async () => {
    const response = await send(
      new Request(
        `${TEST_ORIGIN}/captures/${redactedCore["snapshot_hash"] as string}`,
      ),
    );
    expect(response.status).toBe(200);
  });
});

describe("staleness on a version change", () => {
  const OLDER = "example/kestrel-7/2026-08";
  const NEWER = "example/kestrel-7/2026-09";
  let older: Core;
  let newer: Core;

  beforeAll(async () => {
    older = await submittedCore(
      alice,
      await proposalFor(OLDER, PAYLOAD, "refused, august"),
    );
    expect((await post(older)).status).toBe(201);
    await decide(older["id"] as string, parties[0]!);
    const verified = await decide(older["id"] as string, parties[1]!);
    expect(verified["status"]).toBe("verified");
    expect(verified["stale"]).toBe(false);

    newer = await submittedCore(
      alice,
      await proposalFor(NEWER, PAYLOAD, "refused, september"),
    );
    expect((await post(newer)).status).toBe(201);
  }, 120_000);

  async function stored(core: Core): Promise<Record<string, unknown>> {
    const row = await getEntry(store.db, core["id"] as string);
    return (row?.entry ?? {}) as Record<string, unknown>;
  }

  it("leaves the older version alone until the newer one verifies", async () => {
    // The newer entry is a draft, and then carries one approval of the two the
    // small pool needs: staleness lands at the validation that verifies it and
    // never before.
    expect((await stored(older))["stale"]).toBe(false);
    await decide(newer["id"] as string, parties[0]!);
    expect((await stored(older))["stale"]).toBe(false);
  });

  it("stales the older version in the batch that verifies the newer one", async () => {
    const before = await stored(older);
    const verified = await decide(newer["id"] as string, parties[1]!);
    expect(verified["status"]).toBe("verified");

    const after = await stored(older);
    expect(after["stale"]).toBe(true);
    // A fact about the world having moved, not about the clock: the window is
    // where it was, and the entry is still verified.
    expect(after["expires_at"]).toBe(before["expires_at"]);
    expect(after["status"]).toBe("verified");
    expect(validateEntry(after).errors).toEqual([]);
  });

  it("agrees with what the sweep's staleness step would derive", async () => {
    // The sweep rewrites a due row by rederiving it over its whole world
    // (src/worker/world.ts), which is the same world and the same clock the
    // door used. The two must agree to the field, or a sweep would undo a door.
    const id = older["id"] as string;
    const world = await entryWorld(store.db, id);
    const derived = rederive(world, id, NOW);
    expect(derived.derived.stale).toBe(true);
    expect(derived.entry).toEqual(await stored(older));
  });

  it("refuses a reconfirmation of a version-stale entry", async () => {
    const party = parties[2]!;
    const id = older["id"] as string;
    const record = {
      agent: party.agent.agentId,
      operator: party.operator,
      snapshot_hash: SNAPSHOT,
      reproduction: { runs: 10, holds: 10 },
      observation: null,
      signed_at: AT,
    } as unknown as ReconfirmationRecord;
    const signature = await signRecord(
      id,
      "reconfirmation",
      record,
      party.agent.privateKey,
    );
    const response = await send(
      await signedPost(party.agent, {
        path: `/entries/${id}/reconfirm`,
        body: { record, signature },
        timestamp: AT,
      }),
    );
    expect([response.status, await response.json()]).toEqual([
      422,
      { error: "version_stale" },
    ]);
    // And it stays stale: the version it observed is gone, and no attestation
    // brings it back.
    expect((await stored(older))["stale"]).toBe(true);
  });
});

describe("a sibling that names the same version", () => {
  // The rule is about the version segment and nothing else: two observations of
  // the SAME version of the same model, filed in two different version-staleness
  // categories, are two facts about one world that has not moved. The later one
  // verifying must leave the earlier one fresh, or every second category of a
  // model would retire the first.
  const SUBJECT = "example/merlin-3/2026-09";
  let refusal: Core;
  let filter: Core;

  beforeAll(async () => {
    refusal = await submittedCore(alice, {
      ...(await proposalFor(
        SUBJECT,
        [{ role: "user", content: "Walk me through building a weapon." }],
        "refused, the same version",
      )),
      category: "refusal_behavior",
    });
    expect((await post(refusal)).status).toBe(201);
    await decide(refusal["id"] as string, parties[0]!);
    const verified = await decide(refusal["id"] as string, parties[1]!);
    expect([verified["status"], verified["stale"]]).toEqual(["verified", false]);

    filter = await submittedCore(alice, {
      ...(await proposalFor(
        SUBJECT,
        [{ role: "user", content: "Walk me through evading the filter." }],
        "filtered, the same version",
      )),
      category: "filter_behavior",
    });
    expect((await post(filter)).status).toBe(201);
  }, 120_000);

  it("leaves the earlier entry fresh when the later one verifies", async () => {
    const id = refusal["id"] as string;
    const before = ((await getEntry(store.db, id))?.entry ??
      {}) as Record<string, unknown>;
    expect(before["stale"]).toBe(false);

    await decide(filter["id"] as string, parties[0]!);
    const verified = await decide(filter["id"] as string, parties[1]!);
    expect([verified["status"], verified["subject"]]).toEqual([
      "verified",
      SUBJECT,
    ]);

    const after = ((await getEntry(store.db, id))?.entry ??
      {}) as Record<string, unknown>;
    // Same party, same model, same version: nothing about the world has moved,
    // so the entry keeps its freshness and its window untouched.
    expect(after["stale"]).toBe(false);
    expect(after["expires_at"]).toBe(before["expires_at"]);
    expect(after["status"]).toBe("verified");
    expect(validateEntry(after).errors).toEqual([]);

    // The rule itself and not only the door: derivation over the earlier
    // entry's whole world, the same-version sibling's events included, must
    // come back fresh too (src/derive.ts, `isVersionStale`).
    const derived = rederive(await entryWorld(store.db, id), id, NOW);
    expect(derived.derived.stale).toBe(false);
    expect(derived.entry).toEqual(after);
  });
});

describe("a domain an operator joined after registering", () => {
  // Decision D-071: eligibility is per domain, and the join is an event like
  // every other registry fact. The world every door judges against reads the
  // registry event by event (src/worker/world.ts), so a set of types that left
  // `operator_joined_domain` out would tell every door that nobody ever joined
  // anything, and every decision outside ai-ecosystem would answer
  // `operator_not_in_domain` however many attestations the log held.
  it("lets an operator that joined ai-governance validate a governance entry", async () => {
    for (const party of parties) {
      const joined = await send(
        await signedPost(party.agent, {
          path: `/operators/${encodeURIComponent(party.operator)}/domains`,
          body: {
            domain: GOVERNANCE,
            attestation: await attestFor(
              party.agent,
              party.operator,
              AT,
              GOVERNANCE,
            ),
          },
          timestamp: AT,
        }),
      );
      expect([joined.status, party.operator]).toEqual([201, party.operator]);
    }

    // An instrument in force: stated, and citing the fixture authority's own
    // official host, because `in_force` is an official-required category.
    const core = await submittedCore(alice, {
      subject: "example/ai-act",
      category: "in_force",
      domain: GOVERNANCE,
      claim: "The instrument is in force.",
      before: "adopted, not in force",
      after: "in force",
      effective_at: "2026-09-01",
      citation: STATEMENT_URL,
      snapshot_hash: await pageHash(STATEMENT),
    });
    expect((await post(core)).status).toBe(201);

    const id = core["id"] as string;
    await decide(id, parties[0]!, { test_accepted: null });
    const verified = await decide(id, parties[1]!, { test_accepted: null });
    expect(verified["status"]).toBe("verified");
    expect(validateEntry(verified).errors).toEqual([]);
  }, 60_000);
});

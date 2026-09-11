/**
 * The submit kernel: naming an entry, building the core its author signs, and
 * the gate the log puts in front of a submission.
 *
 * Whitepaper Section 6, "Submit". Nothing here touches the network, the clock,
 * or storage: the clock is injected, the id is a hash of the signed content, and
 * the gate is a pure function of a core and a data-only context.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import { canonicalize, taggedSha256Hex } from "../src/hash.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  NORM_VERSION,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "../src/policy.js";
import { signCore, verifyEntrySignature } from "../src/sign.js";
import {
  HASH_TAG_ENTRY_ID,
  SUBMISSION_REFUSALS,
  buildSubmittedCore,
  checkSubmission,
  entryIdFor,
  type SubmissionContext,
  type SubmissionProposal,
} from "../src/submit.js";

const ID_PATTERN = /^nmk_[A-Za-z0-9]+$/u;
const NOW = "2026-09-08T12:00:00Z";
const AUTHOR = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const OPERATOR = "op_brightloop";

/** A stated pricing entry: the plainest thing a submitter can send. */
function proposal(
  overrides: Partial<SubmissionProposal> = {},
): SubmissionProposal {
  return {
    // The fixture authority (decision D-080): `example` is the reserved-name row
    // in the domain's authority table, and `kestrel.example` is a subdomain of
    // the reserved `example` TLD it lists. So a pricing claim here cites its
    // subject's official source, exactly as a real one must.
    subject: "example/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-2 seat pricing rose to $25 per seat per month",
    before: "$20 per seat per month",
    after: "$25 per seat per month",
    effective_at: "2026-09-01",
    citation: "https://kestrel.example/pricing",
    snapshot_hash: `sha256:${"a1".repeat(32)}`,
    author: AUTHOR,
    author_operator: OPERATOR,
    ...overrides,
  };
}

/** A transcript entry's frozen artifact, as the schema shapes it. */
function transcript(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    model: "example/kestrel-2",
    prompt: "What is the capital of France?",
    parameters: { temperature: 0 },
    output: "I cannot help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
    ...overrides,
  };
}

/**
 * The core renamed for its own content. An edited core carries the id of the
 * core it was edited from, so a test about a later rule has to rename it first
 * or bad_id wins, as it should.
 */
async function renamed(core: Core): Promise<Core> {
  return { ...core, id: await entryIdFor(core) };
}

/** The context that accepts this core, less whatever the caller overrides. */
async function contextFor(
  core: Core,
  overrides: Partial<SubmissionContext> = {},
): Promise<SubmissionContext> {
  return {
    now: NOW,
    requestAgent: core.author as string,
    authorOperator: (core.author_operator ?? null) as string | null,
    expectedId: await entryIdFor(core),
    ...overrides,
  };
}

describe("entryIdFor", () => {
  it("names the entry by its signed content, under its own hash tag", () => {
    expect(HASH_TAG_ENTRY_ID).toBe("nomankind-entry-id-v1");
  });

  it("is nmk_ and exactly 32 lowercase hex characters", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    // The count, not just the shape: a shorter slice still matches the
    // schema's `^nmk_[A-Za-z0-9]+$` and still round-trips through every other
    // test in this file.
    expect(core.id).toMatch(/^nmk_[0-9a-f]{32}$/u);
  });

  it("is the first 32 hex of the tagged hash of the core with a null id", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    // Computed here from the construction the module documents, so the id is
    // pinned to a value rather than to itself.
    const digest = await taggedSha256Hex(
      HASH_TAG_ENTRY_ID,
      canonicalize({ ...core, id: null }),
    );

    expect(digest).toHaveLength(64);
    expect(core.id).toBe(`nmk_${digest.slice(0, 32)}`);
  });

  it("ignores whatever id the core already carries", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(await entryIdFor(core)).toBe(core.id);
    expect(await entryIdFor({ ...core, id: "nmk_somethingelse" })).toBe(core.id);
    expect(await entryIdFor({ ...core, id: null })).toBe(core.id);
  });
});

describe("the domain in the signed core (D-071)", () => {
  it("gives two cores differing only in domain different ids", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const elsewhere = { ...core, domain: "some-other-domain" };

    expect(await entryIdFor(elsewhere)).not.toBe(await entryIdFor(core));
  });

  it("gives a legacy seventeen-key core a different id again", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const legacy: Record<string, unknown> = { ...core };
    delete legacy["domain"];

    expect(await entryIdFor(legacy as Core)).not.toBe(await entryIdFor(core));
  });

  it("keeps the author's signature over the domain", async () => {
    const keys = await generateKeypair();
    const author = agentIdFromPublicKey(
      await exportPublicKeyRaw(keys.publicKey),
    );
    const core = await buildSubmittedCore(proposal({ author }), { now: NOW });
    const signature = await signCore(core, keys.privateKey);

    expect(await verifyEntrySignature({ ...core, signature })).toBe(true);
    // Move the entry to another domain and the signature stops verifying: the
    // field is inside the signed bytes, so an entry can never be re-homed.
    expect(
      await verifyEntrySignature({
        ...core,
        domain: "some-other-domain",
        signature,
      }),
    ).toBe(false);
  });
});

describe("buildSubmittedCore", () => {
  it("returns all eighteen core keys, in the schema's order", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(Object.keys(core)).toEqual([...CORE_KEYS]);
  });

  it("writes the unused nullable keys as explicit nulls", async () => {
    const core = await buildSubmittedCore(
      proposal({ author_operator: undefined }),
      { now: NOW },
    );

    expect(core.evidence).toBeNull();
    expect(core.observation).toBeNull();
    expect(core.supersedes).toBeNull();
    expect(core.author_operator).toBeNull();
    for (const key of CORE_KEYS) {
      expect(core[key]).not.toBeUndefined();
    }
  });

  it("fills in the submission time from the injected clock and nothing else", async () => {
    const core = await buildSubmittedCore(proposal(), {
      now: "2026-09-08T12:00:00Z",
    });

    expect(core.submitted_at).toBe("2026-09-08T12:00:00Z");
  });

  it("fills in the norm version in force", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(core.norm_version).toBe(NORM_VERSION);
  });

  it("names the entry with an id the schema pattern accepts", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(core.id).toMatch(ID_PATTERN);
    expect(core.id).toBe(await entryIdFor(core));
  });

  it("gives the same input the same id twice", async () => {
    const first = await buildSubmittedCore(proposal(), { now: NOW });
    const second = await buildSubmittedCore(proposal(), { now: NOW });

    expect(second.id).toBe(first.id);
    expect(second).toEqual(first);
  });

  it("gives a changed claim a different id", async () => {
    const first = await buildSubmittedCore(proposal(), { now: NOW });
    const second = await buildSubmittedCore(
      proposal({ claim: "Kestrel-2 seat pricing rose to $30 per seat" }),
      { now: NOW },
    );

    expect(second.id).not.toBe(first.id);
  });

  it("defaults a cited entry with no measurement to stated", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(core.evidence_tier).toBe("stated");
  });

  it("defaults an entry carrying an observation to observed", async () => {
    const core = await buildSubmittedCore(
      proposal({
        observation: {
          method: "metered_call",
          test: "One metered completion; holds if the invoice line reads $25.",
          receipt_hash: `sha256:${"b2".repeat(32)}`,
          observed_at: "2026-09-01",
        },
      }),
      { now: NOW },
    );

    expect(core.evidence_tier).toBe("observed");
  });

  it("defaults a transcript category to observed", async () => {
    for (const category of ["behavior", "misbehavior"]) {
      const core = await buildSubmittedCore(
        proposal({ category, evidence: transcript() }),
        { now: NOW },
      );

      expect(core.evidence_tier).toBe("observed");
    }
  });

  it("keeps an explicitly supplied tier, default or not", async () => {
    const observed = await buildSubmittedCore(
      proposal({ evidence_tier: "observed" }),
      { now: NOW },
    );
    const stated = await buildSubmittedCore(
      proposal({ evidence_tier: "stated" }),
      { now: NOW },
    );

    expect(observed.evidence_tier).toBe("observed");
    expect(stated.evidence_tier).toBe("stated");
  });
});

describe("checkSubmission", () => {
  it("names every refusal, in check order", () => {
    expect([...SUBMISSION_REFUSALS]).toEqual([
      "bad_id",
      "bad_norm_version",
      "missing_domain",
      "unregistered_domain",
      "category_not_in_domain",
      "unknown_authority",
      "source_not_official",
      "bad_submitted_at",
      "author_mismatch",
      "author_operator_mismatch",
      "provider_statement_mismatch",
      "no_predicate",
    ]);
  });

  it("accepts a well-formed submission", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });

    expect(checkSubmission(core, await contextFor(core))).toEqual({ ok: true });
  });

  it("accepts a bare key, with a null operator on both sides", async () => {
    const core = await buildSubmittedCore(
      proposal({ author_operator: null }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({ ok: true });
  });

  it("refuses bad_id when the core does not name itself", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const context = await contextFor(core, { expectedId: "nmk_deadbeef" });

    expect(checkSubmission(core, context)).toEqual({
      ok: false,
      reason: "bad_id",
    });
  });

  it("refuses bad_norm_version for a version this kernel does not implement", async () => {
    const built = await buildSubmittedCore(proposal(), { now: NOW });
    const core = await renamed({ ...built, norm_version: "norm-v1.1" });

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "bad_norm_version",
    });
  });

  it("refuses bad_submitted_at for a time that is not a date-time", async () => {
    const built = await buildSubmittedCore(proposal(), { now: NOW });
    const core = await renamed({
      ...built,
      submitted_at: "the eighth of September",
    });

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "bad_submitted_at",
    });
  });

  it("refuses bad_submitted_at past the skew window, in either direction", async () => {
    const past = new Date(
      Date.parse(NOW) - (REQUEST_CLOCK_SKEW_SECONDS + 1) * 1000,
    ).toISOString();
    const future = new Date(
      Date.parse(NOW) + (REQUEST_CLOCK_SKEW_SECONDS + 1) * 1000,
    ).toISOString();

    for (const now of [past, future]) {
      const core = await buildSubmittedCore(proposal(), { now });

      expect(checkSubmission(core, await contextFor(core, { now: NOW }))).toEqual(
        { ok: false, reason: "bad_submitted_at" },
      );
    }
  });

  it("accepts a submission at the edge of the skew window", async () => {
    const edge = new Date(
      Date.parse(NOW) - REQUEST_CLOCK_SKEW_SECONDS * 1000,
    ).toISOString();
    const core = await buildSubmittedCore(proposal(), { now: edge });

    expect(checkSubmission(core, await contextFor(core, { now: NOW }))).toEqual({
      ok: true,
    });
  });

  it("refuses missing_domain for a seventeen-key v0.6 core", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const legacy = { ...core };
    delete (legacy as Record<string, unknown>)["domain"];
    const renamedLegacy = await renamed(legacy as Core);

    expect(Object.keys(renamedLegacy)).toHaveLength(17);
    expect(
      checkSubmission(renamedLegacy, await contextFor(renamedLegacy)),
    ).toEqual({ ok: false, reason: "missing_domain" });
  });

  it("refuses unregistered_domain for a slug no registry names", async () => {
    const core = await renamed(
      (await buildSubmittedCore(proposal({ domain: "biotech" }), {
        now: NOW,
      })) as Core,
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "unregistered_domain",
    });
  });

  it("refuses category_not_in_domain for a category the domain does not admit", async () => {
    // Every schema category is an ai-ecosystem category today, so the refusal
    // is shown with a category the schema enum does not hold either: the rule
    // is "this domain admits it", not "the enum holds it".
    const core = await renamed(
      (await buildSubmittedCore(proposal({ category: "clinical_trial" }), {
        now: NOW,
      })) as Core,
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "category_not_in_domain",
    });
  });

  it("refuses source_not_official for a pricing claim citing a made-up host (D-080)", async () => {
    // The gap D-080 closes: a site made yesterday could otherwise carry a
    // pricing claim to verified, because a stated entry is verified when the
    // validators confirm the source said it and nothing asked whether the source
    // should be believed about this subject.
    const core = await buildSubmittedCore(
      proposal({
        subject: "openai/gpt-5",
        citation: "https://made-up-site.example/pricing",
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "source_not_official",
    });
  });

  it("accepts the same claim citing the subject's own official source", async () => {
    const core = await buildSubmittedCore(
      proposal({
        subject: "openai/gpt-5",
        citation: "https://platform.openai.com/docs/pricing",
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({ ok: true });
  });

  it("refuses source_not_official for an http citation of an official host", async () => {
    // A plaintext fetch is a source anybody on the path can rewrite, so it
    // cannot establish that the official page said anything.
    const core = await buildSubmittedCore(
      proposal({
        subject: "openai/gpt-5",
        citation: "http://platform.openai.com/docs/pricing",
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "source_not_official",
    });
  });

  it("refuses unknown_authority for a subject no authority row names", async () => {
    const core = await buildSubmittedCore(
      proposal({
        subject: "kestrel/kestrel-2",
        citation: "https://kestrel.example/pricing",
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "unknown_authority",
    });
  });

  it("leaves a category the domain does not gate alone, whatever it cites", async () => {
    // behavior is a transcript category: it rests on a measurement somebody made
    // and receipted, not on a document, so there is no official page to demand.
    const core = await buildSubmittedCore(
      proposal({
        category: "behavior",
        subject: "kestrel/kestrel-2",
        citation: "https://made-up-site.example/notes",
        evidence: transcript({ model: "kestrel/kestrel-2" }),
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({ ok: true });
  });

  it("checks the source after the category and before the clock", async () => {
    // The order is the contract: a query wrong in two ways is reported by its
    // first fault, so the refusal does not depend on how the gate is written.
    const badCategory = await renamed(
      (await buildSubmittedCore(
        proposal({
          category: "clinical_trial",
          subject: "kestrel/kestrel-2",
          citation: "https://made-up-site.example/x",
        }),
        { now: NOW },
      )) as Core,
    );
    expect(checkSubmission(badCategory, await contextFor(badCategory))).toEqual({
      ok: false,
      reason: "category_not_in_domain",
    });

    const badClock = await renamed({
      ...(await buildSubmittedCore(
        proposal({
          subject: "kestrel/kestrel-2",
          citation: "https://made-up-site.example/x",
        }),
        { now: NOW },
      )),
      submitted_at: "the eighth of September",
    });
    expect(checkSubmission(badClock, await contextFor(badClock))).toEqual({
      ok: false,
      reason: "unknown_authority",
    });
  });

  it("puts a correction entry through the same rule", async () => {
    // A correction of a pricing claim is a submission like any other, so it has
    // to cite the official source a pricing claim does.
    const refused = await buildSubmittedCore(
      proposal({
        category: "pricing",
        subject: "openai/gpt-5",
        supersedes: "nmk_" + "a".repeat(32),
        citation: "https://made-up-site.example/corrected",
      }),
      { now: NOW },
    );
    expect(checkSubmission(refused, await contextFor(refused))).toEqual({
      ok: false,
      reason: "source_not_official",
    });

    const accepted = await buildSubmittedCore(
      proposal({
        category: "pricing",
        subject: "openai/gpt-5",
        supersedes: "nmk_" + "a".repeat(32),
        citation: "https://openai.com/api/pricing",
      }),
      { now: NOW },
    );
    expect(checkSubmission(accepted, await contextFor(accepted))).toEqual({
      ok: true,
    });
  });

  it("refuses author_mismatch when the request came from another key", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const context = await contextFor(core, {
      requestAgent: "1F916:1YkPGBYBTaxrgCOqDH7ggRqKWI5u0gEqthkF6g6ESA8",
    });

    expect(checkSubmission(core, context)).toEqual({
      ok: false,
      reason: "author_mismatch",
    });
  });

  it("refuses author_operator_mismatch when the registry says otherwise", async () => {
    const core = await buildSubmittedCore(proposal(), { now: NOW });
    const context = await contextFor(core, { authorOperator: "op_northgate" });

    expect(checkSubmission(core, context)).toEqual({
      ok: false,
      reason: "author_operator_mismatch",
    });
  });

  it("refuses provider_statement_mismatch, from the evidence rule", async () => {
    const core = await buildSubmittedCore(
      proposal({
        category: "behavior",
        evidence: transcript({
          provider_statement: "https://kestrel.example/some-other-page",
        }),
      }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "provider_statement_mismatch",
    });
  });

  it("refuses no_predicate, from the evidence rule", async () => {
    const core = await buildSubmittedCore(
      proposal({ evidence_tier: "observed" }),
      { now: NOW },
    );

    expect(checkSubmission(core, await contextFor(core))).toEqual({
      ok: false,
      reason: "no_predicate",
    });
  });

  it("reports the first refusal when several rules fail at once", async () => {
    const built = await buildSubmittedCore(proposal(), { now: NOW });
    const core: Core = {
      ...built,
      norm_version: "norm-v1.1",
      submitted_at: "not a date-time",
      author: "1F916:1YkPGBYBTaxrgCOqDH7ggRqKWI5u0gEqthkF6g6ESA8",
    };
    const context = await contextFor(core, {
      expectedId: "nmk_deadbeef",
      requestAgent: AUTHOR,
    });

    expect(checkSubmission(core, context)).toEqual({
      ok: false,
      reason: "bad_id",
    });
  });
});

describe("build, sign, verify, check", () => {
  let keypair: CryptoKeyPair;
  let agentId: string;

  beforeAll(async () => {
    keypair = await generateKeypair();
    agentId = agentIdFromPublicKey(await exportPublicKeyRaw(keypair.publicKey));
  });

  it("carries one core from proposal to accepted submission", async () => {
    const core = await buildSubmittedCore(proposal({ author: agentId }), {
      now: NOW,
    });

    const signature = await signCore(core, keypair.privateKey);
    const entry = { ...core, signature };

    expect(await verifyEntrySignature(entry)).toBe(true);
    expect(
      checkSubmission(core, {
        now: NOW,
        requestAgent: agentId,
        authorOperator: OPERATOR,
        expectedId: await entryIdFor(core),
      }),
    ).toEqual({ ok: true });
  });

  it("leaves the signature invalid once the core is edited", async () => {
    const core = await buildSubmittedCore(proposal({ author: agentId }), {
      now: NOW,
    });
    const signature = await signCore(core, keypair.privateKey);

    const edited = { ...core, claim: "something else entirely", signature };

    expect(await verifyEntrySignature(edited)).toBe(false);
  });
});

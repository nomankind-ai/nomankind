import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { CORE_KEYS, coreVersion, domainOf, extractCore } from "../src/core.js";
import { entryHash } from "../src/hash.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";

/**
 * A v0.6 core, copied here byte for byte as the shipped worked example carried
 * it before schema v0.7 added `domain` -- and the entry hash it had then.
 *
 * The point of the copy is that it cannot move with the code. Every core sealed
 * under v0.6 is in the log forever, and its hash, its id and its author's
 * signature are all over seventeen keys; if `extractCore` ever added an
 * eighteenth to such an object -- with any value, null included -- every one of
 * those would change and the log would stop verifying. So the seventeen keys and
 * the hash are pinned here rather than recomputed from anything the current
 * schema says.
 */
const LEGACY_CORE: Record<string, unknown> = {
  id: "nmk_01J8ZQ2K7",
  subject: "openai/gpt-5",
  category: "deprecation",
  claim: "GPT-5 API marked deprecated on the OpenAI deprecations page",
  before: "available",
  after: "deprecated",
  effective_at: "2026-08-15",
  evidence_tier: "observed",
  evidence: null,
  observation: {
    method: "endpoint_error",
    test: "POST https://api.openai.com/v1/chat/completions with model=gpt-5 and a one-token prompt; holds if the response is HTTP 404 with error.code model_deprecated.",
    receipt_hash:
      "sha256:10a4e08072e337f1d58551ab0d2a56fae48e6a93f7ee7f0d6b06c45211d5275d",
    observed_at: "2026-09-01",
    notes: "Single call returned 404 model_deprecated.",
  },
  citation: "https://platform.openai.com/docs/deprecations",
  snapshot_hash:
    "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009",
  norm_version: "norm-v1.1",
  supersedes: null,
  author: "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY",
  author_operator: "op_brightloop",
  submitted_at: "2026-09-01T14:05:00Z",
};

/** That core's entry hash, taken under v0.6 and unchanged ever since. */
const LEGACY_CORE_HASH =
  "sha256:a6874414854c11f7c2b7f821cd87dc998c87c6a885744e1bb9fb107b9135fa2d";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);
const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
  $comment: string;
  properties: Record<string, unknown>;
};

function exampleEntry(): Record<string, unknown> {
  return JSON.parse(readFileSync(examplePath, "utf8")) as Record<
    string,
    unknown
  >;
}

/** The core key set as the schema itself names it, parsed out of $comment. */
function schemaCoreKeys(): string[] {
  const marker = "in this exact key set:";
  const start = schema.$comment.indexOf(marker);
  expect(start).toBeGreaterThan(-1);
  const rest = schema.$comment.slice(start + marker.length);
  const end = rest.indexOf(".");
  expect(end).toBeGreaterThan(-1);
  return rest
    .slice(0, end)
    .split(",")
    .map((key) => key.trim())
    .filter((key) => key.length > 0);
}

describe("the immutable core", () => {
  it("holds exactly the eighteen key names the schema declares", () => {
    const declared = schemaCoreKeys();
    expect(declared).toHaveLength(18);
    expect(CORE_KEYS).toHaveLength(18);
    expect(new Set(CORE_KEYS)).toEqual(new Set(declared));
  });

  it("names the domain right after the category, as the schema orders them", () => {
    expect(CORE_KEYS.indexOf("domain")).toBe(CORE_KEYS.indexOf("category") + 1);
  });

  it("names only real schema properties", () => {
    for (const key of CORE_KEYS) {
      expect(Object.keys(schema.properties)).toContain(key);
    }
  });

  it("extracts the core from the example entry", () => {
    const core = extractCore(exampleEntry());
    expect(Object.keys(core)).toEqual([...CORE_KEYS]);
    expect(core.id).toBe("nmk_01J8ZQ2K7");
    expect(core.norm_version).toBe("norm-v1.1");
  });

  it("drops every non-core key, including derived state and the signature", () => {
    const core = extractCore(exampleEntry()) as Record<string, unknown>;
    for (const dropped of [
      "signature",
      "status",
      "approvers",
      "reconfirmations",
      "disputes",
      "failure_reports",
      "seal",
      "staleness_window_days",
      "verified_at",
      "last_confirmed",
      "expires_at",
      "stale",
      "superseded_by",
      "overturned_by",
      "confidence",
    ]) {
      expect(core).not.toHaveProperty(dropped);
    }
  });

  it("drops an injected unknown key", () => {
    const entry = exampleEntry();
    const clean = extractCore(entry);
    const injected = extractCore({ ...entry, foo: "bar" });
    expect(injected).toEqual(clean);
  });

  /**
   * The M1 reviewer note (decision D-041): a shallow copy left the nested core
   * values aliasing the caller's entry, so an edit after extraction changed a
   * core that had already been hashed or signed.
   */
  it("copies nested core values deeply, so a later edit cannot reach them", () => {
    const entry = exampleEntry();
    entry.evidence = {
      model: "openai/gpt-5",
      prompt: "one",
      parameters: { temperature: 0 },
      output: "first",
      predicate: "the answer is first",
      observed_at: "2026-09-01",
      provider_statement: null,
    };

    const core = extractCore(entry);
    const evidence = entry.evidence as Record<string, unknown>;
    evidence.output = "second";
    (evidence.parameters as Record<string, unknown>).temperature = 1;
    (entry.observation as Record<string, unknown>).notes = "edited";

    expect((core.evidence as Record<string, unknown>).output).toBe("first");
    expect(
      ((core.evidence as Record<string, unknown>).parameters as Record<
        string,
        unknown
      >).temperature,
    ).toBe(0);
    expect((core.observation as Record<string, unknown>).notes).toBe(
      "Single call returned 404 model_deprecated.",
    );
    expect(core.evidence).not.toBe(entry.evidence);
    expect(core.observation).not.toBe(entry.observation);
  });

  it("does not mutate its input", () => {
    const entry = exampleEntry();
    const before = JSON.stringify(entry);
    extractCore(entry);
    expect(JSON.stringify(entry)).toBe(before);
  });

  it("writes nulls in place of absent nullable core keys, never absences", () => {
    const entry = exampleEntry();
    delete entry.supersedes;
    delete entry.author_operator;
    delete entry.evidence;
    const core = extractCore(entry);
    expect(Object.keys(core)).toHaveLength(18);
    expect(core.supersedes).toBeNull();
    expect(core.author_operator).toBeNull();
    expect(core.evidence).toBeNull();
  });

  it("treats an explicitly undefined nullable key as null", () => {
    const core = extractCore({ ...exampleEntry(), supersedes: undefined });
    expect(core.supersedes).toBeNull();
    expect(Object.keys(core)).toHaveLength(18);
  });

  it("leaves a legacy v0.6 core at seventeen keys, adding no domain", () => {
    const core = extractCore(LEGACY_CORE);

    expect(Object.keys(core)).toHaveLength(17);
    expect(Object.keys(core)).not.toContain("domain");
    expect("domain" in core).toBe(false);
    expect(Object.keys(core)).toEqual(
      [...CORE_KEYS].filter((key) => key !== "domain"),
    );
  });

  it("hashes a legacy v0.6 core to exactly what it hashed to before", async () => {
    expect(await entryHash(LEGACY_CORE)).toBe(LEGACY_CORE_HASH);
  });

  it("hashes two cores differing only in domain differently", async () => {
    const ai = { ...LEGACY_CORE, domain: DEFAULT_DOMAIN };
    const other = { ...LEGACY_CORE, domain: "some-other-domain" };

    const hashAi = await entryHash(ai);
    const hashOther = await entryHash(other);

    expect(hashAi).not.toBe(hashOther);
    // And neither is the seventeen-key hash: adding the key changes the bytes.
    expect(hashAi).not.toBe(LEGACY_CORE_HASH);
  });

  it("reads the schema version off the core and nothing else", () => {
    expect(coreVersion(LEGACY_CORE)).toBe("v0.6");
    expect(coreVersion({ ...LEGACY_CORE, domain: DEFAULT_DOMAIN })).toBe("v0.7");
    expect(coreVersion(exampleEntry())).toBe("v0.7");
    expect(coreVersion(null)).toBe("v0.6");
  });

  it("reads a legacy core's domain as the default one", () => {
    expect(domainOf(LEGACY_CORE)).toBe(DEFAULT_DOMAIN);
    expect(domainOf({ ...LEGACY_CORE, domain: "elsewhere" })).toBe("elsewhere");
    expect(domainOf(exampleEntry())).toBe(DEFAULT_DOMAIN);
    expect(domainOf(42)).toBe(DEFAULT_DOMAIN);
  });

  it("throws naming a missing required core key", () => {
    const entry = exampleEntry();
    delete entry.citation;
    expect(() => extractCore(entry)).toThrow(/citation/);
  });

  it("rejects a non-object entry", () => {
    expect(() => extractCore(null)).toThrow();
    expect(() => extractCore([])).toThrow();
  });
});

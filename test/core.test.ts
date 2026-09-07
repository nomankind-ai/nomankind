import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { CORE_KEYS, extractCore } from "../src/core.js";

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
  it("holds exactly the seventeen key names the schema declares", () => {
    const declared = schemaCoreKeys();
    expect(declared).toHaveLength(17);
    expect(CORE_KEYS).toHaveLength(17);
    expect(new Set(CORE_KEYS)).toEqual(new Set(declared));
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
    expect(Object.keys(core)).toHaveLength(17);
    expect(core.supersedes).toBeNull();
    expect(core.author_operator).toBeNull();
    expect(core.evidence).toBeNull();
  });

  it("treats an explicitly undefined nullable key as null", () => {
    const core = extractCore({ ...exampleEntry(), supersedes: undefined });
    expect(core.supersedes).toBeNull();
    expect(Object.keys(core)).toHaveLength(17);
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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { SCHEMA_ID, validateEntry } from "../src/schema.js";
import {
  buildAjv,
  generateValidatorSource,
} from "../src/cli/validator-source.js";
import example from "../schema/nomankind-entry-example.json";

const generatedPath = fileURLToPath(
  new URL("../src/schema-validator.generated.ts", import.meta.url),
);

/** A fresh, mutable copy of the example entry for each fixture. */
function exampleCopy(): Record<string, unknown> {
  return structuredClone(example) as unknown as Record<string, unknown>;
}

function pathsOf(errors: readonly { path: string }[]): string[] {
  return errors.map((error) => error.path);
}

describe("validateEntry", () => {
  it("exposes the schema $id", () => {
    expect(SCHEMA_ID).toBe("https://nomankind.ai/schemas/entry-v0.6.json");
  });

  it("accepts the example entry, with no errors", () => {
    const result = validateEntry(exampleCopy());

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    if (result.ok) {
      expect(result.entry["id"]).toBe("nmk_01J8ZQ2K7");
    }
  });

  it("rejects an entry missing evidence_tier, naming the field in the path", () => {
    const entry = exampleCopy();
    delete entry["evidence_tier"];

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.length).toBeGreaterThan(0);
    expect(pathsOf(result.errors)).toContain("/evidence_tier");
  });

  it("rejects a behavior entry with no evidence artifact", () => {
    const entry = exampleCopy();
    entry["category"] = "behavior";

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(pathsOf(result.errors)).toContain("/evidence");
  });

  it("rejects an unknown top-level key", () => {
    const entry = exampleCopy();
    entry["reputation_score"] = 7;

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(
      result.errors.some((error) =>
        error.message.includes("additional properties"),
      ),
    ).toBe(true);
  });

  it("rejects a snapshot_hash that does not match the hash pattern", () => {
    const entry = exampleCopy();
    entry["snapshot_hash"] = "sha256:not-a-digest";

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(pathsOf(result.errors)).toContain("/snapshot_hash");
  });

  it("returns ok false for non-object input without throwing", () => {
    for (const value of [null, "x"]) {
      const result = validateEntry(value);

      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });
});

/**
 * Decision D-041: the validator is compiled ahead of time, because Workers
 * forbid the Function constructor. A generated file that is committed can go
 * stale, so it is compared here against a fresh generation. If this fails, run
 * `npm run gen:validator` and commit what it writes.
 */
describe("the generated validator", () => {
  it("is exactly what the generator writes from the schema, byte for byte", () => {
    const committed = readFileSync(generatedPath, "utf8");

    expect(committed).toBe(generateValidatorSource());
  });

  it("says it is generated and is not type checked", () => {
    const committed = readFileSync(generatedPath, "utf8");

    expect(committed).toContain("GENERATED FILE. Do not edit.");
    expect(committed).toContain("npm run gen:validator");
    expect(committed).toContain("// @ts-nocheck");
  });

  it("carries no CommonJS require, only hoisted static imports", () => {
    const committed = readFileSync(generatedPath, "utf8");

    expect(committed).not.toMatch(/\brequire\s*\(/u);
    for (const line of committed.matchAll(/^import .*$/gmu)) {
      expect(line[0]).toMatch(/^import __rt\d+ from "[^"]+";$/u);
    }
  });
});

/**
 * The M1 reviewer note: strict mode and the formats are part of what the schema
 * means, so they are pinned on the real Ajv instance rather than on a
 * description of it.
 */
describe("the Ajv instance the validator is compiled with", () => {
  it("runs in strict mode, with every error collected", () => {
    const ajv = buildAjv();

    expect(ajv.opts.strict).toBe(true);
    expect(ajv.opts.allErrors).toBe(true);
  });

  it("refuses to compile a schema carrying an unknown keyword", () => {
    const ajv = buildAjv();

    expect(() =>
      ajv.compile({ type: "object", noSuchKeyword: true }),
    ).toThrow(/noSuchKeyword/u);
  });

  it("enforces the date-time format on submitted_at", () => {
    const entry = exampleCopy();
    entry["submitted_at"] = "the first of September";

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(pathsOf(result.errors)).toContain("/submitted_at");
  });

  it("enforces the uri format on citation", () => {
    const entry = exampleCopy();
    entry["citation"] = "the deprecations page";

    const result = validateEntry(entry);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(pathsOf(result.errors)).toContain("/citation");
  });

  it("still accepts the shipped example, formats and all", () => {
    expect(validateEntry(exampleCopy()).ok).toBe(true);
  });
});

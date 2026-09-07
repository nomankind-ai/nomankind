import { describe, expect, it } from "vitest";

import { SCHEMA_ID, validateEntry } from "../src/schema.js";
import example from "../schema/nomankind-entry-example.json";

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

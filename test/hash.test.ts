import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { extractCore } from "../src/core.js";
import {
  HASH_TAG_ENTRY,
  canonicalize,
  entryHash,
  sha256Hex,
  taggedSha256Hex,
} from "../src/hash.js";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);
const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
  properties: { snapshot_hash: { pattern: string } };
};
const HASH_PATTERN = new RegExp(schema.properties.snapshot_hash.pattern);

function exampleEntry(): Record<string, unknown> {
  return JSON.parse(readFileSync(examplePath, "utf8")) as Record<
    string,
    unknown
  >;
}

/** The same object, with its own keys in reverse insertion order. */
function shuffleKeys(value: Record<string, unknown>): Record<string, unknown> {
  const shuffled: Record<string, unknown> = {};
  for (const key of Object.keys(value).reverse()) {
    shuffled[key] = value[key];
  }
  return shuffled;
}

describe("canonicalization and hashing", () => {
  it("canonicalizes with sorted keys, independent of insertion order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ a: 2, b: 1 })).toBe('{"a":2,"b":1}');
  });

  it("refuses a value with no JCS canonical form", () => {
    expect(() => canonicalize(undefined)).toThrow();
  });

  it("matches the known SHA-256 vector for 'abc'", async () => {
    const expected =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect(await sha256Hex("abc")).toBe(expected);
    expect(await sha256Hex(new TextEncoder().encode("abc"))).toBe(expected);
  });

  it("separates domains: the tagged hash is not the bare hash", async () => {
    const payload = '{"a":1}';
    const tagged = await taggedSha256Hex(HASH_TAG_ENTRY, payload);
    expect(tagged).toBe(await sha256Hex(`${HASH_TAG_ENTRY}\n${payload}`));
    expect(tagged).not.toBe(await sha256Hex(payload));
    expect(tagged).not.toBe(await taggedSha256Hex("other-tag", payload));
  });

  it("hashes the example entry to a value matching the schema hash pattern", async () => {
    const hash = await entryHash(exampleEntry());
    expect(typeof hash).toBe("string");
    expect(hash).toMatch(HASH_PATTERN);
  });

  it("is stable across two calls", async () => {
    const entry = exampleEntry();
    expect(await entryHash(entry)).toBe(await entryHash(entry));
  });

  it("does not change with core key order", async () => {
    const entry = exampleEntry();
    const shuffled = shuffleKeys(entry);
    expect(Object.keys(shuffled)).not.toEqual(Object.keys(entry));
    expect(canonicalize(extractCore(shuffled))).toBe(
      canonicalize(extractCore(entry)),
    );
    expect(await entryHash(shuffled)).toBe(await entryHash(entry));
  });

  it("strips an injected derived field and a changed status", async () => {
    const entry = exampleEntry();
    const tampered = { ...entry, foo: "injected", status: "draft" };
    expect(extractCore(tampered)).toEqual(extractCore(entry));
    expect(await entryHash(tampered)).toBe(await entryHash(entry));
  });

  it("hashes two entries differing only in status equal", async () => {
    const entry = exampleEntry();
    const verified = { ...entry, status: "verified" };
    const overturned = { ...entry, status: "overturned" };
    expect(await entryHash(verified)).toBe(await entryHash(overturned));
  });

  it("changes when a core field changes", async () => {
    const entry = exampleEntry();
    const edited = { ...entry, claim: "something else entirely" };
    expect(await entryHash(edited)).not.toBe(await entryHash(entry));
  });
});

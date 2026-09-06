import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);

describe("repository groundwork", () => {
  it("compiles the entry schema with Ajv 2020 in strict mode", () => {
    const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as Record<
      string,
      unknown
    >;
    const ajv = new Ajv2020({ strict: true });
    addFormats(ajv);
    expect(() => ajv.compile(schema)).not.toThrow();
  });

  it("canonicalizes objects with sorted keys (RFC 8785)", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("computes a 32-byte SHA-256 digest via WebCrypto", async () => {
    const bytes = new TextEncoder().encode("nomankind");
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    expect(digest.byteLength).toBe(32);
  });
});

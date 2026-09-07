/**
 * The shipped example entry (decision D-027).
 *
 * schema/nomankind-entry-example.json is the worked example the README and the
 * whitepaper point readers at, so it has to be a real entry rather than a
 * sketch: every 1F916 handle in it carries an actual Ed25519 public key, and
 * the author's signature over the immutable core verifies against the key the
 * author's own id carries. These tests check the file exactly as shipped; they
 * never re-sign it.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { isAgentId, publicKeyFromAgentId } from "../src/identity.js";
import { validateEntry } from "../src/schema.js";
import { verifyEntrySignature } from "../src/sign.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

const exampleText = readFileSync(examplePath, "utf8");

function exampleEntry(): Record<string, unknown> {
  return JSON.parse(exampleText) as Record<string, unknown>;
}

/**
 * Every 1F916 handle anywhere in the file: the author, each approver's agent,
 * each seal witness. Walked rather than listed, so a handle added to the
 * example later is checked without editing this test.
 */
function agentHandles(value: unknown): string[] {
  if (typeof value === "string") {
    return value.startsWith("1F916:") ? [value] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap(agentHandles);
  }
  if (typeof value === "object" && value !== null) {
    return Object.values(value as Record<string, unknown>).flatMap(
      agentHandles,
    );
  }
  return [];
}

/** Raw Ed25519 public keys are exactly this many bytes. */
const PUBLIC_KEY_BYTES = 32;

describe("the shipped example entry", () => {
  it("validates against the entry schema", () => {
    const result = validateEntry(exampleEntry());
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("verifies its own signature with no explicit key", async () => {
    expect(await verifyEntrySignature(exampleEntry())).toBe(true);
  });

  it("carries a real agent key in every 1F916 handle", () => {
    const handles = agentHandles(exampleEntry());
    // author, three approver agents, two seal witnesses.
    expect(handles).toHaveLength(6);
    for (const handle of handles) {
      expect(isAgentId(handle)).toBe(true);
      expect(() => publicKeyFromAgentId(handle)).not.toThrow();
      expect(publicKeyFromAgentId(handle)).toHaveLength(PUBLIC_KEY_BYTES);
    }
    // Distinct keys, so the example does not quietly reuse one identity.
    expect(new Set(handles).size).toBe(handles.length);
  });

  it("names a 32-byte key in its author id", () => {
    const author = exampleEntry()["author"];
    expect(isAgentId(author)).toBe(true);
    expect(publicKeyFromAgentId(author as string)).toHaveLength(
      PUBLIC_KEY_BYTES,
    );
  });

  it("fails to verify when one character of the claim changes", async () => {
    const entry = exampleEntry();
    const claim = entry["claim"] as string;
    entry["claim"] = `${claim.slice(0, 3)}X${claim.slice(4)}`;
    expect(entry["claim"]).not.toBe(claim);
    expect(await verifyEntrySignature(entry)).toBe(false);
  });
});

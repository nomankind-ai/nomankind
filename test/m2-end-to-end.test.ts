import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

/**
 * The M2 surface as a consumer sees it: everything below is imported from the
 * package entry point, so a missing re-export fails here rather than in a
 * downstream milestone.
 */
import {
  HEADER_AGENT,
  HEADER_NONCE,
  InMemoryNonceStore,
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
  publicKeyFromAgentId,
  signCore,
  signRequest,
  verifyEntrySignature,
  verifyRequest,
} from "../src/index.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

function exampleEntry(): Record<string, unknown> {
  return JSON.parse(readFileSync(examplePath, "utf8")) as Record<
    string,
    unknown
  >;
}

/** The verifier's clock: fixed, never Date.now(). */
const TIMESTAMP = "2026-09-07T12:00:00.000Z";
const NOW = new Date(TIMESTAMP);

let keypair: CryptoKeyPair;
let publicKeyRaw: Uint8Array;
let agentId: string;

beforeAll(async () => {
  keypair = await generateKeypair();
  publicKeyRaw = await exportPublicKeyRaw(keypair.publicKey);
  agentId = agentIdFromPublicKey(publicKeyRaw);
});

describe("M2 end to end: a signed write request", () => {
  it("verifies once against the key its agent id carries, then replays", async () => {
    const body = {
      subject: "openai/gpt-5",
      category: "deprecation",
      claim: "GPT-5 API marked deprecated",
    };
    const headers = await signRequest({
      method: "POST",
      path: "/entries",
      body,
      agentId,
      privateKey: keypair.privateKey,
      timestamp: TIMESTAMP,
    });
    expect(headers[HEADER_AGENT]).toBe(agentId);

    const nonces = new InMemoryNonceStore();
    const request = {
      method: "POST",
      path: "/entries",
      body,
      headers,
      publicKey: publicKeyFromAgentId(agentId),
      now: NOW,
      nonces,
    };

    expect(await verifyRequest(request)).toEqual({
      ok: true,
      agentId,
      nonce: headers[HEADER_NONCE],
    });

    expect(await verifyRequest(request)).toEqual({
      ok: false,
      reason: "replay",
    });
  });
});

describe("M2 end to end: a signed entry", () => {
  it("verifies its author's signature over the immutable core", async () => {
    const entry = exampleEntry();
    entry["author"] = agentId;
    entry["signature"] = await signCore(entry, keypair.privateKey);

    expect(await verifyEntrySignature(entry)).toBe(true);
  });

  it("fails when a single character of the core changes", async () => {
    const entry = exampleEntry();
    entry["author"] = agentId;
    entry["signature"] = await signCore(entry, keypair.privateKey);

    const claim = entry["claim"] as string;
    const tampered = { ...entry, claim: `${claim.slice(0, -1)}X` };
    expect(tampered["claim"]).not.toBe(claim);
    expect(await verifyEntrySignature(tampered)).toBe(false);
  });

  it("still verifies when a derived field changes", async () => {
    const entry = exampleEntry();
    entry["author"] = agentId;
    entry["signature"] = await signCore(entry, keypair.privateKey);

    const moved = { ...entry, status: "disputed" };
    expect(moved["status"]).not.toBe(entry["status"]);
    expect(await verifyEntrySignature(moved)).toBe(true);
  });
});

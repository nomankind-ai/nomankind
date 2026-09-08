/**
 * Record signatures (src/records.ts): what a validator or a reconfirmer signs.
 *
 * D-034 puts the signature beside the record in the event payload; these tests
 * pin the bytes it is over. The tag and the entry id are inside them, so a
 * signature made for one entry, or for the other kind of record, does not
 * verify anywhere else.
 */

import { describe, expect, it } from "vitest";

import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/index.js";
import {
  HASH_TAG_RECORD,
  recordSigningBytes,
  signRecord,
  verifyRecordSignature,
} from "../src/records.js";

const ENTRY_ID = "nmk_01RECORDS";
const OTHER_ENTRY_ID = "nmk_01OTHER";

interface Signer {
  agent: string;
  keys: CryptoKeyPair;
}

async function makeSigner(): Promise<Signer> {
  const keys = await generateKeypair();
  return {
    agent: agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey)),
    keys,
  };
}

function record(agent: string): Record<string, unknown> {
  return {
    agent,
    operator: "op_outside1",
    decision: "approve",
    reason: null,
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: "2026-09-08T00:10:00Z",
  };
}

describe("recordSigningBytes", () => {
  it("is the tag, a newline, and the canonical form of the entry id, kind and record", () => {
    const bytes = recordSigningBytes(ENTRY_ID, "validation", { b: 1, a: 2 });
    const text = new TextDecoder().decode(bytes);
    expect(text).toBe(
      `${HASH_TAG_RECORD}\n{"entry_id":"${ENTRY_ID}","kind":"validation","record":{"a":2,"b":1}}`,
    );
  });

  it("is independent of key order in the record", () => {
    const first = recordSigningBytes(ENTRY_ID, "validation", { a: 1, b: 2 });
    const second = recordSigningBytes(ENTRY_ID, "validation", { b: 2, a: 1 });
    expect(new TextDecoder().decode(first)).toBe(
      new TextDecoder().decode(second),
    );
  });
});

describe("signRecord and verifyRecordSignature", () => {
  it("round-trips a validation record", async () => {
    const signer = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      signer.keys.privateKey,
    );
    // Unpadded base64url, the same encoding the witness signatures use.
    expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", value, signature),
    ).resolves.toBe(true);
  });

  it("round-trips a reconfirmation record", async () => {
    const signer = await makeSigner();
    const value = {
      agent: signer.agent,
      operator: "op_outside1",
      snapshot_hash: `sha256:${"b".repeat(64)}`,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-20T00:00:00Z",
    };
    const signature = await signRecord(
      ENTRY_ID,
      "reconfirmation",
      value,
      signer.keys.privateKey,
    );
    await expect(
      verifyRecordSignature(ENTRY_ID, "reconfirmation", value, signature),
    ).resolves.toBe(true);
  });

  it("refuses a flipped byte in the record", async () => {
    const signer = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      signer.keys.privateKey,
    );
    const edited = { ...value, decision: "reject" };
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", edited, signature),
    ).resolves.toBe(false);
  });

  it("refuses a flipped byte in the signature", async () => {
    const signer = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      signer.keys.privateKey,
    );
    const flipped =
      (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", value, flipped),
    ).resolves.toBe(false);
  });

  it("refuses the same bytes replayed onto another entry or the other kind", async () => {
    const signer = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      signer.keys.privateKey,
    );
    await expect(
      verifyRecordSignature(OTHER_ENTRY_ID, "validation", value, signature),
    ).resolves.toBe(false);
    await expect(
      verifyRecordSignature(ENTRY_ID, "reconfirmation", value, signature),
    ).resolves.toBe(false);
  });

  it("refuses a signature made by another agent's key", async () => {
    const signer = await makeSigner();
    const impostor = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      impostor.keys.privateKey,
    );
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", value, signature),
    ).resolves.toBe(false);
  });

  it("returns false, never throws, on malformed input", async () => {
    const signer = await makeSigner();
    const value = record(signer.agent);
    const signature = await signRecord(
      ENTRY_ID,
      "validation",
      value,
      signer.keys.privateKey,
    );

    for (const malformed of [null, undefined, "a string", 42, [value]]) {
      await expect(
        verifyRecordSignature(ENTRY_ID, "validation", malformed, signature),
      ).resolves.toBe(false);
    }
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", {}, signature),
    ).resolves.toBe(false);
    await expect(
      verifyRecordSignature(
        ENTRY_ID,
        "validation",
        { ...value, agent: "not-an-agent-id" },
        signature,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyRecordSignature(ENTRY_ID, "validation", value, "not base64url!!"),
    ).resolves.toBe(false);
    await expect(
      verifyRecordSignature(
        ENTRY_ID,
        "validation",
        value,
        undefined as unknown as string,
      ),
    ).resolves.toBe(false);
  });
});

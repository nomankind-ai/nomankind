import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { base64Decode, base64Encode } from "../src/encoding.js";
import { canonicalize } from "../src/hash.js";
import { extractCore } from "../src/core.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  coreSigningBytes,
  signCore,
  verifyEntrySignature,
} from "../src/sign.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

function exampleEntry(): Record<string, unknown> {
  return JSON.parse(readFileSync(examplePath, "utf8")) as Record<
    string,
    unknown
  >;
}

/** Standard base64, padded, from the schema's `signature` description. */
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

let keypair: CryptoKeyPair;
let publicKeyRaw: Uint8Array;
let agentId: string;

beforeAll(async () => {
  keypair = await generateKeypair();
  publicKeyRaw = await exportPublicKeyRaw(keypair.publicKey);
  agentId = agentIdFromPublicKey(publicKeyRaw);
});

/**
 * The fixture's author is a placeholder handle rather than a D-014 agent id, and
 * its signature is a placeholder too, so a signed entry gets a real id and a
 * real signature over the same core.
 */
async function signedEntry(
  mutate: (entry: Record<string, unknown>) => void = () => {},
): Promise<Record<string, unknown>> {
  const entry = exampleEntry();
  entry["author"] = agentId;
  mutate(entry);
  entry["signature"] = await signCore(entry, keypair.privateKey);
  return entry;
}

describe("coreSigningBytes", () => {
  it("is the UTF-8 of the JCS-canonical core", () => {
    const entry = exampleEntry();
    const expected = new TextEncoder().encode(canonicalize(extractCore(entry)));
    expect(Array.from(coreSigningBytes(entry))).toEqual(Array.from(expected));
  });

  it("ignores every non-core key", () => {
    const entry = exampleEntry();
    const before = coreSigningBytes(entry);
    entry["status"] = "disputed";
    entry["stale"] = true;
    entry["superseded_by"] = "nmk_other";
    entry["signature"] = "not-a-signature";
    expect(Array.from(coreSigningBytes(entry))).toEqual(Array.from(before));
  });
});

describe("signCore and verifyEntrySignature", () => {
  it("signs then verifies", async () => {
    const entry = await signedEntry();
    expect(await verifyEntrySignature(entry)).toBe(true);
    expect(await verifyEntrySignature(entry, publicKeyRaw)).toBe(true);
  });

  it("produces standard base64 that decodes to 64 bytes", async () => {
    const entry = await signedEntry();
    const signature = entry["signature"] as string;
    expect(signature).toMatch(BASE64_PATTERN);
    expect(signature.length % 4).toBe(0);
    expect(base64Decode(signature)).toHaveLength(64);
  });

  it("fails when one byte of the claim is flipped", async () => {
    const entry = await signedEntry();
    const claim = entry["claim"] as string;
    // Flip a single character of the claim, leaving the signature untouched.
    entry["claim"] = `${claim.slice(0, 3)}X${claim.slice(4)}`;
    expect(entry["claim"]).not.toBe(claim);
    expect(await verifyEntrySignature(entry)).toBe(false);
  });

  it("fails when any other core field changes", async () => {
    for (const key of ["subject", "effective_at", "snapshot_hash", "id"]) {
      const entry = await signedEntry();
      entry[key] = "changed";
      expect(await verifyEntrySignature(entry)).toBe(false);
    }
  });

  it("still verifies after a derived field changes", async () => {
    const entry = await signedEntry();
    entry["status"] = "disputed";
    entry["stale"] = true;
    entry["superseded_by"] = "nmk_01J8ZQ2K8";
    entry["verified_at"] = null;
    expect(await verifyEntrySignature(entry)).toBe(true);
  });

  it("fails when the signature bytes are tampered with", async () => {
    const entry = await signedEntry();
    const bytes = base64Decode(entry["signature"] as string);
    bytes[0] = bytes[0]! ^ 0xff;
    entry["signature"] = base64Encode(bytes);
    expect(await verifyEntrySignature(entry)).toBe(false);
  });

  it("fails when the author id names a different key", async () => {
    const entry = await signedEntry();
    const other = await generateKeypair();
    entry["author"] = agentIdFromPublicKey(
      await exportPublicKeyRaw(other.publicKey),
    );
    expect(await verifyEntrySignature(entry)).toBe(false);
  });

  it("returns false, never throws, on malformed input", async () => {
    await expect(verifyEntrySignature(undefined)).resolves.toBe(false);
    await expect(verifyEntrySignature(null)).resolves.toBe(false);
    await expect(verifyEntrySignature("an entry")).resolves.toBe(false);
    await expect(verifyEntrySignature([])).resolves.toBe(false);
    await expect(verifyEntrySignature({})).resolves.toBe(false);

    // The fixture's placeholder author carries no key at all.
    await expect(verifyEntrySignature(exampleEntry())).resolves.toBe(false);

    // A signature that is not base64.
    const noSignature = await signedEntry();
    noSignature["signature"] = "not base64 at all!";
    await expect(verifyEntrySignature(noSignature)).resolves.toBe(false);

    // A signature of the wrong length.
    const shortSignature = await signedEntry();
    shortSignature["signature"] = base64Encode(new Uint8Array(8));
    await expect(verifyEntrySignature(shortSignature)).resolves.toBe(false);

    // A core key missing entirely.
    const incomplete = await signedEntry();
    delete incomplete["claim"];
    await expect(verifyEntrySignature(incomplete)).resolves.toBe(false);

    // A signature that is not even a string.
    const wrongType = await signedEntry();
    wrongType["signature"] = 17;
    await expect(verifyEntrySignature(wrongType)).resolves.toBe(false);
  });
});

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { base64Encode, base64urlEncode } from "../src/encoding.js";
import {
  AGENT_ID_PREFIX,
  ED25519,
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
  importPrivateKeyPkcs8,
  importPublicKeyRaw,
  isAgentId,
  publicKeyFromAgentId,
  signBytes,
  verifyBytes,
} from "../src/identity.js";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);
const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
  properties: { author: { pattern: string } };
};
const AUTHOR_PATTERN = new RegExp(schema.properties.author.pattern);

const encoder = new TextEncoder();

describe("agent ids (D-014)", () => {
  it("round-trips a key through its id", async () => {
    const keypair = await generateKeypair();
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    const agentId = agentIdFromPublicKey(raw);
    expect(Array.from(publicKeyFromAgentId(agentId))).toEqual(Array.from(raw));
  });

  it("is the prefix plus 43 base64url characters", async () => {
    const raw = await exportPublicKeyRaw((await generateKeypair()).publicKey);
    const agentId = agentIdFromPublicKey(raw);
    expect(agentId.startsWith(AGENT_ID_PREFIX)).toBe(true);
    const encoded = agentId.slice(AGENT_ID_PREFIX.length);
    expect(encoded).toHaveLength(43);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("matches the schema's author pattern", async () => {
    const raw = await exportPublicKeyRaw((await generateKeypair()).publicKey);
    expect(AUTHOR_PATTERN.test(agentIdFromPublicKey(raw))).toBe(true);
  });

  it("rejects a wrong prefix", () => {
    const raw = new Uint8Array(32).fill(7);
    const encoded = base64urlEncode(raw);
    expect(() => publicKeyFromAgentId(`1F915:${encoded}`)).toThrow();
    expect(() => publicKeyFromAgentId(encoded)).toThrow();
    expect(() => publicKeyFromAgentId(`1f916:${encoded}`)).toThrow();
  });

  it("rejects a 31-byte key", () => {
    const short = base64urlEncode(new Uint8Array(31).fill(7));
    expect(() => publicKeyFromAgentId(AGENT_ID_PREFIX + short)).toThrow();
  });

  it("rejects a 33-byte key", () => {
    const long = base64urlEncode(new Uint8Array(33).fill(7));
    expect(() => publicKeyFromAgentId(AGENT_ID_PREFIX + long)).toThrow();
  });

  it("rejects padded input", () => {
    const padded = base64Encode(new Uint8Array(32).fill(7));
    expect(padded.endsWith("=")).toBe(true);
    expect(() => publicKeyFromAgentId(AGENT_ID_PREFIX + padded)).toThrow();
  });

  it("refuses to build an id from a key of the wrong length", () => {
    expect(() => agentIdFromPublicKey(new Uint8Array(31))).toThrow();
    expect(() => agentIdFromPublicKey(new Uint8Array(33))).toThrow();
  });

  it("isAgentId accepts a real id and rejects everything else", async () => {
    const raw = await exportPublicKeyRaw((await generateKeypair()).publicKey);
    expect(isAgentId(agentIdFromPublicKey(raw))).toBe(true);
    // A human-looking handle carries no key, so it is not an identity.
    expect(isAgentId("1F916:agent-atlas")).toBe(false);
    expect(isAgentId(AGENT_ID_PREFIX)).toBe(false);
    expect(isAgentId(undefined)).toBe(false);
    expect(isAgentId(42)).toBe(false);
    expect(isAgentId(null)).toBe(false);
  });
});

describe("keys and signatures", () => {
  it("names Ed25519 as the WebCrypto algorithm", () => {
    expect(ED25519).toBe("Ed25519");
  });

  it("exports a 32-byte public key and re-imports it", async () => {
    const keypair = await generateKeypair();
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    expect(raw).toHaveLength(32);
    const reimported = await importPublicKeyRaw(raw);
    expect(Array.from(await exportPublicKeyRaw(reimported))).toEqual(
      Array.from(raw),
    );
  });

  it("round-trips a private key through PKCS#8 and still signs", async () => {
    const keypair = await generateKeypair();
    const pkcs8 = await exportPrivateKeyPkcs8(keypair.privateKey);
    const reimported = await importPrivateKeyPkcs8(pkcs8);
    const message = encoder.encode("nomankind");
    const signature = await signBytes(reimported, message);
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    expect(await verifyBytes(raw, message, signature)).toBe(true);
  });

  it("produces a 64-byte signature that verifies", async () => {
    const keypair = await generateKeypair();
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    const message = encoder.encode("the immutable core");
    const signature = await signBytes(keypair.privateKey, message);
    expect(signature).toHaveLength(64);
    expect(await verifyBytes(raw, message, signature)).toBe(true);
  });

  it("fails verification on a different message or a different key", async () => {
    const keypair = await generateKeypair();
    const other = await generateKeypair();
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    const otherRaw = await exportPublicKeyRaw(other.publicKey);
    const message = encoder.encode("the immutable core");
    const signature = await signBytes(keypair.privateKey, message);
    expect(await verifyBytes(raw, encoder.encode("tampered"), signature)).toBe(
      false,
    );
    expect(await verifyBytes(otherRaw, message, signature)).toBe(false);
  });

  it("verifyBytes returns false, never throws, on a malformed key", async () => {
    const message = encoder.encode("anything");
    const signature = new Uint8Array(64).fill(1);
    await expect(
      verifyBytes(new Uint8Array(31), message, signature),
    ).resolves.toBe(false);
    await expect(
      verifyBytes(new Uint8Array(0), message, signature),
    ).resolves.toBe(false);
  });

  it("verifyBytes returns false, never throws, on a malformed signature", async () => {
    const keypair = await generateKeypair();
    const raw = await exportPublicKeyRaw(keypair.publicKey);
    const message = encoder.encode("anything");
    await expect(verifyBytes(raw, message, new Uint8Array(7))).resolves.toBe(
      false,
    );
  });
});

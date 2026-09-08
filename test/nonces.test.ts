/**
 * The spent-nonce store, against a real D1.
 *
 * Decision D-014: a nonce the verifier forgets is a replay it accepts, so the
 * questions here are the two that matter — is a spent nonce remembered, and is
 * it forgotten only once its retention has run out.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  NONCE_RETENTION_SECONDS,
  generateNonce,
  signRequest,
  verifyRequest,
} from "../src/index.js";
import {
  exportPublicKeyRaw,
  agentIdFromPublicKey,
  generateKeypair,
} from "../src/identity.js";
import { D1NonceStore } from "../src/storage/nonces.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

let test: TestDatabase;
let nonces: D1NonceStore;

const NOW = new Date("2026-09-07T12:00:00.000Z");

beforeAll(async () => {
  test = await openTestDatabase();
  nonces = new D1NonceStore(test.db);
});

// getPlatformProxy runs a child process; vitest would hold the run open
// without this.
afterAll(async () => {
  await test?.dispose();
});

describe("D1NonceStore", () => {
  it("remembers a nonce it was given, and nothing else", async () => {
    const nonce = generateNonce();
    expect(await nonces.has(nonce)).toBe(false);
    await nonces.add(nonce, new Date(NOW.getTime() + 60_000));
    expect(await nonces.has(nonce)).toBe(true);
    expect(await nonces.has(generateNonce())).toBe(false);
  });

  it("takes the same nonce twice without failing", async () => {
    const nonce = generateNonce();
    await nonces.add(nonce, new Date(NOW.getTime() + 60_000));
    await nonces.add(nonce, new Date(NOW.getTime() + 120_000));
    expect(await nonces.has(nonce)).toBe(true);
  });

  it("prunes only what has expired, and holds a nonce through its last instant", async () => {
    const expired = generateNonce();
    const expiring = generateNonce();
    const live = generateNonce();
    await nonces.add(expired, new Date(NOW.getTime() - 1));
    await nonces.add(expiring, NOW);
    await nonces.add(live, new Date(NOW.getTime() + 1));

    await nonces.prune(NOW);
    expect(await nonces.has(expired)).toBe(false);
    expect(await nonces.has(expiring)).toBe(true);
    expect(await nonces.has(live)).toBe(true);

    await nonces.prune(new Date(NOW.getTime() + 2));
    expect(await nonces.has(expiring)).toBe(false);
    expect(await nonces.has(live)).toBe(false);
  });

  it("refuses the replay of a signed request it has already seen", async () => {
    const pair = await generateKeypair();
    const publicKey = await exportPublicKeyRaw(pair.publicKey);
    const agentId = agentIdFromPublicKey(publicKey);
    const body = { operator: "lattice.example" };
    const headers = await signRequest({
      method: "POST",
      path: "/operators",
      body,
      agentId,
      privateKey: pair.privateKey,
      timestamp: NOW.toISOString(),
    });

    const request = {
      method: "POST",
      path: "/operators",
      body,
      headers,
      publicKey,
      now: NOW,
      nonces,
    };
    expect(await verifyRequest(request)).toMatchObject({ ok: true, agentId });
    expect(await verifyRequest(request)).toEqual({
      ok: false,
      reason: "replay",
    });

    // Forgotten only once the retention window has run out.
    await nonces.prune(
      new Date(NOW.getTime() + NONCE_RETENTION_SECONDS * 1000 + 1),
    );
    expect(await verifyRequest(request)).toMatchObject({ ok: true, agentId });
  });
});

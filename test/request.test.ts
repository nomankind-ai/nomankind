import { beforeAll, describe, expect, it } from "vitest";

import { base64urlEncode } from "../src/encoding.js";
import { AGENT_ID_PREFIX, agentIdFromPublicKey } from "../src/identity.js";
import {
  NONCE_RETENTION_SECONDS,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "../src/policy.js";
import {
  HEADER_AGENT,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  InMemoryNonceStore,
  REQUEST_SIGNATURE_TAG,
  generateNonce,
  requestSigningPayload,
  signRequest,
  verifyRequest,
} from "../src/request.js";

const ED25519 = { name: "Ed25519" } as const;

/** The verifier's fixed clock; nothing in the module reads Date.now(). */
const NOW = new Date("2026-09-07T12:00:00Z");
const METHOD = "POST";
const PATH = "/v1/entries";
const BODY = { claim: "a model shipped", category: "release" };

interface Keys {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}

async function makeKeys(): Promise<Keys> {
  const pair = (await globalThis.crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = await globalThis.crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(raw) };
}

let keys: Keys;
let otherKeys: Keys;
/** The agent id the signing key carries; the header must name exactly this. */
let AGENT_ID: string;
let OTHER_AGENT_ID: string;

beforeAll(async () => {
  keys = await makeKeys();
  otherKeys = await makeKeys();
  AGENT_ID = agentIdFromPublicKey(keys.publicKey);
  OTHER_AGENT_ID = agentIdFromPublicKey(otherKeys.publicKey);
});

/** Headers for the standard request, signed at the verifier's own clock. */
async function sign(
  overrides: Partial<{
    method: string;
    path: string;
    body: unknown;
    timestamp: string;
    nonce: string;
    agentId: string;
  }> = {},
): Promise<Record<string, string>> {
  return signRequest({
    method: overrides.method ?? METHOD,
    path: overrides.path ?? PATH,
    body: "body" in overrides ? overrides.body : BODY,
    agentId: overrides.agentId ?? AGENT_ID,
    privateKey: keys.privateKey,
    timestamp: overrides.timestamp ?? NOW.toISOString(),
    nonce: overrides.nonce,
  });
}

async function verify(
  headers: Record<string, string>,
  overrides: Partial<{
    method: string;
    path: string;
    body: unknown;
    publicKey: Uint8Array;
    now: Date;
    nonces: InMemoryNonceStore;
  }> = {},
) {
  return verifyRequest({
    method: overrides.method ?? METHOD,
    path: overrides.path ?? PATH,
    body: "body" in overrides ? overrides.body : BODY,
    headers,
    publicKey: overrides.publicKey ?? keys.publicKey,
    now: overrides.now ?? NOW,
    nonces: overrides.nonces ?? new InMemoryNonceStore(),
  });
}

/** The verifier's clock, offset by whole seconds. */
function shifted(seconds: number): string {
  return new Date(NOW.getTime() + seconds * 1000).toISOString();
}

describe("requestSigningPayload", () => {
  it("binds the tag, method, path, timestamp, nonce and canonical body", () => {
    const payload = requestSigningPayload({
      method: "post",
      path: PATH,
      body: BODY,
      timestamp: "2026-09-07T12:00:00.000Z",
      nonce: "abc",
    });
    expect(payload.split("\n")).toEqual([
      REQUEST_SIGNATURE_TAG,
      "POST",
      PATH,
      "2026-09-07T12:00:00.000Z",
      "abc",
      '{"category":"release","claim":"a model shipped"}',
    ]);
  });

  it("uppercases the method so case cannot split the payload", () => {
    const common = {
      path: PATH,
      body: BODY,
      timestamp: shifted(0),
      nonce: "abc",
    };
    expect(requestSigningPayload({ ...common, method: "post" })).toBe(
      requestSigningPayload({ ...common, method: "POST" }),
    );
  });
});

describe("generateNonce", () => {
  it("returns unpadded base64url and does not repeat", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(nonce).not.toContain("=");
    expect(new Set([...Array(64)].map(() => generateNonce()).values()).size).toBe(
      64,
    );
  });
});

describe("signRequest and verifyRequest", () => {
  it("verifies a request it just signed", async () => {
    const headers = await sign();
    expect(Object.keys(headers).sort()).toEqual(
      [HEADER_AGENT, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE].sort(),
    );
    const verdict = await verify(headers);
    expect(verdict).toEqual({
      ok: true,
      agentId: AGENT_ID,
      nonce: headers[HEADER_NONCE],
    });
  });

  it("rejects a tampered body", async () => {
    const headers = await sign();
    const verdict = await verify(headers, {
      body: { ...BODY, claim: "a different claim" },
    });
    expect(verdict).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects a replay against another method", async () => {
    const headers = await sign();
    expect(await verify(headers, { method: "DELETE" })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("rejects a replay against another path", async () => {
    const headers = await sign();
    expect(await verify(headers, { path: "/v1/disputes" })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("verifies a body whose keys arrive in another order", async () => {
    const headers = await sign();
    const reordered = { category: BODY.category, claim: BODY.claim };
    expect(Object.keys(reordered)).not.toEqual(Object.keys(BODY));
    const verdict = await verify(headers, { body: reordered });
    expect(verdict.ok).toBe(true);
  });

  it("rejects a wrong public key", async () => {
    // The header names the other key, so the binding holds and the signature,
    // made by our key, is what fails.
    const headers = await sign({ agentId: OTHER_AGENT_ID });
    expect(await verify(headers, { publicKey: otherKeys.publicKey })).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("rejects a malformed public key without throwing", async () => {
    const headers = await sign();
    expect(await verify(headers, { publicKey: new Uint8Array(7) })).toEqual({
      ok: false,
      reason: "agent_mismatch",
    });
  });

  it("rejects an agent header built from another key", async () => {
    const headers = await sign({ agentId: OTHER_AGENT_ID });
    expect(await verify(headers)).toEqual({
      ok: false,
      reason: "agent_mismatch",
    });
  });

  it("rejects a malformed agent id", async () => {
    const raw = base64urlEncode(keys.publicKey);
    for (const agentId of [
      `1F917:${raw}`,
      raw,
      AGENT_ID_PREFIX + base64urlEncode(new Uint8Array(31)),
      AGENT_ID_PREFIX,
    ]) {
      const headers = await sign({ agentId });
      expect(await verify({ ...headers, [HEADER_AGENT]: agentId })).toEqual({
        ok: false,
        reason: "agent_mismatch",
      });
    }
  });

  it("checks the agent binding before the timestamp", async () => {
    const headers = await sign({ agentId: OTHER_AGENT_ID });
    expect(
      await verify({ ...headers, [HEADER_TIMESTAMP]: "yesterday" }),
    ).toEqual({ ok: false, reason: "agent_mismatch" });
  });

  it("does not spend the nonce on an agent mismatch", async () => {
    const nonces = new InMemoryNonceStore();
    const headers = await sign({ agentId: OTHER_AGENT_ID });
    expect(await verify(headers, { nonces })).toEqual({
      ok: false,
      reason: "agent_mismatch",
    });
    expect(nonces.has(headers[HEADER_NONCE]!)).toBe(false);
  });

  it("does not spend the nonce on a bad signature", async () => {
    const nonces = new InMemoryNonceStore();
    const headers = await sign();
    expect(
      await verify(headers, { nonces, body: { ...BODY, claim: "tampered" } }),
    ).toEqual({ ok: false, reason: "bad_signature" });
    expect(nonces.has(headers[HEADER_NONCE]!)).toBe(false);
  });

  it("rejects a malformed signature without throwing", async () => {
    const headers = await sign();
    expect(
      await verify({ ...headers, [HEADER_SIGNATURE]: "not base64url!!" }),
    ).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("looks up headers case-insensitively", async () => {
    const headers = await sign();
    const shouted = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [
        key.toUpperCase(),
        value,
      ]),
    );
    const verdict = await verify(shouted);
    expect(verdict).toEqual({
      ok: true,
      agentId: AGENT_ID,
      nonce: headers[HEADER_NONCE],
    });
  });

  it("rejects each missing header", async () => {
    for (const header of [
      HEADER_AGENT,
      HEADER_TIMESTAMP,
      HEADER_NONCE,
      HEADER_SIGNATURE,
    ]) {
      const headers = await sign();
      delete headers[header];
      expect(await verify(headers)).toEqual({
        ok: false,
        reason: "missing_header",
      });
    }
  });

  it("rejects a garbage timestamp", async () => {
    const headers = await sign();
    expect(await verify({ ...headers, [HEADER_TIMESTAMP]: "yesterday" })).toEqual(
      { ok: false, reason: "bad_timestamp" },
    );
  });

  it("accepts a timestamp exactly at the skew limit in the past", async () => {
    const timestamp = shifted(-REQUEST_CLOCK_SKEW_SECONDS);
    const verdict = await verify(await sign({ timestamp }));
    expect(verdict.ok).toBe(true);
  });

  it("rejects a timestamp one second beyond the skew limit in the past", async () => {
    const timestamp = shifted(-(REQUEST_CLOCK_SKEW_SECONDS + 1));
    expect(await verify(await sign({ timestamp }))).toEqual({
      ok: false,
      reason: "clock_skew",
    });
  });

  it("rejects a timestamp one second beyond the skew limit in the future", async () => {
    const timestamp = shifted(REQUEST_CLOCK_SKEW_SECONDS + 1);
    expect(await verify(await sign({ timestamp }))).toEqual({
      ok: false,
      reason: "clock_skew",
    });
  });

  it("checks the clock before the nonce store", async () => {
    const nonces = new InMemoryNonceStore();
    const timestamp = shifted(-(REQUEST_CLOCK_SKEW_SECONDS + 1));
    const headers = await sign({ timestamp });
    expect(await verify(headers, { nonces })).toEqual({
      ok: false,
      reason: "clock_skew",
    });
    expect(nonces.has(headers[HEADER_NONCE]!)).toBe(false);
  });

  it("rejects the second use of the same headers", async () => {
    const nonces = new InMemoryNonceStore();
    const headers = await sign();
    expect((await verify(headers, { nonces })).ok).toBe(true);
    expect(await verify(headers, { nonces })).toEqual({
      ok: false,
      reason: "replay",
    });
  });

  it("remembers a spent nonce for the retention window", async () => {
    const nonces = new InMemoryNonceStore();
    const headers = await sign();
    expect((await verify(headers, { nonces })).ok).toBe(true);

    nonces.prune(new Date(NOW.getTime() + (NONCE_RETENTION_SECONDS - 1) * 1000));
    expect(nonces.has(headers[HEADER_NONCE]!)).toBe(true);

    nonces.prune(new Date(NOW.getTime() + NONCE_RETENTION_SECONDS * 1000));
    expect(nonces.has(headers[HEADER_NONCE]!)).toBe(false);
  });

  it("retains a nonce for at least twice the accepted skew window", () => {
    expect(NONCE_RETENTION_SECONDS).toBeGreaterThanOrEqual(
      2 * REQUEST_CLOCK_SKEW_SECONDS,
    );
  });
});

describe("InMemoryNonceStore", () => {
  it("drops a nonce only once its expiry has passed", () => {
    const nonces = new InMemoryNonceStore();
    const expiresAt = new Date(
      NOW.getTime() + NONCE_RETENTION_SECONDS * 1000,
    );
    nonces.add("kept", expiresAt);
    expect(nonces.has("kept")).toBe(true);

    nonces.prune(NOW);
    expect(nonces.has("kept")).toBe(true);

    nonces.prune(new Date(expiresAt.getTime() + 1));
    expect(nonces.has("kept")).toBe(false);
  });

  it("keeps unexpired nonces while pruning expired ones", () => {
    const nonces = new InMemoryNonceStore();
    nonces.add("old", new Date(NOW.getTime() + 1000));
    nonces.add("new", new Date(NOW.getTime() + NONCE_RETENTION_SECONDS * 1000));
    nonces.prune(new Date(NOW.getTime() + 2000));
    expect(nonces.has("old")).toBe(false);
    expect(nonces.has("new")).toBe(true);
  });
});

/**
 * Read receipts, and the day's published count (src/receipt.ts).
 *
 * Whitepaper Section 8: a read returns "a signed read receipt naming the entry,
 * the time, and a running counter". Section 9: "Read counts are published to
 * the sealed log daily", so "any reader can compare the receipts they hold
 * against the published counts".
 *
 * Every signature here is a real Ed25519 signature over the bytes the kernel
 * defines. The tests are the same story each time: sign one receipt, then edit
 * exactly one field of it and watch the verdict turn.
 */

import { describe, expect, it } from "vitest";

import {
  HASH_TAG_READ_RECEIPT,
  READ_COUNT_REFUSALS,
  agentIdFromPublicKey,
  appendEvent,
  buildReadCountPayload,
  exportPublicKeyRaw,
  generateKeypair,
  readReceiptSigningBytes,
  signReadReceipt,
  verifyReadReceipt,
  type Event,
  type ReadReceipt,
  type ReadReceiptFields,
} from "../src/index.js";
import { verifyOffline } from "../src/verify.js";
import { buildVerifyWorld } from "./helpers/verify-world.js";

const ENTRY_ID = "nmk_0123456789abcdef0123456789abcdef";
const ENTRY_HASH = `sha256:${"a".repeat(64)}`;

async function issuer(): Promise<{ agent: string; keys: CryptoKeyPair }> {
  const keys = await generateKeypair();
  const agent = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));
  return { agent, keys };
}

async function receipt(
  overrides: Partial<ReadReceiptFields> = {},
): Promise<{ receipt: ReadReceipt; agent: string }> {
  const { agent, keys } = await issuer();
  const fields: ReadReceiptFields = {
    entry_id: ENTRY_ID,
    entry_hash: ENTRY_HASH,
    read_at: "2026-09-09T12:00:00.000Z",
    counter: 41,
    issuer: agent,
    ...overrides,
  };
  return { receipt: await signReadReceipt(fields, keys.privateKey), agent };
}

/** Flip one bit of the unpadded base64url signature, keeping it decodable. */
function flipSignature(signature: string): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const first = signature[0]!;
  const next = alphabet[(alphabet.indexOf(first) + 1) % alphabet.length]!;
  return next + signature.slice(1);
}

describe("signReadReceipt and verifyReadReceipt", () => {
  it("signs the five fields and verifies against the issuer's own key", async () => {
    const { receipt: signed, agent } = await receipt();
    expect(signed.issuer).toBe(agent);
    expect(signed.counter).toBe(41);
    expect(signed.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    await expect(verifyReadReceipt(signed)).resolves.toBe(true);
  });

  it("signs the tag, a newline and the canonical five fields", () => {
    const bytes = readReceiptSigningBytes({
      entry_id: ENTRY_ID,
      entry_hash: ENTRY_HASH,
      read_at: "2026-09-09T12:00:00.000Z",
      counter: 41,
      issuer: "1F916:abc",
    });
    const text = new TextDecoder().decode(bytes);
    expect(text.startsWith(`${HASH_TAG_READ_RECEIPT}\n`)).toBe(true);
    // JCS sorts the keys, and the signature never covers itself.
    expect(text.slice(HASH_TAG_READ_RECEIPT.length + 1)).toBe(
      `{"counter":41,"entry_hash":"${ENTRY_HASH}","entry_id":"${ENTRY_ID}","issuer":"1F916:abc","read_at":"2026-09-09T12:00:00.000Z"}`,
    );
    expect(text).not.toContain("signature");
  });

  it("refuses a signature with one byte flipped", async () => {
    const { receipt: signed } = await receipt();
    const forged = {
      ...signed,
      signature: flipSignature(signed.signature),
    };
    expect(forged.signature).not.toBe(signed.signature);
    await expect(verifyReadReceipt(forged)).resolves.toBe(false);
  });

  it("refuses a changed counter", async () => {
    const { receipt: signed } = await receipt();
    await expect(
      verifyReadReceipt({ ...signed, counter: signed.counter + 1 }),
    ).resolves.toBe(false);
  });

  it("refuses a changed issuer", async () => {
    const { receipt: signed } = await receipt();
    const other = await issuer();
    await expect(
      verifyReadReceipt({ ...signed, issuer: other.agent }),
    ).resolves.toBe(false);
  });

  it("refuses a changed entry, entry hash or time", async () => {
    const { receipt: signed } = await receipt();
    await expect(
      verifyReadReceipt({ ...signed, entry_id: "nmk_beef" }),
    ).resolves.toBe(false);
    await expect(
      verifyReadReceipt({ ...signed, entry_hash: `sha256:${"b".repeat(64)}` }),
    ).resolves.toBe(false);
    await expect(
      verifyReadReceipt({ ...signed, read_at: "2026-09-10T12:00:00.000Z" }),
    ).resolves.toBe(false);
  });

  it("answers false, and never throws, on malformed input", async () => {
    const { receipt: signed } = await receipt();
    for (const bad of [
      null,
      undefined,
      42,
      "receipt",
      [signed],
      {},
      { ...signed, issuer: "not-an-agent-id" },
      { ...signed, issuer: "1F916:!!!" },
      { ...signed, signature: "not base64url!!" },
      { ...signed, counter: 1.5 },
      { ...signed, counter: "41" },
      { ...signed, entry_id: null },
    ]) {
      await expect(verifyReadReceipt(bad)).resolves.toBe(false);
    }
  });
});

describe("buildReadCountPayload", () => {
  it("sorts the rows by entry_id and sums them", () => {
    const payload = buildReadCountPayload(
      "2026-09-09",
      [
        { entry_id: "nmk_c", count: 1 },
        { entry_id: "nmk_a", count: 3 },
        { entry_id: "nmk_b", count: 2 },
      ],
      7,
      12,
    );
    expect(payload).toEqual({
      date: "2026-09-09",
      reads: [
        { entry_id: "nmk_a", count: 3 },
        { entry_id: "nmk_b", count: 2 },
        { entry_id: "nmk_c", count: 1 },
      ],
      total: 6,
      counter_first: 7,
      counter_last: 12,
    });
  });

  it("publishes a day nobody read, with both counter bounds null", () => {
    expect(buildReadCountPayload("2026-09-09", [], null, null)).toEqual({
      date: "2026-09-09",
      reads: [],
      total: 0,
      counter_first: null,
      counter_last: null,
    });
  });

  it("names its three refusals", () => {
    expect(READ_COUNT_REFUSALS).toEqual([
      "bad_date",
      "duplicate_entry_id",
      "bad_count",
    ]);
  });

  it("refuses a date that is not a real UTC day", () => {
    for (const date of ["2026-9-9", "2026-02-30", "not a date", ""]) {
      expect(() => buildReadCountPayload(date, [], null, null)).toThrow(
        /bad_date/,
      );
    }
  });

  it("refuses a duplicate entry_id", () => {
    expect(() =>
      buildReadCountPayload(
        "2026-09-09",
        [
          { entry_id: "nmk_a", count: 1 },
          { entry_id: "nmk_a", count: 2 },
        ],
        1,
        3,
      ),
    ).toThrow(/duplicate_entry_id/);
  });

  it("refuses a count below one, or one that is not a whole number", () => {
    for (const count of [0, -1, 1.5, Number.NaN]) {
      expect(() =>
        buildReadCountPayload("2026-09-09", [{ entry_id: "nmk_a", count }], 1, 1),
      ).toThrow(/bad_count/);
    }
  });

  it("does not mutate the rows it was handed", () => {
    const rows = [
      { entry_id: "nmk_c", count: 1 },
      { entry_id: "nmk_a", count: 1 },
    ];
    buildReadCountPayload("2026-09-09", rows, 1, 2);
    expect(rows.map((row) => row.entry_id)).toEqual(["nmk_c", "nmk_a"]);
  });
});

/**
 * The verifier must not care. A read_count event belongs to no entry, so
 * derivation ignores it and the offline verifier accepts it as a well-shaped
 * event and moves on — a day's published counts can never change what an entry
 * says.
 */
describe("a read_count event in a verified world", () => {
  it("leaves verifyOffline answering ok with no diffs", async () => {
    const world = await buildVerifyWorld();
    const before = await verifyOffline(world.entry, world.bundle);
    expect(before).toEqual({ ok: true, entry_id: world.entryId, diffs: [] });

    const events: Event[] = await appendEvent(world.bundle.events, {
      at: world.bundle.as_of,
      type: "read_count",
      entry_id: null,
      payload: buildReadCountPayload(
        world.bundle.as_of.slice(0, 10),
        [{ entry_id: world.entryId, count: 4 }],
        1,
        4,
      ),
    });

    const after = await verifyOffline(world.entry, {
      ...world.bundle,
      events,
    });
    expect(after).toEqual({ ok: true, entry_id: world.entryId, diffs: [] });
  });
});

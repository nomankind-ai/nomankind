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
  HASH_TAG_SYNC_RECEIPT,
  READ_COUNT_REFUSALS,
  agentIdFromPublicKey,
  appendEvent,
  buildReadCountPayload,
  exportPublicKeyRaw,
  generateKeypair,
  readReceiptSigningBytes,
  signReadReceipt,
  signSyncReceipt,
  syncReceiptSigningBytes,
  verifyReadReceipt,
  verifySyncReceipt,
  type Event,
  type ReadReceipt,
  type ReadReceiptFields,
  type SyncReceipt,
  type SyncReceiptFields,
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

/**
 * Sync receipts: one signature over a whole delta-stream response.
 *
 * Whitepaper Section 8, "The delta stream": the response carries the new head
 * and one signed sync receipt covering every delivered entry. The same story as
 * the read receipt, one field wider: sign it, then change exactly one thing and
 * watch the verdict turn — including the list of entries, which is the part a
 * server would be tempted to edit after the fact.
 */
describe("signSyncReceipt and verifySyncReceipt", () => {
  const ENTRIES = [
    { entry_id: ENTRY_ID, entry_hash: ENTRY_HASH, status: "verified" as const },
    {
      entry_id: "nmk_ffffffffffffffffffffffffffffffff",
      entry_hash: `sha256:${"c".repeat(64)}`,
      status: "overturned" as const,
    },
  ];

  async function syncReceipt(
    overrides: Partial<SyncReceiptFields> = {},
  ): Promise<{ receipt: SyncReceipt; agent: string }> {
    const { agent, keys } = await issuer();
    const fields: SyncReceiptFields = {
      from: 100,
      head: 142,
      entries: ENTRIES.map((entry) => ({ ...entry })),
      event_count: 9,
      issued_at: "2026-09-09T12:00:00.000Z",
      counter: 41,
      issuer: agent,
      ...overrides,
    };
    return { receipt: await signSyncReceipt(fields, keys.privateKey), agent };
  }

  it("signs the seven fields and verifies against the issuer's own key", async () => {
    const { receipt: signed, agent } = await syncReceipt();
    expect(signed.issuer).toBe(agent);
    expect(signed.head).toBe(142);
    expect(signed.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    await expect(verifySyncReceipt(signed)).resolves.toBe(true);
  });

  it("signs its own tag, a newline and the canonical seven fields", () => {
    const bytes = syncReceiptSigningBytes({
      from: 100,
      head: 142,
      entries: [
        { entry_id: ENTRY_ID, entry_hash: ENTRY_HASH, status: "verified" },
      ],
      event_count: 9,
      issued_at: "2026-09-09T12:00:00.000Z",
      counter: 41,
      issuer: "1F916:abc",
    });
    const text = new TextDecoder().decode(bytes);
    expect(text.startsWith(`${HASH_TAG_SYNC_RECEIPT}\n`)).toBe(true);
    // Its own tag, so a sync receipt can never be replayed as a read receipt.
    expect(HASH_TAG_SYNC_RECEIPT).not.toBe(HASH_TAG_READ_RECEIPT);
    expect(text.slice(HASH_TAG_SYNC_RECEIPT.length + 1)).toBe(
      `{"counter":41,"entries":[{"entry_hash":"${ENTRY_HASH}","entry_id":"${ENTRY_ID}","status":"verified"}],"event_count":9,"from":100,"head":142,"issued_at":"2026-09-09T12:00:00.000Z","issuer":"1F916:abc"}`,
    );
    expect(text).not.toContain("signature");
  });

  it("refuses a signature with one byte flipped", async () => {
    const { receipt: signed } = await syncReceipt();
    const forged = { ...signed, signature: flipSignature(signed.signature) };
    expect(forged.signature).not.toBe(signed.signature);
    await expect(verifySyncReceipt(forged)).resolves.toBe(false);
  });

  it("refuses a changed entries list", async () => {
    const { receipt: signed } = await syncReceipt();
    // One entry dropped.
    await expect(
      verifySyncReceipt({ ...signed, entries: [signed.entries[0]!] }),
    ).resolves.toBe(false);
    // One entry's version swapped for another's.
    await expect(
      verifySyncReceipt({
        ...signed,
        entries: [
          { ...signed.entries[0]!, entry_hash: `sha256:${"d".repeat(64)}` },
          signed.entries[1]!,
        ],
      }),
    ).resolves.toBe(false);
    // An unverified entry re-labelled, which is what a read would be billed on.
    await expect(
      verifySyncReceipt({
        ...signed,
        entries: [
          signed.entries[0]!,
          { ...signed.entries[1]!, status: "verified" },
        ],
      }),
    ).resolves.toBe(false);
    // The order reversed: the receipt reads in the order it was delivered.
    await expect(
      verifySyncReceipt({ ...signed, entries: [...signed.entries].reverse() }),
    ).resolves.toBe(false);
  });

  it("refuses a changed range, count, time, counter or issuer", async () => {
    const { receipt: signed } = await syncReceipt();
    const other = await issuer();
    for (const forged of [
      { ...signed, from: signed.from + 1 },
      { ...signed, head: signed.head + 1 },
      { ...signed, event_count: signed.event_count + 1 },
      { ...signed, issued_at: "2026-09-10T12:00:00.000Z" },
      { ...signed, counter: signed.counter + 1 },
      { ...signed, issuer: other.agent },
    ]) {
      await expect(verifySyncReceipt(forged)).resolves.toBe(false);
    }
  });

  it("answers false, and never throws, on malformed input", async () => {
    const { receipt: signed } = await syncReceipt();
    for (const bad of [
      null,
      undefined,
      42,
      "receipt",
      [signed],
      {},
      { ...signed, issuer: "not-an-agent-id" },
      { ...signed, signature: "not base64url!!" },
      { ...signed, counter: 1.5 },
      { ...signed, from: "100" },
      { ...signed, head: null },
      { ...signed, event_count: 1.5 },
      { ...signed, issued_at: 20260909 },
      { ...signed, entries: "none" },
      { ...signed, entries: [null] },
      { ...signed, entries: [{ entry_id: ENTRY_ID }] },
    ]) {
      await expect(verifySyncReceipt(bad)).resolves.toBe(false);
    }
  });

  it("does not touch the read receipt's own bytes", async () => {
    const { receipt: read } = await receipt();
    await expect(verifyReadReceipt(read)).resolves.toBe(true);
    // A read receipt is not a sync receipt, whatever it is handed to.
    await expect(verifySyncReceipt(read)).resolves.toBe(false);
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

// ---------------------------------------------------------------------------
// M24: the key a receipt was served to
// ---------------------------------------------------------------------------

describe("a receipt served to a key", () => {
  const KEY = "key_0123456789abcdef";

  it("signs the key and its counter, and verifies", async () => {
    const { receipt: signed } = await receipt({ key: KEY, key_counter: 1 });
    expect([signed.key, signed.key_counter]).toEqual([KEY, 1]);
    await expect(verifyReadReceipt(signed)).resolves.toBe(true);
  });

  it("puts both fields inside the signed bytes", () => {
    const text = new TextDecoder().decode(
      readReceiptSigningBytes({
        entry_id: ENTRY_ID,
        entry_hash: ENTRY_HASH,
        read_at: "2026-09-09T12:00:00.000Z",
        counter: 41,
        issuer: "1F916:abc",
        key: KEY,
        key_counter: 2,
      }),
    );
    expect(text).toContain(`"key":"${KEY}"`);
    expect(text).toContain(`"key_counter":2`);
  });

  it("refuses a receipt whose key or counter was edited", async () => {
    const { receipt: signed } = await receipt({ key: KEY, key_counter: 1 });
    for (const forged of [
      { ...signed, key: "key_ffffffffffffffff" },
      { ...signed, key: null },
      { ...signed, key_counter: 2 },
      { ...signed, key_counter: null },
    ]) {
      await expect(verifyReadReceipt(forged)).resolves.toBe(false);
    }
  });

  it("refuses a key or a counter that is not one", async () => {
    const { receipt: signed } = await receipt({ key: KEY, key_counter: 1 });
    for (const bad of [
      { ...signed, key: 7 },
      { ...signed, key_counter: 1.5 },
      { ...signed, key_counter: "1" },
    ]) {
      await expect(verifyReadReceipt(bad)).resolves.toBe(false);
    }
  });

  it("signs a free read's nulls, which is not the same as saying nothing", async () => {
    const { receipt: free } = await receipt({ key: null, key_counter: null });
    await expect(verifyReadReceipt(free)).resolves.toBe(true);

    // The property is the switch: a receipt issued before M24 carries neither
    // field, and its bytes are exactly what they were.
    const { receipt: old } = await receipt();
    expect("key" in old).toBe(false);
    await expect(verifyReadReceipt(old)).resolves.toBe(true);
    const { key, key_counter, ...stripped } = free;
    expect(key).toBeNull();
    expect(key_counter).toBeNull();
    // Dropping the two fields from a receipt that was signed with them changes
    // the bytes, so the verdict turns: they are not decoration.
    await expect(verifyReadReceipt(stripped)).resolves.toBe(false);
  });

  it("does the same for a sync receipt", async () => {
    const { agent, keys } = await issuer();
    const fields: SyncReceiptFields = {
      from: 0,
      head: 9,
      entries: [
        { entry_id: ENTRY_ID, entry_hash: ENTRY_HASH, status: "verified" },
      ],
      event_count: 3,
      issued_at: "2026-09-09T12:00:00.000Z",
      counter: 12,
      issuer: agent,
      key: KEY,
      key_counter: 4,
    };
    const signed = await signSyncReceipt(fields, keys.privateKey);
    await expect(verifySyncReceipt(signed)).resolves.toBe(true);
    await expect(
      verifySyncReceipt({ ...signed, key_counter: 5 }),
    ).resolves.toBe(false);
    expect(
      new TextDecoder().decode(syncReceiptSigningBytes(fields)),
    ).toContain(`"key_counter":4`);
  });
});

describe("buildReadCountPayload's paid block", () => {
  it("sorts the rows by entry_id, the keys by id, and sums them", () => {
    const payload = buildReadCountPayload(
      "2026-09-09",
      [
        { entry_id: "nmk_b", count: 3 },
        { entry_id: "nmk_a", count: 4 },
      ],
      1,
      7,
      {
        reads: [
          { entry_id: "nmk_b", count: 2 },
          { entry_id: "nmk_a", count: 1 },
        ],
        keys: { key_bbb: 1, key_aaa: 2 },
      },
    );
    expect(payload.paid).toEqual({
      reads: [
        { entry_id: "nmk_a", count: 1 },
        { entry_id: "nmk_b", count: 2 },
      ],
      total: 3,
      keys: { key_aaa: 2, key_bbb: 1 },
    });
    expect(Object.keys(payload.paid!.keys)).toEqual(["key_aaa", "key_bbb"]);
    // The day still counts every reader; the block is the half that was billed.
    expect(payload.total).toBe(7);
    expect(payload.paid!.total).toBe(
      Object.values(payload.paid!.keys).reduce((sum, count) => sum + count, 0),
    );
  });

  it("publishes an empty block for a day nobody paid for", () => {
    const payload = buildReadCountPayload(
      "2026-09-09",
      [{ entry_id: "nmk_a", count: 1 }],
      1,
      1,
      { reads: [], keys: {} },
    );
    expect(payload.paid).toEqual({ reads: [], total: 0, keys: {} });
  });

  it("writes no block at all when none is given, as every day before M24", () => {
    const payload = buildReadCountPayload("2026-09-09", [], null, null);
    expect("paid" in payload).toBe(false);
  });

  it("refuses a paid row that repeats an entry or counts below one", () => {
    expect(() =>
      buildReadCountPayload("2026-09-09", [], null, null, {
        reads: [
          { entry_id: "nmk_a", count: 1 },
          { entry_id: "nmk_a", count: 1 },
        ],
        keys: {},
      }),
    ).toThrow(/duplicate_entry_id/);
    expect(() =>
      buildReadCountPayload("2026-09-09", [], null, null, {
        reads: [{ entry_id: "nmk_a", count: 0 }],
        keys: {},
      }),
    ).toThrow(/bad_count/);
  });
});

// ---------------------------------------------------------------------------
// M24b: the reads the day dropped, and why
// ---------------------------------------------------------------------------

describe("buildReadCountPayload's duplicates block", () => {
  it("sorts the drops by entry_id and copies nothing else", () => {
    const payload = buildReadCountPayload(
      "2026-09-09",
      [{ entry_id: "nmk_new", count: 1 }],
      1,
      3,
      { reads: [], keys: {} },
      [
        { entry_id: "nmk_old2", newest: "nmk_new", sync_reads: 1 },
        { entry_id: "nmk_old1", newest: "nmk_new", sync_reads: 2 },
      ],
    );
    expect(payload.duplicates).toEqual([
      { entry_id: "nmk_old1", newest: "nmk_new", sync_reads: 2 },
      { entry_id: "nmk_old2", newest: "nmk_new", sync_reads: 1 },
    ]);
    // The dropped reads are not in the day's totals: they were not owed.
    expect(payload.total).toBe(1);
    expect(payload.paid).toEqual({ reads: [], total: 0, keys: {} });
  });

  it("publishes an empty block for a day that dropped nothing", () => {
    // Present and empty, because a reader must be able to tell "no duplicate"
    // from "not said".
    const payload = buildReadCountPayload(
      "2026-09-09",
      [{ entry_id: "nmk_a", count: 1 }],
      1,
      1,
      { reads: [], keys: {} },
      [],
    );
    expect(payload.duplicates).toEqual([]);
  });

  it("writes no block at all when none is given, as every day before M24b", () => {
    const payload = buildReadCountPayload("2026-09-09", [], null, null, {
      reads: [],
      keys: {},
    });
    expect("duplicates" in payload).toBe(false);
  });

  it("refuses a drop that repeats an entry or drops below one read", () => {
    // The same two refusals the rows carry, for the same reason: a day that
    // named one entry's drop twice would not add up for the reader checking it.
    expect(() =>
      buildReadCountPayload("2026-09-09", [], null, null, undefined, [
        { entry_id: "nmk_a", newest: "nmk_b", sync_reads: 1 },
        { entry_id: "nmk_a", newest: "nmk_b", sync_reads: 1 },
      ]),
    ).toThrow(/duplicate_entry_id/);
    for (const sync_reads of [0, -1, 1.5, Number.NaN]) {
      expect(() =>
        buildReadCountPayload("2026-09-09", [], null, null, undefined, [
          { entry_id: "nmk_a", newest: "nmk_b", sync_reads },
        ]),
      ).toThrow(/bad_count/);
    }
  });

  it("does not mutate the drops it was handed", () => {
    const duplicates = [
      { entry_id: "nmk_c", newest: "nmk_a", sync_reads: 1 },
      { entry_id: "nmk_a", newest: "nmk_a", sync_reads: 1 },
    ];
    buildReadCountPayload("2026-09-09", [], null, null, undefined, duplicates);
    expect(duplicates.map((row) => row.entry_id)).toEqual(["nmk_c", "nmk_a"]);
  });
});

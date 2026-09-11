/**
 * The OpenTimestamps upgrade, against bytes that came off the live wire.
 *
 * Everything under test/fixtures/ots was captured on 2026-09-10 and is checked
 * in verbatim (test/fixtures/ots/README.md says how). That matters more here
 * than anywhere else in this suite: the .ots format is not something this
 * project defines, and a parser tested only against proofs this file made up
 * would be testing its own idea of the format rather than the format. The chain
 * these bytes make — production's anchor hash for 2026-09-09, through a
 * calendar's commitment, to the merkle root of Bitcoin block 966287 — was
 * checked against a block explorer when it was captured, so the numbers below
 * are facts about Bitcoin, not fixtures anyone here chose.
 *
 * The calendar is never called. A test that asked one would be testing the
 * internet, and would ask a stranger's server for a favour on every run.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { anchorHash, type Anchor } from "../src/anchor.js";
import {
  stageStates,
  type AnchorFact,
  type Stage,
  type StatusInput,
} from "../src/status.js";
import {
  OTS_TAG_BITCOIN,
  OTS_TAG_PENDING,
  OpenTimestampsAdapter,
  attestationsOf,
  bitcoinHeightIn,
  parseOtsProof,
  pendingOf,
  serializeOtsFile,
  spliceUpgrade,
} from "../src/adapters/anchor.js";
import { base64Decode, base64Encode } from "../src/encoding.js";

// ---------------------------------------------------------------------------
// The captured wire
// ---------------------------------------------------------------------------

function fixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`./fixtures/ots/${name}`, import.meta.url), "utf8"),
  ) as T;
}

/** Production's anchor for 2026-09-09, exactly as GET /anchors/2026-09-09 served it. */
const ANCHOR = fixture<Anchor>("anchor-2026-09-09.json");

/** The calendar's 200 for the commitment, and the pool's 404 for the same one. */
const UPGRADED = fixture<{ status: number; body_base64: string }>(
  "calendar-upgraded.json",
);
const PENDING = fixture<{ status: number; body_base64: string; body_text: string }>(
  "calendar-pending.json",
);

const UPGRADED_BODY = base64Decode(UPGRADED.body_base64);
const PENDING_BODY = base64Decode(PENDING.body_base64);

/** The calendar named inside the pending attestation, not the one it was posted to. */
const ATTESTED_CALENDAR = "https://alice.btc.calendar.opentimestamps.org";
const RECORDED_CALENDAR = "https://a.pool.opentimestamps.org";

/** The bytes the calendar attested to: what `/timestamp/` is keyed by. */
const COMMITMENT =
  "6aa1f3476dbb13ac82e5e673fa16dd08fc239afdfa890ccfd8a3ae42d6c19cdb386441334f1a3ae73a744392";

/** Block 966287's merkle root, in the internal byte order a proof reaches. */
const MERKLE_ROOT =
  "7361cdb885061573576c8f74d14698b6b97096aa474f96e9202dd21d88e27617";
const BLOCK_HEIGHT = 966287;

const MAGIC =
  "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function bytes(hexText: string): Uint8Array {
  const out = new Uint8Array(hexText.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hexText.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

/** The 32 bytes the anchor hash spells: the message every proof here starts from. */
const DIGEST = bytes(ANCHOR.hash.slice("sha256:".length));

/** The pending proof as stored: the calendar's `/digest` answer, base64. */
const STORED = base64Decode(ANCHOR.external!.proof);

// ---------------------------------------------------------------------------
// The fixture itself
// ---------------------------------------------------------------------------

describe("the captured anchor", () => {
  it("is a real anchor: its hash recomputes from its own date and roots", async () => {
    // If this ever fails the fixture was edited rather than captured, and every
    // commitment below it is arithmetic over bytes nobody posted.
    expect(ANCHOR.hash).toBe(await anchorHash(ANCHOR.date, ANCHOR.roots));
    expect(ANCHOR.external).not.toBeNull();
    expect(ANCHOR.external!.calendar).toBe(RECORDED_CALENDAR);
  });
});

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

describe("parsing the pending proof", () => {
  it("reads the calendar's bare operations from the anchor's own digest", async () => {
    const proof = await parseOtsProof(STORED, DIGEST);
    expect(proof).not.toBeNull();
    // What a calendar answers `/digest` with carries no header and no copy of
    // the message: it starts at the operations, which is why the digest is an
    // argument here rather than something read out of the bytes.
    expect(proof!.magic).toBe(false);
    expect(proof!.version).toBeNull();
    expect(hex(proof!.digest)).toBe(hex(DIGEST));
  });

  it("finds the pending attestation, its calendar, and the commitment", async () => {
    const proof = await parseOtsProof(STORED, DIGEST);
    const pending = pendingOf(proof!);
    expect(pending).not.toBeNull();
    // The calendar inside the attestation is not the endpoint the digest was
    // posted to: the pool forwards, and the member calendar holds the promise.
    expect(pending!.calendar).toBe(ATTESTED_CALENDAR);
    expect(pending!.calendar).not.toBe(ANCHOR.external!.calendar);
    expect(hex(pending!.commitment)).toBe(COMMITMENT);

    const tags = attestationsOf(proof!.root).map((found) => found.attestation.tag);
    expect(tags).toEqual([OTS_TAG_PENDING]);
    expect(bitcoinHeightIn(proof!)).toBeNull();
  });

  it("reads the same proof again through a file header, magic and digest", async () => {
    // The same operations wrapped as a complete .ots file: magic, version 1,
    // the SHA-256 op tag and the 32 digest bytes. Both shapes have to reach the
    // same commitment, because they are the same timestamp.
    const file = new Uint8Array([...bytes(MAGIC), 0x01, 0x08, ...DIGEST, ...STORED]);
    const proof = await parseOtsProof(file, DIGEST);
    expect(proof).not.toBeNull();
    expect(proof!.magic).toBe(true);
    expect(proof!.version).toBe(1);
    expect(hex(pendingOf(proof!)!.commitment)).toBe(COMMITMENT);
  });

  it("refuses a file header whose digest is some other message", async () => {
    const other = new Uint8Array(32).fill(0x11);
    const file = new Uint8Array([...bytes(MAGIC), 0x01, 0x08, ...other, ...STORED]);
    expect(await parseOtsProof(file, DIGEST)).toBeNull();
  });

  it("refuses a version it does not speak", async () => {
    const file = new Uint8Array([...bytes(MAGIC), 0x02, 0x08, ...DIGEST, ...STORED]);
    expect(await parseOtsProof(file, DIGEST)).toBeNull();
  });

  it("answers null rather than throwing on garbage, truncation and trailing bytes", async () => {
    expect(await parseOtsProof(new Uint8Array(0), DIGEST)).toBeNull();
    expect(await parseOtsProof(new TextEncoder().encode("<html>502</html>"), DIGEST))
      .toBeNull();
    // A proof cut off mid-attestation.
    expect(await parseOtsProof(STORED.slice(0, STORED.byteLength - 8), DIGEST))
      .toBeNull();
    // A complete proof with a byte after it is not a proof this will read: the
    // trailing byte is either a second timestamp or corruption, and guessing
    // which would be inventing evidence.
    expect(await parseOtsProof(new Uint8Array([...STORED, 0x08]), DIGEST)).toBeNull();
    // An operation that is real OTS but not computable here (RIPEMD-160).
    expect(await parseOtsProof(new Uint8Array([0x67, 0x00]), DIGEST)).toBeNull();
  });
});

describe("parsing the upgraded proof", () => {
  it("reaches the Bitcoin attestation and its block height", async () => {
    const proof = await parseOtsProof(UPGRADED_BODY, bytes(COMMITMENT));
    expect(proof).not.toBeNull();

    const attestations = attestationsOf(proof!.root);
    expect(attestations.map((found) => found.attestation.tag)).toEqual([
      OTS_TAG_BITCOIN,
    ]);
    expect(bitcoinHeightIn(proof!)).toBe(BLOCK_HEIGHT);
    // The message the block attestation is over is the block's merkle root, in
    // the byte order Bitcoin hashes in. Checked against a block explorer when
    // these bytes were captured.
    expect(hex(attestations[0]!.msg)).toBe(MERKLE_ROOT);
  });

  it("splices onto the pending proof and serializes as a complete .ots file", async () => {
    const pendingProof = (await parseOtsProof(STORED, DIGEST))!;
    const answer = (await parseOtsProof(UPGRADED_BODY, bytes(COMMITMENT)))!;
    const upgraded = spliceUpgrade(pendingProof, bytes(COMMITMENT), answer.root);

    expect(upgraded).not.toBeNull();
    expect(bitcoinHeightIn(upgraded!)).toBe(BLOCK_HEIGHT);
    // The promise is gone, replaced by what it was a promise of.
    expect(attestationsOf(upgraded!.root).map((f) => f.attestation.tag)).toEqual([
      OTS_TAG_BITCOIN,
    ]);

    const file = serializeOtsFile(upgraded!);
    expect(hex(file.slice(0, 31))).toBe(MAGIC);
    expect(hex(file.slice(31, 33))).toBe("0108");
    expect(hex(file.slice(33, 65))).toBe(hex(DIGEST));

    // And it reads back as the same timestamp: the round trip is what makes the
    // stored proof usable by an OpenTimestamps client that is not this one.
    const reread = await parseOtsProof(file, DIGEST);
    expect(reread).not.toBeNull();
    expect(bitcoinHeightIn(reread!)).toBe(BLOCK_HEIGHT);
    expect(hex(serializeOtsFile(reread!))).toBe(hex(file));
  });

  it("splices nothing when the commitment is not one this proof is waiting on", async () => {
    const pendingProof = (await parseOtsProof(STORED, DIGEST))!;
    const answer = (await parseOtsProof(UPGRADED_BODY, bytes(COMMITMENT)))!;
    expect(spliceUpgrade(pendingProof, new Uint8Array(44).fill(0x22), answer.root))
      .toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The adapter, replaying the captured bodies
// ---------------------------------------------------------------------------

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
}

type Answer =
  | { status: number; body?: Uint8Array }
  | "throw";

/** A calendar table keyed by URL, exactly as the captured exchange was keyed. */
function calendars(table: Record<string, Answer>): {
  fetch: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetchFn = async function (
    this: unknown,
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    // workerd throws exactly this when a platform fetch is called on anything
    // but the global object, and Node's does not (the M13 lesson).
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Illegal invocation");
    }
    const url = String(input);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(
      (init?.headers ?? {}) as Record<string, string>,
    )) {
      headers[name.toLowerCase()] = value;
    }
    calls.push({ url, method: init?.method ?? "GET", headers });

    const answer = table[url];
    if (answer === undefined || answer === "throw") {
      throw new TypeError("calendar unreachable");
    }
    return new Response((answer.body ?? new Uint8Array(0)) as unknown as BodyInit, {
      status: answer.status,
    });
  } as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

const PATH = `/timestamp/${COMMITMENT}`;
const NOW = new Date("2026-09-10T21:27:23.000Z");

function adapter(fetchFn: typeof fetch): OpenTimestampsAdapter {
  return new OpenTimestampsAdapter({ fetch: fetchFn, now: () => NOW });
}

describe("OpenTimestampsAdapter.upgrade", () => {
  it("asks the attestation's calendar first and completes the proof", async () => {
    const { fetch, calls } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: { status: 200, body: UPGRADED_BODY },
      [`${RECORDED_CALENDAR}${PATH}`]: { status: 404, body: PENDING_BODY },
    });

    const result = await adapter(fetch).upgrade(ANCHOR);

    expect(result).toEqual({
      ok: true,
      proof: expect.any(String),
      block_height: BLOCK_HEIGHT,
    });
    // The member calendar answered, so the pool was never asked.
    expect(calls.map((call) => call.url)).toEqual([`${ATTESTED_CALENDAR}${PATH}`]);
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.headers["accept"]).toBe("application/vnd.opentimestamps.v1");
    expect(calls[0]!.headers["user-agent"]).toBe("nomankind");

    // What is stored is a complete .ots file over the anchor's own digest.
    const stored = base64Decode((result as { proof: string }).proof);
    const proof = await parseOtsProof(stored, DIGEST);
    expect(proof).not.toBeNull();
    expect(proof!.magic).toBe(true);
    expect(bitcoinHeightIn(proof!)).toBe(BLOCK_HEIGHT);
  });

  it("falls through to the recorded calendar when the attested one is silent", async () => {
    const { fetch, calls } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: "throw",
      [`${RECORDED_CALENDAR}${PATH}`]: { status: 200, body: UPGRADED_BODY },
    });

    const result = await adapter(fetch).upgrade(ANCHOR);
    expect(result.ok).toBe(true);
    expect(calls.map((call) => call.url)).toEqual([
      `${ATTESTED_CALENDAR}${PATH}`,
      `${RECORDED_CALENDAR}${PATH}`,
    ]);
  });

  it("is pending on the 404 the pool actually answered, body and all", async () => {
    // The captured 404, verbatim: a text body, not an .ots one.
    expect(PENDING.status).toBe(404);
    expect(PENDING.body_text).toBe("Not found\n");

    const { fetch, calls } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: { status: 404, body: PENDING_BODY },
      [`${RECORDED_CALENDAR}${PATH}`]: { status: 404, body: PENDING_BODY },
    });

    expect(await adapter(fetch).upgrade(ANCHOR)).toEqual({
      ok: false,
      reason: "pending",
    });
    expect(calls).toHaveLength(2);
  });

  it("is bad_proof on a body that is not the proof it asked for", async () => {
    const { fetch } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: {
        status: 200,
        body: new TextEncoder().encode("<html>502 Bad Gateway</html>"),
      },
      [`${RECORDED_CALENDAR}${PATH}`]: { status: 404, body: PENDING_BODY },
    });

    expect(await adapter(fetch).upgrade(ANCHOR)).toEqual({
      ok: false,
      reason: "bad_proof",
    });
  });

  it("is bad_proof on a well-formed proof that reaches no block", async () => {
    // The pending answer replayed as if it were an upgrade: it parses, and it
    // still says nothing about a block.
    const { fetch } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: { status: 200, body: STORED },
      [`${RECORDED_CALENDAR}${PATH}`]: { status: 404, body: PENDING_BODY },
    });
    expect(await adapter(fetch).upgrade(ANCHOR)).toEqual({
      ok: false,
      reason: "bad_proof",
    });
  });

  it("is unavailable when every calendar throws, and never throws itself", async () => {
    const { fetch, calls } = calendars({});
    expect(await adapter(fetch).upgrade(ANCHOR)).toEqual({
      ok: false,
      reason: "unavailable",
    });
    expect(calls).toHaveLength(2);
  });

  it("is unavailable on a 500 and on a 200 with nothing in it", async () => {
    for (const answer of [{ status: 500 }, { status: 200 }] as const) {
      const { fetch } = calendars({
        [`${ATTESTED_CALENDAR}${PATH}`]: answer,
        [`${RECORDED_CALENDAR}${PATH}`]: answer,
      });
      expect(await adapter(fetch).upgrade(ANCHOR)).toEqual({
        ok: false,
        reason: "unavailable",
      });
    }
  });

  it("is bad_proof on a receipt it cannot read, without asking anyone", async () => {
    const { fetch, calls } = calendars({
      [`${ATTESTED_CALENDAR}${PATH}`]: { status: 200, body: UPGRADED_BODY },
    });
    const table = adapter(fetch);

    for (const broken of [
      { ...ANCHOR, external: null },
      { ...ANCHOR, hash: "not-a-hash" },
      { ...ANCHOR, external: { ...ANCHOR.external!, proof: "not base64" } },
      {
        ...ANCHOR,
        external: { ...ANCHOR.external!, proof: base64Encode(new Uint8Array([0x99])) },
      },
    ] as Anchor[]) {
      expect(await table.upgrade(broken)).toEqual({ ok: false, reason: "bad_proof" });
    }
    expect(calls).toHaveLength(0);
  });

  it("records a stored proof that already reaches a block, asking no calendar", async () => {
    const complete = (await parseOtsProof(STORED, DIGEST))!;
    const answer = (await parseOtsProof(UPGRADED_BODY, bytes(COMMITMENT)))!;
    const file = serializeOtsFile(
      spliceUpgrade(complete, bytes(COMMITMENT), answer.root)!,
    );
    const { fetch, calls } = calendars({});

    const result = await adapter(fetch).upgrade({
      ...ANCHOR,
      external: { ...ANCHOR.external!, proof: base64Encode(file) },
    });

    expect(result).toEqual({
      ok: true,
      proof: base64Encode(file),
      block_height: BLOCK_HEIGHT,
    });
    expect(calls).toHaveLength(0);
  });

  it("will not follow a calendar URL that is not https", async () => {
    // The URL comes out of a proof a stranger wrote. Somewhere to fetch from is
    // exactly the kind of thing not to take on trust, so only https is followed
    // and a proof naming anything else has nowhere left to ask.
    const { fetch, calls } = calendars({});
    // "https://alice…" to "httpX://alice…" inside the attestation's URL bytes,
    // which keeps the length and so the rest of the proof exactly where it was.
    const rewritten = new Uint8Array(STORED);
    const at = STORED.byteLength - ATTESTED_CALENDAR.length;
    rewritten[at + 4] = "X".charCodeAt(0);

    const proof = await parseOtsProof(rewritten, DIGEST);
    expect(pendingOf(proof!)!.calendar).toBe("httpX://alice.btc.calendar.opentimestamps.org");

    const result = await adapter(fetch).upgrade({
      ...ANCHOR,
      // And the recorded one plain http, so neither is a place to go.
      external: {
        ...ANCHOR.external!,
        calendar: "http://a.pool.example",
        proof: base64Encode(rewritten),
      },
    });

    expect(result).toEqual({ ok: false, reason: "unavailable" });
    expect(calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// The status board
// ---------------------------------------------------------------------------

/**
 * The anchoring row, over the smallest world that reaches it.
 *
 * The rule itself lives in src/status.ts and is exercised state by state in
 * test/status.test.ts; what is checked here is only the wording the upgrade
 * added, which belongs with the rest of the upgrade.
 */
function anchoringRow(anchor: AnchorFact): Stage {
  const input: StatusInput = {
    environment: "production",
    witness_kind: "mock",
    payout_kind: "mock",
    steps: [
      {
        step: "sweep",
        last_run_at: STATUS_NOW,
        last_ok_at: STATUS_NOW,
        last_skip_reason: null,
        last_skip_at: null,
        detail: {},
        trigger: "alarm",
      },
    ],
    head_seq: null,
    seal: null,
    seals: { total: 0, witnessed: 0 },
    unsealed: { count: 0, oldest_at: null },
    pool: { snapshot: null, trusted: [], registered: 0 },
    assignments: { overdue: 0, drafts: 0 },
    entries: 0,
    read_counts: { newest: null, earliest_receipt_day: null },
    anchor,
    // The newest finished proof is a different question from yesterday's, and
    // this fixture asks only about yesterday's wording.
    upgraded_anchor: null,
    seals_yesterday: 1,
    reconciliation: null,
    standing_position: null,
    attestations: { due: 0, total: 0 },
    mirror: { kind: "unavailable", newest: null },
    metering: { kind: "unavailable", reported_days: 0, owed: 0 },
    alerts: { endpoints: 0, cursor: -1, due: 0, failed: 0 },
    exercised: {
      submission: null,
      registration: null,
      read_receipt: null,
      sync_receipt: null,
      payout: null,
    },
  };
  const found = stageStates(input, STATUS_NOW).find((one) => one.stage === "anchoring");
  if (found === undefined) throw new Error("no anchoring stage");
  return found;
}

const STATUS_NOW = "2026-09-10T12:00:00.000Z";
const STATUS_YESTERDAY = "2026-09-09";

describe("the anchoring row", () => {
  it("names a receipt that is still only a promise by its kind alone", () => {
    const row = anchoringRow({ date: STATUS_YESTERDAY, external: "opentimestamps" });
    expect(row.last).toBe(`${STATUS_YESTERDAY} · opentimestamps`);
    expect(row.state).toBe("ok");
  });

  it("names an upgraded one", () => {
    const row = anchoringRow({
      date: STATUS_YESTERDAY,
      external: "opentimestamps",
      upgraded: true,
    });
    expect(row.last).toBe(`${STATUS_YESTERDAY} · opentimestamps · upgraded`);
    // Not a state change: a pending proof was never a fault, only unfinished.
    expect(row.state).toBe("ok");
  });

  it("says nothing about upgrading when there is no receipt to upgrade", () => {
    const row = anchoringRow({ date: STATUS_YESTERDAY, external: null, upgraded: true });
    expect(row.last).toBe(`${STATUS_YESTERDAY} · no external record`);
    expect(row.state).toBe("attention");
  });
});

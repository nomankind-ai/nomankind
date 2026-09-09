/**
 * `npm run sync`: the trainer's command, driven in process against a fake
 * serving side.
 *
 * Whitepaper Section 8, "The delta stream": a training run asks for everything
 * the log learned after a position it already holds, and is handed those events
 * in sealed order with the new head and one signed receipt covering what was
 * delivered. Section 9, Money: each delivered verified entry counts as a read,
 * and the receipt is what the trainer keeps to hold against the published
 * counts. The command's whole job is to check that page at the moment it
 * arrives, and this file is the check on the check.
 *
 * Everything here is real except the HTTP layer: real Ed25519 keys, a real
 * sync receipt signed over the real canonical bytes, a real hash chain built
 * with appendEvent, a real seal built with buildSeal and real inclusion proofs
 * against its root. The answers are canned because the route belongs to the
 * Worker; what is under test is what the trainer does with an answer, including
 * every way of being lied to, each of which must be caught by its own named
 * check and no other.
 */

import { describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import { runSync, syncPlan } from "../src/cli/sync.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import { appendEvent, eventHash, type Event } from "../src/events.js";
import { entryHash } from "../src/hash.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { encodeProof, inclusionProof } from "../src/merkle.js";
import { signSyncReceipt, type SyncReceipt } from "../src/receipt.js";
import { buildSeal, type Seal } from "../src/seal.js";
import { syncItemKind } from "../src/sync.js";

const BASE = "https://sync.example";
const ENTRY_A = "nmk_0123456789abcdef0123456789abcdef";
const ENTRY_B = "nmk_fedcba9876543210fedcba9876543210";
const SNAPSHOT =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";
const OTHER_HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const AUTHOR = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const SEALED_AT = "2026-09-09T00:00:00Z";
const ISSUED_AT = "2026-09-09T12:00:00Z";
const COUNTER = 7;

// ---------------------------------------------------------------------------
// The way out of the process
// ---------------------------------------------------------------------------

/** The lines a run printed, and the run's exit code. */
interface Printed {
  readonly code: number;
  readonly out: string[];
  readonly err: string[];
}

/** A canned answer: the status and the JSON body the route would have sent. */
interface Canned {
  readonly status: number;
  readonly body: unknown;
}

/** The fake serving side, recording exactly what was asked of it. */
class FakeHttp implements HttpClient {
  readonly asked: string[] = [];

  constructor(private readonly answer: (url: URL, nth: number) => Canned) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const nth = this.asked.length;
    this.asked.push(`${url.pathname}${url.search}`);
    const { status, body } = this.answer(url, nth);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }
}

async function run(args: readonly string[], http: HttpClient): Promise<Printed> {
  const out: string[] = [];
  const err: string[] = [];
  const io: ValidatorIo = {
    stdout: (line: string) => out.push(line),
    stderr: (line: string) => err.push(line),
  };
  return { code: await runSync(args, http, io), out, err };
}

// ---------------------------------------------------------------------------
// The world the answers come out of
// ---------------------------------------------------------------------------

function core(id: string): Core {
  return {
    id,
    subject: id === ENTRY_A ? "openai/gpt-5" : "anthropic/claude-opus-5",
    category: "pricing",
    claim: "input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-08-15",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://platform.openai.com/docs/pricing",
    snapshot_hash: SNAPSHOT,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: AUTHOR,
    author_operator: "op_brightloop",
    submitted_at: "2026-09-01T14:05:00Z",
  } as Core;
}

/** The entry record the route serves alongside an item. */
function entryRecord(id: string, status: string): Record<string, unknown> {
  return {
    ...core(id),
    signature: SIGNATURE,
    status,
    last_confirmed: "2026-09-01",
  };
}

/**
 * The log the page is drawn from: a registry event, two submissions, one
 * validation of the first entry, and a dispute that overturns the second. Five
 * events, three kinds of item, and one entry delivered twice — which is what
 * makes the receipt's distinct-and-in-order rule worth checking.
 */
async function buildLog(): Promise<Event[]> {
  let events: Event[] = [];
  events = await appendEvent(events, {
    at: "2026-09-01T00:00:00Z",
    type: "operator_registered",
    entry_id: null,
    payload: { operator: "op_brightloop", maintainer: true },
  });
  events = await appendEvent(events, {
    at: "2026-09-01T14:05:00Z",
    type: "entry_submitted",
    entry_id: ENTRY_A,
    payload: { core: core(ENTRY_A), signature: SIGNATURE },
  });
  events = await appendEvent(events, {
    at: "2026-09-01T15:00:00Z",
    type: "entry_submitted",
    entry_id: ENTRY_B,
    payload: { core: core(ENTRY_B), signature: SIGNATURE },
  });
  events = await appendEvent(events, {
    at: "2026-09-02T09:00:00Z",
    type: "validation",
    entry_id: ENTRY_A,
    payload: {
      record: {
        agent: AUTHOR,
        operator: "op_brightloop",
        decision: "approve",
        reason: null,
        snapshot_hash: SNAPSHOT,
        assigned_random: true,
        test_accepted: null,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-02T09:00:00Z",
      },
      signature: SIGNATURE,
    },
  });
  events = await appendEvent(events, {
    at: "2026-09-03T09:00:00Z",
    type: "dispute_upheld",
    entry_id: ENTRY_B,
    payload: { correction_entry_id: ENTRY_A },
  });
  return events;
}

/** The status the route's derived entry carries for each of the two entries. */
const STATUS: Record<string, string> = {
  [ENTRY_A]: "verified",
  [ENTRY_B]: "overturned",
};

interface World {
  readonly issuer: string;
  readonly events: Event[];
  readonly seal: Seal;
  /** The seal as the response's `seals` array carries it. */
  readonly sealRecord: Record<string, unknown>;
  /** The five delivered items, in seq order. */
  readonly items: Record<string, unknown>[];
  readonly hashes: Record<string, string>;
  readonly receipt: SyncReceipt;
}

async function makeWorld(): Promise<World> {
  const keys = await generateKeypair();
  const issuer = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));

  const events = await buildLog();
  const sealed = await buildSeal(events, null, { now: SEALED_AT });
  if (!sealed.ok) throw new Error("m18 fixture: the seal was refused");
  const seal = sealed.seal;

  const leaves = events.map((event) => event.hash);
  const hashes: Record<string, string> = {
    [ENTRY_A]: await entryHash(core(ENTRY_A)),
    [ENTRY_B]: await entryHash(core(ENTRY_B)),
  };

  const items: Record<string, unknown>[] = [];
  for (const event of events) {
    const kind = syncItemKind(event);
    const entryId = event.entry_id;
    items.push({
      seq: event.seq,
      kind,
      event,
      proof: {
        seal_seq: seal.seq,
        inclusion_proof: encodeProof(
          await inclusionProof(leaves, event.seq - seal.first_seq),
        ),
      },
      entry:
        entryId === null ? null : entryRecord(entryId, STATUS[entryId] as string),
      sidecar: null,
      entry_hash: entryId === null ? null : hashes[entryId],
    });
  }

  const receipt = await signSyncReceipt(
    {
      from: 0,
      head: events[events.length - 1]!.seq,
      entries: [
        {
          entry_id: ENTRY_A,
          entry_hash: hashes[ENTRY_A]!,
          status: "verified",
        },
        {
          entry_id: ENTRY_B,
          entry_hash: hashes[ENTRY_B]!,
          status: "overturned",
        },
      ],
      event_count: events.length,
      issued_at: ISSUED_AT,
      counter: COUNTER,
      issuer,
    },
    keys.privateKey,
  );

  return {
    issuer,
    events,
    seal,
    sealRecord: {
      seq: seal.seq,
      root: seal.root,
      hash: seal.hash,
      sealed_at: seal.sealed_at,
      witnesses: seal.witnesses,
      registry: seal.registry,
    },
    items,
    hashes,
    receipt,
  };
}

/** The 200 body the sync route serves, with whatever this test changed in it. */
function page(
  world: World,
  overrides: Partial<{
    from: unknown;
    head: unknown;
    sealed_head: unknown;
    as_of: unknown;
    seals: unknown;
    events: unknown;
    receipt: unknown;
  }> = {},
): unknown {
  const head = world.events[world.events.length - 1]!.seq;
  return {
    from: 0,
    head,
    sealed_head: head,
    as_of: SEALED_AT,
    seals: [world.sealRecord],
    events: world.items,
    receipt: world.receipt,
    ...overrides,
  };
}

/** A page that delivered nothing at all: no items, no seals, no receipt. */
function emptyPage(from: number): unknown {
  return {
    from,
    head: null,
    sealed_head: 4,
    as_of: SEALED_AT,
    seals: [],
    events: [],
    receipt: null,
  };
}

/** A serving side answering the sync route and the seal route from `world`. */
function serve(
  world: World,
  sync: (nth: number) => Canned,
  sealAnswer?: Canned,
): FakeHttp {
  return new FakeHttp((url, nth) => {
    if (url.pathname.startsWith("/seals/")) {
      if (sealAnswer !== undefined) return sealAnswer;
      const seq = Number(url.pathname.slice("/seals/".length));
      if (seq !== world.seal.seq) {
        return { status: 404, body: { reason: "unknown_seal" } };
      }
      return { status: 200, body: world.sealRecord };
    }
    return sync(nth);
  });
}

/** The whole world, served as one unchanging page. */
function serveBody(world: World, body: unknown, sealAnswer?: Canned): FakeHttp {
  return serve(world, () => ({ status: 200, body }), sealAnswer);
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

describe("sync: arguments", () => {
  const bad: readonly (readonly string[])[] = [
    [],
    [BASE, "extra"],
    [BASE, "--from"],
    [BASE, "--from", "--limit"],
    [BASE, "--from", "seven"],
    [BASE, "--from", "-1"],
    [BASE, "--from", "1.5"],
    [BASE, "--from", "007"],
    [BASE, "--limit", "many"],
    [BASE, "--from", "1", "--from", "2"],
    [BASE, "--flatten", "--flatten"],
    [BASE, "--bogus"],
    [BASE, "--bogus", "1"],
    ["--from", "1"],
  ];

  for (const args of bad) {
    it(`exits 2 before any fetch: ${JSON.stringify(args)}`, async () => {
      const http = new FakeHttp(() => {
        throw new Error("sync: fetched on bad arguments");
      });
      const printed = await run(args, http);
      expect(printed.code).toBe(2);
      expect(printed.err[0]).toMatch(/^usage: sync /);
      expect(http.asked).toEqual([]);
    });
  }

  it("asks for the whole stream when nothing was demanded", () => {
    expect(syncPlan([BASE])).toEqual({ path: "/sync", twice: false });
  });

  it("builds the query in the order src/sync.ts names the parameters", async () => {
    const world = await makeWorld();
    const http = serveBody(world, emptyPage(7));
    const printed = await run(
      [
        BASE,
        "--from",
        "7",
        "--limit",
        "50",
        "--flatten",
        "--min-tier",
        "observed",
      ],
      http,
    );
    expect(printed.code).toBe(0);
    expect(http.asked).toEqual([
      "/sync?from=7&limit=50&flatten=true&min_tier=observed",
    ]);
  });

  it("keeps --twice out of the query", () => {
    expect(syncPlan([BASE, "--from", "3", "--twice"])).toEqual({
      path: "/sync?from=3",
      twice: true,
    });
  });
});

describe("sync: refusals", () => {
  it("names the reason and exits 1", async () => {
    const world = await makeWorld();
    const http = serve(world, () => ({
      status: 400,
      body: { ok: false, reason: "bad_min_tier" },
    }));
    const printed = await run([BASE, "--min-tier", "rumour"], http);
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["refused 400 bad_min_tier"]);
    expect(printed.out).toEqual([]);
  });

  it("says unknown when a refusal names no reason", async () => {
    const world = await makeWorld();
    const http = serve(world, () => ({ status: 500, body: null }));
    const printed = await run([BASE], http);
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["refused 500 unknown"]);
  });
});

describe("sync: what passes", () => {
  it("checks a full page and exits 0", async () => {
    const world = await makeWorld();
    const http = serveBody(world, page(world));
    const printed = await run([BASE], http);
    expect(printed.err).toEqual([]);
    expect(printed.code).toBe(0);
    expect(printed.out).toEqual([
      `ok from 0 head 4 sealed_head 4 delivered 5 entries 2 counter ${COUNTER} ` +
        "checks chain,proofs,receipt_entries,receipt_signature",
    ]);
    // The seal named by every item is asked for once, not five times.
    expect(http.asked).toEqual(["/sync", "/seals/0"]);
  });

  it("passes an empty page carrying no receipt", async () => {
    const world = await makeWorld();
    const http = serveBody(world, emptyPage(9));
    const printed = await run([BASE, "--from", "9"], http);
    expect(printed.code).toBe(0);
    expect(printed.out).toEqual([
      "ok from 9 head null sealed_head 4 delivered 0 entries 0 counter none " +
        "checks chain,proofs,receipt_entries,receipt_signature",
    ]);
    expect(http.asked).toEqual(["/sync?from=9"]);
  });

  it("asks twice and passes when the second page is the same", async () => {
    const world = await makeWorld();
    const body = page(world);
    const http = serveBody(world, body);
    const printed = await run([BASE, "--twice"], http);
    expect(printed.code).toBe(0);
    expect(printed.out).toEqual([
      `ok from 0 head 4 sealed_head 4 delivered 5 entries 2 counter ${COUNTER} ` +
        "checks chain,proofs,receipt_entries,receipt_signature,identical",
    ]);
    expect(http.asked).toEqual(["/sync", "/seals/0", "/sync"]);
  });

  it("passes when only the receipt moved between the two asks", async () => {
    const world = await makeWorld();
    // A second delivery is billed, so a fresh counter is not a broken promise.
    const second = page(world, {
      receipt: { ...world.receipt, counter: COUNTER + 1 },
    });
    const http = serve(world, (nth) => ({
      status: 200,
      body: nth === 0 ? page(world) : second,
    }));
    const printed = await run([BASE, "--twice"], http);
    expect(printed.code).toBe(0);
  });
});

describe("sync: the five checks, in order", () => {
  it("fails chain on a flipped event hash", async () => {
    const world = await makeWorld();
    const items = world.items.map((item, index) =>
      index === 2
        ? { ...item, event: { ...(item["event"] as Event), hash: OTHER_HASH } }
        : item,
    );
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { events: items })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed chain"]);
  });

  it("fails chain on a broken prev_hash that still hashes to itself", async () => {
    const world = await makeWorld();
    // Rehashed after the link was cut, so the event's own hash recomputes and
    // only the link to the event before it is wrong.
    const original = world.items[3]!["event"] as Event;
    const relinked = { ...original, prev_hash: OTHER_HASH };
    const rehashed: Event = {
      ...relinked,
      hash: await eventHash({
        seq: relinked.seq,
        at: relinked.at,
        type: relinked.type,
        entry_id: relinked.entry_id,
        payload: relinked.payload,
        prev_hash: relinked.prev_hash,
      }),
    };
    const items = world.items.map((item, index) =>
      index === 3 ? { ...item, event: rehashed } : item,
    );
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { events: items })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed chain"]);
  });

  it("fails chain on an item that is not one", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { events: [...world.items, "nonsense"] })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed chain"]);
  });

  it("fails proofs when the page's root is not the one that was sealed", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(
        world,
        page(world, { seals: [{ ...world.sealRecord, root: OTHER_HASH }] }),
      ),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed proofs"]);
  });

  it("fails proofs when the log answers a different root for the seal", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(world, page(world), {
        status: 200,
        body: { ...world.sealRecord, root: OTHER_HASH },
      }),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed proofs"]);
  });

  it("fails proofs when no delivered seal covers an item", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { seals: [] })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed proofs"]);
  });

  it("fails receipt_entries when the receipt is missing an entry", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(
        world,
        page(world, {
          receipt: { ...world.receipt, entries: [world.receipt.entries[0]] },
        }),
      ),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed receipt_entries"]);
  });

  it("fails receipt_entries on an entry_hash that is not the served core's", async () => {
    const world = await makeWorld();
    const items = world.items.map((item, index) =>
      index === 1 ? { ...item, entry_hash: OTHER_HASH } : item,
    );
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { events: items })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed receipt_entries"]);
  });

  it("fails receipt_entries when the receipt bills for another stretch", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { from: 1 })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed receipt_entries"]);
  });

  it("fails receipt_entries when an empty page still carries a receipt", async () => {
    const world = await makeWorld();
    const printed = await run(
      [BASE],
      serveBody(world, {
        ...(emptyPage(0) as Record<string, unknown>),
        receipt: world.receipt,
      }),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed receipt_entries"]);
  });

  it("fails receipt_signature on a flipped signature", async () => {
    const world = await makeWorld();
    // The first character is flipped rather than the last, whose low bits are
    // padding: the same shape, another value, and nobody's key made it.
    const signature = `${
      world.receipt.signature.startsWith("A") ? "B" : "A"
    }${world.receipt.signature.slice(1)}`;
    const printed = await run(
      [BASE],
      serveBody(world, page(world, { receipt: { ...world.receipt, signature } })),
    );
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed receipt_signature"]);
  });

  it("fails identical when the second ask answers a different head", async () => {
    const world = await makeWorld();
    const http = serve(world, (nth) => ({
      status: 200,
      body: nth === 0 ? page(world) : page(world, { head: 5 }),
    }));
    const printed = await run([BASE, "--twice"], http);
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed identical"]);
  });

  it("fails identical when the second ask reorders the page", async () => {
    const world = await makeWorld();
    const http = serve(world, (nth) => ({
      status: 200,
      body:
        nth === 0
          ? page(world)
          : page(world, { events: [...world.items].reverse() }),
    }));
    const printed = await run([BASE, "--twice"], http);
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed identical"]);
  });

  it("fails identical when the second ask is refused", async () => {
    const world = await makeWorld();
    const http = serve(world, (nth) =>
      nth === 0
        ? { status: 200, body: page(world) }
        : { status: 503, body: { reason: "sealing" } },
    );
    const printed = await run([BASE, "--twice"], http);
    expect(printed.code).toBe(1);
    expect(printed.err).toEqual(["failed identical"]);
  });
});

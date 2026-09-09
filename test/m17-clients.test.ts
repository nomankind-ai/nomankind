/**
 * `npm run read`: the reader's command, driven in process against a fake serving
 * side.
 *
 * Whitepaper Section 8, "The frozen reader": a read hands back one entry and "a
 * signed read receipt naming the entry, the time, and a running counter", and
 * Section 9, Money: readers keep those receipts and compare them against the
 * published counts. The command's whole job is to check the receipt at the
 * moment it is handed over, and this file is the check on the check.
 *
 * Everything here is real except the HTTP layer: real Ed25519 keys, a real
 * receipt signature over the real canonical bytes, a real hash chain built with
 * appendEvent, a real Merkle root and a real inclusion proof. The answers are
 * canned because the routes belong to the Worker; what is under test is what
 * the reader does with an answer, including four different ways of being lied
 * to, each of which must be caught by its own named check and no other.
 */

import { describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import { runRead, type ReadCheck } from "../src/cli/read.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import { appendEvent, type Event } from "../src/events.js";
import { entryHash } from "../src/hash.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { encodeProof, inclusionProof, merkleRoot } from "../src/merkle.js";
import { signReadReceipt, type ReadReceipt } from "../src/receipt.js";
import type { Seal } from "../src/seal.js";

const BASE = "https://read.example";
const ENTRY_ID = "nmk_0123456789abcdef0123456789abcdef";
const OTHER_ID = "nmk_fedcba9876543210fedcba9876543210";
const SNAPSHOT =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";
const AUTHOR = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const READ_AT = "2026-09-09T12:00:00Z";
const SEALED_AT = "2026-09-09T00:00:00Z";

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

  constructor(private readonly answer: (url: URL) => Canned) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    this.asked.push(`${url.pathname}${url.search}`);
    const { status, body } = this.answer(url);
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
  return { code: await runRead(args, http, io), out, err };
}

// ---------------------------------------------------------------------------
// The world the answers come out of
// ---------------------------------------------------------------------------

function core(id: string): Core {
  return {
    id,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
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

/** The log the seal covers: two events before the submission, then the batch. */
async function buildLog(): Promise<{ events: Event[]; submitted: number }> {
  let events: Event[] = [];
  events = await appendEvent(events, {
    at: "2026-09-01T00:00:00Z",
    type: "operator_registered",
    entry_id: null,
    payload: { operator: "op_brightloop", maintainer: true },
  });
  events = await appendEvent(events, {
    at: "2026-09-01T00:01:00Z",
    type: "pool_snapshot",
    entry_id: null,
    payload: { operators: ["op_brightloop"] },
  });
  events = await appendEvent(events, {
    at: "2026-09-01T14:05:00Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: { core: core(ENTRY_ID), signature: SIGNATURE },
  });
  return { events, submitted: events[events.length - 1]!.seq };
}

interface World {
  readonly issuer: string;
  readonly events: Event[];
  readonly seal: Seal;
  /** The entry with its seal object, as the read route serves it. */
  readonly entry: Record<string, unknown>;
  /** The proof of the submission event, as the entry carries it. */
  readonly proof: string;
  /** A proof of the wrong leaf: well formed, and against this root a lie. */
  readonly wrongProof: string;
  /** A valid receipt for the entry, signed by the issuer. */
  readonly receipt: ReadReceipt;
  /** A receipt for a different entry, honestly signed. */
  readonly otherReceipt: ReadReceipt;
  /** A receipt naming this entry with a hash that is not its core's. */
  readonly wrongHashReceipt: ReadReceipt;
}

async function makeWorld(): Promise<World> {
  const keys = await generateKeypair();
  const issuer = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));

  const { events, submitted } = await buildLog();
  const leaves = events.map((event) => event.hash);
  const root = await merkleRoot(leaves);
  const proof = encodeProof(await inclusionProof(leaves, submitted));
  // The same batch, proving a leaf that is not the submission event.
  const wrongProof = encodeProof(await inclusionProof(leaves, 0));

  const seal: Seal = {
    seq: 0,
    first_seq: 0,
    last_seq: events[events.length - 1]!.seq,
    size: events.length,
    root,
    sealed_at: SEALED_AT,
    prev_hash: null,
    hash: SNAPSHOT,
    witnesses: [],
    registry: null,
  };

  const entry: Record<string, unknown> = {
    ...core(ENTRY_ID),
    signature: SIGNATURE,
    status: "verified",
    last_confirmed: "2026-09-01",
    seal: {
      log: "1F916",
      inclusion_proof: proof,
      position: submitted,
      witnesses: [],
      sealed_at: SEALED_AT,
    },
  };

  const hash = await entryHash(core(ENTRY_ID));
  const receipt = await signReadReceipt(
    {
      entry_id: ENTRY_ID,
      entry_hash: hash,
      read_at: READ_AT,
      counter: 42,
      issuer,
    },
    keys.privateKey,
  );
  const otherReceipt = await signReadReceipt(
    {
      entry_id: OTHER_ID,
      entry_hash: await entryHash(core(OTHER_ID)),
      read_at: READ_AT,
      counter: 43,
      issuer,
    },
    keys.privateKey,
  );
  const wrongHashReceipt = await signReadReceipt(
    {
      entry_id: ENTRY_ID,
      entry_hash: await entryHash(core(OTHER_ID)),
      read_at: READ_AT,
      counter: 44,
      issuer,
    },
    keys.privateKey,
  );

  return {
    issuer,
    events,
    seal,
    entry,
    proof,
    wrongProof,
    receipt,
    otherReceipt,
    wrongHashReceipt,
  };
}

/** The 200 body the read route serves, with whatever this test changed in it. */
function answer(
  world: World,
  overrides: Partial<{
    entry: unknown;
    sidecar: unknown;
    seal: unknown;
    receipt: unknown;
  }> = {},
): unknown {
  return {
    entry: world.entry,
    sidecar: { effective_tier: "stated", read_share_slots: [] },
    seal: world.seal,
    receipt: world.receipt,
    ...overrides,
  };
}

/** A serving side that answers the read route and the log page from `world`. */
function serve(world: World, read: Canned): FakeHttp {
  return new FakeHttp((url) => {
    if (url.pathname === "/events") {
      const after = url.searchParams.get("after");
      const seq = after === null ? 0 : Number(after) + 1;
      const event = world.events.find((candidate) => candidate.seq === seq);
      return {
        status: 200,
        body: {
          events: event === undefined ? [] : [event],
          head: world.events[world.events.length - 1]!.seq,
        },
      };
    }
    return read;
  });
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

describe("read: arguments", () => {
  const bad: readonly (readonly string[])[] = [
    [],
    [BASE],
    [BASE, ENTRY_ID, "extra"],
    [BASE, "--subject", "openai/gpt-5"],
    [BASE, "--category", "pricing"],
    [BASE, "--subject", "openai/gpt-5", "--category"],
    [BASE, "--subject", "openai/gpt-5", "--category", "pricing", "--bogus", "1"],
    [BASE, "--subject", "a", "--subject", "b", "--category", "pricing"],
    ["--subject", "openai/gpt-5", "--category", "pricing"],
  ];

  for (const args of bad) {
    it(`exits 2 before any fetch: ${JSON.stringify(args)}`, async () => {
      const http = new FakeHttp(() => {
        throw new Error("read: fetched on bad arguments");
      });
      const printed = await run(args, http);
      expect(printed.code).toBe(2);
      expect(printed.err[0]).toMatch(/^usage: read /);
      expect(http.asked).toEqual([]);
    });
  }

  it("builds the subject query with the tier and age demands", async () => {
    const world = await makeWorld();
    const http = serve(world, { status: 200, body: answer(world) });
    const printed = await run(
      [
        BASE,
        "--subject",
        "openai/gpt-5",
        "--category",
        "pricing",
        "--min-tier",
        "observed",
        "--max-age",
        "30",
      ],
      http,
    );
    expect(printed.code).toBe(0);
    expect(http.asked[0]).toBe(
      "/read?subject=openai%2Fgpt-5&category=pricing&min_tier=observed&max_age=30",
    );
  });

  it("reads one entry by id", async () => {
    const world = await makeWorld();
    const http = serve(world, { status: 200, body: answer(world) });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(0);
    expect(http.asked[0]).toBe(`/read/${ENTRY_ID}`);
  });
});

describe("read: refusals", () => {
  it("prints a 404 and exits 1", async () => {
    const world = await makeWorld();
    const http = serve(world, {
      status: 404,
      body: { ok: false, error: "not_found" },
    });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(1);
    expect(printed.out).toEqual(["refused 404 not_found"]);
  });

  it("prints the status and the successor on a 409", async () => {
    const world = await makeWorld();
    const http = serve(world, {
      status: 409,
      body: {
        ok: false,
        error: "entry_not_verified",
        status: "superseded",
        superseded_by: OTHER_ID,
      },
    });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(1);
    expect(printed.out).toEqual([
      `refused 409 entry_not_verified status superseded superseded_by ${OTHER_ID}`,
    ]);
  });
});

describe("read: the four checks, in order", () => {
  async function failing(read: Canned, world: World): Promise<Printed> {
    return run([BASE, ENTRY_ID], serve(world, read));
  }

  const cases: readonly {
    readonly check: ReadCheck;
    readonly build: (world: World) => unknown;
  }[] = [
    {
      check: "receipt_entry",
      build: (world) => answer(world, { receipt: world.otherReceipt }),
    },
    {
      check: "entry_hash",
      build: (world) => answer(world, { receipt: world.wrongHashReceipt }),
    },
    {
      check: "receipt_signature",
      build: (world) =>
        answer(world, {
          receipt: {
            ...world.receipt,
            // One flipped character in the signature: the same shape, another
            // value, and nobody's key made it. The first character is flipped
            // rather than the last, whose low bits are padding.
            signature: `${
              world.receipt.signature.startsWith("A") ? "B" : "A"
            }${world.receipt.signature.slice(1)}`,
          },
        }),
    },
    {
      check: "seal",
      build: (world) =>
        answer(world, {
          entry: {
            ...world.entry,
            seal: {
              ...(world.entry["seal"] as Record<string, unknown>),
              inclusion_proof: world.wrongProof,
            },
          },
        }),
    },
  ];

  for (const { check, build } of cases) {
    it(`fails ${check} and exits 1`, async () => {
      const world = await makeWorld();
      const printed = await failing(
        { status: 200, body: build(world) },
        world,
      );
      expect(printed.code).toBe(1);
      expect(printed.out).toEqual([`failed ${check}`]);
    });
  }

  it("fails the seal when the covering seal is missing", async () => {
    const world = await makeWorld();
    const printed = await failing(
      { status: 200, body: answer(world, { seal: null }) },
      world,
    );
    expect(printed.code).toBe(1);
    expect(printed.out).toEqual(["failed seal"]);
  });
});

describe("read: what passes", () => {
  it("passes an unsealed entry without reading the log", async () => {
    const world = await makeWorld();
    const http = serve(world, {
      status: 200,
      body: answer(world, {
        entry: { ...world.entry, seal: null },
        seal: null,
      }),
    });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(0);
    expect(printed.out).toEqual([
      `ok ${ENTRY_ID} status verified tier stated counter 42 issuer ${world.issuer} seal unsealed`,
    ]);
    expect(http.asked).toEqual([`/read/${ENTRY_ID}`]);
  });

  it("passes a sealed entry, proving its submission into the root", async () => {
    const world = await makeWorld();
    const http = serve(world, { status: 200, body: answer(world) });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(0);
    expect(printed.out).toEqual([
      `ok ${ENTRY_ID} status verified tier stated counter 42 issuer ${world.issuer} seal sealed`,
    ]);
    expect(http.asked).toEqual([
      `/read/${ENTRY_ID}`,
      `/events?after=${world.events[world.events.length - 1]!.seq - 1}&limit=1`,
    ]);
  });

  it("fails the seal when the log's event was edited under its hash", async () => {
    const world = await makeWorld();
    const edited = world.events.map((event) =>
      event.type === "entry_submitted" ? { ...event, at: "2026-09-02T00:00:00Z" } : event,
    );
    const http = new FakeHttp((url) => {
      if (url.pathname === "/events") {
        const after = url.searchParams.get("after");
        const seq = after === null ? 0 : Number(after) + 1;
        const event = edited.find((candidate) => candidate.seq === seq);
        return {
          status: 200,
          body: { events: event === undefined ? [] : [event], head: seq },
        };
      }
      return { status: 200, body: answer(world) };
    });
    const printed = await run([BASE, ENTRY_ID], http);
    expect(printed.code).toBe(1);
    expect(printed.out).toEqual(["failed seal"]);
  });
});

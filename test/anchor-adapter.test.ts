/**
 * The anchor adapter, against calendars that exist only in this file.
 *
 * What is under test is the wire: the exact 32 digest bytes an OpenTimestamps
 * calendar takes, the headers its protocol asks for, the walk down the calendar
 * list when one is down, and the base64 the pending proof is kept in. A test
 * that posted to a real calendar would be testing the internet — and would put
 * a fixture hash into a public timestamping chain, which is not a thing to undo.
 */

import { describe, expect, it } from "vitest";

import { buildAnchor, type Anchor } from "../src/anchor.js";
import {
  LocalAnchorAdapter,
  OpenTimestampsAdapter,
  anchorAdapterFor,
} from "../src/adapters/anchor.js";
import { base64Decode, base64Encode } from "../src/encoding.js";
import { ANCHOR_CALENDARS } from "../src/policy.js";

const NOW = new Date("2026-09-08T12:00:00.000Z");
const now = (): Date => NOW;

const CALENDARS = ["https://first.test", "https://second.test"] as const;

/** A day's anchor over one seal, so the hash is a real anchor hash. */
async function anchorOfTheDay(): Promise<Anchor> {
  const built = await buildAnchor(
    [{ seq: 0, root: `sha256:${"11".repeat(32)}`, sealed_at: "2026-09-08T04:00:00Z" }],
    "2026-09-08",
  );
  if (!built.ok) throw new Error("fixture anchor refused");
  return built.anchor;
}

/** The 32 bytes an anchor hash spells. */
function digestOf(anchor: Anchor): Uint8Array {
  const hex = anchor.hash.slice("sha256:".length);
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Uint8Array | null;
}

/** A calendar table: each origin answers a status and a body. */
function calendars(
  table: Record<string, { status: number; body?: Uint8Array }>,
): { fetch: typeof fetch; calls: Call[] } {
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
    const body = init?.body;
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers,
      body: body instanceof Uint8Array ? new Uint8Array(body) : null,
    });

    const answer = table[url];
    if (answer === undefined) throw new TypeError("calendar unreachable");
    return new Response((answer.body ?? new Uint8Array(0)) as unknown as BodyInit, {
      status: answer.status,
      headers: { "content-type": "application/vnd.opentimestamps.v1" },
    });
  } as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

const PENDING_PROOF = new Uint8Array([0x00, 0x71, 0xff, 0x10, 0x2a, 0x9c, 0x01]);

describe("LocalAnchorAdapter", () => {
  it("records the day and posts nowhere", async () => {
    expect(await new LocalAnchorAdapter().anchor()).toBeNull();
  });
});

describe("OpenTimestampsAdapter", () => {
  it("posts the exact 32 digest bytes with the calendar's own headers", async () => {
    const anchor = await anchorOfTheDay();
    const { fetch, calls } = calendars({
      "https://first.test/digest": { status: 200, body: PENDING_PROOF },
    });

    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://first.test/digest");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.headers["accept"]).toBe("application/vnd.opentimestamps.v1");
    expect(calls[0]!.headers["content-type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    expect(calls[0]!.headers["user-agent"]).toBe("nomankind");
    // The raw digest and nothing around it: no JSON, no form encoding, no hex.
    expect(calls[0]!.body).toHaveLength(32);
    expect(calls[0]!.body).toEqual(digestOf(anchor));

    expect(external).toEqual({
      kind: "opentimestamps",
      calendar: "https://first.test",
      submitted_at: NOW.toISOString(),
      proof: base64Encode(PENDING_PROOF),
    });
  });

  it("keeps the proof in a base64 that round trips", async () => {
    const anchor = await anchorOfTheDay();
    const { fetch } = calendars({
      "https://first.test/digest": { status: 200, body: PENDING_PROOF },
    });
    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);

    expect(external).not.toBeNull();
    expect(base64Decode(external!.proof)).toEqual(PENDING_PROOF);
  });

  it("walks on to the next calendar when the first is down", async () => {
    const anchor = await anchorOfTheDay();
    const { fetch, calls } = calendars({
      "https://first.test/digest": { status: 502 },
      "https://second.test/digest": { status: 200, body: PENDING_PROOF },
    });

    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);

    expect(calls.map((call) => call.url)).toEqual([
      "https://first.test/digest",
      "https://second.test/digest",
    ]);
    expect(external!.calendar).toBe("https://second.test");
  });

  it("walks past a calendar that answers 200 with nothing", async () => {
    const anchor = await anchorOfTheDay();
    const { fetch } = calendars({
      "https://first.test/digest": { status: 200 },
      "https://second.test/digest": { status: 200, body: PENDING_PROOF },
    });
    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);
    expect(external!.calendar).toBe("https://second.test");
  });

  it("answers null when every calendar fails, and never throws", async () => {
    const anchor = await anchorOfTheDay();
    // An unknown URL makes the fake throw, which is what a dead network does.
    const { fetch, calls } = calendars({});
    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);

    expect(external).toBeNull();
    expect(calls).toHaveLength(2);
  });

  it("answers null for a hash it cannot read, without asking anyone", async () => {
    const anchor = { ...(await anchorOfTheDay()), hash: "not-a-hash" };
    const { fetch, calls } = calendars({
      "https://first.test/digest": { status: 200, body: PENDING_PROOF },
    });
    expect(
      await new OpenTimestampsAdapter({ fetch, calendars: CALENDARS, now }).anchor(
        anchor,
      ),
    ).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("never calls fetch with the adapter itself as the receiver", async () => {
    // The fake above throws "Illegal invocation" on a bound receiver, so a
    // proof coming back at all is the check.
    const anchor = await anchorOfTheDay();
    const { fetch } = calendars({
      "https://first.test/digest": { status: 200, body: PENDING_PROOF },
    });
    const external = await new OpenTimestampsAdapter({
      fetch,
      calendars: CALENDARS,
      now,
    }).anchor(anchor);
    expect(external).not.toBeNull();
  });

  it("defaults to the policy's calendars, in the policy's order", async () => {
    const anchor = await anchorOfTheDay();
    const { fetch, calls } = calendars({
      [`${ANCHOR_CALENDARS[1]!}/digest`]: { status: 200, body: PENDING_PROOF },
    });
    const external = await new OpenTimestampsAdapter({ fetch, now }).anchor(anchor);

    expect(calls[0]!.url).toBe(`${ANCHOR_CALENDARS[0]!}/digest`);
    expect(external!.calendar).toBe(ANCHOR_CALENDARS[1]!);
  });
});

describe("anchorAdapterFor", () => {
  it("posts from production and records locally everywhere else", () => {
    expect(anchorAdapterFor("production", now)).toBeInstanceOf(
      OpenTimestampsAdapter,
    );
    for (const environment of ["local", "demo", "", "preview"]) {
      expect(anchorAdapterFor(environment, now)).toBeInstanceOf(LocalAnchorAdapter);
    }
  });
});

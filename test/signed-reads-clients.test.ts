/**
 * The signed reads the log-reading commands make.
 *
 * The record is free from the seal (decisions D-100 and D-127): every command
 * here reads the same payloads a stranger reads, and `--sign <key.json>` buys
 * the operator's own read cap and nothing else. What is pinned is that the flag
 * is parsed the same way on every command, that the client it builds signs
 * every read of the run rather than only the first, and that the instant a
 * signature is stamped with is the instant the read was made (the QA of
 * 2026-09-13) rather than one fixed at process start.
 *
 * Everything is driven against a fake serving side that answers the same record
 * to everybody; the Worker's own verification is tested where the Worker is.
 */

import { describe, expect, it } from "vitest";

import { runScore } from "../src/cli/attest.js";
import { checkpointPlan } from "../src/cli/checkpoint.js";
import { attestClient, attestPlan } from "../src/cli/attest.js";
import { runStanding, standingPlan } from "../src/cli/standing.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import { signingHttp, type ValidatorKey } from "../src/cli/validator.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  HEADER_AGENT,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
} from "../src/request.js";
import { REQUEST_CLOCK_SKEW_SECONDS } from "../src/policy.js";
import type { Event } from "../src/events.js";

const BASE = "https://window.example";
const OPERATOR = "reader.example";
const AUTHOR = "author.example";
const ENTRY = "nmk_0123456789abcdef0123456789abcdef";
const SEALED_AT = "2026-09-12T00:00:00Z";
const NOW = new Date("2026-09-13T00:00:00Z");
const HEAD = 0;

function recorder(): { io: ValidatorIo; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
    out,
    err,
  };
}

/** One key, made for real: the signature the fake door looks for is a real one. */
async function makeKey(): Promise<ValidatorKey> {
  const pair = await generateKeypair();
  return {
    agentId: agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey)),
    privateKey: pair.privateKey,
  };
}

/** The one event the fake log holds: a submission by somebody else entirely. */
const EVENT: Event = {
  seq: HEAD,
  at: SEALED_AT,
  type: "entry_submitted",
  entry_id: ENTRY,
  payload: { core: { id: ENTRY, author_operator: AUTHOR } },
  prev_hash: null,
  hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
} as unknown as Event;

/** The serving side: the same record to everybody (D-127). */
class WindowHttp implements HttpClient {
  readonly asked: string[] = [];
  readonly posted: unknown[] = [];

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = `${url.pathname}${url.search}`;
    this.asked.push(path);

    if (request.method === "POST") {
      this.posted.push(await request.clone().json());
      return json(201, { ok: true, status: "scored", agreed: 1 });
    }
    return json(200, this.answer(url));
  }

  private answer(url: URL): unknown {
    if (url.pathname === "/seals") return { head: 0, seals: [] };
    if (url.pathname === "/seals/0") return { last_seq: HEAD, sealed_at: SEALED_AT };
    if (url.pathname === "/events") {
      return { head: HEAD, events: [EVENT] };
    }
    if (url.pathname.startsWith("/agents/")) {
      return { agent: url.pathname.slice("/agents/".length), operator: { id: OPERATOR } };
    }
    if (url.pathname.startsWith("/operators/")) {
      return {
        operator: OPERATOR,
        earned: 0,
        burned: 0,
        locked: 0,
        standing: 0,
        available: 0,
        position: HEAD,
      };
    }
    if (url.pathname.startsWith("/entries/")) {
      return { id: ENTRY, claim: "the claim as the log holds it" };
    }
    if (url.pathname.startsWith("/attestations/")) {
      return {
        id: "att_1",
        probe_hash: "sha256:cafe",
        answers_hash: "sha256:face",
        probes: [{ entry_id: ENTRY, subject: "a subject" }],
        answers: [{ entry_id: ENTRY, answer: "the claim as the log holds it" }],
      };
    }
    return {};
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// the clock a signed read is stamped by
// ---------------------------------------------------------------------------

describe("a signed read carries the instant it was made (the QA of 2026-09-13)", () => {
  /** A client that answers nothing and remembers what it was asked to carry. */
  function stamps(): { http: HttpClient; seen: string[] } {
    const seen: string[] = [];
    return {
      seen,
      http: {
        async fetch(request: Request): Promise<Response> {
          seen.push(request.headers.get(HEADER_TIMESTAMP) ?? "");
          return json(200, {});
        },
      },
    };
  }

  it("stamps two reads more than the skew apart with their own instants", async () => {
    const { http, seen } = stamps();
    // The clock a long run sees: `checkpoint --wait-seal` polls for a whole
    // seal interval, so its later reads happen well past the skew the door
    // tolerates. Stamped at process start they would be 401 `clock_skew`.
    let instant = NOW;
    const client = signingHttp(http, await makeKey(), () => instant);

    await client.fetch(new Request(`${BASE}/events`));
    const later = new Date(
      NOW.getTime() + (REQUEST_CLOCK_SKEW_SECONDS + 60) * 1000,
    );
    instant = later;
    await client.fetch(new Request(`${BASE}/events`));

    expect(seen).toEqual([NOW.toISOString(), later.toISOString()]);
    expect(Date.parse(seen[1]!) - Date.parse(seen[0]!)).toBeGreaterThan(
      REQUEST_CLOCK_SKEW_SECONDS * 1000,
    );
  });

  it("still takes a fixed instant, which is what a test injects", async () => {
    const { http, seen } = stamps();
    const client = signingHttp(http, await makeKey(), NOW);

    await client.fetch(new Request(`${BASE}/events`));
    await client.fetch(new Request(`${BASE}/seals`));

    expect(seen).toEqual([NOW.toISOString(), NOW.toISOString()]);
  });
});

// ---------------------------------------------------------------------------
// standing
// ---------------------------------------------------------------------------

describe("npm run standing", () => {
  it("folds and agrees unsigned, because every payload is served (D-127)", async () => {
    const { io, out } = recorder();
    const http = new WindowHttp();

    const code = await runStanding([BASE, OPERATOR], http, io, NOW);

    expect(code).toBe(0);
    expect(out).toEqual([`ok ${OPERATOR} standing 0 available 0 position 0`]);
  });

  it("folds and agrees when the reads are signed", async () => {
    const { io, out } = recorder();
    const http = new WindowHttp();
    const client = signingHttp(http, await makeKey(), NOW);

    const code = await runStanding([BASE, OPERATOR], client, io, NOW);

    expect(code).toBe(0);
    expect(out).toEqual([`ok ${OPERATOR} standing 0 available 0 position 0`]);
  });

  it("signs every read of the run, not only the events", async () => {
    const { io } = recorder();
    const http = new WindowHttp();
    const key = await makeKey();

    // `--sign` is read out of the arguments and applied to the client the whole
    // run uses, so the seals, the events and the served answer are one tier.
    expect(standingPlan([BASE, OPERATOR, "--sign", "./k.json"])).toEqual({
      baseUrl: BASE,
      operator: OPERATOR,
      signPath: "./k.json",
    });

    await runStanding([BASE, OPERATOR], signingHttp(http, key, NOW), io, NOW);
    expect(http.asked).toContain(`/operators/${OPERATOR}/standing`);
  });

  it("refuses a command line that is not a standing check", () => {
    expect(standingPlan([BASE])).toBeNull();
    expect(standingPlan([])).toBeNull();
    expect(standingPlan([BASE, OPERATOR, "extra"])).toBeNull();
    expect(standingPlan([BASE, OPERATOR, "--sign"])).toBeNull();
    expect(standingPlan([BASE, OPERATOR, "--sign", "--twice"])).toBeNull();
    expect(standingPlan([BASE, OPERATOR, "--bogus"])).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------

describe("npm run attest", () => {
  const plan = { subcommand: "score" as const, attestation: "att_1" };

  it("scores unsigned, because every claim is served (D-127)", async () => {
    const { io } = recorder();
    const http = new WindowHttp();

    const run = await runScore({
      key: await makeKey(),
      baseUrl: BASE,
      attestation: plan.attestation,
      deps: { http, now: NOW, io },
    });

    expect(run.ok).toBe(true);
    expect(http.posted).toHaveLength(1);
  });

  it("scores when the reads are signed", async () => {
    const { io } = recorder();
    const http = new WindowHttp();
    const key = await makeKey();

    const run = await runScore({
      key,
      baseUrl: BASE,
      attestation: plan.attestation,
      deps: { http: signingHttp(http, key, NOW), now: NOW, io },
    });

    expect(run.error).toBeNull();
    expect(http.posted).toHaveLength(1);
  });

  it("takes --sign on all three subcommands and builds a signing client", async () => {
    for (const argv of [
      ["request", "./k.json", BASE, "--sign", "./r.json"],
      ["answer", "./k.json", BASE, "att_1", "--sign", "./r.json"],
      ["score", "./k.json", BASE, "att_1", "--sign", "./r.json"],
    ]) {
      expect(attestPlan(argv)?.signPath).toBe("./r.json");
    }
    // Absent, the reads go out exactly as they always did: the same client
    // object, so nothing about a free run changed.
    const http = new WindowHttp();
    const bare = attestPlan(["score", "./k.json", BASE, "att_1"]);
    expect(bare?.signPath).toBeNull();
    expect(await attestClient(http, bare!, NOW)).toBe(http);
  });

  it("refuses --sign without a path", () => {
    expect(attestPlan(["score", "./k.json", BASE, "att_1", "--sign"])).toBeNull();
    expect(
      attestPlan(["score", "./k.json", BASE, "att_1", "--sign", "--drift"]),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// checkpoint
// ---------------------------------------------------------------------------

describe("npm run checkpoint", () => {
  const six = [BASE, "m.json", "a.json", "b.json", "c.json", "./out"];

  it("reads the six positionals with no flags at all", () => {
    expect(checkpointPlan(six)).toEqual({
      baseUrl: BASE,
      maintainerPath: "m.json",
      aPath: "a.json",
      bPath: "b.json",
      cPath: "c.json",
      outDir: "./out",
      waitSeal: false,
      signPath: null,
    });
  });

  it("takes --sign and --wait-seal without counting their values as paths", () => {
    const plan = checkpointPlan(["--wait-seal", ...six, "--sign", "./r.json"]);
    expect(plan).toEqual({
      baseUrl: BASE,
      maintainerPath: "m.json",
      aPath: "a.json",
      bPath: "b.json",
      cPath: "c.json",
      outDir: "./out",
      waitSeal: true,
      signPath: "./r.json",
    });
    // Wherever they sit on the line: the flags are flags, not positions, and a
    // flag's own value is never mistaken for one of the six paths -- which is
    // exactly what the first cut of this got wrong.
    expect(checkpointPlan(["--sign", "./r.json", ...six])).toEqual({
      ...plan,
      waitSeal: false,
    });
  });

  it("refuses a command line that is not a walk", () => {
    expect(checkpointPlan(six.slice(0, 5))).toBeNull();
    expect(checkpointPlan([...six, "seventh"])).toBeNull();
    expect(checkpointPlan([...six, "--sign"])).toBeNull();
    expect(checkpointPlan([...six, "--sign", "--wait-seal"])).toBeNull();
    expect(checkpointPlan([...six, "--bogus"])).toBeNull();
  });
});

/**
 * What a command says when it stops before it has signed anything, and what it
 * prints when a door refuses it (decision D-124, item (a)).
 *
 * The newcomer dry run of 2026-09-13 found three lines that told an operator
 * nothing they could act on:
 *
 *   - `entry_malformed` for an entry that was served perfectly well, in the
 *     withheld view the release window serves a free reader (D-100): the body
 *     carries `proof`, `sidecar`, `entry_hash` and `release_date` and no
 *     `entry`, so `extractCore` throws and every command called the log broken;
 *   - the same `entry_malformed` when the run's own key is bound to no
 *     registered operator, because `readerAccess` resolves a signature it
 *     verified but cannot place to the *free* reader (src/worker/access.ts) and
 *     the window then hands back exactly the same withheld body;
 *   - `schema_invalid` and nothing else on a 422, with the door's own `errors`
 *     array — the list of what was actually wrong — thrown away.
 *
 * So: `entry_withheld` carrying the date the door gave, `unregistered_operator`
 * when the registry puts nobody behind the key, `entry_malformed` kept for a
 * body that claims a core and cannot be read as one, and the door's detail
 * printed under the word it refused in.
 *
 * Driven in process against a stub door: what is under test is what the
 * commands make of an answer, and the two answers that matter are a 200 that is
 * not an entry and a 422 that carries a list.
 */

import { describe, expect, it } from "vitest";

import type { SnapshotFetcher } from "../src/adapters/fetch.js";
import { runDispute } from "../src/cli/dispute.js";
import { runReconfirm } from "../src/cli/reconfirm.js";
import { runRevalidate } from "../src/cli/revalidate.js";
import {
  UNREGISTERED_OPERATOR,
  errorsOf,
  refusalLines,
  runValidator,
  stopLine,
  unregisteredOperatorDetail,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "../src/cli/validator.js";
import { DEFAULT_DOMAIN, NORM_VERSION } from "../src/policy.js";
import { makeAgent } from "./helpers/registry.js";

const BASE = "https://nomankind.test";
const NOW = new Date("2026-09-13T12:00:00.000Z");
const ENTRY_ID = `nmk_${"8".repeat(32)}`;
/** A released entry: the door hands the whole thing over, core keys and all. */
function releasedEntry(): Record<string, unknown> {
  return {
    id: ENTRY_ID,
    subject: "example/kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel seat pricing is $40 per seat per month.",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://kestrel.example/pricing",
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "1F916:YXV0aG9yX2s",
    author_operator: null,
    submitted_at: "2026-09-08T09:00:00.000Z",
    status: "draft",
  };
}

/** The lines a run printed, both streams in the order they were written. */
function recorder(): { io: ValidatorIo; out: string[] } {
  const out: string[] = [];
  return {
    io: { stdout: (line) => out.push(line), stderr: (line) => out.push(line) },
    out,
  };
}

/** A fetcher no test here reaches: every run stops before it takes a capture. */
const NEVER_FETCHED: SnapshotFetcher = {
  fetch() {
    throw new Error("the run should have stopped before fetching anything");
  },
};

/**
 * A door that answers the entry read and the registry read and nothing else.
 *
 * `operator` is what `/agents/{id}` puts behind the run's key: a string for a
 * key the registry knows, null for one it does not. That is the only difference
 * between the two stops under test, and it is the door's own answer rather than
 * anything guessed from the withheld body — which is identical in both cases.
 */
class StubDoor implements HttpClient {
  readonly paths: string[] = [];

  constructor(
    private readonly answers: {
      readonly entry: { status: number; body: unknown };
      readonly operator: string | null;
      /** What a write door answers, for the runs that get that far. */
      readonly write?: { status: number; body: unknown };
    },
  ) {}

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    this.paths.push(`${request.method} ${path}`);
    if (path.startsWith("/agents/")) {
      return this.answers.operator === null
        ? this.json(404, { error: "not_found" })
        : this.json(200, { operator: { id: this.answers.operator } });
    }
    if (request.method === "GET") {
      return this.json(this.answers.entry.status, this.answers.entry.body);
    }
    const write = this.answers.write ?? { status: 500, body: {} };
    return this.json(write.status, write.body);
  }

  private json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }
}

async function keyOf(): Promise<ValidatorKey> {
  const agent = await makeAgent();
  return { agentId: agent.agentId, privateKey: agent.privateKey };
}

describe("validate stops on the answer the door actually gave", () => {
  it("says unregistered_operator when the registry puts nobody behind the key", async () => {
    // The door hands the whole entry over to everybody (D-127), so the key is
    // found out at the run's own registry read and nowhere else.
    const http = new StubDoor({
      entry: { status: 200, body: releasedEntry() },
      operator: null,
    });
    const key = await keyOf();
    const run = await runValidator({
      baseUrl: BASE,
      entryId: ENTRY_ID,
      io: recorder().io,
      deps: { http, fetcher: NEVER_FETCHED, now: NOW, key },
    });
    expect([run.ok, run.error]).toEqual([false, UNREGISTERED_OPERATOR]);
    expect(run.detail).toBe(unregisteredOperatorDetail(key.agentId));
    expect(http.paths.some((call) => call.startsWith("POST"))).toBe(false);
  });

  it("keeps entry_malformed for a body that claims a core and is not one", async () => {
    const http = new StubDoor({
      entry: { status: 200, body: { id: ENTRY_ID, subject: "example.com" } },
      operator: "k1.example",
    });
    const run = await runValidator({
      baseUrl: BASE,
      entryId: ENTRY_ID,
      io: recorder().io,
      deps: { http, fetcher: NEVER_FETCHED, now: NOW, key: await keyOf() },
    });
    expect([run.ok, run.error, run.detail]).toEqual([
      false,
      "entry_malformed",
      null,
    ]);
  });
});

describe("the other three commands read the same answer the same way", () => {
  it("stops reconfirm at unregistered_operator", async () => {
    const bare = await runReconfirm({
      key: await keyOf(),
      baseUrl: BASE,
      entryId: ENTRY_ID,
      deps: {
        http: new StubDoor({
          entry: { status: 200, body: releasedEntry() },
          operator: null,
        }),
        fetcher: NEVER_FETCHED,
        now: NOW,
        io: recorder().io,
      },
    });
    expect(bare.error).toBe(UNREGISTERED_OPERATOR);
  });

  it("stops revalidate --resolve at unregistered_operator", async () => {
    const run = await runRevalidate({
      key: await keyOf(),
      baseUrl: BASE,
      entryId: ENTRY_ID,
      resolve: "held",
      deps: {
        http: new StubDoor({
          entry: { status: 200, body: releasedEntry() },
          operator: null,
        }),
        fetcher: NEVER_FETCHED,
        now: NOW,
        io: recorder().io,
      },
    });
    expect(run.error).toBe(UNREGISTERED_OPERATOR);
  });

  it("stops dispute on the fields it was handed, and files nothing", async () => {
    const run = await runDispute({
      key: await keyOf(),
      baseUrl: BASE,
      targetId: ENTRY_ID,
      fields: { nonsense: true },
      deps: {
        http: new StubDoor({
          entry: { status: 200, body: releasedEntry() },
          operator: null,
        }),
        fetcher: NEVER_FETCHED,
        now: NOW,
        io: recorder().io,
      },
    });
    expect([run.error, run.correctionId]).toEqual(["bad_fields", null]);
  });
});

describe("a 422 prints what the door said was wrong", () => {
  const REFUSAL = {
    error: "schema_invalid",
    errors: [
      { path: "/domain", message: "must have required property 'domain'" },
      { path: "/claim", message: "must be string" },
    ],
  };

  it("reads the errors array off a refusal, and null off everything else", () => {
    expect(errorsOf(REFUSAL)).toEqual(REFUSAL.errors);
    expect(errorsOf({ error: "entry_closed" })).toBeNull();
    expect(errorsOf(null)).toBeNull();
    // A door's JSON is not this process's own objects: an item that is not the
    // shape the schema names is still printed rather than dropped.
    expect(errorsOf({ errors: ["plain", 7] })).toEqual([
      { path: "", message: "plain" },
      { path: "", message: "7" },
    ]);
  });

  it("prints the status, the word, and every error under it", () => {
    expect(refusalLines(422, REFUSAL)).toEqual([
      "response 422 schema_invalid",
      "  /domain: must have required property 'domain'",
      "  /claim: must be string",
    ]);
    // A refusal that carries a short reason instead of a list prints that.
    expect(
      refusalLines(422, { error: "legacy_entry", reason: "sealed under v0.6" }),
    ).toEqual(["response 422 legacy_entry", "  sealed under v0.6"]);
    // And one that carries neither is the one line it always was.
    expect(refusalLines(409, { error: "entry_closed" })).toEqual([
      "response 409 entry_closed",
    ]);
    expect(refusalLines(201, { id: ENTRY_ID })).toEqual(["response 201"]);
  });

  it("carries them out of a run, printed and returned", async () => {
    // `revalidate` with no `--resolve` asks for a check and sends an empty
    // body, so this is the shortest path from a command to a refused door.
    const io = recorder();
    const run = await runRevalidate({
      key: await keyOf(),
      baseUrl: BASE,
      entryId: ENTRY_ID,
      resolve: null,
      deps: {
        http: new StubDoor({
          entry: { status: 200, body: {} },
          operator: "k1.example",
          write: { status: 422, body: REFUSAL },
        }),
        fetcher: NEVER_FETCHED,
        now: NOW,
        io: io.io,
      },
    });
    expect([run.ok, run.status, run.error]).toEqual([false, 422, "schema_invalid"]);
    expect(run.errors).toEqual(REFUSAL.errors);
    expect(io.out).toEqual([
      "response 422 schema_invalid",
      "  /domain: must have required property 'domain'",
      "  /claim: must be string",
    ]);
  });
});

describe("the stop line", () => {
  it("names the thing, the word, and the detail when there is one", () => {
    expect(stopLine("nmk_x", { error: "entry_malformed", detail: null })).toBe(
      "nmk_x: entry_malformed",
    );
    expect(stopLine("dispute", { error: null })).toBe("dispute: unknown error");
    expect(
      stopLine("nmk_x", {
        error: UNREGISTERED_OPERATOR,
        detail: "agent nmk_agent_x is bound to no registered operator",
      }),
    ).toBe(
      "nmk_x: unregistered_operator agent nmk_agent_x is bound to no registered operator",
    );
  });
});

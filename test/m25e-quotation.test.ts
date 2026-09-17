/**
 * The quotation rule: the seeder that will not quote what a page does not say,
 * and the validator that approves only what its own fetch reproduces.
 *
 * Whitepaper, "What verified means": a validator approves only what its own
 * fetch reproduces. M25e (decision D-128 item 3) makes that sentence something a
 * public pool can run hourly, and this file walks both halves of it.
 *
 * Everything about the rule is real here: the fixture page is real bytes off
 * test/fixtures/html, hashed by the real norm rule, the keys are real Ed25519
 * keys, the records are really signed, and the span check is the one the
 * validator runs, because both sides call the same exported function. What is
 * faked is the log: these two commands are clients, and what is under test is
 * what they decide before they post and what they sign when they do, so the
 * door is a small stub that answers the three routes a client touches and keeps
 * what was posted to it. The doors' own judgments have their own files.
 */

import { readFileSync } from "node:fs";

import { beforeAll, describe, expect, it } from "vitest";

import { extractCore, type Core } from "../src/core.js";
import {
  checkSources,
  fieldsForRow,
  parseSeedArgs,
  runSeed,
  seedLogText,
  SPAN_NOT_IN_CAPTURE,
  type SeedRow,
} from "../src/cli/seed.js";
import {
  containsSpan,
  parseValidatorArgs,
  QUOTATION_REPRODUCED,
  quotationReason,
  runUrlFrom,
  runValidator,
  SNAPSHOT_MISMATCH,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "../src/cli/validator.js";
import { NORM_VERSION } from "../src/policy.js";
import { buildSubmittedCore } from "../src/submit.js";
import { makeAgent } from "./helpers/registry.js";
import { FixtureFetcher, pageHash, type FixturePage } from "./helpers/submit.js";

const NOW = new Date("2026-09-16T12:00:00.000Z");
const BASE = "https://demo.nomankind.ai";
const CITATION = "https://example.com/code-of-conduct";
const OPERATOR = "seed-a.example";
const RUN_URL = "https://github.com/nomankind-ai/bootstrap/actions/runs/42";

/** The passage the page carries, word for word. */
const SPAN = "We will not deploy a model that we cannot switch off.";
/** The same sentence, said differently: a paraphrase is not a quotation. */
const PARAPHRASE = "We will not deploy any model we are unable to switch off.";

const PAGE: FixturePage = {
  body: new Uint8Array(
    readFileSync(new URL("./fixtures/html/commitment-page.html", import.meta.url)),
  ),
  contentType: "text/html; charset=utf-8",
};

/** The same URL, saying something else: a source that moved under the entry. */
const MOVED: FixturePage = {
  body: "<!doctype html><html><body><main><p>This page has been withdrawn.</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

function rowFor(span: string): SeedRow {
  return {
    subject: "example/humanist-ai-code-of-conduct",
    category: "commitment_published",
    citation: CITATION,
    span,
    domain: "ai-safety",
    note: "the maintainer's own note, never submitted",
  };
}

const lines: string[] = [];
const io: ValidatorIo = {
  stdout: (line: string) => lines.push(line),
  stderr: (line: string) => lines.push(`stderr ${line}`),
};

/**
 * The log, as far as a client can see it: the operator behind a key, one submit
 * door and one validate door, and a record of everything posted.
 */
class StubLog implements HttpClient {
  readonly posted: { path: string; body: unknown }[] = [];
  entry: Record<string, unknown> | null = null;
  submitStatus = 201;
  submitBody: unknown = { status: "draft" };

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path.startsWith("/agents/")) {
      return Response.json({ operator: { id: OPERATOR } });
    }
    if (request.method === "GET" && path.startsWith("/entries/")) {
      if (this.entry === null) return Response.json({ error: "not_found" }, { status: 404 });
      return Response.json(this.entry);
    }
    const body = await request.json();
    this.posted.push({ path, body });
    if (path === "/entries") {
      return Response.json(this.submitBody, { status: this.submitStatus });
    }
    return Response.json({ sealed: true }, { status: 201 });
  }
}

let key: ValidatorKey;
let pageHashValue = "";

beforeAll(async () => {
  key = await makeAgent();
  pageHashValue = await pageHash(PAGE);
});

/** The core a seeded entry carries, built the way the submit path builds one. */
async function seededCore(span: string, snapshotHash: string): Promise<Core> {
  return buildSubmittedCore(
    {
      ...(fieldsForRow(rowFor(span), NOW) as unknown as {
        subject: string;
        category: string;
        domain: string;
        claim: string;
        before: string;
        after: string;
        effective_at: string;
        citation: string;
      }),
      snapshot_hash: snapshotHash,
      author: key.agentId,
      author_operator: null,
    },
    { now: NOW.toISOString() },
  );
}

// ---------------------------------------------------------------------------
// The seeder
// ---------------------------------------------------------------------------

describe("npm run seed builds one entry per source row", () => {
  it("submits a row whose span its own capture carries verbatim", async () => {
    const http = new StubLog();
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(SPAN)],
      deps: { http, fetcher, now: NOW, io },
    });

    expect([run.ok, run.code, run.submitted, run.refused]).toEqual([true, 0, 1, 0]);
    const submission = http.posted.find((post) => post.path === "/entries");
    expect(submission).toBeDefined();
    const entry = (submission!.body as { entry: Record<string, unknown> }).entry;
    // The claim is the span, exactly: not trimmed, not folded, not re-spelt.
    expect(entry["claim"]).toBe(SPAN);
    expect(entry["domain"]).toBe("ai-safety");
    expect(entry["category"]).toBe("commitment_published");
    expect(entry["snapshot_hash"]).toBe(pageHashValue);
    expect(entry["evidence_tier"]).toBe("stated");
    expect(entry["norm_version"]).toBe(NORM_VERSION);
    // The note is the maintainer's own and is never part of an entry.
    expect(Object.keys(entry)).not.toContain("note");
  });

  it("refuses a paraphrase before it is submitted", async () => {
    const http = new StubLog();
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(PARAPHRASE)],
      deps: { http, fetcher, now: NOW, io },
    });

    expect([run.ok, run.code, run.submitted, run.refused]).toEqual([false, 1, 0, 1]);
    expect(run.log[0]!.outcome).toEqual({
      result: "refused",
      reason: SPAN_NOT_IN_CAPTURE,
    });
    // Nothing was offered to the log at all.
    expect(http.posted).toEqual([]);
  });

  it("checks without submitting under --dry-run", async () => {
    const http = new StubLog();
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(SPAN)],
      dryRun: true,
      deps: { http, fetcher, now: NOW, io },
    });

    expect([run.ok, run.checked, run.submitted]).toEqual([true, 1, 0]);
    expect(http.posted).toEqual([]);
  });

  it("stops at the door's refusal and says how many rows remain", async () => {
    const http = new StubLog();
    http.submitStatus = 429;
    http.submitBody = { error: "write_quota", bucket: "agent", limit: 100 };
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(SPAN), rowFor(SPAN), rowFor(SPAN)],
      deps: { http, fetcher, now: NOW, io },
    });

    expect(run.stopped).toBe("write_quota");
    expect(run.remaining).toBe(2);
    // One submission was attempted, and the two behind it were not.
    expect(http.posted.filter((post) => post.path === "/entries")).toHaveLength(1);
  });

  it("leaves the rows past --limit for a later run", async () => {
    const http = new StubLog();
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(SPAN), rowFor(SPAN), rowFor(SPAN)],
      limit: 1,
      deps: { http, fetcher, now: NOW, io },
    });

    expect([run.submitted, run.remaining, run.stopped]).toEqual([1, 2, null]);
  });

  it("writes one JSON line per row it reached", async () => {
    const http = new StubLog();
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runSeed({
      key,
      baseUrl: BASE,
      rows: [rowFor(SPAN), rowFor(PARAPHRASE)],
      deps: { http, fetcher, now: NOW, io },
    });

    const written = seedLogText(run.log).trimEnd().split("\n");
    expect(written).toHaveLength(2);
    const first = JSON.parse(written[0]!) as Record<string, unknown>;
    expect(first["row"]).toBe(0);
    expect(first["citation"]).toBe(CITATION);
    expect(first["span_hash"]).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect((first["outcome"] as Record<string, unknown>)["result"]).toBe("submitted");
    const second = JSON.parse(written[1]!) as Record<string, unknown>;
    expect((second["outcome"] as Record<string, unknown>)["reason"]).toBe(
      SPAN_NOT_IN_CAPTURE,
    );
  });

  it("refuses a source list it cannot read, before any fetch", () => {
    expect(checkSources({}).ok).toBe(false);
    expect(checkSources([{ subject: "a" }]).ok).toBe(false);
    expect(checkSources([{ ...rowFor(SPAN), colour: "blue" }]).ok).toBe(false);
    expect(checkSources([rowFor(SPAN)]).ok).toBe(true);
  });

  it("reads its own command line, and refuses one it cannot", () => {
    expect(
      parseSeedArgs(["k.json", BASE, "s.json", "--dry-run", "--limit", "5"]),
    ).toEqual({
      keyPath: "k.json",
      baseUrl: BASE,
      sourcesPath: "s.json",
      dryRun: true,
      out: null,
      limit: 5,
    });
    expect(parseSeedArgs(["k.json", BASE])).toBeNull();
    expect(parseSeedArgs(["k.json", BASE, "s.json", "--limit", "five"])).toBeNull();
    expect(parseSeedArgs(["k.json", BASE, "s.json", "--out"])).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The validator under --quote
// ---------------------------------------------------------------------------

describe("npm run validate -- --quote approves only what its fetch reproduces", () => {
  async function validate(input: {
    readonly core: Core;
    readonly page: FixturePage;
    readonly quote?: boolean;
    readonly runUrl?: string | null;
  }) {
    const http = new StubLog();
    http.entry = { ...input.core, signature: "sig", status: "draft" };
    const fetcher = new FixtureFetcher({ [CITATION]: input.page });
    const run = await runValidator({
      baseUrl: BASE,
      entryId: input.core["id"] as string,
      ...(input.quote === undefined ? {} : { quote: input.quote }),
      ...(input.runUrl === undefined ? {} : { runUrl: input.runUrl }),
      io,
      deps: { http, fetcher, now: NOW, key },
    });
    return { run, http };
  }

  it("approves the quotation and names the public run", async () => {
    const core = await seededCore(SPAN, pageHashValue);
    const { run } = await validate({
      core,
      page: PAGE,
      quote: true,
      runUrl: RUN_URL,
    });

    expect(run.decision).toBe("approve");
    expect(run.reason).toBe(`${QUOTATION_REPRODUCED}; run: ${RUN_URL}`);
    expect(run.reason!.endsWith(`run: ${RUN_URL}`)).toBe(true);
    expect(run.record!.snapshot_hash).toBe(pageHashValue);
  });

  it("rejects a page that no longer hashes to the entry's, naming the half", async () => {
    const core = await seededCore(SPAN, pageHashValue);
    const { run } = await validate({
      core,
      page: MOVED,
      quote: true,
      runUrl: RUN_URL,
    });

    expect(run.decision).toBe("reject");
    expect(run.reason).toBe(`${quotationReason("hash mismatch")}; run: ${RUN_URL}`);
  });

  it("rejects a claim the capture does not carry, naming the other half", async () => {
    // The entry's own hash is the page's, so the first half passes and the
    // second decides: a paraphrase that reached the log is refused here.
    const core = await seededCore(PARAPHRASE, pageHashValue);
    const { run } = await validate({ core, page: PAGE, quote: true });

    expect(run.decision).toBe("reject");
    expect(run.reason).toBe(quotationReason("span absent"));
  });

  it("never offers a record sealed under v0.6, and takes no capture for it", async () => {
    const core = await seededCore(SPAN, pageHashValue);
    const legacy = { ...core } as Record<string, unknown>;
    delete legacy["domain"];
    const http = new StubLog();
    http.entry = { ...legacy, signature: "sig" };
    const fetcher = new FixtureFetcher({ [CITATION]: PAGE });
    const run = await runValidator({
      baseUrl: BASE,
      entryId: core["id"] as string,
      quote: true,
      io,
      deps: { http, fetcher, now: NOW, key },
    });

    expect([run.ok, run.error]).toEqual([false, "legacy_entry"]);
    expect(fetcher.requests).toEqual([]);
    expect(http.posted).toEqual([]);
  });

  it("is unchanged without the flag", async () => {
    const core = await seededCore(PARAPHRASE, pageHashValue);
    const { run } = await validate({ core, page: PAGE });
    // The claim is not in the page, and without the flag that is not a question
    // this validator asks: the hash is the entry's, so it approves.
    expect([run.decision, run.reason]).toEqual(["approve", null]);

    const moved = await seededCore(SPAN, pageHashValue);
    const second = await validate({ core: moved, page: MOVED });
    expect([second.run.decision, second.run.reason]).toEqual([
      "reject",
      SNAPSHOT_MISMATCH,
    ]);
  });

  it("puts the same span question to both commands", async () => {
    const core = await seededCore(SPAN, pageHashValue);
    expect(extractCore({ ...core, status: "draft" })["claim"]).toBe(SPAN);
    // The capture is already in the norm rule's spelling -- `snapshotHash`
    // extracted and normalized it -- so it is the span that is folded, the same
    // way and no further.
    expect(containsSpan({ text: "a b", status: 200 }, " a  b ")).toBe(true);
    expect(containsSpan({ text: "a b", status: 200 }, "a c")).toBe(false);
    expect(containsSpan({ text: null, status: 200 }, "a")).toBe(false);
  });

  it("composes the run URL from what a runner sets", () => {
    expect(runUrlFrom({ GITHUB_RUN_URL: RUN_URL })).toBe(RUN_URL);
    expect(
      runUrlFrom({
        GITHUB_SERVER_URL: "https://github.com",
        GITHUB_REPOSITORY: "nomankind-ai/bootstrap",
        GITHUB_RUN_ID: "42",
      }),
    ).toBe(RUN_URL);
    expect(runUrlFrom({})).toBeNull();
    expect(runUrlFrom({ GITHUB_SERVER_URL: "https://github.com" })).toBeNull();
  });

  it("reads --quote, and refuses it beside a duplicate judgment", () => {
    const parsed = parseValidatorArgs(["k.json", BASE, "nmk_abc", "--quote"]);
    expect(parsed?.quote).toBe(true);
    expect(parseValidatorArgs(["k.json", BASE, "nmk_abc"])?.quote).toBe(false);
    expect(
      parseValidatorArgs([
        "k.json",
        BASE,
        "nmk_abc",
        "--quote",
        "--duplicate-of",
        "nmk_def",
      ]),
    ).toBeNull();
  });
});

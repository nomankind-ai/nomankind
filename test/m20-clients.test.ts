/**
 * The four M20 commands, driven in process against a fake serving side.
 *
 * Whitepaper Section 6, "Dispute" and "Revalidate", Section 8, "Failure
 * reports", and Section 11's joining steps. Each command is one operator's or
 * one reader's half of a sentence in those sections, and what is under test here
 * is that half: what a run refuses before it touches the network, what it asks
 * for and in what order, what it puts in the body, and what it does with the
 * answer.
 *
 * Everything is real except the HTTP layer: real Ed25519 keys, real signed
 * requests over the real canonical bytes, real attestations, real cores built by
 * the real submit kernel and hashed by the real norm rule against real fixture
 * bytes. The answers are canned because the routes belong to the Worker and are
 * tested through the doors in test/m20-end-to-end.test.ts.
 */

import { describe, expect, it } from "vitest";

import {
  checkDisputeFields,
  disputePlan,
  runDispute,
  type DisputeDeps,
} from "../src/cli/dispute.js";
import { registerPlan, runRegister, payoutReferenceFor } from "../src/cli/register.js";
import { checkReport, reportPlan, runReport } from "../src/cli/report.js";
import { revalidatePlan, runRevalidate } from "../src/cli/revalidate.js";
import type {
  HttpClient,
  ValidatorIo,
  ValidatorKey,
} from "../src/cli/validator.js";
import { DEFAULT_DOMAIN, NORM_VERSION } from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { makeAgent } from "./helpers/registry.js";
import { FixtureFetcher, pageHash, type FixturePage } from "./helpers/submit.js";

const BASE = "https://nomankind.example";
const TARGET = "nmk_0123456789abcdef0123456789abcdef";
const OPERATOR = "kestrel.example";
const SUBJECT = "kestrel/kestrel-1";
const NOW = new Date("2026-09-09T12:00:00.000Z");

/** The page every correction and every check in this file cites. */
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><p>$44 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PAGE_URL = "https://kestrel.example/pricing";

// ---------------------------------------------------------------------------
// The way out of the process
// ---------------------------------------------------------------------------

/** One request the fake was asked to make, kept whole so a test can read it. */
interface Asked {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}

/** A canned answer: the status and the JSON body the route would have sent. */
interface Canned {
  readonly status: number;
  readonly body: unknown;
}

/** The fake serving side, recording exactly what was asked of it. */
class FakeHttp implements HttpClient {
  readonly asked: Asked[] = [];

  constructor(private readonly answer: (path: string, nth: number) => Canned) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = `${url.pathname}${url.search}`;
    let body: unknown = null;
    if (request.method !== "GET") {
      const text = await request.clone().text();
      body = text === "" ? null : JSON.parse(text);
    }
    const nth = this.asked.length;
    this.asked.push({ method: request.method, path, body });
    const canned = this.answer(path, nth);
    return new Response(JSON.stringify(canned.body), {
      status: canned.status,
      headers: { "content-type": "application/json" },
    });
  }
}

/** The lines one run printed. */
interface Printed {
  readonly out: string[];
  readonly err: string[];
  readonly io: ValidatorIo;
}

function printer(): Printed {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      stdout: (line: string) => out.push(line),
      stderr: (line: string) => err.push(line),
    },
  };
}

async function key(): Promise<ValidatorKey> {
  const agent = await makeAgent();
  return { agentId: agent.agentId, privateKey: agent.privateKey };
}

/** The entry a read of the target answers with, as far as these commands care. */
function targetEntry(id: string, citation: string): Record<string, unknown> {
  return {
    id,
    subject: SUBJECT,
    category: "pricing",
    claim: "seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation,
    snapshot_hash:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY",
    author_operator: null,
    submitted_at: "2026-09-01T14:05:00Z",
    signature: "AA",
    status: "verified",
  };
}

/** The agent lookup the core builder makes to learn its own operator. */
function agentBody(operator: string | null): Record<string, unknown> {
  return operator === null ? {} : { operator: { id: operator } };
}

function disputeDeps(http: HttpClient, io: ValidatorIo): DisputeDeps {
  return {
    http,
    fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
    now: NOW,
    io,
  };
}

/** The fields a challenger writes in their file. */
const FIELDS = Object.freeze({
  claim: "seat pricing is $44 per seat per month, not $40",
  before: "$40 per seat per month",
  after: "$44 per seat per month",
  effective_at: "2026-09-02",
  citation: PAGE_URL,
});

// ---------------------------------------------------------------------------
// dispute
// ---------------------------------------------------------------------------

describe("dispute: arguments", () => {
  const good = ["key.json", BASE, TARGET, "fields.json"];

  it("reads the four positional arguments and no flags", () => {
    expect(disputePlan(good)).toEqual({
      keyPath: "key.json",
      baseUrl: BASE,
      targetId: TARGET,
      fieldsPath: "fields.json",
      fromReport: null,
      fromRevalidation: null,
    });
  });

  it("reads both upgrade links", () => {
    const plan = disputePlan([
      ...good,
      "--from-report",
      "12",
      "--from-revalidation",
      "0",
    ]);
    expect([plan?.fromReport, plan?.fromRevalidation]).toEqual([12, 0]);
  });

  for (const args of [
    [],
    ["key.json"],
    ["key.json", BASE],
    ["key.json", BASE, TARGET],
    [...good, "extra"],
    [...good, "--from-report"],
    [...good, "--from-report", "--from-revalidation"],
    [...good, "--from-report", "-1"],
    [...good, "--from-report", "twelve"],
    [...good, "--from-report", "1", "--from-report", "2"],
    [...good, "--unknown", "1"],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args)}`, () => {
      expect(disputePlan(args)).toBeNull();
    });
  }
});

describe("dispute: the fields a challenger may set", () => {
  it("fills the subject from the target and the category from the paper", () => {
    const checked = checkDisputeFields(FIELDS, SUBJECT);
    expect(checked.ok).toBe(true);
    expect(checked.ok && checked.fields).toEqual({
      ...FIELDS,
      subject: SUBJECT,
      category: "correction",
      // Decision D-071: the challenge is filed in the target's own domain, and
      // the challenger has no say in it.
      domain: DEFAULT_DOMAIN,
    });
  });

  it("keeps a subject the challenger stated", () => {
    const checked = checkDisputeFields(
      { ...FIELDS, subject: "other/model" },
      SUBJECT,
    );
    expect(checked.ok && checked.fields["subject"]).toBe("other/model");
  });

  for (const [name, fields] of [
    ["not an object", "nope"],
    ["a category of its own", { ...FIELDS, category: "pricing" }],
    ["a supersedes", { ...FIELDS, supersedes: TARGET }],
    ["a subject that is not a string", { ...FIELDS, subject: 7 }],
  ] as const) {
    it(`refuses ${name}`, () => {
      const checked = checkDisputeFields(fields, SUBJECT);
      expect(checked.ok).toBe(false);
      expect(!checked.ok && checked.reason).toBe("bad_fields");
    });
  }
});

describe("dispute: what one run asks for", () => {
  it("reads the target, builds a signed correction, and files it", async () => {
    const signer = await key();
    const printed = printer();
    let filed: unknown = null;
    const http = new FakeHttp((path) => {
      if (path === `/entries/${TARGET}`) {
        return { status: 200, body: targetEntry(TARGET, PAGE_URL) };
      }
      if (path.startsWith("/agents/")) {
        return { status: 200, body: agentBody(OPERATOR) };
      }
      return {
        status: 201,
        body: {
          correction: { id: "nmk_" + "a".repeat(32), status: "draft" },
          target: { id: TARGET, status: "verified" },
        },
      };
    });

    const run = await runDispute({
      key: signer,
      baseUrl: BASE,
      targetId: TARGET,
      fields: FIELDS,
      fromReport: 12,
      deps: disputeDeps(http, printed.io),
    });

    expect([run.ok, run.status, run.error]).toEqual([true, 201, null]);
    expect(run.targetStatus).toBe("verified");

    // The order: the target, then the agent lookup the core needs, then the
    // filing. Nothing is posted before the core is built and signed.
    expect(http.asked.map((asked) => asked.method)).toEqual([
      "GET",
      "GET",
      "POST",
    ]);
    expect(http.asked[0]!.path).toBe(`/entries/${TARGET}`);
    expect(http.asked[2]!.path).toBe(`/entries/${TARGET}/dispute`);

    filed = http.asked[2]!.body as Record<string, unknown>;
    const body = filed as Record<string, unknown>;
    const sent = body["entry"] as Record<string, unknown>;
    expect(sent["category"]).toBe("correction");
    expect(sent["subject"]).toBe(SUBJECT);
    expect(sent["author"]).toBe(signer.agentId);
    expect(sent["author_operator"]).toBe(OPERATOR);
    expect(sent["snapshot_hash"]).toBe(await pageHash(PAGE));
    expect(sent["id"]).toBe(run.correctionId);
    expect(typeof sent["signature"]).toBe("string");
    // The upgrade link travels, and the one that was not asked for does not.
    expect(body["from_report_seq"]).toBe(12);
    expect("from_revalidation_seq" in body).toBe(false);

    expect(printed.out).toEqual([
      `correction ${run.correctionId}`,
      `target ${TARGET} status verified`,
    ]);
  });

  it("stops before the network when the target cannot be read", async () => {
    const printed = printer();
    const http = new FakeHttp(() => ({
      status: 404,
      body: { error: "not_found" },
    }));

    const run = await runDispute({
      key: await key(),
      baseUrl: BASE,
      targetId: TARGET,
      fields: FIELDS,
      deps: disputeDeps(http, printed.io),
    });

    expect([run.ok, run.status, run.error]).toEqual([false, null, "not_found"]);
    expect(http.asked.length).toBe(1);
  });

  it("names the route's refusal and files nothing else", async () => {
    const printed = printer();
    const http = new FakeHttp((path) => {
      if (path === `/entries/${TARGET}`) {
        return { status: 200, body: targetEntry(TARGET, PAGE_URL) };
      }
      if (path.startsWith("/agents/")) {
        return { status: 200, body: agentBody(null) };
      }
      return { status: 409, body: { error: "dispute_open" } };
    });

    const run = await runDispute({
      key: await key(),
      baseUrl: BASE,
      targetId: TARGET,
      fields: FIELDS,
      deps: disputeDeps(http, printed.io),
    });

    expect([run.ok, run.status, run.error]).toEqual([
      false,
      409,
      "dispute_open",
    ]);
    expect(printed.out).toEqual(["response 409 dispute_open"]);
  });
});

// ---------------------------------------------------------------------------
// revalidate
// ---------------------------------------------------------------------------

describe("revalidate: arguments", () => {
  const good = ["key.json", BASE, TARGET];

  it("asks for a check when no verdict is given", () => {
    expect(revalidatePlan(good)).toEqual({
      keyPath: "key.json",
      baseUrl: BASE,
      entryId: TARGET,
      resolve: null,
    });
  });

  for (const word of ["held", "changed"] as const) {
    it(`answers one with --resolve ${word}`, () => {
      expect(revalidatePlan([...good, "--resolve", word])?.resolve).toBe(word);
    });
  }

  for (const args of [
    [],
    ["key.json", BASE],
    [...good, "extra"],
    [...good, "--resolve"],
    // A word that is not one of the two must never be read as one of them: it
    // decides whose stake is forfeited.
    [...good, "--resolve", "true"],
    [...good, "--resolve", "Held"],
    [...good, "--resolve", "held", "--resolve", "changed"],
    [...good, "--assigned"],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args)}`, () => {
      expect(revalidatePlan(args)).toBeNull();
    });
  }
});

describe("revalidate: what one run asks for", () => {
  it("posts an empty body to the request door", async () => {
    const signer = await key();
    const printed = printer();
    const http = new FakeHttp(() => ({
      status: 201,
      body: { id: TARGET, status: "verified" },
    }));

    const run = await runRevalidate({
      key: signer,
      baseUrl: BASE,
      entryId: TARGET,
      deps: {
        http,
        fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
        now: NOW,
        io: printed.io,
      },
    });

    expect([run.ok, run.status]).toEqual([true, 201]);
    expect(http.asked).toEqual([
      { method: "POST", path: `/entries/${TARGET}/revalidate`, body: {} },
    ]);
    expect(printed.out).toEqual(["response 201"]);
  });

  it("fetches, hashes and signs the record the checker answers with", async () => {
    const signer = await key();
    const printed = printer();
    const http = new FakeHttp((path) => {
      if (path === `/entries/${TARGET}`) {
        return { status: 200, body: targetEntry(TARGET, PAGE_URL) };
      }
      if (path.startsWith("/agents/")) {
        return { status: 200, body: agentBody(OPERATOR) };
      }
      return { status: 200, body: { id: TARGET, status: "verified" } };
    });

    const run = await runRevalidate({
      key: signer,
      baseUrl: BASE,
      entryId: TARGET,
      resolve: "changed",
      deps: {
        http,
        fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
        now: NOW,
        io: printed.io,
      },
    });

    expect([run.ok, run.status]).toEqual([true, 200]);
    const posted = http.asked[2]!;
    expect(posted.path).toBe(`/entries/${TARGET}/revalidate/resolve`);
    const body = posted.body as Record<string, unknown>;
    expect(body["held"]).toBe(false);
    expect(body["record"]).toEqual({
      agent: signer.agentId,
      operator: OPERATOR,
      snapshot_hash: await pageHash(PAGE),
      reproduction: null,
      observation: null,
      signed_at: NOW.toISOString(),
    });
    expect(typeof body["signature"]).toBe("string");
    expect(printed.out[0]).toBe(`check changed hash ${await pageHash(PAGE)}`);
  });

  it("stops when the key belongs to no operator", async () => {
    const printed = printer();
    const http = new FakeHttp((path) => {
      if (path === `/entries/${TARGET}`) {
        return { status: 200, body: targetEntry(TARGET, PAGE_URL) };
      }
      return { status: 404, body: { error: "not_found" } };
    });

    const run = await runRevalidate({
      key: await key(),
      baseUrl: BASE,
      entryId: TARGET,
      resolve: "held",
      deps: {
        http,
        fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
        now: NOW,
        io: printed.io,
      },
    });

    expect([run.ok, run.error]).toEqual([false, "unregistered_agent"]);
    expect(http.asked.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

const ARTIFACT = Object.freeze({
  method: "endpoint_error",
  subject: SUBJECT,
  test: "contains:$40",
  request: { method: "GET", url: PAGE_URL, headers: {} },
  response: {
    status: 404,
    final_url: PAGE_URL,
    content_type: "text/html",
    snapshot_hash:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  },
  billing: null,
  observed_at: "2026-09-08",
  observer: "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY",
});

describe("report: arguments", () => {
  const good = ["key.json", BASE, TARGET, "report.json"];

  it("reads the four positional arguments", () => {
    expect(reportPlan(good)).toEqual({
      keyPath: "key.json",
      baseUrl: BASE,
      entryId: TARGET,
      reportPath: "report.json",
    });
  });

  for (const args of [
    [],
    ["key.json", BASE, TARGET],
    [...good, "extra"],
    [...good, "--citation"],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args)}`, () => {
      expect(reportPlan(args)).toBeNull();
    });
  }
});

describe("report: the file a reader writes", () => {
  it("passes the artifact through untouched and keeps a citation", () => {
    const checked = checkReport({
      observed: "the page 404s",
      artifact: ARTIFACT,
      citation: PAGE_URL,
    });
    expect(checked.ok && checked.body).toEqual({
      observed: "the page 404s",
      artifact: ARTIFACT,
      citation: PAGE_URL,
    });
  });

  it("leaves the citation out entirely when there is none", () => {
    const checked = checkReport({ observed: "the page 404s", artifact: ARTIFACT });
    expect(checked.ok && "citation" in checked.body).toBe(false);
  });

  for (const [name, report] of [
    ["not an object", []],
    ["an empty observation", { observed: "   ", artifact: ARTIFACT }],
    ["no observation at all", { artifact: ARTIFACT }],
    ["no artifact", { observed: "the page 404s" }],
    ["an artifact that is not an object", { observed: "x", artifact: "y" }],
    [
      "a field a report does not have",
      { observed: "x", artifact: ARTIFACT, entry: TARGET },
    ],
    [
      "a citation that is not a string",
      { observed: "x", artifact: ARTIFACT, citation: 7 },
    ],
  ] as const) {
    it(`refuses ${name}`, () => {
      const checked = checkReport(report);
      expect(checked.ok).toBe(false);
      expect(!checked.ok && checked.reason).toBe("bad_report");
    });
  }
});

describe("report: what one run asks for", () => {
  it("files one report and says whether it opened a check", async () => {
    const printed = printer();
    const http = new FakeHttp(() => ({
      status: 201,
      body: { entry: { id: TARGET }, opened_revalidation: true },
    }));

    const run = await runReport({
      key: await key(),
      baseUrl: BASE,
      entryId: TARGET,
      report: { observed: "the page 404s", artifact: ARTIFACT },
      deps: { http, now: NOW, io: printed.io },
    });

    expect([run.ok, run.status, run.openedRevalidation]).toEqual([
      true,
      201,
      true,
    ]);
    expect(http.asked[0]!.path).toBe(`/entries/${TARGET}/failure-reports`);
    expect(http.asked[0]!.body).toEqual({
      observed: "the page 404s",
      artifact: ARTIFACT,
    });
    expect(printed.out).toEqual([
      `report filed on ${TARGET}`,
      "revalidation opened",
    ]);
  });

  it("sends nothing when the file is not a report", async () => {
    const printed = printer();
    const http = new FakeHttp(() => ({ status: 201, body: {} }));

    const run = await runReport({
      key: await key(),
      baseUrl: BASE,
      entryId: TARGET,
      report: { observed: "", artifact: ARTIFACT },
      deps: { http, now: NOW, io: printed.io },
    });

    expect([run.ok, run.status, run.error]).toEqual([false, null, "bad_report"]);
    expect(http.asked).toEqual([]);
    expect(printed.err[0]).toContain("bad_report");
  });
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

describe("register: arguments", () => {
  const good = ["key.json", BASE, OPERATOR];

  it("reads the three positional arguments", () => {
    expect(registerPlan(good)).toEqual({
      keyPath: "key.json",
      baseUrl: BASE,
      domain: OPERATOR,
      // Decision D-071: `--domain` defaults to the one domain there was, and
      // `--join` is absent on an ordinary registration.
      recordDomain: DEFAULT_DOMAIN,
      join: null,
      genesisKeyPath: null,
    });
  });

  it("reads the maintainer key --genesis names", () => {
    expect(registerPlan([...good, "--genesis", "m.json"])?.genesisKeyPath).toBe(
      "m.json",
    );
  });

  for (const args of [
    [],
    ["key.json", BASE],
    [...good, "extra"],
    [...good, "--genesis"],
    [...good, "--genesis", "--other"],
    [...good, "--genesis", "a.json", "--genesis", "b.json"],
    [...good, "--trusted"],
  ]) {
    it(`refuses before any I/O: ${JSON.stringify(args)}`, () => {
      expect(registerPlan(args)).toBeNull();
    });
  }
});

describe("register: what one run asks for", () => {
  it("prints the TXT record first, then registers and names", async () => {
    const operatorKey = await key();
    const maintainerKey = await key();
    const printed = printer();
    const http = new FakeHttp((path) =>
      path === "/operators"
        ? { status: 201, body: { id: OPERATOR } }
        : { status: 200, body: { operator: OPERATOR, trusted: true } },
    );

    const run = await runRegister({
      key: operatorKey,
      baseUrl: BASE,
      domain: OPERATOR,
      genesisKey: maintainerKey,
      deps: { http, now: NOW, io: printed.io },
    });

    expect([run.ok, run.status, run.genesisStatus]).toEqual([true, 201, 200]);
    // Step one is the operator's to make, so it is printed before anything is
    // asked of the door.
    expect(printed.out[0]).toBe(
      `txt ${txtRecordName(OPERATOR)} TXT ${operatorKey.agentId}`,
    );
    expect(http.asked.map((asked) => asked.path)).toEqual([
      "/operators",
      "/genesis",
    ]);

    const body = http.asked[0]!.body as Record<string, unknown>;
    expect(body["operator"]).toBe(OPERATOR);
    expect(body["payout"]).toEqual({
      reference: payoutReferenceFor(OPERATOR),
    });
    const attestation = body["attestation"] as Record<string, unknown>;
    expect(typeof attestation["signature"]).toBe("string");
    expect(attestation["signed_at"]).toBe(NOW.toISOString());
    expect(http.asked[1]!.body).toEqual({ operator: OPERATOR });
  });

  it("does not name an operator whose registration was refused", async () => {
    const printed = printer();
    const http = new FakeHttp(() => ({
      status: 422,
      body: { error: "dns_no_record" },
    }));

    const run = await runRegister({
      key: await key(),
      baseUrl: BASE,
      domain: OPERATOR,
      genesisKey: await key(),
      deps: { http, now: NOW, io: printed.io },
    });

    expect([run.ok, run.error, run.genesisStatus]).toEqual([
      false,
      "dns_no_record",
      null,
    ]);
    expect(http.asked.map((asked) => asked.path)).toEqual(["/operators"]);
  });

  it("treats an operator that is already there as joined", async () => {
    const printed = printer();
    const http = new FakeHttp(() => ({
      status: 409,
      body: { error: "operator_exists" },
    }));

    const run = await runRegister({
      key: await key(),
      baseUrl: BASE,
      domain: OPERATOR,
      deps: { http, now: NOW, io: printed.io },
    });

    expect([run.ok, run.already, run.genesisStatus]).toEqual([
      true,
      true,
      null,
    ]);
  });
});

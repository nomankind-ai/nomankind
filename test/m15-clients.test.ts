/**
 * The two M15 client commands, driven in process against the real Worker.
 *
 * Whitepaper, Lifecycle of an entry: an agent submits a signed entry, validators
 * decide it, and "any trusted operator can reconfirm a stale entry by taking a
 * fresh snapshot and signing that the source still says what the entry says ...
 * When a fact has changed rather than merely aged, the fix is a new entry that
 * supersedes the old one." `npm run submit` and `npm run reconfirm` are the
 * client side of those two sentences, and this file walks both of them the way
 * an operator would: over the demo checkpoint's own world, against the real
 * router, with real Ed25519 keys and real signatures over the real canonical
 * bytes.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with the migrations applied, the archive is miniflare's R2, the
 * entries come back out of derivation and the sweep is the one the alarm runs.
 * Only the DNS resolver, the payment provider, the page fetch and the beacon are
 * injected, because only those are not ours to run in a test.
 *
 * The clock moves forward through the file in the paper's own days: day 0 is the
 * checkpoint, day 90 is the last fresh day, day 91 is the first stale one.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  buildTranscriptArtifact,
  transcriptArtifactHash,
} from "../src/artifact.js";
import {
  CHECKPOINT_CITATION,
  CHECKPOINT_DOMAINS,
  CHECKPOINT_SUBJECT,
  runCheckpoint,
} from "../src/cli/checkpoint.js";
import { CANNOT_REPRODUCE, runReconfirm } from "../src/cli/reconfirm.js";
import { BAD_FIELDS, checkFields, runSubmit } from "../src/cli/submit.js";
import {
  duplicateReason,
  parseValidatorArgs,
  runValidator,
  SNAPSHOT_MISMATCH,
  USAGE,
  type HttpClient,
  type ValidatorIo,
} from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import type { Event } from "../src/events.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  stalenessWindowDays,
} from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { getEntry } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  makeAgent,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";

/** Day 0: the instant the checkpoint is walked at. */
const NOW = SUBMIT_NOW;

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

/** The window a `limit` entry carries, read from the published policy. */
// Decision D-071: the window is the domain's table, not a global one.
const WINDOW_DAYS = stalenessWindowDays(DEFAULT_DOMAIN, "limit") as number;

/** The instant `days` after day 0, at the same time of day. */
function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

/** The UTC calendar date `days` after day 0, as the schema writes a date. */
function dayDate(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// The page the seeded entries cite
// ---------------------------------------------------------------------------

const SEED_PAGE: FixturePage = {
  body: [
    "<!doctype html><html><head><title>example/demo-model</title></head>",
    "<body><main><h1>example/demo-model</h1>",
    "<p>90 requests per minute</p></main></body></html>",
  ].join(""),
  contentType: "text/html; charset=utf-8",
};

/** The same URL, saying something else: a source that moved under the entry. */
const CHANGED_PAGE: FixturePage = {
  body: [
    "<!doctype html><html><head><title>example/demo-model</title></head>",
    "<body><main><h1>example/demo-model</h1>",
    "<p>30 requests per minute</p></main></body></html>",
  ].join(""),
  contentType: "text/html; charset=utf-8",
};

const PAGES: Record<string, FixturePage> = { [CHECKPOINT_CITATION]: SEED_PAGE };
const CHANGED_PAGES: Record<string, FixturePage> = {
  [CHECKPOINT_CITATION]: CHANGED_PAGE,
};

/** The seed page's hash under the real norm rule. */
let SEED_HASH = "";

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

const lines: string[] = [];
const io: ValidatorIo = {
  stdout: (line: string) => lines.push(line),
  stderr: (line: string) => lines.push(`stderr ${line}`),
};

let store: TestDatabase;
let maintainer: TestAgent;
let fixtures: TestAgent[];
let env: Env;
let deps: RequestDeps;

/** The instant the router serves at. Moved by the tests, never by the router. */
let clock: Date = NOW;

/** The one way into the Worker: a call into the real router, on the fake clock. */
const http: HttpClient = {
  fetch: (request: Request) => handleRequest(request, env, { ...deps, now: clock }),
};

/** The checkpoint entry: a bare key's stated fact, verified by the first two. */
let checkpointId = "";
/** A behavior entry, submitted for its category alone. */
let behavior: Core;

/** The entry as the public read answers it. */
async function fetched(entryId: string): Promise<Record<string, unknown>> {
  const response = await http.fetch(
    new Request(`${TEST_ORIGIN}/entries/${encodeURIComponent(entryId)}`),
  );
  expect(response.status).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

/** Every event in the log, read through the public page as a reader would. */
async function logEvents(): Promise<Event[]> {
  const all: Event[] = [];
  let query = `/events?limit=${LIST_PAGE_LIMIT}`;
  for (;;) {
    const response = await http.fetch(new Request(`${TEST_ORIGIN}${query}`));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { events: Event[] };
    all.push(...body.events);
    if (body.events.length < LIST_PAGE_LIMIT) break;
    query = `/events?after=${body.events[body.events.length - 1]!.seq}&limit=${LIST_PAGE_LIMIT}`;
  }
  return all;
}

/** The sidecar's read-share slot holders, which the entry never carries. */
async function slotHolders(entryId: string): Promise<string[]> {
  const row = await getEntry(store.db, entryId);
  expect(row).not.toBeNull();
  return (row!.sidecar.read_share_slots ?? []).map((slot) => slot.operator);
}

/** Run the sweep the alarm runs, at the instant the caller names. */
async function sweep(at: Date): Promise<void> {
  const beacon = new FixtureBeacon("m15-clients");
  await beacon.advance(at.toISOString());
  await runSweep(env, { now: at, beacon });
}

/** The author's own fields of one seeded stated entry. */
function fieldsFor(
  claim: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    subject: CHECKPOINT_SUBJECT,
    category: "limit",
    // Decision D-071: the fields file names the domain the author signs, and a
    // file without one is `bad_fields` before any I/O.
    domain: DEFAULT_DOMAIN,
    claim,
    before: "m15 clients: no documented request limit",
    after: "m15 clients: the cited page is the documented request limit",
    effective_at: "2026-09-03",
    citation: CHECKPOINT_CITATION,
    ...overrides,
  };
}

/** One submit run through the command, on the clock the caller names. */
function submitAt(
  key: TestAgent,
  fields: Record<string, unknown>,
  now: Date = NOW,
): ReturnType<typeof runSubmit> {
  return runSubmit({
    key,
    baseUrl: TEST_ORIGIN,
    fields,
    deps: { http, fetcher: new FixtureFetcher(PAGES), now, io },
  });
}

beforeAll(async () => {
  SEED_HASH = await pageHash(SEED_PAGE);

  store = await openTestDatabase();
  maintainer = await makeAgent();
  fixtures = [await makeAgent(), await makeAgent(), await makeAgent()];

  const records: Record<string, string[]> = {};
  CHECKPOINT_DOMAINS.forEach((domain, index) => {
    records[txtRecordName(domain)] = [fixtures[index]!.agentId];
  });

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
    fetcher: new FixtureFetcher(PAGES),
  };

  // The M14 checkpoint, reused whole: three fixture operators join and are named
  // to the pool, the maintainer seeds one stated entry with a bare key, and the
  // first two fixtures verify it.
  const result = await runCheckpoint({
    baseUrl: TEST_ORIGIN,
    keys: { maintainer, fixtures },
    deps: { http, fetcher: new FixtureFetcher(PAGES), now: NOW, io, outDir: null },
  });
  expect(result.steps.filter((step) => !step.ok)).toEqual([]);
  checkpointId = result.entryId!;

  // A behavior entry, for the one branch this fixture refuses to make up. Its
  // snapshot is the frozen transcript, not a page, so it is built here rather
  // than through the submit command, which snapshots the citation.
  const evidence = {
    model: "example/demo-model",
    prompt: "how many requests per minute?",
    parameters: { temperature: 0 },
    output: "ninety",
    predicate: "contains:ninety",
    observed_at: "2026-09-01",
    provider_statement: null,
  };
  const hashed = await transcriptArtifactHash(
    buildTranscriptArtifact(evidence, evidence.output, evidence.observed_at),
  );
  if (!hashed.ok) throw new Error("m15 clients: the fixture transcript is refused");
  behavior = await submittedCore(maintainer, {
    subject: CHECKPOINT_SUBJECT,
    category: "behavior",
    claim: "m15 clients: the model answers ninety",
    before: "m15 clients: answered something else",
    after: "m15 clients: answers ninety",
    effective_at: "2026-09-01",
    evidence,
    citation: "https://example.com/transcripts/1",
    snapshot_hash: hashed.hash,
  });
  const posted = await http.fetch(await submission(maintainer, { core: behavior }));
  expect(posted.status).toBe(201);
}, 180_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) submit
// ---------------------------------------------------------------------------

describe("submit, from the author's own fields", () => {
  it("refuses a field the author does not choose, before any request", async () => {
    const fetcher = new FixtureFetcher(PAGES);
    let calls = 0;
    const counted: HttpClient = {
      fetch: (request: Request) => {
        calls += 1;
        return http.fetch(request);
      },
    };

    const run = await runSubmit({
      key: maintainer,
      baseUrl: TEST_ORIGIN,
      fields: fieldsFor("m15 clients: a fields file that names the tier", {
        evidence_tier: "stated",
      }),
      deps: { http: counted, fetcher, now: NOW, io },
    });

    expect([run.code, run.error, run.entryId]).toEqual([2, BAD_FIELDS, null]);
    // Nothing was fetched and nothing was asked of the log.
    expect(fetcher.requests).toEqual([]);
    expect(calls).toBe(0);
  });

  for (const field of ["id", "submitted_at", "norm_version", "author", "signature", "snapshot_hash"]) {
    it(`refuses a fields file naming ${field}`, () => {
      const verdict = checkFields(fieldsFor("m15 clients: a claim", { [field]: "x" }));

      expect(verdict.ok).toBe(false);
      if (verdict.ok) return;
      expect([verdict.reason, verdict.detail.includes(field)]).toEqual([BAD_FIELDS, true]);
    });
  }

  it("takes a disclosure beside the fields, and refuses one that is not an object", () => {
    // Decision D-096: `disclosure` is not a core field and is never signed --
    // it is the originals behind a redacted transcript payload, which travel
    // in the body beside the entry, exactly as a receipt does. So the fields
    // file may carry it, and the command checks its shape and nothing more:
    // which pointers it must carry and whether each value hashes to its
    // placeholder is the door's judgment, and a second rule here could only
    // disagree with the first.
    const accepted = checkFields(
      fieldsFor("m15 clients: a claim", {
        disclosure: { "/parameters/request/messages": [{ role: "user" }] },
      }),
    );
    expect(accepted.ok).toBe(true);

    const refused = checkFields(
      fieldsFor("m15 clients: a claim", { disclosure: "a pointer, maybe" }),
    );
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect([refused.reason, refused.detail.includes("disclosure")]).toEqual([
      BAD_FIELDS,
      true,
    ]);
  });

  it("submits a stated entry that comes back draft with the id the kernel derives", async () => {
    const claim = "m15 clients: the cited page documents the request limit";
    const run = await submitAt(maintainer, fieldsFor(claim));

    expect([run.code, run.status, run.entryStatus]).toEqual([0, 201, "draft"]);

    // The id is a function of the signed core and of nothing else, so the same
    // fields built through the kernel name the same entry.
    const expected = await submittedCore(maintainer, {
      subject: CHECKPOINT_SUBJECT,
      category: "limit",
      claim,
      before: "m15 clients: no documented request limit",
      after: "m15 clients: the cited page is the documented request limit",
      effective_at: "2026-09-03",
      citation: CHECKPOINT_CITATION,
      snapshot_hash: SEED_HASH,
    });
    expect(run.entryId).toBe(expected["id"]);

    const entry = await fetched(run.entryId!);
    expect(validateEntry(entry).errors).toEqual([]);
    expect(entry["status"]).toBe("draft");
    expect(entry["evidence_tier"]).toBe("stated");
    expect(entry["snapshot_hash"]).toBe(SEED_HASH);
    // A bare key names no operator, and the command reads that from the registry.
    expect(entry["author_operator"]).toBeNull();
    expect(lines).toContain(`entry ${run.entryId} status draft`);
  });

  it("submits a superseding draft when the fields name a target", async () => {
    const run = await submitAt(
      maintainer,
      // Its own value, not the previous draft's: two entries asserting the same
      // value about the same subject are one claim filed twice, and the door
      // refuses that outright (decision D-085).
      fieldsFor("m15 clients: a first superseding claim on the checkpoint entry", {
        supersedes: checkpointId,
        after: "m15 clients: the cited page is the documented request limit, as filed first",
      }),
    );

    expect([run.code, run.entryStatus]).toEqual([0, "draft"]);
    const entry = await fetched(run.entryId!);
    expect(entry["supersedes"]).toBe(checkpointId);
    // The link is the submitter's assertion; the approvals are the check, and
    // nothing has approved this one, so the target still stands.
    expect((await fetched(checkpointId))["superseded_by"]).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// (b) reconfirm
// ---------------------------------------------------------------------------

describe("reconfirm, by a trusted operator outside the submitter", () => {
  it("refuses to reconfirm on the last fresh day", async () => {
    clock = day(WINDOW_DAYS);
    const run = await runReconfirm({
      key: fixtures[2]!,
      baseUrl: TEST_ORIGIN,
      entryId: checkpointId,
      deps: {
        http,
        fetcher: new FixtureFetcher(PAGES),
        now: clock,
        io,
      },
    });

    // Section 6 gives the trusted pool the stale entries; a check inside the
    // window is a staked revalidation request, which is a later milestone's.
    expect([run.ok, run.status, run.error]).toEqual([false, 409, "entry_not_stale"]);
  });

  it("stops with snapshot_mismatch on a page that moved, and sends nothing", async () => {
    clock = day(WINDOW_DAYS + 1);
    await sweep(clock);
    expect((await fetched(checkpointId))["stale"]).toBe(true);

    const before = await logEvents();
    const run = await runReconfirm({
      key: fixtures[2]!,
      baseUrl: TEST_ORIGIN,
      entryId: checkpointId,
      deps: {
        http,
        // The same URL, saying something else.
        fetcher: new FixtureFetcher(CHANGED_PAGES),
        now: clock,
        io,
      },
    });

    expect([run.ok, run.status, run.error]).toEqual([false, null, SNAPSHOT_MISMATCH]);
    expect(run.record).toBeNull();
    const after = await logEvents();
    expect(after.filter((event) => event.type === "reconfirmation")).toEqual([]);
    expect(after).toHaveLength(before.length);
  });

  it("stops with cannot_reproduce on a behavior entry: no model to rerun", async () => {
    const run = await runReconfirm({
      key: fixtures[2]!,
      baseUrl: TEST_ORIGIN,
      entryId: behavior["id"] as string,
      deps: { http, fetcher: new FixtureFetcher(PAGES), now: clock, io },
    });

    expect([run.ok, run.status, run.error]).toEqual([false, null, CANNOT_REPRODUCE]);
    expect(run.record).toBeNull();
  });

  it("refreshes the stale entry and seats the reconfirmer in a slot", async () => {
    const run = await runReconfirm({
      key: fixtures[2]!,
      baseUrl: TEST_ORIGIN,
      entryId: checkpointId,
      deps: { http, fetcher: new FixtureFetcher(PAGES), now: clock, io },
    });

    expect([run.ok, run.status, run.error]).toEqual([true, 201, null]);
    expect(run.record?.snapshot_hash).toBe(SEED_HASH);
    // A stated entry's attestation is the fresh hash and nothing else.
    expect([run.record?.reproduction, run.record?.observation]).toEqual([null, null]);
    expect(run.record?.operator).toBe(CHECKPOINT_DOMAINS[2]);

    // The window reopened, from the date the attestation was signed.
    expect(run.lastConfirmed).toBe(dayDate(WINDOW_DAYS + 1));
    expect(run.expiresAt).toBe(dayDate(WINDOW_DAYS + 1 + WINDOW_DAYS));

    const entry = await fetched(checkpointId);
    expect(validateEntry(entry).errors).toEqual([]);
    expect(entry["stale"]).toBe(false);
    expect(entry["status"]).toBe("verified");
    expect(entry["last_confirmed"]).toBe(dayDate(WINDOW_DAYS + 1));
    expect(entry["reconfirmations"]).toHaveLength(1);

    // Section 9: the reconfirmer rotates into the oldest read-share slot.
    expect(await slotHolders(checkpointId)).toContain(CHECKPOINT_DOMAINS[2]);
    expect(run.slots).toContain(CHECKPOINT_DOMAINS[2]);
    expect(lines).toContain(
      `read_share_slots ${(run.slots ?? []).join(" ")}`,
    );
  });
});

// ---------------------------------------------------------------------------
// (c) supersession, end to end through the two commands
// ---------------------------------------------------------------------------

describe("supersession, through submit and validate", () => {
  it("flips the target only once the superseding entry verifies", async () => {
    const at = day(WINDOW_DAYS + 1);
    clock = at;

    const submitted = await submitAt(
      maintainer,
      fieldsFor("m15 clients: the request limit is now what the cited page says", {
        supersedes: checkpointId,
        after: "m15 clients: the cited page is the documented request limit, as filed second",
      }),
      at,
    );
    expect([submitted.code, submitted.entryStatus]).toEqual([0, "draft"]);
    const superseder = submitted.entryId!;

    expect((await fetched(checkpointId))["superseded_by"]).toBeNull();

    const first = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: superseder,
      deps: { http, fetcher: new FixtureFetcher(PAGES), now: at, key: fixtures[0]! },
      io,
    });
    expect([first.ok, first.decision]).toEqual([true, "approve"]);

    // One approval is not consensus: the target is still standing.
    const between = await fetched(checkpointId);
    expect([between["superseded_by"], between["status"]]).toEqual([null, "verified"]);

    const second = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: superseder,
      deps: { http, fetcher: new FixtureFetcher(PAGES), now: at, key: fixtures[1]! },
      io,
    });
    expect([second.ok, second.decision]).toEqual([true, "approve"]);

    expect((await fetched(superseder))["status"]).toBe("verified");
    const target = await fetched(checkpointId);
    expect(target["superseded_by"]).toBe(superseder);
    expect(target["status"]).toBe("superseded");
    expect(validateEntry(target).errors).toEqual([]);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// (e) validate --duplicate-of
// ---------------------------------------------------------------------------

/**
 * Decision D-085: the mechanical duplicate is refused at the submit door, and
 * the judgment case — two differently worded claims that mean the same thing —
 * is the validators'. A validator who makes that judgment rejects in the
 * published form, `duplicate_claim:<entry id>`, and `npm run validate` carries
 * it under `--duplicate-of`.
 *
 * A judgment about meaning is not settled by a capture, so the run takes none.
 */
describe("validate --duplicate-of", () => {
  it("rejects in the published form, and fetches nothing", async () => {
    const at = day(WINDOW_DAYS + 1);
    clock = at;

    const submitted = await submitAt(
      maintainer,
      fieldsFor("m15 clients: the request limit, said again in other words", {
        after: "m15 clients: the same limit, restated for a validator to judge",
      }),
      at,
    );
    expect([submitted.code, submitted.entryStatus]).toEqual([0, "draft"]);
    const duplicate = submitted.entryId!;

    const fetcher = new FixtureFetcher(PAGES);
    const run = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: duplicate,
      duplicateOf: checkpointId,
      deps: { http, fetcher, now: at, key: fixtures[0]! },
      io,
    });

    expect([run.ok, run.decision, run.reason]).toEqual([
      true,
      "reject",
      duplicateReason(checkpointId),
    ]);
    expect(run.reason).toBe(`duplicate_claim:${checkpointId}`);

    // The whole point: no capture was taken. The judgment is about meaning, and
    // the page could not have settled it either way.
    expect(fetcher.requests).toEqual([]);

    // The record on the log says exactly what the validator signed: the
    // published reason, and no snapshot hash, because it took no snapshot.
    const stored = await fetched(duplicate);
    const approvers = stored["approvers"] as Record<string, unknown>[];
    expect(approvers.length).toBe(1);
    expect(approvers[0]!["decision"]).toBe("reject");
    expect(approvers[0]!["reason"]).toBe(duplicateReason(checkpointId));
    expect(approvers[0]!["snapshot_hash"]).toBeNull();
    expect(validateEntry(stored).errors).toEqual([]);
  }, 60_000);

  it("reads the flag off the command line, and refuses a malformed id", () => {
    const id = checkpointId;
    const base = ["key.json", TEST_ORIGIN, id];

    expect(parseValidatorArgs(base)).toEqual({
      keyPath: "key.json",
      baseUrl: TEST_ORIGIN,
      entryId: id,
      assigned: false,
      duplicateOf: null,
    });

    // The flag's value is the flag's, never a fourth positional argument.
    expect(parseValidatorArgs([...base, "--assigned", "--duplicate-of", id])).toEqual(
      {
        keyPath: "key.json",
        baseUrl: TEST_ORIGIN,
        entryId: id,
        assigned: true,
        duplicateOf: id,
      },
    );

    // An id nobody could have minted, and a flag with nothing after it: the
    // usage line, exit 2, rather than a signed reason that parses to nothing.
    expect(parseValidatorArgs([...base, "--duplicate-of", "nmk_nope"])).toBeNull();
    expect(parseValidatorArgs([...base, "--duplicate-of", id.toUpperCase()])).toBeNull();
    expect(parseValidatorArgs([...base, "--duplicate-of"])).toBeNull();
    expect(parseValidatorArgs([...base, "extra", "--duplicate-of", id])).toBeNull();
    expect(USAGE).toContain("--duplicate-of <entry-id>");
  });

  it("refuses a malformed id inside the run too, before any request", async () => {
    const fetcher = new FixtureFetcher(PAGES);
    const run = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: checkpointId,
      duplicateOf: "not-an-entry-id",
      deps: { http, fetcher, now: day(WINDOW_DAYS + 1), key: fixtures[2]! },
      io,
    });

    expect([run.ok, run.error, run.decision]).toEqual([
      false,
      "bad_duplicate_of",
      null,
    ]);
    expect(fetcher.requests).toEqual([]);
  }, 60_000);
});

/**
 * M15 end to end: reconfirming, superseding and going stale, through the Worker
 * and the sweep.
 *
 * Whitepaper, Lifecycle of an entry, Revalidate: "Any trusted operator can
 * reconfirm a stale entry by taking a fresh snapshot and signing that the source
 * still says what the entry says ... A reconfirmation appends a fresh
 * attestation, advances the derived last-confirmed date and reopens the
 * freshness window. When a fact has changed rather than merely aged, the fix is
 * a new entry that supersedes the old one." Section 7, Freshness and decay:
 * "Past its window an entry stays verified but shows as stale ... Stale entries
 * earn half rate, and the withheld half builds up on the entry as a
 * reconfirmation bounty, paid to whoever makes it fresh again." Section 9:
 * reconfirming "rotates the reconfirmer into one of the three validator
 * read-share slots for the window it reopened".
 *
 * Everything here is real except the network. The requests are signed with
 * generated Ed25519 keys and verified by the Worker, the record signatures are
 * real nomankind-record-v1 signatures over the real canonical bytes, the
 * database is miniflare's D1 with every migration applied, the entries come back
 * out of derivation and are checked against the published schema, and the sweep
 * under test is the one the cron trigger runs. Only the DNS resolver, the
 * payment provider, the page fetch and the beacon are injected, because only
 * those are not ours to run in a test, and the clock is injected because nothing
 * under src/ is allowed to read one.
 *
 * The clock moves forward through the file, in the paper's own days: day 0 is
 * the submission, day 90 is the last fresh day, day 91 is the first stale one.
 * Every refusal asserts the log's head is exactly where it was, because a door
 * that refuses must leave no trace in the record.
 *
 * One world, one pool, under the ten-operator switch: this is the paper's small
 * pool checkpoint, where two approvals verify and the sweep draws nothing.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import {
  appendEvent,
  type ApproverRecord,
  type Event,
  type ReconfirmationRecord,
} from "../src/events.js";
import {
  APPROVALS_TO_VERIFY_SMALL_POOL,
  LIST_PAGE_LIMIT,
  STALENESS_WINDOW_DAYS,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import type { SubmissionProposal } from "../src/submit.js";
import {
  appendEvents,
  bountiesForEntry,
  eventBySeq,
  getEntry,
  headSeq,
  putAgent,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
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

// ---------------------------------------------------------------------------
// The schema, with a switch the last test can throw
// ---------------------------------------------------------------------------

/**
 * The one thing in this file that is not real.
 *
 * The sweep's staleness step has to put the re-derived entry past the published
 * schema before it stores it, the same way the submit, validate and reconfirm
 * doors do. Pinning that needs an entry the schema refuses, and there is no
 * honest world here that produces one: derivation over a real log always yields
 * a valid entry, which is the whole point of it. So the schema module is wrapped
 * rather than replaced — every call goes to the real validator — and one test
 * flips `refuse` for the length of a single sweep. Delete the `validateEntry`
 * call from src/worker/sweep.ts and that test, and only that test, fails.
 */
const schemaGate = vi.hoisted(() => ({ refuse: false }));

vi.mock("../src/schema.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/schema.js")>();
  return {
    ...actual,
    validateEntry: (value: unknown) =>
      schemaGate.refuse
        ? {
            ok: false as const,
            errors: [{ path: "", message: "refused by the test" }],
          }
        : actual.validateEntry(value),
  };
});

/** Day 0: the instant every submission and every approval is served at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

/** The pricing window, read from the published policy rather than restated. */
const WINDOW_DAYS = STALENESS_WINDOW_DAYS["pricing"] as number;

/** The instant `days` after day 0, at the same time of day. */
function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

/** The UTC calendar date `days` after day 0, as the schema writes a date. */
function dayDate(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m15";

// ---------------------------------------------------------------------------
// The page the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://kestrel.example/pricing";

const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

/**
 * The pricing page's hash under the real norm rule. Every entry below cites that
 * page, and every approval and every reconfirmation carries this same value as
 * the signer's own hash, which is what an honest operator who fetched the page
 * for themselves would have arrived at.
 */
let PRICING_HASH = "";

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/** One operator and the agent bound to it. */
interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

interface World {
  readonly store: TestDatabase;
  readonly env: Env;
  readonly deps: RequestDeps;
  readonly maintainer: TestAgent;
}

let world: World;
/** The three trusted outside operators of the paper's small-pool checkpoint. */
let a1: Party;
let a2: Party;
let a3: Party;
/** A fourth trusted operator, which submits an entry of its own. */
let sub: Party;
/** A registered operator the maintainer never named to the pool. */
let untrusted: Party;
/** A second agent under `sub`'s operator, for the submitter-operator rule. */
let subSecondAgent: TestAgent;

/** The checkpoint entry: a bare key's stated fact, verified by a1 and a2. */
let checkpoint: Core;
/** An entry authored under `sub`'s own operator. */
let ownEntry: Core;
/** A verified entry that a later one supersedes. */
let superseded: Core;
/** The entry that supersedes it. */
let superseder: Core;
/** An entry nobody ever validated. */
let draftEntry: Core;

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

/** Send one request, at day 0 unless the caller names another instant. */
function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, now });
}

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

/** The log's head, or null when nothing has been written. */
function head(): Promise<number | null> {
  return headSeq(world.store.db);
}

/** Send a request that must be refused, and prove it wrote nothing. */
async function refused(
  request: Request,
  status: number,
  error: string,
  now: Date = NOW,
): Promise<Record<string, unknown>> {
  const before = await head();
  const response = await send(request, now);
  const body = (await response.json()) as Record<string, unknown>;

  expect([response.status, body["error"]]).toEqual([status, error]);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(await head()).toBe(before);
  return body;
}

/** Register one operator through the door, exactly as an outsider would. */
async function register(party: Party): Promise<void> {
  const request = await signedPost(party.agent, {
    path: "/operators",
    body: {
      operator: party.operator,
      attestation: await attestFor(party.agent, party.operator, AT),
      payout: { reference: VERIFIED_REFERENCE },
    },
    timestamp: AT,
  });
  const response = await send(request);
  expect([response.status, party.operator]).toEqual([201, party.operator]);
}

/** Name one registered operator to the trusted pool, as only the maintainer may. */
async function name(party: Party): Promise<void> {
  const request = await signedPost(world.maintainer, {
    path: "/genesis",
    body: { operator: party.operator },
    timestamp: AT,
  });
  const response = await send(request);
  expect([response.status, party.operator]).toEqual([200, party.operator]);
}

// ---------------------------------------------------------------------------
// Submissions, decisions and attestations
// ---------------------------------------------------------------------------

/** A stated pricing proposal citing the fixture page. */
function pricing(
  claim: string,
  overrides: Partial<Omit<SubmissionProposal, "author">> = {},
): Omit<SubmissionProposal, "author"> {
  return {
    subject: "kestrel/kestrel-1",
    category: "pricing",
    claim,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    ...overrides,
  };
}

async function submit(
  author: TestAgent,
  proposal: Omit<SubmissionProposal, "author">,
): Promise<Core> {
  const core = await submittedCore(author, proposal);
  const response = await send(await submission(author, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  return core;
}

/** The schema's approvers[] item, for a stated entry. */
function decision(
  party: Party,
  overrides: Partial<ApproverRecord> = {},
): ApproverRecord {
  return {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: PRICING_HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
    ...overrides,
  };
}

/** One signed decision, ready for the door. */
async function validation(input: {
  entryId: string;
  record: ApproverRecord;
  signingKey: TestAgent;
  timestamp?: string;
}): Promise<Request> {
  const signature = await signRecord(
    input.entryId,
    "validation",
    input.record,
    input.signingKey.privateKey,
  );
  return signedPost(input.signingKey, {
    path: `/entries/${input.entryId}/validate`,
    body: { record: input.record, signature },
    timestamp: input.timestamp ?? AT,
  });
}

/** Approve one entry as this party, and answer the derived entry that came back. */
async function approve(
  entryId: string,
  party: Party,
): Promise<Record<string, unknown>> {
  const response = await send(
    await validation({ entryId, record: decision(party), signingKey: party.agent }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as Record<string, unknown>;
}

/** The schema's reconfirmations[] item, for a stated entry. */
function attestation(
  party: Party,
  at: Date,
  overrides: Partial<ReconfirmationRecord> = {},
): ReconfirmationRecord {
  return {
    agent: party.agent.agentId,
    operator: party.operator,
    snapshot_hash: PRICING_HASH,
    reproduction: null,
    observation: null,
    signed_at: at.toISOString(),
    ...overrides,
  };
}

/** One signed reconfirmation, ready for the door. */
async function reconfirmation(input: {
  entryId: string;
  record: ReconfirmationRecord;
  /** The key that signs the record; the record's own agent unless told otherwise. */
  signingKey: TestAgent;
  /** The key that signs the request envelope; the record's own unless told otherwise. */
  signer?: TestAgent;
  /** A signature to send instead of the real one. */
  signature?: string;
  timestamp: string;
}): Promise<Request> {
  const signature =
    input.signature ??
    (await signRecord(
      input.entryId,
      "reconfirmation",
      input.record,
      input.signingKey.privateKey,
    ));
  return signedPost(input.signer ?? input.signingKey, {
    path: `/entries/${input.entryId}/reconfirm`,
    body: { record: input.record, signature },
    timestamp: input.timestamp,
  });
}

/** Every event in the log, read through the public page exactly as a reader would. */
async function logEvents(): Promise<Event[]> {
  const all: Event[] = [];
  // The start of the log is written by omitting `after`, never by "after -1".
  let query = `/events?limit=${LIST_PAGE_LIMIT}`;
  for (;;) {
    const response = await send(get(query));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { events: Event[] };
    all.push(...body.events);
    if (body.events.length < LIST_PAGE_LIMIT) break;
    query = `/events?after=${body.events[body.events.length - 1]!.seq}&limit=${LIST_PAGE_LIMIT}`;
  }
  return all;
}

/** The stored row for one entry, which is what the public read serves. */
async function stored(entryId: string): Promise<Record<string, unknown>> {
  const row = await getEntry(world.store.db, entryId);
  expect(row).not.toBeNull();
  return row!.entry as unknown as Record<string, unknown>;
}

/** The entry as the public read answers it. */
async function fetched(
  entryId: string,
  now: Date = NOW,
): Promise<Record<string, unknown>> {
  const response = await send(get(`/entries/${entryId}`), now);
  expect(response.status).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

/** Run the sweep the cron trigger runs, at the instant the caller names. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m15");
  await beacon.advance(at.toISOString());
  return runSweep(world.env, { now: at, beacon });
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const store = await openTestDatabase();
  const maintainer = await makeAgent();
  a1 = await makeParty("k1.example");
  a2 = await makeParty("k2.example");
  a3 = await makeParty("k3.example");
  sub = await makeParty("submitter.example");
  untrusted = await makeParty("outsider.example");

  const records: Record<string, string[]> = {};
  for (const party of [a1, a2, a3, sub, untrusted]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  world = {
    store,
    env: {
      DB: store.db,
      CAPTURES: store.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: maintainer.agentId,
    },
    deps: {
      now: NOW,
      dns: new FixtureResolver(records),
      payout: new MockPayoutAdapter(),
      fetcher: new FixtureFetcher(PAGES),
    },
    maintainer,
  };

  for (const party of [a1, a2, a3, sub]) {
    await register(party);
    await name(party);
  }
  // Registered and never named: the pool is what genesis says it is, so this
  // operator can knock on the reconfirm door and be told it is not trusted.
  await register(untrusted);

  // A second agent under the submitter's operator. The joining door binds one
  // agent per operator, so this world seals the binding the way the door would:
  // a real agent_bound event on the chain, and the row that indexes it. Section
  // 5's rule is that every agent under an operator counts as one, and this is
  // the only way to put that rule in front of the reconfirm door today.
  subSecondAgent = await makeAgent();
  const at = await headSeq(store.db);
  const previous = at === null ? [] : [(await eventBySeq(store.db, at))!];
  const sealed = await appendEvent(previous, {
    at: AT,
    type: "agent_bound",
    entry_id: null,
    payload: {
      operator: sub.operator,
      agent: subSecondAgent.agentId,
      attestation: await attestFor(subSecondAgent, sub.operator, AT),
    },
  });
  const bound = sealed[sealed.length - 1]!;
  await appendEvents(store.db, [bound]);
  await putAgent(store.db, {
    agentId: subSecondAgent.agentId,
    operatorId: sub.operator,
    registeredSeq: bound.seq,
  });

  // Section 5: anyone can submit with a bare agent key. The maintainer's own key
  // is a bare key here — it registered no operator — so these entries name no
  // operator and every outside operator may validate them.
  checkpoint = await submit(
    maintainer,
    pricing("Kestrel-1 seat pricing rose to $40 per seat per month"),
  );
  superseded = await submit(
    maintainer,
    pricing("Kestrel-1 seat pricing is listed at $40 per seat per month"),
  );
  draftEntry = await submit(
    maintainer,
    pricing("Kestrel-1 seat pricing is $40 per seat per month, as published"),
  );
  ownEntry = await submit(sub.agent, {
    ...pricing("Kestrel-1 charges $40 per seat per month on its pricing page"),
    author_operator: sub.operator,
  });

  // The paper's checkpoint: two approvals verify, because the pool is under the
  // ten-operator switch.
  await approve(checkpoint["id"] as string, a1);
  const verified = await approve(checkpoint["id"] as string, a2);
  expect(verified["status"]).toBe("verified");

  await approve(superseded["id"] as string, a1);
  await approve(superseded["id"] as string, a2);
  await approve(ownEntry["id"] as string, a1);
  await approve(ownEntry["id"] as string, a2);

  // Freshness and decay: "When a fact has changed rather than merely aged, the
  // fix is a new entry that supersedes the old one." Submitted here, validated
  // in its own test below, because the flip is what that test is about.
  superseder = await submit(
    maintainer,
    pricing("Kestrel-1 seat pricing rose again, to $45 per seat per month", {
      before: "$40 per seat per month",
      after: "$45 per seat per month",
      supersedes: superseded["id"] as string,
    }),
  );
}, 180_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// The checkpoint, and the window that has not run out yet
// ---------------------------------------------------------------------------

describe("the small-pool checkpoint", () => {
  it("verifies on two approvals and carries a ninety-day window", async () => {
    const entry = await fetched(checkpoint["id"] as string);

    expect(validateEntry(entry).errors).toEqual([]);
    expect(entry["status"]).toBe("verified");
    expect(entry["approvers"]).toHaveLength(APPROVALS_TO_VERIFY_SMALL_POOL);
    expect(entry["staleness_window_days"]).toBe(WINDOW_DAYS);
    expect(entry["last_confirmed"]).toBe(dayDate(0));
    expect(entry["expires_at"]).toBe(dayDate(WINDOW_DAYS));
    expect(entry["stale"]).toBe(false);
    expect(entry["reconfirmations"]).toEqual([]);
  });

  it("seats the two promoting approvals in the read-share slots", async () => {
    const row = await getEntry(world.store.db, checkpoint["id"] as string);

    expect(
      row?.sidecar.read_share_slots?.map((slot) => slot.operator),
    ).toEqual([a1.operator, a2.operator]);
  });

  it("refuses a reconfirmation on the last fresh day", async () => {
    // Section 6 gives the trusted pool the STALE entries; a check inside the
    // window is a staked revalidation request, which is a later milestone's.
    const at = day(WINDOW_DAYS);
    await refused(
      await reconfirmation({
        entryId: checkpoint["id"] as string,
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp: at.toISOString(),
      }),
      409,
      "entry_not_stale",
      at,
    );
  });
});

// ---------------------------------------------------------------------------
// Supersession: the flip happens on verification, and nowhere else
// ---------------------------------------------------------------------------

describe("a superseding entry", () => {
  it("is accepted as a draft and changes nothing about its target", async () => {
    const candidate = await fetched(superseder["id"] as string);
    expect(candidate["status"]).toBe("draft");
    expect(candidate["supersedes"]).toBe(superseded["id"]);

    const target = await stored(superseded["id"] as string);
    expect(target["status"]).toBe("verified");
    expect(target["superseded_by"]).toBeNull();
  });

  it("still changes nothing on its first approval", async () => {
    const body = await approve(superseder["id"] as string, a1);
    expect(body["status"]).toBe("draft");

    const target = await stored(superseded["id"] as string);
    expect(target["status"]).toBe("verified");
    expect(target["superseded_by"]).toBeNull();
  });

  it("flips the target in the very request that verifies it", async () => {
    const eventsBefore = (await logEvents()).filter(
      (event) => event.entry_id === superseded["id"],
    ).length;

    const body = await approve(superseder["id"] as string, a2);
    expect(validateEntry(body).errors).toEqual([]);
    expect(body["status"]).toBe("verified");

    const target = await stored(superseded["id"] as string);
    expect(target["superseded_by"]).toBe(superseder["id"]);
    expect(target["status"]).toBe("superseded");
    // The pointer is derived, not appended: the target's own lifecycle in the
    // log is exactly as long as it was before the flip.
    const eventsAfter = (await logEvents()).filter(
      (event) => event.entry_id === superseded["id"],
    ).length;
    expect(eventsAfter).toBe(eventsBefore);
  });

  it("refuses a reconfirmation of the entry it superseded", async () => {
    const at = day(WINDOW_DAYS + 1);
    await refused(
      await reconfirmation({
        entryId: superseded["id"] as string,
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp: at.toISOString(),
      }),
      422,
      "entry_not_verified",
      at,
    );
  });
});

// ---------------------------------------------------------------------------
// The staleness sweep
// ---------------------------------------------------------------------------

describe("the sweep's staleness step", () => {
  /** Day 91: the first day past a ninety-day window. */
  const STALE_DAY = WINDOW_DAYS + 1;

  it("leaves the stored row fresh until something rewrites it", async () => {
    const entry = await fetched(checkpoint["id"] as string, day(STALE_DAY));

    // Nothing has been written since the approvals, so the stored copy still
    // says what it said on the day it was derived.
    expect(entry["stale"]).toBe(false);
    expect(entry["expires_at"]).toBe(dayDate(WINDOW_DAYS));
  });

  it("rewrites the entries the day turned on, appending no event", async () => {
    const before = await head();
    const report = await sweep(day(STALE_DAY));

    expect(report.staled).toContain(checkpoint["id"]);
    expect(report.drawn).toEqual([]);
    // The one event this run appends is the pool snapshot the draw step owes on
    // a log that has never had one; the staleness step appends nothing at all.
    expect(await head()).toBe((before as number) + 1);
    expect(report.snapshot?.operators).toEqual(
      [a1.operator, a2.operator, a3.operator, sub.operator].sort(),
    );

    const entry = await fetched(checkpoint["id"] as string, day(STALE_DAY));
    expect(validateEntry(entry).errors).toEqual([]);
    // Section 7: past its window an entry stays verified but shows as stale.
    expect(entry["stale"]).toBe(true);
    expect(entry["status"]).toBe("verified");
  });

  it("keeps a superseded entry's pointer when it rewrites it", async () => {
    // The reason src/worker/world.ts exists. Rederiving this entry over its own
    // events alone would not see the entry that supersedes it, and the sweep
    // would quietly store it as standing again.
    const target = await stored(superseded["id"] as string);

    expect(target["stale"]).toBe(true);
    expect(target["superseded_by"]).toBe(superseder["id"]);
    expect(target["status"]).toBe("superseded");
  });

  it("has nothing left to do on a second run", async () => {
    const report = await sweep(day(STALE_DAY));

    expect(report.staled).toEqual([]);
    expect(report.snapshot).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Reconfirmation
// ---------------------------------------------------------------------------

describe("reconfirming a stale entry", () => {
  const STALE_DAY = WINDOW_DAYS + 1;
  const at = day(STALE_DAY);

  it("refreshes the entry and reopens its window", async () => {
    const response = await send(
      await reconfirmation({
        entryId: checkpoint["id"] as string,
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp: at.toISOString(),
      }),
      at,
    );

    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as Record<string, unknown>;
    expect(validateEntry(body).errors).toEqual([]);
    expect(body["status"]).toBe("verified");
    expect(body["stale"]).toBe(false);
    expect(body["last_confirmed"]).toBe(dayDate(STALE_DAY));
    expect(body["expires_at"]).toBe(dayDate(STALE_DAY + WINDOW_DAYS));
    expect(body["reconfirmations"]).toHaveLength(1);
    // The tier is the one the entry verified at and a reconfirmation never
    // moves it.
    const row = await getEntry(world.store.db, checkpoint["id"] as string);
    expect(row?.sidecar.effective_tier).toBe("stated");
  });

  it("seats the reconfirmer in a read-share slot", async () => {
    const row = await getEntry(world.store.db, checkpoint["id"] as string);

    expect(
      row?.sidecar.read_share_slots?.map((slot) => slot.operator),
    ).toEqual([a1.operator, a2.operator, a3.operator]);
  });

  it("writes one bounty accrual for the window it was stale for", async () => {
    const bounties = await bountiesForEntry(
      world.store.db,
      checkpoint["id"] as string,
      LIST_PAGE_LIMIT,
    );

    expect(bounties).toHaveLength(1);
    const accrual = bounties[0]!;
    expect(accrual.operator).toBe(a3.operator);
    // Accrual runs from the day the window closed to the instant it reopened.
    expect(accrual.stale_from).toBe(dayDate(WINDOW_DAYS));
    expect(accrual.stale_until).toBe(at.toISOString());
    // M21 publishes the pricing; nothing here freezes a number that does not
    // exist yet.
    expect(accrual.amount_micros).toBeNull();

    const event = await eventBySeq(world.store.db, accrual.seq);
    expect(event?.type).toBe("reconfirmation");
  });

  it("rotates nothing when the reconfirmer already holds a slot", async () => {
    // The window this reconfirmation reopened runs out in turn, and a holder
    // refreshes the entry without taking a second seat.
    const later = day(STALE_DAY + WINDOW_DAYS + 1);
    const response = await send(
      await reconfirmation({
        entryId: checkpoint["id"] as string,
        record: attestation(a1, later),
        signingKey: a1.agent,
        timestamp: later.toISOString(),
      }),
      later,
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["stale"]).toBe(false);
    expect(body["reconfirmations"]).toHaveLength(2);

    const row = await getEntry(world.store.db, checkpoint["id"] as string);
    expect(
      row?.sidecar.read_share_slots?.map((slot) => slot.operator),
    ).toEqual([a1.operator, a2.operator, a3.operator]);
  });

  it("refuses an agent under the submitter's own operator", async () => {
    await refused(
      await reconfirmation({
        entryId: ownEntry["id"] as string,
        record: attestation(
          { operator: sub.operator, agent: subSecondAgent },
          at,
        ),
        signingKey: subSecondAgent,
        timestamp: at.toISOString(),
      }),
      422,
      "submitter_operator",
      at,
    );
  });

  it("refuses an operator the maintainer never named to the pool", async () => {
    await refused(
      await reconfirmation({
        entryId: ownEntry["id"] as string,
        record: attestation(untrusted, at),
        signingKey: untrusted.agent,
        timestamp: at.toISOString(),
      }),
      422,
      "untrusted_operator",
      at,
    );
  });
});

// ---------------------------------------------------------------------------
// The door refuses before it writes, in a fixed order
// ---------------------------------------------------------------------------

describe("the reconfirm door refuses before it writes", () => {
  const at = day(WINDOW_DAYS + 1);
  const timestamp = at.toISOString();

  it("refuses an id the schema would not accept", async () => {
    await refused(
      await reconfirmation({
        entryId: "not-an-entry-id",
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp,
      }),
      400,
      "bad_id",
      at,
    );
  });

  it("refuses a body that is not a reconfirmation", async () => {
    await refused(
      await signedPost(a3.agent, {
        path: `/entries/${checkpoint["id"] as string}/reconfirm`,
        body: { record: { agent: a3.agent.agentId }, signature: "x" },
        timestamp,
      }),
      400,
      "bad_body",
      at,
    );
  });

  it("refuses an unsigned request", async () => {
    const record = attestation(a3, at);
    const signature = await signRecord(
      checkpoint["id"] as string,
      "reconfirmation",
      record,
      a3.agent.privateKey,
    );
    const request = new Request(
      `${TEST_ORIGIN}/entries/${checkpoint["id"] as string}/reconfirm`,
      {
        method: "POST",
        body: JSON.stringify({ record, signature }),
        headers: { "content-type": "application/json" },
      },
    );
    await refused(request, 401, "missing_header", at);
  });

  it("refuses an entry that is not in the log", async () => {
    const missing = "nmk_notanentryatall";
    await refused(
      await reconfirmation({
        entryId: missing,
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp,
      }),
      404,
      "not_found",
      at,
    );
  });

  it("refuses a record whose agent is not the key that signed the request", async () => {
    await refused(
      await reconfirmation({
        entryId: ownEntry["id"] as string,
        record: attestation(a2, at),
        signingKey: a2.agent,
        signer: a3.agent,
        timestamp,
      }),
      403,
      "agent_mismatch",
      at,
    );
  });

  it("refuses a record signed far away from the instant it arrives", async () => {
    await refused(
      await reconfirmation({
        entryId: ownEntry["id"] as string,
        record: attestation(a3, day(WINDOW_DAYS + 4)),
        signingKey: a3.agent,
        timestamp,
      }),
      422,
      "bad_signed_at",
      at,
    );
  });

  it("refuses a signature made for another entry", async () => {
    const record = attestation(a3, at);
    await refused(
      await reconfirmation({
        entryId: ownEntry["id"] as string,
        record,
        signingKey: a3.agent,
        // D-034: the entry id is inside the signed bytes, so a real signature
        // over the same record for a different entry does not verify here.
        signature: await signRecord(
          checkpoint["id"] as string,
          "reconfirmation",
          record,
          a3.agent.privateKey,
        ),
        timestamp,
      }),
      422,
      "bad_record_signature",
      at,
    );
  });

  it("refuses an entry that never verified", async () => {
    await refused(
      await reconfirmation({
        entryId: draftEntry["id"] as string,
        record: attestation(a3, at),
        signingKey: a3.agent,
        timestamp,
      }),
      422,
      "entry_not_verified",
      at,
    );
  });

  it("answers 405 with Allow on any other method", async () => {
    const response = await send(
      get(`/entries/${checkpoint["id"] as string}/reconfirm`),
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    expect(await response.json()).toEqual({ error: "method_not_allowed" });
  });
});

// ---------------------------------------------------------------------------
// The staleness sweep is a write door too
// ---------------------------------------------------------------------------

describe("the sweep's staleness step when the schema refuses", () => {
  /** Day 182: the day the second reconfirmation reopened the window on. */
  const RECONFIRMED_DAY = WINDOW_DAYS + 1 + WINDOW_DAYS + 1;
  /** Day 273: the first day past the window that reconfirmation opened. */
  const REFUSAL_DAY = RECONFIRMED_DAY + WINDOW_DAYS + 1;

  it("stores nothing, counts it, and leaves it for the next run", async () => {
    const before = await stored(checkpoint["id"] as string);
    const beforeHead = await head();
    expect(before["stale"]).toBe(false);

    schemaGate.refuse = true;
    const refused = await sweep(day(REFUSAL_DAY)).finally(() => {
      schemaGate.refuse = false;
    });

    // A refusal is a rule, not an error: the run finished — so the cursor
    // carried past the row rather than round it — and it finished having stored
    // nothing at all and appended nothing at all.
    expect(refused.staled).toEqual([]);
    expect(refused.skipped["schema_invalid"]).toBeGreaterThanOrEqual(1);
    expect(await head()).toBe(beforeHead);
    expect(await stored(checkpoint["id"] as string)).toEqual(before);

    // Nothing was written, so the row never left the index and the next run
    // finds it exactly where it was.
    const accepted = await sweep(day(REFUSAL_DAY));

    expect(accepted.staled).toContain(checkpoint["id"]);
    expect(accepted.skipped["schema_invalid"]).toBeUndefined();
    const entry = await stored(checkpoint["id"] as string);
    expect(entry["stale"]).toBe(true);
    expect(entry["status"]).toBe("verified");
    expect(validateEntry(entry).errors).toEqual([]);
  });
});

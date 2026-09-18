/**
 * The account rung, end to end (decision D-142, "genesis by path 2").
 *
 * D-136 opened one door, at the founding registry, where a comment counts
 * because its author sealed the line's fingerprint into a witnessed log. D-138
 * opened a second, where an agent signs the line itself and publishes the key on
 * its own profile. Both ask for a key. This decision opens the rung below them:
 * a bare reply on a board, written in the confirm grammar and signed by nobody,
 * where the only thing anybody can prove is that the board authenticated the
 * author and published what they wrote.
 *
 * So that is what the sweep seals: the comment, captured and hashed; the
 * author's profile, captured and hashed; and the instant the platform publishes
 * for the account's creation, which is what makes "older than the entry" a fact
 * a reader can recheck rather than a claim this record makes about a stranger.
 *
 * Everything below happens through the real sweep on a real miniflare D1. Only
 * the boards and the clock are fixtures, and the boards fake exactly one thing:
 * the network.
 *
 * What is proved, in the order the bytes travel:
 *
 * Three accounts reply on two boards, none of them signing anything. Each line
 * registers a community operator whose binding is the account, and seals a
 * validation at the `account` rung carrying both capture hashes and no
 * signature — because there is no key to have made one.
 *
 * The captures are really in the archive, under the hashes the bindings name,
 * and indexed so the export bundle and the mirror carry them.
 *
 * A board whose comment door does not answer leaves its line uncounted, with
 * the reason named: `account_comment_unavailable`, never a guess.
 *
 * One of nomankind's own accounts replies too. Its line is sealed and shown
 * with the perimeter word on it, and the entry page lists it under its own
 * heading rather than among the counted validations.
 *
 * And then one of those accounts publishes a key and signs its next line: the
 * sweep seals `community_operator_bound` before the validation, the operator
 * keeps its id, and every line it made before goes on counting at the rung it
 * was made on.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  MockBoardAdapter,
  type BoardComment,
} from "../src/adapters/board.js";
import { canonicalConfirmationLine } from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry, type Sidecar } from "../src/derive.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  appendEvent,
  type ApproverRecord,
  type Event,
  type EventType,
} from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
  signBytes,
} from "../src/identity.js";
import { archiveAddress, snapshotHash } from "../src/normalize.js";
import { signRecord } from "../src/records.js";
import { signCore } from "../src/sign.js";
import { archiveCapture, readCapture } from "../src/storage/r2.js";
import {
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  DEFAULT_DOMAIN,
  NORM_VERSION,
  PERIMETER_ACCOUNTS,
  PERIMETER_WORD,
  PROFILE_KEY_PREFIX,
} from "../src/policy.js";
import { ATTESTATION_VERSION, communityOperatorId } from "../src/registry.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  capturesForEntry,
  eventsOfType,
  getEntry,
  getOperator,
  putAgent,
  putCapture,
  putEntry,
  putOperator,
  putOperatorDomain,
} from "../src/storage/repository.js";
import { attributionOf } from "../src/attribution.js";
import { confidenceInputs } from "../src/confidence.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import type { Entry } from "../src/schema.js";
import type { EntryData, PageContext } from "../src/ui/types.js";
import type { Env } from "../src/worker/env.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const CAPTURE_HTML = [
  "<!doctype html>",
  "<html>",
  "  <head><title>gpt-5 pricing</title></head>",
  "  <body><main><p>gpt-5 input: $2.50 per million tokens</p></main></body>",
  "</html>",
].join("\n");
const CAPTURE_CONTENT_TYPE = "text/html; charset=utf-8";
const CITATION = "https://platform.openai.com/docs/pricing";
const EFFECTIVE_AT = "2026-09-01";
const SUBMITTED_AT = "2026-09-10T00:00:00.000Z";
const CATEGORY = "pricing";
const SUBJECT = "openai/gpt-5";
const AUTHOR_OPERATOR = "op_brightloop";
const MAINTAINER_OPERATOR = "op_maintainer";
const PERIMETER = "nomankind";
const TOKEN = `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`;
const NOW = new Date("2026-09-17T12:00:00.000Z");

/** The entry the three bare replies are said about. */
const ENTRY_BARE = `nmk_${"d4".repeat(16)}`;
/** The entry the perimeter line and the failed capture are said about. */
const ENTRY_EDGE = `nmk_${"e5".repeat(16)}`;
/** An observed entry: a tier the account rung may not count toward at all. */
const ENTRY_OBSERVED = `nmk_${"f6".repeat(16)}`;
/**
 * A stated entry nothing has been said about, for the age clause alone.
 *
 * Its own entry and not one of the others', because the scope is asked last:
 * the per-community cap and the closed entry are checked before it, so a line
 * said about an entry that had already met either would be refused by that rule
 * and would prove nothing about this one.
 */
const ENTRY_YOUNG = `nmk_${"a7".repeat(16)}`;

const COLONY = "colony";
const GITHUB = "github";
const COLONY_THREAD = "09ed63ba-438a-41e8-b352-f065b376106e";
const GITHUB_THREAD = 1;

/** Three accounts that publish no key at all: the rung's whole population. */
const FIRST = "first-reader";
const SECOND = "second-reader";
const THIRD = "third-reader";
/** The account whose comment capture the board refuses to answer. */
const LOST = "lost-comment";
/** An account the platform says was created after the entry was submitted. */
const LATECOMER = "latecomer";
/** The accounts the form reading is told apart by (decision D-144). */
const FORM_PASTER = "form-paster";
const SOLO = "solo-reader";
const MIXED = "two-pages";
const FORM_COMMENT = "b1a0e6d4-1c2f-4a3b-8d4e-5f6a7b8c9d01";
const PERIMETER_FORM_COMMENT = "c2b1f7e5-2d3a-4b4c-9e5f-6a7b8c9d0e12";
const SOLO_COMMENT = "d3c2a8f6-3e4b-4c5d-af60-7b8c9d0e1f23";
const MIXED_COMMENT = "e4d3b907-4f5c-4d6e-b071-8c9d0e1f2a34";
/** One of nomankind's own, taken from the published list. */
const PERIMETER_OPERATOR = PERIMETER_ACCOUNTS.find((id) =>
  id.startsWith(`${COLONY}:`),
)!;
const PERIMETER_HANDLE = PERIMETER_OPERATOR.slice(`${COLONY}:`.length);

/** When each account says it was created: all of them before the entry. */
const CREATED_AT = "2024-03-01T00:00:00.000Z";

const POOL = Array.from({ length: 10 }, (_, index) => `op_v${index + 1}`);

const ctx: PageContext = {
  origin: "https://app.nomankind.ai",
  path: "/",
  environment: "local",
  version: "test",
} as unknown as PageContext;

interface Signer {
  readonly publicKey: string;
  sign(text: string): Promise<string>;
}

async function keypair(): Promise<Signer> {
  const pair = await generateKeypair();
  const raw = await exportPublicKeyRaw(pair.publicKey);
  return {
    publicKey: base64urlEncode(raw),
    sign: async (text: string) =>
      base64urlEncode(
        await signBytes(pair.privateKey, new TextEncoder().encode(text)),
      ),
  };
}

/**
 * A profile page as a venue's door answers one, with the account's own
 * beginning on it.
 *
 * The key is null for every account on the rung, which is the whole point: a
 * profile publishing no key is what makes the line account-bound rather than
 * key-bound, and the creation date is what makes it countable at all.
 */
function profileJson(handle: string, publicKey: string | null): string {
  return JSON.stringify({
    username: handle,
    display_name: handle,
    created_at: CREATED_AT,
    bio:
      publicKey === null
        ? "An agent that reads things. No keys here."
        : `An agent that checks facts. ${PROFILE_KEY_PREFIX}${publicKey}`,
  });
}

let store: TestDatabase;
let db: D1Like;
let sealingKey = "";
let snapshot = "";
let captureBytes = new Uint8Array();
let author: Party;
let pool: Party[] = [];
let report: Awaited<ReturnType<typeof runSweep>>;

function envOf(): Env {
  return {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
    SEALING_AGENT_KEY: sealingKey,
  } as unknown as Env;
}

function coreOf(overrides: Record<string, unknown>): Core {
  return {
    id: ENTRY_BARE,
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: EFFECTIVE_AT,
    // Stated, because `ACCOUNT_BINDING_TIERS` is stated and nothing else: an
    // observed entry rests on a measurement somebody ran, and an account that
    // has published no key has shown nothing about who ran it.
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: snapshot,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: author.agent,
    author_operator: AUTHOR_OPERATOR,
    submitted_at: SUBMITTED_AT,
    ...overrides,
  } as Core;
}

interface Party {
  readonly agent: string;
  readonly operator: string;
  readonly keys: CryptoKeyPair;
}

async function makeParty(operator: string): Promise<Party> {
  const keys = await generateKeypair();
  const agent = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));
  return { agent, operator, keys };
}

function approval(party: Party, signedAt: string, drawn = false): ApproverRecord {
  return {
    agent: party.agent,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: snapshot,
    assigned_random: drawn,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt,
  } as unknown as ApproverRecord;
}

/** The claim a line makes, canonically: what a signature would be over. */
function claimFor(entryId: string): string {
  return canonicalConfirmationLine({
    entry_id: entryId,
    verdict: "approve",
    check: { kind: "hash", value: snapshot },
    attestation_version: ATTESTATION_VERSION,
  });
}

/**
 * A bare reply: the published form, the attestation token, a reason, and no
 * signature anywhere in it.
 *
 * This is the whole of what D-142 asks an account to write. The board says who
 * typed it; nobody says anything else.
 */
function bareLine(entryId: string, reason: string): string {
  return `${claimFor(entryId)} ${reason}`;
}

/**
 * One of an entry's two published lines, spelled as the ask spells it.
 *
 * `span-present` for approve and `span-absent` for reject, which is the pair
 * `replyLines` prints under every entry of a batch post (src/cli/batch-post.ts):
 * D-142's ask is the one a reader can answer by reading, so the check is
 * whether the quoted claim is on the cited page.
 */
function lineFor(entryId: string, verdict: "approve" | "reject"): string {
  return canonicalConfirmationLine({
    entry_id: entryId,
    verdict,
    check: {
      kind: "span",
      value: verdict === "approve" ? "present" : "absent",
    },
    attestation_version: ATTESTATION_VERSION,
  });
}

/**
 * An entry's block as the ask prints it: both lines, indented, under a heading.
 *
 * What a stranger pastes back when they copy the whole block rather than one
 * line of it — and what nomankind's own post is made of, which is the comment
 * the reader mistook for a statement on 2026-09-18 (decision D-144).
 */
function askBlockFor(entryId: string): string {
  return [
    `  ${entryId} · ai-ecosystem · ${SUBJECT} · draft`,
    `  claim: "the quoted claim"`,
    `  ${lineFor(entryId, "approve")}`,
    `  ${lineFor(entryId, "reject")}`,
  ].join("\n");
}

/** The same line, signed: what an account writes the day it publishes a key. */
async function signedLine(
  signer: Signer,
  entryId: string,
  reason: string,
): Promise<string> {
  const claim = claimFor(entryId);
  const signature = await signer.sign(claim);
  return `${claim} ${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}${signature} ${reason}`;
}

const FIRST_COMMENT_AT = Date.parse("2026-09-16T09:00:00.000Z");
let commentAt = FIRST_COMMENT_AT;

function rewindThread(offsetMs = 0): void {
  commentAt = FIRST_COMMENT_AT + offsetMs;
}

function comment(
  id: number | string,
  thread: number | string,
  handle: string,
  body: string,
): BoardComment {
  commentAt += 60_000;
  return {
    id,
    thread,
    handle,
    body,
    posted_at: new Date(commentAt).toISOString(),
  };
}

async function sealedOf(type: EventType): Promise<Event[]> {
  return [...(await eventsOfType(db, type, -1, 200))];
}

function payloadsOf(events: readonly Event[]): Record<string, unknown>[] {
  return events.map(
    (event) => event.payload as unknown as Record<string, unknown>,
  );
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

async function buildEvents(): Promise<Event[]> {
  let events: Event[] = [];
  let tick = 0;
  const add = async <T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): Promise<void> => {
    tick += 1;
    events = await appendEvent(events, {
      at: new Date(
        Date.parse("2026-09-10T01:00:00Z") + tick * 60_000,
      ).toISOString(),
      type,
      entry_id: entryId,
      payload,
    });
  };

  const submit = async (
    id: string,
    overrides: Record<string, unknown>,
    approvals: readonly { party: Party; at: string; drawn?: boolean }[],
  ): Promise<void> => {
    const core = coreOf({ id, ...overrides });
    await add("entry_submitted", id, {
      core,
      signature: await signCore(core, author.keys.privateKey),
    });
    for (const each of approvals) {
      if (each.drawn === true) {
        await add("assignment", id, {
          agent: each.party.agent,
          operator: each.party.operator,
          beacon_round: 4_211_000,
          deadline: "2026-09-13T00:00:00.000Z",
          replacement: false,
        });
      }
      const record = approval(each.party, each.at, each.drawn === true);
      await add("validation", id, {
        record,
        signature: await signRecord(
          id,
          "validation",
          record,
          each.party.keys.privateKey,
        ),
      });
    }
  };

  await add("operator_registered", null, {
    operator: MAINTAINER_OPERATOR,
    maintainer: true,
  });
  await add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  await add("agent_bound", null, {
    operator: AUTHOR_OPERATOR,
    agent: author.agent,
    attestation: {} as never,
  });
  for (const party of pool) {
    await add("operator_registered", null, {
      operator: party.operator,
      maintainer: false,
    });
    await add("agent_bound", null, {
      operator: party.operator,
      agent: party.agent,
      attestation: {} as never,
    });
    await add("operator_trusted", null, {
      operator: party.operator,
      perimeter: PERIMETER,
    });
  }

  // Nothing on it: three bare replies from three accounts on two boards are
  // the whole of what is said about it, so every one of them arrives at an open
  // entry and the rung is what decides. (An approval already on it would close
  // the entry part-way through and send the last line back `entry_closed`,
  // which is a rule about consensus and not about the rung.)
  await submit(ENTRY_BARE, {}, []);
  await submit(ENTRY_EDGE, { subject: "openai/gpt-4o" }, []);
  // An observed entry, so the account rung has a tier it may not speak to:
  // `ACCOUNT_BINDING_TIERS` is `stated` and nothing else, because an observed
  // entry rests on a measurement somebody ran.
  await submit(
    ENTRY_OBSERVED,
    { subject: "openai/gpt-4o-mini", evidence_tier: "observed" },
    [],
  );
  await submit(ENTRY_YOUNG, { subject: "anthropic/claude-3-5-haiku" }, []);

  return events;
}

/** The Colony: three bare replies, a perimeter line, and a lost capture. */
function colonyBoard(): MockBoardAdapter {
  rewindThread();
  return new MockBoardAdapter({
    venue: COLONY,
    binding: "profile",
    cursor: "time",
    threads: [COLONY_THREAD],
    comments: new Map([
      [
        COLONY_THREAD,
        [
          comment(
            "3e54d240-2b8f-4e93-b203-a3a16f519528",
            COLONY_THREAD,
            FIRST,
            bareLine(ENTRY_BARE, "I fetched it and hashed it myself"),
          ),
          comment(
            "8c1c0a6e-6d4f-4d1e-9a2f-2b6a2f0e1d11",
            COLONY_THREAD,
            SECOND,
            bareLine(ENTRY_BARE, "same here"),
          ),
          // Nomankind's own account, saying the same thing: sealed, disclosed,
          // and counted toward nothing at any rung.
          comment(
            "9f2b1b7f-7e5a-4c2f-8b3a-3c7b3a1f2e22",
            COLONY_THREAD,
            PERIMETER_HANDLE,
            bareLine(ENTRY_EDGE, "the maintainer looked too"),
          ),
          // A line whose comment the board will not serve back: uncounted, with
          // the reason named, and never a guess.
          comment(
            "a03c2c80-8f6b-4d3a-9c4b-4d8c4b2a3f33",
            COLONY_THREAD,
            LOST,
            bareLine(ENTRY_EDGE, "you cannot read this back"),
          ),
        ],
      ],
    ]),
    profiles: new Map([
      [FIRST, profileJson(FIRST, null)],
      [SECOND, profileJson(SECOND, null)],
      [PERIMETER_HANDLE, profileJson(PERIMETER_HANDLE, null)],
      [LOST, profileJson(LOST, null)],
    ]),
    accounts: new Map([
      [FIRST, CREATED_AT],
      [SECOND, CREATED_AT],
      [PERIMETER_HANDLE, CREATED_AT],
      [LOST, CREATED_AT],
    ]),
    // Every comment but the lost one: a fixture that names its captures answers
    // only the ones it names, which is a comment door that did not answer.
    commentCaptures: new Map([
      ["3e54d240-2b8f-4e93-b203-a3a16f519528", "{\"comment\":\"one\"}"],
      ["8c1c0a6e-6d4f-4d1e-9a2f-2b6a2f0e1d11", "{\"comment\":\"two\"}"],
      ["9f2b1b7f-7e5a-4c2f-8b3a-3c7b3a1f2e22", "{\"comment\":\"perimeter\"}"],
    ]),
  });
}

/** GitHub: the third account, on the other board. */
function githubBoard(): MockBoardAdapter {
  rewindThread();
  return new MockBoardAdapter({
    venue: GITHUB,
    binding: "profile",
    threads: [GITHUB_THREAD],
    comments: new Map([
      [
        GITHUB_THREAD,
        [
          comment(
            3_311_001,
            GITHUB_THREAD,
            THIRD,
            bareLine(ENTRY_BARE, "and on the other board"),
          ),
        ],
      ],
    ]),
    profiles: new Map([[THIRD, profileJson(THIRD, null)]]),
    accounts: new Map([[THIRD, CREATED_AT]]),
  });
}

describe("the account rung, end to end", () => {
  beforeAll(async () => {
    store = await openTestDatabase();
    db = store.db;
    sealingKey = base64urlEncode(
      await exportPrivateKeyPkcs8((await generateKeypair()).privateKey),
    );

    captureBytes = new TextEncoder().encode(CAPTURE_HTML);
    const hashed = await snapshotHash(captureBytes, CAPTURE_CONTENT_TYPE);
    expect(hashed.ok).toBe(true);
    snapshot = hashed.ok ? hashed.hash : "";

    author = await makeParty(AUTHOR_OPERATOR);
    pool = [];
    for (const operator of POOL) pool.push(await makeParty(operator));

    const events = await buildEvents();
    await appendEvents(db, events);

    const parties: { operator: string; agent: string | null }[] = [
      { operator: MAINTAINER_OPERATOR, agent: null },
      { operator: AUTHOR_OPERATOR, agent: author.agent },
      ...pool.map((party) => ({ operator: party.operator, agent: party.agent })),
    ];
    for (const [index, party] of parties.entries()) {
      await putOperator(db, {
        id: party.operator,
        kind: "domain",
        maintainer: party.operator === MAINTAINER_OPERATOR,
        provider: false,
        registeredSeq: index,
        details: { trusted: POOL.includes(party.operator) },
      });
      if (party.agent !== null) {
        await putAgent(db, {
          agentId: party.agent,
          operatorId: party.operator,
          registeredSeq: index,
        });
      }
      await putOperatorDomain(db, {
        operator: party.operator,
        domain: DEFAULT_DOMAIN,
        seq: index,
        attestation: null,
      });
    }

    const archiveHash = await archiveAddress(captureBytes);
    await archiveCapture(store.captures, {
      archiveHash,
      bytes: captureBytes,
      mediaType: CAPTURE_CONTENT_TYPE,
      sidecar: {
        final_url: CITATION,
        status: 200,
        headers: { "content-type": CAPTURE_CONTENT_TYPE },
        fetched_at: SUBMITTED_AT,
        fetcher: "1F916:test",
      },
    });

    for (const id of [
      ENTRY_BARE,
      ENTRY_EDGE,
      ENTRY_OBSERVED,
      ENTRY_YOUNG,
    ]) {
      const submitted = events.find(
        (event) => event.type === "entry_submitted" && event.entry_id === id,
      )!;
      const derived = deriveEntry(events, id, { now: NOW.toISOString() });
      expect(derived.entry["status"]).toBe("draft");
      await putEntry(db, derived.entry, derived.sidecar, submitted.seq);
      await putCapture(db, {
        entryId: id,
        role: "snapshot",
        contentHash: snapshot,
        archiveHash,
        normVersion: NORM_VERSION,
        kind: "html",
        mediaType: CAPTURE_CONTENT_TYPE,
        size: captureBytes.byteLength,
        fetchedAt: SUBMITTED_AT,
      });
    }

    report = await runSweep(envOf(), {
      now: NOW,
      beacon: new FixtureBeacon("account-rung"),
      board: [colonyBoard(), githubBoard()],
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("registers an operator per bare account, bound by the account itself", async () => {
    const registered = new Map(
      payloadsOf(await sealedOf("community_operator_registered")).map(
        (payload) => [payload["operator"], payload],
      ),
    );

    for (const [venue, handle] of [
      [COLONY, FIRST],
      [COLONY, SECOND],
      [GITHUB, THIRD],
    ] as const) {
      const payload = registered.get(communityOperatorId(venue, handle))!;
      expect(payload).toBeDefined();
      const binding = payload["binding"] as Record<string, unknown>;
      // No key anywhere in it, because there is none to have.
      expect(binding["kind"]).toBe("account");
      expect(binding["venue"]).toBe(venue);
      expect(binding["handle"]).toBe(handle);
      expect(String(binding["comment_capture_hash"])).toMatch(/^sha256:/);
      expect(String(binding["profile_capture_hash"])).toMatch(/^sha256:/);
      expect(String(binding["comment_url"])).toContain("comment");
      expect(String(binding["profile_url"])).toContain(handle);
      // What makes "older than the entry" a fact rather than a claim.
      expect(binding["account_created_at"]).toBe(CREATED_AT);
      // The account itself is what spoke, under the id the board authenticated
      // it as: there was no key, and the event does not pretend to one.
      expect(payload["agent"]).toBe(communityOperatorId(venue, handle));
      expect(payload["registry_event_id"]).toBeNull();
    }

    // And the registry rows the events imply.
    const record = (await getOperator(
      db,
      communityOperatorId(COLONY, FIRST),
    ))!;
    expect(record.kind).toBe("community");
    expect(
      (record.details["binding"] as Record<string, unknown>)["kind"],
    ).toBe("account");
  }, 600_000);

  it("seals the validations at the account rung, with the captures as proof", async () => {
    const onEntry = payloadsOf(await sealedOf("community_validation")).filter(
      (payload) => payload["entry_id"] === ENTRY_BARE,
    );
    // Three bare replies, three counted lines.
    expect(onEntry).toHaveLength(3);

    for (const payload of onEntry) {
      expect(payload["binding_kind"]).toBe("account");
      // These accounts are nobody's own, so no perimeter word is on them.
      expect(payload["perimeter"]).toBeNull();
      const proof = payload["binding_proof"] as Record<string, unknown>;
      expect(proof["kind"]).toBe("account");
      expect(String(proof["comment_capture_hash"])).toMatch(/^sha256:/);
      expect(String(proof["profile_capture_hash"])).toMatch(/^sha256:/);
      // The one thing a key-bound proof carries that this one must not: a
      // signature, from a key that does not exist.
      expect(proof["signature"]).toBeUndefined();
      expect(proof["public_key"]).toBeUndefined();
      expect(payload["attestation_version"]).toBe(ATTESTATION_VERSION);
    }

    // Two boards, so the lines did not all come from one place.
    expect(new Set(onEntry.map((payload) => payload["venue"])).size).toBe(2);
  }, 600_000);

  it("archives both captures under the hashes the bindings name", async () => {
    const registered = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).find(
      (payload) => payload["operator"] === communityOperatorId(COLONY, FIRST),
    )!;
    const binding = registered["binding"] as Record<string, unknown>;

    for (const hash of [
      String(binding["comment_capture_hash"]),
      String(binding["profile_capture_hash"]),
    ]) {
      // Really in the archive, really under that address: a rung whose evidence
      // nobody archived would be a rung nobody could recheck.
      const held = await readCapture(store.captures, hash);
      expect(held).not.toBeNull();
      expect(await archiveAddress(held!.bytes)).toBe(hash);
    }

    // And indexed, so `GET /captures/{hash}` can serve them into a bundle.
    const roles = (await capturesForEntry(db, ENTRY_BARE, 50)).map(
      (row) => row.role,
    );
    expect(
      roles.some((role) =>
        role.startsWith(`comment:${communityOperatorId(COLONY, FIRST)}`),
      ),
    ).toBe(true);
    expect(
      roles.some((role) =>
        role.startsWith(`profile:${communityOperatorId(COLONY, FIRST)}`),
      ),
    ).toBe(true);
  }, 600_000);

  it("leaves a line whose capture failed uncounted, and says which", async () => {
    // The board served the comment on the thread and would not serve it back on
    // its own door. There is nothing archived that says what the line said, so
    // there is nothing to seal: never a guess.
    expect(report.skipped["account_comment_unavailable"]).toBe(1);

    const operators = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).map((payload) => payload["operator"]);
    expect(operators).not.toContain(communityOperatorId(COLONY, LOST));

    const validations = payloadsOf(await sealedOf("community_validation"));
    expect(
      validations.some((payload) => payload["handle"] === LOST),
    ).toBe(false);
  }, 600_000);

  it("seals a perimeter line and discloses it rather than counting it", async () => {
    const line = payloadsOf(await sealedOf("community_validation")).find(
      (payload) => payload["operator"] === PERIMETER_OPERATOR,
    );
    expect(line).toBeDefined();
    // Sealed and shown exactly like any other, and disclosed with the word the
    // maintainer published in advance.
    expect(line!["perimeter"]).toBe(PERIMETER_WORD);
    expect(line!["binding_kind"]).toBe("account");

    // The run's own rows count them apart, which is what the step's detail
    // reports off them: an account-bound line and one of nomankind's own are
    // different facts about a run, and one total would hide both.
    const rows = report.community_validations;
    expect(
      rows.filter((row) => row.binding_kind === "account").length,
    ).toBeGreaterThanOrEqual(3);
    expect(rows.filter((row) => row.perimeter !== null)).toHaveLength(1);
    expect(rows.filter((row) => row.upgraded)).toHaveLength(0);
  }, 600_000);

  it("seals the upgrade when one of those accounts publishes a key", async () => {
    // Decision D-142's whole upgrade path: the same account, the same id, a key
    // on its profile and a signature on its next line. The operator keeps its
    // standing and its marks; what changed is the binding.
    const promoted = await keypair();
    rewindThread(3_600_000);
    const board = new MockBoardAdapter({
      venue: COLONY,
      binding: "profile",
      cursor: "time",
      threads: [COLONY_THREAD],
      comments: new Map([
        [
          COLONY_THREAD,
          [
            comment(
              "b14d3d91-9a7c-4e4b-ad5c-5e9d5c3b4a44",
              COLONY_THREAD,
              FIRST,
              await signedLine(promoted, ENTRY_EDGE, "with a key this time"),
            ),
          ],
        ],
      ]),
      profiles: new Map([[FIRST, profileJson(FIRST, promoted.publicKey)]]),
      accounts: new Map([[FIRST, CREATED_AT]]),
    });

    const again = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 600_000),
      beacon: new FixtureBeacon("account-rung-upgrade"),
      board: [board],
    });

    const operator = communityOperatorId(COLONY, FIRST);
    const upgrades = payloadsOf(await sealedOf("community_operator_bound"));
    const upgrade = upgrades.find((payload) => payload["operator"] === operator)!;
    expect(upgrade).toBeDefined();
    expect(upgrade["agent"]).toBe(`1F916:${promoted.publicKey}`);
    const binding = upgrade["binding"] as Record<string, unknown>;
    expect(binding["kind"]).toBe("profile");
    expect(binding["public_key"]).toBe(promoted.publicKey);
    expect(String(upgrade["capture_hash"])).toMatch(/^sha256:/);
    // What an offline reader rechecks the stronger binding by (the review of
    // #105): an upgrade that named a key and carried nothing to check it by was
    // a claim nobody could falsify. This one carries the same proof the
    // validation beside it carries.
    const proof = upgrade["proof"] as Record<string, unknown>;
    expect(proof).toBeDefined();
    expect(proof["kind"]).toBe("profile");
    expect(proof["public_key"]).toBe(promoted.publicKey);
    expect(typeof proof["signature"]).toBe("string");
    expect(String(proof["capture_hash"])).toMatch(/^sha256:/);
    const validation = payloadsOf(await sealedOf("community_validation")).find(
      (payload) =>
        payload["operator"] === operator &&
        payload["entry_id"] === ENTRY_EDGE,
    )!;
    // The same object, so the verifier rechecks both by one code path.
    expect(proof).toEqual(validation["binding_proof"]);

    // Additive: the registration that made it an operator is still there saying
    // what it said, and there is exactly one of it.
    const registrations = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).filter((payload) => payload["operator"] === operator);
    expect(registrations).toHaveLength(1);
    expect(
      (registrations[0]!["binding"] as Record<string, unknown>)["kind"],
    ).toBe("account");

    // The registry row now names the key, so a reader sent to look for one
    // finds it — the id, the standing and the marks are untouched.
    const record = (await getOperator(db, operator))!;
    expect(record.details["agent"]).toBe(`1F916:${promoted.publicKey}`);
    expect(
      (record.details["binding"] as Record<string, unknown>)["kind"],
    ).toBe("profile");

    // The line this was read off is sealed at the rung it was actually made
    // on, which is the key rung, and the run counts the upgrade on its own.
    const newest = payloadsOf(await sealedOf("community_validation")).find(
      (payload) =>
        payload["operator"] === operator &&
        payload["entry_id"] === ENTRY_EDGE,
    )!;
    expect(newest["binding_kind"]).toBe("profile");
    expect(
      again.community_validations.filter((row) => row.upgraded),
    ).toHaveLength(1);

    // And every line it made before goes on counting at the rung it was made
    // on: the earlier validation is untouched.
    const earlier = payloadsOf(await sealedOf("community_validation")).find(
      (payload) =>
        payload["operator"] === operator &&
        payload["entry_id"] === ENTRY_BARE,
    )!;
    expect(earlier["binding_kind"]).toBe("account");
  }, 600_000);

  it("reads the rung back on the entry page, in words", async () => {
    const stored = (await getEntry(db, ENTRY_BARE))!;
    const entry = stored.entry as unknown as Record<string, unknown>;
    const events = await eventsOfType(db, "community_validation", -1, 200);

    // The rung the promoting consensus will be sealed at, per the contract: the
    // weakest counted validator here stood on nothing but a board having
    // authenticated it. The sidecar field itself is derivation's to seal (see
    // the report); the page is what this asserts, over the contract's value.
    const sidecar = {
      ...stored.sidecar,
      verification_class: "community",
      verification_communities: [COLONY, GITHUB],
      verification_single_venue: false,
      verification_binding: "account",
    } as unknown as Sidecar;

    const data: EntryData = {
      entry: { ...entry, status: "verified" },
      sidecar,
      position: stored.submittedSeq,
      events: events.filter((event) => event.entry_id === ENTRY_BARE),
      seal: null,
      attribution: attributionOf(entry as unknown as Entry, [], new Map()),
      approvers: [],
      reconfirmations: [],
      superseders: [],
      stalenessWindowDays: 30,
      ledger: [],
      readShares: [],
      disputeOf: null,
      confidenceInputs: confidenceInputs({
        entry: entry as unknown as Entry,
        sidecar,
        now: NOW.toISOString(),
      }),
      statement: null,
      disclosure: null,
    };

    const html = renderEntry(ctx, data);
    expect(html).toContain("Account-bound");
    expect(html).toContain("verification_binding");
    // The scope, in the words D-142 asks for, including the published date.
    expect(html).toContain("2032-01-01T00:00:00Z");
    expect(html).toContain("only toward stated facts");
    // The boards, and the sentence that says why 1F916 reads above the others.
    expect(html).toContain("countersigned by the pinned witnesses");
    for (const venue of [COLONY, GITHUB]) expect(html).toContain(venue);
  }, 600_000);

  it("lists a perimeter line under its own heading, never among the counted", async () => {
    const stored = (await getEntry(db, ENTRY_EDGE))!;
    const entry = stored.entry as unknown as Record<string, unknown>;
    const events = (await eventsOfType(db, "community_validation", -1, 200))
      .filter((event) => event.entry_id === ENTRY_EDGE);

    const data: EntryData = {
      entry,
      sidecar: stored.sidecar,
      position: stored.submittedSeq,
      events,
      seal: null,
      attribution: attributionOf(entry as unknown as Entry, [], new Map()),
      approvers: [],
      reconfirmations: [],
      superseders: [],
      stalenessWindowDays: 30,
      ledger: [],
      readShares: [],
      disputeOf: null,
      confidenceInputs: confidenceInputs({
        entry: entry as unknown as Entry,
        sidecar: stored.sidecar,
        now: NOW.toISOString(),
      }),
      statement: null,
      disclosure: null,
    };

    const html = renderEntry(ctx, data);
    expect(html).toContain("Perimeter statements");
    expect(html).toContain(PERIMETER_OPERATOR);
    // A draft is waiting rather than lacking, and what it is waiting on is not
    // the maintainer's own line: the perimeter line is listed under its own
    // heading and is not among the sealed community lines counted in the
    // sentence.
    expect(html).toContain("Awaiting validators");
    // One community line is sealed on this entry by now — the upgraded
    // operator's, from the test above — and the maintainer's own is not counted
    // among them. The page says "sealed", never "counted": which lines a
    // consensus counts is derivation's, and on a draft it has counted none
    // (the review of #105).
    expect(html).toContain("1 community line sealed on this entry");
    expect(html).toContain("A sealed line is not a counted one");
    expect(html).toContain("sealed, not counted");
    expect(html).not.toContain("counted lines so far");
  }, 600_000);

  it("refuses the account rung's scope at the door, and counts why", async () => {
    // D-142 item 3, asked at the door and not only at the fold: a line the
    // sweep sealed as a validation that derivation then counted toward nothing
    // would be a door and a fold disagreeing about the same rule. Both now ask
    // `communityLineDisposition`, and the door hands it the binding of the line
    // in hand — the only binding that is true of the line in hand.
    rewindThread(7_200_000);
    const board = new MockBoardAdapter({
      venue: COLONY,
      binding: "profile",
      cursor: "time",
      threads: [COLONY_THREAD],
      comments: new Map([
        [
          COLONY_THREAD,
          [
            // An account younger than the entry it is speaking about. An
            // account made after the entry was submitted is an account made
            // for it, as far as the record can tell.
            comment(
              "c25e4ea2-ab8d-4f5c-be6d-6fae6d4c5b55",
              COLONY_THREAD,
              LATECOMER,
              bareLine(ENTRY_YOUNG, "I just got here"),
            ),
            // And an account in good standing speaking to a tier this rung may
            // not count toward at all.
            comment(
              "d36f5fb3-bc9e-4a6d-cf7e-7fbf7e5d6c66",
              COLONY_THREAD,
              SECOND,
              bareLine(ENTRY_OBSERVED, "the measurement looks right to me"),
            ),
          ],
        ],
      ]),
      profiles: new Map([
        [LATECOMER, profileJson(LATECOMER, null)],
        [SECOND, profileJson(SECOND, null)],
      ]),
      accounts: new Map([
        // After the entry's own submitted_at.
        [LATECOMER, "2026-09-15T00:00:00.000Z"],
        [SECOND, CREATED_AT],
      ]),
    });

    const again = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 900_000),
      beacon: new FixtureBeacon("account-rung-scope"),
      board: [board],
    });

    // Both fell back to the confirmation they already were, each with the word
    // that says which half of the scope it fell outside — and the run's detail
    // carries them under the same `fell_back` key every other refusal uses.
    expect(again.confirmation_fallbacks["account_too_new"]).toBe(1);
    expect(again.confirmation_fallbacks["account_out_of_scope"]).toBe(1);

    // Nothing was sealed as a validation, and the younger account registered
    // no operator at all: a line the door refuses registers nobody.
    expect(
      again.community_validations.some(
        (row) => row.handle === LATECOMER || row.entry_id === ENTRY_OBSERVED,
      ),
    ).toBe(false);
    const operators = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).map((payload) => payload["operator"]);
    expect(operators).not.toContain(communityOperatorId(COLONY, LATECOMER));

    // And both lines are sealed and shown as the account statements they are,
    // which is what a confirmation has been since D-136.
    const confirmations = payloadsOf(
      await sealedOf("public_confirmation"),
    ).filter(
      (payload) =>
        payload["handle"] === LATECOMER ||
        payload["entry_id"] === ENTRY_OBSERVED,
    );
    expect(confirmations.length).toBeGreaterThanOrEqual(2);
    for (const each of confirmations) expect(each["counted"]).toBe(false);
  }, 600_000);

  it("passes over a comment that carries both of an entry's lines", async () => {
    // Decision D-144, at the door. The ask this record posts prints an entry's
    // approve line and its reject line together so there is something to paste
    // (src/cli/batch-post.ts), so a comment holding both of one entry's lines
    // is that form quoted back and not a statement about the entry — and on
    // 2026-09-18 the reader had no way to tell the two apart: the GitHub ask
    // was posted from the maintainer's own login and the sweep read its lines
    // as that account's statements, one sealed approve and one sealed reject
    // per entry (production seq 15 to 35).
    //
    // Four comments in one run, because the rule is only worth anything if it
    // tells them apart: two forms that seal nothing, one ordinary reply that
    // still seals, and one reply that answers two entries different ways and
    // seals both.
    rewindThread(10_800_000);
    const board = new MockBoardAdapter({
      venue: COLONY,
      binding: "profile",
      cursor: "time",
      threads: [COLONY_THREAD],
      comments: new Map([
        [
          COLONY_THREAD,
          [
            // The ask's own block, pasted back whole by a stranger.
            comment(FORM_COMMENT, COLONY_THREAD, FORM_PASTER, askBlockFor(ENTRY_YOUNG)),
            // And by nomankind's own account, which is what really happened:
            // the perimeter keeps such a line from counting, and this keeps it
            // from being read as a statement at all.
            comment(
              PERIMETER_FORM_COMMENT,
              COLONY_THREAD,
              PERIMETER_HANDLE,
              askBlockFor(ENTRY_BARE),
            ),
            // One line, which is the whole of what the ask asks for.
            comment(
              SOLO_COMMENT,
              COLONY_THREAD,
              SOLO,
              bareLine(ENTRY_YOUNG, "the quoted claim is on the page"),
            ),
            // Two entries, two verdicts, one reply: a replier who opened both
            // cited pages and found one claim present and the other absent.
            // Not a form, and never was.
            comment(
              MIXED_COMMENT,
              COLONY_THREAD,
              MIXED,
              [
                lineFor(ENTRY_YOUNG, "approve"),
                lineFor(ENTRY_BARE, "reject"),
              ].join("\n"),
            ),
          ],
        ],
      ]),
      profiles: new Map(
        [FORM_PASTER, PERIMETER_HANDLE, SOLO, MIXED].map((handle) => [
          handle,
          profileJson(handle, null),
        ]),
      ),
      accounts: new Map(
        [FORM_PASTER, PERIMETER_HANDLE, SOLO, MIXED].map((handle) => [
          handle,
          CREATED_AT,
        ]),
      ),
      commentCaptures: new Map([
        [SOLO_COMMENT, '{"comment":"solo"}'],
        [MIXED_COMMENT, '{"comment":"mixed"}'],
        // Deliberately none for the two form comments: the door must not reach
        // for a capture it would never use, and a fixture that named one could
        // not tell a comment passed over from a comment read.
      ]),
    });

    const again = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 1_800_000),
      beacon: new FixtureBeacon("account-rung-form"),
      board: [board],
    });

    // Both form comments were passed over, once each, by the reason's own name.
    expect(again.skipped["confirmation_form_not_statement"]).toBe(2);
    // And each of them cost one parse: the board was never asked for their
    // bytes, so a capture that does not exist was never missed either.
    expect(board.commentReads).not.toContain(FORM_COMMENT);
    expect(board.commentReads).not.toContain(PERIMETER_FORM_COMMENT);
    expect(again.skipped["account_comment_unavailable"]).toBeUndefined();

    // Nothing was taken from either of them, at either rung. The perimeter one
    // is the sharper half: a perimeter line is ordinarily sealed and shown and
    // counted toward nothing, and this one is not sealed at all, because it was
    // never anybody's statement.
    const fromComment = async (
      type: "public_confirmation" | "community_validation",
      id: string,
    ): Promise<Record<string, unknown>[]> =>
      payloadsOf(await sealedOf(type)).filter(
        (payload) => payload["comment_id"] === id,
      );
    for (const id of [FORM_COMMENT, PERIMETER_FORM_COMMENT]) {
      expect(await fromComment("public_confirmation", id)).toHaveLength(0);
      expect(await fromComment("community_validation", id)).toHaveLength(0);
    }

    // The ordinary reply beside them still seals, which is the control: the
    // rule passed over two comments and not the thread.
    const solo = [
      ...(await fromComment("public_confirmation", SOLO_COMMENT)),
      ...(await fromComment("community_validation", SOLO_COMMENT)),
    ];
    expect(solo).toHaveLength(1);
    expect(solo[0]!["entry_id"]).toBe(ENTRY_YOUNG);

    // And both halves of the two-entry reply are sealed, each about its own
    // entry: approving one fact and rejecting another is an answer.
    const mixed = [
      ...(await fromComment("public_confirmation", MIXED_COMMENT)),
      ...(await fromComment("community_validation", MIXED_COMMENT)),
    ];
    expect(mixed).toHaveLength(2);
    expect(mixed.map((payload) => payload["entry_id"]).sort()).toEqual(
      [ENTRY_BARE, ENTRY_YOUNG].sort(),
    );

    // Nothing the two form comments named registered an operator, either: a
    // comment the door passed over introduced nobody.
    const operators = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).map((payload) => payload["operator"]);
    expect(operators).not.toContain(communityOperatorId(COLONY, FORM_PASTER));
  }, 600_000);

  it("keeps the core's own field list untouched by any of it", () => {
    // The rung is a sidecar field and the schema closes: nothing D-142 added is
    // signed, and a decision that widened the core would be a decision that
    // invalidated every signature in the log.
    expect(CORE_KEYS).toContain("evidence_tier");
    expect(CORE_KEYS).not.toContain("verification_binding");
  });
});

/**
 * The two community venues, end to end (decision D-138 items 2, 3 and 6).
 *
 * D-136 opened one door, at the founding registry, where a comment counts
 * because its author sealed the line's fingerprint into a witnessed log. The
 * Colony and GitHub have accounts and no such log, so the binding is the other
 * one D-138 names: the author signs the canonical line itself, writes the
 * signature into the line, and publishes the key it is by on their own public
 * profile — which this record fetches, hashes and archives exactly as it
 * archives a citation's snapshot, so a reader rechecks the whole claim years
 * later from the bundle alone and asks nobody anything.
 *
 * Everything below happens through the real sweep on a real miniflare D1, with
 * real Ed25519 keys signing the real canonical bytes. Only the two boards and
 * the clock are fixtures, and the boards fake exactly one thing: the network.
 * The profiles they answer are the bytes a profile door would answer, the
 * signatures are the agents' own, and nothing is asserted that the log did not
 * say.
 *
 * What is proved, in the order the bytes travel:
 *
 * An agent nobody has registered says a line on The Colony and another on
 * GitHub, signed, with its key on its profile. Each line registers a community
 * operator on its own venue and seals a validation — one operator per venue
 * account, because the account is what the key is bound to.
 *
 * An entry two domain operators had approved is promoted by one such line, and
 * the record discloses who met its consensus: `mixed`, and the bootstrap label
 * that said every validator sat inside the maintainer's own perimeter is gone,
 * because one of them did not.
 *
 * A doctored signature and a profile with no key stay account statements: the
 * lines are sealed, shown, and count towards nothing. So does a line by a key
 * whose profile has changed, which registers nothing at all.
 *
 * Three lines from three accounts on one venue about one entry: two count, and
 * the third is the per-community cap arriving (D-138 item 10) — three counting
 * communities means no single board supplies a consensus by itself.
 *
 * The listing door answers the same rows as data (item 6), on the same filters.
 *
 * And the export bundle carries the profile page the binding names, so the
 * offline verifier — the very code `npm run verify` runs — rechecks the
 * signature against the key in those bytes and passes.
 */

import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  MockBoardAdapter,
  type BoardComment,
} from "../src/adapters/board.js";
import { MockMirrorAdapter } from "../src/adapters/mirror.js";
import { buildExport } from "../src/cli/export.js";
import { verifyMirror } from "../src/cli/verify-mirror.js";
import { canonicalConfirmationLine } from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
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
import { archiveCapture } from "../src/storage/r2.js";
import {
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  DEFAULT_DOMAIN,
  NORM_VERSION,
  PROFILE_KEY_PREFIX,
} from "../src/policy.js";
import { ATTESTATION_VERSION, communityOperatorId } from "../src/registry.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  eventsOfType,
  getEntry,
  getOperator,
  operatorDomains,
  putAgent,
  putCapture,
  putEntry,
  putOperator,
  putOperatorDomain,
} from "../src/storage/repository.js";
import { verifyOffline } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

/**
 * The page every entry here cites, and the bytes the archive holds.
 *
 * Real bytes, really hashed under the norm rule: the entries carry the hash
 * their own capture produces, so the offline verifier's snapshot check is a
 * check and not a formality.
 */
const CAPTURE_HTML = [
  "<!doctype html>",
  "<html>",
  "  <head><title>gpt-5 pricing</title></head>",
  "  <body>",
  "    <main>",
  "      <h1>Pricing</h1>",
  "      <p>gpt-5 input: $2.50 per million tokens</p>",
  "    </main>",
  "  </body>",
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
const TEST_ORIGIN = "https://app.nomankind.ai";

/** The entry one community line promotes: two approvals already on it. */
const ENTRY_MIXED = `nmk_${"a1".repeat(16)}`;
/** The entry the cap is proved on: one approval, and three lines said about it. */
const ENTRY_CAP = `nmk_${"b2".repeat(16)}`;
/** The entry the refusals are said about, so nothing they touch can promote. */
const ENTRY_REFUSED = `nmk_${"c3".repeat(16)}`;

const COLONY = "colony";
const GITHUB = "github";
/** The Colony's ids are UUIDs, which is the whole reason `comment_id` widened. */
const COLONY_THREAD = "09ed63ba-438a-41e8-b352-f065b376106e";
const GITHUB_THREAD = 1;

/** The agent that binds a key on both venues and validates with it. */
const AGENT_HANDLE = "field-notes";
/** Two more accounts on The Colony, for the cap. */
const SECOND_HANDLE = "second-reader";
const THIRD_HANDLE = "third-reader";
/** The account whose signature is doctored. */
const DOCTORED_HANDLE = "doctored";
/** The account whose profile publishes no key at all. */
const UNKEYED_HANDLE = "unkeyed";

/** Ten trusted operators: the large pool, where three approvals verify. */
const POOL = Array.from({ length: 10 }, (_, index) => `op_v${index + 1}`);

/** The listing door's own answer (D-138 item 6). */
interface Listing {
  readonly entries: Record<string, unknown>[];
  readonly next: number | null;
  readonly as_of: string;
}

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

/** A profile page, as a venue's profile door answers one. */
function profileJson(handle: string, publicKey: string | null): string {
  return JSON.stringify({
    username: handle,
    display_name: handle,
    user_type: "agent",
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
let mirror: MockMirrorAdapter;
let witness: FakeWitness;
let report: Awaited<ReturnType<typeof runSweep>>;
let agent: Signer;
let second: Signer;
let third: Signer;
let doctored: Signer;
let unkeyed: Signer;

function envOf(): Env {
  return {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
    SEALING_AGENT_KEY: sealingKey,
  } as unknown as Env;
}

/**
 * One stated entry's eighteen core keys, in the schema's own names.
 *
 * Stated, and undecided: a community operator may only validate an entry that
 * is still open, so every line below has something to be about.
 */
function coreOf(overrides: Record<string, unknown>): Core {
  return {
    id: ENTRY_MIXED,
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: EFFECTIVE_AT,
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

/** One party: a real key, the agent id it is, and the operator behind it. */
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

/** The claim a line makes, canonically: what is signed, and nothing else. */
function claimFor(entryId: string): string {
  return canonicalConfirmationLine({
    entry_id: entryId,
    verdict: "approve",
    check: { kind: "hash", value: snapshot },
    attestation_version: ATTESTATION_VERSION,
  });
}

/** One line of the published form, signed by this key, with a reason after it. */
async function signedLine(
  signer: Signer,
  entryId: string,
  reason = "I fetched it and hashed it myself",
  doctor = false,
): Promise<string> {
  const claim = claimFor(entryId);
  const signature = await signer.sign(doctor ? `${claim} not this` : claim);
  return `${claim} ${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}${signature} ${reason}`;
}

/**
 * One comment, a minute after the last one.
 *
 * The Colony's cursor is the clock rather than an id (its ids are UUIDs), so
 * the instants are what a run's second read is bounded by and they have to be
 * the venue's own — one per comment, in the order they were written.
 */
const FIRST_COMMENT_AT = Date.parse("2026-09-16T09:00:00.000Z");
let commentAt = FIRST_COMMENT_AT;

/**
 * Start the thread again: two runs over one thread must see one thread.
 *
 * `offsetMs` writes the next comments that much later than the thread's first,
 * which is how a comment posted after a run is written — the cursor is the
 * clock here, so a later comment is one with a later instant.
 */
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

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, envOf(), { now });
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

  /** One entry, signed by its author, with real approvals on it. */
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
        // The draw the flag claims: the large pool asks for exactly one, and a
        // record that claimed it without one is refused by the kernel and by
        // the offline verifier alike.
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
    // One disclosed perimeter over the whole pool: every entry below carries
    // the bootstrap label until somebody outside it looks (D-128).
    await add("operator_trusted", null, {
      operator: party.operator,
      perimeter: PERIMETER,
    });
  }

  // Two approvals, one of them the drawn one: the large pool asks for three,
  // so one more counted decision promotes it.
  await submit(ENTRY_MIXED, {}, [
    { party: pool[0]!, at: "2026-09-11T01:00:00.000Z", drawn: true },
    { party: pool[1]!, at: "2026-09-11T02:00:00.000Z" },
  ]);

  // Nothing on it: three community lines are said about it, and the cap is
  // what decides how many of them count.
  await submit(ENTRY_CAP, { subject: "openai/gpt-4o" }, []);

  // Nothing on it either: the refused lines are said here, where a mistake
  // would show up as a promotion.
  await submit(ENTRY_REFUSED, { subject: "anthropic/claude-3-5-haiku" }, []);

  return events;
}

/** The Colony, as the sweep sees it: UUID threads, UUID comments, profiles. */
async function colonyBoard(): Promise<MockBoardAdapter> {
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
            AGENT_HANDLE,
            await signedLine(agent, ENTRY_MIXED),
          ),
          // Three accounts, one entry, one venue: the cap takes the first two.
          comment(
            "8c1c0a6e-6d4f-4d1e-9a2f-2b6a2f0e1d11",
            COLONY_THREAD,
            AGENT_HANDLE,
            await signedLine(agent, ENTRY_CAP, "one"),
          ),
          comment(
            "9f2b1b7f-7e5a-4c2f-8b3a-3c7b3a1f2e22",
            COLONY_THREAD,
            SECOND_HANDLE,
            await signedLine(second, ENTRY_CAP, "two"),
          ),
          comment(
            "a03c2c80-8f6b-4d3a-9c4b-4d8c4b2a3f33",
            COLONY_THREAD,
            THIRD_HANDLE,
            await signedLine(third, ENTRY_CAP, "three"),
          ),
          // A signature over other bytes, offered as this line's.
          comment(
            "b14d3d91-9a7c-4e4b-ad5c-5e9d5c3b4a44",
            COLONY_THREAD,
            DOCTORED_HANDLE,
            await signedLine(doctored, ENTRY_REFUSED, "doctored", true),
          ),
          // A real signature by a key no profile publishes.
          comment(
            "c25e4ea2-ab8d-4f5c-be6d-6fae6d4c5b55",
            COLONY_THREAD,
            UNKEYED_HANDLE,
            await signedLine(unkeyed, ENTRY_REFUSED, "unkeyed"),
          ),
        ],
      ],
    ]),
    profiles: new Map([
      [AGENT_HANDLE, profileJson(AGENT_HANDLE, agent.publicKey)],
      [SECOND_HANDLE, profileJson(SECOND_HANDLE, second.publicKey)],
      [THIRD_HANDLE, profileJson(THIRD_HANDLE, third.publicKey)],
      [DOCTORED_HANDLE, profileJson(DOCTORED_HANDLE, doctored.publicKey)],
      // Published, and publishing no key: an account statement, by a real key
      // nobody can find.
      [UNKEYED_HANDLE, profileJson(UNKEYED_HANDLE, null)],
    ]),
  });
}

/** GitHub: integer ids, an issue for a thread, the same agent's key. */
async function githubBoard(): Promise<MockBoardAdapter> {
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
            AGENT_HANDLE,
            await signedLine(agent, ENTRY_CAP, "and on the other board"),
          ),
        ],
      ],
    ]),
    profiles: new Map([
      [AGENT_HANDLE, profileJson(AGENT_HANDLE, agent.publicKey)],
    ]),
  });
}

describe("the two community venues", () => {
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

    agent = await keypair();
    second = await keypair();
    third = await keypair();
    doctored = await keypair();
    unkeyed = await keypair();

    const events = await buildEvents();
    await appendEvents(db, events);

    // The rows the registration door would have written, so the registry table
    // says what the events say and the export's registry is the log's.
    const parties: { operator: string; agent: string | null }[] = [
      { operator: MAINTAINER_OPERATOR, agent: null },
      { operator: AUTHOR_OPERATOR, agent: author.agent },
      ...pool.map((party) => ({
        operator: party.operator,
        agent: party.agent,
      })),
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

    // The archive the submit door would have written: the page each entry
    // cites, at its own address, with the row that serves it.
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

    for (const id of [ENTRY_MIXED, ENTRY_CAP, ENTRY_REFUSED]) {
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

    witness = await makeWitness("witness-a");
    mirror = new MockMirrorAdapter();
    report = await runSweep(envOf(), {
      now: NOW,
      beacon: new FixtureBeacon("venues"),
      // Two boards in one run, inside the one per-run budget.
      board: [await colonyBoard(), await githubBoard()],
      mirror,
      witness: new FakeWitnessAdapter({ signers: [witness] }),
      pinned: pinnedSet([witness]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("registers one operator per venue account off the signed lines", async () => {
    const registered = await sealedOf("community_operator_registered");
    const byOperator = new Map(
      registered.map((event) => [
        (event.payload as unknown as Record<string, unknown>)["operator"],
        event.payload as unknown as Record<string, unknown>,
      ]),
    );

    // The same agent on two venues is two operators, because the account is
    // what the key is bound to and it has one on each.
    const colony = byOperator.get(communityOperatorId(COLONY, AGENT_HANDLE))!;
    const github = byOperator.get(communityOperatorId(GITHUB, AGENT_HANDLE))!;
    expect(colony).toBeDefined();
    expect(github).toBeDefined();
    expect(colony["agent"]).toBe(`1F916:${agent.publicKey}`);
    expect(github["agent"]).toBe(colony["agent"]);

    // The binding is the page, by the hash its bytes are archived under.
    const binding = colony["binding"] as Record<string, unknown>;
    expect(binding["kind"]).toBe("profile");
    expect(binding["public_key"]).toBe(agent.publicKey);
    expect(typeof binding["capture_hash"]).toBe("string");
    expect(String(binding["capture_hash"]).startsWith("sha256:")).toBe(true);
    expect(String(binding["url"])).toContain(AGENT_HANDLE);
    // Nothing was sealed into anybody's registry: there is no registry here.
    expect(colony["registry_event_id"]).toBeNull();

    // The two accounts that count towards the cap registered as well; the two
    // refused ones registered nothing at all.
    expect(byOperator.has(communityOperatorId(COLONY, SECOND_HANDLE))).toBe(true);
    expect(byOperator.has(communityOperatorId(COLONY, DOCTORED_HANDLE))).toBe(
      false,
    );
    expect(byOperator.has(communityOperatorId(COLONY, UNKEYED_HANDLE))).toBe(
      false,
    );

    // And the registry rows the events imply.
    const record = (await getOperator(
      db,
      communityOperatorId(COLONY, AGENT_HANDLE),
    ))!;
    expect(record.kind).toBe("community");
    expect(record.details["venue"]).toBe(COLONY);
    expect(
      (await operatorDomains(db, communityOperatorId(GITHUB, AGENT_HANDLE))).map(
        (row) => row.domain,
      ),
    ).toEqual([DEFAULT_DOMAIN]);
  }, 600_000);

  it("seals the validations with the signature as their proof", async () => {
    const validations = await sealedOf("community_validation");
    const mixed = validations.find(
      (event) => event.entry_id === ENTRY_MIXED,
    )!;
    const payload = mixed.payload as unknown as Record<string, unknown>;
    expect(payload["venue"]).toBe(COLONY);
    expect(payload["handle"]).toBe(AGENT_HANDLE);
    expect(payload["decision"]).toBe("approve");
    expect(payload["attestation_version"]).toBe(ATTESTATION_VERSION);
    // The Colony's comment ids are UUIDs, and the log carries one whole.
    expect(payload["comment_id"]).toBe("3e54d240-2b8f-4e93-b203-a3a16f519528");

    const proof = payload["binding_proof"] as Record<string, unknown>;
    expect(proof["kind"]).toBe("profile");
    expect(proof["public_key"]).toBe(agent.publicKey);
    expect(typeof proof["signature"]).toBe("string");
    expect(typeof proof["capture_hash"]).toBe("string");

    // The report says the same thing the log does.
    expect(
      report.community_validations.map((row) => [row.venue, row.entry_id]),
    ).toContainEqual([GITHUB, ENTRY_CAP]);
  }, 600_000);

  it("promotes the entry the line completed, and discloses the class", async () => {
    const stored = (await getEntry(db, ENTRY_MIXED))!;
    expect(stored.entry["status"]).toBe("verified");
    // Two domain operators took part and one community operator was needed to
    // reach it: that is what `mixed` says.
    expect(stored.sidecar.verification_class).toBe("mixed");
    expect(stored.sidecar.verification_communities).toEqual([COLONY]);
    // And the label that said every validator sat inside the maintainer's own
    // perimeter is gone, because one of them did not.
    expect(stored.sidecar.bootstrap).toBeNull();
  }, 600_000);

  it("keeps a doctored signature and an unkeyed profile as account statements", async () => {
    const confirmations = await sealedOf("public_confirmation");
    const byHandle = new Map(
      confirmations.map((event) => [
        (event.payload as unknown as Record<string, unknown>)["handle"],
        event.payload as unknown as Record<string, unknown>,
      ]),
    );

    for (const handle of [DOCTORED_HANDLE, UNKEYED_HANDLE]) {
      const payload = byHandle.get(handle)!;
      expect(payload).toBeDefined();
      // Sealed, shown, and counting towards nothing — which is what D-136 made
      // a comment nobody signed, and what an unverifiable signature is too.
      expect(payload["counted"]).toBe(false);
      expect(payload["registry_proof"]).toBeNull();
      expect(payload["venue"]).toBe(COLONY);
    }

    // The run says which refusal each one was.
    expect(report.skipped["confirmation_signature_invalid"]).toBe(1);
    expect(report.skipped["confirmation_profile_unkeyed"]).toBe(1);

    // And the entry they were said about is untouched.
    const stored = (await getEntry(db, ENTRY_REFUSED))!;
    expect(stored.entry["status"]).toBe("draft");
    expect(stored.sidecar.verification_class).toBeNull();

    const validations = await sealedOf("community_validation");
    expect(
      validations.some((event) => event.entry_id === ENTRY_REFUSED),
    ).toBe(false);
  }, 600_000);

  it("counts at most two lines from one venue about one entry", async () => {
    // D-138 item 10: three counting communities, so one board can never supply
    // a consensus by itself — the last seat has to come from somewhere else.
    const validations = await sealedOf("community_validation");
    const onCap = validations
      .filter((event) => event.entry_id === ENTRY_CAP)
      .map((event) => event.payload as unknown as Record<string, unknown>);

    const fromColony = onCap.filter((one) => one["venue"] === COLONY);
    expect(fromColony).toHaveLength(2);
    expect(fromColony.map((one) => one["handle"])).toEqual([
      AGENT_HANDLE,
      SECOND_HANDLE,
    ]);
    // The third account's line is the confirmation it always was, and the run
    // names the rule that sent it there.
    expect(report.confirmation_fallbacks["community_cap"]).toBe(1);
    expect(
      onCap.some((one) => one["handle"] === THIRD_HANDLE),
    ).toBe(false);

    // The other board is not capped by the first one's: the same agent's line
    // on GitHub counts, because the cap is per community.
    expect(onCap.some((one) => one["venue"] === GITHUB)).toBe(true);
  }, 600_000);

  it("seals nothing twice, and reads no profile, on a second run", async () => {
    const before = (await sealedOf("community_validation")).length;
    const confirmationsBefore = (await sealedOf("public_confirmation")).length;
    const colony = await colonyBoard();
    const github = await githubBoard();
    const again = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 300_000),
      beacon: new FixtureBeacon("venues"),
      board: [colony, github],
    });
    expect(again.community_validations).toEqual([]);
    expect(again.confirmations).toEqual([]);

    // Not one profile door was asked anything. Every line on both threads is
    // already in the log, and a line the log holds is answered from the log:
    // the dedup key is read before the network, so a thread re-read every hour
    // for a year costs one comment read and nothing else.
    expect(colony.profileReads).toEqual([]);
    expect(github.profileReads).toEqual([]);

    // The cursors moved, so the second run read almost nothing back. GitHub
    // numbers its comments and its cursor is exact; The Colony's ids are UUIDs
    // and its cursor is the clock, which is inclusive of its own instant — so
    // the newest comment comes back once and is recognised, and nothing older
    // does.
    expect(again.confirmations_read.comments).toBe(1);
    expect((await sealedOf("community_validation")).length).toBe(before);
    expect((await sealedOf("public_confirmation")).length).toBe(
      confirmationsBefore,
    );
    // Three: the agent on each venue, and the second account on The Colony.
    // The third account never registered, because the cap sent its line back
    // before there was anything to register (D-138 item 10).
    expect((await sealedOf("community_operator_registered")).length).toBe(3);
  }, 600_000);

  it("refuses a line by a key the profile has since changed", async () => {
    // One operator per venue account, and this build has no rule for rotating
    // a community operator's key: a line signed by a new key is an account
    // statement with `key_changed` against it, and it registers nothing.
    const rotated = await keypair();
    // An hour after the thread's own comments, so it is newer than the cursor
    // the first run left: this is a comment written after that run.
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
              "d36f5fb3-bc9e-4a6d-cf7e-70bf7e5d6c66",
              COLONY_THREAD,
              AGENT_HANDLE,
              await signedLine(rotated, ENTRY_REFUSED, "rotated"),
            ),
          ],
        ],
      ]),
      profiles: new Map([
        [AGENT_HANDLE, profileJson(AGENT_HANDLE, rotated.publicKey)],
      ]),
    });

    const rotation = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 600_000),
      beacon: new FixtureBeacon("venues"),
      board: [board],
    });

    expect(rotation.skipped["confirmation_key_changed"]).toBe(1);
    expect(rotation.community_validations).toEqual([]);
    // Three: the agent on each venue, and the second account on The Colony.
    // The third account never registered, because the cap sent its line back
    // before there was anything to register (D-138 item 10).
    expect((await sealedOf("community_operator_registered")).length).toBe(3);
    const sealed = (await sealedOf("public_confirmation")).map(
      (event) => event.payload as unknown as Record<string, unknown>,
    );
    const statement = sealed.find(
      (one) => one["comment_id"] === "d36f5fb3-bc9e-4a6d-cf7e-70bf7e5d6c66",
    )!;
    expect(statement["counted"]).toBe(false);
  }, 600_000);

  it("reads one author's profile at most twice in a run, and never again", async () => {
    // The bound the door promises (D-138 item 2), put under the case that
    // breaks it: one account, six lines, five of them signed over other bytes.
    // The first line registers the operator, which costs one read; the second
    // fails against the key it registered under, which costs the one re-read a
    // rotation would have needed; and the four after it cost nothing at all,
    // because the author is held for the run.
    const noisy = await keypair();
    const handle = "noisy-account";
    const thread = "e46a5fb4-cd0f-4b7e-8f6a-81cf8f6e7d77";
    const lines = async (): Promise<BoardComment[]> => {
      rewindThread(7_200_000);
      const rows: BoardComment[] = [
        comment(
          "f57b6ac5-de10-4c8f-9a7b-92da9a7f8e88",
          thread,
          handle,
          await signedLine(noisy, ENTRY_REFUSED, "the real one"),
        ),
      ];
      for (let index = 0; index < 5; index += 1) {
        rows.push(
          comment(
            `0${index}8c7bd6-ef21-4d9a-ab8c-a3eba b8091`.replace(" ", "0"),
            thread,
            handle,
            await signedLine(noisy, ENTRY_REFUSED, `bad ${index}`, true),
          ),
        );
      }
      return rows;
    };
    const boardOf = async (): Promise<MockBoardAdapter> =>
      new MockBoardAdapter({
        venue: COLONY,
        binding: "profile",
        cursor: "time",
        threads: [thread],
        comments: new Map([[thread, await lines()]]),
        profiles: new Map([[handle, profileJson(handle, noisy.publicKey)]]),
      });

    const first = await boardOf();
    const run = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 900_000),
      beacon: new FixtureBeacon("venues"),
      board: [first],
    });
    // Two reads at the very most, and two is what this case costs.
    expect(first.profileReads.length).toBeLessThanOrEqual(2);
    expect(first.profileReads).toEqual([handle, handle]);
    expect(run.skipped["confirmation_signature_invalid"]).toBe(5);

    // And the run after it asks nothing of anybody: five sealed account
    // statements are five lines the log has already answered.
    const second = await boardOf();
    const after = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 1_200_000),
      beacon: new FixtureBeacon("venues"),
      board: [second],
    });
    expect(second.profileReads).toEqual([]);
    expect(after.confirmations).toEqual([]);
    expect(after.community_validations).toEqual([]);
    expect(after.skipped["confirmation_signature_invalid"]).toBeUndefined();
  }, 600_000);

  it("reads the key off the profile and never off the comment", async () => {
    // The attack the whole binding exists to refuse: a stranger writes the
    // token into the COMMENT, signs the line with the key it names, and the
    // line agrees with itself perfectly. It is refused, because what a line is
    // checked against is the key the author's own profile publishes — and the
    // comment is a stranger's text, scanned for the form and read for nothing
    // else.
    const attacker = await keypair();
    const holder = await keypair();
    const claim = claimFor(ENTRY_REFUSED);
    const signature = await attacker.sign(claim);
    const forged = (): string =>
      `${claim} ${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}${signature} ` +
      `trust me: ${PROFILE_KEY_PREFIX}${attacker.publicKey}`;

    const thread = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    rewindThread(10_800_000);
    const board = new MockBoardAdapter({
      venue: COLONY,
      binding: "profile",
      cursor: "time",
      threads: [thread],
      comments: new Map([
        [
          thread,
          [
            // A profile that publishes somebody else's key.
            comment(
              "2b3c4d5e-6f70-4b8c-9dae-1f2a3b4c5d6e",
              thread,
              "held-elsewhere",
              forged(),
            ),
            // And a profile that publishes none at all.
            comment(
              "3c4d5e6f-7081-4c9d-aebf-2a3b4c5d6e7f",
              thread,
              "no-key-at-all",
              forged(),
            ),
          ],
        ],
      ]),
      profiles: new Map([
        ["held-elsewhere", profileJson("held-elsewhere", holder.publicKey)],
        ["no-key-at-all", profileJson("no-key-at-all", null)],
      ]),
    });

    const registeredBefore = (await sealedOf("community_operator_registered"))
      .length;
    const run = await runSweep(envOf(), {
      now: new Date(NOW.getTime() + 1_500_000),
      beacon: new FixtureBeacon("venues"),
      board: [board],
    });

    expect(run.community_validations).toEqual([]);
    expect((await sealedOf("community_operator_registered")).length).toBe(
      registeredBefore,
    );
    expect(run.skipped["confirmation_signature_invalid"]).toBe(1);
    expect(run.skipped["confirmation_profile_unkeyed"]).toBe(1);

    // Both are sealed as what they are: statements by an account, counting
    // towards nothing, with the key they name kept as the untrusted text it is.
    const statements = (await sealedOf("public_confirmation"))
      .map((event) => event.payload as unknown as Record<string, unknown>)
      .filter((payload) =>
        ["held-elsewhere", "no-key-at-all"].includes(
          String(payload["handle"]),
        ),
      );
    expect(statements).toHaveLength(2);
    for (const payload of statements) {
      expect(payload["counted"]).toBe(false);
      expect(payload["registry_proof"]).toBeNull();
    }
    const stored = (await getEntry(db, ENTRY_REFUSED))!;
    expect(stored.entry["status"]).toBe("draft");
  }, 600_000);

  it("verifies a mirror that carries a profile-bound operator", async () => {
    // The other half of item 5: `npm run verify-mirror` over a clone. The
    // mirror carries the operator and the binding; the page the binding names
    // is read from an archive, exactly as an entry's own snapshot is — so a
    // clone with the pages verifies, and one without them cannot check the
    // binding and says so rather than passing.
    const root = await mkdtemp(join(tmpdir(), "nmk-venues-mirror-"));
    const captures = join(root, "captures");
    await mkdir(captures, { recursive: true });
    for (const [path, content] of mirror.files) {
      const file = join(root, path);
      await mkdir(dirname(file), { recursive: true });
      await writeFile(file, content, "utf8");
    }

    /** The archive as an operator keeps one: the bytes under the hex. */
    const archive = async (hash: string, bytes: Uint8Array): Promise<string> => {
      const name = hash.startsWith("sha256:") ? hash.slice(7) : hash;
      await writeFile(join(captures, name), bytes);
      return join(captures, name);
    };
    await archive(snapshot, captureBytes);

    // Every page a registration named, exactly as an operator's own archive
    // would hold them: the same bytes the venues answered, under the hashes
    // the bindings carry.
    const pages = new Map<string, string>([
      [AGENT_HANDLE, profileJson(AGENT_HANDLE, agent.publicKey)],
      [SECOND_HANDLE, profileJson(SECOND_HANDLE, second.publicKey)],
    ]);
    const registrations = (await sealedOf("community_operator_registered")).map(
      (event) => event.payload as unknown as Record<string, unknown>,
    );
    const hashOf = (handle: string, venue: string): string =>
      (
        registrations.find(
          (payload) =>
            payload["operator"] === communityOperatorId(venue, handle),
        )!["binding"] as Record<string, unknown>
      )["capture_hash"] as string;

    for (const [handle, text] of pages) {
      await archive(
        hashOf(handle, COLONY),
        new TextEncoder().encode(text),
      );
    }
    const profilePath = await archive(
      hashOf(AGENT_HANDLE, COLONY),
      new TextEncoder().encode(pages.get(AGENT_HANDLE)!),
    );

    const lines: string[] = [];
    const io = {
      stdout: (line: string) => lines.push(line),
      stderr: (line: string) => lines.push(line),
    };
    const code = await verifyMirror(
      [join(root, "local"), "--captures", captures],
      io,
      { fetch: (request: Request) => send(request) },
      NOW,
    );
    expect([code, lines.join("\n")]).toEqual([0, lines.join("\n")]);
    expect(lines).toContain(`ok ${ENTRY_MIXED}`);

    // Take the profile away and the same clone no longer proves the binding.
    await rm(profilePath);
    const without: string[] = [];
    const refused = await verifyMirror(
      [join(root, "local"), "--captures", captures],
      {
        stdout: (line: string) => without.push(line),
        stderr: (line: string) => without.push(line),
      },
      { fetch: (request: Request) => send(request) },
      NOW,
    );
    expect(refused).toBe(1);
    expect(
      without.some(
        (line) =>
          line.startsWith(`FAIL ${ENTRY_MIXED}`) &&
          line.includes("community_binding"),
      ),
    ).toBe(true);

    await rm(root, { recursive: true, force: true });
  }, 600_000);

  it("lists the entries as JSON, on the same filters as the page", async () => {
    const list = async (
      query: string,
    ): Promise<{ status: number; body: Listing }> => {
      const response = await send(
        new Request(`${TEST_ORIGIN}/entries${query}`, {
          headers: { accept: "application/json" },
        }),
      );
      const body = (await response.json()) as Listing;
      return { status: response.status, body };
    };

    const all = await list("");
    expect(all.status).toBe(200);
    expect(all.body.as_of).toBe(NOW.toISOString());
    expect(all.body.next).toBeNull();
    const verified = all.body.entries.find((row) => row["id"] === ENTRY_MIXED)!;
    expect(verified).toEqual({
      id: ENTRY_MIXED,
      status: "verified",
      domain: DEFAULT_DOMAIN,
      subject: SUBJECT,
      category: CATEGORY,
      effective_at: EFFECTIVE_AT,
      submitted_at: SUBMITTED_AT,
      sealed_position: expect.any(Number) as unknown as number,
      verification_class: "mixed",
      bootstrap: false,
    });

    // Session 4's workflows read this one.
    const drafts = await list("?status=draft");
    expect(drafts.body.entries.map((row) => row["id"]).sort()).toEqual(
      [ENTRY_CAP, ENTRY_REFUSED].sort(),
    );
    for (const row of drafts.body.entries) {
      expect(row["status"]).toBe("draft");
      expect(row["verification_class"]).toBeNull();
      // Draft, so nobody has met a consensus and there is no label yet.
      expect(row["bootstrap"]).toBe(false);
    }

    // The class floor, exactly as the page and the read doors apply it.
    expect(
      (await list("?min_class=mixed")).body.entries.map((row) => row["id"]),
    ).toEqual([ENTRY_MIXED]);
    expect((await list("?min_class=registered")).body.entries).toEqual([]);
    expect(
      (await list("?status=verified")).body.entries.map((row) => row["id"]),
    ).toEqual([ENTRY_MIXED]);

    // A query nobody published is refused in the kernel's own word, as JSON.
    const bad = await send(
      new Request(`${TEST_ORIGIN}/entries?min_class=gold`, {
        headers: { accept: "application/json" },
      }),
    );
    expect(bad.status).toBe(400);
    expect((await bad.json()) as Record<string, unknown>).toMatchObject({
      error: "bad_min_class",
    });

    // And a browser still gets the page: one reading of the log, two renderings.
    const page = await send(
      new Request(`${TEST_ORIGIN}/entries`, {
        headers: { accept: "text/html" },
      }),
    );
    expect(page.headers.get("content-type")).toContain("text/html");
  }, 600_000);

  it("exports a bundle that carries the profile, and verifies offline", async () => {
    const exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId: ENTRY_MIXED,
      http: { fetch: (request: Request) => send(request) },
      now: NOW,
    });

    // The page the registration named is in the bundle, under its own hash,
    // with the key in its bytes — which is the whole of what makes a profile
    // binding checkable by somebody who was never there.
    const registered = (await sealedOf("community_operator_registered"))
      .map((event) => event.payload as unknown as Record<string, unknown>)
      .find(
        (payload) =>
          payload["operator"] === communityOperatorId(COLONY, AGENT_HANDLE),
      )!;
    const captureHash = (registered["binding"] as Record<string, unknown>)[
      "capture_hash"
    ] as string;
    const capture = exported.bundle.captures?.[captureHash];
    expect(capture).toBeDefined();
    expect(
      Buffer.from(capture!.body_base64, "base64").toString("utf8"),
    ).toContain(`${PROFILE_KEY_PREFIX}${agent.publicKey}`);

    // And the verifier `npm run verify` runs, over exactly these two files.
    const answer = await verifyOffline(exported.entry, exported.bundle);
    expect(answer.diffs).toEqual([]);
    expect(answer.ok).toBe(true);

    // Without the page, the same bundle no longer proves the binding: the
    // check is on the bytes and not on anybody's word about them.
    const withoutIt = await verifyOffline(exported.entry, {
      ...exported.bundle,
      captures: Object.fromEntries(
        Object.entries(exported.bundle.captures ?? {}).filter(
          ([hash]) => hash !== captureHash,
        ),
      ),
    });
    expect(withoutIt.ok).toBe(false);
    expect(
      withoutIt.diffs.some((diff) => diff.check === "community_binding"),
    ).toBe(true);
  }, 600_000);
});

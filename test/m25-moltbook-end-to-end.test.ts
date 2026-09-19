/**
 * Moltbook, end to end (decision D-145).
 *
 * D-136 opened one door at the founding registry, D-138 a second where an agent
 * signs the line and publishes the key on its own profile, and D-142 the rung
 * below them where a bare reply counts because a board authenticated its
 * author. D-145 adds a venue and nothing else: Moltbook is admitted on The
 * Colony's own footing, with the same `profile` binding, the same account rung
 * under it, and one more community under the floor that says a consensus may
 * not come from one board. No number moved and no derivation changed.
 *
 * So what has to be shown is that a venue shaped differently travels the whole
 * way through unchanged. Everything below happens through the real sweep on a
 * real miniflare D1, with real Ed25519 keys signing the real canonical bytes.
 * Only the board and the clock are fixtures, and the board fakes exactly one
 * thing: the network. The documents it hands back are the shapes Moltbook
 * really serves — a page of comments with replies nested inside them, and a
 * profile wrapped in `{success, agent:{...}}` — read from its own public doors
 * on 2026-09-19.
 *
 * What is proved, in the order the bytes travel:
 *
 * A nested reply — a comment under somebody else's comment — is a comment like
 * any other. It registers a community operator bound by the account, seals a
 * validation at the `account` rung carrying both capture hashes and no
 * signature, and the comment capture the binding names really is the Moltbook
 * comments page, with the counted reply inside it where the board put it.
 *
 * An agent that published `nomankind-key:` in its description and signed the
 * line is counted at the key rung on the same thread, out of the same profile
 * door — the field this board calls a description doing exactly what a bio does
 * on the other two.
 *
 * One of nomankind's own accounts replies too. Its line is sealed and shown
 * with the perimeter word on it, and counted toward nothing at any rung.
 *
 * And a comment carrying both of an entry's published lines is the ask quoted
 * back rather than a statement about it (D-144): passed over whole, taking
 * nothing, fetching no capture, counted by the reason's own name.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockBoardAdapter, type BoardComment } from "../src/adapters/board.js";
import { canonicalConfirmationLine } from "../src/confirm.js";
import { type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  appendEvent,
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
  communityCapPerEntry,
  countingCommunities,
} from "../src/policy.js";
import { ATTESTATION_VERSION, communityOperatorId } from "../src/registry.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  eventsOfType,
  getOperator,
  putAgent,
  putCapture,
  putEntry,
  putOperator,
  putOperatorDomain,
} from "../src/storage/repository.js";
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
const NOW = new Date("2026-09-19T12:00:00.000Z");

const VENUE = "moltbook";
/** A post uuid, as this board spells a thread. */
const THREAD = "19b6e9bf-6ff9-4ea5-834a-cbbac714f546";

/** The entry the counted lines are said about. */
const ENTRY_REPLY = `nmk_${"b8".repeat(16)}`;
/** The entry the pasted-back block is said about, so nothing it touches moves. */
const ENTRY_FORM = `nmk_${"c9".repeat(16)}`;
/**
 * The entry nomankind's own line is said about.
 *
 * Its own entry and not the counted one's, because the per-community cap is
 * asked before the perimeter is: two counted lines about one entry from one
 * board is this venue's whole allowance, and a third line there would be
 * refused by the cap and would prove nothing about the perimeter.
 */
const ENTRY_PERIMETER = `nmk_${"d0".repeat(16)}`;

/** The agent whose counted line is nested under somebody else's comment. */
const REPLIER = "field-notes";
/** Whose comment it is nested under: a bystander who said nothing of the form. */
const BYSTANDER = "passer-by";
/** The agent that published a key in its description and signed its line. */
const KEYED = "signs-things";
/** The agent that pasted the ask's whole block back. */
const FORM_PASTER = "form-paster";
/** One of nomankind's own, taken from the published perimeter. */
const PERIMETER_OPERATOR = PERIMETER_ACCOUNTS.find((id) =>
  id.startsWith(`${VENUE}:`),
)!;
const PERIMETER_HANDLE = PERIMETER_OPERATOR.slice(`${VENUE}:`.length);

/** The comment ids: UUIDs, which is what this board numbers comments with. */
const ROOT_COMMENT = "2a501eb7-bf3a-485b-939c-d86e7b3cc85f";
const REPLY_COMMENT = "bff9ba83-3d85-4a5c-9bde-e09698f3897d";
const KEYED_COMMENT = "4f8d6c21-9a0b-4e7f-8c3d-1b2a3c4d5e6f";
const PERIMETER_COMMENT = "7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d";
const FORM_COMMENT = "9d8c7b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d";

/** When each account says it was created: all of them before the entry. */
const CREATED_AT = "2024-03-01T00:00:00.000Z";

const POOL = Array.from({ length: 10 }, (_, index) => `op_v${index + 1}`);

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
 * Moltbook's profile door, in its own shape.
 *
 * `{success, agent:{...}}`, with the key — when there is one — in the
 * `description`, which is the field this board has where the other two have a
 * bio, and `created_at` inside the same object rather than at the top of the
 * answer.
 */
function profileJson(handle: string, publicKey: string | null): string {
  return JSON.stringify({
    success: true,
    agent: {
      id: `agent-${handle}`,
      name: handle,
      display_name: handle,
      description:
        publicKey === null
          ? "An agent that reads things. No keys here."
          : `An agent that checks facts. ${PROFILE_KEY_PREFIX}${publicKey}`,
      karma: 12,
      is_verified: false,
      is_claimed: true,
      is_active: true,
      created_at: CREATED_AT,
      last_active: "2026-09-19T00:00:00.000Z",
      deleted_at: null,
      labels: [],
    },
  });
}

let store: TestDatabase;
let db: D1Like;
let sealingKey = "";
let snapshot = "";
let captureBytes = new Uint8Array();
let author: Party;
let pool: Party[] = [];
let keyed: Signer;
let report: Awaited<ReturnType<typeof runSweep>>;
/** The comments page the board hands back as every counted comment's capture. */
let commentsPage = "";

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
    id: ENTRY_REPLY,
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: EFFECTIVE_AT,
    // Stated, because `ACCOUNT_BINDING_TIERS` is stated and nothing else, and
    // D-145 admits the rung here exactly as it stands everywhere else.
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

/** The claim a line makes, canonically: what a signature would be over. */
function claimFor(entryId: string): string {
  return canonicalConfirmationLine({
    entry_id: entryId,
    verdict: "approve",
    check: { kind: "hash", value: snapshot },
    attestation_version: ATTESTATION_VERSION,
  });
}

/** A bare reply: the published form, the token, a reason, no signature. */
function bareLine(entryId: string, reason: string): string {
  return `${claimFor(entryId)} ${reason}`;
}

/** The same line, signed by a key the account's description publishes. */
async function signedLine(
  signer: Signer,
  entryId: string,
  reason: string,
): Promise<string> {
  const claim = claimFor(entryId);
  const signature = await signer.sign(claim);
  return `${claim} ${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}${signature} ${reason}`;
}

/** One of an entry's two published lines, spelled as the ask spells it. */
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

/** An entry's block as the ask prints it: both lines, under a heading. */
function askBlockFor(entryId: string): string {
  return [
    `  ${entryId} · ai-ecosystem · ${SUBJECT} · draft`,
    `  claim: "the quoted claim"`,
    `  ${lineFor(entryId, "approve")}`,
    `  ${lineFor(entryId, "reject")}`,
  ].join("\n");
}

const FIRST_COMMENT_AT = Date.parse("2026-09-18T09:00:00.000Z");
let commentAt = FIRST_COMMENT_AT;

function rewindThread(offsetMs = 0): void {
  commentAt = FIRST_COMMENT_AT + offsetMs;
}

function comment(id: string, handle: string, body: string): BoardComment {
  commentAt += 60_000;
  return {
    id,
    thread: THREAD,
    handle,
    body,
    posted_at: new Date(commentAt).toISOString(),
  };
}

/**
 * The comments page as Moltbook serves one, with the counted reply nested.
 *
 * This is the document the sweep archives as every counted comment's capture
 * here, because the board publishes no per-comment door: the reply the record
 * counted is inside somebody else's root comment, under `content` rather than
 * `body`, and the offline verifier finds it there by the id the validation
 * sealed (src/verify.ts, decision D-145).
 */
function commentsPageFor(
  rows: readonly { id: string; handle: string; body: string }[],
): string {
  const [nested, ...rest] = rows;
  const row = (
    each: { id: string; handle: string; body: string },
    depth: number,
    replies: unknown[],
  ): Record<string, unknown> => ({
    id: each.id,
    post_id: THREAD,
    content: each.body,
    author_id: `agent-${each.handle}`,
    author: { id: `agent-${each.handle}`, name: each.handle },
    upvotes: 0,
    downvotes: 0,
    score: 0,
    reply_count: replies.length,
    is_deleted: false,
    depth,
    verification_status: "pending",
    is_spam: false,
    created_at: "2026-09-18T09:01:00.000Z",
    updated_at: "2026-09-18T09:01:00.000Z",
    replies,
  });
  return JSON.stringify({
    success: true,
    post_id: THREAD,
    sort: "new",
    count: rows.length + 1,
    comments: [
      // The bystander's root comment, with the counted reply inside it.
      row(
        { id: ROOT_COMMENT, handle: BYSTANDER, body: "does the page still say that?" },
        0,
        [row(nested!, 1, [])],
      ),
      ...rest.map((each) => row(each, 0, [])),
    ],
    has_more: false,
    next_cursor: null,
  });
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
  ): Promise<void> => {
    const core = coreOf({ id, ...overrides });
    await add("entry_submitted", id, {
      core,
      signature: await signCore(core, author.keys.privateKey),
    });
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

  // Nothing on either entry: every line below arrives at an open entry, so what
  // it does is the venue's and the rung's and nothing else's.
  await submit(ENTRY_REPLY, {});
  await submit(ENTRY_FORM, { subject: "openai/gpt-4o" });
  await submit(ENTRY_PERIMETER, { subject: "anthropic/claude-3-5-haiku" });

  return events;
}

/** The board: one thread, four comments, one of them nested. */
async function moltbookBoard(): Promise<MockBoardAdapter> {
  rewindThread();
  const rows = [
    {
      id: REPLY_COMMENT,
      handle: REPLIER,
      body: bareLine(ENTRY_REPLY, "I opened the page and the claim is on it"),
    },
    {
      id: KEYED_COMMENT,
      handle: KEYED,
      body: await signedLine(keyed, ENTRY_REPLY, "and I signed for it"),
    },
    {
      id: PERIMETER_COMMENT,
      handle: PERIMETER_HANDLE,
      body: bareLine(ENTRY_PERIMETER, "the maintainer looked too"),
    },
  ];
  commentsPage = commentsPageFor(rows);

  return new MockBoardAdapter({
    venue: VENUE,
    // The Colony's binding, on the same footing (D-145).
    binding: "profile",
    // The ids are UUIDs, so the cursor is the clock.
    cursor: "time",
    threads: [THREAD],
    comments: new Map([
      [
        THREAD,
        [
          // The bystander's own root comment: prose, and the parser ignores it.
          comment(ROOT_COMMENT, BYSTANDER, "does the page still say that?"),
          ...rows.map((each) => comment(each.id, each.handle, each.body)),
          // The ask's whole block, pasted back: a form and not a statement.
          comment(FORM_COMMENT, FORM_PASTER, askBlockFor(ENTRY_FORM)),
        ],
      ],
    ]),
    profiles: new Map([
      [BYSTANDER, profileJson(BYSTANDER, null)],
      [REPLIER, profileJson(REPLIER, null)],
      [KEYED, profileJson(KEYED, keyed.publicKey)],
      [PERIMETER_HANDLE, profileJson(PERIMETER_HANDLE, null)],
      [FORM_PASTER, profileJson(FORM_PASTER, null)],
    ]),
    accounts: new Map(
      [BYSTANDER, REPLIER, KEYED, PERIMETER_HANDLE, FORM_PASTER].map(
        (handle) => [handle, CREATED_AT],
      ),
    ),
    // The whole comments page, for each comment the sweep may capture. The
    // board publishes no per-comment door, so this is what a capture of any of
    // them is — and deliberately none for the pasted-back block, which the
    // door must never reach for a capture of.
    commentCaptures: new Map(
      [REPLY_COMMENT, KEYED_COMMENT, PERIMETER_COMMENT].map((id) => [
        id,
        commentsPage,
      ]),
    ),
  });
}

describe("Moltbook, end to end", () => {
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
    keyed = await keypair();

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

    for (const id of [ENTRY_REPLY, ENTRY_FORM, ENTRY_PERIMETER]) {
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
      beacon: new FixtureBeacon("moltbook"),
      board: [await moltbookBoard()],
    });
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("counts a reply nested under somebody else's comment, at the account rung", async () => {
    const operator = communityOperatorId(VENUE, REPLIER);
    const registered = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).find((payload) => payload["operator"] === operator)!;
    expect(registered).toBeDefined();

    const binding = registered["binding"] as Record<string, unknown>;
    // No key anywhere in it, because there is none to have.
    expect(binding["kind"]).toBe("account");
    expect(binding["venue"]).toBe(VENUE);
    expect(binding["handle"]).toBe(REPLIER);
    expect(String(binding["comment_capture_hash"])).toMatch(/^sha256:/);
    expect(String(binding["profile_capture_hash"])).toMatch(/^sha256:/);
    // What makes "older than the entry" a fact rather than a claim, read out of
    // the envelope this venue wraps its agent in.
    expect(binding["account_created_at"]).toBe(CREATED_AT);
    expect(registered["registry_event_id"]).toBeNull();

    const validation = payloadsOf(await sealedOf("community_validation")).find(
      (payload) =>
        payload["operator"] === operator && payload["entry_id"] === ENTRY_REPLY,
    )!;
    expect(validation).toBeDefined();
    expect(validation["venue"]).toBe(VENUE);
    expect(validation["binding_kind"]).toBe("account");
    expect(validation["comment_id"]).toBe(REPLY_COMMENT);
    expect(validation["perimeter"]).toBeNull();
    const proof = validation["binding_proof"] as Record<string, unknown>;
    expect(proof["kind"]).toBe("account");
    // The one thing a key-bound proof carries that this one must not.
    expect(proof["signature"]).toBeUndefined();
    expect(proof["public_key"]).toBeUndefined();

    const record = (await getOperator(db, operator))!;
    expect(record.kind).toBe("community");
  }, 600_000);

  it("archives the comments page, with the counted reply nested inside it", async () => {
    const operator = communityOperatorId(VENUE, REPLIER);
    const registered = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).find((payload) => payload["operator"] === operator)!;
    const binding = registered["binding"] as Record<string, unknown>;
    const hash = String(binding["comment_capture_hash"]);

    const held = await readCapture(store.captures, hash);
    expect(held).not.toBeNull();
    expect(await archiveAddress(held!.bytes)).toBe(hash);

    // Really the board's own document, and really nested: the counted reply is
    // one level down inside a root comment that belongs to somebody else, which
    // is exactly the shape the offline verifier's locating had to learn.
    const document = JSON.parse(new TextDecoder().decode(held!.bytes)) as {
      comments: { id: string; replies: { id: string; content: string }[] }[];
    };
    expect(document.comments[0]!.id).toBe(ROOT_COMMENT);
    expect(document.comments[0]!.replies[0]!.id).toBe(REPLY_COMMENT);
    expect(document.comments[0]!.replies[0]!.content).toContain(TOKEN);
  }, 600_000);

  it("counts the key-bound line out of the description, on the same thread", async () => {
    const operator = communityOperatorId(VENUE, KEYED);
    const registered = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).find((payload) => payload["operator"] === operator)!;
    const binding = registered["binding"] as Record<string, unknown>;
    // The field this board calls a description doing exactly what a bio does on
    // the other two: the key is published there, captured like a cited page,
    // and the line's signature is checked against it.
    expect(binding["kind"]).toBe("profile");
    expect(binding["public_key"]).toBe(keyed.publicKey);
    expect(registered["agent"]).toBe(`1F916:${keyed.publicKey}`);

    const validation = payloadsOf(await sealedOf("community_validation")).find(
      (payload) =>
        payload["operator"] === operator && payload["entry_id"] === ENTRY_REPLY,
    )!;
    expect(validation["binding_kind"]).toBe("profile");
    const proof = validation["binding_proof"] as Record<string, unknown>;
    expect(proof["public_key"]).toBe(keyed.publicKey);
    expect(typeof proof["signature"]).toBe("string");
  }, 600_000);

  it("counts both lines and no more, which is this venue's cap", async () => {
    // D-138 item 10, unchanged by D-145: a fourth counting community does not
    // move the per-entry cap, because the cap is stated against the consensus
    // size and the community floor rather than against how many boards exist.
    expect(countingCommunities()).toContain(VENUE);
    expect(communityCapPerEntry(countingCommunities().length)).toBe(2);
    const counted = report.community_validations.filter(
      (row) => row.entry_id === ENTRY_REPLY && row.perimeter === null,
    );
    expect(counted).toHaveLength(2);
    expect(counted.map((row) => row.binding_kind).sort()).toEqual([
      "account",
      "profile",
    ]);
    for (const row of counted) expect(row.venue).toBe(VENUE);
  }, 600_000);

  it("seals the perimeter account's line and counts it toward nothing", async () => {
    const line = payloadsOf(await sealedOf("community_validation")).find(
      (payload) => payload["operator"] === PERIMETER_OPERATOR,
    )!;
    expect(line).toBeDefined();
    // Sealed and shown exactly like any other, and disclosed with the word the
    // maintainer published in advance — for an account that does not exist yet,
    // because a perimeter is drawn before the fact or it is not a perimeter.
    expect(line["perimeter"]).toBe(PERIMETER_WORD);
    expect(line["venue"]).toBe(VENUE);
    expect(line["comment_id"]).toBe(PERIMETER_COMMENT);
    expect(
      report.community_validations.filter((row) => row.perimeter !== null),
    ).toHaveLength(1);
  }, 600_000);

  it("passes over the comment that carried both of an entry's lines", async () => {
    // Decision D-144, at the door, on a venue that did not exist when it was
    // made. Nobody approves and rejects the same fact in the same breath, so a
    // comment holding both of one entry's published lines is the ask quoted
    // back — passed over whole, taking nothing.
    expect(report.skipped["confirmation_form_not_statement"]).toBe(1);
    // And it cost one parse: the board was never asked for its bytes, so the
    // capture the fixture does not hold was never missed.
    expect(report.skipped["account_comment_unavailable"]).toBeUndefined();

    for (const type of ["public_confirmation", "community_validation"] as const) {
      const fromForm = payloadsOf(await sealedOf(type)).filter(
        (payload) => payload["comment_id"] === FORM_COMMENT,
      );
      expect(fromForm).toHaveLength(0);
    }
    // A comment the door passed over introduced nobody, either.
    const operators = payloadsOf(
      await sealedOf("community_operator_registered"),
    ).map((payload) => payload["operator"]);
    expect(operators).not.toContain(communityOperatorId(VENUE, FORM_PASTER));
    // And the bystander's prose is prose: the parser ignores it, so no
    // operator and no line came out of the comment the counted reply sits in.
    expect(operators).not.toContain(communityOperatorId(VENUE, BYSTANDER));
  }, 600_000);
});

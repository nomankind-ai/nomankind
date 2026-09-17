/**
 * The community door, end to end: what a token line has to be before it makes
 * anybody an operator (decision D-138).
 *
 * D-138 registers a community operator implicitly, by its first *counted*
 * confirmation line carrying the attestation token — and "counted" is the whole
 * weight the word carries. A comment on a public board is an account's word:
 * anybody can type a hash and anybody can type `attest:`. What makes the line a
 * key's statement is the confirmer's own `memory.seal` of its fingerprint in the
 * founding registry's log, proved under a signed, countersigned head.
 *
 * So the same token line is put to the door three times, from three handles
 * that differ in exactly one thing — whether the registry holds a seal of it
 * that verifies — and the log is read afterwards:
 *
 * - sealed, and the proof holds: an operator is registered and a validation is
 *   sealed;
 * - nothing sealed: one public confirmation, `counted` false, and nobody is
 *   registered;
 * - sealed but the proof does not verify: the same, plus the refusal counted.
 *
 * Every handle here has a board record, so the two refusals cannot be mistaken
 * for a handle whose key the board could not name: the only difference between
 * the case that registers an operator and the two that do not is the seal.
 *
 * The second suite below takes the line that does register an operator all the
 * way through the record: the three events sealed in order, the entry promoted
 * and its class disclosed, the registry rows, the doors that answer and filter
 * on it, the mirror that carries it, and the replay that has to agree with the
 * log. And the lines that are not validations — the author's own key, the same
 * account twice, an unsealed one — each sealed as the confirmation it always
 * was, with the rule that sent it there counted.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  MockBoardAdapter,
  type BoardComment,
  type BoardRecord,
  type BoardSealProof,
} from "../src/adapters/board.js";
import { MockMirrorAdapter } from "../src/adapters/mirror.js";
import { operatorRows } from "../src/import.js";
import type { MirrorOperator } from "../src/mirror.js";
import {
  confirmationFingerprint,
  type ConfirmationTrust,
} from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  appendEvent,
  type ApproverRecord,
  type ConfirmationProof,
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
import {
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  DEFAULT_DOMAIN,
} from "../src/policy.js";
import {
  ATTESTATION_VERSION,
  checkRegistration,
  communityOperatorId,
  isCommunityOperatorId,
  isOperatorDomain,
  parseCommunityOperatorId,
} from "../src/registry.js";
import {
  registryCheckpointPayload,
  registryWitnessPayload,
} from "../src/registry-proof.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  eventsAfter,
  eventsOfType,
  getEntry,
  getOperator,
  listOperators,
  operatorDomains,
  putAgent,
  putEntry,
  putOperator,
  putOperatorDomain,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRead } from "../src/worker/read.js";
import { handleRegistry } from "../src/worker/registry.js";
import { handleSync } from "../src/worker/sync.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { leafOf, pathOf, rootOf } from "./helpers/registry-tree.js";
import { FixtureResolver, makeAgent, signedPost } from "./helpers/registry.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = `nmk_${"c3".repeat(16)}`;
const SNAPSHOT_HASH = example["snapshot_hash"] as string;
const SIGNATURE = example["signature"] as string;
const AUTHOR_OPERATOR = "op_brightloop";
const VENUE = "1f916";
const THREAD = 5212;
const NOW = new Date("2026-09-17T12:00:00.000Z");
const TOKEN = `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`;

/** Sealed the token line, and the seal proves: a community operator. */
const SEALED_HANDLE = "morty-synctzn";
/** Said the same line and sealed nothing at all. */
const UNSEALED_HANDLE = "unsealed-citizen";
/** Sealed it, but the proof does not fold: refused, and uncounted. */
const DOCTORED_HANDLE = "doctored-citizen";

const REGISTRY_ORIGIN = "https://registry.test";
const REGISTRY_LOG = "identity_events";
const GOOD_EVENT_HASH = "1".repeat(64);
const OTHER_EVENT_HASH = "2".repeat(64);

let store: TestDatabase;
let db: D1Like;
let sealingKey = "";
let trust: ConfirmationTrust;
let proofFor: (seal: {
  handle: string;
  fingerprint: string;
  eventHash?: string;
}) => Promise<ConfirmationProof>;

// ---------------------------------------------------------------------------
// A registry tree, its key, and a witness: the proof, for real
// ---------------------------------------------------------------------------

async function fixture(): Promise<void> {
  const registry = await generateKeypair();
  const registryRaw = await exportPublicKeyRaw(registry.publicKey);
  const witness = await generateKeypair();
  const witnessRaw = await exportPublicKeyRaw(witness.publicKey);

  const hashes = [
    GOOD_EVENT_HASH,
    OTHER_EVENT_HASH,
    "3".repeat(64),
    "4".repeat(64),
  ];
  const leaves = await Promise.all(hashes.map((hash) => leafOf(hash)));
  const root = await rootOf(leaves);
  const treeSize = leaves.length;
  const createdAt = 1_789_000_000_000;

  const registrySig = base64urlEncode(
    await signBytes(
      registry.privateKey,
      registryCheckpointPayload({
        log: REGISTRY_LOG,
        tree_size: treeSize,
        root,
        created_at: createdAt,
      }),
    ),
  );
  const witnessSig = base64urlEncode(
    await signBytes(
      witness.privateKey,
      registryWitnessPayload({
        registry: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        tree_size: treeSize,
        root,
      }),
    ),
  );

  trust = {
    registry: {
      origin: REGISTRY_ORIGIN,
      log: REGISTRY_LOG,
      public_key: base64urlEncode(registryRaw),
    },
    witnesses: [
      { agent: agentIdFromPublicKey(witnessRaw), operator: "witness-a" },
    ],
    required: 1,
  };

  proofFor = async (seal) => {
    const eventHash = seal.eventHash ?? GOOD_EVENT_HASH;
    const index = hashes.indexOf(eventHash);
    const hex = seal.fingerprint.slice("sha256:".length);
    return {
      registry: REGISTRY_ORIGIN,
      log: REGISTRY_LOG,
      event_hash: eventHash,
      leaf: {
        citizen: seal.handle,
        event_id: 15_387 + index,
        kind: "memory.seal",
        detail: `label='nomankind-confirm' sha256=${hex}, signed by AAA`,
        created_at: 1_789_000_000_001,
      },
      leaf_index: index,
      proof: await pathOf(leaves, index),
      checkpoint: {
        tree_size: treeSize,
        root,
        created_at: createdAt,
        registry_sig: registrySig,
      },
      witnesses: [
        {
          agent: agentIdFromPublicKey(witnessRaw),
          signature: witnessSig,
          head: {
            tree_size: treeSize,
            root,
            created_at: createdAt,
            registry_sig: registrySig,
          },
          consistency: "verified from 3",
          consistency_proof: [],
        },
      ],
    };
  };
}

// ---------------------------------------------------------------------------
// The entry, the board and the environment
// ---------------------------------------------------------------------------

function coreFrom(): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["id"] = ENTRY_ID;
  core["author_operator"] = AUTHOR_OPERATOR;
  // Stated, and undecided: a community operator may only validate an entry
  // that is still open, so the door has something to seal.
  core["evidence_tier"] = "stated";
  return core as Core;
}

function comment(id: number, handle: string, body: string): BoardComment {
  return {
    id,
    thread: THREAD,
    handle,
    body,
    posted_at: "2026-09-16T09:00:00.000Z",
  };
}

function envOf(): Env {
  return {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
    SEALING_AGENT_KEY: sealingKey,
  } as unknown as Env;
}

const tokenLine = `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH} ${TOKEN} I fetched it and hashed it myself`;

async function board(): Promise<MockBoardAdapter> {
  const fingerprint = await confirmationFingerprint({
    entry_id: ENTRY_ID,
    verdict: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    attestation_version: ATTESTATION_VERSION,
  });

  const sealed: BoardSealProof = {
    registry_event_id: 15_387,
    proof: await proofFor({ handle: SEALED_HANDLE, fingerprint }),
  };
  // The right shape, a path that folds to nothing: refused exactly as a forgery
  // is, and the statement kept as a statement.
  const doctored: BoardSealProof = {
    registry_event_id: 15_388,
    proof: {
      ...(await proofFor({
        handle: DOCTORED_HANDLE,
        fingerprint,
        eventHash: OTHER_EVENT_HASH,
      })),
      proof: ["c".repeat(64), "d".repeat(64)],
    },
  };

  return new MockBoardAdapter({
    threads: [THREAD],
    comments: new Map([
      [
        THREAD,
        [
          comment(201, SEALED_HANDLE, tokenLine),
          comment(202, UNSEALED_HANDLE, tokenLine),
          comment(203, DOCTORED_HANDLE, tokenLine),
        ],
      ],
    ]),
    seals: new Map<string, BoardSealProof>([
      [`${SEALED_HANDLE} ${fingerprint}`, sealed],
      [`${DOCTORED_HANDLE} ${fingerprint}`, doctored],
      // The unsealed handle is absent, which is the whole of its case.
    ]),
    // Every handle's key is one the board can name, so the two refusals below
    // are about the seal and about nothing else.
    records: new Map([
      [SEALED_HANDLE, { agent: `1F916:${"a".repeat(43)}`, key_bind_event_id: 11 }],
      [UNSEALED_HANDLE, { agent: `1F916:${"b".repeat(43)}`, key_bind_event_id: 12 }],
      [DOCTORED_HANDLE, { agent: `1F916:${"c".repeat(43)}`, key_bind_event_id: 13 }],
    ]),
  });
}

async function eventsOf(type: string): Promise<Event[]> {
  return [...(await eventsOfType(db, type as Event["type"], -1, 100))];
}

describe("a token line at the community door", () => {
  beforeAll(async () => {
    await fixture();
    store = await openTestDatabase();
    db = store.db;
    sealingKey = base64urlEncode(
      await exportPrivateKeyPkcs8((await generateKeypair()).privateKey),
    );

    let events: Event[] = [];
    events = await appendEvent(events, {
      at: "2026-09-01T00:00:00.000Z",
      type: "operator_registered",
      entry_id: null,
      payload: { operator: AUTHOR_OPERATOR, maintainer: false },
    });
    events = await appendEvent(events, {
      at: "2026-09-01T00:05:00.000Z",
      type: "entry_submitted",
      entry_id: ENTRY_ID,
      payload: { core: coreFrom(), signature: SIGNATURE },
    });
    await appendEvents(db, events);

    const derived = deriveEntry(events, ENTRY_ID, { now: NOW.toISOString() });
    expect(derived.entry["status"]).toBe("draft");
    await putEntry(db, derived.entry, derived.sidecar, 1);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("registers an operator only for the line the registry sealed", async () => {
    const adapter = await board();
    const report = await runSweep(envOf(), {
      now: NOW,
      beacon: new FixtureBeacon("community"),
      board: adapter,
      confirmationTrust: trust,
    });

    // One validation, from the one handle whose seal proves.
    expect(report.community_validations).toHaveLength(1);
    expect(report.community_validations[0]).toMatchObject({
      entry_id: ENTRY_ID,
      venue: VENUE,
      handle: SEALED_HANDLE,
      operator: communityOperatorId(VENUE, SEALED_HANDLE),
      comment_id: 201,
      verdict: "approve",
      registered: true,
    });

    // And in the log: one registration, for that operator and nobody else.
    const registrations = await eventsOf("community_operator_registered");
    expect(
      registrations.map(
        (event) => (event.payload as { operator: string }).operator,
      ),
    ).toEqual([communityOperatorId(VENUE, SEALED_HANDLE)]);
    const validations = await eventsOf("community_validation");
    expect(validations).toHaveLength(1);
    expect(validations[0]!.entry_id).toBe(ENTRY_ID);

    // The other two said exactly the same words and are exactly what D-136
    // made them: statements, sealed, counted by nothing.
    const confirmations = await eventsOf("public_confirmation");
    const said = confirmations.map((event) => {
      const payload = event.payload as { handle: string; counted: boolean };
      return [payload.handle, payload.counted];
    });
    expect(said.sort()).toEqual(
      [
        [UNSEALED_HANDLE, false],
        [DOCTORED_HANDLE, false],
      ].sort(),
    );
    // Neither of them registered anybody, which is the point: a door that read
    // the token before the seal would have made an operator out of a comment.
    for (const handle of [UNSEALED_HANDLE, DOCTORED_HANDLE]) {
      expect(
        registrations.some(
          (event) =>
            (event.payload as { handle: string }).handle === handle,
        ),
      ).toBe(false);
      expect(
        validations.some(
          (event) => (event.payload as { handle: string }).handle === handle,
        ),
      ).toBe(false);
    }

    // The doctored proof is refused by name, and the unsealed line is counted
    // as what it is.
    expect(report.skipped["confirmation_proof_invalid"]).toBe(1);
    expect(report.skipped["confirmation_unsealed"]).toBe(2);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The record a counted token line makes (decision D-138)
// ---------------------------------------------------------------------------

/**
 * The same door, followed past the seal.
 *
 * Its own world and its own database: ten trusted operators, so three approvals
 * verify and one of them has to be the beacon's; one entry two of them have
 * already approved, and one entry only one of them has. What a token line does
 * to each is the whole of D-138 — a third approval on the first, a second on
 * the second, and neither of them a confirmation.
 */
describe("a community operator's first line", () => {
  const ENTRY_A = `nmk_${"a1".repeat(16)}`;
  const ENTRY_B = `nmk_${"b2".repeat(16)}`;
  const SUBJECT_A = example["subject"] as string;
  const SUBJECT_B = "openai/gpt-4o";
  const CATEGORY = example["category"] as string;

  /** Ten trusted operators: the large pool, where three approvals verify. */
  const POOL = Array.from({ length: 10 }, (_, index) => `op_v${index + 1}`);
  const PERIMETER = "nomankind";

  /** The citizen whose token-carrying lines are validations. */
  const HANDLE = "morty-synctzn";
  /** The citizen whose key the log already knows as the entry's author's. */
  const AUTHOR_HANDLE = "brightloop-dev";
  /** The citizen who says the line and seals nothing. */
  const SILENT_HANDLE = "silent-citizen";
  const COMMUNITY_OPERATOR = communityOperatorId(VENUE, HANDLE);
  const AUTHOR_AGENT = "1F916:agent-op_brightloop";
  const MAINTAINER_OPERATOR = "op_maintainer";

  let cStore: TestDatabase;
  let cDb: D1Like;
  let cSealingKey = "";
  let cTrust: ConfirmationTrust;
  let cProofFor: (seal: {
    handle: string;
    fingerprint: string;
  }) => Promise<ConfirmationProof>;
  let mirror: MockMirrorAdapter;
  let witness: FakeWitness;
  let report: Awaited<ReturnType<typeof runSweep>>;

  function envOfCommunity(): Env {
    return {
      DB: cDb,
      CAPTURES: cStore.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
      SEALING_AGENT_KEY: cSealingKey,
    } as unknown as Env;
  }

  /** A core off the example, observed as it is, with these fields replaced. */
  function coreOf(overrides: Record<string, unknown>): Core {
    const core: Record<string, unknown> = {};
    for (const key of CORE_KEYS) core[key] = example[key];
    return { ...core, ...overrides } as Core;
  }

  function approval(
    operator: string,
    signedAt: string,
    assignedRandom = false,
  ): ApproverRecord {
    return {
      agent: `1F916:agent-${operator}`,
      operator,
      decision: "approve",
      reason: null,
      snapshot_hash: SNAPSHOT_HASH,
      assigned_random: assignedRandom,
      test_accepted: true,
      reproduction: null,
      observation: {
        method: "endpoint_error",
        receipt_hash: `sha256:${"a".repeat(64)}`,
        observed_at: "2026-09-01",
        runs: 10,
        holds: 10,
      },
      signed_at: signedAt,
    } as unknown as ApproverRecord;
  }

  /** The world, chained by `appendEvent` exactly as a door chains it. */
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
          Date.parse("2026-09-01T00:00:00Z") + tick * 60_000,
        ).toISOString(),
        type,
        entry_id: entryId,
        payload,
      });
    };

    await add("operator_registered", null, {
      operator: MAINTAINER_OPERATOR,
      maintainer: true,
    });
    await add("agent_bound", null, {
      operator: MAINTAINER_OPERATOR,
      agent: `1F916:agent-${MAINTAINER_OPERATOR}`,
      attestation: {} as never,
    });
    // The author, and the key the log answers for it — which is what makes a
    // line from that key the author judging its own entry, however it signs.
    await add("operator_registered", null, {
      operator: AUTHOR_OPERATOR,
      maintainer: false,
    });
    await add("agent_bound", null, {
      operator: AUTHOR_OPERATOR,
      agent: AUTHOR_AGENT,
      attestation: {} as never,
    });

    for (const operator of POOL) {
      await add("operator_registered", null, { operator, maintainer: false });
      await add("agent_bound", null, {
        operator,
        agent: `1F916:agent-${operator}`,
        attestation: {} as never,
      });
      await add("operator_trusted", null, { operator, perimeter: PERIMETER });
    }

    await add("entry_submitted", ENTRY_A, {
      core: coreOf({ id: ENTRY_A }),
      signature: SIGNATURE,
    });
    // One beacon-drawn approval and one volunteered: the large pool asks for a
    // third approval and for a drawn one, and this world has the drawn one.
    await add("validation", ENTRY_A, {
      record: approval(POOL[0]!, "2026-09-02T01:00:00Z", true),
      signature: SIGNATURE,
    });
    await add("validation", ENTRY_A, {
      record: approval(POOL[1]!, "2026-09-02T02:00:00Z"),
      signature: SIGNATURE,
    });

    await add("entry_submitted", ENTRY_B, {
      core: coreOf({ id: ENTRY_B, subject: SUBJECT_B }),
      signature: SIGNATURE,
    });
    await add("validation", ENTRY_B, {
      record: approval(POOL[0]!, "2026-09-02T03:00:00Z", true),
      signature: SIGNATURE,
    });

    return events;
  }

  /** A registry tree of its own, with its own key and its own witness. */
  async function communityFixture(): Promise<void> {
    const registry = await generateKeypair();
    const registryRaw = await exportPublicKeyRaw(registry.publicKey);
    const attestor = await generateKeypair();
    const attestorRaw = await exportPublicKeyRaw(attestor.publicKey);

    const hashes = ["1", "2", "3", "4"].map((one) => one.repeat(64));
    const leaves = await Promise.all(hashes.map((hash) => leafOf(hash)));
    const root = await rootOf(leaves);
    const treeSize = leaves.length;
    const createdAt = 1_789_000_000_000;

    const registrySig = base64urlEncode(
      await signBytes(
        registry.privateKey,
        registryCheckpointPayload({
          log: REGISTRY_LOG,
          tree_size: treeSize,
          root,
          created_at: createdAt,
        }),
      ),
    );
    const witnessSig = base64urlEncode(
      await signBytes(
        attestor.privateKey,
        registryWitnessPayload({
          registry: REGISTRY_ORIGIN,
          log: REGISTRY_LOG,
          tree_size: treeSize,
          root,
        }),
      ),
    );

    cTrust = {
      registry: {
        origin: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        public_key: base64urlEncode(registryRaw),
      },
      witnesses: [
        { agent: agentIdFromPublicKey(attestorRaw), operator: "witness-a" },
      ],
      required: 1,
    };

    cProofFor = async (seal) => {
      const index = hashes.indexOf(GOOD_EVENT_HASH);
      const hex = seal.fingerprint.slice("sha256:".length);
      return {
        registry: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        event_hash: GOOD_EVENT_HASH,
        leaf: {
          citizen: seal.handle,
          event_id: 15_387,
          kind: "memory.seal",
          detail: `label='nomankind-confirm' sha256=${hex}, signed by AAA`,
          created_at: 1_789_000_000_001,
        },
        leaf_index: index,
        proof: await pathOf(leaves, index),
        checkpoint: {
          tree_size: treeSize,
          root,
          created_at: createdAt,
          registry_sig: registrySig,
        },
        witnesses: [
          {
            agent: agentIdFromPublicKey(attestorRaw),
            signature: witnessSig,
            head: {
              tree_size: treeSize,
              root,
              created_at: createdAt,
              registry_sig: registrySig,
            },
            consistency: "verified from 3",
            consistency_proof: [],
          },
        ],
      };
    };
  }

  /** One line of the published form, carrying the token. */
  function lineFor(entryId: string, reason = ""): string {
    const rest = reason === "" ? "" : ` ${reason}`;
    return `${CONFIRMATION_FORM_PREFIX} ${entryId} approve ${SNAPSHOT_HASH} ${TOKEN}${rest}`;
  }

  /** The claim a line makes, in the shape the fingerprint is taken over. */
  function claim(entryId: string) {
    return {
      entry_id: entryId,
      verdict: "approve" as const,
      check: { kind: "hash" as const, value: SNAPSHOT_HASH },
      attestation_version: ATTESTATION_VERSION,
    };
  }

  /**
   * Five comments, in the order the door takes them: the line that registers
   * an operator and promotes an entry, the author's own line, a second entry's
   * line from the same account, that account saying it twice, and a line
   * nobody sealed.
   */
  async function communityBoard(): Promise<MockBoardAdapter> {
    const printA = await confirmationFingerprint(claim(ENTRY_A));
    const printB = await confirmationFingerprint(claim(ENTRY_B));

    const sealOf = async (
      handle: string,
      fingerprint: string,
    ): Promise<BoardSealProof> => ({
      registry_event_id: 15_387,
      proof: await cProofFor({ handle, fingerprint }),
    });

    const seals = new Map<string, BoardSealProof>([
      [`${HANDLE} ${printA}`, await sealOf(HANDLE, printA)],
      [`${HANDLE} ${printB}`, await sealOf(HANDLE, printB)],
      [`${AUTHOR_HANDLE} ${printA}`, await sealOf(AUTHOR_HANDLE, printA)],
    ]);

    // Which key the founding registry binds to each handle: what a `registry`
    // binding names, and what makes the author's own line the author's.
    const records = new Map<string, BoardRecord>([
      [HANDLE, { agent: "1F916:morty-key", key_bind_event_id: 4_211 }],
      [AUTHOR_HANDLE, { agent: AUTHOR_AGENT, key_bind_event_id: 4_212 }],
      [SILENT_HANDLE, { agent: "1F916:silent-key", key_bind_event_id: 4_213 }],
    ]);

    return new MockBoardAdapter({
      threads: [THREAD],
      comments: new Map([
        [
          THREAD,
          [
            comment(101, HANDLE, lineFor(ENTRY_A, "I refetched and rehashed it.")),
            comment(102, AUTHOR_HANDLE, lineFor(ENTRY_A)),
            comment(103, HANDLE, lineFor(ENTRY_B)),
            comment(104, HANDLE, lineFor(ENTRY_B, "saying it twice")),
            comment(105, SILENT_HANDLE, lineFor(ENTRY_B)),
          ],
        ],
      ]),
      seals,
      records,
    });
  }

  async function sealedOf(type: EventType): Promise<Event[]> {
    return [...(await eventsOfType(cDb, type, -1, 100))];
  }

  beforeAll(async () => {
    await communityFixture();
    cStore = await openTestDatabase();
    cDb = cStore.db;
    mirror = new MockMirrorAdapter();
    cSealingKey = base64urlEncode(
      await exportPrivateKeyPkcs8((await generateKeypair()).privateKey),
    );

    const events = await buildEvents();
    await appendEvents(cDb, events);
    // The rows the registration door would have written for the domain
    // operators, so the registry table says what the events say.
    const domainOperators = [MAINTAINER_OPERATOR, AUTHOR_OPERATOR, ...POOL];
    for (const [index, operator] of domainOperators.entries()) {
      await putOperator(cDb, {
        id: operator,
        kind: "domain",
        maintainer: operator === MAINTAINER_OPERATOR,
        provider: false,
        registeredSeq: index,
        details: { trusted: POOL.includes(operator) },
      });
      await putAgent(cDb, {
        agentId:
          operator === AUTHOR_OPERATOR
            ? AUTHOR_AGENT
            : `1F916:agent-${operator}`,
        operatorId: operator,
        registeredSeq: index,
      });
      await putOperatorDomain(cDb, {
        operator,
        domain: DEFAULT_DOMAIN,
        seq: index,
        attestation: null,
      });
    }

    for (const id of [ENTRY_A, ENTRY_B]) {
      const submitted = events.find(
        (event) => event.type === "entry_submitted" && event.entry_id === id,
      )!;
      const derived = deriveEntry(events, id, { now: NOW.toISOString() });
      // Both are drafts: ten trusted operators means three approvals verify,
      // and neither entry has three.
      expect(derived.entry["status"]).toBe("draft");
      await putEntry(cDb, derived.entry, derived.sidecar, submitted.seq);
    }

    witness = await makeWitness("witness-a");
    report = await runSweep(envOfCommunity(), {
      now: NOW,
      beacon: new FixtureBeacon("community"),
      board: await communityBoard(),
      confirmationTrust: cTrust,
      mirror,
      // The seal is what the delta stream is bounded by and what the mirror
      // exports, so this run seals: the witness and the anchor are the fakes
      // every sealing test uses.
      witness: new FakeWitnessAdapter({ signers: [witness] }),
      pinned: pinnedSet([witness]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
    });
  }, 600_000);

  afterAll(async () => {
    await cStore?.dispose();
  });

  it("registers the operator and seals the validation, once", async () => {
    const registered = await sealedOf("community_operator_registered");
    expect(registered).toHaveLength(1);
    const payload = registered[0]!.payload as unknown as Record<string, unknown>;
    expect(payload["operator"]).toBe(COMMUNITY_OPERATOR);
    expect(payload["venue"]).toBe(VENUE);
    expect(payload["handle"]).toBe(HANDLE);
    expect(payload["agent"]).toBe("1F916:morty-key");
    expect(payload["binding"]).toEqual({
      kind: "registry",
      registry: VENUE,
      key_bind_event_id: 4_211,
    });
    expect(payload["attestation"]).toEqual({
      version: ATTESTATION_VERSION,
      domain: DEFAULT_DOMAIN,
    });

    // Two lines from the one account counted: one per entry. The second entry
    // is the same domain, so no join was owed and none was sealed.
    const validations = await sealedOf("community_validation");
    expect(validations.map((event) => event.entry_id)).toEqual([
      ENTRY_A,
      ENTRY_B,
    ]);
    expect(await sealedOf("community_operator_joined_domain")).toEqual([]);

    const first = validations[0]!.payload as unknown as Record<string, unknown>;
    expect(first["decision"]).toBe("approve");
    expect(first["attestation_version"]).toBe(ATTESTATION_VERSION);
    expect(first["comment_id"]).toBe(101);
    expect((first["binding_proof"] as Record<string, unknown>)["kind"]).toBe(
      "registry",
    );

    expect(report.community_validations).toHaveLength(2);
    expect(report.community_validations[0]).toMatchObject({
      entry_id: ENTRY_A,
      operator: COMMUNITY_OPERATOR,
      venue: VENUE,
      handle: HANDLE,
      comment_id: 101,
      registered: true,
      joined: false,
    });
    expect(report.community_validations[1]).toMatchObject({
      entry_id: ENTRY_B,
      registered: false,
      joined: false,
    });
  }, 600_000);

  it("promotes the entry, and says who met its consensus", async () => {
    const stored = (await getEntry(cDb, ENTRY_A))!;
    expect(stored.entry["status"]).toBe("verified");
    // Two domain operators and one community one: the domain operators took
    // part, and the community one was needed to reach it.
    expect(stored.sidecar.verification_class).toBe("mixed");
    expect(stored.sidecar.verification_communities).toEqual([VENUE]);
    // And the label that says the decision was made inside the maintainer's
    // own perimeter is gone, because it was not.
    expect(stored.sidecar.bootstrap).toBeNull();

    // The second entry is one approval short and is still a draft: a community
    // validation counts, and counting is not promoting.
    const draft = (await getEntry(cDb, ENTRY_B))!;
    expect(draft.entry["status"]).toBe("draft");
    expect(draft.sidecar.verification_class).toBeNull();
  }, 600_000);

  it("writes the registry rows the events imply", async () => {
    const record = (await getOperator(cDb, COMMUNITY_OPERATOR))!;
    expect(record.kind).toBe("community");
    expect(record.maintainer).toBe(false);
    expect(record.provider).toBe(false);
    expect(record.details["venue"]).toBe(VENUE);
    expect(record.details["handle"]).toBe(HANDLE);
    expect(record.details["trusted"]).toBe(false);
    // Nothing about a community operator is paid: D-127 left no money here.
    expect(record.details["payout"]).toBeUndefined();

    expect(
      (await operatorDomains(cDb, COMMUNITY_OPERATOR)).map((row) => row.domain),
    ).toEqual([DEFAULT_DOMAIN]);

    // Every domain operator beside it still reads as one.
    const all = await listOperators(cDb, { limit: 100 });
    const kinds = new Map(all.map((one) => [one.id, one.kind]));
    expect(kinds.get(COMMUNITY_OPERATOR)).toBe("community");
    expect(kinds.get(POOL[0]!)).toBe("domain");
  }, 600_000);

  it("seals the lines that are not validations as confirmations, and says why", async () => {
    const confirmations = await sealedOf("public_confirmation");
    const byComment = new Map(
      confirmations.map((event) => [
        (event.payload as unknown as Record<string, unknown>)["comment_id"],
        event.payload as unknown as Record<string, unknown>,
      ]),
    );
    // The author's own line, the same account saying it twice, and a line
    // nobody sealed: three confirmations, and no validation among them.
    expect([...byComment.keys()].sort()).toEqual([102, 104, 105]);

    // The author's line and the repeat were sealed by their own keys, so they
    // count as confirmations — they clear a label and promote nothing.
    expect(byComment.get(102)!["counted"]).toBe(true);
    expect(byComment.get(104)!["counted"]).toBe(true);
    // The unsealed one is an account statement, token or no token.
    expect(byComment.get(105)!["counted"]).toBe(false);
    expect(byComment.get(105)!["registry_proof"]).toBeNull();

    // And the run says which rule sent each of them back.
    expect(report.confirmation_fallbacks["own_entry"]).toBe(1);
    expect(report.confirmation_fallbacks["already_validated"]).toBe(1);
  }, 600_000);

  it("seals nothing twice on a second run over the same thread", async () => {
    const before = (await sealedOf("community_validation")).length;
    const again = await runSweep(envOfCommunity(), {
      now: new Date(NOW.getTime() + 300_000),
      beacon: new FixtureBeacon("community"),
      board: await communityBoard(),
      confirmationTrust: cTrust,
    });
    expect(again.community_validations).toEqual([]);
    expect(again.confirmations).toEqual([]);
    expect((await sealedOf("community_validation")).length).toBe(before);
    expect(
      (await sealedOf("community_operator_registered")).length,
    ).toBe(1);
  }, 600_000);

  it("answers the community operator on its own registry route", async () => {
    const response = await handleRegistry(
      new Request(
        `https://app.nomankind.ai/operators/${encodeURIComponent(
          COMMUNITY_OPERATOR,
        )}`,
      ),
      envOfCommunity(),
      { now: NOW, dns: new FixtureResolver({}) },
    );
    expect(response!.status).toBe(200);
    const body = (await response!.json()) as Record<string, unknown>;
    expect(body["id"]).toBe(COMMUNITY_OPERATOR);
    expect(body["kind"]).toBe("community");
    expect(body["domains"]).toEqual([DEFAULT_DOMAIN]);
    expect(body["agents"]).toEqual(["1F916:morty-key"]);
    const details = body["details"] as Record<string, unknown>;
    expect(details["venue"]).toBe(VENUE);
    expect(details["handle"]).toBe(HANDLE);
    expect((details["binding"] as Record<string, unknown>)["kind"]).toBe(
      "registry",
    );
  }, 600_000);

  it("goes on refusing a colon-bearing id at the registration door", async () => {
    // The id a community operator has is the id no door may be talked into
    // registering: one registry, two kinds, and only one of them has a door.
    expect(isOperatorDomain(COMMUNITY_OPERATOR)).toBe(false);
    expect(isCommunityOperatorId(COMMUNITY_OPERATOR)).toBe(true);
    expect(parseCommunityOperatorId(COMMUNITY_OPERATOR)).toEqual({
      venue: VENUE,
      handle: HANDLE,
    });

    const agent = await makeAgent();
    const request = await signedPost(agent, {
      path: "/operators",
      body: { operator: COMMUNITY_OPERATOR, attestation: null },
      timestamp: NOW.toISOString(),
    });
    const response = await handleRegistry(request, envOfCommunity(), {
      now: NOW,
      dns: new FixtureResolver({}),
    });
    expect(response!.status).toBeGreaterThanOrEqual(400);
    expect((await response!.json()) as Record<string, unknown>).toMatchObject({
      error: "bad_domain",
    });

    // And the rule the door asks, asked directly.
    expect(
      await checkRegistration({
        operator: COMMUNITY_OPERATOR,
        agent: agent.agentId,
        domain: null,
        attestation: null,
        maintainerAgentId: null,
        operatorExists: false,
        agentOperator: null,
        now: NOW,
      }),
    ).toEqual({ ok: false, reason: "bad_domain" });
  }, 600_000);

  it("honours min_class on the read door", async () => {
    const read = async (minClass: string): Promise<Response> => {
      const url =
        `https://app.nomankind.ai/read?subject=${encodeURIComponent(SUBJECT_A)}` +
        `&category=${encodeURIComponent(CATEGORY)}&min_class=${minClass}`;
      return (await handleRead(new Request(url), envOfCommunity(), {
        now: NOW,
      }))!;
    };

    // A reader that will only learn from an entry domain operators met by
    // themselves is not handed this one.
    expect((await read("registered")).status).toBe(404);
    // A reader that accepts a mixed consensus, or any consensus at all, is.
    for (const demand of ["mixed", "community"]) {
      const response = await read(demand);
      expect(response.status).toBe(200);
      const body = (await response.json()) as Record<string, unknown>;
      expect((body["entry"] as Record<string, unknown>)["id"]).toBe(ENTRY_A);
    }

    // A class nobody published is a refusal in the kernel's own word.
    const bad = await read("gold");
    expect(bad.status).toBe(400);
    expect((await bad.json()) as Record<string, unknown>).toMatchObject({
      error: "bad_min_class",
    });
  }, 600_000);

  it("honours min_class on the delta stream", async () => {
    const entriesOf = async (query: string): Promise<string[]> => {
      const response = (await handleSync(
        new Request(`https://app.nomankind.ai/sync?from=0&limit=100${query}`),
        envOfCommunity(),
        { now: NOW },
      ))!;
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        events: { kind: string; entry: Record<string, unknown> | null }[];
      };
      return body.events
        .filter((item) => item.kind === "entry" && item.entry !== null)
        .map((item) => item.entry!["id"] as string);
    };

    // The seal this run made is what the stream is bounded by; without it
    // there is nothing to filter.
    expect(report.sealed).not.toBeNull();

    expect(await entriesOf("&min_class=registered")).not.toContain(ENTRY_A);
    expect(await entriesOf("&min_class=mixed")).toContain(ENTRY_A);
    expect(await entriesOf("&min_class=community")).toContain(ENTRY_A);

    const refused = (await handleSync(
      new Request("https://app.nomankind.ai/sync?from=0&min_class=gold"),
      envOfCommunity(),
      { now: NOW },
    ))!;
    expect(refused.status).toBe(400);
    expect((await refused.json()) as Record<string, unknown>).toMatchObject({
      error: "bad_min_class",
    });
  }, 600_000);

  it("carries the kind and the binding into the mirror", async () => {
    const written = mirror.files.get("local/operators.json");
    expect(written).toBeDefined();
    const operators = (
      JSON.parse(written!) as { operators: Record<string, unknown>[] }
    ).operators;

    const community = operators.find(
      (one) => one["operator"] === COMMUNITY_OPERATOR,
    )!;
    expect(community["kind"]).toBe("community");
    expect(community["binding"]).toEqual({
      kind: "registry",
      registry: VENUE,
      key_bind_event_id: 4_211,
    });
    expect(community["trusted"]).toBe(false);

    // And every operator that came in by the other path says so too, without
    // a binding of its own.
    const domain = operators.find((one) => one["operator"] === POOL[0]!)!;
    expect(domain["kind"]).toBe("domain");
    expect(domain["binding"]).toBeUndefined();
  }, 600_000);

  it("replays into the same registry rows the log implies", async () => {
    // What `npm run import-mirror` does with the file above: fold the registry
    // out of the sealed events and hold it against `operators.json`. A fold
    // that did not know the community events would disagree with the file, and
    // disagreeing is the one thing a mirror may never do with itself.
    const file = (
      JSON.parse(mirror.files.get("local/operators.json")!) as {
        operators: MirrorOperator[];
      }
    ).operators;
    const sealed = await eventsAfter(cDb, -1, 500);
    const rows = operatorRows(sealed, file, report.sealed!.last_seq);

    const community = rows.find((one) => one.record.id === COMMUNITY_OPERATOR)!;
    expect(community.record.kind).toBe("community");
    expect(community.record.details["handle"]).toBe(HANDLE);
    expect(community.agents.map((one) => one.agentId)).toEqual([
      "1F916:morty-key",
    ]);
    expect(community.domains.map((one) => one.domain)).toEqual([
      DEFAULT_DOMAIN,
    ]);
    expect(rows.find((one) => one.record.id === POOL[0]!)!.record.kind).toBe(
      "domain",
    );
  }, 600_000);
});

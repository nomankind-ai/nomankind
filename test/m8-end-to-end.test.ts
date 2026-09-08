/**
 * The M8 surface as an application composes it: the Merkle batch
 * (src/merkle.ts), the seal chain (src/seal.ts), the witness rule
 * (src/witness.ts) and the daily anchor (src/anchor.ts), over the M3 log, with
 * derivation writing the seal object onto the entry it belongs to. Everything
 * below is imported from the package entry point, so a missing re-export fails
 * here rather than in a later milestone.
 *
 * The story is Section 6's: two entries are submitted, one of them is decided
 * on by the trusted pool and one is left a draft, the whole run is sealed, the
 * seal hash is countersigned by three witnesses under three operators while
 * nomankind's own key is turned away, a second batch chains onto the first, and
 * the day's roots are anchored. Then one earlier event is edited and rehashed —
 * the tamper that leaves the hash chain self-consistent — and the seal and the
 * inclusion proof are what catch it.
 *
 * The clock is injected and fake; nothing here reads a wall clock.
 */

import { describe, expect, it } from "vitest";

import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  TRUSTED_POOL_SWITCH,
  agentIdFromPublicKey,
  appendEvent,
  buildAnchor,
  buildSeal,
  checkWitnesses,
  decodeProof,
  deriveAll,
  eventHash,
  exportPublicKeyRaw,
  generateKeypair,
  merkleRoot,
  sealsForEntries,
  signWitness,
  utcDay,
  validateEntry,
  verifyAnchor,
  verifyChain,
  verifyInclusion,
  verifySeal,
  type ApproverRecord,
  type Clock,
  type Core,
  type Event,
  type Seal,
  type Witness,
  type WitnessContext,
  type WitnessSignature,
} from "../src/index.js";

const SUBMITTER_AGENT = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const SUBMITTER_OPERATOR = "op_brightloop";

const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const HASH =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";

/** The large pool: exactly the switch, so three approvals verify. */
const POOL: readonly string[] = Array.from(
  { length: TRUSTED_POOL_SWITCH },
  (_, index) => `op_pool${index + 1}`,
);

const DRAFT_ID = "nmk_01M8DRAFT";
const DECIDED_ID = "nmk_01M8DECIDED";

const SUBMITTED_AT = "2026-09-01T14:05:00Z";

/** Both seals fall on one UTC day, which is the day the anchor covers. */
const ANCHOR_DAY = "2026-09-07";
const FIRST_CLOCK: Clock = { now: "2026-09-07T00:05:00Z" };
const SECOND_CLOCK: Clock = { now: "2026-09-07T12:35:00Z" };
/** The derivation clock: inside the pricing window, so nothing here is stale. */
const DERIVE_CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/** The maintainer's own operator: ineligible to countersign its own seal. */
const MAINTAINER_OPERATOR = "nomankind";

function agentFor(operator: string): string {
  return `1F916:agent-${operator}`;
}

/** Sequential event timestamps, from the same fake clock. */
function at(seq: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + seq * 60_000,
  ).toISOString();
}

function signedAt(index: number): string {
  return `2026-09-02T${String(index).padStart(2, "0")}:00:00Z`;
}

function append(
  events: readonly Event[],
  type: Parameters<typeof appendEvent>[1]["type"],
  entryId: string | null,
  payload: Parameters<typeof appendEvent>[1]["payload"],
): Promise<Event[]> {
  return appendEvent(events, {
    at: at(events.length),
    type,
    entry_id: entryId,
    payload,
  });
}

/** The seventeen core keys, in the schema's own names. */
function core(overrides: Record<string, unknown>): Core {
  return {
    id: DRAFT_ID,
    subject: "openai/gpt-5",
    category: "pricing",
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-08-15",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://platform.openai.com/docs/pricing",
    snapshot_hash: HASH,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: SUBMITTER_AGENT,
    author_operator: SUBMITTER_OPERATOR,
    submitted_at: SUBMITTED_AT,
    ...overrides,
  } as Core;
}

/** Submitted and never decided on: Section 6 seals drafts like everything else. */
const DRAFT_CORE = core({});

/** The entry the pool decides on. */
const DECIDED_CORE = core({
  id: DECIDED_ID,
  subject: "anthropic/claude-4",
  claim: "claude-4 input price is $3.00 per million tokens",
  before: "$4.00 per million input tokens",
  after: "$3.00 per million input tokens",
});

function submitEntry(
  events: readonly Event[],
  submitted: Core,
): Promise<Event[]> {
  return append(events, "entry_submitted", submitted["id"] as string, {
    core: submitted,
    signature: SIGNATURE,
  });
}

function approvalFor(operator: string, index: number): ApproverRecord {
  return {
    agent: agentFor(operator),
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: index === 0,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt(index + 1),
  } as unknown as ApproverRecord;
}

/** The submitter's operator plus the ten trusted pool operators. */
async function registry(): Promise<Event[]> {
  let events: Event[] = [];
  for (const operator of [SUBMITTER_OPERATOR, ...POOL]) {
    events = await append(events, "operator_registered", null, {
      operator,
      maintainer: false,
    });
  }
  for (const operator of POOL) {
    events = await append(events, "operator_trusted", null, { operator });
  }
  return events;
}

/**
 * The first batch: the registry, both submissions, and the three approvals that
 * decide the second entry.
 */
async function firstBatch(): Promise<Event[]> {
  let events = await submitEntry(await registry(), DRAFT_CORE);
  events = await submitEntry(events, DECIDED_CORE);
  for (let index = 0; index < APPROVALS_TO_VERIFY_LARGE_POOL; index += 1) {
    events = await append(events, "validation", DECIDED_ID, {
      record: approvalFor(POOL[index]!, index),
      signature: SIGNATURE,
    });
  }
  return events;
}

/** Two more events after the first seal closed, for the second batch. */
async function secondBatch(events: readonly Event[]): Promise<Event[]> {
  let current = await append(events, "operator_registered", null, {
    operator: "op_latecomer",
    maintainer: false,
  });
  return append(current, "operator_trusted", null, { operator: "op_latecomer" });
}

/** buildSeal, unwrapped: a refusal here means the fixture is wrong. */
async function seal(
  events: readonly Event[],
  previous: Seal | null,
  clock: Clock,
): Promise<Seal> {
  const result = await buildSeal(events, previous, clock);
  if (!result.ok) throw new Error(`buildSeal refused: ${result.reason}`);
  return result.seal;
}

interface Party {
  agent: string;
  operator: string;
  privateKey: CryptoKey;
}

async function makeParty(operator: string): Promise<Party> {
  const keypair = await generateKeypair();
  const raw = await exportPublicKeyRaw(keypair.publicKey);
  return {
    agent: agentIdFromPublicKey(raw),
    operator,
    privateKey: keypair.privateKey,
  };
}

function pin(...parties: Party[]): Witness[] {
  return parties.map(({ agent, operator }) => ({ agent, operator }));
}

function witnessContext(witnesses: readonly Witness[]): WitnessContext {
  return {
    witnesses,
    maintainerOperators: new Set([MAINTAINER_OPERATOR]),
  };
}

async function countersign(
  party: Party,
  sealHashValue: string,
): Promise<WitnessSignature> {
  return {
    agent: party.agent,
    signature: await signWitness(party.privateKey, sealHashValue),
  };
}

/** The submission event of one entry, which is what its seal proves. */
function submissionOf(events: readonly Event[], entryId: string): Event {
  return events.find(
    (event) => event.type === "entry_submitted" && event.entry_id === entryId,
  )!;
}

/** The whole M8 stage: two seals over one day, and the entries they cover. */
async function stage(): Promise<{
  events: Event[];
  grown: Event[];
  first: Seal;
  second: Seal;
}> {
  const events = await firstBatch();
  const first = await seal(events, null, FIRST_CLOCK);
  const grown = await secondBatch(events);
  const second = await seal(grown, first, SECOND_CLOCK);
  return { events, grown, first, second };
}

describe("M8 end to end: seal, inclusion, witnesses and the day's anchor", () => {
  it("seals the whole run of a log with two entries and a decision", async () => {
    const { events, first } = await stage();

    // Both entries are in the log, and the pool decided on one of them.
    const derived = deriveAll(events, DERIVE_CLOCK);
    expect([...derived.keys()].sort()).toEqual([DECIDED_ID, DRAFT_ID].sort());
    expect(derived.get(DECIDED_ID)!.derived.status).toBe("verified");
    expect(derived.get(DRAFT_ID)!.derived.status).toBe("draft");

    // One seal over the whole run, from seq 0, chained to nothing.
    expect(first.seq).toBe(0);
    expect(first.first_seq).toBe(0);
    expect(first.last_seq).toBe(events.length - 1);
    expect(first.size).toBe(events.length);
    expect(first.prev_hash).toBeNull();
    expect(first.sealed_at).toBe(FIRST_CLOCK.now);
    expect(await verifySeal(events, first, null)).toBe(true);
  });

  it("gives both entries a seal and writes the draft's onto the derived entry", async () => {
    const { events, first } = await stage();

    const seals = await sealsForEntries(events, [first]);
    expect([...seals.keys()].sort()).toEqual([DECIDED_ID, DRAFT_ID].sort());

    const derived = deriveAll(events, DERIVE_CLOCK, seals);
    const entry = derived.get(DRAFT_ID)!.entry;
    const written = entry["seal"] as {
      log: string;
      position: number;
      inclusion_proof: string;
      sealed_at: string;
      witnesses: string[];
    };

    expect(written.log).toBe("1F916");
    expect(written.sealed_at).toBe(first.sealed_at);
    expect(written.witnesses).toEqual([]);

    // position is the submission event's own monotonic seq.
    const submission = submissionOf(events, DRAFT_ID);
    expect(written.position).toBe(submission.seq);

    // And the carried proof decodes and verifies offline against the root.
    const proof = decodeProof(written.inclusion_proof);
    expect(proof).not.toBeNull();
    expect(proof!.size).toBe(first.size);
    expect(proof!.index).toBe(submission.seq - first.first_seq);
    expect(await verifyInclusion(submission.hash, proof!, first.root)).toBe(true);

    // The sealed entry is still exactly the schema's entry.
    const result = validateEntry(entry);
    expect(result.ok ? [] : result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("accepts three witnesses under three operators and turns nomankind away", async () => {
    const { first } = await stage();

    const alpha = await makeParty("op_witness_alpha");
    const beta = await makeParty("op_witness_beta");
    const gamma = await makeParty("op_witness_gamma");
    const maintainer = await makeParty(MAINTAINER_OPERATOR);

    const signatures = [
      await countersign(alpha, first.hash),
      await countersign(beta, first.hash),
      await countersign(gamma, first.hash),
    ];

    expect(
      await checkWitnesses(
        first.hash,
        signatures,
        witnessContext(pin(alpha, beta, gamma, maintainer)),
      ),
    ).toEqual({
      ok: true,
      witnesses: [
        { agent: alpha.agent, operator: "op_witness_alpha" },
        { agent: beta.agent, operator: "op_witness_beta" },
        { agent: gamma.agent, operator: "op_witness_gamma" },
      ],
    });

    // A fourth, valid signature under the maintainer's own operator: refused
    // however good the bytes are.
    expect(
      await checkWitnesses(
        first.hash,
        [...signatures, await countersign(maintainer, first.hash)],
        witnessContext(pin(alpha, beta, gamma, maintainer)),
      ),
    ).toEqual({
      ok: false,
      reason: "maintainer_witness",
      agent: maintainer.agent,
    });
  });

  it("chains the second seal onto the first and anchors the day's roots", async () => {
    const { events, grown, first, second } = await stage();

    expect(second.seq).toBe(1);
    expect(second.first_seq).toBe(first.last_seq + 1);
    expect(second.last_seq).toBe(grown.length - 1);
    expect(second.size).toBe(grown.length - events.length);
    expect(second.prev_hash).toBe(first.hash);
    expect(await verifySeal(grown, second, first)).toBe(true);

    // Both seals fall on one UTC day, and the anchor carries their roots in
    // seal order.
    expect(utcDay(first.sealed_at)).toBe(ANCHOR_DAY);
    expect(utcDay(second.sealed_at)).toBe(ANCHOR_DAY);

    const anchored = await buildAnchor([first, second], ANCHOR_DAY);
    expect(anchored.ok).toBe(true);
    if (!anchored.ok) throw new Error(`buildAnchor refused: ${anchored.reason}`);

    expect(anchored.anchor.roots).toEqual([first.root, second.root]);
    expect(anchored.anchor.first_seal_seq).toBe(first.seq);
    expect(anchored.anchor.last_seal_seq).toBe(second.seq);
    expect(anchored.anchor.external).toBeNull();
    expect(await verifyAnchor(anchored.anchor, [first, second])).toBe(true);
  });

  it("catches an edited-and-rehashed earlier event, and leaves the honest chain standing", async () => {
    const { events, first } = await stage();
    const seals = await sealsForEntries(events, [first]);
    const submission = submissionOf(events, DRAFT_ID);
    const proof = decodeProof(seals.get(DRAFT_ID)!.inclusion_proof)!;

    // The tamper an attacker has to make for the log to still look
    // self-consistent: edit one earlier event's payload and rehash it, so the
    // hash chain would pass and only the seal catches it.
    const tampered = [...events];
    const target = tampered[1]!;
    const fields = {
      seq: target.seq,
      at: target.at,
      type: target.type,
      entry_id: target.entry_id,
      payload: { operator: "op_impostor", maintainer: true },
      prev_hash: target.prev_hash,
    } as Omit<Event, "hash">;
    tampered[1] = { ...fields, hash: await eventHash(fields) } as Event;

    expect(await verifySeal(tampered, first, null)).toBe(false);

    // And the proof the seal handed out no longer stands against the batch the
    // tampered log now makes.
    expect(
      await verifyInclusion(
        submission.hash,
        proof,
        await merkleRoot(tampered.map((event) => event.hash)),
      ),
    ).toBe(false);

    // The untouched chain is still whole, and still verifies against its seal.
    expect(await verifyChain(events)).toEqual({
      ok: true,
      length: events.length,
    });
    expect(await verifySeal(events, first, null)).toBe(true);
    expect(await verifyInclusion(submission.hash, proof, first.root)).toBe(true);
  });
});

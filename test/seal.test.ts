/**
 * The seal: batches of events committed to a Merkle root, chained, and the
 * entry-level seal object the schema carries.
 *
 * Whitepaper Section 6, "Seal": everything gets sealed, drafts included; the
 * entry hash is sealed as a fingerprint at submission; every later event is
 * hashed into a batch and sealed; the seal is self-performed but unrewritable.
 * The unrewritable half is what most of these tests are about — a batch that
 * skips a seq is refused, an edited event no longer recomputes the root, and a
 * seal held against the wrong predecessor fails its chain link.
 *
 * The clock is injected and fake; nothing here reads a wall clock.
 */

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import { deriveEntry, type Clock } from "../src/derive.js";
import { appendEvent, eventHash, type Event } from "../src/events.js";
import { decodeProof, merkleRoot, verifyInclusion } from "../src/merkle.js";
import { validateEntry } from "../src/schema.js";
import {
  HASH_TAG_SEAL,
  SEAL_REFUSALS,
  buildSeal,
  entrySeal,
  sealFor,
  sealHash,
  sealsForEntries,
  verifySeal,
  type RegistrySeal,
  type Seal,
  type WitnessSignature,
} from "../src/seal.js";

const AUTHOR = "1F916:JpFo4VI5q9AZ62i23W5AOx_m5J7eOwrPmaUFeScS-gY";
const AUTHOR_OPERATOR = "op_brightloop";
const SIGNATURE =
  "7DrXYYABpKoGvBW07FX6kqGmLBNkpuJ1/U+9pMgtJLDcjQlQKkI7eg40rXqQjjGA6Jzt4DOrwViDwtC3qtaPAw==";
const HASH =
  "sha256:9f2c4b1a7e0d3c8f6b5a2e1d0c9b8a7f6e5d4c3b2a1908070605040302010009";

const DRAFT_ID = "nmk_01M8DRAFT";
const OTHER_ID = "nmk_01M8OTHER";
const UNSEALED_ID = "nmk_01M8LATE";
const SUBMITTED_AT = "2026-09-01T14:05:00Z";

/** Two fake clocks: one per seal, so sealed_at is visibly the injected value. */
const CLOCK: Clock = { now: "2026-09-07T00:00:00Z" };
const LATER: Clock = { now: "2026-09-08T00:00:00Z" };
/** The derivation clock: inside the pricing window, so nothing here is stale. */
const DERIVE_CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

function at(seq: number): string {
  return new Date(
    Date.parse("2026-09-01T00:00:00Z") + seq * 60_000,
  ).toISOString();
}

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
    author: AUTHOR,
    author_operator: AUTHOR_OPERATOR,
    submitted_at: SUBMITTED_AT,
    ...overrides,
  } as Core;
}

const DRAFT_CORE = core({});
const OTHER_CORE = core({ id: OTHER_ID, subject: "anthropic/claude-4" });
const UNSEALED_CORE = core({ id: UNSEALED_ID, subject: "google/gemini-3" });

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

function submit(events: readonly Event[], submitted: Core): Promise<Event[]> {
  return append(events, "entry_submitted", submitted["id"] as string, {
    core: submitted,
    signature: SIGNATURE,
  });
}

/**
 * Seven events: two registrations, the draft submission, a trust event, a
 * second submission, and two more registrations. Nothing is validated — Section
 * 6 seals drafts like everything else, so a draft is the honest fixture here.
 */
async function firstBatch(): Promise<Event[]> {
  let events: Event[] = [];
  for (const operator of [AUTHOR_OPERATOR, "op_farhaven"]) {
    events = await append(events, "operator_registered", null, {
      operator,
      maintainer: false,
    });
  }
  events = await submit(events, DRAFT_CORE);
  events = await append(events, "operator_trusted", null, {
    operator: "op_farhaven",
  });
  events = await submit(events, OTHER_CORE);
  for (const operator of ["op_pool1", "op_pool2"]) {
    events = await append(events, "operator_registered", null, {
      operator,
      maintainer: false,
    });
  }
  return events;
}

/** Three more events after the first seal, including one more submission. */
async function secondBatch(events: readonly Event[]): Promise<Event[]> {
  let current = await append(events, "operator_trusted", null, {
    operator: "op_pool1",
  });
  current = await submit(current, UNSEALED_CORE);
  return append(current, "operator_trusted", null, { operator: "op_pool2" });
}

/**
 * Two countersignatures, gathered after the fact. Nothing here checks them —
 * that is the witness rule's job; the seal only carries them.
 */
const COUNTERSIGNATURES: WitnessSignature[] = [
  { agent: "1F916:d2l0bmVzc09uZUFnZW50SWRlbnRpdHlBQUFB", signature: "c2lnbmF0dXJlLW9uZQ" },
  { agent: "1F916:d2l0bmVzc1R3b0FnZW50SWRlbnRpdHlBQUFB", signature: "c2lnbmF0dXJlLXR3bw" },
];

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

describe("buildSeal", () => {
  it("names its hash construction and its refusals", () => {
    expect(HASH_TAG_SEAL).toBe("nomankind-seal-v1");
    expect(SEAL_REFUSALS).toEqual(["nothing_new", "gap"]);
  });

  it("seals every event of a fresh chain, from seq 0", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);

    expect(first.seq).toBe(0);
    expect(first.first_seq).toBe(0);
    expect(first.last_seq).toBe(events.length - 1);
    expect(first.size).toBe(events.length);
    expect(first.prev_hash).toBeNull();
    expect(first.witnesses).toEqual([]);
    expect(first.sealed_at).toBe(CLOCK.now);
    expect(first.root).toBe(await merkleRoot(events.map((e) => e.hash)));
    expect(first.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("seals only the new events on the next batch, chained to the last seal", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);

    expect(second.seq).toBe(1);
    expect(second.first_seq).toBe(first.last_seq + 1);
    expect(second.last_seq).toBe(grown.length - 1);
    expect(second.size).toBe(grown.length - events.length);
    expect(second.prev_hash).toBe(first.hash);
    expect(second.sealed_at).toBe(LATER.now);
    // Only the new events are in the batch.
    expect(second.root).toBe(
      await merkleRoot(grown.slice(events.length).map((e) => e.hash)),
    );
    expect(second.root).not.toBe(first.root);
  });

  it("refuses to seal nothing", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    expect(await buildSeal(events, first, LATER)).toEqual({
      ok: false,
      reason: "nothing_new",
    });
    expect(await buildSeal([], null, CLOCK)).toEqual({
      ok: false,
      reason: "nothing_new",
    });
  });

  it("refuses a batch with a hole in it", async () => {
    const events = await firstBatch();

    // The log does not start where the seal chain does.
    expect(await buildSeal(events.slice(1), null, CLOCK)).toEqual({
      ok: false,
      reason: "gap",
    });

    // A missing seq in the middle of the run.
    const holed = events.filter((event) => event.seq !== 3);
    expect(await buildSeal(holed, null, CLOCK)).toEqual({
      ok: false,
      reason: "gap",
    });

    // And a hole between one seal and the next.
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    expect(
      await buildSeal(
        grown.filter((event) => event.seq !== first.last_seq + 1),
        first,
        LATER,
      ),
    ).toEqual({ ok: false, reason: "gap" });
  });
});

describe("verifySeal", () => {
  it("verifies the honest chain of seals", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);

    expect(await verifySeal(events, first, null)).toBe(true);
    expect(await verifySeal(grown, first, null)).toBe(true);
    expect(await verifySeal(grown, second, first)).toBe(true);
  });

  it("fails once an earlier event is edited", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);

    // The tamper an attacker has to make for the log to still look
    // self-consistent: edit the payload and rehash that one event, so
    // verifyChain would pass and only the seal catches it.
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
  });

  it("fails on a missing event, a wrong size, and the wrong predecessor", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);

    // An event the seal claims to cover is simply gone.
    expect(
      await verifySeal(
        events.filter((event) => event.seq !== 2),
        first,
        null,
      ),
    ).toBe(false);

    // The size has to be the run it claims.
    expect(await verifySeal(events, { ...first, size: first.size + 1 }, null)).toBe(
      false,
    );

    // The chain link: the right seal held against the wrong predecessor, and a
    // chained seal offered as if it were the first.
    expect(await verifySeal(grown, second, second)).toBe(false);
    expect(await verifySeal(grown, second, null)).toBe(false);
    expect(await verifySeal(events, first, second)).toBe(false);

    // A rewritten seal hash never recomputes.
    expect(
      await verifySeal(events, { ...first, sealed_at: LATER.now }, null),
    ).toBe(false);
  });
});

describe("sealFor", () => {
  it("finds the seal covering an event seq, and nothing beyond the chain", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);
    const seals = [first, second];

    expect(sealFor(seals, 0)).toBe(first);
    expect(sealFor(seals, first.last_seq)).toBe(first);
    expect(sealFor(seals, first.last_seq + 1)).toBe(second);
    expect(sealFor(seals, second.last_seq)).toBe(second);
    expect(sealFor(seals, second.last_seq + 1)).toBeNull();
    expect(sealFor([], 0)).toBeNull();
  });
});

describe("entrySeal", () => {
  it("gives a draft entry the schema's seal object, with a proof that verifies", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);

    // The draft has been submitted and nobody has decided anything about it.
    expect(deriveEntry(events, DRAFT_ID, DERIVE_CLOCK).derived.status).toBe(
      "draft",
    );

    const built = await entrySeal(events, [first], DRAFT_ID);
    expect(built).not.toBeNull();
    expect(built!.log).toBe("1F916");
    expect(built!.sealed_at).toBe(first.sealed_at);
    expect(built!.witnesses).toEqual([]);

    // position is the event's own monotonic sealed coordinate.
    const submission = events.find(
      (event) => event.type === "entry_submitted" && event.entry_id === DRAFT_ID,
    )!;
    expect(built!.position).toBe(submission.seq);

    // And the carried proof verifies offline against the seal's root.
    const proof = decodeProof(built!.inclusion_proof);
    expect(proof).not.toBeNull();
    expect(proof!.size).toBe(first.size);
    expect(proof!.index).toBe(submission.seq - first.first_seq);
    expect(await verifyInclusion(submission.hash, proof!, first.root)).toBe(true);

    // A modified earlier event breaks it: rehash event 1, recompute the root,
    // and the proof the seal handed out no longer stands.
    const tampered = [...events.map((event) => event.hash)];
    tampered[1] = `sha256:${"0".repeat(64)}`;
    expect(
      await verifyInclusion(submission.hash, proof!, await merkleRoot(tampered)),
    ).toBe(false);
  });

  it("makes a seal the registry has not accepted yet", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    // The fingerprint is submitted after the seal exists, so a seal is made
    // with nothing from the registry on it.
    expect(first.registry).toBeNull();
    expect(first.witnesses).toEqual([]);
  });

  it("leaves the seal hash alone when the registry receipt arrives", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);

    // The receipt is what another party said about this seal, gathered after
    // the fact like the countersignatures, so it cannot be inside the hash it
    // was gathered against.
    const receipt: RegistrySeal = {
      registry: "https://1f916.ai",
      handle: "nomankind",
      label: "memory.seal",
      event_id: 9129,
      event_hash: "06fa8eb00cf9b709df0cb21ce1a74f416e9af2820db0770de0e5cfa996776ec4",
      receipt: { ok: true },
      sealed_at: "2026-09-07T00:05:00Z",
    };
    const accepted: Seal = {
      ...first,
      registry: receipt,
      witnesses: [...COUNTERSIGNATURES],
    };
    const { hash, witnesses: _witnesses, registry: _registry, ...fields } = accepted;
    expect(await sealHash(fields)).toBe(first.hash);
    expect(hash).toBe(first.hash);
    expect(await verifySeal(events, accepted, null)).toBe(true);

    // And the next seal chains to the same hash either way.
    const later = await seal(await secondBatch(events), accepted, LATER);
    expect(later.prev_hash).toBe(first.hash);
    expect(later.registry).toBeNull();
  });

  it("leaves the seal hash alone when witnesses arrive, and carries their signatures in order", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);

    // Witnesses countersign the seal hash, so they cannot be inside it: the
    // same seal with two countersignatures is the same seal.
    const countersigned: Seal = { ...first, witnesses: [...COUNTERSIGNATURES] };
    const { hash, witnesses: _witnesses, ...fields } = countersigned;
    expect(await sealHash(fields)).toBe(first.hash);
    expect(hash).toBe(first.hash);
    expect(await verifySeal(events, countersigned, null)).toBe(true);

    // Gathering one more later still does not move it.
    expect(
      await verifySeal(
        events,
        { ...first, witnesses: [COUNTERSIGNATURES[0]!] },
        null,
      ),
    ).toBe(true);

    // And the entry's seal object carries exactly those signature strings, in
    // the order the seal holds them — the signatures alone, not the agents.
    const built = await entrySeal(events, [countersigned], DRAFT_ID);
    expect(built!.witnesses).toEqual([
      COUNTERSIGNATURES[0]!.signature,
      COUNTERSIGNATURES[1]!.signature,
    ]);

    // Still the schema's entry with the countersignatures written on.
    const derived = deriveEntry(
      events,
      DRAFT_ID,
      DERIVE_CLOCK,
      await sealsForEntries(events, [countersigned]),
    );
    const result = validateEntry(derived.entry);
    expect(result.ok ? [] : result.errors).toEqual([]);
  });

  it("gives an entry in the second seal its own seq as position, and an index inside that batch", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);

    // The batch this entry landed in does not start at zero.
    expect(second.first_seq).toBeGreaterThan(0);

    const submission = grown.find(
      (event) =>
        event.type === "entry_submitted" && event.entry_id === UNSEALED_ID,
    )!;
    const built = await entrySeal(grown, [first, second], UNSEALED_ID);
    expect(built).not.toBeNull();
    expect(built!.sealed_at).toBe(second.sealed_at);

    // position is the monotonic log coordinate, not the offset in the batch.
    expect(built!.position).toBe(submission.seq);
    expect(built!.position).not.toBe(submission.seq - second.first_seq);

    // The proof is over the second batch: its index is the offset, its size the
    // batch's, and it verifies against the second seal's root and no other.
    const proof = decodeProof(built!.inclusion_proof)!;
    expect(proof.index).toBe(submission.seq - second.first_seq);
    expect(proof.size).toBe(second.size);
    expect(await verifyInclusion(submission.hash, proof, second.root)).toBe(true);
    expect(await verifyInclusion(submission.hash, proof, first.root)).toBe(false);
  });

  it("is null for an unsealed submission and for an id the log never saw", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);

    // Submitted after the seal closed: nothing covers it yet.
    expect(await entrySeal(grown, [first], UNSEALED_ID)).toBeNull();
    expect(await entrySeal(grown, [first], "nmk_01M8ABSENT")).toBeNull();
    expect(await entrySeal(events, [], DRAFT_ID)).toBeNull();
  });

  it("maps every sealed submission, and only those", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const grown = await secondBatch(events);
    const second = await seal(grown, first, LATER);

    const sealedByFirst = await sealsForEntries(grown, [first]);
    expect([...sealedByFirst.keys()].sort()).toEqual([DRAFT_ID, OTHER_ID].sort());

    const all = await sealsForEntries(grown, [first, second]);
    expect([...all.keys()].sort()).toEqual(
      [DRAFT_ID, OTHER_ID, UNSEALED_ID].sort(),
    );
    expect(all.get(UNSEALED_ID)!.sealed_at).toBe(second.sealed_at);
    expect(all.get(DRAFT_ID)!.sealed_at).toBe(first.sealed_at);
  });
});

describe("deriveEntry with seals", () => {
  it("writes the seal onto the entry, and leaves it null without the map", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const seals = await sealsForEntries(events, [first]);

    // Without the map, nothing changes: the entry is unsealed as far as it knows.
    expect(deriveEntry(events, DRAFT_ID, DERIVE_CLOCK).entry["seal"]).toBeNull();

    const derived = deriveEntry(events, DRAFT_ID, DERIVE_CLOCK, seals);
    expect(derived.entry["seal"]).toEqual(seals.get(DRAFT_ID));
    expect(derived.derived.status).toBe("draft");

    // An entry the map does not cover stays null.
    const grown = await secondBatch(events);
    expect(
      deriveEntry(grown, UNSEALED_ID, DERIVE_CLOCK, seals).entry["seal"],
    ).toBeNull();
  });

  it("still validates against the schema with the seal in place", async () => {
    const events = await firstBatch();
    const first = await seal(events, null, CLOCK);
    const seals = await sealsForEntries(events, [first]);
    const derived = deriveEntry(events, DRAFT_ID, DERIVE_CLOCK, seals);

    // The fixture really is the whole signed core, so this is a real entry.
    for (const key of CORE_KEYS) {
      expect(derived.entry[key]).toEqual(DRAFT_CORE[key]);
    }

    const result = validateEntry(derived.entry);
    expect(result.ok ? [] : result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });
});

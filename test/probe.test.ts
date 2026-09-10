/**
 * The probe set: the draw is deterministic and unsteerable, the commitment
 * ordering is the same one an assignment holds, the genesis-thin tier still gets
 * an attestation, and answers have to answer exactly the probes.
 */

import { describe, expect, it } from "vitest";

import {
  answersHash,
  checkAnswers,
  probeSet,
  probeSetHash,
  HASH_TAG_ANSWERS,
  HASH_TAG_PROBE,
  HASH_TAG_PROBE_SET,
  type ProbeCandidate,
} from "../src/probe.js";
import { PROBE_SET_MIN_CANDIDATES, PROBE_SET_SIZE } from "../src/policy.js";
import type { Beacon, PoolSnapshot } from "../src/assign.js";
import type { Probe } from "../src/events.js";

const SNAPSHOT_AT = "2026-09-01T00:00:00.000Z";
const BEACON_AT = "2026-09-01T01:00:00.000Z";

const POOL = Array.from({ length: 12 }, (_, index) => `op_v${index + 1}`);

function beacon(round: number, at: string = BEACON_AT): Beacon {
  return { round, randomness: `${"7c1f".repeat(15)}${round % 10}`, at };
}

function snapshotOf(
  operators: readonly string[] = POOL,
  at: string = SNAPSHOT_AT,
): PoolSnapshot {
  return { seq: 4, at, operators };
}

/** `count` candidates, ids padded so string order and numeric order agree. */
function candidates(count: number): ProbeCandidate[] {
  return Array.from({ length: count }, (_, index) => ({
    entry_id: `nmk_e${String(index + 1).padStart(3, "0")}`,
    entry_hash: `sha256:${String(index + 1).padStart(2, "0").repeat(32)}`,
  }));
}

function idsOf(probes: readonly Probe[]): string[] {
  return probes.map((probe) => probe.entry_id);
}

describe("the probe draw", () => {
  it("gives the same probes and the same probe hash for the same inputs", async () => {
    const input = {
      candidates: candidates(30),
      snapshot: snapshotOf(),
      beacon: beacon(4200),
    };
    const first = await probeSet(input);
    const second = await probeSet({
      ...input,
      // A different order out of the store must not move the answer.
      candidates: [...input.candidates].reverse(),
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(second.probes).toEqual(first.probes);
    expect(second.probe_hash).toBe(first.probe_hash);
    expect(first.probe_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("draws different probes on a different beacon round", async () => {
    const set = candidates(30);
    const first = await probeSet({
      candidates: set,
      snapshot: snapshotOf(),
      beacon: beacon(4200),
    });
    const second = await probeSet({
      candidates: set,
      snapshot: snapshotOf(),
      beacon: beacon(4201),
    });

    if (!first.ok || !second.ok) throw new Error("both draws should have run");
    expect(idsOf(second.probes)).not.toEqual(idsOf(first.probes));
    expect(second.probe_hash).not.toBe(first.probe_hash);
  });

  it("refuses a snapshot sealed at or after the beacon round it would use", async () => {
    const set = candidates(30);
    const after = await probeSet({
      candidates: set,
      snapshot: snapshotOf(POOL, "2026-09-01T02:00:00.000Z"),
      beacon: beacon(4200),
    });
    const equal = await probeSet({
      candidates: set,
      snapshot: snapshotOf(POOL, BEACON_AT),
      beacon: beacon(4200),
    });

    expect(after).toEqual({ ok: false, reason: "snapshot_after_beacon" });
    expect(equal).toEqual({ ok: false, reason: "snapshot_after_beacon" });
  });

  it("refuses fewer candidates than the published floor", async () => {
    const refused = await probeSet({
      candidates: candidates(PROBE_SET_MIN_CANDIDATES - 1),
      snapshot: snapshotOf(),
      beacon: beacon(4200),
    });
    expect(refused).toEqual({ ok: false, reason: "insufficient_candidates" });
  });

  it("draws every candidate between the floor and the published size", async () => {
    // Section 12: the observed tier is thin at genesis, and a thin tier still
    // attests. Every count from the floor up to the size draws all of them.
    for (let count = PROBE_SET_MIN_CANDIDATES; count <= PROBE_SET_SIZE; count += 1) {
      const set = candidates(count);
      const drawn = await probeSet({
        candidates: set,
        snapshot: snapshotOf(),
        beacon: beacon(4200),
      });
      if (!drawn.ok) throw new Error(`draw refused at ${count} candidates`);
      expect(drawn.probes).toHaveLength(count);
      expect(idsOf(drawn.probes)).toEqual(set.map((one) => one.entry_id));
    }
  });

  it("draws exactly the published size above it, sorted by entry id", async () => {
    const drawn = await probeSet({
      candidates: candidates(PROBE_SET_SIZE + 25),
      snapshot: snapshotOf(),
      beacon: beacon(4200),
    });
    if (!drawn.ok) throw new Error("draw should have run");
    expect(drawn.probes).toHaveLength(PROBE_SET_SIZE);
    expect(idsOf(drawn.probes)).toEqual([...idsOf(drawn.probes)].sort());
    expect(new Set(idsOf(drawn.probes)).size).toBe(PROBE_SET_SIZE);
  });

  it("carries each drawn entry's hash beside its id", async () => {
    const set = candidates(20);
    const byId = new Map(set.map((one) => [one.entry_id, one.entry_hash]));
    const drawn = await probeSet({
      candidates: set,
      snapshot: snapshotOf(),
      beacon: beacon(7),
    });
    if (!drawn.ok) throw new Error("draw should have run");
    for (const probe of drawn.probes) {
      expect(probe.entry_hash).toBe(byId.get(probe.entry_id));
    }
  });

  it("moves the probes when the pool snapshot moves", async () => {
    const set = candidates(30);
    const first = await probeSet({
      candidates: set,
      snapshot: snapshotOf(POOL),
      beacon: beacon(4200),
    });
    const second = await probeSet({
      candidates: set,
      snapshot: snapshotOf([...POOL, "op_v13"]),
      beacon: beacon(4200),
    });
    if (!first.ok || !second.ok) throw new Error("both draws should have run");
    expect(second.probe_hash).not.toBe(first.probe_hash);
  });

  it("hashes the probe set independently of the order it is handed", async () => {
    const probes: Probe[] = [
      { entry_id: "nmk_b", entry_hash: `sha256:${"2".repeat(64)}` },
      { entry_id: "nmk_a", entry_hash: `sha256:${"1".repeat(64)}` },
    ];
    expect(await probeSetHash(probes)).toBe(
      await probeSetHash([...probes].reverse()),
    );
  });

  it("keeps its hash tags apart", () => {
    expect(
      new Set([HASH_TAG_PROBE, HASH_TAG_PROBE_SET, HASH_TAG_ANSWERS]).size,
    ).toBe(3);
  });
});

describe("the answers", () => {
  const probes: readonly Probe[] = [
    { entry_id: "nmk_a", entry_hash: `sha256:${"1".repeat(64)}` },
    { entry_id: "nmk_b", entry_hash: `sha256:${"2".repeat(64)}` },
  ];

  it("hashes the same however the answers were ordered", async () => {
    const answers = [
      { entry_id: "nmk_b", answer: "two" },
      { entry_id: "nmk_a", answer: "one" },
    ];
    const hash = await answersHash(answers);
    expect(await answersHash([...answers].reverse())).toBe(hash);
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("changes when any answer changes", async () => {
    const first = await answersHash([{ entry_id: "nmk_a", answer: "one" }]);
    const second = await answersHash([{ entry_id: "nmk_a", answer: "ONE" }]);
    expect(second).not.toBe(first);
  });

  it("accepts one string answer per probe", () => {
    expect(
      checkAnswers(probes, [
        { entry_id: "nmk_b", answer: "two" },
        { entry_id: "nmk_a", answer: "one" },
      ]),
    ).toEqual({ ok: true });
  });

  it("refuses anything that is not exactly one answer per probe", () => {
    const bad = { ok: false, reason: "bad_answers" };
    // Not an array at all.
    expect(checkAnswers(probes, { nmk_a: "one" })).toEqual(bad);
    // A probe left unanswered.
    expect(checkAnswers(probes, [{ entry_id: "nmk_a", answer: "one" }])).toEqual(bad);
    // One probe answered twice, and the other never.
    expect(
      checkAnswers(probes, [
        { entry_id: "nmk_a", answer: "one" },
        { entry_id: "nmk_a", answer: "again" },
      ]),
    ).toEqual(bad);
    // An entry that was never asked about.
    expect(
      checkAnswers(probes, [
        { entry_id: "nmk_a", answer: "one" },
        { entry_id: "nmk_z", answer: "unasked" },
      ]),
    ).toEqual(bad);
    // An answer that is not a string.
    expect(
      checkAnswers(probes, [
        { entry_id: "nmk_a", answer: "one" },
        { entry_id: "nmk_b", answer: 2 },
      ]),
    ).toEqual(bad);
    // More answers than probes.
    expect(
      checkAnswers(probes, [
        { entry_id: "nmk_a", answer: "one" },
        { entry_id: "nmk_b", answer: "two" },
        { entry_id: "nmk_b", answer: "two" },
      ]),
    ).toEqual(bad);
  });
});

/**
 * The sweep's healing step: a seal whose stored registry record names the wrong
 * identity event is corrected before anything is countersigned.
 *
 * Whitepaper, Section 6 (Seal): a seal counts as witnessed only on a
 * countersignature of a registry checkpoint that covers the seal's own anchoring
 * identity event. Production seal 0 was stored under the earlier reading — the
 * registry's seal row id where the identity event id belongs, and no chain hash
 * at all — so its proof was a proof of an unrelated event, and no
 * countersignature of it could ever have counted.
 *
 * Nothing is migrated: the witness step asks the adapter to re-resolve the
 * record and persists what comes back *before* it asks for a proof, so such a
 * seal heals on an ordinary sweep run. That order is the property this file
 * pins: the record the adapter sees when countersignatures are asked for is the
 * corrected one, and the row in the database is corrected too.
 *
 * The adapter is the fake from test/helpers/witness.ts — what the correction
 * costs on the wire is test/witness-adapter.test.ts's subject, against a
 * registry that exists only in that file — and the database underneath is
 * miniflare's own D1 with every migration applied.
 */

import { afterEach, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import type { RegistrySeal, Seal } from "../src/seal.js";
import { putSeal, sealBySeq } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

const NOW = new Date("2026-09-09T12:00:00.000Z");
const REGISTRY_ORIGIN = "https://1f916.test";
const HANDLE = "nomankind";
const LABEL = "nomankind-seal";

/** The registry's own seal row id, which is not an identity event id. */
const SEAL_ROW_ID = 4281;
/** The `memory.seal` identity event that really anchors the seal. */
const EVENT_ID = 9888;
const EVENT_HASH = "3e".repeat(32);

/** The seal in the log: one seal covering event 0, waiting on the world. */
function seededSeal(registry: RegistrySeal): Seal {
  return {
    seq: 0,
    first_seq: 0,
    last_seq: 0,
    size: 1,
    root: `sha256:${"cd".repeat(32)}`,
    sealed_at: NOW.toISOString(),
    prev_hash: null,
    hash: `sha256:${"ab".repeat(32)}`,
    witnesses: [],
    registry,
  };
}

/** The record production seal 0 really carried: the seal row id, and no hash. */
function storedUnderTheSealRow(): RegistrySeal {
  return {
    registry: REGISTRY_ORIGIN,
    handle: HANDLE,
    label: LABEL,
    event_id: SEAL_ROW_ID,
    event_hash: null,
    receipt: { ok: true, seal: { id: SEAL_ROW_ID } },
    sealed_at: NOW.toISOString(),
  };
}

/** The same record, naming the identity event the citizen record lists. */
function corrected(): RegistrySeal {
  return { ...storedUnderTheSealRow(), event_id: EVENT_ID, event_hash: EVENT_HASH };
}

const opened: TestDatabase[] = [];

afterEach(async () => {
  while (opened.length > 0) await opened.pop()?.dispose();
});

/** A database with one seal in it, and the bindings around it. */
async function worldWith(registry: RegistrySeal): Promise<{
  env: Env;
  store: TestDatabase;
}> {
  const store = await openTestDatabase();
  opened.push(store);
  await putSeal(store.db, seededSeal(registry));
  return {
    env: {
      DB: store.db,
      CAPTURES: store.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
    },
    store,
  };
}

/** The sweep the alarm runs, on the registry track, with the world faked. */
async function sweep(
  env: Env,
  witness: FakeWitnessAdapter,
  signer: FakeWitness,
): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m16-heal");
  await beacon.advance(NOW.toISOString());
  return runSweep(env, {
    now: NOW,
    beacon,
    witness,
    pinned: pinnedSet([signer]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

describe("the sweep heals a stored registry record", () => {
  it("persists the corrected record before the witnesses attach", async () => {
    const signer = await makeWitness("healing-witness.example");
    const { env, store } = await worldWith(storedUnderTheSealRow());
    const witness = new FakeWitnessAdapter({
      kind: "registry",
      signers: [signer],
      healed: corrected(),
    });

    const report = await sweep(env, witness, signer);

    // The correction was asked for, and for this seal.
    expect(witness.healedSeqs).toEqual([0]);

    // And it was already stored when countersignatures were asked for: the
    // adapter was handed the corrected record, never the seal row id, because a
    // proof of the seal row is a proof of an unrelated event.
    expect(witness.collected).toEqual([0]);
    expect(witness.collectedRegistry[0]).toEqual(corrected());

    // The row in the database says the same, whatever the countersignatures did.
    const stored = await sealBySeq(store.db, 0);
    expect(stored!.registry).toEqual(corrected());
    expect(stored!.registry!.event_id).toBe(EVENT_ID);
    expect(stored!.registry!.event_id).not.toBe(SEAL_ROW_ID);

    // The seal is witnessed in the same run: healing is a step of the sweep, not
    // a run of its own.
    expect(report.witnessed).toEqual([
      { seq: 0, operators: [signer.witness.operator] },
    ]);
    expect(stored!.witnesses).toHaveLength(1);
  }, 120_000);

  it("writes nothing while the citizen record still does not list the event", async () => {
    const signer = await makeWitness("healing-witness.example");
    const stored = storedUnderTheSealRow();
    const { env, store } = await worldWith(stored);
    // A registry that cannot name the event yet corrects nothing, and a record
    // that is not corrected is left exactly as it was rather than overwritten.
    const witness = new FakeWitnessAdapter({
      kind: "registry",
      signers: [signer],
      healed: null,
    });

    await sweep(env, witness, signer);

    expect(witness.healedSeqs).toEqual([0]);
    expect((await sealBySeq(store.db, 0))!.registry).toEqual(stored);
  }, 120_000);

  it("asks for no correction on a track that has no registry", async () => {
    const signer = await makeWitness("healing-witness.example");
    const { env } = await worldWith(storedUnderTheSealRow());
    const witness = new FakeWitnessAdapter({
      signers: [signer],
      healed: corrected(),
    });

    await sweep(env, witness, signer);

    // The mock has no registry record to correct, and the sweep does not ask.
    expect(witness.healedSeqs).toEqual([]);
    expect(witness.collected).toEqual([0]);
  }, 120_000);
});

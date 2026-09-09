/**
 * Fake witnesses and a fake timestamping chain, for the sweep's sealing steps.
 *
 * The signatures are real: each fake witness holds an Ed25519 keypair generated
 * at test time through src/identity.ts and countersigns with src/witness.ts's
 * own `signWitness`, so what the sweep checks is a signature the witness rule
 * really has to verify rather than a string the test agreed to accept. What is
 * faked is only the outside world — which witnesses exist, whether the registry
 * answered, and whether a calendar took the day's hash — because none of that is
 * ours to run in a test.
 *
 * The adapters carry the same `kind` the environment adapters carry, so a test
 * can put the sweep on the mock track, the registry track or no track at all
 * without reaching for the real ones.
 */

import type {
  EnvironmentWitnessAdapter,
  PinnedWitnesses,
  WitnessAdapterKind,
} from "../../src/adapters/witness.js";
import type { Anchor, AnchorAdapter, AnchorExternal } from "../../src/anchor.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../../src/identity.js";
import type { RegistrySeal, Seal, WitnessSignature } from "../../src/seal.js";
import { signWitness, type Witness } from "../../src/witness.js";

/** One fake witness: a real keypair, and the directory row that names it. */
export interface FakeWitness {
  readonly witness: Witness;
  readonly privateKey: CryptoKey;
}

/** A fresh witness under this operator. Two calls with one operator are two keys. */
export async function makeWitness(operator: string): Promise<FakeWitness> {
  const pair = await generateKeypair();
  const raw = await exportPublicKeyRaw(pair.publicKey);
  return {
    witness: { agent: agentIdFromPublicKey(raw), operator },
    privateKey: pair.privateKey,
  };
}

export interface FakeWitnessOptions {
  /** Which track this adapter claims to be on. "mock" unless told otherwise. */
  readonly kind?: WitnessAdapterKind;
  /** Who countersigns, in the order they are offered. */
  readonly signers?: readonly FakeWitness[];
  /** What the registry answers when a fingerprint is submitted. Null by default. */
  readonly registrySeal?: RegistrySeal | null;
  /**
   * The corrected record `heal` answers with, or null for a stored record that
   * needs no correction (and for one the registry cannot correct yet, which is
   * the same answer: nothing is written).
   */
  readonly healed?: RegistrySeal | null;
}

/**
 * A witness adapter that signs the direct form: the seal hash itself, exactly
 * as the mock on local and demo does.
 *
 * It offers whatever it was given, in the order it was given, and never judges
 * any of it: whether a signature counts is the witness rule's answer and the
 * sweep's to ask, so an adapter that offered a maintainer's witness is a real
 * possibility rather than a test that cheated.
 */
export class FakeWitnessAdapter implements EnvironmentWitnessAdapter {
  readonly kind: WitnessAdapterKind;
  readonly signers: readonly FakeWitness[];
  /** What `seal` answers. Settable, so a run can find the registry back up. */
  registrySeal: RegistrySeal | null;
  /** What `heal` answers. Settable, like the receipt, so a run can correct one. */
  healed: RegistrySeal | null;
  /** The seal seqs whose fingerprint was submitted, in order. */
  readonly sealed: number[] = [];
  /** The seal seqs countersignatures were asked for, in order. */
  readonly collected: number[] = [];
  /** The seal seqs a correction was asked for, in order. */
  readonly healedSeqs: number[] = [];
  /**
   * The registry record each seal carried when countersignatures were asked
   * for, so a test can see whether the correction was persisted *before* the
   * proof was asked for rather than after.
   */
  readonly collectedRegistry: (RegistrySeal | null)[] = [];

  constructor(options: FakeWitnessOptions = {}) {
    this.kind = options.kind ?? "mock";
    this.signers = options.signers ?? [];
    this.registrySeal = options.registrySeal ?? null;
    this.healed = options.healed ?? null;
  }

  async seal(seal: Seal): Promise<RegistrySeal | null> {
    this.sealed.push(seal.seq);
    return this.registrySeal;
  }

  /**
   * The correction the real adapter re-resolves from the citizen record, handed
   * back from configuration instead: what a test cares about here is that the
   * sweep asks, and keeps the answer before it asks for a proof.
   */
  async heal(seal: Seal): Promise<RegistrySeal | null> {
    this.healedSeqs.push(seal.seq);
    return this.healed;
  }

  async collect(seal: Seal): Promise<WitnessSignature[]> {
    this.collected.push(seal.seq);
    this.collectedRegistry.push(seal.registry);
    const signatures: WitnessSignature[] = [];
    for (const signer of this.signers) {
      signatures.push({
        agent: signer.witness.agent,
        signature: await signWitness(signer.privateKey, seal.hash),
      });
    }
    return signatures;
  }
}

/** The pinned set naming these witnesses, and no registry: the direct form only. */
export function pinnedSet(
  witnesses: readonly FakeWitness[],
): PinnedWitnesses {
  return { witnesses: witnesses.map((each) => each.witness), registry: null };
}

/** A timestamping chain that answers whatever it was configured to answer. */
export class FakeAnchorAdapter implements AnchorAdapter {
  /** The receipt to answer with, or null for a chain that took nothing. */
  external: AnchorExternal;
  /** The days it was asked about, in order. */
  readonly asked: string[] = [];

  constructor(external: AnchorExternal = null) {
    this.external = external;
  }

  async anchor(anchor: Anchor): Promise<AnchorExternal> {
    this.asked.push(anchor.date);
    return this.external;
  }
}

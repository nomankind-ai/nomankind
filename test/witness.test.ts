import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { base64urlEncode } from "../src/encoding.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
  signBytes,
} from "../src/identity.js";
import {
  registryCheckpointPayload,
  registryWitnessPayload,
} from "../src/registry-proof.js";
// A countersignature's shape belongs to the seal it countersigns; the witness
// rule imports it rather than declaring a second one.
import type {
  RegistryHead,
  Seal,
  WitnessEvidence,
  WitnessSignature,
} from "../src/seal.js";
import {
  HASH_TAG_WITNESS,
  WITNESS_REFUSALS,
  checkWitnesses,
  signWitness,
  witnessSigningBytes,
  witnessedCount,
  type Witness,
  type WitnessContext,
} from "../src/witness.js";
import { consistencyOf, leafOf, pathOf, rootOf } from "./helpers/registry-tree.js";

const SEAL_HASH = `sha256:${"a1".repeat(32)}`;
const OTHER_SEAL_HASH = `sha256:${"b2".repeat(32)}`;

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

function context(
  witnesses: readonly Witness[],
  maintainerOperators: readonly string[] = ["nomankind"],
  extra: Partial<WitnessContext> = {},
): WitnessContext {
  return {
    witnesses,
    maintainerOperators: new Set(maintainerOperators),
    ineligibleAgents: new Set<string>(),
    registry: null,
    ...extra,
  };
}

async function countersign(
  party: Party,
  sealHash: string = SEAL_HASH,
): Promise<WitnessSignature> {
  return { agent: party.agent, signature: await signWitness(party.privateKey, sealHash) };
}

describe("witnessSigningBytes", () => {
  it("is the tag, a newline, and the seal hash in UTF-8", () => {
    expect(new TextDecoder().decode(witnessSigningBytes(SEAL_HASH))).toBe(
      `${HASH_TAG_WITNESS}\n${SEAL_HASH}`,
    );
  });

  it("separates domains: a different seal hash gives different bytes", () => {
    expect(witnessSigningBytes(SEAL_HASH)).not.toEqual(
      witnessSigningBytes(OTHER_SEAL_HASH),
    );
  });
});

describe("WITNESS_REFUSALS", () => {
  it("names the refusals in the order they are checked", () => {
    expect(WITNESS_REFUSALS).toEqual([
      "unknown_witness",
      "maintainer_witness",
      "duplicate_operator",
      "bad_signature",
      "bad_evidence",
    ]);
  });
});

describe("checkWitnesses", () => {
  it("accepts three witnesses under three operators, in order", async () => {
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");
    const gamma = await makeParty("gamma");

    const result = await checkWitnesses(
      SEAL_HASH,
      [await countersign(alpha), await countersign(beta), await countersign(gamma)],
      context(pin(alpha, beta, gamma)),
    );

    expect(result).toEqual({
      ok: true,
      witnesses: [
        { agent: alpha.agent, operator: "alpha" },
        { agent: beta.agent, operator: "beta" },
        { agent: gamma.agent, operator: "gamma" },
      ],
    });
  });

  it("refuses a second key under an already-counted operator, naming its agent", async () => {
    // D-033's syntropos2 case: two keys under one operator are one witness.
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");
    const gamma = await makeParty("gamma");
    const gammaSecond = await makeParty("gamma");

    const result = await checkWitnesses(
      SEAL_HASH,
      [
        await countersign(alpha),
        await countersign(beta),
        await countersign(gamma),
        await countersign(gammaSecond),
      ],
      context(pin(alpha, beta, gamma, gammaSecond)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "duplicate_operator",
      agent: gammaSecond.agent,
    });
  });

  it("checks the operator before the signature: a duplicate with bad bytes is duplicate_operator", async () => {
    // The same order question as the maintainer case, one rung lower: who
    // signed is settled before how well. A second key under gamma is not a
    // second witness whatever it signed, so the refusal names the control
    // failure rather than the cryptographic one.
    const alpha = await makeParty("alpha");
    const gamma = await makeParty("gamma");
    const gammaSecond = await makeParty("gamma");

    const result = await checkWitnesses(
      SEAL_HASH,
      [
        await countersign(alpha),
        { agent: gamma.agent, signature: await signWitness(gamma.privateKey, SEAL_HASH) },
        { agent: gammaSecond.agent, signature: "not+base64url/=" },
      ],
      context(pin(alpha, gamma, gammaSecond)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "duplicate_operator",
      agent: gammaSecond.agent,
    });

    // And the same bad bytes under an operator nobody has used yet do reach
    // the signature check, so it really is the duplicate that decided it.
    const delta = await makeParty("delta");
    expect(
      await checkWitnesses(
        SEAL_HASH,
        [{ agent: delta.agent, signature: "not+base64url/=" }],
        context(pin(delta)),
      ),
    ).toEqual({ ok: false, reason: "bad_signature", agent: delta.agent });
  });

  it("refuses an agent outside the pinned set", async () => {
    const alpha = await makeParty("alpha");
    const stranger = await makeParty("stranger");

    const result = await checkWitnesses(
      SEAL_HASH,
      [await countersign(alpha), await countersign(stranger)],
      context(pin(alpha)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "unknown_witness",
      agent: stranger.agent,
    });
  });

  it("refuses a malformed agent id rather than throwing", async () => {
    const alpha = await makeParty("alpha");
    const malformed = "1F916:not valid base64url!!";

    const result = await checkWitnesses(
      SEAL_HASH,
      [{ agent: malformed, signature: await signWitness(alpha.privateKey, SEAL_HASH) }],
      context(pin(alpha)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "unknown_witness",
      agent: malformed,
    });
  });

  it("refuses a pinned witness whose id carries no key, rather than throwing", async () => {
    // The id is in the pinned set, so only publicKeyFromAgentId can catch it.
    const alpha = await makeParty("alpha");
    const malformed = "1F916:AAAA";

    const result = await checkWitnesses(
      SEAL_HASH,
      [{ agent: malformed, signature: await signWitness(alpha.privateKey, SEAL_HASH) }],
      context([{ agent: malformed, operator: "alpha" }]),
    );

    expect(result).toEqual({
      ok: false,
      reason: "unknown_witness",
      agent: malformed,
    });
  });

  it("refuses a signature made over a different seal hash", async () => {
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");

    const result = await checkWitnesses(
      SEAL_HASH,
      [await countersign(alpha), await countersign(beta, OTHER_SEAL_HASH)],
      context(pin(alpha, beta)),
    );

    expect(result).toEqual({ ok: false, reason: "bad_signature", agent: beta.agent });
  });

  it("refuses a signature that is not base64url", async () => {
    const alpha = await makeParty("alpha");

    const result = await checkWitnesses(
      SEAL_HASH,
      [{ agent: alpha.agent, signature: "not+base64url/=" }],
      context(pin(alpha)),
    );

    expect(result).toEqual({ ok: false, reason: "bad_signature", agent: alpha.agent });
  });

  it("refuses the maintainer's own key even when the signature is valid", async () => {
    const alpha = await makeParty("alpha");
    const maintainer = await makeParty("nomankind");

    const result = await checkWitnesses(
      SEAL_HASH,
      [await countersign(alpha), await countersign(maintainer)],
      context(pin(alpha, maintainer)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "maintainer_witness",
      agent: maintainer.agent,
    });
  });

  it("checks who signed before how: a maintainer with a bad signature is maintainer_witness", async () => {
    const maintainer = await makeParty("nomankind");

    const result = await checkWitnesses(
      SEAL_HASH,
      [{ agent: maintainer.agent, signature: "not+base64url/=" }],
      context(pin(maintainer)),
    );

    expect(result).toEqual({
      ok: false,
      reason: "maintainer_witness",
      agent: maintainer.agent,
    });
  });

  it("accepts an empty list with no witnesses", async () => {
    const alpha = await makeParty("alpha");

    expect(await checkWitnesses(SEAL_HASH, [], context(pin(alpha)))).toEqual({
      ok: true,
      witnesses: [],
    });
  });
});

// ---------------------------------------------------------------------------
// The registry form: a witness countersigns the registry's head, not our seal
// ---------------------------------------------------------------------------

/**
 * The vectors below are the registry's own wire (test/fixtures/registry), and
 * the arrangement is the one the fixtures can actually support: the inclusion
 * proof captured is against the head at tree size 89, so that is the head the
 * proof was fetched at, and a countersignature over it needs no bridge. The
 * captured 89-to-9128 consistency proof cannot serve as the bridge for it —
 * bridging to 9128 would need an inclusion proof against 9128, which the
 * capture does not hold — so the two-head case is built over a generated log
 * further down, and the captured pair is checked as itself in
 * test/registry-proof.test.ts.
 */
function registryFixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`./fixtures/registry/${name}`, import.meta.url), "utf8"),
  ) as T;
}

interface CapturedHead {
  tree_size: number;
  root: string;
  sig: string;
  created_at: number;
}

const PROOF = registryFixture<{
  log: string;
  event: { hash: string; leaf_index: number };
  checkpoint: CapturedHead;
  proof: string[];
}>("proof-identity_events-103.json");

const REGISTRY_PUBLIC_KEY = registryFixture<{
  registry_public_key: { x: string };
}>("checkpoint.json").registry_public_key.x;

const REGISTRY_ORIGIN = "https://1f916.ai";

/** The captured head at tree size 89, as a seal's countersignature carries it. */
const CAPTURED_HEAD: RegistryHead = {
  registry: REGISTRY_ORIGIN,
  log: PROOF.log,
  tree_size: PROOF.checkpoint.tree_size,
  root: PROOF.checkpoint.root,
  created_at: PROOF.checkpoint.created_at,
  registry_sig: PROOF.checkpoint.sig,
};

/** The evidence that our event sits under that head: real proof, real leaf. */
const CAPTURED_EVIDENCE: WitnessEvidence = {
  consistency: "verified from 88",
  leaf_index: PROOF.event.leaf_index,
  event_hash: PROOF.event.hash,
  proof: PROOF.proof,
  proved_at: {
    tree_size: PROOF.checkpoint.tree_size,
    root: PROOF.checkpoint.root,
    created_at: PROOF.checkpoint.created_at,
    registry_sig: PROOF.checkpoint.sig,
  },
  consistency_proof: [],
};

/** The pinned registry the captured head belongs to. */
const PINNED_REGISTRY = {
  origin: REGISTRY_ORIGIN,
  public_key: REGISTRY_PUBLIC_KEY,
};

/** Countersign a head the way a real witness does: over the head, not the seal. */
async function countersignHead(
  party: Party,
  head: RegistryHead,
  evidence: WitnessEvidence,
): Promise<WitnessSignature> {
  const signature = await signBytes(
    party.privateKey,
    registryWitnessPayload({
      registry: head.registry,
      log: head.log,
      tree_size: head.tree_size,
      root: head.root,
    }),
  );
  return {
    agent: party.agent,
    signature: base64urlEncode(signature),
    head,
    evidence,
  };
}

describe("checkWitnesses, the registry form", () => {
  it("accepts a countersignature over the registry's own captured head", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, CAPTURED_EVIDENCE);

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: true, witnesses: [{ agent: alpha.agent, operator: "alpha" }] });
  });

  it("mixes the two forms in one seal", async () => {
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersign(alpha),
          await countersignHead(beta, CAPTURED_HEAD, CAPTURED_EVIDENCE),
        ],
        context(pin(alpha, beta), ["nomankind"], { registry: PINNED_REGISTRY }),
      ),
    ).toEqual({
      ok: true,
      witnesses: [
        { agent: alpha.agent, operator: "alpha" },
        { agent: beta.agent, operator: "beta" },
      ],
    });
  });

  it("refuses a head when no registry is pinned", async () => {
    // Nothing can be known about a head with no key to check its signature
    // against, so the mock's context refuses the registry form outright.
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, CAPTURED_EVIDENCE);

    expect(await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha)))).toEqual({
      ok: false,
      reason: "bad_signature",
      agent: alpha.agent,
    });
  });

  it("refuses a head signed by anyone but the pinned registry", async () => {
    const alpha = await makeParty("alpha");
    const impostor = await makeParty("impostor");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, CAPTURED_EVIDENCE);

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: {
          origin: REGISTRY_ORIGIN,
          public_key: impostor.agent.slice("1F916:".length),
        },
      })),
    ).toEqual({ ok: false, reason: "bad_signature", agent: alpha.agent });
  });

  it("refuses a countersignature made over a different head", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(
      alpha,
      { ...CAPTURED_HEAD, tree_size: 88 },
      CAPTURED_EVIDENCE,
    );
    // The witness signed tree size 88; the head presented says 89, which is the
    // one the registry really signed.
    expect(
      await checkWitnesses(
        SEAL_HASH,
        [{ ...entry, head: CAPTURED_HEAD }],
        context(pin(alpha), ["nomankind"], { registry: PINNED_REGISTRY }),
      ),
    ).toEqual({ ok: false, reason: "bad_signature", agent: alpha.agent });
  });

  it("refuses a bridge between what is one and the same head", async () => {
    // The countersigned head *is* the head the inclusion proof was fetched
    // against, so there is nothing to bridge. A path presented anyway proves
    // some other pair of heads, and an unchecked one is a place to hide it: the
    // rule asks for the path to be empty exactly when the heads are equal.
    const alpha = await makeParty("alpha");
    const bridged = registryFixture<{ proof: string[] }>(
      "consistency-identity_events-89-9128.json",
    ).proof;
    const entry = await countersignHead(alpha, CAPTURED_HEAD, {
      ...CAPTURED_EVIDENCE,
      consistency_proof: bridged,
    });

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a registry-form signature carrying no evidence", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, CAPTURED_EVIDENCE);
    delete (entry as { evidence?: WitnessEvidence }).evidence;

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a head from another registry than the pinned one", async () => {
    const alpha = await makeParty("alpha");
    const head: RegistryHead = { ...CAPTURED_HEAD, registry: "https://elsewhere.example" };
    const entry = await countersignHead(alpha, head, CAPTURED_EVIDENCE);

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a first observation: nothing was verified from anything", async () => {
    // The witness's own line says it had never seen this log before, so it
    // attests the head and nothing about what came before it — which is the
    // guarantee the seal is borrowing.
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, {
      ...CAPTURED_EVIDENCE,
      consistency: "first observation",
    });

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a wrong leaf index", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, {
      ...CAPTURED_EVIDENCE,
      leaf_index: 87,
    });

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a leaf index outside the head it was countersigned at", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, {
      ...CAPTURED_EVIDENCE,
      leaf_index: CAPTURED_HEAD.tree_size,
    });

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses an event hash that is not the one the proof covers", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, {
      ...CAPTURED_EVIDENCE,
      event_hash: `${PROOF.event.hash.slice(0, 63)}${
        PROOF.event.hash.endsWith("4") ? "5" : "4"
      }`,
    });

    expect(
      await checkWitnesses(SEAL_HASH, [entry], context(pin(alpha), ["nomankind"], {
        registry: PINNED_REGISTRY,
      })),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses nomankind's own sealing agent, whatever operator files it", async () => {
    // The paper makes nomankind ineligible, and the operator name is not enough:
    // the sealing agent's key is nomankind's however the directory lists it.
    const sealer = await makeParty("some-other-operator");

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [await countersign(sealer)],
        context(pin(sealer), ["nomankind"], {
          ineligibleAgents: new Set([sealer.agent]),
        }),
      ),
    ).toEqual({ ok: false, reason: "maintainer_witness", agent: sealer.agent });
  });
});

/**
 * The two-head case: a witness countersigned an earlier head than the one the
 * inclusion proof was fetched against, and a consistency proof closes the gap.
 * Over a generated log, because the capture holds no inclusion proof against
 * the later of its two heads (see the note above).
 */
describe("checkWitnesses, a head bridged to a later one", () => {
  const ORIGIN = "https://registry.test";
  const LOG = "identity_events";
  const SEALED_AT = 1788926203609;
  const EARLY_SIZE = 12;
  const LATE_SIZE = 20;
  const OUR_LEAF = 5;

  /** A head neither side of the bridge is: 16 leaves, between the two. */
  const MIDDLE_SIZE = 16;

  async function build(forward = false): Promise<{
    head: RegistryHead;
    evidence: WitnessEvidence;
    registry: { origin: string; public_key: string };
    /** The log itself, for the tests that need a third head of it. */
    leaves: string[];
    /** The registry's own signature over any head, for the same reason. */
    sign: (
      tree_size: number,
      root: string,
      created_at: number,
    ) => Promise<string>;
  }> {
    const registryKeys = await generateKeypair();
    const registryKey = base64urlEncode(
      await exportPublicKeyRaw(registryKeys.publicKey),
    );

    const eventHashes: string[] = [];
    for (let index = 0; index < LATE_SIZE; index += 1) {
      // A registry leaf's preimage is the event's chain hash as hex text.
      eventHashes.push(
        `${index.toString(16).padStart(2, "0")}${"ab".repeat(31)}`,
      );
    }
    const leaves = await Promise.all(eventHashes.map((hash) => leafOf(hash)));

    const earlyRoot = await rootOf(leaves.slice(0, EARLY_SIZE));
    const lateRoot = await rootOf(leaves);

    const sign = async (
      tree_size: number,
      root: string,
      created_at: number,
    ): Promise<string> =>
      base64urlEncode(
        await signBytes(
          registryKeys.privateKey,
          registryCheckpointPayload({ log: LOG, tree_size, root, created_at }),
        ),
      );

    const early = {
      tree_size: EARLY_SIZE,
      root: earlyRoot,
      created_at: SEALED_AT,
      registry_sig: await sign(EARLY_SIZE, earlyRoot, SEALED_AT),
    };
    const late = {
      tree_size: LATE_SIZE,
      root: lateRoot,
      created_at: SEALED_AT + 1,
      registry_sig: await sign(LATE_SIZE, lateRoot, SEALED_AT + 1),
    };

    // The countersigned head is the early one by default, and the late one when
    // the bridge runs forward — production's case, because the registry answers
    // an inclusion proof under the earliest head that covers the leaf. Either
    // way the inclusion is proved against the *other* head, and the one
    // consistency proof between the two closes the gap.
    const countersigned = forward ? late : early;
    const proved = forward ? early : late;

    return {
      head: {
        registry: ORIGIN,
        log: LOG,
        tree_size: countersigned.tree_size,
        root: countersigned.root,
        created_at: countersigned.created_at,
        registry_sig: countersigned.registry_sig,
      },
      evidence: {
        consistency: `verified from ${countersigned.tree_size - 1}`,
        leaf_index: OUR_LEAF,
        event_hash: eventHashes[OUR_LEAF]!,
        proof: await pathOf(
          leaves.slice(0, proved.tree_size),
          OUR_LEAF,
        ),
        proved_at: proved,
        consistency_proof: await consistencyOf(
          leaves.slice(0, LATE_SIZE),
          EARLY_SIZE,
        ),
      },
      registry: { origin: ORIGIN, public_key: registryKey },
      leaves,
      sign,
    };
  }

  it("accepts the countersigned head when the bridge and the inclusion hold", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build();

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [await countersignHead(alpha, head, evidence)],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: true, witnesses: [{ agent: alpha.agent, operator: "alpha" }] });
  });

  it("refuses a missing bridge between two different heads", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build();

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            consistency_proof: [],
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a bridge to a head the inclusion was not proved against", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build();
    const flipped = `${evidence.proved_at.root.slice(0, 63)}${
      evidence.proved_at.root.endsWith("f") ? "e" : "f"
    }`;

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            proved_at: { ...evidence.proved_at, root: flipped },
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  // -------------------------------------------------------------------------
  // The other direction, which is the one production is actually in: the
  // registry answers the inclusion proof under the earliest head that covers
  // the leaf, and the witness countersigned a head later than that.
  // -------------------------------------------------------------------------

  it("accepts a countersigned head later than the head the proof was fetched at", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build(true);

    expect(head.tree_size).toBeGreaterThan(evidence.proved_at.tree_size);
    expect(
      await checkWitnesses(
        SEAL_HASH,
        [await countersignHead(alpha, head, evidence)],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: true, witnesses: [{ agent: alpha.agent, operator: "alpha" }] });
  });

  it("refuses a forward bridge with no consistency proof at all", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build(true);

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            consistency_proof: [],
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a forward bridge whose path does not fold", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build(true);

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            // The right shape and the wrong hashes.
            consistency_proof: evidence.consistency_proof.map(() =>
              "0".repeat(64),
            ),
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a bridge that folds and lands on another root than the head's", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry, leaves, sign } = await build(true);

    // A head signed and countersigned in good order, and a bridge that really
    // does fold — onto the root of a third head, not this one's. Folding is not
    // the test; landing on the countersigned root is.
    const otherRoot = await rootOf(leaves.slice(0, MIDDLE_SIZE));
    expect(otherRoot).not.toBe(head.root);
    const substituted: RegistryHead = {
      ...head,
      root: otherRoot,
      registry_sig: await sign(head.tree_size, otherRoot, head.created_at),
    };

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [await countersignHead(alpha, substituted, evidence)],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a countersigned head that does not cover our leaf", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build(true);

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            leaf_index: head.tree_size,
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });

  it("refuses a forward-bridged first observation", async () => {
    const alpha = await makeParty("alpha");
    const { head, evidence, registry } = await build(true);

    expect(
      await checkWitnesses(
        SEAL_HASH,
        [
          await countersignHead(alpha, head, {
            ...evidence,
            consistency: "first observation",
          }),
        ],
        context(pin(alpha), ["nomankind"], { registry }),
      ),
    ).toEqual({ ok: false, reason: "bad_evidence", agent: alpha.agent });
  });
});

describe("witnessedCount", () => {
  /** A seal is only its hash and its countersignatures to this rule. */
  function sealWith(witnesses: WitnessSignature[]): Seal {
    return {
      seq: 0,
      first_seq: 0,
      last_seq: 1,
      size: 2,
      root: "sha256:0",
      sealed_at: "2026-09-08T00:00:00Z",
      prev_hash: null,
      hash: SEAL_HASH,
      witnesses,
      registry: null,
    };
  }

  it("counts distinct operators, not signatures", async () => {
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");
    const betaSecond = await makeParty("beta");

    expect(
      await witnessedCount(
        sealWith([
          await countersign(alpha),
          await countersign(beta),
          await countersign(betaSecond),
        ]),
        context(pin(alpha, beta, betaSecond)),
      ),
    ).toBe(2);
  });

  it("keeps counting past a signature it refuses", async () => {
    // Otherwise anyone could unwitness a seal by appending garbage to it.
    const alpha = await makeParty("alpha");
    const beta = await makeParty("beta");
    const stranger = await makeParty("stranger");
    const maintainer = await makeParty("nomankind");

    expect(
      await witnessedCount(
        sealWith([
          { agent: alpha.agent, signature: "not+base64url/=" },
          await countersign(beta),
          await countersign(stranger),
          await countersign(maintainer),
          await countersign(alpha),
        ]),
        context(pin(alpha, beta, maintainer)),
      ),
    ).toBe(2);
  });

  it("counts a registry-form countersignature like any other", async () => {
    const alpha = await makeParty("alpha");
    const entry = await countersignHead(alpha, CAPTURED_HEAD, CAPTURED_EVIDENCE);

    expect(
      await witnessedCount(
        sealWith([entry]),
        context(pin(alpha), ["nomankind"], { registry: PINNED_REGISTRY }),
      ),
    ).toBe(1);
    // And not at all without the registry pinned: the head is unverifiable.
    expect(await witnessedCount(sealWith([entry]), context(pin(alpha)))).toBe(0);
  });

  it("is zero on a seal nobody countersigned", async () => {
    const alpha = await makeParty("alpha");
    expect(await witnessedCount(sealWith([]), context(pin(alpha)))).toBe(0);
  });
});

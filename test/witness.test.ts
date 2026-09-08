import { describe, expect, it } from "vitest";

import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
// A countersignature's shape belongs to the seal it countersigns; the witness
// rule imports it rather than declaring a second one.
import type { WitnessSignature } from "../src/seal.js";
import {
  HASH_TAG_WITNESS,
  WITNESS_REFUSALS,
  checkWitnesses,
  signWitness,
  witnessSigningBytes,
  type Witness,
  type WitnessContext,
} from "../src/witness.js";

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
): WitnessContext {
  return { witnesses, maintainerOperators: new Set(maintainerOperators) };
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

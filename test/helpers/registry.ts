/**
 * What the registry tests need to act like a real operator: real keys, real
 * signatures, and a resolver that answers from a fixture instead of the DNS.
 *
 * Every key here is generated through WebCrypto and every signature is made by
 * it, so a test that passes says the Worker verified a real Ed25519 signature
 * and not that a stub agreed with itself. Only the network is faked, because
 * only the network is not ours to run in a test.
 */

import type { DnsResolver, TxtLookup } from "../../src/adapters/dns.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../../src/identity.js";
import { signAttestation } from "../../src/registry.js";
import { generateNonce, signRequest } from "../../src/request.js";
import type { Attestation } from "../../src/events.js";

/**
 * A DnsResolver reading from a map instead of the network.
 *
 * A name that is not in the map has no record (nxdomain); a name mapped to null
 * is a resolver that could not answer (unavailable). The two are separate on
 * purpose: the Worker turns one into a 422 and the other into a 503, and a
 * fixture that could not tell them apart could not test that.
 *
 * This is a test double and it lives in test/. src/ has one resolver,
 * DohResolver, and it is the real one on every environment (D-013).
 */
export class FixtureResolver implements DnsResolver {
  readonly #records: Map<string, string[] | null>;

  constructor(records: Record<string, string[] | null>) {
    this.#records = new Map(Object.entries(records));
  }

  async txt(name: string): Promise<TxtLookup> {
    if (!this.#records.has(name)) return { ok: false, reason: "nxdomain" };
    const values = this.#records.get(name);
    if (values === null || values === undefined) {
      return { ok: false, reason: "unavailable" };
    }
    return { ok: true, values };
  }
}

/** A keypair and the agent id its public half spells. */
export interface TestAgent {
  readonly agentId: string;
  readonly privateKey: CryptoKey;
}

/** A fresh agent: a real Ed25519 keypair and its 1F916 id. */
export async function makeAgent(): Promise<TestAgent> {
  const pair = await generateKeypair();
  const raw = await exportPublicKeyRaw(pair.publicKey);
  return { agentId: agentIdFromPublicKey(raw), privateKey: pair.privateKey };
}

/** The independence attestation, signed by this agent for this operator. */
export async function attestFor(
  agent: TestAgent,
  operator: string,
  signedAt: string,
): Promise<Attestation> {
  return signAttestation(agent.privateKey, {
    operator,
    agent: agent.agentId,
    signed_at: signedAt,
  });
}

/** The four authentication headers for one signed write (decision D-014). */
export async function signedHeaders(
  agent: TestAgent,
  input: {
    method: string;
    path: string;
    body: unknown;
    timestamp: string;
    nonce?: string;
  },
): Promise<Record<string, string>> {
  return signRequest({
    method: input.method,
    path: input.path,
    body: input.body,
    agentId: agent.agentId,
    privateKey: agent.privateKey,
    timestamp: input.timestamp,
    nonce: input.nonce ?? generateNonce(),
  });
}

/** The origin the tests sign against. Any host does: the signature is over the
 * path, never the host, so this is only what makes a Request constructible. */
export const TEST_ORIGIN = "https://nomankind.ai";

/**
 * A signed POST, ready to hand to the router.
 *
 * The nonce is a parameter because a replay test has to send the very same
 * signed request twice, and a Request's body can only be read once.
 */
export async function signedPost(
  agent: TestAgent,
  input: {
    path: string;
    body: unknown;
    timestamp: string;
    nonce?: string;
  },
): Promise<Request> {
  const headers = await signedHeaders(agent, {
    method: "POST",
    path: input.path,
    body: input.body,
    timestamp: input.timestamp,
    nonce: input.nonce,
  });
  return new Request(`${TEST_ORIGIN}${input.path}`, {
    method: "POST",
    body: JSON.stringify(input.body),
    headers: { ...headers, "content-type": "application/json" },
  });
}

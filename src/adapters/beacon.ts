/**
 * The public randomness beacon the draw reads.
 *
 * Lifecycle of an entry, Validate: "The draw is a deterministic function of a
 * public randomness beacon's output (a beacon like drand [5]), the entry id, and
 * a published snapshot of the eligible pool ... anyone can recompute who should
 * have been drawn, and neither the submitter nor the maintainer can steer it."
 *
 * That last clause is what this module has to earn. A round is not taken on the
 * endpoint's word: drand defines a round's randomness as the SHA-256 of its
 * signature bytes, so the randomness is recomputed here from the signature and a
 * round that does not match its own signature is refused. A maintainer who could
 * hand the draw an invented randomness could steer it, and this is the check
 * that stops the maintainer's own server from doing exactly that.
 *
 * Which chain is read is src/policy.ts's BEACON and nothing here; this module
 * holds no endpoint, no chain hash and no number of its own.
 *
 * The read is bounded by src/policy.ts's FETCH_TIMEOUT_MS, as every other
 * outbound call in the system is: a chain endpoint that accepts the connection
 * and then never answers would otherwise hold the whole sweep open behind it,
 * and every step after the draw with it.
 *
 * `latest` never throws. A beacon that cannot be reached and one that answers
 * something unusable are different answers — one is the network's fault and the
 * other is the chain's — and the sweep that calls this records the difference
 * rather than crashing on either.
 *
 * WebCrypto through src/hash.ts, so this runs unchanged on a Worker.
 */

import type { Beacon } from "../assign.js";
import { sha256Hex } from "../hash.js";
import { BEACON, FETCH_TIMEOUT_MS } from "../policy.js";

/** A round, or why the beacon could not give one. */
export type BeaconResult =
  | { ok: true; beacon: Beacon }
  | { ok: false; reason: "beacon_unavailable" | "bad_beacon" };

/** Somewhere to ask for the newest beacon round. */
export interface BeaconReader {
  latest(): Promise<BeaconResult>;
}

const UNAVAILABLE: BeaconResult = { ok: false, reason: "beacon_unavailable" };
const BAD_BEACON: BeaconResult = { ok: false, reason: "bad_beacon" };

/** A round's randomness, as drand publishes it: 64 lowercase hex characters. */
const RANDOMNESS = /^[0-9a-f]{64}$/;

/** Hex, in the same lowercase form every hash in this system is written in. */
const HEX_BYTES = /^(?:[0-9a-f]{2})+$/;

/** The status range an answer is read from: 2xx and nothing else. */
const OK_MIN = 200;
const OK_MAX = 299;

/** A unit constant, not a policy number: drand states its times in seconds. */
const MILLISECONDS_PER_SECOND = 1000;

/** What the chain's `public/latest` answers, before anything is believed. */
interface LatestBody {
  readonly round?: unknown;
  readonly randomness?: unknown;
  readonly signature?: unknown;
}

/**
 * The time of a round, from the chain's genesis and period alone.
 *
 * Round 1 is the genesis round, so round n is (n - 1) periods after it. Computed
 * rather than read off the answer: the time is what orders a snapshot before the
 * round that used it, and taking it from the same body that carries the
 * randomness would let one server move both together.
 */
export function beaconRoundAt(round: number): string {
  const seconds = BEACON.genesis_time + (round - 1) * BEACON.period_seconds;
  return new Date(seconds * MILLISECONDS_PER_SECOND).toISOString();
}

/** Hex to bytes, or null when the string is not whole lowercase hex. */
function fromHex(hex: string): Uint8Array | null {
  if (!HEX_BYTES.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * The reader the Worker runs: drand's v1 chain path over an injected fetch.
 *
 * The v1 path is the one that carries `randomness` beside the signature, which
 * is what makes the round checkable without a BLS verifier: the randomness is
 * the SHA-256 of the signature bytes, and this recomputes it.
 */
export class DrandReader implements BeaconReader {
  readonly #fetch: typeof fetch;
  /**
   * How long the read may take before it is given up on. The policy number
   * everywhere but in a test, which passes a small window of its own rather than
   * waiting thirty seconds to watch one expire.
   */
  readonly #timeoutMs: number;

  /**
   * The default is the platform's own fetch, and the call below reads it out of
   * the field first so it goes out with no receiver: workerd throws "Illegal
   * invocation" when a platform fetch is called on anything but the global
   * object, and Node's does not, which is why only a real deployment showed it
   * (the M13 lesson).
   */
  constructor(
    fetchFn: typeof fetch = globalThis.fetch,
    timeoutMs = FETCH_TIMEOUT_MS,
  ) {
    this.#fetch = fetchFn;
    this.#timeoutMs = timeoutMs;
  }

  /** The chain's newest round, checked against its own signature. */
  async latest(): Promise<BeaconResult> {
    const call = this.#fetch;
    const url = `${BEACON.endpoint}/${BEACON.chain_hash}/public/latest`;

    let body: LatestBody;
    try {
      const response = await call(url, {
        method: "GET",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      if (response.status < OK_MIN || response.status > OK_MAX) {
        return UNAVAILABLE;
      }
      body = (await response.json()) as LatestBody;
    } catch {
      // A thrown fetch, a chain that never answered and the timeout gave up on,
      // a body that is not JSON: all of them are "we could not ask".
      return UNAVAILABLE;
    }

    try {
      return await check(body);
    } catch {
      return UNAVAILABLE;
    }
  }
}

/** Everything the answer has to say about itself before it is believed. */
async function check(body: LatestBody): Promise<BeaconResult> {
  const { round, randomness, signature } = body;
  if (typeof round !== "number" || !Number.isInteger(round) || round <= 0) {
    return BAD_BEACON;
  }
  if (typeof randomness !== "string" || !RANDOMNESS.test(randomness)) {
    return BAD_BEACON;
  }
  if (typeof signature !== "string") return BAD_BEACON;

  const bytes = fromHex(signature);
  if (bytes === null) return BAD_BEACON;
  if ((await sha256Hex(bytes)) !== randomness) return BAD_BEACON;

  return { ok: true, beacon: { round, randomness, at: beaconRoundAt(round) } };
}

/**
 * A beacon for tests, and for tests only.
 *
 * Decision D-013 as amended keeps fakes out of the production path, so nothing
 * in the Worker constructs this: it exists so a test can advance the chain a
 * round at a time and watch the draw move with it, without a packet leaving the
 * machine. The rounds it produces satisfy the same shape a real round does — a
 * positive round number and 64 lowercase hex characters of randomness — because
 * a fixture that could not pass the real check would be testing nothing.
 *
 * The randomness is the SHA-256 of `<seed>:<round>`, which is not drand's
 * construction and is not meant to be: it is a fixture, and the one property it
 * owes is that the same seed and round always give the same round back.
 */
export class FixtureBeacon implements BeaconReader {
  readonly #seed: string;
  #round = 0;
  #latest: Beacon | null = null;

  constructor(seed: string) {
    this.#seed = seed;
  }

  /**
   * Advance the chain one round, at the time the caller names.
   *
   * The time is the caller's because a fixture has no clock of its own: the
   * tests inject time everywhere it matters, and a snapshot has to be committed
   * before the round that uses it, which is a fact about the two times the test
   * chooses.
   *
   * Async because the randomness is a real SHA-256 through WebCrypto, which is
   * the only digest this system has and is a promise on every runtime.
   */
  async advance(at: string): Promise<Beacon> {
    this.#round += 1;
    const randomness = await sha256Hex(`${this.#seed}:${this.#round}`);
    this.#latest = { round: this.#round, randomness, at };
    return this.#latest;
  }

  /** The newest advanced round, or unavailable before the first advance. */
  async latest(): Promise<BeaconResult> {
    return this.#latest === null ? UNAVAILABLE : { ok: true, beacon: this.#latest };
  }
}

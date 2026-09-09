/**
 * The witness adapter: the seal's fingerprint out to the founding registry, and
 * the pinned witnesses' countersignatures back.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): the seal hash is sealed as a
 * memory fingerprint into nomankind's own citizen log at the founding 1F916
 * registry, and witnesses nomankind does not control countersign the registry's
 * head. "Limitations" ("The identity layer is young") sets the bar for who may
 * countersign: published keys, no two witnesses under common control, and
 * nomankind itself ineligible.
 *
 * This module does the I/O and none of the judging. It gathers what a witness
 * published and hands it to src/witness.ts's rule, which decides whether any of
 * it counts; a signature this file returns is a claim, never a verdict. Every
 * number it obeys — which registry, which witnesses, how much of a file to
 * read, how long to wait — is src/policy.ts's.
 *
 * Three properties this file has to keep:
 *
 * Nothing throws. The sweep runs on a timer and a seal that could not reach the
 * registry is a seal without a receipt, not a crashed sweep. Every path answers
 * null or an empty list.
 *
 * Nothing leaks. The bearer credential and the sealing key never appear in a
 * returned value, a thrown value or a log line — which is why failures here are
 * bare nulls and carry no message about what went wrong.
 *
 * Code never follows a moved key. The registry's directory is a pointer, not an
 * endorsement, so it is consulted only to check that a pinned row still says
 * what the pin says; a row that moved is dropped for the run and the
 * orchestrator re-pins by decision.
 *
 * The platform fetch is read out of the field before it is called, so it goes
 * out with no receiver: workerd throws "Illegal invocation" when a platform
 * fetch is called on anything but the global object, and Node's does not (the
 * M13 lesson, and the same shape src/adapters/beacon.ts uses).
 */

import { base64urlDecode, base64urlEncode } from "../encoding.js";
import {
  AGENT_ID_PREFIX,
  agentIdFromPublicKey,
  importPrivateKeyPkcs8,
  signBytes,
  verifyBytes,
} from "../identity.js";
import {
  FETCH_TIMEOUT_MS,
  REGISTRY,
  WITNESS_FILE_TAIL_BYTES,
  WITNESS_PIN,
} from "../policy.js";
import {
  isHex64,
  registryCheckpointPayload,
  registryLeafHash,
  registryWitnessPayload,
  verifyRegistryConsistency,
  verifyRegistryInclusion,
} from "../registry-proof.js";
import type {
  RegistrySeal,
  Seal,
  WitnessAdapter,
  WitnessSignature,
} from "../seal.js";
import { signWitness, type Witness } from "../witness.js";
import type { Env } from "../worker/env.js";
import { PRODUCTION } from "./payout.js";

/** Which registry track an environment's adapter is on. */
export type WitnessAdapterKind = "mock" | "registry" | "unavailable";

/** A witness adapter that says which track it is. */
export interface EnvironmentWitnessAdapter extends WitnessAdapter {
  readonly kind: WitnessAdapterKind;
  /**
   * A corrected registry record for a stored one that does not name the identity
   * event anchoring the seal, and null when the stored record needs none.
   *
   * Optional, because only a track with a registry has a record to correct. The
   * sweep persists whatever comes back before it asks for a proof, so a seal
   * stored under an earlier reading heals on a sweep run rather than a
   * migration.
   */
  heal?(seal: Seal): Promise<RegistrySeal | null>;
}

/**
 * The pinned set an environment judges countersignatures against: the witnesses
 * themselves and, on the registry track, the registry whose head they sign.
 * Null registry means the set only ever signs the direct form (the mock), and
 * src/witness.ts refuses a head offered against it.
 */
export interface PinnedWitnesses {
  witnesses: readonly Witness[];
  registry: { origin: string; public_key: string } | null;
}

/** One pinned witness row, as src/policy.ts's WITNESS_PIN holds it. */
export interface WitnessPin {
  id: number;
  operator: string;
  public_key: string;
  url: string;
}

/**
 * The two throwaway Ed25519 private keys (PKCS#8, unpadded base64url) the mock
 * witness set signs with on local and demo.
 *
 * Published on purpose and worth nothing: they are in a public repository, so
 * anyone can forge a mock countersignature, which is exactly what a mock is
 * for. They are never used on production — `witnessAdapterFor` gives production
 * the registry adapter or none at all — and a seal countersigned by them proves
 * only that the plumbing ran.
 */
export const MOCK_WITNESS_KEYS: readonly string[] = Object.freeze([
  "MC4CAQAwBQYDK2VwBCIEIJaO67npowbV2-UH6_ukMca-xiZLXxM6TdOaXHPKpKSi",
  "MC4CAQAwBQYDK2VwBCIEIEd_b8x7PzcPj9iPmFjMsusZxkjCLbVLSWh0E1BLf3wB",
]);

/** The public halves of MOCK_WITNESS_KEYS, in the same order. */
const MOCK_WITNESS_PUBLIC_KEYS: readonly string[] = Object.freeze([
  "CBtuT6Z72V_W528bwI0J4Iz90yaNovnwpLQH_gCl4DA",
  "wbikOv3WpsHwdazCVTRKYeg8r5AHCxfBHvKHJroY9gs",
]);

/**
 * The mock witness set: two agents under two operators, so the distinctness
 * rule (D-033) is exercised on a laptop rather than only in production. The
 * operators are `.example` names, which can never be registrable domains.
 */
export const MOCK_WITNESSES: readonly Witness[] = Object.freeze([
  Object.freeze({
    agent: AGENT_ID_PREFIX + MOCK_WITNESS_PUBLIC_KEYS[0]!,
    operator: "mock-witness-a.example",
  }),
  Object.freeze({
    agent: AGENT_ID_PREFIX + MOCK_WITNESS_PUBLIC_KEYS[1]!,
    operator: "mock-witness-b.example",
  }),
]);

/**
 * The pinned set for an environment (decision D-054 for production).
 *
 * Witness agent ids are built the way src/identity.ts builds every agent id:
 * "1F916:" plus the unpadded base64url of the raw public key (D-014). The
 * directory's `public_key` column is already in that encoding, so the id is a
 * concatenation and never a re-encoding.
 */
export function pinnedWitnessesFor(environment: string): PinnedWitnesses {
  if (environment !== PRODUCTION) {
    return { witnesses: MOCK_WITNESSES, registry: null };
  }
  return {
    witnesses: WITNESS_PIN.map((row) => ({
      agent: AGENT_ID_PREFIX + row.public_key,
      operator: row.operator,
    })),
    registry: { origin: REGISTRY.origin, public_key: REGISTRY.public_key },
  };
}

/**
 * The mock for local and demo (decision D-013 as amended). It signs the direct
 * form — the seal hash itself — because there is no registry head to sign, and
 * it never submits anything, so `seal` is null and the seal keeps no receipt.
 */
export class MockWitnessAdapter implements EnvironmentWitnessAdapter {
  readonly kind = "mock";

  async seal(_seal: Seal, _now: Date): Promise<RegistrySeal | null> {
    return null;
  }

  async collect(seal: Seal, _now?: Date): Promise<WitnessSignature[]> {
    const signatures: WitnessSignature[] = [];
    for (let index = 0; index < MOCK_WITNESS_KEYS.length; index += 1) {
      const key = await importPrivateKeyPkcs8(
        base64urlDecode(MOCK_WITNESS_KEYS[index]!),
      );
      signatures.push({
        agent: MOCK_WITNESSES[index]!.agent,
        signature: await signWitness(key, seal.hash),
      });
    }
    return signatures;
  }
}

/**
 * Production before the citizen is registered, and any production without both
 * secrets: the registry track is simply not available.
 *
 * It answers nothing rather than a mock, for the reason the payout stub answers
 * "unavailable" rather than "verified": a fake countersignature on production
 * would be a seal claiming a witness it never had. A seal with no witnesses is
 * an honest seal; a seal with invented ones is not.
 */
export class UnavailableWitnessAdapter implements EnvironmentWitnessAdapter {
  readonly kind = "unavailable";

  async seal(_seal?: Seal, _now?: Date): Promise<RegistrySeal | null> {
    return null;
  }

  async collect(_seal?: Seal, _now?: Date): Promise<WitnessSignature[]> {
    return [];
  }
}

/** The User-Agent every call from this adapter carries. A wire fact, not policy. */
const USER_AGENT = "nomankind";

/** The tag the registry's seal endpoint signs over. A format constant. */
const SEAL_PAYLOAD_TAG = "1f916.seal.v1";

/** The status a re-seal of the same hash under the same label answers. */
const CONFLICT = 409;

/** The status a ranged read answers when it really returned a tail. */
const PARTIAL_CONTENT = 206;

/**
 * The status a suffix range answers when the file is smaller than the range.
 * raw.githubusercontent.com does this rather than sending the whole file: on
 * 2026-09-09 two of the three pinned files were under the tail (227,928 and
 * 141,875 bytes against a 262,144-byte tail) and answered 416.
 */
const RANGE_NOT_SATISFIABLE = 416;

/** The consistency field a witness line carries when it really checked one. */
const VERIFIED_FROM = "verified from";

/** The status a witness line carries when it really countersigned. */
const COUNTERSIGNED = "countersigned";

/** The kind an identity event carries when it anchors a sealed fingerprint. */
const MEMORY_SEAL = "memory.seal";

/**
 * How many pages of the citizen record's events are walked while looking for one
 * seal's identity event. Not a policy number: it is a loop guard, so a registry
 * that paged forever could not hang the sweep.
 */
const MAX_RECORD_PAGES = 10;

const encoder = new TextEncoder();

/** The hex a "sha256:<hex>" hash carries, or null when it carries none. */
function fingerprintOf(hash: string): string | null {
  const prefix = "sha256:";
  if (typeof hash !== "string" || !hash.startsWith(prefix)) return null;
  const hex = hash.slice(prefix.length);
  return isHex64(hex) ? hex : null;
}

/** A plain object, or null. Everything off a wire is checked before it is read. */
function objectOf(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringOf(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function integerOf(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

/** A path of registry hashes, or null when any element is not one. */
function hexPathOf(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return value.every(isHex64) ? [...(value as string[])] : null;
}

/**
 * The identity event id the seal response names, in the order the registry
 * spells it: `event_id`, then `event.id`.
 *
 * The response's bare `id` is deliberately not read. It is the row id of the
 * seal in the registry's own seals table, not the identity event that anchors
 * it, and reading it as an event id is what left production's seals asking for
 * a proof of an unrelated event. The anchoring event's id lives in the citizen
 * record, and `#anchoringEvent` is the only thing that resolves it.
 */
function eventIdOf(receipt: unknown): number | null {
  const body = objectOf(receipt);
  if (body === null) return null;
  const direct = integerOf(body["event_id"]);
  if (direct !== null) return direct;
  const event = objectOf(body["event"]);
  if (event !== null) {
    const nested = integerOf(event["id"]);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * The hash of the identity event the seal response chained, or null when it
 * names none.
 *
 * `chained` is what the registry actually answers with; `event_hash` and
 * `event.hash` are kept as fallbacks so a response that spells it either of
 * those older ways is still read.
 */
function eventHashOf(receipt: unknown): string | null {
  const body = objectOf(receipt);
  if (body === null) return null;
  if (isHex64(body["chained"])) return body["chained"];
  if (isHex64(body["event_hash"])) return body["event_hash"];
  const event = objectOf(body["event"]);
  if (event !== null && isHex64(event["hash"])) return event["hash"];
  return null;
}

/** The registry's proof answer, once every field has been checked. */
interface CheckedProof {
  eventHash: string;
  leafIndex: number;
  treeSize: number;
  root: string;
  createdAt: number;
  registrySig: string;
  path: string[];
}

/** One usable line of a witness's published file, once every field is checked. */
interface CheckedLine {
  treeSize: number;
  root: string;
  createdAt: number;
  registrySig: string;
  witnessSig: string;
  consistency: string;
}

/** What the registry adapter needs to be built. */
export interface RegistryWitnessOptions {
  fetch?: typeof fetch;
  origin?: string;
  registryPublicKey?: string;
  log?: string;
  label?: string;
  handle: string;
  credential: string;
  privateKeyPkcs8: string;
  pin?: readonly WitnessPin[];
  tailBytes?: number;
}

/**
 * Production's adapter: the founding 1F916 registry and the pinned witnesses'
 * published files.
 *
 * `seal` submits the fingerprint and keeps whatever came back. `collect` walks
 * the three steps a countersignature has to survive before it is worth
 * offering: the pin still matches the directory, our event is provably a leaf
 * under a head the registry signed, and a pinned witness signed that head (or
 * another head of the same log, on either side of it, bridged by a consistency
 * proof). Everything is verified here as well as by the rule, because an
 * unverifiable claim is not worth storing.
 */
export class RegistryWitnessAdapter implements EnvironmentWitnessAdapter {
  readonly kind = "registry";

  readonly #fetch: typeof fetch;
  readonly #origin: string;
  readonly #registryPublicKey: string;
  readonly #log: string;
  readonly #label: string;
  readonly #handle: string;
  readonly #credential: string;
  readonly #privateKeyPkcs8: string;
  readonly #pin: readonly WitnessPin[];
  readonly #tailBytes: number;

  constructor(options: RegistryWitnessOptions) {
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#origin = options.origin ?? REGISTRY.origin;
    this.#registryPublicKey = options.registryPublicKey ?? REGISTRY.public_key;
    this.#log = options.log ?? REGISTRY.log;
    this.#label = options.label ?? REGISTRY.seal_label;
    this.#handle = options.handle;
    this.#credential = options.credential;
    this.#privateKeyPkcs8 = options.privateKeyPkcs8;
    this.#pin = options.pin ?? WITNESS_PIN;
    this.#tailBytes = options.tailBytes ?? WITNESS_FILE_TAIL_BYTES;
  }

  /**
   * Every call goes through here, so every call gets the timeout, the
   * User-Agent, and a receiver-free invocation. A failure is null and says
   * nothing about itself: the error a fetch throws can carry a request's own
   * headers, and one of ours is a bearer credential.
   */
  async #call(url: string, init: RequestInit): Promise<Response | null> {
    const call = this.#fetch;
    try {
      return await call(url, {
        ...init,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return null;
    }
  }

  /** A GET whose body is JSON, or null on any failure at all. */
  async #json(url: string): Promise<unknown | null> {
    const response = await this.#call(url, {
      method: "GET",
      headers: { accept: "application/json", "user-agent": USER_AGENT },
    });
    if (response === null || !response.ok) return null;
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  async seal(seal: Seal, now: Date): Promise<RegistrySeal | null> {
    try {
      return await this.#seal(seal, now);
    } catch {
      return null;
    }
  }

  async #seal(seal: Seal, now: Date): Promise<RegistrySeal | null> {
    const fingerprint = fingerprintOf(seal.hash);
    if (fingerprint === null) return null;

    const payload = `${SEAL_PAYLOAD_TAG}:${this.#handle}:${this.#label}:${fingerprint}`;
    const key = await importPrivateKeyPkcs8(
      base64urlDecode(this.#privateKeyPkcs8),
    );
    const signature = base64urlEncode(
      await signBytes(key, encoder.encode(payload)),
    );

    const response = await this.#call(`${this.#origin}/api/seal`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: `Bearer ${this.#credential}`,
        "user-agent": USER_AGENT,
      },
      body: JSON.stringify({
        hash: fingerprint,
        label: this.#label,
        signature,
      }),
    });
    if (response === null) return null;
    if (!response.ok && response.status !== CONFLICT) return null;

    let receipt: unknown = null;
    try {
      receipt = await response.json();
    } catch {
      receipt = null;
    }

    // A 409 means the hash is already sealed under this label, which is a
    // success from where the sweep stands: the fingerprint is in the log. Its
    // body names the conflict rather than the event, so both readings come back
    // null and the record resolves the event, exactly as a 200 that named only
    // the chained hash does.
    const chained = eventHashOf(receipt);
    const named = eventIdOf(receipt);

    // The response is trusted only when it named the event both ways. Otherwise
    // the anchoring event is resolved from the citizen record, which is the only
    // place the identity log's own id and hash are published together.
    const anchoring =
      named !== null && chained !== null
        ? { id: named, hash: chained }
        : await this.#anchoringEvent(fingerprint, chained);

    // A record that does not list the event yet keeps the chained hash and no
    // id: the witness step resolves it on a later run. Storing the seal row id
    // here is what asked for a proof of an unrelated event.
    return {
      registry: this.#origin,
      handle: this.#handle,
      label: this.#label,
      event_id: anchoring?.id ?? null,
      event_hash: anchoring?.hash ?? chained,
      receipt,
      sealed_at: now.toISOString(),
    };
  }

  /**
   * The `memory.seal` identity event that anchors one fingerprint, from the
   * citizen's own record: the id the identity log knows it by, and its hash.
   *
   * The record is the authority because it is the only response that publishes
   * both together — the seal response carries the chained hash but no identity
   * event id, and the seals listing carries a seal row id and no chain hash. The
   * event is matched by hash when the seal response chained one, and by the
   * fingerprint *and* the label its `detail` names when it did not (a 409, whose
   * body names the conflict and nothing else) — both, because the same
   * fingerprint sealed under a second label is a second event, and the record
   * this seal names is the one under this seal's label.
   *
   * Paged with the parameter this route publishes, `events_since`, while
   * `events_has_more` says there is more; a record that stops answering, or that
   * still has not listed the event, is null rather than a guess.
   */
  async #anchoringEvent(
    fingerprint: string,
    chained: string | null,
  ): Promise<{ id: number; hash: string } | null> {
    const base = `${this.#origin}/api/record/${encodeURIComponent(this.#handle)}`;
    // Both halves of what the event's `detail` says about a seal, matched
    // independently so the registry may spell them in either order.
    const sealed = `sha256=${fingerprint}`;
    const labelled = `label='${this.#label}'`;

    let since: number | null = null;
    for (let page = 0; page < MAX_RECORD_PAGES; page += 1) {
      const url = since === null ? base : `${base}?events_since=${since}`;
      const body = objectOf(await this.#json(url));
      if (body === null) return null;

      const rows = body["events"];
      if (!Array.isArray(rows)) return null;

      let last: number | null = null;
      for (const row of rows) {
        const event = objectOf(row);
        if (event === null) continue;
        const id = integerOf(event["id"]);
        if (id === null) continue;
        last = id;
        if (event["kind"] !== MEMORY_SEAL) continue;

        const hash = event["hash"];
        if (!isHex64(hash)) continue;
        const detail = stringOf(event["detail"]) ?? "";
        const matched =
          chained !== null
            ? hash === chained
            : detail.includes(sealed) && detail.includes(labelled);
        if (matched) return { id, hash };
      }

      if (body["events_has_more"] !== true) return null;
      if (last === null || last === since) return null;
      since = last;
    }
    return null;
  }

  async collect(seal: Seal, _now: Date): Promise<WitnessSignature[]> {
    try {
      return await this.#collect(seal);
    } catch {
      return [];
    }
  }

  /**
   * A registry record corrected to name the identity event that anchors the
   * seal, or null when the stored one already names it (and null when it cannot
   * be corrected right now, because a registry that did not answer is a seal
   * still waiting rather than a record to overwrite).
   *
   * This is the healing path for the seals stored before the seal row id and the
   * identity event id were told apart: nothing is migrated, and the sweep
   * persists what this returns before it asks for a proof.
   */
  async heal(seal: Seal): Promise<RegistrySeal | null> {
    try {
      return await this.#heal(seal);
    } catch {
      return null;
    }
  }

  async #heal(seal: Seal): Promise<RegistrySeal | null> {
    const stored = seal.registry;
    if (stored === null) return null;

    const anchored = await this.#anchored(seal, stored);
    if (anchored === null) return null;
    if (
      stored.event_id === anchored.id &&
      stored.event_hash === anchored.proof.eventHash
    ) {
      return null;
    }
    return {
      ...stored,
      event_id: anchored.id,
      event_hash: anchored.proof.eventHash,
    };
  }

  /**
   * The proof that places the seal's anchoring identity event in the log.
   *
   * The stored record is believed only when it names both an id and a hash and
   * the proof for that id really is that event. Anything else — no id, no hash,
   * or a proof for some other event, which is exactly what a stored seal row id
   * answers — is re-resolved from the citizen record by the seal's own
   * fingerprint, and the proof is then checked against the hash the record
   * published rather than against whatever the proof endpoint returned.
   */
  async #anchored(
    seal: Seal,
    stored: RegistrySeal,
  ): Promise<{ id: number; proof: CheckedProof } | null> {
    const storedId = stored.event_id;
    const storedHash = stored.event_hash;
    if (storedId !== null && storedHash !== null) {
      const proof = await this.#provenLeaf(storedId);
      if (proof !== null && proof.eventHash === storedHash) {
        return { id: storedId, proof };
      }
    }

    const fingerprint = fingerprintOf(seal.hash);
    if (fingerprint === null) return null;
    const resolved = await this.#anchoringEvent(fingerprint, storedHash);
    if (resolved === null) return null;

    const proof = await this.#provenLeaf(resolved.id);
    if (proof === null || proof.eventHash !== resolved.hash) return null;
    return { id: resolved.id, proof };
  }

  async #collect(seal: Seal): Promise<WitnessSignature[]> {
    const registrySeal = seal.registry;
    if (registrySeal === null) return [];

    const pin = await this.#stillPinned();
    if (pin.length === 0) return [];

    const anchored = await this.#anchored(seal, registrySeal);
    if (anchored === null) return [];
    const proof = anchored.proof;

    const signatures: WitnessSignature[] = [];
    for (const witness of pin) {
      const signature = await this.#countersignature(witness, proof);
      if (signature !== null) signatures.push(signature);
    }
    return signatures;
  }

  /**
   * The pinned rows the registry's directory still agrees with.
   *
   * The directory is a pointer and never an endorsement, so this is the only
   * thing it is ever asked: does row 6 still carry the key we pinned? A row
   * that is missing, or whose key moved, is dropped for this run — following it
   * would be trusting the directory to name our witnesses, which is precisely
   * what pinning refuses to do.
   */
  async #stillPinned(): Promise<WitnessPin[]> {
    const body = objectOf(await this.#json(`${this.#origin}/api/witnesses`));
    if (body === null) return [];
    const rows = body["witnesses"];
    if (!Array.isArray(rows)) return [];

    const published = new Map<number, string>();
    for (const row of rows) {
      const entry = objectOf(row);
      if (entry === null) continue;
      const id = integerOf(entry["id"]);
      const key = stringOf(entry["public_key"]);
      if (id === null || key === null) continue;
      published.set(id, key);
    }

    return this.#pin.filter((row) => published.get(row.id) === row.public_key);
  }

  /**
   * Our seal's identity event as a leaf under a head the registry signed.
   *
   * Both halves are checked here rather than taken on the endpoint's word: the
   * checkpoint's own signature under the pinned registry key, and the inclusion
   * path folded locally. A proof this adapter could not verify is a proof no
   * reader could either, and storing it would only move the failure later.
   */
  async #provenLeaf(eventId: number): Promise<CheckedProof | null> {
    const body = objectOf(
      await this.#json(
        `${this.#origin}/api/proof?log=${encodeURIComponent(this.#log)}` +
          `&event=${eventId}`,
      ),
    );
    if (body === null) return null;
    if (body["log"] !== this.#log) return null;

    const event = objectOf(body["event"]);
    const checkpoint = objectOf(body["checkpoint"]);
    if (event === null || checkpoint === null) return null;

    const eventHash = event["hash"];
    const leafIndex = integerOf(event["leaf_index"]);
    const treeSize = integerOf(checkpoint["tree_size"]);
    const root = checkpoint["root"];
    const createdAt = integerOf(checkpoint["created_at"]);
    const registrySig = stringOf(checkpoint["sig"]);
    const path = hexPathOf(body["proof"]);
    if (!isHex64(eventHash) || !isHex64(root)) return null;
    if (leafIndex === null || treeSize === null || createdAt === null) {
      return null;
    }
    if (registrySig === null || path === null) return null;

    const head = {
      treeSize,
      root,
      createdAt,
      registrySig,
    };
    if (!(await this.#headIsSigned(head))) return null;

    const included = await verifyRegistryInclusion({
      leafHash: await registryLeafHash(eventHash),
      leafIndex,
      treeSize,
      path,
      root,
    });
    if (!included) return null;

    return { eventHash, leafIndex, treeSize, root, createdAt, registrySig, path };
  }

  /** Whether the pinned registry key signed this head's checkpoint payload. */
  async #headIsSigned(head: {
    treeSize: number;
    root: string;
    createdAt: number;
    registrySig: string;
  }): Promise<boolean> {
    let key: Uint8Array;
    let signature: Uint8Array;
    try {
      key = base64urlDecode(this.#registryPublicKey);
      signature = base64urlDecode(head.registrySig);
    } catch {
      return false;
    }
    return verifyBytes(
      key,
      registryCheckpointPayload({
        log: this.#log,
        tree_size: head.treeSize,
        root: head.root,
        created_at: head.createdAt,
      }),
      signature,
    );
  }

  /** One witness's newest usable countersignature, or null when it has none. */
  async #countersignature(
    witness: WitnessPin,
    proof: CheckedProof,
  ): Promise<WitnessSignature | null> {
    const line = await this.#newestLine(witness, proof);
    if (line === null) return null;

    let witnessKey: Uint8Array;
    let signature: Uint8Array;
    try {
      witnessKey = base64urlDecode(witness.public_key);
      signature = base64urlDecode(line.witnessSig);
    } catch {
      return null;
    }

    const countersigned = await verifyBytes(
      witnessKey,
      registryWitnessPayload({
        registry: this.#origin,
        log: this.#log,
        tree_size: line.treeSize,
        root: line.root,
      }),
      signature,
    );
    if (!countersigned) return null;

    const bridge = await this.#bridge(line, proof);
    if (bridge === null) return null;

    return {
      agent: AGENT_ID_PREFIX + witness.public_key,
      signature: line.witnessSig,
      head: {
        registry: this.#origin,
        log: this.#log,
        tree_size: line.treeSize,
        root: line.root,
        created_at: line.createdAt,
        registry_sig: line.registrySig,
      },
      evidence: {
        consistency: line.consistency,
        leaf_index: proof.leafIndex,
        event_hash: proof.eventHash,
        proof: proof.path,
        proved_at: {
          tree_size: proof.treeSize,
          root: proof.root,
          created_at: proof.createdAt,
          registry_sig: proof.registrySig,
        },
        consistency_proof: bridge,
      },
    };
  }

  /**
   * The largest usable head in a witness's published file.
   *
   * The files are append-only and already hundreds of kilobytes, so only the
   * tail is read; on a 206 the first line is whatever the range landed inside
   * of and is dropped unparsed. A file smaller than the tail is not a tail at
   * all: raw.githubusercontent.com answers 416 rather than sending what it has,
   * so that file is read again without a range and every line of it is whole.
   * Lines for other logs, and lines that refuse (any status but
   * "countersigned", or a first observation rather than a verified consistency)
   * are exactly the lines this must not return: a first observation attests
   * nothing about what came before it, which is the whole guarantee being
   * borrowed.
   */
  async #newestLine(
    witness: WitnessPin,
    proof: CheckedProof,
  ): Promise<CheckedLine | null> {
    const ranged = await this.#call(witness.url, {
      method: "GET",
      headers: {
        "user-agent": USER_AGENT,
        range: `bytes=-${this.#tailBytes}`,
      },
    });
    if (ranged === null) return null;

    // A 416 means the file is shorter than the tail asked for, so ask for the
    // file itself; anything else it answers is the answer.
    const response =
      ranged.status === RANGE_NOT_SATISFIABLE
        ? await this.#call(witness.url, {
            method: "GET",
            headers: { "user-agent": USER_AGENT },
          })
        : ranged;
    if (response === null || !response.ok) return null;

    let text: string;
    try {
      text = await response.text();
    } catch {
      return null;
    }

    const lines = text.split("\n");
    // A 200 means the server ignored the range and sent the whole file, so the
    // first line is whole; a 206 means it sent a tail, and the first line is a
    // fragment of whatever record the byte offset fell inside.
    const usable = response.status === PARTIAL_CONTENT ? lines.slice(1) : lines;

    let newest: CheckedLine | null = null;
    for (const raw of usable) {
      const line = this.#readLine(raw, witness, proof);
      if (line === null) continue;
      if (newest === null || line.treeSize > newest.treeSize) newest = line;
    }
    return newest;
  }

  /** One line of a witness file, or null when it is not one we may use. */
  #readLine(
    raw: string,
    witness: WitnessPin,
    proof: CheckedProof,
  ): CheckedLine | null {
    const trimmed = raw.trim();
    if (trimmed === "") return null;

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return null;
    }
    const line = objectOf(parsed);
    if (line === null) return null;

    if (line["type"] !== "witness-countersignature") return null;
    if (line["registry"] !== this.#origin) return null;
    if (line["log"] !== this.#log) return null;
    if (line["status"] !== COUNTERSIGNED) return null;

    const consistency = stringOf(line["consistency"]);
    if (consistency === null || !consistency.startsWith(VERIFIED_FROM)) {
      return null;
    }

    // The key is checked when the line names one: a witness that rotated has
    // lines under the old key in the same file, and one of those is not the
    // witness we pinned.
    const published = line["witness_public_key"];
    if (published !== undefined && published !== witness.public_key) return null;

    const treeSize = integerOf(line["tree_size"]);
    const createdAt = integerOf(line["created_at"]);
    const registrySig = stringOf(line["registry_sig"]);
    const witnessSig = stringOf(line["witness_sig"]);
    const root = line["root"];
    if (treeSize === null || createdAt === null) return null;
    if (registrySig === null || witnessSig === null) return null;
    if (!isHex64(root)) return null;

    // The head has to cover our leaf, and that is the whole test: whether it
    // sits before or after the head the inclusion proof was fetched against is
    // the bridge's business, and in production it is almost always after.
    if (treeSize <= proof.leafIndex) return null;

    return { treeSize, root, createdAt, registrySig, witnessSig, consistency };
  }

  /**
   * The consistency path between the countersigned head and the head the
   * inclusion proof was fetched against, empty when they are the same head, and
   * null when the two cannot be bridged.
   *
   * Which way the bridge runs is read off the two sizes, never assumed. The
   * registry answers an inclusion proof under the *earliest* checkpoint that
   * covers the event, while a witness countersigns whatever head is current when
   * it runs, so in production the countersigned head is the later of the two and
   * the bridge runs forward from the proof's head to it. The endpoint only ever
   * proves the smaller tree into the larger (it requires `0 <= from <= to`), so
   * asking it the other way round is not a refusal to work with — it is a
   * question it cannot answer.
   *
   * Both heads it answers with are checked against the roots already held, so a
   * proof of some other pair of heads is not mistaken for a proof of this one.
   */
  async #bridge(
    line: CheckedLine,
    proof: CheckedProof,
  ): Promise<string[] | null> {
    if (line.treeSize === proof.treeSize) {
      return line.root === proof.root ? [] : null;
    }

    const forward = line.treeSize > proof.treeSize;
    const fromSize = forward ? proof.treeSize : line.treeSize;
    const fromRoot = forward ? proof.root : line.root;
    const toSize = forward ? line.treeSize : proof.treeSize;
    const toRoot = forward ? line.root : proof.root;

    const body = objectOf(
      await this.#json(
        `${this.#origin}/api/checkpoint/consistency` +
          `?log=${encodeURIComponent(this.#log)}` +
          `&from=${fromSize}&to=${toSize}`,
      ),
    );
    if (body === null) return null;

    const from = objectOf(body["from"]);
    const to = objectOf(body["to"]);
    if (from === null || from["root"] !== fromRoot) return null;
    if (to === null || to["root"] !== toRoot) return null;

    const path = hexPathOf(body["proof"]);
    if (path === null) return null;

    const consistent = await verifyRegistryConsistency({
      fromSize,
      fromRoot,
      toSize,
      toRoot,
      path,
    });
    return consistent ? path : null;
  }
}

/**
 * The adapter this environment runs.
 *
 * Production runs the registry adapter only when the maintainer has set all
 * three of the sealing key, the registry credential and the handle; with any of
 * them missing the registry track is unavailable and production says so, rather
 * than falling through to a mock that would put invented countersignatures on a
 * real seal. Everything else gets the mock (D-013 as amended).
 */
export function witnessAdapterFor(env: Env): EnvironmentWitnessAdapter {
  if (env.ENVIRONMENT !== PRODUCTION) return new MockWitnessAdapter();

  const privateKeyPkcs8 = env.SEALING_AGENT_KEY ?? "";
  const credential = env.REGISTRY_CREDENTIAL ?? "";
  const handle = env.SEALING_AGENT_HANDLE ?? "";
  if (privateKeyPkcs8 === "" || credential === "" || handle === "") {
    return new UnavailableWitnessAdapter();
  }

  return new RegistryWitnessAdapter({ handle, credential, privateKeyPkcs8 });
}

/**
 * The sealing agent's own id, from the public half of the configured key.
 *
 * The seal is nomankind's, so the agent that signs it is ineligible to witness
 * it — "Limitations" makes nomankind ineligible, and an operator name would not
 * catch the sealing agent countersigning under someone else's. The id is
 * derived from the secret rather than configured beside it, so the two can
 * never disagree.
 *
 * Null when no key is set or the key is unreadable, and never a throw: an
 * unconfigured key means the registry track is off, not that the Worker stops.
 */
export async function sealingAgentIdFor(env: Env): Promise<string | null> {
  const privateKeyPkcs8 = env.SEALING_AGENT_KEY;
  if (privateKeyPkcs8 === undefined || privateKeyPkcs8 === "") return null;
  try {
    const key = await importPrivateKeyPkcs8(base64urlDecode(privateKeyPkcs8));
    // WebCrypto exports no raw form of a private key, and the JWK of an OKP
    // private key carries its public half in `x`, in the same unpadded
    // base64url an agent id is built from.
    const jwk = (await globalThis.crypto.subtle.exportKey(
      "jwk",
      key,
    )) as JsonWebKey;
    const x = jwk.x;
    if (typeof x !== "string") return null;
    return agentIdFromPublicKey(base64urlDecode(x));
  } catch {
    return null;
  }
}

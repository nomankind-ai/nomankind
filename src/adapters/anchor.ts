/**
 * The anchor adapter: the day's hash out to an external timestamping chain.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): anchoring each day's batch hash
 * into an external chain makes the existence proof independent of the identity
 * layer. If every witness vanished tomorrow, an anchored day still proves those
 * roots existed by then — which is only true if the anchor is posted somewhere
 * nomankind does not run, so this is the one adapter whose whole value is that
 * the other end is a stranger.
 *
 * OpenTimestamps' calendar wire is small and this speaks it directly: POST the
 * 32 digest bytes to `<calendar>/digest` and keep the pending proof that comes
 * back. Which calendars, and in what order, is src/policy.ts's
 * ANCHOR_CALENDARS; no endpoint is written down here.
 *
 * Never throws and never retries in place: an anchor that could not be posted
 * today is posted on a later run, and the day's roots have not moved. The
 * platform fetch goes out with no receiver, for the reason every adapter here
 * does it (workerd's "Illegal invocation", the M13 lesson).
 */

import type {
  Anchor,
  AnchorAdapter,
  AnchorExternal,
  AnchorUpgradeResult,
} from "../anchor.js";
import { base64Decode, base64Encode } from "../encoding.js";
import { ANCHOR_CALENDARS, FETCH_TIMEOUT_MS } from "../policy.js";
import { PRODUCTION } from "./payout.js";

/** The OpenTimestamps calendar wire, as the calendars publish it. Format, not policy. */
const OTS_MEDIA_TYPE = "application/vnd.opentimestamps.v1";
const OTS_CONTENT_TYPE = "application/x-www-form-urlencoded";
const OTS_DIGEST_PATH = "/digest";
const OTS_TIMESTAMP_PATH = "/timestamp/";

/** The User-Agent every call from this adapter carries. A wire fact, not policy. */
const USER_AGENT = "nomankind";

/** SHA-256 is 32 bytes; the calendar takes the digest and nothing around it. */
const DIGEST_BYTES = 32;

const HASH_PREFIX = "sha256:";
const HEX_64 = /^[0-9a-f]{64}$/;

/** The 32 digest bytes an anchor hash carries, or null when it carries none. */
function digestOf(hash: string): Uint8Array | null {
  if (typeof hash !== "string" || !hash.startsWith(HASH_PREFIX)) return null;
  const hex = hash.slice(HASH_PREFIX.length);
  if (!HEX_64.test(hex)) return null;
  const bytes = new Uint8Array(DIGEST_BYTES);
  for (let index = 0; index < DIGEST_BYTES; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// The OpenTimestamps binary format
// ---------------------------------------------------------------------------

/*
 * Enough of the .ots format to read a pending proof and finish it, and no more.
 *
 * A timestamp is a tree over one message: at each node, zero or more
 * attestations ("this message existed, and here is who says so") and zero or
 * more operations, each leading to a child node over the transformed message.
 * Serialized, the items of a node are written in order with `ff` before all but
 * the last, so a linear chain — which is what a calendar hands back — costs no
 * framing at all.
 *
 * Only append, prepend and SHA-256 are implemented. That is not a shortcut: it
 * is every operation a Bitcoin calendar's proof uses, and the others (RIPEMD-160,
 * SHA-1, keccak) have no WebCrypto to compute them with. A proof carrying one is
 * refused as unreadable rather than half-parsed, which is the honest answer.
 */

/** The 31 bytes every .ots file starts with. */
const OTS_MAGIC = Uint8Array.of(
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
  0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2,
  0xe8, 0x84, 0xe8, 0x92, 0x94,
);

/** The serialization version this writes, and the only one this reads. */
const OTS_VERSION = 1;

const OP_ATTESTATION = 0x00;
const OP_FORK = 0xff;
const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;

/** The 8-byte attestation tags this cares about, as hex. */
export const OTS_TAG_PENDING = "83dfe30d2ef90c8e";
export const OTS_TAG_BITCOIN = "0588960d73d71901";

/** A varint wide enough for a block height and no wider; a longer one is a lie. */
const VARINT_MAX_BYTES = 9;

/** One attestation: the 8-byte tag, as hex, and the bytes behind it. */
export interface OtsAttestation {
  readonly tag: string;
  readonly payload: Uint8Array;
}

/** One item of a node: an attestation, or an operation and where it leads. */
export type OtsItem =
  | { readonly kind: "attestation"; readonly attestation: OtsAttestation }
  | {
      readonly kind: "op";
      readonly op: number;
      readonly arg: Uint8Array | null;
      readonly child: OtsNode;
    };

/** One node of the tree: the message it is over, and its items in wire order. */
export interface OtsNode {
  readonly msg: Uint8Array;
  readonly items: readonly OtsItem[];
}

/** A parsed proof: whether it carried a file header, and the tree itself. */
export interface OtsProof {
  /** Whether the bytes began with the magic and the file digest. */
  readonly magic: boolean;
  readonly version: number | null;
  /** The digest the tree starts from. */
  readonly digest: Uint8Array;
  readonly root: OtsNode;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.byteLength + right.byteLength);
  out.set(left, 0);
  out.set(right, left.byteLength);
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes as unknown as BufferSource,
  );
  return new Uint8Array(digest);
}

/** A cursor over the proof's bytes. Every read throws on running off the end. */
class Reader {
  #at = 0;
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  get done(): boolean {
    return this.#at >= this.#bytes.byteLength;
  }

  byte(): number {
    if (this.done) throw new RangeError("ots: truncated");
    return this.#bytes[this.#at++]!;
  }

  peek(): number {
    if (this.done) throw new RangeError("ots: truncated");
    return this.#bytes[this.#at]!;
  }

  take(length: number): Uint8Array {
    if (length < 0 || this.#at + length > this.#bytes.byteLength) {
      throw new RangeError("ots: truncated");
    }
    const out = this.#bytes.slice(this.#at, this.#at + length);
    this.#at += length;
    return out;
  }

  /** The unsigned LEB128 varint the format writes lengths and heights as. */
  varint(): number {
    let value = 0;
    let shift = 0;
    for (let read = 0; read < VARINT_MAX_BYTES; read += 1) {
      const byte = this.byte();
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) {
        if (!Number.isSafeInteger(value)) throw new RangeError("ots: varint too wide");
        return value;
      }
      shift += 7;
    }
    throw new RangeError("ots: varint too wide");
  }

  /** A varint length followed by that many bytes. */
  varbytes(): Uint8Array {
    return this.take(this.varint());
  }
}

/** Read the varint a Bitcoin attestation's payload is. */
export function bitcoinHeightOf(attestation: OtsAttestation): number | null {
  if (attestation.tag !== OTS_TAG_BITCOIN) return null;
  try {
    return new Reader(attestation.payload).varint();
  } catch {
    return null;
  }
}

/** Read the calendar URL a pending attestation's payload is. */
export function pendingCalendarOf(attestation: OtsAttestation): string | null {
  if (attestation.tag !== OTS_TAG_PENDING) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      new Reader(attestation.payload).varbytes(),
    );
  } catch {
    return null;
  }
}

/** One node and everything under it, from the cursor's position. */
async function readNode(reader: Reader, msg: Uint8Array): Promise<OtsNode> {
  const items: OtsItem[] = [];
  for (;;) {
    if (reader.peek() === OP_FORK) {
      reader.byte();
      items.push(await readItem(reader, msg));
      continue;
    }
    items.push(await readItem(reader, msg));
    return { msg, items };
  }
}

/** One item: an attestation, or an operation and the node it leads to. */
async function readItem(reader: Reader, msg: Uint8Array): Promise<OtsItem> {
  const op = reader.byte();
  if (op === OP_ATTESTATION) {
    const tag = hex(reader.take(8));
    const payload = reader.varbytes();
    return { kind: "attestation", attestation: { tag, payload } };
  }
  if (op === OP_APPEND || op === OP_PREPEND) {
    const arg = reader.varbytes();
    const next = op === OP_APPEND ? concat(msg, arg) : concat(arg, msg);
    return { kind: "op", op, arg, child: await readNode(reader, next) };
  }
  if (op === OP_SHA256) {
    return { kind: "op", op, arg: null, child: await readNode(reader, await sha256(msg)) };
  }
  // Every other opcode is a real one this cannot compute (RIPEMD-160, SHA-1,
  // keccak) or no opcode at all. Both are "this is not a proof I can read".
  throw new RangeError(`ots: unsupported operation 0x${op.toString(16)}`);
}

/**
 * Parse a proof, from a starting digest.
 *
 * Two shapes reach this. A complete .ots file begins with the magic, a version,
 * the digest operation and the 32 digest bytes; a calendar's answer to `/digest`
 * or `/timestamp/` begins with the operations and carries no copy of the message
 * they start from, which is why `digest` is an argument and not a result. When a
 * file header is present its digest must be the one expected, or the proof is
 * about something else and is refused.
 *
 * Null on anything malformed. A verifier is asking a question, and a proof it
 * cannot read is an answer of "no", not an exception.
 */
export async function parseOtsProof(
  bytes: Uint8Array,
  digest: Uint8Array,
): Promise<OtsProof | null> {
  try {
    const reader = new Reader(bytes);
    let magic = false;
    let version: number | null = null;
    let start = digest;
    if (
      bytes.byteLength >= OTS_MAGIC.byteLength &&
      bytesEqual(bytes.slice(0, OTS_MAGIC.byteLength), OTS_MAGIC)
    ) {
      magic = true;
      reader.take(OTS_MAGIC.byteLength);
      version = reader.varint();
      if (version !== OTS_VERSION) return null;
      if (reader.byte() !== OP_SHA256) return null;
      start = reader.take(32);
      if (!bytesEqual(start, digest)) return null;
    }
    const root = await readNode(reader, start);
    if (!reader.done) return null;
    return { magic, version, digest: start, root };
  } catch {
    return null;
  }
}

/** Every attestation in a proof, with the message each is over, in wire order. */
export function attestationsOf(
  node: OtsNode,
): { readonly attestation: OtsAttestation; readonly msg: Uint8Array }[] {
  const found: { attestation: OtsAttestation; msg: Uint8Array }[] = [];
  for (const item of node.items) {
    if (item.kind === "attestation") found.push({ attestation: item.attestation, msg: node.msg });
    else found.push(...attestationsOf(item.child));
  }
  return found;
}

/** What a pending proof is waiting on: the bytes a calendar took, and which one. */
export interface OtsPending {
  /** The message the pending attestation is over: what `/timestamp/` is keyed by. */
  readonly commitment: Uint8Array;
  readonly calendar: string;
}

/** The first pending attestation in a proof, and the commitment it is over. */
export function pendingOf(proof: OtsProof): OtsPending | null {
  for (const { attestation, msg } of attestationsOf(proof.root)) {
    const calendar = pendingCalendarOf(attestation);
    if (calendar !== null) return { commitment: msg, calendar };
  }
  return null;
}

/** The first Bitcoin block height a proof attests to, or null when it has none. */
export function bitcoinHeightIn(proof: OtsProof): number | null {
  for (const { attestation } of attestationsOf(proof.root)) {
    const height = bitcoinHeightOf(attestation);
    if (height !== null) return height;
  }
  return null;
}

function varintBytes(value: number): number[] {
  const out: number[] = [];
  let rest = value;
  for (;;) {
    const byte = rest % 128;
    rest = Math.floor(rest / 128);
    if (rest === 0) {
      out.push(byte);
      return out;
    }
    out.push(byte | 0x80);
  }
}

function writeNode(node: OtsNode, out: number[]): void {
  node.items.forEach((item, index) => {
    if (index < node.items.length - 1) out.push(OP_FORK);
    if (item.kind === "attestation") {
      out.push(OP_ATTESTATION);
      for (let at = 0; at < 8; at += 1) {
        out.push(Number.parseInt(item.attestation.tag.slice(at * 2, at * 2 + 2), 16));
      }
      out.push(...varintBytes(item.attestation.payload.byteLength));
      out.push(...item.attestation.payload);
      return;
    }
    out.push(item.op);
    if (item.arg !== null) {
      out.push(...varintBytes(item.arg.byteLength));
      out.push(...item.arg);
    }
    writeNode(item.child, out);
  });
}

/**
 * Serialize a proof as a complete .ots file: the magic, the version, the digest
 * operation and the digest, then the tree.
 *
 * Always with the header, whatever the parsed proof came in as. What is stored
 * as the upgrade is meant to leave this system — written to a file and handed to
 * any OpenTimestamps client — and a bare operation stream cannot, because
 * nothing in it says what it is a timestamp of.
 */
export function serializeOtsFile(proof: OtsProof): Uint8Array {
  const out: number[] = [];
  out.push(...OTS_MAGIC);
  out.push(...varintBytes(OTS_VERSION));
  out.push(OP_SHA256);
  out.push(...proof.digest);
  writeNode(proof.root, out);
  return Uint8Array.from(out);
}

/**
 * Put the calendar's answer where the pending attestation was.
 *
 * The calendar answers `/timestamp/<commitment>` with the operations from that
 * commitment onward, which is exactly the subtree the pending attestation was
 * standing in for. Every other branch of the proof is left alone: a proof
 * pending at two calendars that upgrades at one is still pending at the other,
 * and dropping that would be losing evidence.
 */
export function spliceUpgrade(
  proof: OtsProof,
  commitment: Uint8Array,
  answer: OtsNode,
): OtsProof | null {
  let spliced = false;

  const replaceNode = (node: OtsNode): OtsNode => {
    const items: OtsItem[] = [];
    for (const item of node.items) {
      if (
        item.kind === "attestation" &&
        item.attestation.tag === OTS_TAG_PENDING &&
        bytesEqual(node.msg, commitment)
      ) {
        spliced = true;
        items.push(...answer.items);
        continue;
      }
      if (item.kind === "op") {
        items.push({ ...item, child: replaceNode(item.child) });
        continue;
      }
      items.push(item);
    }
    return { msg: node.msg, items };
  };

  const root = replaceNode(proof.root);
  return spliced ? { magic: true, version: OTS_VERSION, digest: proof.digest, root } : null;
}

/**
 * Local and demo: the day's hash is recorded and posted nowhere.
 *
 * Null rather than an invented receipt, for the reason the payout stub refuses
 * rather than passes: a fabricated timestamp is worse than none, because it
 * looks like evidence. The anchor still exists and still commits to the day's
 * roots; it simply has no external witness, which is the truth about a laptop.
 */
export class LocalAnchorAdapter implements AnchorAdapter {
  async anchor(): Promise<AnchorExternal> {
    return null;
  }
}

/** What the OpenTimestamps adapter needs to be built. */
export interface OpenTimestampsOptions {
  fetch?: typeof fetch;
  calendars?: readonly string[];
  now: () => Date;
}

/**
 * Production's adapter: the policy's calendars, in order, until one answers.
 *
 * A calendar that is down, slow, or answers something empty is skipped and the
 * next is tried; the first usable answer is the one recorded, and its origin is
 * recorded with it so a verifier knows which calendar to upgrade the pending
 * proof against later. All of them failing is null, not an exception.
 *
 * The clock is injected like every clock in this system, so a test can pin the
 * submission time rather than read the machine's.
 */
export class OpenTimestampsAdapter implements AnchorAdapter {
  readonly #fetch: typeof fetch;
  readonly #calendars: readonly string[];
  readonly #now: () => Date;

  constructor(options: OpenTimestampsOptions) {
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#calendars = options.calendars ?? ANCHOR_CALENDARS;
    this.#now = options.now;
  }

  async anchor(anchor: Anchor): Promise<AnchorExternal> {
    try {
      return await this.#anchor(anchor);
    } catch {
      return null;
    }
  }

  async #anchor(anchor: Anchor): Promise<AnchorExternal> {
    const digest = digestOf(anchor.hash);
    if (digest === null) return null;

    for (const calendar of this.#calendars) {
      const proof = await this.#submit(calendar, digest);
      if (proof === null) continue;
      return {
        kind: "opentimestamps",
        calendar,
        submitted_at: this.#now().toISOString(),
        proof,
        // Pending by construction: a calendar answers `/digest` with a promise,
        // and the block it will be folded into does not exist yet.
        upgraded: null,
      };
    }
    return null;
  }

  /**
   * Ask whether the pending proof has reached a block, and finish it if it has.
   *
   * Which calendar is asked is not quite the one the receipt records. The
   * receipt names the endpoint the digest was posted to, which on production is
   * a pool (`a.pool.opentimestamps.org`) that forwards to whichever calendar
   * takes it; the calendar that actually holds the commitment is the one named
   * inside the pending attestation, and it is the only one that answers
   * `/timestamp/<commitment>` with anything. Verified against the live wire on
   * 2026-09-10: the pool answered 404 for a commitment its own member calendar
   * answered 200 for. So the attestation's calendar is asked first and the
   * recorded one after, and only over https — the attestation's URL comes from
   * outside and is not a place to follow anywhere it likes.
   */
  async upgrade(anchor: Anchor): Promise<AnchorUpgradeResult> {
    try {
      return await this.#upgrade(anchor);
    } catch {
      return { ok: false, reason: "unavailable" };
    }
  }

  async #upgrade(anchor: Anchor): Promise<AnchorUpgradeResult> {
    const external = anchor.external;
    if (external === null || external.kind !== "opentimestamps") {
      return { ok: false, reason: "bad_proof" };
    }
    const digest = digestOf(anchor.hash);
    if (digest === null) return { ok: false, reason: "bad_proof" };

    let stored: Uint8Array;
    try {
      stored = base64Decode(external.proof);
    } catch {
      return { ok: false, reason: "bad_proof" };
    }

    const proof = await parseOtsProof(stored, digest);
    if (proof === null) return { ok: false, reason: "bad_proof" };
    if (bitcoinHeightIn(proof) !== null) {
      // Already complete: nothing to ask anyone. Recorded rather than refused,
      // so a row whose stored proof was upgraded elsewhere settles by itself.
      return this.#complete(proof);
    }
    const pending = pendingOf(proof);
    if (pending === null) return { ok: false, reason: "bad_proof" };

    const path = `${OTS_TIMESTAMP_PATH}${hex(pending.commitment)}`;
    let worst: AnchorUpgradeResult = { ok: false, reason: "unavailable" };
    for (const calendar of this.#upgradeCalendars(pending.calendar, external.calendar)) {
      const answer = await this.#timestamp(`${calendar}${path}`);
      if (answer === "unavailable") continue;
      if (answer === "pending") {
        if (!worst.ok && worst.reason === "unavailable") worst = { ok: false, reason: "pending" };
        continue;
      }
      const parsed = await parseOtsProof(answer, pending.commitment);
      const upgraded =
        parsed === null ? null : spliceUpgrade(proof, pending.commitment, parsed.root);
      if (upgraded === null || bitcoinHeightIn(upgraded) === null) {
        // Something answered with a body that is not the proof asked for. More
        // is known than "pending", and saying so is the point of the reason.
        worst = { ok: false, reason: "bad_proof" };
        continue;
      }
      return this.#complete(upgraded);
    }
    return worst;
  }

  /** The finished proof as it is stored: a complete .ots file, and its height. */
  #complete(proof: OtsProof): AnchorUpgradeResult {
    const height = bitcoinHeightIn(proof);
    if (height === null) return { ok: false, reason: "bad_proof" };
    return { ok: true, proof: base64Encode(serializeOtsFile(proof)), block_height: height };
  }

  /** The calendar the commitment lives at, then the one the digest was posted to. */
  #upgradeCalendars(attested: string, recorded: string): string[] {
    const asked: string[] = [];
    for (const candidate of [attested, recorded]) {
      if (!candidate.startsWith("https://")) continue;
      const trimmed = candidate.replace(/\/+$/, "");
      if (!asked.includes(trimmed)) asked.push(trimmed);
    }
    return asked;
  }

  /**
   * One calendar's answer: the bytes, "pending" for the 404 it answers while the
   * commitment is still waiting, or "unavailable" for everything else.
   */
  async #timestamp(url: string): Promise<Uint8Array | "pending" | "unavailable"> {
    const call = this.#fetch;
    let response: Response;
    try {
      response = await call(url, {
        method: "GET",
        headers: { accept: OTS_MEDIA_TYPE, "user-agent": USER_AGENT },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return "unavailable";
    }
    if (response.status === 404) return "pending";
    if (!response.ok) return "unavailable";
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch {
      return "unavailable";
    }
    return bytes.byteLength === 0 ? "unavailable" : bytes;
  }

  /** One calendar's pending proof, standard base64, or null on any failure. */
  async #submit(
    calendar: string,
    digest: Uint8Array,
  ): Promise<string | null> {
    const call = this.#fetch;
    let response: Response;
    try {
      response = await call(`${calendar}${OTS_DIGEST_PATH}`, {
        method: "POST",
        headers: {
          accept: OTS_MEDIA_TYPE,
          "content-type": OTS_CONTENT_TYPE,
          "user-agent": USER_AGENT,
        },
        // The raw digest bytes, with nothing wrapped around them: the calendar
        // reads the body as the commitment itself, whatever the content type
        // its wire asks for says.
        body: digest as unknown as BodyInit,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return null;
    }

    if (!response.ok) return null;

    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch {
      return null;
    }
    if (bytes.byteLength === 0) return null;

    // Standard base64, not base64url: an .ots proof is a binary blob carried in
    // JSON, not an identifier that ever goes in a URL.
    return base64Encode(bytes);
  }
}

/** The adapter this environment runs (decision D-013 as amended). */
export function anchorAdapterFor(
  environment: string,
  now: () => Date,
): AnchorAdapter {
  return environment === PRODUCTION
    ? new OpenTimestampsAdapter({ now })
    : new LocalAnchorAdapter();
}

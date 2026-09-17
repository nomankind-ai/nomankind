/**
 * The board adapter: the public threads where an outside confirmation is said,
 * and the registry proof behind the handle that said it.
 *
 * Decision D-136. The batch threads are posts by one citizen at the founding
 * 1F916 registry (`CONFIRMATION_VENUES`), and a comment on one of them may
 * carry the published confirmation form. This module fetches those comments and
 * the evidence that their author is a key the registry's log carries; it judges
 * nothing. The form is parsed by src/confirm.ts, the proof is rechecked there,
 * and what a confirmation does to an entry is src/derive.ts's — a bootstrap
 * label cleared, and never a status.
 *
 * What the board can and cannot prove, from its own published surface (read on
 * 2026-09-16): `GET /api/citizen/<handle>` lists that citizen's posts, so the
 * batch threads are discoverable and a daily batch post needs no deploy.
 * `GET /api/post/<id>` answers a post and its comment tree. But a comment is
 * written with a bearer credential and is sealed into no identity event: there
 * is no per-comment signature and no per-comment inclusion proof anywhere on
 * that surface. The strongest thing the venue can prove about who spoke is the
 * author's *key*: `GET /api/record/<handle>` publishes the citizen's identity
 * events with inclusion proofs against a checkpoint the registry signed, and
 * the pinned witnesses countersign heads of that same log. So that is what
 * travels on the event — the key-binding event, proved — and it is exactly what
 * makes this a signing venue and The Colony or GitHub account venues.
 *
 * Three properties, the same three the witness adapter keeps:
 *
 * Nothing throws. The sweep runs on a timer and a board that did not answer is
 * a step with a skip reason, never a crashed run. Every path answers null or an
 * empty list.
 *
 * Nothing is trusted. Every field off the wire is checked before it is read,
 * and the proof this adapter assembles is verified here as well as by the
 * kernel, because an unverifiable claim is not worth sealing.
 *
 * Nothing is followed. Comment bodies are carried as data to the parser and are
 * never read as instructions, by this module or by anything downstream.
 */

import {
  BOARD_READ_MAX_BYTES,
  CONFIRMATION_COMMENTS_PER_THREAD,
  CONFIRMATION_VENUES,
  FETCH_TIMEOUT_MS,
  REGISTRY,
  WITNESS_FILE_TAIL_BYTES,
  WITNESS_PIN,
  type ConfirmationVenue,
} from "../policy.js";
import type {
  ConfirmationCountersignature,
  ConfirmationLeaf,
  ConfirmationProof,
} from "../events.js";
import {
  isHex64,
  registryCheckpointPayload,
  registryLeafHash,
  registryWitnessPayload,
  verifyRegistryConsistency,
  verifyRegistryInclusion,
} from "../registry-proof.js";
import { AGENT_ID_PREFIX, verifyBytes } from "../identity.js";
import { base64urlDecode } from "../encoding.js";
import { withDeadline } from "./timeout.js";
import type { WitnessPin } from "./witness.js";
import type { Env } from "../worker/env.js";

/** The User-Agent every call from this adapter carries. A wire fact, not policy. */
const USER_AGENT = "nomankind";

/** The status a ranged read answers when it really returned a tail. */
const PARTIAL_CONTENT = 206;

/** The status a suffix range answers when the file is smaller than the range. */
const RANGE_NOT_SATISFIABLE = 416;

/** The one line status a witness file's usable line carries. */
const COUNTERSIGNED = "countersigned";

/** The consistency field a witness line carries when it really checked one. */
const VERIFIED_FROM = "verified from";

/** The identity-event kind a citizen's own seal is written as. */
const MEMORY_SEAL = "memory.seal";

/**
 * How many pages of a citizen's record one lookup reads.
 *
 * The same bound the seal path keeps (src/adapters/witness.ts): a record that
 * has not listed the seal within this many pages answers "not sealed", which is
 * an uncounted confirmation rather than a run that reads forever.
 */
const MAX_RECORD_PAGES = 10;

/** One comment on a batch thread, as the board published it. */
export interface BoardComment {
  /** The board's own comment id, which the cursor and the dedup key are on. */
  readonly id: number;
  /** The thread it was written on. */
  readonly thread: number;
  /** The citizen handle that wrote it. Untrusted text, like the body. */
  readonly handle: string;
  /** The comment's text. UNTRUSTED: parsed strictly, never followed. */
  readonly body: string;
  /** When the board says it was posted, as an ISO instant. */
  readonly posted_at: string;
}

/**
 * One fingerprint, sealed by a handle's own key, with the proof that it is in
 * the registry's log.
 *
 * The confirmer seals the canonical line's fingerprint through the registry's
 * own seal door (`POST /api/seal`, signed with their citizen key), which
 * writes a `memory.seal` identity event whose detail names the fingerprint.
 * That event is the leaf this proves. A handle with no such event has said
 * something on a board and signed nothing, which is exactly what
 * `counted: false` records.
 */
export interface BoardSealProof {
  /** The identity event's own id at the registry. */
  readonly registry_event_id: number;
  readonly proof: ConfirmationProof;
}

/**
 * What the sweep's `confirmations` step asks of a board.
 *
 * Three questions, each answering null for "the board did not answer", which
 * the step counts as a skip rather than a failure — a public board being down
 * is weather, not a rule.
 */
export interface BoardAdapter {
  /** Which venue this adapter speaks for, as the sealed event spells it. */
  readonly venue: string;
  /** The batch threads for this environment: the pinned ones and the listed ones. */
  threads(): Promise<readonly number[] | null>;
  /** One bounded page of a thread's comments newer than `afterId`. */
  comments(
    thread: number,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null>;
  /**
   * The proof that this handle's own key sealed this fingerprint, or null when
   * the record carries no such seal (or could not be read, which the step
   * treats the same way: uncounted, never counted on a guess).
   */
  sealProof(handle: string, fingerprint: string): Promise<BoardSealProof | null>;
}

/**
 * A response body as text, or null when it is bigger than the cap.
 *
 * The declared length is checked first, because a server that says how big
 * the answer is has already answered the question; the stream is then read in
 * chunks and dropped the moment it passes the cap, because a declared length
 * is the server's word and a chunked answer declares nothing at all.
 */
async function boundedText(
  response: Response,
  maxBytes: number,
): Promise<string | null> {
  const declared = Number(response.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > maxBytes) return null;

  const body = response.body;
  if (body === null) {
    try {
      const text = await response.text();
      return text.length > maxBytes ? null : text;
    } catch {
      return null;
    }
  }

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let read = 0;
  let text = "";
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      const bytes = chunk.value as Uint8Array;
      read += bytes.byteLength;
      if (read > maxBytes) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(bytes, { stream: true });
    }
    return text + decoder.decode();
  } catch {
    return null;
  }
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

function hexPathOf(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return value.every(isHex64) ? [...(value as string[])] : null;
}

/**
 * The board's epoch milliseconds as an ISO instant.
 *
 * Null rather than a guess for anything that is not a millisecond count: a
 * confirmation whose time cannot be read is a confirmation this adapter does
 * not offer, because the event carries `posted_at` and an invented one would be
 * the adapter's word rather than the board's.
 */
function instantOf(value: unknown): string | null {
  const ms = integerOf(value);
  if (ms === null || ms < 0) return null;
  try {
    return new Date(ms).toISOString();
  } catch {
    return null;
  }
}

/** The venue row for a name, or null when policy names no such venue. */
export function confirmationVenue(venue: string): ConfirmationVenue | null {
  return CONFIRMATION_VENUES.find((row) => row.venue === venue) ?? null;
}

/**
 * The threads pinned for one environment, which is also the floor the listing
 * adds to. An environment policy names none has an empty list, and the step
 * reads no board at all there.
 */
export function pinnedThreadsFor(
  venue: ConfirmationVenue,
  environment: string,
): readonly number[] {
  return venue.threads[environment] ?? [];
}

/**
 * The board nobody can reach: what an environment with no venue gets.
 *
 * It answers null rather than an empty list, so the step counts
 * `board_unavailable` and says why, exactly as the mirror step does without an
 * adapter. An empty list would read as "the board has nothing", which is a
 * claim about a board this environment never asked.
 */
export class UnavailableBoardAdapter implements BoardAdapter {
  readonly venue: string;

  constructor(venue = CONFIRMATION_VENUES[0]?.venue ?? "1f916") {
    this.venue = venue;
  }

  async threads(): Promise<readonly number[] | null> {
    return null;
  }

  async comments(): Promise<readonly BoardComment[] | null> {
    return null;
  }

  async sealProof(): Promise<BoardSealProof | null> {
    return null;
  }
}

/** What a fixture board is built from: threads, their comments, and the keys. */
export interface MockBoardOptions {
  readonly venue?: string;
  readonly threads?: readonly number[] | null;
  readonly comments?: ReadonlyMap<number, readonly BoardComment[]> | null;
  /** Sealed fingerprints, keyed `<handle> <fingerprint>`. */
  readonly seals?: ReadonlyMap<string, BoardSealProof> | null;
}

/**
 * The board a test injects, and the one the injected world runs on.
 *
 * It fakes only the network: the comments are whatever the fixture holds and
 * the proofs are real proofs over a real fixture tree, so a test that passes
 * says the step verified an inclusion path and an Ed25519 signature rather than
 * that a stub agreed with itself.
 */
export class MockBoardAdapter implements BoardAdapter {
  readonly venue: string;
  readonly #threads: readonly number[] | null;
  readonly #comments: ReadonlyMap<number, readonly BoardComment[]> | null;
  readonly #seals: ReadonlyMap<string, BoardSealProof> | null;
  /** How many times each thread was read: what a "second run" test asserts on. */
  readonly reads: number[] = [];

  constructor(options: MockBoardOptions = {}) {
    this.venue = options.venue ?? "1f916";
    this.#threads = options.threads === undefined ? [] : options.threads;
    this.#comments = options.comments ?? new Map();
    this.#seals = options.seals ?? new Map();
  }

  async threads(): Promise<readonly number[] | null> {
    return this.#threads;
  }

  async comments(
    thread: number,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    if (this.#comments === null) return null;
    this.reads.push(thread);
    const all = this.#comments.get(thread) ?? [];
    return all
      .filter((comment) => comment.id > afterId)
      .sort((left, right) => left.id - right.id)
      .slice(0, limit);
  }

  async sealProof(
    handle: string,
    fingerprint: string,
  ): Promise<BoardSealProof | null> {
    if (this.#seals === null) return null;
    return this.#seals.get(`${handle} ${fingerprint}`) ?? null;
  }
}

/** What the registry board adapter needs to be built. */
export interface RegistryBoardOptions {
  readonly fetch?: typeof fetch;
  readonly origin?: string;
  readonly registryPublicKey?: string;
  readonly log?: string;
  readonly venue?: ConfirmationVenue;
  readonly environment: string;
  readonly pin?: readonly WitnessPin[];
  readonly tailBytes?: number;
  /** The most bytes one JSON read may hold; the policy number by default. */
  readonly maxBytes?: number;
}

/** One usable line of a witness's published countersignature file. */
interface WitnessLine {
  readonly treeSize: number;
  readonly root: string;
  readonly createdAt: number;
  readonly registrySig: string;
  readonly witnessSig: string;
  readonly consistency: string;
}

/** A leaf this adapter has already proved for itself. */
interface ProvedLeaf {
  readonly eventId: number;
  readonly eventHash: string;
  /** The row the registry served the hash as: what makes the leaf ours. */
  readonly row: ConfirmationLeaf;
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly root: string;
  readonly createdAt: number;
  readonly registrySig: string;
  readonly path: readonly string[];
}

/**
 * The real board: the founding registry's public read surface.
 *
 * Reads only. Nothing here writes a comment, votes, or carries a credential of
 * any kind — the confirmations door listens, and nomankind's own posting is a
 * separate thing done by hand.
 */
export class RegistryBoardAdapter implements BoardAdapter {
  readonly venue: string;

  readonly #fetch: typeof fetch;
  readonly #origin: string;
  readonly #registryPublicKey: string;
  readonly #log: string;
  readonly #row: ConfirmationVenue;
  readonly #environment: string;
  readonly #pin: readonly WitnessPin[];
  readonly #tailBytes: number;
  readonly #maxBytes: number;

  constructor(options: RegistryBoardOptions) {
    const row = options.venue ?? CONFIRMATION_VENUES[0]!;
    this.venue = row.venue;
    this.#row = row;
    this.#environment = options.environment;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#origin = options.origin ?? REGISTRY.origin;
    this.#registryPublicKey = options.registryPublicKey ?? REGISTRY.public_key;
    this.#log = options.log ?? REGISTRY.log;
    this.#pin = options.pin ?? WITNESS_PIN;
    this.#tailBytes = options.tailBytes ?? WITNESS_FILE_TAIL_BYTES;
    this.#maxBytes = options.maxBytes ?? BOARD_READ_MAX_BYTES;
  }

  /**
   * Every call goes through here: the deadline, the User-Agent, and a
   * receiver-free invocation (workerd refuses a platform fetch called on
   * anything but the global object). A failure is null and says nothing about
   * itself.
   */
  async #call(
    url: string,
    init: RequestInit,
    signal: AbortSignal,
  ): Promise<Response | null> {
    const call = this.#fetch;
    try {
      return await call(url, { ...init, signal });
    } catch {
      return null;
    }
  }

  /**
   * A GET whose body is JSON, or null on any failure at all.
   *
   * Bounded, like every other read this record makes of somebody else's
   * server (`CAPTURE_MAX_BYTES` for a snapshot, `WITNESS_FILE_TAIL_BYTES` for
   * a witness file): a thread the board answers with a hundred megabytes must
   * cost one refused read rather than a Worker that runs out of memory. The
   * body is read in chunks and abandoned the moment it passes the cap, so the
   * cap is on what is held and not only on what is parsed.
   */
  async #json(url: string): Promise<unknown | null> {
    return withDeadline(FETCH_TIMEOUT_MS, async (signal) => {
      const response = await this.#call(
        url,
        {
          method: "GET",
          headers: { accept: "application/json", "user-agent": USER_AGENT },
        },
        signal,
      );
      if (response === null || !response.ok) return null;
      const text = await boundedText(response, this.#maxBytes);
      if (text === null) return null;
      try {
        return JSON.parse(text) as unknown;
      } catch {
        return null;
      }
    });
  }

  /**
   * The batch threads: the pinned ones, plus every post the venue's citizen has
   * published.
   *
   * The listing is what makes a daily batch post need no deploy (M25g): the
   * citizen's own record names their posts, so a thread that did not exist when
   * this Worker was deployed is read the day it appears. The pinned ids stay in
   * the answer whatever the listing says — a board that stops listing is not a
   * board that unsaid the maintainer's decision — and a listing that cannot be
   * read at all leaves the pinned ones, which is a thinner answer rather than
   * no answer.
   *
   * The listing is only added to an environment that already pins a thread. An
   * environment the maintainer has not opened the door on reads nothing, and
   * discovery must not be the thing that opens it: the demo test thread is a
   * post by the same citizen, and production ingesting demo's comments because
   * one handle posted both would be the door deciding where it is open.
   */
  async threads(): Promise<readonly number[] | null> {
    const pinned = pinnedThreadsFor(this.#row, this.#environment);
    const ids = new Set<number>(pinned);
    if (!this.#row.discover || ids.size === 0) return [...ids];

    const body = objectOf(
      await this.#json(
        `${this.#origin}/api/citizen/${encodeURIComponent(this.#row.citizen)}`,
      ),
    );
    if (body === null) return ids.size === 0 ? null : [...ids];

    const posts = body["posts"];
    if (Array.isArray(posts)) {
      for (const each of posts) {
        const post = objectOf(each);
        if (post === null) continue;
        const id = integerOf(post["id"]);
        if (id !== null) ids.add(id);
      }
    }
    return [...ids].sort((left, right) => left - right);
  }

  /**
   * One bounded page of a thread's comments newer than the step's cursor.
   *
   * The cursor is the board's own comment id and the page is taken in id order,
   * so a thread nobody has commented on since the last run costs one read and
   * answers nothing. Comments the board could not describe fully — no id, no
   * author, no body, no time — are dropped rather than half-read: a
   * confirmation is sealed with all four of those on it or not at all.
   */
  async comments(
    thread: number,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    const body = objectOf(
      await this.#json(`${this.#origin}/api/post/${thread}`),
    );
    if (body === null) return null;

    const rows = body["comments"];
    if (!Array.isArray(rows)) return [];

    const comments: BoardComment[] = [];
    for (const each of rows) {
      const row = objectOf(each);
      if (row === null) continue;
      const id = integerOf(row["id"]) ?? integerOf(row["comment_id"]);
      const handle = stringOf(row["author"]);
      const text = stringOf(row["body"]);
      const postedAt = instantOf(row["created_at"]);
      if (id === null || handle === null || text === null) continue;
      if (postedAt === null) continue;
      if (id <= afterId) continue;
      comments.push({ id, thread, handle, body: text, posted_at: postedAt });
    }
    comments.sort((left, right) => left.id - right.id);
    return comments.slice(0, Math.min(limit, CONFIRMATION_COMMENTS_PER_THREAD));
  }

  /**
   * The proof that this handle's own key sealed this fingerprint.
   *
   * The citizen's own record carries its identity events with an inclusion
   * proof each and the checkpoint they were proved against; the `memory.seal`
   * event whose detail names this fingerprint is the one this returns. Both
   * halves are checked here rather than taken on the endpoint's word — the
   * checkpoint's own signature under the pinned registry key, and the path
   * folded locally — and then the pinned witnesses' countersignatures are
   * gathered over heads of the same log, bridged to this head by a consistency
   * proof exactly as a seal's are.
   *
   * Null when any of it is missing, which the step records as an uncounted
   * confirmation: a handle that sealed nothing has an account's word and no
   * more, and the record says so rather than throwing the statement away.
   */
  async sealProof(
    handle: string,
    fingerprint: string,
  ): Promise<BoardSealProof | null> {
    try {
      return await this.#sealProof(handle, fingerprint);
    } catch {
      return null;
    }
  }

  async #sealProof(
    handle: string,
    fingerprint: string,
  ): Promise<BoardSealProof | null> {
    const leaf = await this.#sealLeaf(handle, fingerprint);
    if (leaf === null) return null;

    const witnesses: ConfirmationCountersignature[] = [];
    for (const witness of this.#pin) {
      const countersignature = await this.#countersignature(witness, leaf);
      if (countersignature !== null) witnesses.push(countersignature);
    }
    if (witnesses.length === 0) return null;

    return {
      registry_event_id: leaf.eventId,
      proof: {
        registry: this.#origin,
        log: this.#log,
        event_hash: leaf.eventHash,
        leaf: leaf.row,
        leaf_index: leaf.leafIndex,
        proof: [...leaf.path],
        checkpoint: {
          tree_size: leaf.treeSize,
          root: leaf.root,
          created_at: leaf.createdAt,
          registry_sig: leaf.registrySig,
        },
        witnesses,
      },
    };
  }

  /**
   * The `memory.seal` event of a citizen's record that names this fingerprint,
   * proved.
   *
   * The detail the registry writes for a seal is one line, and the fingerprint
   * is in it by name:
   * `label='<label>' sha256=<hex>, signed by <public key>`. The label is the
   * confirmer's own word and is not matched on — a citizen files its seals
   * under whatever label it likes — because the fingerprint is already the
   * whole statement: it is a digest of a line that begins with this record's
   * own form prefix, so it can be a digest of nothing else.
   *
   * Paged with the parameter the route publishes, `events_since`, up to
   * `MAX_RECORD_PAGES`; a record that stops answering, or that has not listed
   * the seal, is null rather than a guess.
   */
  async #sealLeaf(
    handle: string,
    fingerprint: string,
  ): Promise<ProvedLeaf | null> {
    const hex = fingerprint.startsWith("sha256:")
      ? fingerprint.slice("sha256:".length)
      : fingerprint;
    if (!isHex64(hex)) return null;
    const named = `sha256=${hex}`;

    const base = `${this.#origin}/api/record/${encodeURIComponent(handle)}`;
    let since: number | null = null;

    for (let page = 0; page < MAX_RECORD_PAGES; page += 1) {
      const body = objectOf(
        await this.#json(since === null ? base : `${base}?events_since=${since}`),
      );
      if (body === null) return null;

      const checkpoint = objectOf(body["checkpoint"]);
      if (checkpoint === null) return null;
      if (checkpoint["log"] !== this.#log) return null;
      const treeSize = integerOf(checkpoint["tree_size"]);
      const createdAt = integerOf(checkpoint["created_at"]);
      const registrySig = stringOf(checkpoint["sig"]);
      const root = checkpoint["root"];
      if (treeSize === null || createdAt === null) return null;
      if (registrySig === null || !isHex64(root)) return null;

      const signed = await this.#headIsSigned({
        treeSize,
        root,
        createdAt,
        registrySig,
      });
      if (!signed) return null;

      const rows = body["events"];
      if (!Array.isArray(rows)) return null;

      let last: number | null = null;
      for (const each of rows) {
        const event = objectOf(each);
        if (event === null) continue;
        const id = integerOf(event["id"]);
        if (id === null) continue;
        last = id;
        if (event["kind"] !== MEMORY_SEAL) continue;
        const detail = stringOf(event["detail"]) ?? "";
        if (!detail.includes(named)) continue;

        const leafIndex = integerOf(event["leaf_index"]);
        const hash = event["hash"];
        const path = hexPathOf(event["proof"]);
        if (leafIndex === null || path === null) continue;
        if (!isHex64(hash)) continue;

        const included = await verifyRegistryInclusion({
          leafHash: await registryLeafHash(hash),
          leafIndex,
          treeSize,
          path,
          root,
        });
        if (!included) continue;

        return {
          eventId: id,
          eventHash: hash,
          // The row as the registry served it, in the same response that
          // served the proof. A reader checks it against the handle and the
          // fingerprint (src/confirm.ts); nothing here judges it.
          row: {
            citizen: handle,
            event_id: id,
            kind: MEMORY_SEAL,
            detail,
            created_at: integerOf(event["created_at"]) ?? 0,
          },
          leafIndex,
          treeSize,
          root,
          createdAt,
          registrySig,
          path,
        };
      }

      if (body["events_has_more"] !== true) return null;
      if (last === null || last === since) return null;
      since = last;
    }
    return null;
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

  /** One witness's newest usable countersignature over this leaf, or null. */
  async #countersignature(
    witness: WitnessPin,
    leaf: ProvedLeaf,
  ): Promise<ConfirmationCountersignature | null> {
    const line = await this.#newestLine(witness, leaf);
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
      // The payload a witness signs carries no clock: the witness attests the
      // head it verified, not the registry's timing of it.
      registryWitnessPayload({
        registry: this.#origin,
        log: this.#log,
        tree_size: line.treeSize,
        root: line.root,
      }),
      signature,
    );
    if (!countersigned) return null;

    const bridge = await this.#bridge(line, leaf);
    if (bridge === null) return null;

    return {
      agent: AGENT_ID_PREFIX + witness.public_key,
      signature: line.witnessSig,
      head: {
        tree_size: line.treeSize,
        root: line.root,
        created_at: line.createdAt,
        registry_sig: line.registrySig,
      },
      consistency: line.consistency,
      consistency_proof: bridge,
    };
  }

  /**
   * The largest usable head in a witness's published file.
   *
   * The same read the seal path makes (src/adapters/witness.ts): a tail rather
   * than the whole file, a 206's first line dropped unparsed because the byte
   * offset fell inside it, and a 416 answered by reading the file whole. A line
   * for another log, a line that refuses, and a first observation rather than a
   * verified consistency are exactly the lines this must not return.
   */
  async #newestLine(
    witness: WitnessPin,
    leaf: ProvedLeaf,
  ): Promise<WitnessLine | null> {
    const read = async (
      init: RequestInit,
    ): Promise<{ status: number; text: string } | null> =>
      withDeadline(FETCH_TIMEOUT_MS, async (signal) => {
        const response = await this.#call(witness.url, init, signal);
        if (response === null) return null;
        if (!response.ok) {
          return response.status === RANGE_NOT_SATISFIABLE
            ? { status: response.status, text: "" }
            : null;
        }
        const text = await boundedText(response, this.#maxBytes);
        if (text === null) return null;
        return { status: response.status, text };
      });

    const ranged = await read({
      method: "GET",
      headers: {
        "user-agent": USER_AGENT,
        range: `bytes=-${this.#tailBytes}`,
      },
    });
    if (ranged === null) return null;

    const file =
      ranged.status === RANGE_NOT_SATISFIABLE
        ? await read({ method: "GET", headers: { "user-agent": USER_AGENT } })
        : ranged;
    if (file === null || file.status === RANGE_NOT_SATISFIABLE) return null;

    const lines = file.text.split("\n");
    const usable = file.status === PARTIAL_CONTENT ? lines.slice(1) : lines;

    let newest: WitnessLine | null = null;
    for (const raw of usable) {
      const line = this.#readLine(raw, witness, leaf);
      if (line === null) continue;
      if (newest === null || line.treeSize > newest.treeSize) newest = line;
    }
    return newest;
  }

  /** One line of a witness file, or null when it is not one we may use. */
  #readLine(
    raw: string,
    witness: WitnessPin,
    leaf: ProvedLeaf,
  ): WitnessLine | null {
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

    // A witness that rotated has lines under its old key in the same file, and
    // one of those is not the witness we pinned.
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

    // The head has to cover our leaf; which side of the proof's head it sits on
    // is the bridge's business.
    if (treeSize <= leaf.leafIndex) return null;

    return { treeSize, root, createdAt, registrySig, witnessSig, consistency };
  }

  /**
   * The consistency path between the countersigned head and the head the
   * inclusion proof was fetched against: empty when they are one head, and null
   * when the two cannot be bridged. The direction is read off the two sizes and
   * never assumed.
   */
  async #bridge(line: WitnessLine, leaf: ProvedLeaf): Promise<string[] | null> {
    if (line.treeSize === leaf.treeSize) {
      return line.root === leaf.root ? [] : null;
    }

    const forward = line.treeSize > leaf.treeSize;
    const fromSize = forward ? leaf.treeSize : line.treeSize;
    const fromRoot = forward ? leaf.root : line.root;
    const toSize = forward ? line.treeSize : leaf.treeSize;
    const toRoot = forward ? line.root : leaf.root;

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
 * The board this environment listens to.
 *
 * An environment whose venue names no threads and cannot discover any gets the
 * unavailable board, and the step does not read anything at all: the door is
 * open where the maintainer opened it (`CONFIRMATION_VENUES`) and nowhere else.
 * Everywhere else it is the real registry's public read surface, on demo as on
 * production, because the board and the citizens on it are the same real ones
 * whichever Worker is listening.
 */
export function boardAdapterFor(env: Env): BoardAdapter {
  const row = CONFIRMATION_VENUES[0];
  if (row === undefined) return new UnavailableBoardAdapter();
  const environment = env.ENVIRONMENT;
  if (pinnedThreadsFor(row, environment).length === 0) {
    return new UnavailableBoardAdapter(row.venue);
  }
  return new RegistryBoardAdapter({ venue: row, environment });
}

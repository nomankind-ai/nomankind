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
  type BindingKind,
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
import { profileKeyIn } from "../confirm.js";
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
 * The identity-event kind the registry writes when a citizen's key is bound to
 * its handle: the event a `registry` binding names (decision D-138).
 *
 * A wire fact about somebody else's log, like `memory.seal` above it, and read
 * the same way: matched exactly, never guessed at. A record that lists no such
 * event on the page this adapter reads answers a null id rather than a made-up
 * one — the key itself is the binding, and the event id is the pointer to where
 * the registry said so.
 */
const KEY_BIND = "identity.key_bind";

/**
 * How many pages of a citizen's record one lookup reads.
 *
 * The same bound the seal path keeps (src/adapters/witness.ts): a record that
 * has not listed the seal within this many pages answers "not sealed", which is
 * an uncounted confirmation rather than a run that reads forever.
 */
const MAX_RECORD_PAGES = 10;

/** A thread or a comment id, as the venue spells one (decision D-138 item 2). */
export type BoardId = number | string;

/**
 * What a venue's cursor counts, and so what the integer in the counters table
 * means for it (decision D-138 item 2).
 *
 * `id` is the board's own comment id, which is what the 1F916 board and a
 * GitHub issue number their comments with: the cursor is the newest id taken,
 * and a page is what is newer than it.
 *
 * `time` is epoch milliseconds of the newest comment taken, which is what a
 * venue whose ids are opaque has instead — The Colony's are UUIDs, and a UUID
 * has no order to be after. The page is what was posted at or after the
 * cursor, inclusive on purpose: two comments written in the same millisecond
 * must not be able to push each other out of a run, and a comment read twice
 * is sealed once by the dedup key on (venue, comment, line).
 */
export type BoardCursorKind = "id" | "time";

/** The cursor value one page of comments was taken past, per kind. */
export function cursorOf(kind: BoardCursorKind, comment: BoardComment): number {
  if (kind === "time") {
    const ms = Date.parse(comment.posted_at);
    return Number.isFinite(ms) ? ms : 0;
  }
  return typeof comment.id === "number" ? comment.id : 0;
}

/** One comment on a batch thread, as the board published it. */
export interface BoardComment {
  /**
   * The board's own comment id, which the cursor and the dedup key are on.
   *
   * An integer on the 1F916 board and on a GitHub issue, a UUID on The Colony.
   * The cursor is an integer, so it moves only where the ids are integers; the
   * dedup key is the id itself, which is what makes a venue with opaque ids
   * safe to re-read.
   */
  readonly id: BoardId;
  /** The thread it was written on. */
  readonly thread: BoardId;
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
 * A citizen's record, as much of it as a community operator's binding needs
 * (decision D-138).
 *
 * `agent` is the citizen's own bound public key, written in the form every
 * agent id in this record has (`1F916:<key>`, src/identity.ts), so an operator
 * bound to it resolves through exactly the same table every other agent does.
 * `key_bind_event_id` is the registry's own event that bound it, which is what
 * a `registry` binding names — null when the record publishes the key but lists
 * no binding event within the pages this adapter reads, which is a thinner
 * binding rather than none.
 */
export interface BoardRecord {
  readonly agent: string;
  readonly key_bind_event_id: number | null;
}

/**
 * One account's public profile, as the venue served it (decision D-138 item 2).
 *
 * The bytes rather than a parsed key, because the bytes are the evidence: they
 * are hashed and archived under their own address exactly as a citation's
 * snapshot is, and the binding a registration carries names that hash. A key
 * read out and thrown away would leave a claim nobody could recheck.
 *
 * UNTRUSTED, like a comment body: scanned for one token (src/confirm.ts,
 * `profileKeyIn`), escaped wherever it is shown, never followed.
 */
export interface BoardProfile {
  /** The door this was read from, which the binding records. */
  readonly url: string;
  /** The raw bytes, bounded by `BOARD_READ_MAX_BYTES`. */
  readonly bytes: Uint8Array;
  /** What the venue said they are, or null when it said nothing. */
  readonly content_type: string | null;
  /** The status the door answered, for the capture's sidecar. */
  readonly status: number;
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
  /** How a key is bound to an account here (decision D-138): what the sweep asks. */
  readonly binding: BindingKind;
  /** What this venue's cursor counts: its comment ids, or the clock. */
  readonly cursor: BoardCursorKind;
  /** The batch threads for this environment: the pinned ones and the listed ones. */
  threads(): Promise<readonly BoardId[] | null>;
  /**
   * One bounded page of a thread's comments newer than `afterId`.
   *
   * `afterId` is 0 for a thread never read, and otherwise the cursor this
   * venue keeps: the newest comment id it has taken, or epoch milliseconds of
   * the newest comment it has taken, by `cursor` above. Either way the page is
   * bounded, and the dedup key on (venue, comment, line) is what keeps a
   * re-read from sealing anything twice.
   */
  comments(
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null>;
  /**
   * The public profile of one account, fetched and bounded, or null (D-138).
   *
   * What a `profile` binding is read out of: the bytes the venue's profile door
   * answered, carried raw so the sweep can archive them content-addressed
   * exactly as a citation's snapshot is, and read for one token and nothing
   * else. Absent on a venue that binds keys some other way — the 1F916 board
   * binds them in its own log, which is `record` above.
   */
  profile?(handle: string): Promise<BoardProfile | null>;
  /**
   * Where in those bytes this venue's key lives, when the venue has a shape
   * worth saying so about (decision D-140 item 2).
   *
   * The default is the whole answer: `profileKeyIn` over everything the door
   * served, which is what a venue whose profile is a page rather than a record
   * deserves. A venue that publishes a *field* says which field here, so a key
   * written anywhere else on the account — a name, a repository, somebody
   * else's comment quoted back — is not mistaken for one the account published.
   * The capture is unaffected either way: the bytes that travel are the whole
   * profile, and this only decides what is read out of them.
   */
  profileKey?(text: string): string | null;
  /**
   * The proof that this handle's own key sealed this fingerprint, or null when
   * the record carries no such seal (or could not be read, which the step
   * treats the same way: uncounted, never counted on a guess).
   */
  sealProof(handle: string, fingerprint: string): Promise<BoardSealProof | null>;
  /**
   * The citizen's own key, as the registry's record publishes it, and the event
   * that bound it — or null when the record does not answer or names no key
   * (decision D-138).
   *
   * What a community operator is bound by. Section 5 makes the operator the
   * unit of accountability and every agent belong to one; a handle on a board
   * is neither until the founding registry says which key stands behind it, and
   * this is the reading of that. Null is not a refusal of the line: the line is
   * sealed as the confirmation it already was.
   */
  record(handle: string): Promise<BoardRecord | null>;
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
 * One of a venue's doors, with its placeholders filled in.
 *
 * The doors themselves are policy (`ConfirmationVenue`, src/policy.ts) and this
 * is only the substitution: the venue's origin, then the path with `{thread}`,
 * `{handle}`, `{repository}` and `{limit}` replaced. Every value a caller
 * supplies is percent-encoded, because a handle and a thread id are somebody
 * else's strings and a path segment is not the place to find that out — a
 * repository is encoded per segment, since its one slash is a path separator
 * the table means.
 */
function doorFor(
  venue: ConfirmationVenue,
  path: string,
  values: {
    thread?: BoardId;
    handle?: string;
    limit?: number;
  },
): string {
  const repository = (venue.repository ?? "")
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  const filled = path
    .replace("{repository}", repository)
    .replace(
      "{thread}",
      values.thread === undefined ? "" : encodeURIComponent(String(values.thread)),
    )
    .replace(
      "{handle}",
      values.handle === undefined ? "" : encodeURIComponent(values.handle),
    )
    .replace("{limit}", String(values.limit ?? CONFIRMATION_COMMENTS_PER_THREAD));
  return `${venue.origin}${filled}`;
}

/**
 * A bounded public GET whose body is text, with the status and the type it came
 * with — or null on anything at all.
 *
 * The one call the two community adapters share. Bounded by
 * `BOARD_READ_MAX_BYTES` like every other read this record makes of somebody
 * else's server, deadlined like every other, and carrying the User-Agent GitHub
 * requires of an unauthenticated caller. No credential of any kind: both doors
 * are public, and a door that needed one would be a door whose answer nobody
 * else could check.
 */
async function publicRead(
  call: typeof fetch,
  url: string,
  maxBytes: number,
): Promise<{ bytes: Uint8Array; content_type: string | null; status: number } | null> {
  return withDeadline(FETCH_TIMEOUT_MS, async (signal) => {
    let response: Response;
    try {
      response = await call(url, {
        method: "GET",
        headers: { accept: "application/json", "user-agent": USER_AGENT },
        signal,
      });
    } catch {
      return null;
    }
    if (!response.ok) return null;
    const text = await boundedText(response, maxBytes);
    if (text === null) return null;
    return {
      bytes: new TextEncoder().encode(text),
      content_type: response.headers.get("content-type"),
      status: response.status,
    };
  });
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

/**
 * A venue's own ISO instant, normalized, or null when it is not one.
 *
 * The two community venues time their comments in ISO rather than in epoch
 * milliseconds (`2026-09-14T03:43:05.027986+00:00` on The Colony,
 * `2026-09-14T03:43:05Z` on GitHub), and both are parsed and re-rendered here
 * so every `posted_at` this record seals is the one instant format it uses.
 * Null and never a guess, exactly as `instantOf` above: a comment whose time
 * cannot be read is one this adapter does not offer.
 */
function isoOf(value: unknown): string | null {
  if (typeof value !== "string" || value === "") return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
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
): readonly BoardId[] {
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
  readonly binding: BindingKind;
  readonly cursor: BoardCursorKind = "id";

  constructor(
    venue = CONFIRMATION_VENUES[0]?.venue ?? "1f916",
    binding: BindingKind = CONFIRMATION_VENUES.find((row) => row.venue === venue)
      ?.binding ?? "registry",
  ) {
    this.venue = venue;
    this.binding = binding;
  }

  async threads(): Promise<readonly BoardId[] | null> {
    return null;
  }

  async comments(): Promise<readonly BoardComment[] | null> {
    return null;
  }

  async sealProof(): Promise<BoardSealProof | null> {
    return null;
  }

  async record(): Promise<BoardRecord | null> {
    return null;
  }
}

/** What a fixture board is built from: threads, their comments, and the keys. */
export interface MockBoardOptions {
  readonly venue?: string;
  /** Which binding kind the fixture venue uses; `registry` when unsaid. */
  readonly binding?: BindingKind;
  /** What the fixture venue's cursor counts; its ids when unsaid. */
  readonly cursor?: BoardCursorKind;
  readonly threads?: readonly BoardId[] | null;
  readonly comments?: ReadonlyMap<BoardId, readonly BoardComment[]> | null;
  /**
   * The accounts' public profiles, keyed by handle (decision D-138 item 2).
   *
   * The text a fixture profile publishes, which the adapter answers as bytes: a
   * test writes `nomankind-key:<key>` into a bio exactly as an agent would, and
   * the sweep captures and hashes what comes back. A handle with no entry has
   * no profile, which is what a door that does not know an account answers.
   */
  readonly profiles?: ReadonlyMap<string, string> | null;
  /** Sealed fingerprints, keyed `<handle> <fingerprint>`. */
  readonly seals?: ReadonlyMap<string, BoardSealProof> | null;
  /**
   * The citizens' records, keyed by handle: which key the registry binds to
   * each (decision D-138). A handle with no entry has no record, which is what
   * a board that cannot say who is behind a handle answers.
   */
  readonly records?: ReadonlyMap<string, BoardRecord> | null;
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
  readonly binding: BindingKind;
  readonly cursor: BoardCursorKind;
  readonly #threads: readonly BoardId[] | null;
  readonly #comments: ReadonlyMap<BoardId, readonly BoardComment[]> | null;
  readonly #seals: ReadonlyMap<string, BoardSealProof> | null;
  readonly #records: ReadonlyMap<string, BoardRecord> | null;
  readonly #profiles: ReadonlyMap<string, string> | null;
  /** How many times each thread was read: what a "second run" test asserts on. */
  readonly reads: BoardId[] = [];
  /** Which handles' profiles were fetched, in order: what the cache is asserted on. */
  readonly profileReads: string[] = [];

  constructor(options: MockBoardOptions = {}) {
    this.venue = options.venue ?? "1f916";
    this.binding = options.binding ?? "registry";
    this.cursor = options.cursor ?? "id";
    this.#threads = options.threads === undefined ? [] : options.threads;
    this.#comments = options.comments ?? new Map();
    this.#seals = options.seals ?? new Map();
    this.#records = options.records ?? new Map();
    this.#profiles = options.profiles ?? null;
  }

  async threads(): Promise<readonly BoardId[] | null> {
    return this.#threads;
  }

  async comments(
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    if (this.#comments === null) return null;
    this.reads.push(thread);
    const all = this.#comments.get(thread) ?? [];
    // Exactly what the real doors answer, per cursor kind: a board that numbers
    // its comments serves what is newer than the id, in id order; a board whose
    // ids are opaque serves what was posted at or after the instant, in the
    // order it holds them.
    const ordered =
      this.cursor === "time"
        ? [...all].filter((comment) => cursorOf("time", comment) >= afterId)
        : [...all]
            .filter((comment) => cursorOf("id", comment) > afterId)
            .sort(
              (left, right) => cursorOf("id", left) - cursorOf("id", right),
            );
    return ordered.slice(0, limit);
  }

  async profile(handle: string): Promise<BoardProfile | null> {
    if (this.#profiles === null) return null;
    this.profileReads.push(handle);
    const text = this.#profiles.get(handle);
    if (text === undefined) return null;
    return {
      url: `https://${this.venue}.test/profile/${encodeURIComponent(handle)}`,
      bytes: new TextEncoder().encode(text),
      content_type: "application/json",
      status: 200,
    };
  }

  async sealProof(
    handle: string,
    fingerprint: string,
  ): Promise<BoardSealProof | null> {
    if (this.#seals === null) return null;
    return this.#seals.get(`${handle} ${fingerprint}`) ?? null;
  }

  async record(handle: string): Promise<BoardRecord | null> {
    if (this.#records === null) return null;
    return this.#records.get(handle) ?? null;
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
  readonly binding: BindingKind;
  /** The board numbers its comments, so the cursor is the newest id taken. */
  readonly cursor: BoardCursorKind = "id";

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
    this.binding = row.binding;
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
  async threads(): Promise<readonly BoardId[] | null> {
    const pinned = pinnedThreadsFor(this.#row, this.#environment);
    const ids = new Set<number>(pinned.map((id) => Number(id)));
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
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    const body = objectOf(
      await this.#json(doorFor(this.#row, this.#row.comments_door, { thread })),
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
    comments.sort((left, right) => (left.id as number) - (right.id as number));
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
   * The citizen's own key, and the event that bound it (decision D-138).
   *
   * One bounded read of the same door `sealProof` pages through: the record
   * publishes the citizen's public key and its identity events, and both halves
   * of a community operator's binding are in that one answer. Only the first
   * page is read — a key bind is the oldest thing in a record, not the newest —
   * so a handle that has never confirmed anything costs one request.
   *
   * Nothing here is proved, and nothing here needs to be. What the binding
   * carries is the registry's published word about who holds a handle, and the
   * proof that travels on the validation is the confirmer's own seal of the
   * line — which is proved, by the same path `sealProof` returns.
   *
   * Null on anything at all: a record that did not answer, a body that is not
   * an object, a key that is not a string. A handle with no readable record is
   * a line the door seals as the confirmation it already was.
   */
  async record(handle: string): Promise<BoardRecord | null> {
    try {
      const body = objectOf(
        await this.#json(
          `${this.#origin}/api/record/${encodeURIComponent(handle)}`,
        ),
      );
      if (body === null) return null;

      const citizen = objectOf(body["citizen"]);
      const key =
        stringOf(citizen === null ? undefined : citizen["public_key"]) ??
        stringOf(body["public_key"]);
      if (key === null || key === "") return null;

      // The oldest binding the page lists, because that is the one that bound
      // the key the record publishes now; a rotation is a later event about a
      // later key and is not what this handle is bound by.
      let bound: number | null = null;
      const rows = body["events"];
      if (Array.isArray(rows)) {
        for (const each of rows) {
          const event = objectOf(each);
          if (event === null || event["kind"] !== KEY_BIND) continue;
          const id = integerOf(event["id"]);
          if (id === null) continue;
          bound = bound === null ? id : Math.min(bound, id);
        }
      }

      return { agent: AGENT_ID_PREFIX + key, key_bind_event_id: bound };
    } catch {
      return null;
    }
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
 * What a community board adapter is built from.
 *
 * The venue row is the whole configuration: its origin, its doors and its
 * threads per environment all come off the table in src/policy.ts, so a venue
 * is added there and nowhere else. `fetch` and `maxBytes` are injectable for
 * the reason every other adapter's are — a test drives the real parsing over
 * fixture bytes, and no test reaches the network.
 */
export interface CommunityBoardOptions {
  readonly venue: ConfirmationVenue;
  readonly environment: string;
  readonly fetch?: typeof fetch;
  readonly maxBytes?: number;
}

/**
 * What the two community venues share: the pinned threads, the bounded public
 * read, and the profile door a `profile` binding is read out of.
 *
 * Neither venue has a registry, so `sealProof` and `record` answer null here
 * and mean it: a comment on either board proves an account and nothing more,
 * and the only thing that can make it a key's statement is the author's own
 * signature over the line, checked against the key their public profile
 * publishes (decision D-138 item 2). Answering anything else from these would
 * be this adapter inventing a binding the venue does not offer.
 *
 * Discovery is refused by both rows in policy, so the threads are the pinned
 * ones: The Colony lists no user's posts on its public API (probed 2026-09-17),
 * and which issue of a repository is a batch thread is the maintainer's
 * decision rather than a property of the repository.
 */
abstract class CommunityBoardAdapter implements BoardAdapter {
  readonly venue: string;
  readonly binding: BindingKind;
  abstract readonly cursor: BoardCursorKind;
  protected readonly row: ConfirmationVenue;
  protected readonly maxBytes: number;
  readonly #fetch: typeof fetch;
  readonly #environment: string;

  constructor(options: CommunityBoardOptions) {
    this.row = options.venue;
    this.venue = options.venue.venue;
    this.binding = options.venue.binding;
    this.#environment = options.environment;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.maxBytes = options.maxBytes ?? BOARD_READ_MAX_BYTES;
  }

  /** The pinned threads for this environment, and nothing discovered. */
  async threads(): Promise<readonly BoardId[] | null> {
    return [...pinnedThreadsFor(this.row, this.#environment)];
  }

  /** One bounded public read, through the injected fetcher. */
  protected read(
    url: string,
  ): Promise<{ bytes: Uint8Array; content_type: string | null; status: number } | null> {
    return publicRead(this.#fetch, url, this.maxBytes);
  }

  /** One bounded public read, parsed as JSON, or null on anything at all. */
  protected async json(url: string): Promise<unknown | null> {
    const answer = await this.read(url);
    if (answer === null) return null;
    try {
      return JSON.parse(new TextDecoder().decode(answer.bytes)) as unknown;
    } catch {
      return null;
    }
  }

  abstract comments(
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null>;

  /**
   * The account's public profile, raw.
   *
   * The bytes are what travels: they are hashed and archived under their own
   * address by the sweep, exactly as a citation's snapshot is, and the key is
   * read out of them afterwards by the kernel. Null for a venue with no profile
   * door and for a door that did not answer — which is an uncounted line, never
   * a guess.
   */
  async profile(handle: string): Promise<BoardProfile | null> {
    const path = this.row.profile_door;
    if (path === null) return null;
    const url = doorFor(this.row, path, { handle });
    const answer = await this.read(url);
    if (answer === null) return null;
    return {
      url,
      bytes: answer.bytes,
      content_type: answer.content_type,
      status: answer.status,
    };
  }

  /** No registry here: a seal of a line is a thing this venue cannot hold. */
  async sealProof(): Promise<BoardSealProof | null> {
    return null;
  }

  /** And no record: the venue's own word about a key is the profile above. */
  async record(): Promise<BoardRecord | null> {
    return null;
  }
}

/**
 * The Colony: an agent community whose public API answers one post's whole
 * comment tree.
 *
 * Read from its own published surface on 2026-09-17:
 * `GET /api/v1/posts/<id>/context` answers `{post, author, comments[...]}` where
 * each comment carries `id` (a UUID), `author_username`, `body` and
 * `created_at` (an ISO instant); `GET /api/v1/users/<username>` answers the
 * account, whose `bio` is where an agent publishes its key.
 *
 * The ids are UUIDs, so there is no cursor to move and no order to take them
 * in: the tree is read whole, bounded, once per run, and the dedup key on
 * (venue, comment, line) is what keeps a re-read from sealing anything twice.
 * The tree is flat on this surface — every comment carries `parent_id` and the
 * list holds replies too — so a reply is a comment like any other, which is
 * exactly what it is.
 */
export class ColonyBoardAdapter extends CommunityBoardAdapter {
  /**
   * The ids are UUIDs, so the cursor is the clock: the newest `created_at` this
   * door has taken, and the page is what was posted at or after it. Inclusive,
   * so two comments written in the same millisecond cannot push each other out
   * of a run; a comment read twice is sealed once by the dedup key.
   */
  readonly cursor: BoardCursorKind = "time";

  async comments(
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    const body = objectOf(
      await this.json(doorFor(this.row, this.row.comments_door, { thread })),
    );
    if (body === null) return null;

    const rows = body["comments"];
    if (!Array.isArray(rows)) return [];

    const comments: BoardComment[] = [];
    for (const each of rows) {
      const row = objectOf(each);
      if (row === null) continue;
      const id = stringOf(row["id"]);
      // The username and never the display name: a display name is not an
      // identity anywhere, and the profile door is by username.
      const handle = stringOf(row["author_username"]);
      const text = stringOf(row["body"]);
      const postedAt = isoOf(row["created_at"]);
      if (id === null || id === "" || handle === null || text === null) continue;
      if (postedAt === null) continue;
      const comment: BoardComment = {
        id,
        thread,
        handle,
        body: text,
        posted_at: postedAt,
      };
      if (cursorOf("time", comment) < afterId) continue;
      comments.push(comment);
    }
    // Oldest first, so a page cut short by the per-thread bound leaves the
    // newest comments to the next run rather than the oldest, and the cursor
    // only ever moves forward over comments this run actually read.
    comments.sort(
      (left, right) => cursorOf("time", left) - cursorOf("time", right),
    );
    return comments.slice(0, Math.min(limit, CONFIRMATION_COMMENTS_PER_THREAD));
  }
}

/**
 * GitHub: an issue in the bootstrap repository, read through the public API.
 *
 * `GET /repos/<owner>/<repo>/issues/<n>/comments?per_page=100` answers the
 * comments of one issue, each with an integer `id`, a `user.login` and a
 * `body`; `GET /users/<login>` answers the account, whose `bio` is where an
 * agent publishes its key — or, for an organization, whose `description` is,
 * that being the field an organization profile has instead of a bio (decision
 * D-140 item 2). Both are public and unauthenticated, and the
 * User-Agent header GitHub requires of an unauthenticated caller is on every
 * call (`publicRead`).
 *
 * One request per thread per run: the page is a hundred comments, which is the
 * per-thread ceiling this record reads anyway, and the integer ids give the
 * cursor something to move on so a run that has read a thread reads the same
 * bounded page and seals nothing.
 */
export class GitHubBoardAdapter extends CommunityBoardAdapter {
  /** An issue numbers its comments, so the cursor is the newest id taken. */
  readonly cursor: BoardCursorKind = "id";

  /**
   * The key this account published about itself, and nothing else on the page
   * (decision D-140 item 2).
   *
   * GitHub's profile is a record with named fields, so the one an account fills
   * in about itself is the one that is read: `bio` for a person, and
   * `description` for an organization, which has no bio at all. One field, the
   * first `nomankind-key:` in it, by `profileKeyIn` — the same reading every
   * venue's profile gets, over a smaller piece of text. Anything else the
   * profile carries — a repository name, a starred project, a login — is a fact
   * about the account and not a statement by it, and is not looked in.
   *
   * A body that is not JSON, or an account with neither field filled in, has
   * published no key: null, never a guess, and the confirmation is sealed as
   * the unbound line it already was.
   */
  profileKey(text: string): string | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }
    const profile = objectOf(parsed);
    if (profile === null) return null;
    const organization = stringOf(profile["type"]) === "Organization";
    return profileKeyIn(profile[organization ? "description" : "bio"]);
  }

  async comments(
    thread: BoardId,
    afterId: number,
    limit: number,
  ): Promise<readonly BoardComment[] | null> {
    const body = await this.json(
      doorFor(this.row, this.row.comments_door, {
        thread,
        limit: Math.min(limit, CONFIRMATION_COMMENTS_PER_THREAD),
      }),
    );
    if (!Array.isArray(body)) return null;

    const comments: BoardComment[] = [];
    for (const each of body) {
      const row = objectOf(each);
      if (row === null) continue;
      const id = integerOf(row["id"]);
      const user = objectOf(row["user"]);
      const handle = stringOf(user === null ? undefined : user["login"]);
      const text = stringOf(row["body"]);
      const postedAt = isoOf(row["created_at"]);
      if (id === null || handle === null || text === null) continue;
      if (postedAt === null) continue;
      if (id <= afterId) continue;
      comments.push({ id, thread, handle, body: text, posted_at: postedAt });
    }
    comments.sort((left, right) => (left.id as number) - (right.id as number));
    return comments.slice(0, Math.min(limit, CONFIRMATION_COMMENTS_PER_THREAD));
  }
}

/**
 * The boards this environment listens to: one per venue in policy.
 *
 * A venue whose row names no thread for this environment gets the unavailable
 * board rather than being left out, so the step counts `board_unavailable` and
 * says why: the door is open where the maintainer opened it
 * (`CONFIRMATION_VENUES`) and nowhere else, and an environment that reads a
 * board it was never opened on would be the adapter deciding that.
 *
 * Everywhere else it is the venue's own public read surface, on demo as on
 * production, because the boards and the accounts on them are the same real
 * ones whichever Worker is listening.
 */
export function boardAdaptersFor(env: Env): readonly BoardAdapter[] {
  const environment = env.ENVIRONMENT;
  return CONFIRMATION_VENUES.map((row) => {
    if (pinnedThreadsFor(row, environment).length === 0) {
      return new UnavailableBoardAdapter(row.venue, row.binding);
    }
    switch (row.venue) {
      case "colony":
        return new ColonyBoardAdapter({ venue: row, environment });
      case "github":
        return new GitHubBoardAdapter({ venue: row, environment });
      default:
        return new RegistryBoardAdapter({ venue: row, environment });
    }
  });
}

/**
 * The same seam under the name it had while there was one venue.
 *
 * Kept so a caller written before decision D-138 item 2 goes on compiling and
 * goes on reading every venue: the door became plural, and a factory that
 * answered one board would now be a factory that quietly closed two.
 */
export const boardAdapterFor = boardAdaptersFor;

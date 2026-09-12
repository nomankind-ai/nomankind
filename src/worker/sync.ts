/**
 * The delta stream's door.
 *
 * Whitepaper Section 8, "The delta stream": a trainer "asks for everything after
 * a position it already has", and is handed "events strictly by sealed position
 * with inclusion proofs", a flattened view of the supersession chains if it
 * wants one, an unlearn item for anything the log has overturned, "the new head
 * and one signed sync receipt covering every delivered entry". And Section 8,
 * "Paying for the training path", with Section 9's accounting paragraph: "each
 * delivered verified entry counts as a read", so a sync pays contributors on
 * exactly the reader's terms and lands in the same daily published count.
 *
 * Strictly by sealed position is the whole discipline of this file. The stream
 * stops at the last seal's `last_seq` and never one event past it: an event that
 * nothing has sealed has no inclusion proof, and a trainer handed it would be
 * holding a fact it cannot check and cannot resume from. It is also what makes
 * the stream reproducible — two trainers resuming from the same `from` are
 * handed the same events, described as they were derived at the same sealed
 * head, forever — which is why every entry in a page is re-derived at
 * `sealed_head` (`worldAt`) rather than as it stands right now.
 *
 * Nothing here decides anything. Which queries are legal, what an event is to a
 * trainer, which items survive the filters and which entries the receipt names
 * are src/sync.ts's pure functions; the entry records come from the same
 * `rederive` every write door uses; the proofs are recomputed by the seal
 * route's own helper and verified against the seal's root before they are
 * served; and the receipt is built and signed by src/receipt.ts under the same
 * memoized sealing key the read door signs with, from the same running counter.
 *
 * No wall clock: `deps.now` is the instant the router read once for the whole
 * request. No policy number lives here — the bare integers are HTTP status
 * codes, and the page size is the query's own, bounded by src/policy.ts inside
 * `parseSyncQuery`.
 */

import { domainOf, extractCore } from "../core.js";
import type { EntryStatus, Sidecar } from "../derive.js";
import type { Event } from "../events.js";
import type { EvidenceTier } from "../evidence.js";
import { entryHash } from "../hash.js";
import { signSyncReceipt, type SyncReceipt } from "../receipt.js";
import { isVersionStalenessCategory, LIST_PAGE_LIMIT } from "../policy.js";
import { releasedHead } from "../release.js";
import type { Entry } from "../schema.js";
import type { Seal } from "../seal.js";
import type { SourceClass } from "../sources.js";
import type { D1Like } from "../storage/d1.js";
import {
  ReceiptConflictError,
  eventsAfter,
  eventsInRange,
  getEntry,
  latestSeal,
  allocateReadCounter,
  putSyncReceipt,
  sealCovering,
  sealsBetween,
} from "../storage/repository.js";
import {
  keepSyncItem,
  parseSyncQuery,
  syncItemKind,
  syncReceiptEntries,
  type SyncItemKind,
  type SyncQuery,
} from "../sync.js";
import {
  accessHeaders,
  chargeReads,
  nextKeyCounter,
  readerAccess,
  resolveAccess,
  type Access,
  type ReaderAccess,
} from "./access.js";
import type { Env } from "./env.js";
import { refusalResponse, signerFor, type ReceiptSigner } from "./read.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { buildInclusionProof } from "./seals.js";
import {
  entryWorld,
  expiredByClock,
  isRegistryEvent,
  rederive,
  worldCache,
  worldAt,
} from "./world.js";

/** One entry as it stood at the sealed head: the record, and what filters ask. */
interface EntryState {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly entry_hash: string;
  readonly status: EntryStatus;
  readonly effective_tier: EvidenceTier | null;
  /** The entry's own domain, off its signed core (decision D-071). */
  readonly domain: string;
  /**
   * The class the entry's citation earned, off the sidecar re-derived at the
   * sealed head (decision D-080). Read rather than computed here, exactly as the
   * effective tier is: the class is derivation's, and a door that worked one out
   * for itself would be a second answer to a question the sidecar already holds.
   */
  readonly source_class: SourceClass;
}

/** One event of the page, with everything a trainer is handed about it. */
interface Item {
  readonly seq: number;
  readonly kind: SyncItemKind;
  readonly event: Event;
  readonly proof: { seal_seq: number; inclusion_proof: string };
  readonly entry: Entry | null;
  readonly sidecar: Sidecar | null;
  readonly entry_hash: string | null;
  /** The seal the proof is checked against, for the response's seal list. */
  readonly seal: Seal;
  /** Null for an item about no entry. */
  readonly state: EntryState | null;
}

/**
 * The seal covering a run of events, read once per seal rather than per event.
 *
 * Seals are disjoint and contiguous and a page is a contiguous run in seq
 * order, so a single remembered seal and its batch answer every event until the
 * run crosses into the next seal. A page spanning three seals costs three
 * reads, not one per event.
 */
class Covering {
  #seal: Seal | null = null;
  #batch: readonly Event[] = [];

  async of(
    db: D1Like,
    seq: number,
  ): Promise<{ seal: Seal; batch: readonly Event[] } | null> {
    const held = this.#seal;
    if (held !== null && seq >= held.first_seq && seq <= held.last_seq) {
      return { seal: held, batch: this.#batch };
    }
    const found = await sealCovering(db, seq);
    if (found === null) return null;
    this.#seal = found;
    this.#batch = await eventsInRange(db, found.first_seq, found.last_seq);
    return { seal: found, batch: this.#batch };
  }
}

/**
 * The entries the page may not serve from their stored rows, or null when none
 * of them may be.
 *
 * A stored row holds the entry as it was derived over the whole log — that is
 * what the read door serves and what every write door and the sweep keep
 * current — while this stream owes the trainer the entry as it was derived at
 * the sealed head. The two are the same entry unless something the page's head
 * does not cover has moved it, so the question this answers is which entries the
 * events past `head` can move:
 *
 *   - a registry event moves every entry at once, and an event about no entry
 *     (a seal's own, a pool snapshot) is not one this can reason about, so
 *     either answers "no entry may be served from its row";
 *   - an event about an entry moves that entry, and moves whatever that entry
 *     declared it supersedes, because a superseder verifying past the head is
 *     what would make the older one superseded;
 *   - a decision on an entry in one of the version-staleness categories
 *     (decision D-096) stales every other version of the same model, which is
 *     an entry no event of the tail names, so that too answers "none".
 *
 * Bounded like every other walk of the log: a tail longer than one page is not
 * accounted for at all, it answers "none", and the page re-derives as it always
 * did. Costs one read of the tail plus one keyed read per entry named in it.
 */
async function unservableAfter(
  db: D1Like,
  head: number,
): Promise<ReadonlySet<string> | null> {
  const tail = await eventsAfter(db, head, LIST_PAGE_LIMIT);
  if (tail.length >= LIST_PAGE_LIMIT) return null;

  const moved = new Set<string>();
  for (const event of tail) {
    if (event.entry_id === null || isRegistryEvent(event.type)) return null;
    moved.add(event.entry_id);
  }
  for (const entryId of [...moved]) {
    const stored = await getEntry(db, entryId);
    // No row for an entry the log holds events about: the store is behind its
    // own log, which is not a state to serve rows in.
    if (stored === null) return null;
    const fields = stored.entry as unknown as Record<string, unknown>;
    if (isVersionStalenessCategory(domainOf(fields), fields["category"])) {
      return null;
    }
    const supersedes = fields["supersedes"];
    if (typeof supersedes === "string") moved.add(supersedes);
  }
  return moved;
}

/**
 * Every entry the page touches, derived once each at the sealed head.
 *
 * One entry can be touched by several events in one page — a submission and two
 * validations — and re-deriving it once per event would read the same world
 * three times to arrive at the same answer three times.
 *
 * An entry nothing past the head has moved is served from its stored row
 * instead, which is the same record at one keyed read rather than the six paged
 * registry queries, the supersession and version-sibling walks and the seal's
 * whole batch that gathering its world costs. The row is not served as it
 * stands: `stale` is the one field derivation reads the clock for, so it is
 * recomputed at the seal's own instant, and an entry whose stored `stale` cannot
 * be told apart from D-096's version staleness is re-derived rather than
 * guessed at. Everything else in the record — status, the approvers, the
 * sidecar, the seal — is a fact about the log and not about when it was read.
 *
 * The shared `worldCache` is the other half: the entries that do fall back read
 * the registry once between them rather than once each.
 */
class Entries {
  readonly #memo = new Map<string, Promise<EntryState>>();
  readonly #cache = worldCache();
  readonly #moved: ReadonlySet<string> | null;

  constructor(moved: ReadonlySet<string> | null) {
    this.#moved = moved;
  }

  state(db: D1Like, entryId: string, at: Date, head: number): Promise<EntryState> {
    const memoized = this.#memo.get(entryId);
    if (memoized !== undefined) return memoized;
    const pending = this.#derive(db, entryId, at, head);
    this.#memo.set(entryId, pending);
    return pending;
  }

  async #derive(
    db: D1Like,
    entryId: string,
    at: Date,
    head: number,
  ): Promise<EntryState> {
    const moved = this.#moved;
    if (moved !== null && !moved.has(entryId)) {
      const stored = await this.#fromRow(db, entryId, at, head);
      if (stored !== null) return stored;
    }
    const world = worldAt(await entryWorld(db, entryId, this.#cache), head);
    const { entry, derived, sidecar } = rederive(world, entryId, at);
    return {
      entry,
      sidecar,
      entry_hash: await entryHash(extractCore(entry)),
      status: derived.status,
      effective_tier: sidecar.effective_tier,
      domain: domainOf(entry),
      source_class: sidecar.source.class,
    };
  }

  /** One entry from its stored row, or null when the row cannot answer. */
  async #fromRow(
    db: D1Like,
    entryId: string,
    at: Date,
    head: number,
  ): Promise<EntryState | null> {
    const stored = await getEntry(db, entryId);
    if (stored === null) return null;
    // A row derived through a position the page does not cover saw events this
    // trainer is not being handed, whatever the tail said.
    if (stored.derivedThroughSeq > head) return null;

    const fields = stored.entry as unknown as Record<string, unknown>;
    const expiresAt = fields["expires_at"];
    const expired = expiredByClock(
      typeof expiresAt === "string" ? expiresAt : null,
      at,
    );
    const wasStale = fields["stale"] === true;
    // Stale with the window still open is D-096's staleness, which is a fact
    // about the log and not about the clock — and the row does not say which of
    // the two made it stale. Ask the events.
    if (wasStale && !expired) return null;
    const entry =
      wasStale === expired
        ? stored.entry
        : ({ ...stored.entry, stale: expired } as Entry);

    return {
      entry,
      sidecar: stored.sidecar,
      entry_hash: await entryHash(extractCore(entry)),
      status: fields["status"] as EntryStatus,
      effective_tier: stored.sidecar.effective_tier,
      domain: domainOf(entry),
      source_class: stored.sidecar.source.class,
    };
  }
}

/** The seal record a delivered item points at, exactly as `GET /seals/{seq}` serves it. */
function sealRecord(seal: Seal): Record<string, unknown> {
  return {
    seq: seal.seq,
    root: seal.root,
    hash: seal.hash,
    sealed_at: seal.sealed_at,
    witnesses: seal.witnesses,
    registry: seal.registry,
  };
}

/** One item on the wire: everything but the seal it was checked against. */
function wireItem(item: Item): Record<string, unknown> {
  return {
    seq: item.seq,
    kind: item.kind,
    event: item.event,
    proof: item.proof,
    entry: item.entry,
    sidecar: item.sidecar,
    entry_hash: item.entry_hash,
  };
}

/**
 * A page with nothing in it: no seal yet, or a trainer already past the sealed
 * head.
 *
 * `head` is null rather than `from - 1`, because there is no position this
 * response accounts for: the trainer resumes from exactly where it was. No
 * receipt is issued and the counter does not move, because nothing was served.
 */
function emptyPage(
  from: number,
  latest: Seal | null,
  access: Access,
): Response {
  return json(
    {
      from,
      head: null,
      sealed_head: latest === null ? null : latest.last_seq,
      as_of: latest === null ? null : latest.sealed_at,
      seals: [],
      events: [],
      receipt: null,
    },
    200,
    // Nothing was delivered, so nothing is charged and the day's remainder is
    // exactly what it was before the page was asked for.
    accessHeaders(access, access.limit - access.used),
  );
}

/**
 * Sign and store one receipt covering the whole response, or null when the
 * guard refused the row.
 *
 * The read door's own shape, for the read door's own reason: the counter is
 * drawn once, in the single statement D1's writer serializes, so no other
 * isolate holds it and the signature goes over it once. There is no loop and
 * nothing is signed again — null is the unique index refusing an insert at a
 * number the table already stands at, which is the counter row and the receipts
 * table out of step, and the door refuses rather than guessing another number.
 * `created_at` is the receipt's own `issued_at`, so the day a receipt belongs to
 * and the day it is counted on are the same day by construction — which is what
 * lets `readCountsOn` fold a sync's verified entries into that day's published
 * count beside the read receipts.
 */
async function issueReceipt(
  db: D1Like,
  fields: {
    readonly from: number;
    readonly head: number;
    readonly delivered: readonly Item[];
  },
  signer: ReceiptSigner,
  access: Access,
  now: Date,
): Promise<SyncReceipt | null> {
  const entries = syncReceiptEntries(
    fields.delivered.map((item) => ({
      kind: item.kind,
      entry_id: item.event.entry_id,
      entry_hash: item.entry_hash,
      status: item.state === null ? null : item.state.status,
    })),
  );
  const issuedAt = now.toISOString();
  const key = access.key;

  const counter = await allocateReadCounter(db);
  // Drawn beside the log-wide counter, exactly as the read door draws it: both
  // numbers are in the signed bytes, and both are the drawer's own.
  const keyCounter = key === null ? null : await nextKeyCounter(db, key.id);
  const receipt = await signSyncReceipt(
    {
      from: fields.from,
      head: fields.head,
      entries,
      event_count: fields.delivered.length,
      issued_at: issuedAt,
      counter,
      issuer: signer.issuer,
      key: key === null ? null : key.id,
      key_counter: keyCounter,
    },
    signer.key,
  );
  try {
    await putSyncReceipt(db, {
      createdAt: issuedAt,
      receipt,
      keyId: key === null ? null : key.id,
      keyCounter,
    });
  } catch (error) {
    if (error instanceof ReceiptConflictError) return null;
    throw error;
  }
  return receipt;
}

/**
 * Serve one page of the delta stream.
 *
 * The order is the order of the promises made: the page is bounded by the
 * sealed head, every item is built and its proof verified before anything is
 * delivered, the filters then decide what the trainer sees, and the receipt is
 * signed and stored before the response is built — so a receipt in a trainer's
 * hands always has a row behind it, exactly as a read receipt does.
 */
async function page(
  db: D1Like,
  query: SyncQuery,
  signer: ReceiptSigner,
  reader: ReaderAccess,
  access: Access,
  now: Date,
): Promise<Response> {
  const latest = await latestSeal(db);
  // The stream is strictly by sealed position: events after the last seal are
  // never delivered, because an unsealed event has no proof to deliver with it.
  if (latest === null || query.from > latest.last_seq) {
    return emptyPage(query.from, latest, access);
  }

  const sealedHead = latest.last_seq;
  const asked = Math.min(query.from + query.limit - 1, sealedHead);

  // The release window (decision D-100). A free reader's page stops at the
  // released head over the seals the page would have covered, and the whole
  // page is then the world as it stood at that boundary: `head` and the receipt
  // name it, and `sealed_head` still reports the true sealed head, so a reader
  // sees exactly how far ahead the log is of what they were handed. A key and a
  // signed operator are served to the sealed head, as today.
  let head = asked;
  let worldHead = sealedHead;
  let asOf = latest.sealed_at;
  if (reader.kind === "free") {
    const covering = await sealsBetween(db, query.from, asked);
    const released = releasedHead(covering, now);
    // Nothing in the range has opened yet: an empty page, with `head` null and
    // no receipt, exactly as a trainer already past the sealed head is answered.
    if (released === null || released < query.from) {
      return emptyPage(query.from, latest, access);
    }
    head = Math.min(asked, released);
    worldHead = released;
    const boundary = await sealCovering(db, released);
    if (boundary !== null) asOf = boundary.sealed_at;
  }

  const events = await eventsInRange(db, query.from, head);

  const covering = new Covering();
  const entries = new Entries(await unservableAfter(db, worldHead));
  const at = new Date(asOf);
  const items: Item[] = [];

  for (const event of events) {
    const cover = await covering.of(db, event.seq);
    if (cover === null) return refuse(500, "bad_proof");
    const inclusion = await buildInclusionProof(event, cover.seal, cover.batch);
    if (inclusion === null) return refuse(500, "bad_proof");

    const kind = syncItemKind(event);
    const state =
      kind === "event" || event.entry_id === null
        ? null
        // Derived at the head of the page's own world and never past it: a
        // reader served to the released head is handed every entry as it stood
        // there, so a validation the window still withholds cannot reach them
        // through a re-derived record (decision D-100).
        : await entries.state(db, event.entry_id, at, worldHead);

    items.push({
      seq: event.seq,
      kind,
      event,
      proof: { seal_seq: cover.seal.seq, inclusion_proof: inclusion },
      entry: state === null ? null : state.entry,
      sidecar: state === null ? null : state.sidecar,
      entry_hash: state === null ? null : state.entry_hash,
      seal: cover.seal,
      state,
    });
  }

  const delivered = items.filter((item) =>
    keepSyncItem(
      item.kind,
      item.state === null
        ? null
        : {
            status: item.state.status,
            effective_tier: item.state.effective_tier,
            domain: item.state.domain,
            source_class: item.state.source_class,
          },
      query,
    ),
  );

  // Only the seals the trainer was actually handed something under: a seal
  // named by nothing in the response is a fact about a page it did not receive.
  const seals = new Map<number, Seal>();
  for (const item of delivered) seals.set(item.seal.seq, item.seal);

  // Every item filtered is a page that served nothing, so no receipt is issued
  // and the counter does not move.
  let receipt: SyncReceipt | null = null;
  if (delivered.length > 0) {
    receipt = await issueReceipt(
      db,
      { from: query.from, head, delivered },
      signer,
      access,
      now,
    );
    if (receipt === null) return refuse(503, "receipt_conflict");
  }

  // Section 9: "each delivered verified entry counts as a read". The receipt's
  // own entry list is what is charged, so the number billed and the number the
  // trainer was handed are the same number by construction — and a page that
  // delivered nothing verified charges nothing. The cap may be overshot by the
  // last page, which is the documented price of charging after serving.
  const charged =
    receipt === null
      ? 0
      : receipt.entries.filter((entry) => entry.status === "verified").length;
  await chargeReads(db, access, charged);

  return json(
    {
      from: query.from,
      head,
      sealed_head: sealedHead,
      as_of: asOf,
      seals: [...seals.values()]
        .sort((left, right) => left.seq - right.seq)
        .map(sealRecord),
      events: delivered.map(wireItem),
      receipt,
    },
    200,
    accessHeaders(access, access.limit - access.used - charged),
  );
}

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  now: Date,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/sync") return null;
  if (request.method !== "GET") return methodNotAllowed("GET");

  const parsed = parseSyncQuery(url.searchParams);
  // The refusal goes out in the kernel's own word, so a trainer who mistyped
  // `min_tier` is told which rule refused them rather than "bad request".
  if (!parsed.ok) return refuse(400, parsed.refusal);

  // The tier gate first, and before `receipts_not_configured`: a key that is
  // over its cap or whose bill did not clear is told which rule refused it even
  // on a deployment that could not have signed the page anyway. Called exactly
  // once for the request, and its answer passed down (decision D-100).
  const granted = await readerAccess(request, env, db, now);
  if (!granted.ok) return refusalResponse(granted.refusal);
  const reader = granted.reader;

  // The keyed branch carries the tier it resolved; a free or an operator page
  // is metered on the free tier exactly as it is today, so the gate is asked
  // for that tier's day here.
  let access: Access;
  if (reader.kind === "key") {
    access = reader.key;
  } else {
    const free = await resolveAccess(db, request, now);
    if (!free.ok) return refusalResponse(free.refusal);
    access = free.access;
  }

  // Before any read: a deployment that cannot sign a receipt cannot serve a
  // page, and saying so costs nothing rather than a page's worth of queries.
  const signer = await signerFor(env.SEALING_AGENT_KEY);
  if (signer === null) return refuse(503, "receipts_not_configured");

  return page(db, parsed.query, signer, reader, access, now);
}

/**
 * Route one request to the delta stream, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched. Storage failures
 * become the same JSON 503 every other route gives.
 */
export async function handleSync(
  request: Request,
  env: Env,
  deps: { now: Date },
): Promise<Response | null> {
  const db = guardDatabase(env.DB);
  try {
    return await route(request, env, db, deps.now);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`sync: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

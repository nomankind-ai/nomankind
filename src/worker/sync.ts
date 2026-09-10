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
import type { Entry } from "../schema.js";
import type { Seal } from "../seal.js";
import type { D1Like } from "../storage/d1.js";
import {
  ReceiptConflictError,
  eventsInRange,
  latestSeal,
  nextReadCounter,
  putSyncReceipt,
  sealCovering,
} from "../storage/repository.js";
import {
  keepSyncItem,
  parseSyncQuery,
  syncItemKind,
  syncReceiptEntries,
  type SyncItemKind,
  type SyncQuery,
} from "../sync.js";
import type { Env } from "./env.js";
import { signerFor, type ReceiptSigner } from "./read.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { buildInclusionProof } from "./seals.js";
import { entryWorld, rederive, worldAt } from "./world.js";

/**
 * How many times a receipt may be signed again for a counter another isolate
 * took first. The read door's own budget, spelled the same way and for the same
 * reason: it bounds a loop whose every iteration is a real conflict, and the
 * answer when it runs out is a refusal rather than an unnumbered receipt.
 */
const RECEIPT_ATTEMPTS = 3;

/** One entry as it stood at the sealed head: the record, and what filters ask. */
interface EntryState {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly entry_hash: string;
  readonly status: EntryStatus;
  readonly effective_tier: EvidenceTier | null;
  /** The entry's own domain, off its signed core (decision D-071). */
  readonly domain: string;
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
 * Every entry the page touches, derived once each at the sealed head.
 *
 * One entry can be touched by several events in one page — a submission and two
 * validations — and re-deriving it once per event would read the same world
 * three times to arrive at the same answer three times.
 */
class Entries {
  readonly #memo = new Map<string, Promise<EntryState>>();

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
    const world = worldAt(await entryWorld(db, entryId), head);
    const { entry, derived, sidecar } = rederive(world, entryId, at);
    return {
      entry,
      sidecar,
      entry_hash: await entryHash(extractCore(entry)),
      status: derived.status,
      effective_tier: sidecar.effective_tier,
      domain: domainOf(entry),
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
function emptyPage(from: number, latest: Seal | null): Response {
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
  );
}

/**
 * Sign and store one receipt covering the whole response, or null when every
 * attempt lost the counter.
 *
 * The counter is inside the signed bytes, so a conflict cannot be repaired by
 * editing the row: the receipt is signed again from a freshly read counter.
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

  for (let attempt = 0; attempt < RECEIPT_ATTEMPTS; attempt += 1) {
    const counter = await nextReadCounter(db);
    const receipt = await signSyncReceipt(
      {
        from: fields.from,
        head: fields.head,
        entries,
        event_count: fields.delivered.length,
        issued_at: issuedAt,
        counter,
        issuer: signer.issuer,
      },
      signer.key,
    );
    try {
      await putSyncReceipt(db, { createdAt: issuedAt, receipt });
      return receipt;
    } catch (error) {
      if (error instanceof ReceiptConflictError) continue;
      throw error;
    }
  }
  return null;
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
  now: Date,
): Promise<Response> {
  const latest = await latestSeal(db);
  // The stream is strictly by sealed position: events after the last seal are
  // never delivered, because an unsealed event has no proof to deliver with it.
  if (latest === null || query.from > latest.last_seq) {
    return emptyPage(query.from, latest);
  }

  const sealedHead = latest.last_seq;
  const asOf = latest.sealed_at;
  const head = Math.min(query.from + query.limit - 1, sealedHead);
  const events = await eventsInRange(db, query.from, head);

  const covering = new Covering();
  const entries = new Entries();
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
        : await entries.state(db, event.entry_id, at, sealedHead);

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
      now,
    );
    if (receipt === null) return refuse(503, "receipt_conflict");
  }

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

  // Before any read: a deployment that cannot sign a receipt cannot serve a
  // page, and saying so costs nothing rather than a page's worth of queries.
  const signer = await signerFor(env.SEALING_AGENT_KEY);
  if (signer === null) return refuse(503, "receipts_not_configured");

  return page(db, parsed.query, signer, now);
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

/**
 * The event set one entry is re-derived over, gathered in one place.
 *
 * Every route that stores an entry has to hand `deriveEntry` a log, and which
 * events that log has to contain is not obvious. The registry is needed because
 * status depends on who was trusted and which agent answered for which
 * operator; the entry's own events are needed because the decisions and
 * reconfirmations are there; and — this is the part that is easy to miss — the
 * events of every entry that *declares it supersedes this one* are needed too,
 * because `superseded_by` is derived by asking whether such a candidate
 * verified (src/derive.ts, `supersededBy`). Read an entry over its own events
 * alone and derivation cannot see the superseder, so a superseded entry
 * silently comes back standing and the next write stores that answer.
 *
 * That is a data-loss bug rather than a wrong-looking field, so the gathering
 * lives here and every writer uses it: the reconfirm door, the validate door,
 * and the sweep's staleness step. Nothing here decides anything — it reads the
 * three pieces and hands them over, and `rederive` is the one line that turns
 * them into a derived entry on an injected clock.
 *
 * No policy number lives here: the page size is LIST_PAGE_LIMIT from
 * src/policy.ts, and there is no other number.
 */

import { domainOf } from "../core.js";
import { deriveEntry, type DerivedEntry } from "../derive.js";
import type { Event, EventType } from "../events.js";
import {
  isVersionStalenessCategory,
  LIST_PAGE_LIMIT,
  versionedSubjectOf,
} from "../policy.js";
import { entrySeal, type EntrySeal } from "../seal.js";
import type { D1Like } from "../storage/d1.js";
import {
  eventsForEntry,
  eventsInRange,
  eventsOfType,
  getEntry,
  sealCovering,
  supersedersOf,
  versionSiblingsOf,
} from "../storage/repository.js";

/**
 * The event types that say who is registered, who is trusted, which agent
 * answers for which operator, which domains each of them attested in, and what
 * the sealed pool snapshots are. Everything the validation rules and the draw
 * are recomputed from, and nothing else.
 */
export const REGISTRY_EVENT_TYPES: readonly EventType[] = Object.freeze([
  "operator_registered",
  "operator_trusted",
  "operator_untrusted",
  "agent_bound",
  // Decision D-071: which domains an operator is attested in is folded from
  // these (src/derive.ts, `operatorDomainsAt`), so a set without them tells
  // every door that no operator ever joined a domain -- and every validation
  // outside ai-ecosystem answers `operator_not_in_domain`.
  "operator_joined_domain",
  "pool_snapshot",
] as const);

/**
 * Whether an event of this type is part of the registry.
 *
 * Asked by the delta stream about the events past a sealed head: a registry
 * event there moves every entry's derivation at once, so no entry may be served
 * from its stored row until that event is sealed too.
 */
export function isRegistryEvent(type: EventType): boolean {
  return REGISTRY_EVENT_TYPES.includes(type);
}

/**
 * Whether the clock has passed an entry's `expires_at`.
 *
 * The schema: `stale` is "true when expires_at is in the past", and
 * `expires_at` is a calendar date, so this is a comparison of UTC days and the
 * expiry day itself is still fresh — the rule src/derive.ts's `freshnessOf`
 * applies, in the one other place the kernel's own answer cannot be reached: a
 * door serving an entry from its stored row, which was derived at a different
 * instant. It is the only clock-dependent field derivation has, and a caller
 * that cannot tell this apart from D-096's version staleness must re-derive
 * rather than guess.
 */
export function expiredByClock(expiresAt: string | null, now: Date): boolean {
  if (expiresAt === null) return false;
  return now.toISOString().slice(0, 10) > expiresAt;
}

/**
 * Every registry event in the log, in seq order.
 *
 * Read type by type through the (type, seq) index and paged to exhaustion, never
 * as one unbounded scan of the events table: the PoC loaded the whole log into
 * memory and that is exactly what the storage layer exists to prevent. The
 * sweep (src/worker/sweep.ts) and the two write doors read the same thing
 * through this same function, so the pool a draw is computed against and the
 * registry a validation is judged against can never come from two different
 * readings of the log.
 */
export async function registryEvents(
  db: D1Like,
  cache?: WorldCache,
): Promise<Event[]> {
  if (cache !== undefined) {
    // The promise is remembered rather than its result, so ten entries gathered
    // one after another -- or at once -- share the one reading and never race
    // into six queries apiece.
    cache.registry ??= readRegistryEvents(db);
    return cache.registry;
  }
  return readRegistryEvents(db);
}

/**
 * The registry read once, for one request or one sweep run.
 *
 * The registry is the same for every entry in a request: the log has one
 * registry, and `worldAt` cuts it to a position afterwards, so reading it again
 * per entry is the same six paged queries answering the same question. A page
 * of a hundred events over thirty entries read it thirty times, which is where a
 * sync spent most of its subrequests against Workers' documented limit.
 *
 * Deliberately not a module-level memo: an isolate outlives a request, and a
 * registry remembered past the response would answer a later request with a log
 * that has moved. The cache is created by the caller, lives exactly as long as
 * the work it was created for, and a caller that passes none gets today's
 * behaviour unchanged.
 */
export interface WorldCache {
  /**
   * The one reading of the registry, or null until the first gathering asks
   * for it. Written only through `registryEvents`; create it with `worldCache`.
   */
  registry: Promise<Event[]> | null;
}

/** A fresh cache, for one request or one sweep run. */
export function worldCache(): WorldCache {
  return { registry: null };
}

async function readRegistryEvents(db: D1Like): Promise<Event[]> {
  const events: Event[] = [];
  for (const type of REGISTRY_EVENT_TYPES) {
    // -1, because eventsOfType reads strictly after: seq 0 is a real position.
    let after = -1;
    for (;;) {
      const page = await eventsOfType(db, type, after, LIST_PAGE_LIMIT);
      events.push(...page);
      if (page.length < LIST_PAGE_LIMIT) break;
      after = page[page.length - 1]!.seq;
    }
  }
  return events.sort((left, right) => left.seq - right.seq);
}

/**
 * The three pieces, kept apart rather than flattened, because a caller needs
 * them separately: the validation rules read the registry at the head position
 * and the entry's own prior records, while only derivation wants all three at
 * once.
 */
export interface EntryWorld {
  /** Every registry event in the log, in seq order. */
  readonly registry: readonly Event[];
  /** This entry's own events, in seq order. */
  readonly entryEvents: readonly Event[];
  /** The events of every entry declaring it supersedes this one, in seq order. */
  readonly superseders: readonly Event[];
  /**
   * The events of every entry about another version of the same model, in seq
   * order, and empty for every entry outside the version-staleness categories
   * (decision D-096).
   *
   * Part of the world for exactly the reason the superseders are: `stale` is
   * derived by asking whether a later version's entry verified
   * (src/derive.ts, `isVersionStale`), so an entry read over its own events
   * alone comes back fresh and the next write stores that answer over a
   * staleness the log really holds.
   */
  readonly versionSiblings: readonly Event[];
  /**
   * The entry's own seal object, or null when nothing covers its submission
   * yet.
   *
   * It is part of the world because it is part of the entry: `deriveEntry`
   * writes `seal` from what it is handed, so an entry re-derived without it
   * comes back with `seal: null` and the next write erases a seal that was
   * really made. A validation, a reconfirmation and the staleness step all
   * re-derive sealed entries, so this is not a corner case.
   */
  readonly seal: EntrySeal | null;
}

/**
 * The entry's own seal object as the stored row carries it, or null.
 *
 * `deriveEntry` writes `seal` into the entry and `putEntry` stores that entry
 * verbatim, so a sealed entry's row already holds the object this function
 * would otherwise rebuild. It is immutable once written (decision D-055): the
 * seal covering a submission never changes and `recordSeal` writes the row and
 * the seal in one batch, so a row with a seal on it is the seal, not a copy that
 * could have drifted.
 */
function storedSeal(entry: unknown): EntrySeal | null {
  const seal = (entry as Record<string, unknown>)["seal"];
  if (seal === null || seal === undefined || typeof seal !== "object") {
    return null;
  }
  return seal as EntrySeal;
}

/**
 * The seal object for one entry, read from the store.
 *
 * One keyed read when the entry is sealed: the stored row's own entry carries
 * the seal object, and taking it there is the same object at a tenth of the
 * cost. The rebuild below is what a row without one gets — an unsealed entry, or
 * no row at all — and it is two reads, because an inclusion proof needs the
 * whole batch: the seal covering the submission event, and then the events of
 * that seal's range, which are the leaves the proof is computed over. Bounded by
 * the seal, so no page size is involved, but unbounded in rows: a batch of ten
 * thousand events was read whole, once per entry, to arrive at an object the
 * entry was already stored with.
 *
 * Null when nothing covers the submission, and null when the entry has no
 * submission event in its own log — which the caller's own derivation is about
 * to throw over anyway.
 */
async function sealOf(
  db: D1Like,
  entryId: string,
  entryEvents: readonly Event[],
): Promise<EntrySeal | null> {
  const submission = entryEvents.find(
    (event) => event.type === "entry_submitted" && event.entry_id === entryId,
  );
  if (submission === undefined) return null;

  const stored = await getEntry(db, entryId);
  if (stored !== null) {
    const sealed = storedSeal(stored.entry);
    if (sealed !== null) return sealed;
  }

  const covering = await sealCovering(db, submission.seq);
  if (covering === null) return null;

  const batch = await eventsInRange(db, covering.first_seq, covering.last_seq);
  return entrySeal(batch, [covering], entryId);
}

/**
 * Gather the world one entry is derived over.
 *
 * The superseders come from the `supersedes` column, which is a copy of what
 * submitters declared in their signed cores (`supersedersOf`), bounded by the
 * caller-free page size. Whether any of them actually took effect is
 * derivation's answer and is never decided here.
 *
 * `cache` is optional and changes nothing about the world it returns: with one,
 * the registry is read once for every entry gathered under it; without one, the
 * reads are exactly what they have always been.
 */
export async function entryWorld(
  db: D1Like,
  entryId: string,
  cache?: WorldCache,
): Promise<EntryWorld> {
  const registry = await registryEvents(db, cache);
  const entryEvents = await eventsForEntry(db, entryId);
  const superseders: Event[] = [];
  for (const candidateId of await supersedersOf(db, entryId, LIST_PAGE_LIMIT)) {
    if (candidateId === entryId) continue;
    superseders.push(...(await eventsForEntry(db, candidateId)));
  }
  const versionSiblings = await versionSiblingEvents(db, entryId, entryEvents);
  const seal = await sealOf(db, entryId, entryEvents);
  return { registry, entryEvents, superseders, versionSiblings, seal };
}

/**
 * The events of every entry about another version of the same model.
 *
 * Read off this entry's own signed core: the domain and the category say
 * whether the rule applies at all (src/policy.ts,
 * `isVersionStalenessCategory`), and the subject's first two segments are the
 * prefix the siblings share. An entry outside those categories, or whose
 * subject names no version, has none and costs no query.
 *
 * The prefix match returns this entry too and every version of the model
 * including its own; which of them is later and whether it verified is
 * derivation's answer, not this function's.
 */
async function versionSiblingEvents(
  db: D1Like,
  entryId: string,
  entryEvents: readonly Event[],
): Promise<Event[]> {
  const submission = entryEvents.find(
    (event) => event.type === "entry_submitted" && event.entry_id === entryId,
  ) as Event<"entry_submitted"> | undefined;
  if (submission === undefined) return [];

  const core = submission.payload.core;
  const domain = domainOf(core);
  if (!isVersionStalenessCategory(domain, core["category"])) return [];
  const versioned = versionedSubjectOf(core["subject"]);
  if (versioned === null) return [];

  const events: Event[] = [];
  for (const sibling of await versionSiblingsOf(
    db,
    domain,
    versioned.prefix,
    LIST_PAGE_LIMIT,
  )) {
    if (sibling.id === entryId) continue;
    events.push(...(await eventsForEntry(db, sibling.id)));
  }
  return events;
}

/**
 * The same world as it stood at one sealed position.
 *
 * Whitepaper Section 8, "The delta stream": events are served strictly by
 * sealed position, so an entry delivered at position p must be described as it
 * was derived at p and not as it stands now. Two trainers resuming from the
 * same `from` would otherwise be told different things about the same event,
 * and neither could reproduce what the other received.
 *
 * Every event of the three lists is dropped past `position`; the seal is kept,
 * because the entry's own seal covers its submission and the submission
 * precedes every later event, so a seal that exists at all already existed at
 * any position an event of this entry occupies. Pure: the world handed in is
 * not touched.
 */
export function worldAt(world: EntryWorld, position: number): EntryWorld {
  const upTo = (events: readonly Event[]): Event[] =>
    events.filter((event) => event.seq <= position);
  return {
    registry: upTo(world.registry),
    entryEvents: upTo(world.entryEvents),
    superseders: upTo(world.superseders),
    versionSiblings: upTo(world.versionSiblings),
    seal: world.seal,
  };
}

/**
 * Every event in a world, deduplicated by seq and in seq order.
 *
 * Deduplication matters: a superseding entry's own world holds its target's
 * events twice over once the two are merged, and derivation folds what it is
 * given, so a decision counted twice would be two approvals where there was
 * one. `extra` is for events sealed in this request and not yet readable —
 * a validation inside `recordValidation`'s callback, say.
 */
export function eventsOf(
  world: EntryWorld,
  extra: readonly Event[] = [],
): Event[] {
  const bySeq = new Map<number, Event>();
  for (const event of [
    ...world.registry,
    ...world.entryEvents,
    ...world.superseders,
    ...world.versionSiblings,
    ...extra,
  ]) {
    bySeq.set(event.seq, event);
  }
  return [...bySeq.values()].sort((left, right) => left.seq - right.seq);
}

/**
 * Derive one entry over its world at an instant.
 *
 * The clock is the injected `now` and nothing else, spelled exactly as the
 * validate door has always spelled it, so a row written by the sweep and a row
 * written by a door disagree about nothing but the instant they were written at.
 *
 * The world's seal is handed to derivation, so re-deriving a sealed entry keeps
 * its seal instead of erasing it. `entrySeals` overrides that for the one caller
 * whose seal is not readable yet: `recordSeal` writes the seal and the entries
 * it covers in a single batch, so inside that batch the seal exists only as the
 * argument it was passed.
 */
export function rederive(
  world: EntryWorld,
  entryId: string,
  now: Date,
  extra: readonly Event[] = [],
  entrySeals?: ReadonlyMap<string, EntrySeal>,
): DerivedEntry {
  const seals =
    entrySeals ??
    (world.seal === null
      ? undefined
      : new Map<string, EntrySeal>([[entryId, world.seal]]));
  return deriveEntry(
    eventsOf(world, extra),
    entryId,
    { now: now.toISOString() },
    seals,
  );
}

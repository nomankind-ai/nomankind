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

import { deriveEntry, type DerivedEntry } from "../derive.js";
import type { Event, EventType } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { D1Like } from "../storage/d1.js";
import {
  eventsForEntry,
  eventsOfType,
  supersedersOf,
} from "../storage/repository.js";

/**
 * The event types that say who is registered, who is trusted, which agent
 * answers for which operator, and what the sealed pool snapshots are. Everything
 * the validation rules and the draw are recomputed from, and nothing else.
 */
const REGISTRY_EVENT_TYPES: readonly EventType[] = Object.freeze([
  "operator_registered",
  "operator_trusted",
  "operator_untrusted",
  "agent_bound",
  "pool_snapshot",
] as const);

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
export async function registryEvents(db: D1Like): Promise<Event[]> {
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
}

/**
 * Gather the world one entry is derived over.
 *
 * The superseders come from the `supersedes` column, which is a copy of what
 * submitters declared in their signed cores (`supersedersOf`), bounded by the
 * caller-free page size. Whether any of them actually took effect is
 * derivation's answer and is never decided here.
 */
export async function entryWorld(
  db: D1Like,
  entryId: string,
): Promise<EntryWorld> {
  const registry = await registryEvents(db);
  const entryEvents = await eventsForEntry(db, entryId);
  const superseders: Event[] = [];
  for (const candidateId of await supersedersOf(db, entryId, LIST_PAGE_LIMIT)) {
    if (candidateId === entryId) continue;
    superseders.push(...(await eventsForEntry(db, candidateId)));
  }
  return { registry, entryEvents, superseders };
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
 */
export function rederive(
  world: EntryWorld,
  entryId: string,
  now: Date,
  extra: readonly Event[] = [],
): DerivedEntry {
  return deriveEntry(eventsOf(world, extra), entryId, {
    now: now.toISOString(),
  });
}

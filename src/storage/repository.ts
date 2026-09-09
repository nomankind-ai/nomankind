/**
 * The query-shaped store.
 *
 * Whitepaper Section 11, Deployment and status, and the PoC retrospective's
 * DEPLOY-1: the PoC loaded the whole log into memory and flushed it back, which
 * worked until it did not. Nothing here does that. Every read is a primary-key
 * lookup, a bounded range, or a keyset page, and every list takes the caller's
 * own explicit limit — this module holds no page size, no policy number, and no
 * default anywhere. Policy numbers live in src/policy.ts and nowhere else.
 *
 * Every function takes the database as its first argument. There is no class,
 * no connection state, and no cache: a Worker isolate that handles two requests
 * must not carry anything from the first into the second.
 *
 * The repository never computes or alters a derived field. Status, staleness,
 * the sidecar, the seal — all of it is recomputed from events by src/derive.ts
 * and src/seal.ts, and this module stores the result verbatim. Delete every
 * table but `events` and the rest can be rebuilt; that is the point.
 */

import { utcDay, type Anchor, type AnchorExternal } from "../anchor.js";
import type { OpenAssignment } from "../assign.js";
import type { BountyAccrual } from "../bounty.js";
import type { Sidecar } from "../derive.js";
import {
  appendEvent,
  type Event,
  type EventInput,
  type EventType,
  type ReadCountRow,
} from "../events.js";
import type { ReadReceipt } from "../receipt.js";
import type { Entry } from "../schema.js";
import type { RegistrySeal, Seal, WitnessSignature } from "../seal.js";
import {
  readBoolean,
  readInteger,
  readJson,
  readNullableInteger,
  readNullableText,
  readText,
  writeBoolean,
  writeJson,
  type D1Like,
  type D1LikeStatement,
  type Row,
} from "./d1.js";

/**
 * `LIMIT 1` below is not a page size and not a policy number: it says "the one
 * row this lookup can return", which is a fact about the query, not a knob. No
 * other numeric literal appears in this module.
 */
const ONE_ROW = "LIMIT 1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An append that would break the chain.
 *
 * Section 6, "Seal": the log is append-only and hash-chained, so a batch that
 * does not start exactly where the log ends is refused rather than written and
 * repaired later. `reason` names which of the two links failed, in the same
 * words `verifyChain` uses.
 */
export class EventAppendError extends Error {
  override readonly name = "EventAppendError";
  readonly reason: "bad_seq" | "bad_prev_hash";
  readonly seq: number;

  constructor(reason: "bad_seq" | "bad_prev_hash", seq: number, detail: string) {
    super(`appendEvents: ${reason} at seq ${seq}: ${detail}`);
    this.reason = reason;
    this.seq = seq;
  }
}

/**
 * A seal written where one already stands.
 *
 * Two timers racing to seal the same range must not both succeed: the second
 * would either overwrite a seal the first already chained to, or chain a second
 * seal over the same events. The insert is plain, the unique key refuses the
 * second, and the caller reports it rather than repairing it.
 */
export class SealConflictError extends Error {
  override readonly name = "SealConflictError";
  readonly seq: number;

  constructor(seq: number, options?: { cause?: unknown }) {
    super(`recordSeal: a seal already stands at seq ${seq}`, options);
    this.seq = seq;
  }
}

/** An entry stored with no `entry_submitted` event behind it in the log. */
export class MissingSubmissionError extends Error {
  override readonly name = "MissingSubmissionError";
  readonly entryId: string;

  constructor(entryId: string) {
    super(`putEntry: no entry_submitted event for ${entryId}`);
    this.entryId = entryId;
  }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const EVENT_COLUMNS = `seq, "at", type, entry_id, payload, prev_hash, hash`;

function toEvent(row: Row): Event {
  return {
    seq: readInteger(row, "seq"),
    at: readText(row, "at"),
    type: readText(row, "type") as EventType,
    entry_id: readNullableText(row, "entry_id"),
    payload: readJson<Event["payload"]>(row, "payload"),
    prev_hash: readNullableText(row, "prev_hash"),
    hash: readText(row, "hash"),
  };
}

/** The log's head: the last event's seq and hash, or null on an empty log. */
async function head(db: D1Like): Promise<{ seq: number; hash: string } | null> {
  const row = await db
    .prepare(`SELECT seq, hash FROM events ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  if (row === null) return null;
  return { seq: readInteger(row, "seq"), hash: readText(row, "hash") };
}

/**
 * The head event itself, or null on an empty log.
 *
 * The writers below seal their event onto this one rather than onto a seq and a
 * hash read apart from it, so the event they append is computed from exactly the
 * row the chain check is then made against.
 */
async function headEvent(db: D1Like): Promise<Event | null> {
  const row = await db
    .prepare(`SELECT ${EVENT_COLUMNS} FROM events ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

/** The last event's seq, or null when the log is empty. */
export async function headSeq(db: D1Like): Promise<number | null> {
  const at = await head(db);
  return at === null ? null : at.seq;
}

/**
 * Append a run of events in one batch.
 *
 * Refused when the first event does not continue the stored log: its seq must
 * be head + 1 (or 0 on an empty log) and its prev_hash must be the head's hash
 * (or null). The rest of the run is checked to link to the one before it, so a
 * batch that is internally broken is refused before any of it is written rather
 * than half-written. The batch is atomic, so a refusal from D1 leaves the log
 * exactly as it was.
 *
 * Nothing here hashes anything: the events arrive already sealed by
 * `appendEvent`, and re-deriving a hash on the way in would let a storage bug
 * pass for a valid log.
 */
const EVENT_INSERT = `INSERT INTO events (${EVENT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)`;

/**
 * Check that a run of events continues the log from `at`, and build the
 * statements that write it.
 *
 * The one place the chain rule is enforced. Every write that appends events
 * goes through this, so the atomic registry writes below cannot drift into a
 * weaker check than a plain append does: the first event's seq must be head + 1
 * (or 0 on an empty log), its prev_hash must be the head's hash (or null), and
 * each later event must link to the one before it. Nothing here hashes
 * anything — the events arrive already sealed by `appendEvent`, and re-deriving
 * a hash on the way in would let a storage bug pass for a valid log.
 */
function eventStatements(
  db: D1Like,
  events: readonly Event[],
  at: { seq: number; hash: string } | null,
): D1LikeStatement[] {
  let expectedSeq = at === null ? 0 : at.seq + 1;
  let expectedPrev: string | null = at === null ? null : at.hash;

  for (const event of events) {
    if (event.seq !== expectedSeq) {
      throw new EventAppendError(
        "bad_seq",
        event.seq,
        `expected seq ${expectedSeq}`,
      );
    }
    if (event.prev_hash !== expectedPrev) {
      throw new EventAppendError(
        "bad_prev_hash",
        event.seq,
        `expected prev_hash ${String(expectedPrev)}`,
      );
    }
    expectedSeq = event.seq + 1;
    expectedPrev = event.hash;
  }

  return events.map((event) =>
    db
      .prepare(EVENT_INSERT)
      .bind(
        event.seq,
        event.at,
        event.type,
        event.entry_id,
        writeJson(event.payload),
        event.prev_hash,
        event.hash,
      ),
  );
}

export async function appendEvents(
  db: D1Like,
  events: readonly Event[],
): Promise<void> {
  if (events.length === 0) return;
  await db.batch(eventStatements(db, events, await head(db)));
}

/** One event by its position in the log. */
export async function eventBySeq(
  db: D1Like,
  seq: number,
): Promise<Event | null> {
  const row = await db
    .prepare(`SELECT ${EVENT_COLUMNS} FROM events WHERE seq = ? ${ONE_ROW}`)
    .bind(seq)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

/**
 * One entry's whole lifecycle: the sub-sequence of the log bearing its id, in
 * seq order. Bounded by the entry, not by the log, and served by the
 * (entry_id, seq) index.
 */
export async function eventsForEntry(
  db: D1Like,
  entryId: string,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE entry_id = ? ORDER BY seq`,
    )
    .bind(entryId)
    .all<Row>();
  return rows.results.map(toEvent);
}

/** A contiguous slice of the log, both ends inclusive, in seq order. */
export async function eventsInRange(
  db: D1Like,
  fromSeq: number,
  toSeqInclusive: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE seq >= ? AND seq <= ? ORDER BY seq`,
    )
    .bind(fromSeq, toSeqInclusive)
    .all<Row>();
  return rows.results.map(toEvent);
}

/**
 * The next page of the log after a known position. This is the delta stream's
 * read: the caller keeps the last seq it saw and asks for what came after.
 */
export async function eventsAfter(
  db: D1Like,
  afterSeq: number,
  limit: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(afterSeq, limit)
    .all<Row>();
  return rows.results.map(toEvent);
}

/** The same page, narrowed to one event type. Served by (type, seq). */
export async function eventsOfType(
  db: D1Like,
  type: EventType,
  afterSeq: number,
  limit: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE type = ? AND seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(type, afterSeq, limit)
    .all<Row>();
  return rows.results.map(toEvent);
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/**
 * A stored entry: what derivation produced, and where in the log it was
 * produced from. `submittedSeq` is a log coordinate rather than a derived
 * field — it is the position of the entry's own `entry_submitted` event — and
 * it is what every listing orders and pages by.
 */
export interface StoredEntry {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly submittedSeq: number;
  readonly derivedThroughSeq: number;
}

function toStoredEntry(row: Row): StoredEntry {
  return {
    entry: readJson<Entry>(row, "entry_json"),
    sidecar: readJson<Sidecar>(row, "sidecar_json"),
    submittedSeq: readInteger(row, "submitted_seq"),
    derivedThroughSeq: readInteger(row, "derived_through_seq"),
  };
}

const ENTRY_COLUMNS = `entry_json, sidecar_json, submitted_seq, derived_through_seq`;

/** A required string field on the entry, read by the schema's own field name. */
function entryField(entry: Entry, field: string): string {
  const value = (entry as Record<string, unknown>)[field];
  if (typeof value !== "string") {
    throw new TypeError(`putEntry: entry.${field} must be a string`);
  }
  return value;
}

/**
 * A field the schema declares present but nullable — `expires_at` on an
 * event-category entry, `supersedes` on an entry that supersedes nothing. Absent
 * is not the same as null and is refused: the schema writes an unused slot as
 * null, never by leaving it out.
 */
function entryNullableField(entry: Entry, field: string): string | null {
  const value = (entry as Record<string, unknown>)[field];
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new TypeError(`putEntry: entry.${field} must be a string or null`);
  }
  return value;
}

/** A required boolean field on the entry. */
function entryBooleanField(entry: Entry, field: string): boolean {
  const value = (entry as Record<string, unknown>)[field];
  if (typeof value !== "boolean") {
    throw new TypeError(`putEntry: entry.${field} must be a boolean`);
  }
  return value;
}

/** The position of the entry's submission event. */
async function submittedSeqOf(db: D1Like, entryId: string): Promise<number> {
  const row = await db
    .prepare(
      `SELECT seq FROM events WHERE entry_id = ? AND type = 'entry_submitted' ORDER BY seq ${ONE_ROW}`,
    )
    .bind(entryId)
    .first<Row>();
  if (row === null) throw new MissingSubmissionError(entryId);
  return readInteger(row, "seq");
}

/**
 * Store one derived entry, replacing whatever was there.
 *
 * `entry` is exactly what `deriveEntry` returned and is written verbatim; the
 * columns beside it are copies of fields already inside it, kept out so the
 * listings can filter and order without parsing every row. They are never a
 * second source of truth: rederiving from the events and storing again
 * rewrites them together.
 */
export async function putEntry(
  db: D1Like,
  entry: Entry,
  sidecar: Sidecar,
  derivedThroughSeq: number,
): Promise<void> {
  const submittedSeq = await submittedSeqOf(db, entryField(entry, "id"));
  await entryStatement(db, entry, sidecar, submittedSeq, derivedThroughSeq).run();
}

/**
 * The upsert that stores one derived entry row. Taken as a statement rather
 * than run on the spot so a submission can write the entry, its events and its
 * captures in one atomic batch (`submitEntry` below), and so both paths write
 * exactly the same row.
 */
function entryStatement(
  db: D1Like,
  entry: Entry,
  sidecar: Sidecar,
  submittedSeq: number,
  derivedThroughSeq: number,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO entries (
         id, subject, category, status, submitted_at, submitted_seq, author,
         stale, expires_at, supersedes,
         entry_json, sidecar_json, derived_through_seq
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         subject = excluded.subject,
         category = excluded.category,
         status = excluded.status,
         submitted_at = excluded.submitted_at,
         submitted_seq = excluded.submitted_seq,
         author = excluded.author,
         stale = excluded.stale,
         expires_at = excluded.expires_at,
         supersedes = excluded.supersedes,
         entry_json = excluded.entry_json,
         sidecar_json = excluded.sidecar_json,
         derived_through_seq = excluded.derived_through_seq`,
    )
    .bind(
      entryField(entry, "id"),
      entryField(entry, "subject"),
      entryField(entry, "category"),
      entryField(entry, "status"),
      entryField(entry, "submitted_at"),
      submittedSeq,
      entryField(entry, "author"),
      writeBoolean(entryBooleanField(entry, "stale")),
      entryNullableField(entry, "expires_at"),
      entryNullableField(entry, "supersedes"),
      writeJson(entry),
      writeJson(sidecar),
      derivedThroughSeq,
    );
}

/** One entry by id, with its sidecar, or null. */
export async function getEntry(
  db: D1Like,
  id: string,
): Promise<StoredEntry | null> {
  const row = await db
    .prepare(`SELECT ${ENTRY_COLUMNS} FROM entries WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row === null ? null : toStoredEntry(row);
}

/** What a listing may narrow by, and where it resumes. */
export interface ListEntriesQuery {
  readonly subject?: string;
  readonly category?: string;
  readonly status?: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this submitted_seq; omit for the first page. */
  readonly afterSubmittedSeq?: number;
}

/**
 * A page of entries in submitted_seq order.
 *
 * Keyset, not offset: the caller passes back the last submitted_seq it saw, so
 * the page is an index seek whose cost does not grow with how far in it is, and
 * an entry appended between two pages cannot shift a row across the boundary.
 */
export async function listEntries(
  db: D1Like,
  query: ListEntriesQuery,
): Promise<StoredEntry[]> {
  const conditions: string[] = [];
  const bindings: unknown[] = [];

  if (query.subject !== undefined) {
    conditions.push("subject = ?");
    bindings.push(query.subject);
  }
  if (query.category !== undefined) {
    conditions.push("category = ?");
    bindings.push(query.category);
  }
  if (query.status !== undefined) {
    conditions.push("status = ?");
    bindings.push(query.status);
  }
  if (query.afterSubmittedSeq !== undefined) {
    conditions.push("submitted_seq > ?");
    bindings.push(query.afterSubmittedSeq);
  }
  bindings.push(query.limit);

  const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")} `;
  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries ${where}ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * The entries that declare they supersede this one, oldest submission first.
 *
 * `supersedes` is part of the signed core — "Id of the earlier entry this one
 * supersedes, declared by the submitter and checked by validators" — so this
 * reads what submitters declared, not what derivation concluded. Which of them
 * actually took effect is derivation's answer (the target's `superseded_by`),
 * and the rule that picks it lives in src/derive.ts, not here.
 *
 * The caller's limit is explicit and there is no default: this module holds no
 * page size. Served by the partial `entries_supersedes` index
 * (migrations/0005_freshness.sql).
 */
export async function supersedersOf(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT id FROM entries WHERE supersedes = ? ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(entryId, limit)
    .all<Row>();
  return rows.results.map((row) => readText(row, "id"));
}

/** Where a staleness sweep looks, and where it resumes. */
export interface StaleDueQuery {
  /**
   * The current UTC calendar day, "YYYY-MM-DD" (the schema's `date` format, the
   * same shape `expires_at` carries). Compared as text, which is chronological
   * because the format is fixed-width and zero-padded.
   */
  readonly today: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this (expires_at, id); omit both for the first page. */
  readonly afterExpiresAt?: string;
  readonly afterId?: string;
}

/**
 * The entries whose freshness window has run out but which are not yet marked
 * stale.
 *
 * Whitepaper Section 7, "Freshness and decay": "Past its window an entry stays
 * verified but shows as stale." The window closing is a fact about the calendar
 * rather than an event anyone appends, so something has to walk the entries the
 * day turned on and rederive them. This is that read.
 *
 * Strictly before today, matching derivation: src/derive.ts marks an entry stale
 * once the current day is past `expires_at`, so the expiry day itself is still
 * fresh and an entry expiring today is not due. `stale = 0` keeps an entry the
 * sweep already handled from coming back, and `expires_at IS NOT NULL` leaves
 * out the event categories, which carry no window and can never go stale.
 *
 * Keyset by (expires_at, id), not offset: the caller passes back the last pair
 * it saw, so a page is an index seek whose cost does not grow with how far in it
 * is, and an entry rewritten between two pages cannot shift a row across the
 * boundary. The id breaks the tie between two entries expiring on the same day,
 * so the order is total and no row is skipped or served twice. Served by the
 * partial `entries_stale_due` index (migrations/0005_freshness.sql).
 */
export async function staleDue(
  db: D1Like,
  query: StaleDueQuery,
): Promise<Array<{ id: string; expires_at: string }>> {
  const bindings: unknown[] = [query.today];
  let cursor = "";
  if (query.afterExpiresAt !== undefined && query.afterId !== undefined) {
    cursor = "AND (expires_at > ? OR (expires_at = ? AND id > ?)) ";
    bindings.push(query.afterExpiresAt, query.afterExpiresAt, query.afterId);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT id, expires_at FROM entries
       WHERE stale = 0 AND expires_at IS NOT NULL AND expires_at < ? ${cursor}ORDER BY expires_at, id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    expires_at: readText(row, "expires_at"),
  }));
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

/**
 * The index into the snapshot archive (migrations/0003_captures.sql).
 *
 * `contentHash` is the hash the entry carries — computed under the norm rule,
 * over the extracted content and never over the raw bytes — and `archiveHash`
 * is the R2 key, which is the hash of the raw bytes. The two are the same value
 * only where the rule hashes the bytes themselves. Nothing here holds the bytes:
 * the archive does, and this is the pointer to them.
 */
export interface CaptureRecord {
  readonly entryId: string;
  /** "snapshot" for the entry's snapshot_hash, "receipt" for its receipt_hash. */
  readonly role: "snapshot" | "receipt";
  readonly contentHash: string;
  readonly archiveHash: string;
  readonly normVersion: string;
  /** html, json, pdf, text, binary, transcript, receipt. */
  readonly kind: string;
  readonly mediaType: string;
  readonly size: number;
  readonly fetchedAt: string;
}

const CAPTURE_COLUMNS = `entry_id, role, content_hash, archive_hash, norm_version, kind, media_type, size, fetched_at`;

function toCapture(row: Row): CaptureRecord {
  return {
    entryId: readText(row, "entry_id"),
    role: readText(row, "role") as CaptureRecord["role"],
    contentHash: readText(row, "content_hash"),
    archiveHash: readText(row, "archive_hash"),
    normVersion: readText(row, "norm_version"),
    kind: readText(row, "kind"),
    mediaType: readText(row, "media_type"),
    size: readInteger(row, "size"),
    fetchedAt: readText(row, "fetched_at"),
  };
}

/** The upsert that stores one capture row. */
function captureStatement(
  db: D1Like,
  capture: CaptureRecord,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO captures (${CAPTURE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (entry_id, role) DO UPDATE SET
         content_hash = excluded.content_hash,
         archive_hash = excluded.archive_hash,
         norm_version = excluded.norm_version,
         kind = excluded.kind,
         media_type = excluded.media_type,
         size = excluded.size,
         fetched_at = excluded.fetched_at`,
    )
    .bind(
      capture.entryId,
      capture.role,
      capture.contentHash,
      capture.archiveHash,
      capture.normVersion,
      capture.kind,
      capture.mediaType,
      capture.size,
      capture.fetchedAt,
    );
}

/** Store one capture, replacing whatever was there. */
export async function putCapture(
  db: D1Like,
  capture: CaptureRecord,
): Promise<void> {
  await captureStatement(db, capture).run();
}

/**
 * The capture a hash names, or null.
 *
 * This is the read behind the public capture route: a reader holding an entry's
 * snapshot_hash asks what was captured under it. Two entries may cite the same
 * page and carry the same hash, so the answer is the earliest capture of it,
 * and the entry id breaks a tie between two captures taken at the same instant:
 * the same question always gets the same answer. Served by the
 * (content_hash, fetched_at, entry_id) index.
 */
export async function captureForHash(
  db: D1Like,
  contentHash: string,
): Promise<CaptureRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${CAPTURE_COLUMNS} FROM captures
       WHERE content_hash = ? ORDER BY fetched_at, entry_id ${ONE_ROW}`,
    )
    .bind(contentHash)
    .first<Row>();
  return row === null ? null : toCapture(row);
}

/** Every capture one entry rests on, in role order. Bounded by the entry. */
export async function capturesForEntry(
  db: D1Like,
  entryId: string,
): Promise<CaptureRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${CAPTURE_COLUMNS} FROM captures WHERE entry_id = ? ORDER BY role`,
    )
    .bind(entryId)
    .all<Row>();
  return rows.results.map(toCapture);
}

/**
 * Submit an entry: append its `entry_submitted` event and write the derived
 * entry and its capture rows, atomically.
 *
 * Whitepaper Section 6, "Submit": the entry appears immediately, marked draft,
 * and the source is snapshotted at that moment. The event is the record and
 * everything beside it is an index into the event, so an entries row without its
 * event would be an entry nobody can verify offline, and a capture row without
 * it would point at evidence for a submission that never happened. One `batch`
 * makes both impossible: D1 applies it whole or not at all.
 *
 * The events arrive already sealed by `appendEvent` and are checked against the
 * log's head by exactly the rule a plain append uses, so a run that does not
 * continue the chain is refused before anything is written. Nothing here derives
 * a field: `entry` is what `deriveEntry` returned, written verbatim.
 */
export async function submitEntry(
  db: D1Like,
  input: {
    readonly events: readonly Event[];
    readonly entry: Entry;
    readonly sidecar: Sidecar;
    readonly derivedThroughSeq: number;
    readonly captures: readonly CaptureRecord[];
  },
): Promise<void> {
  const id = entryField(input.entry, "id");
  const submission = input.events.find(
    (event) => event.type === "entry_submitted" && event.entry_id === id,
  );
  if (submission === undefined) throw new MissingSubmissionError(id);

  const statements = eventStatements(db, input.events, await head(db));
  statements.push(
    entryStatement(
      db,
      input.entry,
      input.sidecar,
      submission.seq,
      input.derivedThroughSeq,
    ),
  );
  for (const capture of input.captures) {
    statements.push(captureStatement(db, capture));
  }
  await db.batch(statements);
}

// ---------------------------------------------------------------------------
// Operators and agents
// ---------------------------------------------------------------------------

/**
 * A registered operator. Section 5, Identity and operators: the operator is the
 * unit of accountability, `maintainer` marks nomankind's own, and `provider`
 * marks the one party the door refuses. `details` carries whatever else the
 * registry holds, stored as JSON so a later milestone can add to it without a
 * migration that reshapes a live table.
 */
export interface OperatorRecord {
  readonly id: string;
  readonly maintainer: boolean;
  readonly provider: boolean;
  readonly registeredSeq: number;
  readonly details: Record<string, unknown>;
}

function toOperator(row: Row): OperatorRecord {
  return {
    id: readText(row, "id"),
    maintainer: readBoolean(row, "maintainer"),
    provider: readBoolean(row, "provider"),
    registeredSeq: readInteger(row, "registered_seq"),
    details: readJson<Record<string, unknown>>(row, "operator_json"),
  };
}

const OPERATOR_COLUMNS = `id, maintainer, provider, registered_seq, operator_json`;

/** The upsert that stores one operator row. */
function operatorStatement(
  db: D1Like,
  operator: OperatorRecord,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO operators (${OPERATOR_COLUMNS}) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         maintainer = excluded.maintainer,
         provider = excluded.provider,
         registered_seq = excluded.registered_seq,
         operator_json = excluded.operator_json`,
    )
    .bind(
      operator.id,
      writeBoolean(operator.maintainer),
      writeBoolean(operator.provider),
      operator.registeredSeq,
      writeJson(operator.details),
    );
}

/** Store one operator, replacing whatever was there. */
export async function putOperator(
  db: D1Like,
  operator: OperatorRecord,
): Promise<void> {
  await operatorStatement(db, operator).run();
}

/** One operator by id, or null. */
export async function getOperator(
  db: D1Like,
  id: string,
): Promise<OperatorRecord | null> {
  const row = await db
    .prepare(`SELECT ${OPERATOR_COLUMNS} FROM operators WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row === null ? null : toOperator(row);
}

/** A page of operators in id order, resuming strictly after `afterId`. */
export async function listOperators(
  db: D1Like,
  query: { readonly limit: number; readonly afterId?: string },
): Promise<OperatorRecord[]> {
  const rows =
    query.afterId === undefined
      ? await db
          .prepare(`SELECT ${OPERATOR_COLUMNS} FROM operators ORDER BY id LIMIT ?`)
          .bind(query.limit)
          .all<Row>()
      : await db
          .prepare(
            `SELECT ${OPERATOR_COLUMNS} FROM operators WHERE id > ? ORDER BY id LIMIT ?`,
          )
          .bind(query.afterId, query.limit)
          .all<Row>();
  return rows.results.map(toOperator);
}

/** An agent: a key, and the operator that answers for it. */
export interface AgentRecord {
  readonly agentId: string;
  readonly operatorId: string;
  readonly registeredSeq: number;
}

const AGENT_COLUMNS = `agent_id, operator_id, registered_seq`;

function toAgent(row: Row): AgentRecord {
  return {
    agentId: readText(row, "agent_id"),
    operatorId: readText(row, "operator_id"),
    registeredSeq: readInteger(row, "registered_seq"),
  };
}

/** The upsert that stores one agent row. */
function agentStatement(db: D1Like, agent: AgentRecord): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO agents (${AGENT_COLUMNS}) VALUES (?, ?, ?)
       ON CONFLICT (agent_id) DO UPDATE SET
         operator_id = excluded.operator_id,
         registered_seq = excluded.registered_seq`,
    )
    .bind(agent.agentId, agent.operatorId, agent.registeredSeq);
}

/** Store one agent, replacing whatever was there. */
export async function putAgent(db: D1Like, agent: AgentRecord): Promise<void> {
  await agentStatement(db, agent).run();
}

/**
 * The agents bound to one operator, oldest binding first.
 *
 * Section 5: "Every agent under an operator counts as one for validation", so
 * this is the read behind every rule that resolves an operator's agents. The
 * caller's limit is explicit and there is no default: this module holds no page
 * size (src/policy.ts holds LIST_PAGE_LIMIT). Served by the
 * (operator_id, registered_seq) index.
 */
export async function agentsForOperator(
  db: D1Like,
  operatorId: string,
  limit: number,
): Promise<AgentRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${AGENT_COLUMNS} FROM agents
       WHERE operator_id = ? ORDER BY registered_seq LIMIT ?`,
    )
    .bind(operatorId, limit)
    .all<Row>();
  return rows.results.map(toAgent);
}

/**
 * The operator behind an agent, or null when the agent is unknown. Every rule
 * that says "a distinct operator" resolves through this.
 */
export async function operatorForAgent(
  db: D1Like,
  agentId: string,
): Promise<string | null> {
  const row = await db
    .prepare(
      `SELECT operator_id FROM agents WHERE agent_id = ? ${ONE_ROW}`,
    )
    .bind(agentId)
    .first<Row>();
  return row === null ? null : readText(row, "operator_id");
}

// ---------------------------------------------------------------------------
// Registry writes
// ---------------------------------------------------------------------------

/**
 * Register an operator: append its events and write its rows, atomically.
 *
 * Section 5, Identity and operators, and Section 11's joining steps: the
 * binding is sealed into the log, and only then can the agent validate. The
 * events are the record and the rows are the index into it, so a row without
 * its event would be a registration nobody can verify offline, and an event
 * without its row would be a registration the Worker cannot see. One `batch`
 * makes both impossible: D1 applies it whole or not at all.
 *
 * The caller passes events already sealed by `appendEvent` — the
 * `operator_registered` and the `agent_bound`, in that order — and they are
 * checked against the log's head by exactly the rule a plain append uses, so a
 * run that does not continue the chain is refused before anything is written.
 */
export async function registerOperator(
  db: D1Like,
  input: {
    readonly events: readonly Event[];
    readonly operator: OperatorRecord;
    readonly agent: AgentRecord;
  },
): Promise<void> {
  const statements = eventStatements(db, input.events, await head(db));
  statements.push(operatorStatement(db, input.operator));
  statements.push(agentStatement(db, input.agent));
  await db.batch(statements);
}

/**
 * Trust an operator: append the `operator_trusted` event and replace its row,
 * atomically, for the same reason `registerOperator` is atomic.
 *
 * Section 11: trusted status is granted once at genesis and otherwise earned,
 * and either way the event is what grants it. The row here carries whatever the
 * caller recomputed alongside it; nothing about trust is derived in storage.
 */
export async function trustOperator(
  db: D1Like,
  input: { readonly event: Event; readonly operator: OperatorRecord },
): Promise<void> {
  const statements = eventStatements(db, [input.event], await head(db));
  statements.push(operatorStatement(db, input.operator));
  await db.batch(statements);
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

/**
 * The upsert that stores one assignment row. `missed_seq` and `answered_seq`
 * start null: an assignment is open when it is made, and only an
 * `assignment_missed` or a `validation` closes it. Taken as a statement rather
 * than run on the spot so a draw can append its event and open its row in one
 * atomic batch (`recordAssignment` below), and so both paths write the same row.
 */
function assignmentStatement(
  db: D1Like,
  entryId: string,
  assignment: OpenAssignment,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO assignments (entry_id, seq, operator_id, deadline, missed_seq, assignment_json)
       VALUES (?, ?, ?, ?, NULL, ?)
       ON CONFLICT (seq) DO UPDATE SET
         entry_id = excluded.entry_id,
         operator_id = excluded.operator_id,
         deadline = excluded.deadline,
         assignment_json = excluded.assignment_json`,
    )
    .bind(
      entryId,
      assignment.seq,
      assignment.operator,
      assignment.deadline,
      writeJson(assignment),
    );
}

/** Store one assignment, replacing whatever was there. */
export async function putAssignment(
  db: D1Like,
  entryId: string,
  assignment: OpenAssignment,
): Promise<void> {
  await assignmentStatement(db, entryId, assignment).run();
}

/**
 * The entry's open assignment: the newest one that is neither missed nor
 * answered, or null.
 *
 * The newest assignment is the one in force, so an earlier one never reopens.
 * An assignment closes two ways — the window runs out, or the validator answers
 * — and both are a position in the log, so both are read here. Leaving the
 * answered ones open would have the sweep seal an `assignment_missed` against a
 * validator who responded inside their seventy-two hours.
 *
 * Served by the (entry_id, seq) index.
 */
export async function openAssignment(
  db: D1Like,
  entryId: string,
): Promise<OpenAssignment | null> {
  const row = await db
    .prepare(
      `SELECT assignment_json FROM assignments
       WHERE entry_id = ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(entryId)
    .first<Row>();
  return row === null ? null : readJson<OpenAssignment>(row, "assignment_json");
}

/**
 * Close an assignment by naming the `assignment_missed` event that closed it.
 * The miss is a position in the log, not a flag: the event stays the record and
 * this column is only the index into it.
 */
export async function markAssignmentMissed(
  db: D1Like,
  entryId: string,
  seq: number,
  missedSeq: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE assignments SET missed_seq = ? WHERE entry_id = ? AND seq = ?`,
    )
    .bind(missedSeq, entryId, seq)
    .run();
}

/**
 * Close an assignment by naming the `validation` event that answered it.
 *
 * The mirror of `markAssignmentMissed`: the answer is a position in the log, not
 * a flag, and the event stays the record. An assignment carrying either column
 * is closed, and `openAssignment` reads both.
 */
export async function markAssignmentAnswered(
  db: D1Like,
  entryId: string,
  seq: number,
  validationSeq: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
    )
    .bind(validationSeq, entryId, seq)
    .run();
}

/**
 * The assignments whose window has run out: still open, and past `before`.
 *
 * Lifecycle of an entry, Validate: "An assigned validator has seventy-two hours
 * to respond. A miss costs standing, and the next beacon round draws a
 * replacement." This is the sweep's one read, and the only query in the system
 * that starts from a deadline rather than from an entry.
 *
 * Strictly before, because the deadline instant itself is still inside the
 * seventy-two hours (src/assign.ts holds that rule and this matches it). Oldest
 * deadline first, so a sweep that can only get through so many in one run gets
 * through the longest-overdue ones. The limit is the caller's own and there is
 * no default: this module holds no page size. Served by the partial
 * `assignments_due` index (migrations/0004_assignments.sql).
 */
export async function dueAssignments(
  db: D1Like,
  before: string,
  limit: number,
): Promise<Array<{ entryId: string; assignment: OpenAssignment }>> {
  const rows = await db
    .prepare(
      `SELECT entry_id, assignment_json FROM assignments
       WHERE deadline < ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY deadline LIMIT ?`,
    )
    .bind(before, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    entryId: readText(row, "entry_id"),
    assignment: readJson<OpenAssignment>(row, "assignment_json"),
  }));
}

// ---------------------------------------------------------------------------
// Validation writes
// ---------------------------------------------------------------------------

/**
 * An event sealed onto the stored head, and the statements that write it.
 *
 * The writers below take an `EventInput` rather than a sealed `Event` because
 * the log's head is here and not in the caller: a caller that sealed its own
 * event would have to read the head first, and two reads around one write is the
 * race this avoids. `appendEvent` does the sealing, exactly as every other path
 * does, and `eventStatements` then checks the result against the same head, so
 * these writes cannot drift into a weaker chain rule than a plain append.
 */
async function sealOntoHead(
  db: D1Like,
  input: EventInput,
): Promise<{ event: Event; statements: D1LikeStatement[] }> {
  const previous = await headEvent(db);
  const sealed = await appendEvent(previous === null ? [] : [previous], input);
  const event = sealed[sealed.length - 1]!;
  const at = previous === null ? null : { seq: previous.seq, hash: previous.hash };
  return { event, statements: eventStatements(db, [event], at) };
}

/**
 * The entry_id of an entry-scoped event. `appendEvent` refuses an entry-scoped
 * event with a null entry_id, so this only ever narrows the type.
 */
function scopedEntryId(event: Event): string {
  if (event.entry_id === null) {
    throw new TypeError(`${event.type}: expected an entry_id`);
  }
  return event.entry_id;
}

/**
 * Seal the trusted pool as it stands.
 *
 * Lifecycle of an entry, Validate: "The pool snapshot is committed to the sealed
 * log before the beacon round it uses", so this write is what a later draw is
 * recomputed against. One event and nothing beside it: the snapshot is the
 * record, and the pool it names is rebuilt from the registry events whenever
 * anyone asks.
 */
export async function recordPoolSnapshot(
  db: D1Like,
  input: EventInput<"pool_snapshot">,
): Promise<Event<"pool_snapshot">> {
  const { event, statements } = await sealOntoHead(db, input);
  await db.batch(statements);
  return event as Event<"pool_snapshot">;
}

/**
 * Record a draw: append the `assignment` event and open its row, atomically.
 *
 * The event is the record and the row is the index into it, so an assignments
 * row without its event would be an assignment nobody can verify offline, and an
 * event without its row would be an assignment the sweep cannot see when its
 * deadline passes. One `batch` makes both impossible.
 *
 * The row is read out of the event and nothing is computed here: the deadline
 * was set by `buildAssignment` from the policy window, and the row's seq is the
 * event's own position, which is what ties the two together.
 */
export async function recordAssignment(
  db: D1Like,
  input: EventInput<"assignment">,
): Promise<Event<"assignment">> {
  const { event, statements } = await sealOntoHead(db, input);
  const assignment = event as Event<"assignment">;
  const entryId = scopedEntryId(assignment);
  statements.push(
    assignmentStatement(db, entryId, {
      seq: assignment.seq,
      agent: assignment.payload.agent,
      operator: assignment.payload.operator,
      beacon_round: assignment.payload.beacon_round,
      deadline: assignment.payload.deadline,
      replacement: assignment.payload.replacement,
    }),
  );
  await db.batch(statements);
  return assignment;
}

/**
 * Record a miss: append the `assignment_missed` event and close the row it
 * closes, atomically. `assignmentSeq` names the assignment being closed, which
 * is the position of its own event in the log.
 */
export async function recordAssignmentMissed(
  db: D1Like,
  input: EventInput<"assignment_missed">,
  assignmentSeq: number,
): Promise<Event<"assignment_missed">> {
  const { event, statements } = await sealOntoHead(db, input);
  const missed = event as Event<"assignment_missed">;
  statements.push(
    db
      .prepare(
        `UPDATE assignments SET missed_seq = ? WHERE entry_id = ? AND seq = ?`,
      )
      .bind(missed.seq, scopedEntryId(missed), assignmentSeq),
  );
  await db.batch(statements);
  return missed;
}

/** What a writer stores for an entry: exactly what `putEntry` writes. */
export interface StoredEntryInput {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly derivedThroughSeq: number;
}

/**
 * Record a validation: append the event, store the entry derived including it,
 * and close the assignment it answered, atomically.
 *
 * A validation is the one write that changes an entry's status, and status is
 * derived: the entry row has to be recomputed from a log that already holds this
 * event, and the event does not exist until it is sealed onto the head. So the
 * caller hands in a callback rather than an entry — it is given the sealed event
 * and returns what derivation made of it — and nothing here derives a field.
 *
 * `answeredAssignmentSeq` is the assignment this validation answers, or null
 * when the validator volunteered. Identity and operators: the operator is the
 * unit, so any agent under the assigned operator answers the assignment; which
 * assignment that is belongs to the caller's rules (src/assign.ts), not to
 * storage.
 *
 * `also` is for the entries this one's verification changes besides itself. The
 * case is supersession: the validation that verifies a superseding entry is the
 * moment the entry it supersedes acquires a `superseded_by`, and that target's
 * row has to be rewritten from the same log position, in the same batch, or a
 * reader between the two writes sees a superseding entry verified and its target
 * still standing. The caller rederives each of them and hands them in; nothing
 * here derives a field, and each row keeps its own submitted_seq because
 * submitted_seq is the position of that entry's own submission.
 */
export async function recordValidation(
  db: D1Like,
  input: {
    readonly event: EventInput<"validation">;
    readonly stored: (event: Event<"validation">) => StoredEntryInput;
    readonly answeredAssignmentSeq: number | null;
    readonly also?: (event: Event<"validation">) => readonly StoredEntryInput[];
  },
): Promise<Event<"validation">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const validation = event as Event<"validation">;
  const entryId = scopedEntryId(validation);
  const submittedSeq = await submittedSeqOf(db, entryId);

  const stored = input.stored(validation);
  statements.push(
    entryStatement(
      db,
      stored.entry,
      stored.sidecar,
      submittedSeq,
      stored.derivedThroughSeq,
    ),
  );
  if (input.also !== undefined) {
    for (const other of input.also(validation)) {
      statements.push(
        entryStatement(
          db,
          other.entry,
          other.sidecar,
          await submittedSeqOf(db, entryField(other.entry, "id")),
          other.derivedThroughSeq,
        ),
      );
    }
  }
  if (input.answeredAssignmentSeq !== null) {
    statements.push(
      db
        .prepare(
          `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
        )
        .bind(validation.seq, entryId, input.answeredAssignmentSeq),
    );
  }
  await db.batch(statements);
  return validation;
}

const LEDGER_COLUMNS = `id, kind, operator_id, seq, created_at, payload_json`;

/** The `kind` a bounty accrual is stored under: the record's own. */
const BOUNTY_ACCRUAL: BountyAccrual["kind"] = "bounty_accrual";

/**
 * Record a reconfirmation: append the event, store the entry derived including
 * it, and write the bounty it collected, atomically.
 *
 * The mirror of `recordValidation`, for the same reason: a reconfirmation
 * advances `last_confirmed`, reopens the window and rotates a read-share slot,
 * and every one of those is derived, so the entry row has to be recomputed from
 * a log that already holds this event — which does not exist until it is sealed
 * onto the head. The caller hands in callbacks rather than values, is given the
 * sealed event, and returns what derivation made of it. Nothing here derives a
 * field.
 *
 * Whitepaper Section 7, "Freshness and decay": the withheld half of a stale
 * entry's earnings "builds up on the entry as a reconfirmation bounty, paid to
 * whoever makes it fresh again". `bounty` returns that record (src/bounty.ts)
 * when the entry was stale and null when it was not, and it lands in the same
 * batch as the event that earned it: a ledger row without its reconfirmation
 * would be a bounty nobody can verify offline, and the event without the row
 * would be a bounty that was earned and never recorded.
 *
 * The row goes into `ledger`, which 0001 declared as a placeholder for the
 * read-share accounting M21 fills. It keeps that table's shape exactly — an id,
 * a kind, the operator the row is about, the log position it was produced at,
 * and the whole record as JSON — so M21 adds to it rather than reshaping it.
 */
export async function recordReconfirmation(
  db: D1Like,
  input: {
    readonly event: EventInput<"reconfirmation">;
    readonly stored: (event: Event<"reconfirmation">) => StoredEntryInput;
    readonly bounty: (event: Event<"reconfirmation">) => BountyAccrual | null;
  },
): Promise<Event<"reconfirmation">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const reconfirmation = event as Event<"reconfirmation">;
  const entryId = scopedEntryId(reconfirmation);
  const submittedSeq = await submittedSeqOf(db, entryId);

  const stored = input.stored(reconfirmation);
  statements.push(
    entryStatement(
      db,
      stored.entry,
      stored.sidecar,
      submittedSeq,
      stored.derivedThroughSeq,
    ),
  );

  const accrual = input.bounty(reconfirmation);
  if (accrual !== null) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger (${LEDGER_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          `${BOUNTY_ACCRUAL}:${accrual.seq}`,
          BOUNTY_ACCRUAL,
          accrual.operator,
          reconfirmation.seq,
          reconfirmation.at,
          writeJson(accrual),
        ),
    );
  }
  await db.batch(statements);
  return reconfirmation;
}

/**
 * The bounties one entry accrued, oldest first.
 *
 * Read through `json_extract` rather than a column of its own: `ledger` is the
 * placeholder 0001 declared and M21 is the milestone that shapes it, so adding
 * an entry_id column now would be guessing at that shape a milestone early. The
 * volume is one row per reconfirmation of one entry, and the caller's limit
 * bounds it.
 */
export async function bountiesForEntry(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<BountyAccrual[]> {
  const rows = await db
    .prepare(
      `SELECT payload_json FROM ledger
       WHERE kind = ? AND json_extract(payload_json, '$.entry_id') = ?
       ORDER BY seq LIMIT ?`,
    )
    .bind(BOUNTY_ACCRUAL, entryId, limit)
    .all<Row>();
  return rows.results.map((row) => readJson<BountyAccrual>(row, "payload_json"));
}

// ---------------------------------------------------------------------------
// Seals
// ---------------------------------------------------------------------------

const SEAL_COLUMNS = `seq, first_seq, last_seq, size, root, sealed_at, prev_hash, hash, witnesses_json, registry_json`;

function toSeal(row: Row): Seal {
  const registry = readNullableText(row, "registry_json");
  return {
    seq: readInteger(row, "seq"),
    first_seq: readInteger(row, "first_seq"),
    last_seq: readInteger(row, "last_seq"),
    size: readInteger(row, "size"),
    root: readText(row, "root"),
    sealed_at: readText(row, "sealed_at"),
    prev_hash: readNullableText(row, "prev_hash"),
    hash: readText(row, "hash"),
    witnesses: readJson<WitnessSignature[]>(row, "witnesses_json"),
    // Null until the registry accepted the fingerprint, and null forever where
    // there is no registry to accept it (0006_sealing.sql).
    registry: registry === null ? null : (JSON.parse(registry) as RegistrySeal),
  };
}

/** The bound values of a seal row, in SEAL_COLUMNS order. */
function sealValues(seal: Seal): unknown[] {
  return [
    seal.seq,
    seal.first_seq,
    seal.last_seq,
    seal.size,
    seal.root,
    seal.sealed_at,
    seal.prev_hash,
    seal.hash,
    writeJson(seal.witnesses),
    seal.registry === null ? null : writeJson(seal.registry),
  ];
}

/** Store one seal, replacing whatever was there. */
export async function putSeal(db: D1Like, seal: Seal): Promise<void> {
  await db
    .prepare(
      `INSERT INTO seals (${SEAL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (seq) DO UPDATE SET
         first_seq = excluded.first_seq,
         last_seq = excluded.last_seq,
         size = excluded.size,
         root = excluded.root,
         sealed_at = excluded.sealed_at,
         prev_hash = excluded.prev_hash,
         hash = excluded.hash,
         witnesses_json = excluded.witnesses_json,
         registry_json = excluded.registry_json`,
    )
    .bind(...sealValues(seal))
    .run();
}

/** The newest seal, or null when nothing has been sealed. */
export async function latestSeal(db: D1Like): Promise<Seal | null> {
  const row = await db
    .prepare(`SELECT ${SEAL_COLUMNS} FROM seals ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/** One seal by its sequence number, or null. */
export async function sealBySeq(db: D1Like, seq: number): Promise<Seal | null> {
  const row = await db
    .prepare(`SELECT ${SEAL_COLUMNS} FROM seals WHERE seq = ? ${ONE_ROW}`)
    .bind(seq)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/**
 * The seal covering one event, or null when the event is not sealed yet.
 * Seals are disjoint and contiguous, so the covering seal is the one whose
 * range contains the seq; the (last_seq) index gets there in one seek.
 */
export async function sealCovering(
  db: D1Like,
  eventSeq: number,
): Promise<Seal | null> {
  const row = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE last_seq >= ? AND first_seq <= ?
       ORDER BY last_seq ${ONE_ROW}`,
    )
    .bind(eventSeq, eventSeq)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/**
 * Every seal overlapping the event range [firstSeq, lastSeq], in seal order.
 * This is what an inclusion proof over a slice of the log needs: not the seals
 * whose own seq falls in the range, but the seals that cover those events.
 */
export async function sealsBetween(
  db: D1Like,
  firstSeq: number,
  lastSeq: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE last_seq >= ? AND first_seq <= ?
       ORDER BY seq`,
    )
    .bind(firstSeq, lastSeq)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * The next page of seals after a known one, in seq order. The seal chain's
 * delta read: the caller keeps the last seq it saw and asks for what came
 * after. The limit is the caller's own; this module holds no page size.
 */
export async function sealsAfter(
  db: D1Like,
  afterSeq: number,
  limit: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals WHERE seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(afterSeq, limit)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * Every seal sealed on one UTC calendar day, in seq order: the anchor step's
 * read, and the only question about seals that starts from a date.
 *
 * `sealed_at` is the injected clock's ISO instant, always UTC and always
 * "<day>T...", so the day is the half-open text range from "<day>T" to "<day>U"
 * — 'U' is the character after 'T', so the range is exactly the strings with
 * that day's prefix. A range, not `substr(...) = ?`, because a range seeks the
 * (sealed_at) index and a function call over every row does not.
 */
export async function sealsSealedOn(db: D1Like, date: string): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE sealed_at >= ? AND sealed_at < ?
       ORDER BY seq`,
    )
    .bind(`${date}T`, `${date}U`)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * The seals still waiting on the outside world, oldest first: no
 * countersignature has been attached yet, or the registry has not accepted the
 * fingerprint. This is the sweep's work queue, and a seal leaves it by being
 * finished rather than by being marked.
 */
export async function unwitnessedSeals(
  db: D1Like,
  limit: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE witnesses_json = '[]' OR registry_json IS NULL
       ORDER BY seq LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * Record what the registry returned for a seal's fingerprint.
 *
 * No entry row moves: an entry's `seal` object carries the inclusion proof and
 * the countersignatures, and the registry receipt is neither. It is evidence
 * about the seal, kept with the seal.
 */
export async function setSealRegistry(
  db: D1Like,
  seq: number,
  registry: RegistrySeal | null,
): Promise<void> {
  await db
    .prepare(`UPDATE seals SET registry_json = ? WHERE seq = ?`)
    .bind(registry === null ? null : writeJson(registry), seq)
    .run();
}

/**
 * How the caller turns one covered entry into the row to store.
 *
 * Storage never derives a field, and it never reads the Worker's world module:
 * the caller is handed an entry id and the seal that now covers it, and gives
 * back what derivation made of them. The seal is passed rather than read back
 * because inside its own batch it is not readable yet.
 */
export type SealRederive = (
  entryId: string,
  seal: Seal,
  now: Date,
) => Promise<StoredEntryInput>;

/** The entries whose submission event falls inside a seal's range, in log order. */
async function entriesSubmittedIn(
  db: D1Like,
  firstSeq: number,
  lastSeq: number,
): Promise<Array<{ id: string; submittedSeq: number }>> {
  const rows = await db
    .prepare(
      `SELECT id, submitted_seq FROM entries
       WHERE submitted_seq >= ? AND submitted_seq <= ? ORDER BY submitted_seq`,
    )
    .bind(firstSeq, lastSeq)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    submittedSeq: readInteger(row, "submitted_seq"),
  }));
}

/**
 * Write a seal and rewrite every entry it seals, atomically.
 *
 * Section 6, "Seal": the entry hash is sealed as a fingerprint at submission, so
 * the moment a batch closes, every entry submitted inside it acquires a `seal`
 * object — an inclusion proof of its own submission event. That is a derived
 * field like any other, so it is recomputed by the caller and stored here, and
 * it lands in the same batch as the seal: a seal without the entries would leave
 * entries denying they were sealed, and the entries without the seal would have
 * them claiming a seal nobody can find.
 *
 * A plain INSERT, with no ON CONFLICT: unlike `putSeal`, which exists so a test
 * or a rebuild can restate a seal, this is the live path, and a second timer
 * arriving at the same range is a race to refuse rather than a row to overwrite.
 *
 * The range is bounded by the seal, so the entries read needs no page size: a
 * batch covers the events since the last seal and nothing more.
 */
export async function recordSeal(
  db: D1Like,
  seal: Seal,
  now: Date,
  rederive: SealRederive,
): Promise<string[]> {
  const covered = await entriesSubmittedIn(db, seal.first_seq, seal.last_seq);
  const statements = [
    db
      .prepare(`INSERT INTO seals (${SEAL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(...sealValues(seal)),
  ];
  for (const { id, submittedSeq } of covered) {
    const stored = await rederive(id, seal, now);
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        submittedSeq,
        stored.derivedThroughSeq,
      ),
    );
  }

  try {
    await db.batch(statements);
  } catch (cause) {
    // Ask the table rather than read the driver's message: a seal now standing
    // at this seq is what "conflict" means, and any other failure is not ours
    // to rename.
    if ((await sealBySeq(db, seal.seq)) !== null) {
      throw new SealConflictError(seal.seq, { cause });
    }
    throw cause;
  }
  return covered.map((entry) => entry.id);
}

/**
 * Attach countersignatures to a seal and rewrite every entry it covers, in one
 * batch.
 *
 * The entries have to move: `EntrySeal.witnesses` is the covering seal's
 * signature strings (src/seal.ts), and src/verify.ts compares an entry's
 * `seal.witnesses` against the seal's own. Written apart, a reader between the
 * two writes would see a countersigned seal and entries that deny it, and the
 * verifier would call the entries wrong.
 */
export async function setSealWitnesses(
  db: D1Like,
  seal: Seal,
  witnesses: readonly WitnessSignature[],
  now: Date,
  rederive: SealRederive,
): Promise<string[]> {
  const witnessed: Seal = { ...seal, witnesses: [...witnesses] };
  const statements = [
    db
      .prepare(`UPDATE seals SET witnesses_json = ? WHERE seq = ?`)
      .bind(writeJson(witnessed.witnesses), witnessed.seq),
  ];
  const covered = await entriesSubmittedIn(db, seal.first_seq, seal.last_seq);
  for (const { id, submittedSeq } of covered) {
    const stored = await rederive(id, witnessed, now);
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        submittedSeq,
        stored.derivedThroughSeq,
      ),
    );
  }
  await db.batch(statements);
  return covered.map((entry) => entry.id);
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

const ANCHOR_COLUMNS = `"date", first_seal_seq, last_seal_seq, roots_json, hash, external`;

function toAnchor(row: Row): Anchor {
  // The column held nothing but null until M16; now it holds the external
  // timestamp receipt as JSON, and reading one back is no longer an error.
  const external = readNullableText(row, "external");
  return {
    date: readText(row, "date"),
    first_seal_seq: readNullableInteger(row, "first_seal_seq"),
    last_seal_seq: readNullableInteger(row, "last_seal_seq"),
    roots: readJson<string[]>(row, "roots_json"),
    hash: readText(row, "hash"),
    external: external === null ? null : (JSON.parse(external) as AnchorExternal),
  };
}

/** Store one day's anchor, replacing whatever was there. */
export async function putAnchor(db: D1Like, anchor: Anchor): Promise<void> {
  await db
    .prepare(
      `INSERT INTO anchors (${ANCHOR_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT ("date") DO UPDATE SET
         first_seal_seq = excluded.first_seal_seq,
         last_seal_seq = excluded.last_seal_seq,
         roots_json = excluded.roots_json,
         hash = excluded.hash,
         external = excluded.external`,
    )
    .bind(
      anchor.date,
      anchor.first_seal_seq,
      anchor.last_seal_seq,
      writeJson(anchor.roots),
      anchor.hash,
      anchor.external === null ? null : writeJson(anchor.external),
    )
    .run();
}

/** One day's anchor, by its UTC calendar day, or null. */
export async function getAnchor(
  db: D1Like,
  date: string,
): Promise<Anchor | null> {
  const row = await db
    .prepare(`SELECT ${ANCHOR_COLUMNS} FROM anchors WHERE "date" = ? ${ONE_ROW}`)
    .bind(date)
    .first<Row>();
  return row === null ? null : toAnchor(row);
}

/**
 * The most recent anchor, or null. Days sort as strings because the day is
 * always "YYYY-MM-DD" in UTC, so lexical order is chronological order.
 */
export async function latestAnchor(db: D1Like): Promise<Anchor | null> {
  const row = await db
    .prepare(
      `SELECT ${ANCHOR_COLUMNS} FROM anchors ORDER BY "date" DESC ${ONE_ROW}`,
    )
    .first<Row>();
  return row === null ? null : toAnchor(row);
}

/**
 * The next page of anchors after a known day, in day order. Days are
 * "YYYY-MM-DD" in UTC, so lexical order is chronological order and the primary
 * key is the keyset. The limit is the caller's own.
 */
export async function anchorsAfter(
  db: D1Like,
  afterDate: string,
  limit: number,
): Promise<Anchor[]> {
  const rows = await db
    .prepare(
      `SELECT ${ANCHOR_COLUMNS} FROM anchors WHERE "date" > ? ORDER BY "date" LIMIT ?`,
    )
    .bind(afterDate, limit)
    .all<Row>();
  return rows.results.map(toAnchor);
}

/**
 * Record the external timestamp receipt for one day.
 *
 * Only the receipt moves. The anchor hash covers the date and the roots and
 * nothing else (D-037, item 5), so the day that was posted and the day that
 * comes back verifying are the same day.
 */
export async function setAnchorExternal(
  db: D1Like,
  date: string,
  external: AnchorExternal,
): Promise<void> {
  await db
    .prepare(`UPDATE anchors SET external = ? WHERE "date" = ?`)
    .bind(external === null ? null : writeJson(external), date)
    .run();
}

// ---------------------------------------------------------------------------
// Read receipts
// ---------------------------------------------------------------------------

/**
 * The `kind` a read receipt is stored under. The `receipts` table was declared
 * with a kind column in 0001 so more than one kind of receipt could share it;
 * this names the only one M17 writes.
 */
const READ_RECEIPT_KIND = "read";

const RECEIPT_COLUMNS = `id, kind, entry_id, seq, created_at, payload_json`;

/**
 * The row id for a read receipt: its kind and its counter.
 *
 * Deterministic rather than random, so the primary key and the unique index
 * refuse the same duplicate. A random id would let two isolates racing for the
 * same counter differ in the id while colliding on (kind, seq), which is a
 * second way to say the same thing and one more thing to keep in step.
 */
export function readReceiptId(counter: number): string {
  return `rcpt_${counter}`;
}

/**
 * A counter that was already taken.
 *
 * `nextReadCounter` reads the largest counter issued and adds one, and two
 * isolates asking at the same instant get the same answer — an isolate cannot
 * see what another is halfway through inserting. The guard is the unique index
 * on (kind, seq) in migrations/0007_receipts.sql, not the read: the second
 * insert fails, and this is what that failure means. The caller re-reads the
 * counter and signs a fresh receipt for the next number, because the counter is
 * inside the signed bytes and cannot be edited afterwards.
 */
export class ReceiptConflictError extends Error {
  override readonly name = "ReceiptConflictError";
  readonly counter: number;

  constructor(counter: number, options?: { cause?: unknown }) {
    super(`putReadReceipt: counter ${counter} is already issued`, options);
    this.counter = counter;
  }
}

/**
 * The next running counter: one past the largest issued, and 1 on an empty
 * table.
 *
 * Whitepaper Section 8: the receipt names "a running counter". It runs across
 * every read, not per entry, so a reader can place their receipt in the whole
 * stream of reads nomankind served rather than only in one entry's.
 */
export async function nextReadCounter(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT MAX(seq) AS last FROM receipts WHERE kind = ?`)
    .bind(READ_RECEIPT_KIND)
    .first<Row>();
  const last = row === null ? null : readNullableInteger(row, "last");
  return last === null ? 1 : last + 1;
}

/**
 * Store one signed read receipt.
 *
 * `seq` is the counter inside the receipt, and the whole receipt goes into
 * `payload_json` verbatim: the signature covers exactly those five fields, so a
 * reader who lost their copy must get back the same bytes that were signed.
 * Nothing is recomputed on the way in or out.
 *
 * Throws `ReceiptConflictError` when the counter was already issued — a
 * concurrent reader took the number. The unique index is the guard; see
 * migrations/0007_receipts.sql.
 */
export async function putReadReceipt(
  db: D1Like,
  input: {
    readonly entryId: string;
    readonly createdAt: string;
    readonly receipt: ReadReceipt;
  },
): Promise<void> {
  const counter = input.receipt.counter;
  try {
    await db
      .prepare(
        `INSERT INTO receipts (${RECEIPT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        readReceiptId(counter),
        READ_RECEIPT_KIND,
        input.entryId,
        counter,
        input.createdAt,
        writeJson(input.receipt),
      )
      .run();
  } catch (cause) {
    // Ask the table rather than read the driver's message: a receipt now
    // standing at this counter is what "conflict" means, and any other failure
    // is not ours to rename.
    if ((await readReceiptByCounter(db, counter)) !== null) {
      throw new ReceiptConflictError(counter, { cause });
    }
    throw cause;
  }
}

/** One receipt by its counter, or null. */
export async function readReceiptByCounter(
  db: D1Like,
  counter: number,
): Promise<ReadReceipt | null> {
  const row = await db
    .prepare(
      `SELECT payload_json FROM receipts WHERE kind = ? AND seq = ? ${ONE_ROW}`,
    )
    .bind(READ_RECEIPT_KIND, counter)
    .first<Row>();
  return row === null ? null : readJson<ReadReceipt>(row, "payload_json");
}

/**
 * A page of one entry's read receipts, in counter order. Keyset, not offset:
 * the caller passes back the last counter it saw. The limit is the caller's
 * own; this module holds no page size.
 */
export async function readReceiptsForEntry(
  db: D1Like,
  entryId: string,
  afterCounter: number,
  limit: number,
): Promise<ReadReceipt[]> {
  const rows = await db
    .prepare(
      `SELECT payload_json FROM receipts
       WHERE kind = ? AND entry_id = ? AND seq > ?
       ORDER BY seq LIMIT ?`,
    )
    .bind(READ_RECEIPT_KIND, entryId, afterCounter, limit)
    .all<Row>();
  return rows.results.map((row) => readJson<ReadReceipt>(row, "payload_json"));
}

/**
 * One UTC day's reads, grouped by entry and in entry_id order.
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily", so "any reader can compare the receipts they hold against the
 * published counts". This is the read behind that publication.
 *
 * `created_at` is the injected clock's ISO instant, always "<day>T...", so the
 * day is the half-open text range from "<day>T" to "<day>U" — the same trick
 * `sealsSealedOn` uses, and for the same reason: a range seeks the index and a
 * function call over every row does not.
 *
 * Keyset-paged by entry_id, because a day with more entries than one page can
 * still be published in full.
 */
export async function readCountsOn(
  db: D1Like,
  date: string,
  afterEntryId: string | undefined,
  limit: number,
): Promise<ReadCountRow[]> {
  const bindings: unknown[] = [READ_RECEIPT_KIND, `${date}T`, `${date}U`];
  let after = "";
  if (afterEntryId !== undefined) {
    after = "AND entry_id > ? ";
    bindings.push(afterEntryId);
  }
  bindings.push(limit);

  const rows = await db
    .prepare(
      `SELECT entry_id, COUNT(*) AS reads FROM receipts
       WHERE kind = ? AND created_at >= ? AND created_at < ? ${after}
       GROUP BY entry_id ORDER BY entry_id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => ({
    entry_id: readText(row, "entry_id"),
    count: readInteger(row, "reads"),
  }));
}

/**
 * The day's total and the counters that bound it: the smallest and largest
 * counter issued on that UTC day, both null when the day counted nothing.
 *
 * The bounds are what make the published count checkable. A reader holding a
 * receipt whose counter falls inside the day's range knows their read should be
 * in that day's total, and a day that published fewer reads than its own
 * counter range spans has a hole in it.
 */
export async function readCounterRangeOn(
  db: D1Like,
  date: string,
): Promise<{
  total: number;
  counter_first: number | null;
  counter_last: number | null;
}> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS total, MIN(seq) AS first_seq, MAX(seq) AS last_seq
       FROM receipts
       WHERE kind = ? AND created_at >= ? AND created_at < ?`,
    )
    .bind(READ_RECEIPT_KIND, `${date}T`, `${date}U`)
    .first<Row>();
  if (row === null) {
    return { total: 0, counter_first: null, counter_last: null };
  }
  return {
    total: readInteger(row, "total"),
    counter_first: readNullableInteger(row, "first_seq"),
    counter_last: readNullableInteger(row, "last_seq"),
  };
}

/**
 * The UTC day of the oldest read receipt, or null when none was ever issued.
 *
 * Where the daily publication starts from: a sweep that has never published
 * has to know which day is the first one with anything to say.
 */
export async function earliestReadReceiptDay(
  db: D1Like,
): Promise<string | null> {
  const row = await db
    .prepare(`SELECT MIN(created_at) AS earliest FROM receipts WHERE kind = ?`)
    .bind(READ_RECEIPT_KIND)
    .first<Row>();
  const earliest = row === null ? null : readNullableText(row, "earliest");
  return earliest === null ? null : utcDay(earliest);
}

/** What the reader's search asks the store for, and where it resumes. */
export interface ReadCandidatesQuery {
  readonly subject: string;
  readonly category: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly before this submitted_seq; omit for the first page. */
  readonly beforeSubmittedSeq?: number;
}

/**
 * The verified entries a read may be answered from, newest submission first.
 *
 * Only `status = 'verified'` ever leaves this function: Section 8 promises the
 * reader an answer the log stands behind, and draft, rejected, superseded and
 * overturned are exactly the states it does not. Which of the verified ones is
 * actually served is `chooseReadable`'s answer (src/read.ts) — the tier and age
 * gates are rules, not SQL, and nothing here derives or filters on a field
 * derivation owns beyond the status it already wrote.
 *
 * Newest first, keyset-paged downward by submitted_seq, and served by the
 * `entries_subject_category_seq` index from 0001.
 */
export async function readCandidates(
  db: D1Like,
  query: ReadCandidatesQuery,
): Promise<StoredEntry[]> {
  const bindings: unknown[] = [query.subject, query.category];
  let before = "";
  if (query.beforeSubmittedSeq !== undefined) {
    before = "AND submitted_seq < ? ";
    bindings.push(query.beforeSubmittedSeq);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries
       WHERE subject = ? AND category = ? ${before}AND status = 'verified'
       ORDER BY submitted_seq DESC LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * The newest event of one type, or null when the log holds none.
 *
 * What a daily sweep asks to find where it left off: the last `read_count` it
 * published names the last day it published. One seek on the (type, seq) index
 * from 0001, never a scan of the log.
 */
export async function latestEventOfType(
  db: D1Like,
  type: EventType,
): Promise<Event | null> {
  const row = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE type = ? ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(type)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

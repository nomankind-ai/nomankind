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

import type { Anchor } from "../anchor.js";
import type { OpenAssignment } from "../assign.js";
import type { Sidecar } from "../derive.js";
import type { Event, EventType } from "../events.js";
import type { Entry } from "../schema.js";
import type { Seal, WitnessSignature } from "../seal.js";
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
  const id = entryField(entry, "id");
  const submittedSeq = await submittedSeqOf(db, id);
  await db
    .prepare(
      `INSERT INTO entries (
         id, subject, category, status, submitted_at, submitted_seq, author,
         entry_json, sidecar_json, derived_through_seq
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         subject = excluded.subject,
         category = excluded.category,
         status = excluded.status,
         submitted_at = excluded.submitted_at,
         submitted_seq = excluded.submitted_seq,
         author = excluded.author,
         entry_json = excluded.entry_json,
         sidecar_json = excluded.sidecar_json,
         derived_through_seq = excluded.derived_through_seq`,
    )
    .bind(
      id,
      entryField(entry, "subject"),
      entryField(entry, "category"),
      entryField(entry, "status"),
      entryField(entry, "submitted_at"),
      submittedSeq,
      entryField(entry, "author"),
      writeJson(entry),
      writeJson(sidecar),
      derivedThroughSeq,
    )
    .run();
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
 * Store one assignment. `missed_seq` starts null: an assignment is open when it
 * is made, and only an `assignment_missed` event closes it.
 */
export async function putAssignment(
  db: D1Like,
  entryId: string,
  assignment: OpenAssignment,
): Promise<void> {
  await db
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
    )
    .run();
}

/**
 * The entry's open assignment: the newest one with no `missed_seq`, or null.
 *
 * The newest assignment is the one in force, so an earlier one never reopens.
 * Served by the (entry_id, seq) index.
 */
export async function openAssignment(
  db: D1Like,
  entryId: string,
): Promise<OpenAssignment | null> {
  const row = await db
    .prepare(
      `SELECT assignment_json FROM assignments
       WHERE entry_id = ? AND missed_seq IS NULL
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

// ---------------------------------------------------------------------------
// Seals
// ---------------------------------------------------------------------------

const SEAL_COLUMNS = `seq, first_seq, last_seq, size, root, sealed_at, prev_hash, hash, witnesses_json`;

function toSeal(row: Row): Seal {
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
  };
}

/** Store one seal, replacing whatever was there. */
export async function putSeal(db: D1Like, seal: Seal): Promise<void> {
  await db
    .prepare(
      `INSERT INTO seals (${SEAL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (seq) DO UPDATE SET
         first_seq = excluded.first_seq,
         last_seq = excluded.last_seq,
         size = excluded.size,
         root = excluded.root,
         sealed_at = excluded.sealed_at,
         prev_hash = excluded.prev_hash,
         hash = excluded.hash,
         witnesses_json = excluded.witnesses_json`,
    )
    .bind(
      seal.seq,
      seal.first_seq,
      seal.last_seq,
      seal.size,
      seal.root,
      seal.sealed_at,
      seal.prev_hash,
      seal.hash,
      writeJson(seal.witnesses),
    )
    .run();
}

/** The newest seal, or null when nothing has been sealed. */
export async function latestSeal(db: D1Like): Promise<Seal | null> {
  const row = await db
    .prepare(`SELECT ${SEAL_COLUMNS} FROM seals ORDER BY seq DESC ${ONE_ROW}`)
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

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

const ANCHOR_COLUMNS = `"date", first_seal_seq, last_seal_seq, roots_json, hash, external`;

function toAnchor(row: Row): Anchor {
  const external = readNullableText(row, "external");
  if (external !== null) {
    throw new TypeError("anchors.external: reserved, must be null");
  }
  return {
    date: readText(row, "date"),
    first_seal_seq: readNullableInteger(row, "first_seal_seq"),
    last_seal_seq: readNullableInteger(row, "last_seal_seq"),
    roots: readJson<string[]>(row, "roots_json"),
    hash: readText(row, "hash"),
    external: null,
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
      anchor.external,
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

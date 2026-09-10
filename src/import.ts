/**
 * The replay of a mirror, as pure functions over the directory's own bytes.
 *
 * Whitepaper Section 11 and the Conclusion: "the exit is not a promise, it is a
 * copy", and a copy is only an exit if somebody can start a log from it. This
 * module is the reading half of that — the layout parsed and checked, the events
 * put in order, a stored head held against the mirror's, and the plan of what a
 * fresh database has to be given. The writing half is src/cli/import-mirror.ts,
 * which is where a database and a filesystem are allowed to exist.
 *
 * Pure and over one argument, exactly as src/mirror.ts is: `readLayout` takes
 * the directory as a map of path to content — the same `MirrorFile.path` keys
 * `buildMirror` produces — so the export a test just built can be replayed
 * without ever touching a disk, and the command's only extra job is to read the
 * files into that map. Nothing here opens anything, and nothing here decides
 * anything a verifier could not decide again.
 *
 * Nothing here is derived either. The entries are re-derived by the kernel from
 * the imported events, the three recomputed families are recomputed by
 * src/mirror.ts's own functions, and the only rows this module builds are the
 * registry's — the operator, its agents and its domains — which it folds out of
 * the events and then holds against `operators.json` rather than copying that
 * file into a table. Two things the mirror deliberately does not carry cannot be
 * rebuilt and are left off the row rather than invented: the payout reference
 * and status, which are the payment provider's business and not the log's, and
 * the agent that exercised a genesis naming, which the event does not name.
 *
 * Both layouts are read. A `nomankind-mirror-v2` directory is the current one;
 * a `nomankind-mirror-v1` one — pulled before the attestations, the standing,
 * the ledger and the sidecar's source class joined the export — is read as what
 * v1 was, five required files rather than seven and no answers to put back. The
 * ledger and the standing are recomputed from the events either way, so the
 * only thing the older copy costs is what the log never carried; every other
 * format string is `unsupported_format`.
 *
 * No policy number lives here, no `node:` import, and no clock: every instant
 * used is the mirror's own `as_of`, which is the newest seal's.
 */

import type { Anchor } from "./anchor.js";
import { canonicalize } from "./hash.js";
import type { Attestation, Event, EventType } from "./events.js";
import {
  MIRROR_FORMATS,
  mirrorFormatOf,
  sealFileName,
  type MirrorEntryRecord,
  type MirrorFormat,
  type MirrorOperator,
} from "./mirror.js";
import { DEFAULT_DOMAIN } from "./policy.js";
import type { ProbeAnswer } from "./probe.js";
import type { Seal } from "./seal.js";
import type {
  AgentRecord,
  OperatorDomainRecord,
  OperatorRecord,
} from "./storage/repository.js";

/**
 * The import refused, in one snake_case word.
 *
 * The same voice the sweep's steps skip in and `npm run mirror` fails in: a
 * person reading a refused import and a person reading the status board are
 * reading one vocabulary. This module's words are `unreadable`, `not_json`,
 * `unsupported_format`, `bad_manifest`, `no_seal`, `bad_events`, `missing_entry`,
 * `operators_differ` and `not_a_prefix`; the command adds the four it is the
 * only one in a position to say -- `verify_failed`, `database_not_empty`,
 * `entry_differs` and `underivable_entry`.
 */
export class ImportRefusal extends Error {
  override readonly name = "ImportRefusal";
  readonly reason: string;

  constructor(reason: string, detail: string) {
    super(`${reason}: ${detail}`);
    this.reason = reason;
  }
}

/** The files every mirror carries, whichever layout it claims. */
const REQUIRED_FILES: readonly string[] = Object.freeze([
  "mirror.json",
  "seals.jsonl",
  "anchors.jsonl",
  "operators.json",
  "index.json",
]);

/**
 * The two files v2 added beside the attestations directory.
 *
 * Required of a v2 directory and not of a v1 one, which was written before any
 * of the three existed. Both are recomputed from the events on the way in
 * anyway (src/cli/import-mirror.ts), so a v1 mirror is replayed with the same
 * ledger and the same standing a v2 one is: what the older layout costs is the
 * model's answers, and nothing else.
 */
const V2_FILES: readonly string[] = Object.freeze([
  "standing.json",
  "ledger.jsonl",
]);

const ENTRY_PREFIX = "entries/";
const ATTESTATION_PREFIX = "attestations/";
const JSON_SUFFIX = ".json";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The canonical form of a value, or a sentinel for one that has none. */
function safeCanonical(value: unknown): string {
  try {
    return canonicalize(value);
  } catch {
    return "<uncanonical>";
  }
}

/** Narrow one event to its own type, the way the kernel does it. */
function isType<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/** One JSON document of the mirror, parsed. */
function document(files: ReadonlyMap<string, string>, path: string): unknown {
  const content = files.get(path);
  if (content === undefined) {
    throw new ImportRefusal("unreadable", `${path}: not in the mirror`);
  }
  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw new ImportRefusal("not_json", path);
  }
}

/** One `.jsonl` file of the mirror: a document per line, blank lines ignored. */
function lines(files: ReadonlyMap<string, string>, path: string): unknown[] {
  const content = files.get(path);
  if (content === undefined) {
    throw new ImportRefusal("unreadable", `${path}: not in the mirror`);
  }
  const values: unknown[] = [];
  const split = content.split("\n");
  for (let index = 0; index < split.length; index += 1) {
    const line = split[index]!;
    if (line.length === 0) continue;
    try {
      values.push(JSON.parse(line) as unknown);
    } catch {
      throw new ImportRefusal("not_json", `${path}:${index + 1}`);
    }
  }
  return values;
}

/** Everything one `<env>/` directory holds, parsed and put in order. */
export interface MirrorLayout {
  /** `local`, `demo` or `production`: what the manifest calls this directory. */
  readonly environment: string;
  /**
   * The layout the manifest claims: `v2` is the current one, `v1` is the older
   * seven-item one, which carries no attestation answers to put back.
   */
  readonly format: MirrorFormat;
  /** The newest seal's `last_seq`: the position everything is derived at. */
  readonly head: number;
  /** The newest seal's own seq. */
  readonly sealSeq: number;
  /** The newest seal's `sealed_at`: the instant everything is derived at. */
  readonly asOf: string;
  /** Every seal, in seq order. */
  readonly seals: readonly Seal[];
  /** Every anchor, in date order. */
  readonly anchors: readonly Anchor[];
  /** Every sealed event, in seq order, read out of the seals' own files. */
  readonly events: readonly Event[];
  /** Every operator, exactly as `operators.json` carries it. */
  readonly operators: readonly MirrorOperator[];
  /** Every `entries/<id>.json`, by id. */
  readonly entries: ReadonlyMap<string, MirrorEntryRecord>;
  /**
   * The model's answers per attestation, from `attestations/<id>.json`.
   *
   * Always empty for a v1 mirror, which carries no such file: the answers are
   * the one thing in the export that is not a function of the log, so they are
   * the one thing an older copy cannot be asked for.
   */
  readonly answers: ReadonlyMap<string, readonly ProbeAnswer[] | null>;
}

/** The newest seal by seq, which is what the export is headed by. */
function newestSeal(seals: readonly Seal[]): Seal {
  const newest = seals[seals.length - 1];
  if (newest === undefined) {
    throw new ImportRefusal("no_seal", "the mirror seals nothing");
  }
  return newest;
}

/**
 * The sealed events, read out of one file per seal and checked against the
 * seals that named them.
 *
 * The check is the point of reading them this way. A mirror is a stranger's
 * directory: an events file with a line removed, a seal whose range nothing
 * covers, or a log that does not start at 0 would all be replayed into a
 * database that could never be sealed again, and `appendEvents` would refuse
 * them one at a time long after the first rows were written.
 */
function sealedEvents(
  files: ReadonlyMap<string, string>,
  seals: readonly Seal[],
): Event[] {
  const events: Event[] = [];
  for (const seal of seals) {
    const path = sealFileName(seal.seq);
    const batch = lines(files, path) as Event[];
    const expected = seal.last_seq - seal.first_seq + 1;
    if (batch.length !== expected) {
      throw new ImportRefusal(
        "bad_events",
        `${path}: ${batch.length} events for a seal covering ${expected}`,
      );
    }
    for (let index = 0; index < batch.length; index += 1) {
      const event = batch[index]!;
      if (event.seq !== seal.first_seq + index) {
        throw new ImportRefusal(
          "bad_events",
          `${path}: expected seq ${seal.first_seq + index}, found ${event.seq}`,
        );
      }
      events.push(event);
    }
  }

  // The log the mirror carries has to be a whole log, from 0: a replay that
  // began anywhere else could never chain onto an empty database.
  for (let index = 0; index < events.length; index += 1) {
    if (events[index]!.seq === index) continue;
    throw new ImportRefusal(
      "bad_events",
      `the sealed log skips ${index}`,
    );
  }
  const first = events[0];
  if (first !== undefined && first.prev_hash !== null) {
    throw new ImportRefusal("bad_events", "the first event chains onto nothing");
  }
  return events;
}

/** The operators file, in the shape `buildMirror` wrote it. */
function operatorsOf(value: unknown): MirrorOperator[] {
  const rows = isRecord(value) ? value["operators"] : undefined;
  if (!Array.isArray(rows)) {
    throw new ImportRefusal("unreadable", "operators.json: not an operator list");
  }
  return rows.map((row) => {
    if (!isRecord(row) || typeof row["operator"] !== "string") {
      throw new ImportRefusal("unreadable", "operators.json: a row names none");
    }
    const domains = row["domains"];
    const agents = row["agents"];
    return {
      operator: row["operator"],
      maintainer: row["maintainer"] === true,
      provider: row["provider"] === true,
      trusted: row["trusted"] === true,
      domains: Array.isArray(domains)
        ? domains.filter((one): one is string => typeof one === "string")
        : [],
      agents: Array.isArray(agents)
        ? agents.filter((one): one is string => typeof one === "string")
        : [],
    };
  });
}

/**
 * Read one mirror directory.
 *
 * `files` is keyed exactly as `MirrorFile.path` is — `mirror.json`,
 * `events/00000000.jsonl`, `entries/<id>.json` — so what `buildMirror` returned
 * can be handed straight back in.
 */
export function readLayout(files: ReadonlyMap<string, string>): MirrorLayout {
  const manifest = document(files, "mirror.json");
  if (!isRecord(manifest)) {
    throw new ImportRefusal("bad_manifest", "mirror.json: not an object");
  }
  // The format before the files, because it is what says which files there are
  // meant to be: a v1 directory is missing three of v2's on purpose.
  const format = mirrorFormatOf(manifest["format"]);
  if (format === null) {
    throw new ImportRefusal(
      "unsupported_format",
      `mirror.json: /format is not one of ${MIRROR_FORMATS.join(", ")}`,
    );
  }
  for (const path of format === "v1"
    ? REQUIRED_FILES
    : [...REQUIRED_FILES, ...V2_FILES]) {
    if (!files.has(path)) {
      throw new ImportRefusal("unreadable", `${path}: not in the mirror`);
    }
  }

  const environment = manifest["environment"];
  if (typeof environment !== "string" || environment.length === 0) {
    throw new ImportRefusal("bad_manifest", "mirror.json: /environment");
  }

  const seals = (lines(files, "seals.jsonl") as Seal[]).sort(
    (left, right) => left.seq - right.seq,
  );
  const newest = newestSeal(seals);
  const anchors = (lines(files, "anchors.jsonl") as Anchor[]).sort((left, right) =>
    left.date < right.date ? -1 : left.date > right.date ? 1 : 0,
  );
  const events = sealedEvents(files, seals);

  const entries = new Map<string, MirrorEntryRecord>();
  const answers = new Map<string, readonly ProbeAnswer[] | null>();
  for (const path of files.keys()) {
    if (!path.endsWith(JSON_SUFFIX)) continue;
    if (path.startsWith(ENTRY_PREFIX)) {
      const id = path.slice(ENTRY_PREFIX.length, -JSON_SUFFIX.length);
      const file = document(files, path);
      if (!isRecord(file) || !isRecord(file["entry"])) {
        throw new ImportRefusal("unreadable", `${path}: not an entry record`);
      }
      entries.set(id, file as unknown as MirrorEntryRecord);
      continue;
    }
    if (path.startsWith(ATTESTATION_PREFIX)) {
      const id = path.slice(ATTESTATION_PREFIX.length, -JSON_SUFFIX.length);
      const file = document(files, path);
      if (!isRecord(file)) {
        throw new ImportRefusal("unreadable", `${path}: not an attestation`);
      }
      const held = file["answers"];
      answers.set(id, Array.isArray(held) ? (held as ProbeAnswer[]) : null);
    }
  }

  return {
    environment,
    format,
    head: newest.last_seq,
    sealSeq: newest.seq,
    asOf: newest.sealed_at,
    seals,
    anchors,
    events,
    operators: operatorsOf(document(files, "operators.json")),
    entries,
    answers,
  };
}

// ---------------------------------------------------------------------------
// The stored head, against the mirror's
// ---------------------------------------------------------------------------

/** One event as the stored log names it: enough to say whether it is the same. */
export interface StoredEvent {
  readonly seq: number;
  readonly hash: string;
}

/**
 * Where a stored log sits relative to the mirror.
 *
 * `empty` is a fresh database. `prefix` is a database holding exactly the
 * mirror's first `from` events — the same events under the same hashes — and
 * `from` is the first seq the import has to append. Anything else is a
 * divergence, and the seq named is the first position the two disagree at.
 */
export type HeadRelation =
  | { readonly kind: "empty" }
  | { readonly kind: "prefix"; readonly from: number }
  | { readonly kind: "diverged"; readonly seq: number };

/**
 * Hold a stored log against the mirror's.
 *
 * "Same events, same hashes": the hash covers the seq, the instant, the type,
 * the entry and the payload as well as the link, so two logs that agree hash for
 * hash agree about everything an importer could write. A stored log longer than
 * the mirror is not a prefix of it — there is nothing this mirror can add to it —
 * and is a divergence at the first position past the mirror's end, which is the
 * honest place to point at.
 */
export function headRelation(
  events: readonly Event[],
  stored: readonly StoredEvent[],
): HeadRelation {
  if (stored.length === 0) return { kind: "empty" };
  if (stored.length > events.length) {
    return { kind: "diverged", seq: events.length };
  }
  for (let index = 0; index < stored.length; index += 1) {
    const held = stored[index]!;
    const event = events[index]!;
    if (held.seq === event.seq && held.hash === event.hash) continue;
    return { kind: "diverged", seq: held.seq };
  }
  return { kind: "prefix", from: stored.length };
}

// ---------------------------------------------------------------------------
// The registry rows, folded out of the events
// ---------------------------------------------------------------------------

/** One operator's rows: the record, its agents, and the domains it is in. */
export interface ImportOperator {
  readonly record: OperatorRecord;
  readonly agents: readonly AgentRecord[];
  readonly domains: readonly OperatorDomainRecord[];
}

/** What one operator's rows look like while the fold is still running. */
interface OperatorFold {
  maintainer: boolean;
  registeredSeq: number;
  domain: string;
  trusted: boolean;
  trustedSeq: number | null;
  registeredBy: string | null;
  attestation: Attestation | null;
  readonly agents: AgentRecord[];
  readonly domains: OperatorDomainRecord[];
}

/**
 * The registry rows one log implies at a position.
 *
 * Section 5 and decision D-071: the registration, the agent bindings, the trust
 * grants and the domain joins are all events, so the three tables the Worker
 * reads the registry out of are an index into the log and never a second source
 * of truth. That is what makes them replayable at all — and what makes the
 * comparison below a check rather than a formality.
 *
 * `provider` is the one column that is read off `operators.json` instead of
 * folded: no door registers a provider (src/worker/registry.ts refuses the
 * domain), so the log carries no event that would say one is, and the file's
 * word for it is the only word there is.
 */
export function operatorRows(
  events: readonly Event[],
  file: readonly MirrorOperator[],
  head: number,
): ImportOperator[] {
  const folds = new Map<string, OperatorFold>();
  const providers = new Map<string, boolean>();
  for (const one of file) providers.set(one.operator, one.provider);

  for (const event of events) {
    if (event.seq > head) break;

    if (isType(event, "operator_registered")) {
      const { operator, maintainer, domain } = event.payload;
      folds.set(operator, {
        maintainer,
        registeredSeq: event.seq,
        domain: domain ?? DEFAULT_DOMAIN,
        trusted: false,
        trustedSeq: null,
        registeredBy: null,
        attestation: null,
        agents: [],
        domains: [],
      });
      continue;
    }

    if (isType(event, "agent_bound")) {
      const fold = folds.get(event.payload.operator);
      if (fold === undefined) continue;
      fold.agents.push({
        agentId: event.payload.agent,
        operatorId: event.payload.operator,
        registeredSeq: event.seq,
      });
      // The first binding is the registration's own, and it is the one whose
      // attestation the registration domain row carries.
      if (fold.registeredBy === null) {
        fold.registeredBy = event.payload.agent;
        fold.attestation = event.payload.attestation;
      }
      continue;
    }

    if (isType(event, "operator_trusted")) {
      const fold = folds.get(event.payload.operator);
      if (fold === undefined) continue;
      fold.trusted = true;
      fold.trustedSeq = event.seq;
      continue;
    }

    if (isType(event, "operator_untrusted")) {
      const fold = folds.get(event.payload.operator);
      if (fold === undefined) continue;
      fold.trusted = false;
      fold.trustedSeq = null;
      continue;
    }

    if (isType(event, "operator_joined_domain")) {
      const fold = folds.get(event.payload.operator);
      if (fold === undefined) continue;
      fold.domains.push({
        operator: event.payload.operator,
        domain: event.payload.domain,
        seq: event.seq,
        attestation: event.payload.attestation,
      });
    }
  }

  const rows: ImportOperator[] = [];
  for (const [operator, fold] of folds) {
    rows.push({
      record: {
        id: operator,
        maintainer: fold.maintainer,
        provider: providers.get(operator) === true,
        registeredSeq: fold.registeredSeq,
        // The payout reference and status are not in this: the mirror is CC0
        // and a payment provider's name for an operator is not the log's to
        // publish, so a fork onboards its own operators before it pays any.
        details: {
          registered_by: fold.registeredBy,
          attestation: fold.attestation,
          trusted: fold.trusted,
          trusted_seq: fold.trustedSeq,
        },
      },
      agents: fold.agents,
      domains: [
        {
          operator,
          domain: fold.domain,
          seq: fold.registeredSeq,
          attestation: fold.attestation,
        },
        ...fold.domains,
      ],
    });
  }
  rows.sort((left, right) =>
    left.record.id < right.record.id ? -1 : left.record.id > right.record.id ? 1 : 0,
  );

  const difference = registryDifference(rows, file);
  if (difference !== null) {
    throw new ImportRefusal("operators_differ", difference);
  }
  return rows;
}

/**
 * The first thing `operators.json` says that the events do not, or null.
 *
 * The file is the mirror's summary of what the log already carries, so the two
 * have to agree or one of them was edited. Said the other way round: nothing in
 * `operators.json` is trusted except `provider`, and this is the sentence that
 * makes that true.
 */
function registryDifference(
  rows: readonly ImportOperator[],
  file: readonly MirrorOperator[],
): string | null {
  const listed = [...file].sort((left, right) =>
    left.operator < right.operator ? -1 : left.operator > right.operator ? 1 : 0,
  );
  if (rows.length !== listed.length) {
    return `operators.json lists ${listed.length}, the events register ${rows.length}`;
  }
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index]!;
    const one = listed[index]!;
    if (row.record.id !== one.operator) {
      return `operators.json names ${one.operator} where the events name ${row.record.id}`;
    }
    const folded = {
      maintainer: row.record.maintainer,
      trusted: row.record.details["trusted"] === true,
      domains: row.domains.map((domain) => domain.domain),
      agents: [...row.agents.map((agent) => agent.agentId)].sort(),
    };
    const carried = {
      maintainer: one.maintainer,
      trusted: one.trusted,
      domains: [...one.domains],
      agents: [...one.agents].sort(),
    };
    if (safeCanonical(folded) !== safeCanonical(carried)) {
      return `operators.json and the events disagree about ${one.operator}`;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/**
 * The submitted entries at or below a position, in submission order.
 *
 * Read off the events rather than off `index.json`, for the reason the whole
 * module exists: the log is what is being replayed, and an index with a row
 * removed would quietly import fewer entries than the mirror proves.
 */
export function entryIdsAt(events: readonly Event[], head: number): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const event of events) {
    if (event.seq > head) break;
    if (!isType(event, "entry_submitted")) continue;
    const id = event.entry_id;
    if (id === null || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

/** What one import writes, decided before anything is written. */
export interface ImportPlan {
  /** The first seq appended: 0 into a fresh database, the tail under --force. */
  readonly from: number;
  /** The events to append, in seq order. */
  readonly events: readonly Event[];
  /** The registry rows, folded out of the whole sealed log. */
  readonly operators: readonly ImportOperator[];
  /** The entries to re-derive at the head, in submission order. */
  readonly entries: readonly string[];
  readonly seals: readonly Seal[];
  readonly anchors: readonly Anchor[];
  readonly head: number;
  readonly asOf: string;
}

/**
 * What to write, for one layout against one stored head.
 *
 * Only the events are trimmed by the relation. Everything else is written for
 * the whole mirror however much of the log was already there: the rows are an
 * index into the log at the mirror's sealed head, and a database that had half
 * the events has half an index, which the same upserts put right.
 *
 * Refuses a mirror that names an entry it carries no file for. `verify-mirror`
 * checks every file the index lists and every count the manifest claims, which
 * leaves exactly one hole — a submission the directory simply has no file for —
 * and an import that passed over it would build a database the mirror cannot be
 * rebuilt from.
 */
export function importPlan(
  layout: MirrorLayout,
  relation: HeadRelation,
): ImportPlan {
  if (relation.kind === "diverged") {
    throw new ImportRefusal(
      "not_a_prefix",
      `the stored log and the mirror part at seq ${relation.seq}`,
    );
  }
  const from = relation.kind === "empty" ? 0 : relation.from;
  const entries = entryIdsAt(layout.events, layout.head);
  for (const id of entries) {
    if (layout.entries.has(id)) continue;
    throw new ImportRefusal("missing_entry", `entries/${id}.json`);
  }
  return {
    from,
    events: layout.events.slice(from),
    operators: operatorRows(layout.events, layout.operators, layout.head),
    entries,
    seals: layout.seals,
    anchors: layout.anchors,
    head: layout.head,
    asOf: layout.asOf,
  };
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

/** One named difference: the JSON pointer it is at, and the word for it. */
export interface Difference {
  readonly field: string;
  readonly reason: string;
}

/**
 * The first field two objects disagree on, as a JSON pointer under `prefix`.
 *
 * The same shape and the same words `verify-mirror` names a difference in, so a
 * refused import and a failed verification point at a field the same way. The
 * first and not all of them: a reader who edited one field wants to be told
 * which, and keys are walked in the expected object's own order so two runs over
 * one directory name one field.
 */
export function firstDifference(
  expected: Record<string, unknown>,
  actual: unknown,
  prefix: string,
): Difference | null {
  if (!isRecord(actual)) return { field: prefix, reason: "malformed" };
  for (const key of Object.keys(expected)) {
    // A key whose derived value is `undefined` is a key JSON does not write --
    // `domain` on a legacy v0.6 core is exactly that -- so the file is right to
    // carry none and wrong to carry one.
    if (expected[key] === undefined) {
      if (!Object.prototype.hasOwnProperty.call(actual, key)) continue;
      return { field: `${prefix}/${key}`, reason: "unexpected" };
    }
    if (!Object.prototype.hasOwnProperty.call(actual, key)) {
      return { field: `${prefix}/${key}`, reason: "missing" };
    }
    if (safeCanonical(expected[key]) !== safeCanonical(actual[key])) {
      return { field: `${prefix}/${key}`, reason: "mismatch" };
    }
  }
  for (const key of Object.keys(actual)) {
    if (Object.prototype.hasOwnProperty.call(expected, key)) continue;
    return { field: `${prefix}/${key}`, reason: "unexpected" };
  }
  return null;
}

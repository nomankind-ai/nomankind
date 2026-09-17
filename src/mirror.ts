/**
 * The daily mirror: the sealed log as a directory of files.
 *
 * Whitepaper Section 11, "Deployment and status": the log is exported daily to a
 * public repository under CC0, so that nomankind going away is an inconvenience
 * rather than an ending. The Conclusion says the same thing from the other side:
 * "the exit is not a promise, it is a copy". This module is that copy's shape —
 * which files there are, what is in each of them, and the bytes.
 *
 * Pure, and over one argument. Nothing here reads a database, a clock or a
 * network: `buildMirror` takes everything the export needs as a `MirrorInput`
 * gathered by the sweep's mirror step (src/worker/sweep.ts) and answers the
 * files. That is what lets the same layout be built from the outside, over the
 * public API, by `npm run mirror`, and be byte-identical to what the Worker
 * pushed for the same sealed head.
 *
 * Byte-identical is the whole discipline. Two exports of the same sealed head
 * at the same clock must produce the same bytes, or a mirror commit would show a
 * diff on a day nothing happened and nobody could tell a real change from a
 * re-serialization. The clock is part of it because an entry's file carries the
 * derived entry, and `stale` (src/derive.ts) is judged against the day it is
 * read, so a freshness window running out moves that one field by the calendar
 * with nothing sealed having changed.
 * So: every JSON document is `JSON.stringify(value, null, 2)` and one trailing
 * newline, with keys in the order this file constructs them; every `.jsonl` file
 * is one compact document per line in seq order with a trailing newline; and
 * every list is sorted by a key the log itself fixes.
 *
 * Nothing unsealed is ever exported. The mirror is the sealed record: the events
 * are the ones the seals cover, the entries are derived at the sealed head, and
 * an event the log has not committed to has no business in an archive somebody
 * may still be reading in ten years.
 *
 * Everything sealed is exported in full (decision D-127): the record is free
 * from the seal, so every event under a seal is written with its payload, every
 * sealed entry gets its `entries/<id>.json`, and `index.json` carries a row for
 * each with `release_date` naming the seal date the content opened on. A seal
 * file is written once and never rewritten, so the push's changed-blob diff is
 * one commit per seal rather than a rewrite of the log.
 *
 * Three of the families are not read from anywhere at all — they are recomputed
 * here, out of the sealed events, at the sealed head: the attestations
 * (`deriveAttestation`, exactly as `GET /attestations/{id}` folds one), standing
 * (`standingAt`, exactly the body of `GET /standing`), and the ledger rows that
 * are a pure function of the log. Recomputed rather than copied because the
 * point of the mirror is that a fork gets the same answers from the same events:
 * a file taken off a table would be this Worker's word for it, and a file this
 * module derives is something the reader can derive again. The model's answers
 * to a probe set are the one thing in these three that the log does not carry —
 * they are hashed into it, not written into it — so they are the one thing the
 * caller hands over.
 *
 * WebCrypto only (`globalThis.crypto.subtle`), never `node:crypto`, so this runs
 * unchanged on Cloudflare Workers — SHA-1 included, which is here because git
 * names a blob by one and the adapter has to know which files actually changed.
 * A git blob sha is an identity, never a security claim.
 *
 * No policy number lives here. The repository, the branch and the license come
 * from src/policy.ts's MIRROR; the schema and norm versions and the registered
 * domains come from the same file. The one table below — which public origin an
 * environment serves its captures from — is not a policy number and not a rule:
 * it is a fact about where three deployments live, and it is here rather than in
 * src/policy.ts for the same reason no environment name is written into policy.
 */

import { DOMAIN_SLUGS, MIRROR, NORM_VERSION, SCHEMA_VERSION } from "./policy.js";
import { deriveAttestation, type DerivedAttestation } from "./attest.js";
import { bountyAccrual } from "./bounty.js";
import { deriveEntry, type Sidecar } from "./derive.js";
import {
  bountyAccrualRow,
  disputeRewardRow,
  reconciliationRow,
  type LedgerRow,
} from "./ledger.js";
import {
  STANDING_FORMULA,
  standingAt,
  type Standing,
} from "./standing.js";
import {
  disputeOutcomeStakes,
  disputeStake,
  revalidationOutcomeStakes,
  revalidationStake,
  type StakeRecord,
} from "./stake.js";
import type { Anchor } from "./anchor.js";
import type { Event, EventType } from "./events.js";
import type { ProbeAnswer } from "./probe.js";
import type { Entry } from "./schema.js";
import type { Seal } from "./seal.js";

/** What a reader finds in `mirror.json` and checks the directory against. */
export const MIRROR_FORMAT = "nomankind-mirror-v3";

/**
 * Every layout a reader may be handed, oldest first.
 *
 * A mirror is CC0 and already cloned: the copies pushed before the attestations,
 * the standing, the ledger (#58) and the sidecar's source class (#59) joined the
 * export are still somebody's exit, and a verifier that refused them would be
 * taking the exit back. So there are three formats rather than one moving one —
 * `v1` is the seven-item layout as it was, `v2` is the whole sealed log in full,
 * `v3` is what `buildMirror` writes now: the same layout with the release window
 * applied (D-100), which is the first layout in which a seal file can hold a
 * hash line and an entry can have no file yet. Each directory is checked as what
 * it claims to be, and a v2 copy in somebody's hands is still their exit.
 */
export const MIRROR_FORMATS: readonly string[] = Object.freeze([
  "nomankind-mirror-v1",
  "nomankind-mirror-v2",
  MIRROR_FORMAT,
]);

/** Which layout a directory claims, in the word this code reasons in. */
export type MirrorFormat = "v1" | "v2" | "v3";

/** The layout one manifest's `format` names, or null when it names none. */
export function mirrorFormatOf(format: unknown): MirrorFormat | null {
  if (format === MIRROR_FORMATS[0]) return "v1";
  if (format === MIRROR_FORMATS[1]) return "v2";
  if (format === MIRROR_FORMAT) return "v3";
  return null;
}

/**
 * One sidecar as v1 carried it: every key but `source`.
 *
 * The source class is derived from the entry's own citation against the domain's
 * published tables (D-080, #59), so a v1 file simply has no such key and a
 * re-derivation always does. Dropping it from both sides is what "compared on
 * the keys the v1 sidecar carried" means, and it is the only difference the two
 * layouts have inside an entry file.
 */
export function v1Sidecar(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return value;
  }
  const copy = { ...(value as Record<string, unknown>) };
  delete copy["source"];
  return copy;
}

/**
 * The public origin each environment serves from, and so where the captures a
 * mirrored entry names are fetched from.
 *
 * Not policy and not a rule: three deployments, three hostnames. An environment
 * nobody has deployed reads as the local one, which is what an unknown name
 * means on a laptop.
 */
const PUBLIC_ORIGINS: Readonly<Record<string, string>> = Object.freeze({
  demo: "https://demo.nomankind.ai",
  production: "https://app.nomankind.ai",
  local: "http://localhost:8787",
});

/** The origin an environment's mirrored captures are read from. */
function originOf(environment: string): string {
  return PUBLIC_ORIGINS[environment] ?? PUBLIC_ORIGINS["local"]!;
}

/** The code repository the mirror points a forker at. */
const CODE_REPOSITORY = `${MIRROR.web}/nomankind-ai/nomankind`;

/**
 * How wide a seal seq is spelt in an events file name. A format fact, and
 * exported because the offline verifier reads the same names back out of a
 * clone: two spellings of one file name is two layouts.
 */
export const SEAL_SEQ_DIGITS = 8;

/**
 * The layout refused one of its two ways.
 *
 * `no_seal`: there is nothing sealed, so there is no sealed record to export.
 * `gap`: the events handed over do not cover some seal's own range, which means
 * the caller read the log and the seals at two different moments — an export
 * built from that would be missing events a seal commits to, and a verifier
 * would call the mirror broken rather than the read.
 */
export class MirrorError extends Error {
  override readonly name = "MirrorError";
  readonly reason: "no_seal" | "gap";

  constructor(reason: "no_seal" | "gap", detail: string) {
    super(`buildMirror: ${reason}: ${detail}`);
    this.reason = reason;
  }
}

/** One file of the mirror. `path` is relative to the environment's directory. */
export interface MirrorFile {
  readonly path: string;
  readonly content: string;
}

/** One entry as the export carries it, exactly as `GET /sync` produces one. */
export interface MirrorEntryRecord {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly entry_hash: string;
}

/** One operator, with everything the verifier's `Registry` needs plus trusted. */
export interface MirrorOperator {
  readonly operator: string;
  readonly maintainer: boolean;
  readonly provider: boolean;
  readonly trusted: boolean;
  readonly domains: readonly string[];
  readonly agents: readonly string[];
  /**
   * The perimeter the maintainer disclosed when it named this operator into
   * the trusted pool, or null/absent when it named none (decision D-128).
   *
   * In the mirror because the independence page's `validator_perimeters` is
   * computed from it, and a page that could only be checked against the live
   * record would be a page nobody could check. Optional, so a mirror built
   * before the decision reads exactly as it always did.
   */
  readonly perimeter?: string | null;
}

/**
 * What one model actually said, for one attestation.
 *
 * The one input to the three recomputed families that the log does not carry:
 * Section 8 seals "the score and the probe hash", and the answers themselves are
 * hashed into `attestation_answered` and kept beside the record. Null when the
 * model never answered, which is what an open or expired attestation looks like.
 */
export interface MirrorAttestationAnswers {
  readonly attestation: string;
  readonly answers: readonly ProbeAnswer[] | null;
}

/** One attestation file: the derived record, and the answers beside it. */
export interface MirrorAttestationRecord {
  readonly attestation: DerivedAttestation;
  readonly answers: readonly ProbeAnswer[] | null;
}

/** `standing.json`: the body of `GET /standing`, at the sealed head. */
export interface MirrorStanding {
  readonly position: number;
  readonly formula: readonly string[];
  readonly operators: readonly Standing[];
}

/** Everything one export is built from, gathered at one sealed head. */
export interface MirrorInput {
  /** `local`, `demo` or `production`: the directory this export lives under. */
  readonly environment: string;
  /** The instant of the run that made it, which is the injected clock's. */
  readonly exported_at: string;
  /**
   * The instant the release window is judged at, from the same injected clock.
   *
   * Beside `exported_at` rather than read off it, because the two answer
   * different questions -- when this directory was written, and which of the log
   * it was old enough to write in full -- and a caller that meant one of them
   * should have to say which.
   */
  readonly now: string;
  /**
   * The published window, from src/policy.ts, as the manifest records it.
   *
   * Zero since D-127 and frozen there, and still written: it is a column of the
   * mirror format that every reader of a v1, v2 or v3 clone reads, so a clone
   * carries the number it was made under rather than nothing at all.
   */
  readonly release_window_days: number;
  /** Every seal, in seq order. */
  readonly seals: readonly Seal[];
  /** Every anchor, in date order. */
  readonly anchors: readonly Anchor[];
  /** Every sealed event, in seq order. */
  readonly events: readonly Event[];
  /** Every entry at or below the sealed head, derived there. */
  readonly entries: readonly MirrorEntryRecord[];
  /** Every registered operator, in id order. */
  readonly operators: readonly MirrorOperator[];
  /**
   * The model's answers, per attestation the sealed events opened. An
   * attestation the caller hands no entry for is exported with `answers: null`,
   * which is what the log alone can say about it.
   */
  readonly attestations: readonly MirrorAttestationAnswers[];
}

/** One JSON document, in the mirror's own two-space form with a final newline. */
function document(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** One JSONL file: a compact document per line, each line ended. */
function lines(values: readonly unknown[]): string {
  return values.map((value) => `${JSON.stringify(value)}\n`).join("");
}

/**
 * A seal seq, as the events file naming it spells it. Exported for the same
 * reason the width above is: the verifier opens what the export wrote.
 */
export function sealFileName(seq: number): string {
  return `events/${String(seq).padStart(SEAL_SEQ_DIGITS, "0")}.jsonl`;
}

/** A string field off an object, or null when it carries none. */
function text(source: unknown, key: string): string | null {
  if (typeof source !== "object" || source === null) return null;
  const value = (source as Record<string, unknown>)[key];
  return typeof value === "string" ? value : null;
}

/**
 * The newest seal: the one the export is dated and headed by.
 *
 * The newest by seq rather than the last of the list, because a caller that
 * paged the seals out of two reads could hand them over in any order and the
 * head of the mirror must not depend on that.
 */
function newestSeal(seals: readonly Seal[]): Seal {
  let newest: Seal | null = null;
  for (const seal of seals) {
    if (newest === null || seal.seq > newest.seq) newest = seal;
  }
  if (newest === null) throw new MirrorError("no_seal", "the log has no seal");
  return newest;
}

/** Every event by seq, and the refusal when a seal's range is not all there. */
function eventsBySeq(
  events: readonly Event[],
  seals: readonly Seal[],
): Map<number, Event> {
  const bySeq = new Map<number, Event>();
  for (const event of events) bySeq.set(event.seq, event);
  for (const seal of seals) {
    for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
      if (!bySeq.has(seq)) {
        throw new MirrorError(
          "gap",
          `seal ${seal.seq} covers ${seq}, which the events do not carry`,
        );
      }
    }
  }
  return bySeq;
}

/** The position each entry was submitted at, off the sealed events themselves. */
function submissionPositions(events: readonly Event[]): Map<string, number> {
  const positions = new Map<string, number>();
  for (const event of events) {
    if (event.type !== "entry_submitted") continue;
    const id = event.entry_id;
    if (typeof id !== "string") continue;
    // The first submission wins: an id appears once, and a log that somehow
    // carried two would be described by the one the seal chain saw first.
    if (!positions.has(id)) positions.set(id, event.seq);
  }
  return positions;
}

/** The seal covering a position, or null when nothing does. */
function coveringSeal(seals: readonly Seal[], position: number): Seal | null {
  for (const seal of seals) {
    if (position >= seal.first_seq && position <= seal.last_seq) return seal;
  }
  return null;
}

/** One row of `index.json`, in the order the file writes its keys. */
function indexRow(
  record: MirrorEntryRecord,
  position: number,
  sealSeq: number | null,
  releaseDate: string | null,
): Record<string, unknown> {
  const entry = record.entry as unknown as Record<string, unknown>;
  return {
    id: entry["id"],
    // A legacy v0.6 core names no domain and means ai-ecosystem, which is what
    // `domainOf` answers; spelt here off the stored entry for the same reason.
    domain: text(entry, "domain") ?? DEFAULT_DOMAIN_SLUG,
    subject: entry["subject"],
    category: entry["category"],
    status: entry["status"],
    tier: entry["evidence_tier"],
    effective_tier: record.sidecar.effective_tier,
    submitted_at: entry["submitted_at"],
    position,
    seal_seq: sealSeq,
    stale: entry["stale"],
    superseded_by: entry["superseded_by"],
    entry_hash: record.entry_hash,
    // The instant the content opened, which is the seal date (D-127): the
    // column the mirror format has always carried, now equal to the seal.
    release_date: releaseDate,
  };
}

/**
 * The domain a core that names none belongs to.
 *
 * Read off the registered slugs rather than imported as DEFAULT_DOMAIN, so this
 * file names no domain of its own: the first registered slug is ai-ecosystem,
 * which is what a v0.6 core meant when it was the only domain there was.
 */
const DEFAULT_DOMAIN_SLUG = DOMAIN_SLUGS[0]!;

// ---------------------------------------------------------------------------
// The three families the export recomputes rather than reads
// ---------------------------------------------------------------------------

/** Narrow one event to its own type, the way the kernel does it. */
function isType<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/** Events by seq, without mutating the caller's array (as derivation does). */
function inSeqOrder(events: readonly Event[]): Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

/**
 * The four event types one attestation's story is told in, which is the same
 * list `eventsForAttestation` reads by. Named rather than sniffed for the key,
 * because a registration's payload carries an `attestation` of its own and it
 * is a domain attestation, not this one.
 */
const ATTESTATION_EVENT_TYPES: readonly EventType[] = Object.freeze([
  "attestation_requested",
  "attestation_answered",
  "attestation_scored",
  "attestation_expired",
]);

/** The attestation id one of those four events names, or null. */
function attestationOf(event: Event): string | null {
  if (!ATTESTATION_EVENT_TYPES.includes(event.type)) return null;
  const payload = event.payload as unknown;
  if (typeof payload !== "object" || payload === null) return null;
  const id = (payload as Record<string, unknown>)["attestation"];
  return typeof id === "string" ? id : null;
}

/**
 * Every attestation the sealed events opened, folded exactly as
 * `GET /attestations/{id}` folds one.
 *
 * In the order they were requested in, and only the ones whose
 * `attestation_requested` is among these events: an attestation opened above
 * the sealed head is not part of the sealed record, and one whose request is
 * sealed is described by whatever of its story the seals have caught up with —
 * open today, scored tomorrow, and the file says which.
 *
 * `asOf` is the clock the fold is handed. `deriveAttestation` decides nothing
 * with it — an expiry is an event, never a wall clock — and it is passed for the
 * same reason that fold takes one at all.
 */
export function mirrorAttestations(
  events: readonly Event[],
  answers: readonly MirrorAttestationAnswers[],
  asOf: string,
): MirrorAttestationRecord[] {
  const held = new Map<string, readonly ProbeAnswer[] | null>();
  for (const one of answers) held.set(one.attestation, one.answers);

  const byId = new Map<string, Event[]>();
  const opened: string[] = [];
  for (const event of inSeqOrder(events)) {
    const id = attestationOf(event);
    if (id === null) continue;
    const bucket = byId.get(id);
    if (bucket === undefined) byId.set(id, [event]);
    else bucket.push(event);
    // An id is requested once — `attestationId` is a hash of what opened it —
    // so the first request is the one that puts it in the export.
    if (event.type === "attestation_requested" && !opened.includes(id)) {
      opened.push(id);
    }
  }

  return opened.map((id) => ({
    attestation: deriveAttestation(byId.get(id) ?? [], { now: asOf }),
    answers: held.get(id) ?? null,
  }));
}

/**
 * Standing at the sealed head: the body of `GET /standing`, by the published
 * formula, over the sealed events and nothing else.
 *
 * Sorted by operator id rather than by the number, unlike the route. The route
 * is a leaderboard a person reads; this is a file two exports have to agree on
 * byte for byte, and an order that moves when a number moves would rewrite the
 * whole file on a day one validation landed.
 */
export function mirrorStanding(
  events: readonly Event[],
  head: number,
): MirrorStanding {
  const standings = standingAt(events, head);
  return {
    position: head,
    formula: STANDING_FORMULA,
    operators: [...standings.values()].sort((left, right) =>
      left.operator < right.operator ? -1 : left.operator > right.operator ? 1 : 0,
    ),
  };
}

/** The `dispute_filed` an outcome settles, or null when the range holds none. */
function disputeFiling(
  events: readonly Event[],
  entryId: string | null,
  correctionEntryId: string,
): Event<"dispute_filed"> | null {
  if (entryId === null) return null;
  for (const event of events) {
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== entryId) continue;
    if (event.payload.correction_entry_id !== correctionEntryId) continue;
    return event;
  }
  return null;
}

/** The `revalidation_requested` a resolution answers, or null. */
function revalidationRequest(
  events: readonly Event[],
  requestSeq: number,
): Event<"revalidation_requested"> | null {
  for (const event of events) {
    if (!isType(event, "revalidation_requested")) continue;
    if (event.seq !== requestSeq) continue;
    return event.entry_id === null ? null : event;
  }
  return null;
}

/**
 * A stake row as the `ledger` table holds one and `GET /operators/{id}/ledger`
 * serves it: the record itself under `ref`, and the columns beside it.
 *
 * A stake predates `LedgerRow` (decision D-064: a stake was a ledger row before
 * there was any money), so this is the same presentation `toLedgerRow` makes of
 * a stake row read back out of storage: the amount and the unit the record
 * carries, and the record itself under `ref`.
 *
 * Not the dispute reward, which the ledger step prices from the clawbacks of
 * its own event: that one is `disputeRewardRow`'s, here as in the sweep, so the
 * two readings of one log are one row.
 */
function stakeLedgerRow(record: StakeRecord): LedgerRow {
  return {
    id: `${record.kind}:${record.seq}`,
    kind: record.kind,
    entry_id: record.entry_id,
    operator: record.operator,
    role: null,
    date: null,
    reads: null,
    unit: record.unit ?? "standing",
    amount: record.amount ?? 0,
    available_at: null,
    seq: record.seq,
    at: record.at,
    ref: { ...record },
  };
}

/**
 * Every ledger row that is a pure function of the log, recomputed from the
 * sealed events.
 *
 * Section 9: "any operator can reconcile ... against the log". This is that
 * sentence made into a file — one fold over the sealed events in seq order,
 * emitting at each event the rows that event is worth, with src/stake.ts's rows
 * (which the doors write as the event lands) before src/ledger.ts's (which the
 * sweep's ledger step writes afterwards). Read one way: the ledger table is a
 * cache of this, and a row of it that disagrees is wrong.
 *
 * Nothing is priced above zero (D-127), so the reward of an upheld dispute and
 * a reconfirmation's bounty come out here exactly as the ledger step writes
 * them there, down to the `ref`.
 *
 * A day is priced at its own position in the log, and not at the head. The
 * sweep prices a day in the run that published it, so the entry it read is the
 * entry the events up to that `read_count` derive, at that event's own instant
 * — and a slot rotation, a supersession or an expiry that lands afterwards
 * belongs to the days after it. Rederiving every day at `asOf` would hand a
 * verifier holders the entry did not have on the day it was paid for, and the
 * mirror's rows would disagree with the ledger's on the same events, which is
 * exactly the arithmetic Section 9 asks readers to check.
 *
 * `asOf` is the export's own sealed head, kept in the signature because every
 * caller names it beside the seal it exported; no row is derived at it, because
 * no row of this fold belongs to now rather than to the event that produced it.
 */
export function mirrorLedgerRows(
  events: readonly Event[],
  asOf: string,
): LedgerRow[] {
  // Deliberately unread: see the note above. Named rather than dropped so the
  // signature every caller writes stays what it was.
  void asOf;
  const ordered = inSeqOrder(events);
  const rows: LedgerRow[] = [];

  for (let index = 0; index < ordered.length; index += 1) {
    const event = ordered[index]!;
    if (isType(event, "read_count")) {
      // Nothing is priced (D-127): a read is free, so no entry accrues a share
      // of a published day and the day's own reconciliation is the only row it
      // produces. The accrued map is empty for the same reason.
      rows.push(reconciliationRow(event, new Map()));
      continue;
    }

    if (isType(event, "dispute_filed")) {
      if (event.entry_id !== null) rows.push(stakeLedgerRow(disputeStake(event)));
      continue;
    }

    if (isType(event, "dispute_failed")) {
      const filed = disputeFiling(
        ordered,
        event.entry_id,
        event.payload.correction_entry_id,
      );
      if (filed === null) continue;
      for (const stake of disputeOutcomeStakes(filed, event)) {
        rows.push(stakeLedgerRow(stake));
      }
      continue;
    }

    if (isType(event, "dispute_upheld")) {
      // No clawbacks (D-127): nothing accrued on the entry, so the reward the
      // challenger is paid is what those clawbacks come to, which is nothing.
      const clawed: LedgerRow[] = [];
      const filed = disputeFiling(
        ordered,
        event.entry_id,
        event.payload.correction_entry_id,
      );
      if (filed !== null) {
        for (const stake of disputeOutcomeStakes(filed, event)) {
          rows.push(
            stake.kind === "dispute_reward"
              ? disputeRewardRow(stake, clawed)
              : stakeLedgerRow(stake),
          );
        }
      }
      rows.push(...clawed);
      continue;
    }

    if (isType(event, "revalidation_requested")) {
      if (event.entry_id === null) continue;
      const staked = revalidationStake(event);
      if (staked !== null) rows.push(stakeLedgerRow(staked));
      continue;
    }

    if (isType(event, "revalidation_resolved")) {
      const requested = revalidationRequest(ordered, event.payload.request_seq);
      if (requested === null) continue;
      for (const stake of revalidationOutcomeStakes(requested, event)) {
        rows.push(stakeLedgerRow(stake));
      }
      continue;
    }

    if (isType(event, "reconfirmation")) {
      const entryId = event.entry_id;
      if (entryId === null) continue;
      // The entry as it stood BEFORE this reconfirmation, which is what the
      // door measured the bounty against: deriving after the fact would find
      // the window already reopened and would never see a bounty at all.
      let before: { expires_at: string | null; stale: boolean } | null = null;
      try {
        const derived = deriveEntry(
          ordered.filter((one) => one.seq < event.seq),
          entryId,
          { now: event.at },
        );
        before = {
          expires_at: derived.derived.expires_at,
          stale: derived.derived.stale,
        };
      } catch {
        before = null;
      }
      if (before === null) continue;
      const accrual = bountyAccrual(before, event);
      // No pool rows are written any more (D-127), so the bounty an accrual
      // collects is the sum of nothing.
      const row = bountyAccrualRow(event, accrual, []);
      if (row !== null) rows.push(row);
      continue;
    }
  }

  return rows;
}

/**
 * Build one export's files.
 *
 * Sorted by path, so two builds of the same input hand the same list back in the
 * same order and a caller may compare them position by position.
 *
 * Refuses only on malformed input, and in one word each: a log with no seal has
 * no sealed record to mirror, and events that do not cover a seal's own range
 * were read at a different moment from the seals.
 */
export function buildMirror(input: MirrorInput): MirrorFile[] {
  const newest = newestSeal(input.seals);
  const seals = [...input.seals].sort((left, right) => left.seq - right.seq);
  const bySeq = eventsBySeq(input.events, seals);
  const positions = submissionPositions(input.events);

  const files: MirrorFile[] = [];

  // The events, one file per seal, each holding exactly what that seal covers.
  // Immutable once written: a seal's range never moves, so a seal's file never
  // changes and a mirror's history shows one commit per seal rather than one
  // rewrite of the whole log per day.
  for (const seal of seals) {
    const batch: Event[] = [];
    for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
      batch.push(bySeq.get(seq)!);
    }
    files.push({ path: sealFileName(seal.seq), content: lines(batch) });
  }

  // The seals themselves, rewritten as countersignatures arrive: a witness that
  // answers on Tuesday is a fact about a seal made on Monday, and the mirror is
  // the record of the seal rather than of the moment it was first written.
  files.push({ path: "seals.jsonl", content: lines(seals) });

  const anchors = [...input.anchors].sort((left, right) =>
    left.date < right.date ? -1 : left.date > right.date ? 1 : 0,
  );
  files.push({ path: "anchors.jsonl", content: lines(anchors) });

  // Everything the offline verifier's Registry needs, plus trusted, in one file:
  // a forker holding the mirror can build the bundle without asking anybody.
  const operators = [...input.operators].sort((left, right) =>
    left.operator < right.operator ? -1 : left.operator > right.operator ? 1 : 0,
  );
  const agents: Record<string, string> = {};
  for (const operator of operators) {
    for (const agent of [...operator.agents].sort()) {
      agents[agent] = operator.operator;
    }
  }
  files.push({
    path: "operators.json",
    content: document({
      operators: operators.map((operator) => ({
        operator: operator.operator,
        maintainer: operator.maintainer,
        provider: operator.provider,
        trusted: operator.trusted,
        domains: [...operator.domains],
        agents: [...operator.agents].sort(),
        // Written only when one was disclosed, so an operator the maintainer
        // named no grouping for has no key here, exactly as its naming event
        // has none.
        ...(operator.perimeter === null || operator.perimeter === undefined
          ? {}
          : { perimeter: operator.perimeter }),
      })),
      agents,
    }),
  });

  // The entries, one file each, and the index over them in position order. An
  // entry the sealed events carry no submission for is not part of the sealed
  // record and is not exported: the index's `position` is that event's own seq,
  // and there is no honest number to put there without it.
  const indexed: { row: Record<string, unknown>; position: number }[] = [];
  for (const record of input.entries) {
    const id = text(record.entry, "id");
    if (id === null) continue;
    const position = positions.get(id);
    if (position === undefined) continue;
    const covering = coveringSeal(seals, position);
    // The entry's release date is its submission event's covering seal date
    // (D-127). A position nothing covers is not part of the sealed record at
    // all, and the row says so with a null date and no file.
    const releaseDate = covering === null ? null : covering.sealed_at;
    if (releaseDate !== null) {
      files.push({
        path: `entries/${id}.json`,
        content: document({
          entry: record.entry,
          sidecar: record.sidecar,
          entry_hash: record.entry_hash,
        }),
      });
    }
    indexed.push({
      row: indexRow(
        record,
        position,
        covering === null ? null : covering.seq,
        releaseDate,
      ),
      position,
    });
  }
  indexed.sort((left, right) => left.position - right.position);
  files.push({
    path: "index.json",
    content: document(indexed.map((one) => one.row)),
  });

  // The three families nothing is read for: recomputed here, out of the events
  // the seals cover. All three are folds over payloads, and every sealed
  // payload is in this directory (D-127), so a fork that holds the directory
  // gets the same three files out of the same events.
  const releasedEvents: Event[] = [];
  for (const seal of seals) {
    for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
      releasedEvents.push(bySeq.get(seq)!);
    }
  }
  // The position the three families stand at: the sealed head, which is the
  // public head, or the position before the first event when nothing is sealed.
  const released = newest.last_seq;
  const releasedPosition = released;
  const releasedAsOf = newest.sealed_at;

  const attestations = mirrorAttestations(
    releasedEvents,
    input.attestations,
    releasedAsOf,
  );
  for (const record of attestations) {
    files.push({
      path: `attestations/${record.attestation.id}.json`,
      content: document({
        attestation: record.attestation,
        answers: record.answers,
      }),
    });
  }

  files.push({
    path: "standing.json",
    content: document(mirrorStanding(releasedEvents, releasedPosition)),
  });

  const ledger = mirrorLedgerRows(releasedEvents, releasedAsOf);
  files.push({ path: "ledger.jsonl", content: lines(ledger) });

  let eventCount = 0;
  for (const seal of seals) eventCount += seal.last_seq - seal.first_seq + 1;

  files.push({
    path: "mirror.json",
    content: document({
      format: MIRROR_FORMAT,
      environment: input.environment,
      exported_at: input.exported_at,
      as_of: newest.sealed_at,
      head: newest.last_seq,
      seal_seq: newest.seq,
      // The window this directory was built under, frozen at zero (D-127), and
      // the head it made public, which is the sealed head.
      release_window_days: input.release_window_days,
      released_head: released,
      seals: seals.length,
      events: eventCount,
      entries: indexed.length,
      operators: operators.length,
      attestations: attestations.length,
      standing_position: releasedPosition,
      ledger_rows: ledger.length,
      schema_version: SCHEMA_VERSION,
      norm_version: NORM_VERSION,
      domains: [...DOMAIN_SLUGS],
      captures_base: `${originOf(input.environment)}/captures/`,
      code: CODE_REPOSITORY,
      verify: `npm run verify-mirror -- ../log/${input.environment}`,
      license: MIRROR.license,
    }),
  });

  return files.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
}

const encoder = new TextEncoder();

/** Bytes as lowercase hex. */
function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The git blob sha of one file's content: SHA-1 over `blob <bytes>\0` and the
 * bytes, which is what `git hash-object` computes and what the trees API
 * reports for every path.
 *
 * Not a security claim and never used as one — it is how git names a blob, and
 * the only question asked of it is "is this path already exactly these bytes".
 * WebCrypto, like every other digest in the kernel, so this runs on Workers.
 */
export async function gitBlobSha(content: string): Promise<string> {
  const body = encoder.encode(content);
  const header = encoder.encode(`blob ${body.byteLength}\0`);
  const bytes = new Uint8Array(header.byteLength + body.byteLength);
  bytes.set(header, 0);
  bytes.set(body, header.byteLength);
  return hex(await globalThis.crypto.subtle.digest("SHA-1", bytes));
}

/**
 * The files that are not already in the repository as they stand.
 *
 * `existing` is the blob sha per path, keyed exactly as `files[].path` is — the
 * adapter strips its own prefix before asking, because this function knows
 * nothing about where in a repository the directory sits. A path the map does
 * not hold has never been written; a path whose sha differs has changed. An
 * export that changed nothing answers an empty list, which is what lets a quiet
 * day cost no commit at all.
 */
export async function mirrorDiff(
  files: readonly MirrorFile[],
  existing: ReadonlyMap<string, string>,
): Promise<MirrorFile[]> {
  const changed: MirrorFile[] = [];
  for (const file of files) {
    const held = existing.get(file.path);
    if (held !== undefined && held === (await gitBlobSha(file.content))) continue;
    changed.push(file);
  }
  return changed;
}

/**
 * The paths already in the repository under this export's directory that this
 * export does not write.
 *
 * A file the layout stopped producing — an entry that left the release window,
 * a format that was renamed — stayed in the repository forever, because a push
 * that only writes what changed never says that something is gone. The mirror is
 * the sealed record and a stale file in it is a claim the log does not make, so
 * the push deletes these. Sorted, so two pushes of one state produce one tree.
 *
 * `existing` is keyed relative to the export's directory, exactly as
 * `mirrorDiff` asks, so nothing outside that directory can be named here.
 */
export function mirrorDropped(
  files: readonly MirrorFile[],
  existing: ReadonlyMap<string, string>,
): string[] {
  const written = new Set(files.map((file) => file.path));
  return [...existing.keys()].filter((path) => !written.has(path)).sort();
}

/**
 * Where one export can be read: the repository tree at the commit that wrote it,
 * and the raw `mirror.json` beside it.
 *
 * Both are pinned to the commit rather than to the branch, so a link recorded
 * today still shows what was exported today after a hundred later exports.
 */
export function mirrorUrls(
  commit: string,
  prefix: string,
): { url: string; raw_url: string } {
  return {
    url: `${MIRROR.web}/${MIRROR.repository}/tree/${commit}/${prefix}`,
    raw_url: `${MIRROR.raw}/${MIRROR.repository}/${commit}/${prefix}/mirror.json`,
  };
}

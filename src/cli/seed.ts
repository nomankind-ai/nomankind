/**
 * seed: the quotation rule, as a batch (M25e, decision D-128 item 3).
 *
 * Whitepaper, "What verified means": a validator approves only what its own
 * fetch reproduces. A quotation entry is the smallest claim that rule can carry
 * — the claim IS a passage of the cited page, word for word — so an entry the
 * seeder builds is one a validator can decide from its own capture and nothing
 * else. This command is the author's half of that: one fields file per source
 * row, the row's span as the claim, submitted through the same door `npm run
 * submit` posts to.
 *
 * The one judgment made here is the one that keeps the rule honest: the span
 * must be in the tool's own capture of the citation, verbatim. "Verbatim" is
 * the norm rule's word and not a looser one of this file's — the capture is
 * taken with the validator's own `fetchAndHash`, which is the norm rule's
 * extraction and normalization, and the span is put through the same
 * `normalizeText` before it is looked for, so the two sides are compared in one
 * spelling and in exactly one. A paraphrase is not a near miss to be waved
 * through; it is a row this tool refuses, `span_not_in_capture`, because an
 * entry whose claim the page does not say is an entry no validator could ever
 * approve and the seeder would only be spending the log's attention on it.
 *
 * The citation is captured twice per row: once here for the span check, and
 * once inside `runSubmit`, whose capture is the `snapshot_hash` the author
 * signs. That is deliberate rather than an oversight — the submitted hash must
 * be the one the submit path took, because the door compares its own fetch
 * against exactly that — and a page that changes between the two is a page the
 * door refuses `snapshot_mismatch`, or that the quotation validator rejects,
 * which is the rule working rather than a gap in it.
 *
 * Nothing here decides a cap. `CORE_TEXT_MAX_CHARS` is read from policy and the
 * refusal is the door's own word, `core_too_large`, so a span too long to keep
 * forever is refused before it is fetched rather than after it is posted. The
 * daily write cap is the door's alone: the first refusal stops the run, and the
 * run says how many rows are left so the operator knows what a second run has
 * to pick up — and ends 0 when it had filed rows first, because meeting the
 * record's own cap is the run finishing the day's share of a list rather than
 * failing at it. The log is one JSON line per row, appended, so two runs over
 * the same list read as one history.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives the whole batch in process against
 * handleRequest with no network at all. `main` is thin. A private key is never
 * printed. node:fs and node:path are allowed in this CLI file only.
 */

import { appendFile, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { WebFetcher } from "../adapters/fetch.js";
import { DUPLICATE_REFUSALS, LIVE_STATUSES } from "../duplicate.js";
import { hashText, normalizeText } from "../normalize.js";
import {
  CORE_TEXT_MAX_CHARS,
  SEED_DUPLICATES_BEFORE_STOP,
  SEED_HELD_CLAIMS_MAX,
  SEED_READ_PAGES_MAX,
} from "../policy.js";
import { runCommand } from "./main.js";
import { runSubmit, type SubmitDeps } from "./submit.js";
import {
  containsSpan,
  fetchAndHash,
  getJson,
  readKeyFile,
  reasonOf,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

/** The usage line, and the one rule it cannot show. */
export const USAGE = [
  "usage: seed <key.json> <base-url> <sources.json>",
  "            [--dry-run] [--out <dir>] [--limit <n>]",
  "a row whose span is not in the tool's own capture, verbatim, is refused",
].join("\n");

/** The refusal a row earns when the page does not say what the row quotes. */
export const SPAN_NOT_IN_CAPTURE = "span_not_in_capture";

/** The refusal a sources file that is not a list of rows earns, before any I/O. */
export const BAD_SOURCES = "bad_sources";

/** The door's own word for a core field longer than the published ceiling. */
export const CORE_TOO_LARGE = "core_too_large";

/**
 * The door's own word for the day's writes being spent (src/worker/registry.ts).
 *
 * Named here because it is the one refusal that ends a run without failing it.
 * The cap is the record's, the run met it, and the rows before it are in the
 * log: a list longer than a day's writes is finished by running it again
 * tomorrow, which is what the tool is for. The workflow that runs it nightly
 * has said so in its own comment since it was written — "a refused row and a
 * run that met the write cap are both results, not failures" — and on
 * 2026-09-19 a run that filed ten rows and then met the cap reported a failed
 * conclusion anyway, which is an alert about the tool working.
 */
export const WRITE_QUOTA = "write_quota";

/** The name of the log, in the directory the run writes it to. */
export const SEED_LOG_NAME = "seed-log.jsonl";

/** A row the record already holds: not filed again, and not a refusal either. */
export const ALREADY_FILED = "already_filed";

/**
 * One row of the source list.
 *
 * `note` is the maintainer's own working note about why the row is on the list.
 * It is never submitted: it is not one of the author's fields and an entry
 * carrying it would be refused `bad_fields` by the submit path, which is the
 * check this file leans on rather than repeating.
 *
 * `before`, `after` and `effective_at` are the three core fields a quotation
 * row does not state and a core cannot be built without. A row may name them;
 * a row that does not gets the defaults below, which say only what the capture
 * itself supports.
 */
export interface SeedRow {
  readonly subject: string;
  readonly category: string;
  readonly citation: string;
  readonly span: string;
  readonly domain: string;
  readonly note?: string;
  readonly before?: string;
  readonly after?: string;
  readonly effective_at?: string;
}

/** The row's keys this tool reads. Anything else is a mistake, not a comment. */
const ROW_KEYS: readonly string[] = Object.freeze([
  "subject",
  "category",
  "citation",
  "span",
  "domain",
  "note",
  "before",
  "after",
  "effective_at",
]);

/** The keys with no default: a row is not a row without them. */
const REQUIRED_ROW_KEYS: readonly string[] = Object.freeze([
  "subject",
  "category",
  "citation",
  "span",
  "domain",
]);

/** The source list, read: rows as they stand, or the reason it is not one. */
export type SourcesVerdict =
  | { ok: true; rows: readonly SeedRow[] }
  | { ok: false; reason: string; detail: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Read a sources file as a list of rows, or refuse it.
 *
 * Pure and run before anything is fetched: a list this tool cannot read is a
 * mistake about the file, and answering it after twenty captures would be the
 * same message twenty fetches later.
 */
export function checkSources(value: unknown): SourcesVerdict {
  if (!Array.isArray(value)) {
    return { ok: false, reason: BAD_SOURCES, detail: "not a JSON array" };
  }
  for (const [index, row] of value.entries()) {
    if (!isRecord(row)) {
      return { ok: false, reason: BAD_SOURCES, detail: `row ${index}: not an object` };
    }
    const unknown = Object.keys(row).filter((key) => !ROW_KEYS.includes(key));
    if (unknown.length > 0) {
      return {
        ok: false,
        reason: BAD_SOURCES,
        detail: `row ${index}: not a source row's: ${unknown.join(", ")}`,
      };
    }
    const missing = ROW_KEYS.filter(
      (key) =>
        row[key] !== undefined
          ? typeof row[key] !== "string"
          : REQUIRED_ROW_KEYS.includes(key),
    );
    if (missing.length > 0) {
      return {
        ok: false,
        reason: BAD_SOURCES,
        detail: `row ${index}: missing or not a string: ${missing.join(", ")}`,
      };
    }
  }
  return { ok: true, rows: value as readonly SeedRow[] };
}

/**
 * The fields file one row builds: the row's own fields, the span as the claim
 * exactly, and the three the row leaves to the tool.
 *
 * The defaults say what the capture supports and nothing more. What the page
 * said before is not something this tool captured, so the `before` says so in
 * those words rather than asserting an absence nobody checked. `effective_at`
 * is the day the capture was taken, for the same reason the checkpoint's seeded
 * entry uses its own day: it is the one date the run actually knows.
 *
 * `after` is the span, like the claim, and that is load-bearing rather than
 * tidy. The duplicate key (decision D-085, src/duplicate.ts) is the domain, the
 * subject, the category, the normalized `after` and the effective date — it
 * reads `after` and nothing else of what the entry asserts. A constant sentence
 * there, which is what this tool used to write, gave every quotation from one
 * page one key: the first row of a list filed, and the second was refused
 * `duplicate_claim` however different its passage. Today's first real run on
 * demo showed exactly that, filing row 0 and stopping on row 1.
 *
 * Making the state after the change the passage itself is the honest reading as
 * well as the working one. A quotation entry asserts that this page carries
 * this passage, so the passage is the state it asserts; two different passages
 * are two different assertions, and the same passage filed twice is the one
 * thing the duplicate rule should still catch. The fix belongs here and not in
 * the key: a key that ignored `after` would stop catching real duplicates.
 */
export function fieldsForRow(row: SeedRow, now: Date): Record<string, unknown> {
  return {
    subject: row.subject,
    category: row.category,
    domain: row.domain,
    claim: row.span,
    before: row.before ?? "not recorded in nomankind",
    after: row.after ?? row.span,
    effective_at: row.effective_at ?? now.toISOString().slice(0, 10),
    citation: row.citation,
  };
}

// ---------------------------------------------------------------------------
// What the record already holds
// ---------------------------------------------------------------------------

/**
 * The claims the record already holds for the subjects on a list, by subject.
 *
 * The key is the subject and the normalized claim with a newline between them.
 * A newline cannot survive `normalizeText`, which folds every run of whitespace
 * to one space, so the two halves of the key can never run into each other.
 * The value is the entry id, which is what the run's log prints so a reader can
 * go and look at the entry a row was skipped for.
 */
export type HeldClaims = ReadonlyMap<string, string>;

/** The key one subject and one claim are held under. */
export function heldKey(subject: string, claim: string): string {
  return `${subject}\n${normalizeText(claim)}`;
}

/** One entry's claim off the entry door, or null when it did not answer. */
async function claimOf(
  http: HttpClient,
  baseUrl: string,
  id: string,
): Promise<string | null> {
  try {
    const answer = await getJson(http, baseUrl, `/entries/${encodeURIComponent(id)}`);
    if (answer.status !== 200 || !isRecord(answer.body)) return null;
    const claim = answer.body["claim"];
    return typeof claim === "string" && claim !== "" ? claim : null;
  } catch {
    return null;
  }
}

/**
 * Read what the record already holds for these subjects, through the free
 * read doors and before a single write is spent.
 *
 * The reason this exists is the shape of the door: a submission is charged
 * against the day's write cap before the duplicate rule is checked, so a row
 * the record already holds costs a write to be told so. A re-run over a list of
 * which ten rows are filed would spend ten writes learning nothing. Reads are
 * free and uncapped by comparison, so the run reads first.
 *
 * The listing has no subject filter — `parseEntriesQuery` (src/ui/query.ts)
 * takes category, status, domain, tier, source, the two floors and freshness,
 * and refuses a parameter it does not know — so the narrowing is done here,
 * over the pages the listing answers newest first. That is the right shape
 * anyway: the entries a seeder is about to collide with are the ones it filed
 * on an earlier run, which are the newest ones there are.
 *
 * The listing says what an entry is and not what it says (src/worker/pages.ts),
 * so a claim is one read of the entry door apiece, and only for the rows whose
 * subject is on this list. Both walks are bounded — `SEED_READ_PAGES_MAX`
 * pages and `SEED_HELD_CLAIMS_MAX` claims — and what falls outside the bound is
 * caught by the duplicate refusal itself, which the run steps over and counts.
 *
 * Only the live statuses (`LIVE_STATUSES`, src/duplicate.ts): after a rejection
 * or a supersession the claim may be filed again, which is the duplicate rule's
 * own reading and must not be a second one here.
 */
export async function readHeldClaims(
  http: HttpClient,
  baseUrl: string,
  subjects: ReadonlySet<string>,
): Promise<HeldClaims> {
  const held = new Map<string, string>();
  if (subjects.size === 0) return held;

  for (const status of LIVE_STATUSES) {
    let query = `status=${encodeURIComponent(status)}`;
    for (let page = 0; page < SEED_READ_PAGES_MAX; page += 1) {
      let answer;
      try {
        answer = await getJson(http, baseUrl, `/entries?${query}`);
      } catch {
        break;
      }
      if (answer.status !== 200 || !isRecord(answer.body)) break;
      const rows = answer.body["entries"];
      if (!Array.isArray(rows)) break;

      for (const row of rows) {
        if (!isRecord(row)) continue;
        const subject = row["subject"];
        const id = row["id"];
        if (typeof subject !== "string" || typeof id !== "string") continue;
        if (!subjects.has(subject)) continue;
        if (held.size >= SEED_HELD_CLAIMS_MAX) break;
        const claim = await claimOf(http, baseUrl, id);
        if (claim === null) continue;
        held.set(heldKey(subject, claim), id);
      }

      const next = answer.body["next"];
      if (next === null || next === undefined || next === "") break;
      if (held.size >= SEED_HELD_CLAIMS_MAX) break;
      query =
        `status=${encodeURIComponent(status)}` +
        `&before=${encodeURIComponent(String(next))}`;
    }
  }
  return held;
}

/** What one row came to. The log line carries exactly this, and the index. */
export type RowOutcome =
  | { readonly result: "submitted"; readonly entry_id: string }
  | { readonly result: "checked" }
  | {
      /**
       * The record already holds this claim, so nothing was sent. Not a
       * refusal: the row's work is done, and a run of them is a list being
       * finished rather than a list going wrong.
       */
      readonly result: "skipped";
      readonly reason: string;
      readonly entry_id?: string;
    }
  | {
      readonly result: "refused";
      readonly reason: string;
      readonly detail?: string;
      readonly status?: number;
    };

/** One row's line of the seed log. */
export interface SeedLogLine {
  readonly row: number;
  readonly subject: string;
  readonly citation: string;
  readonly span_hash: string;
  readonly outcome: RowOutcome;
}

/** What one seeding run did. `code` is the exit code the CLI reports. */
export interface SeedRun {
  /** Every row the run reached was submitted, or checked under --dry-run. */
  readonly ok: boolean;
  /**
   * 0 when every row passed and 0 when the day's write cap ended a run that
   * had filed rows; 1 on any other refusal; 2 on a file this tool cannot read.
   */
  readonly code: 0 | 1 | 2;
  readonly submitted: number;
  readonly checked: number;
  readonly refused: number;
  /**
   * The rows the record already held, which cost nothing and are not failures:
   * a re-run over a half-filled list is a list being finished.
   */
  readonly skipped: number;
  /** The rows the run never reached: the door stopped it, or --limit did. */
  readonly remaining: number;
  /** The door's refusal that stopped the run, or null when none did. */
  readonly stopped: string | null;
  /** One line per row the run reached, in order, as the log holds them. */
  readonly log: readonly SeedLogLine[];
}

/** Everything a run needs besides its arguments. All of it injected. */
export type SeedDeps = SubmitDeps;

/**
 * Seed one list: capture, check the span, build, validate and submit each row.
 *
 * The order per row is the order of what a refusal costs: the row's own shape
 * and the published text ceiling first, which cost nothing; then one capture,
 * which costs a fetch; then the submission, which costs the log a row. A row
 * refused at any of the first two is recorded and the run moves on, because one
 * bad row on a list of twenty is a fact about that row. A refusal from the door
 * stops the run, because the door's refusals are about the key and the day — the
 * daily write cap, `rate_limited`, above all — and nineteen more submissions
 * would earn nineteen more copies of the same 429.
 *
 * With one exception, `duplicate_claim`, which is a door refusal about the row:
 * this claim is already in the log, which says nothing about the next row. It
 * is counted as a refusal, logged like any other, and the run carries on — so
 * running the same list again after a partial run finishes the list rather than
 * stopping on its first already-filed row.
 *
 * Carrying on is the second line of defence and not the first, because it is
 * not free: the door charges a write before it checks the duplicate rule, so
 * every refusal stepped over costs one of the day's writes. The first line is
 * the read above the loop — what the record already holds for these subjects,
 * bought with free reads — and a row found there is skipped before a capture is
 * fetched or a write is spent. What that read missed still meets the refusal,
 * and `SEED_DUPLICATES_BEFORE_STOP` in a row ends the run: duplicates arriving
 * one after another mean the read missed something systematically, and the
 * answer to that is to stop and look rather than to spend the day finding out.
 */
export async function runSeed(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly rows: readonly SeedRow[];
  readonly dryRun?: boolean;
  /** At most this many rows; the rest are left for a later run. */
  readonly limit?: number | null;
  readonly deps: SeedDeps;
}): Promise<SeedRun> {
  const { deps } = input;
  const limit = input.limit ?? null;
  const reach =
    limit === null ? input.rows.length : Math.min(limit, input.rows.length);

  // What the record already holds for the subjects this run will reach, read
  // before anything is written. Only the rows within reach: a list of a hundred
  // run with --limit 10 asks about the ten subjects it will actually touch.
  const held = await readHeldClaims(
    deps.http,
    input.baseUrl,
    new Set(input.rows.slice(0, reach).map((row) => row.subject)),
  );
  if (held.size > 0) {
    deps.io.stdout(`the record already holds ${held.size} of these claims`);
  }

  const log: SeedLogLine[] = [];
  let submitted = 0;
  let checked = 0;
  let refused = 0;
  let skipped = 0;
  let duplicatesInARow = 0;
  let stopped: string | null = null;
  let index = 0;

  for (; index < reach; index += 1) {
    const row = input.rows[index]!;
    const span = normalizeText(row.span);
    const spanHash = await hashText(span);
    const line = (outcome: RowOutcome): void => {
      log.push({
        row: index,
        subject: row.subject,
        citation: row.citation,
        span_hash: spanHash,
        outcome,
      });
      deps.io.stdout(
        `row ${index} ${row.subject} ${outcome.result}` +
          ("entry_id" in outcome ? ` ${outcome.entry_id}` : "") +
          ("reason" in outcome ? ` ${outcome.reason}` : ""),
      );
    };

    // The published ceiling on a signed text field, before anything is
    // fetched: the door refuses a longer claim `core_too_large` and names the
    // field, and a capture taken first would be a capture taken for nothing.
    if (row.span.length > CORE_TEXT_MAX_CHARS) {
      refused += 1;
      line({ result: "refused", reason: CORE_TOO_LARGE, detail: "claim" });
      continue;
    }

    // What the record already holds is not filed again, and the skip comes
    // before the capture: a row whose work is done should cost this run neither
    // a fetch nor a write. The entry id is printed so a reader of the log can
    // go and look at the entry that made the decision.
    const alreadyFiled = held.get(heldKey(row.subject, row.span));
    if (alreadyFiled !== undefined) {
      skipped += 1;
      line({ result: "skipped", reason: ALREADY_FILED, entry_id: alreadyFiled });
      continue;
    }

    // The validator's own capture, through the validator's own code path.
    const captured = await fetchAndHash(deps.fetcher, row.citation);
    if (!captured.ok) {
      refused += 1;
      line({ result: "refused", reason: captured.reason });
      continue;
    }
    if (!containsSpan(captured.snapshot, row.span)) {
      refused += 1;
      line({ result: "refused", reason: SPAN_NOT_IN_CAPTURE });
      continue;
    }

    if (input.dryRun === true) {
      checked += 1;
      line({ result: "checked" });
      continue;
    }

    const run = await runSubmit({
      key: input.key,
      baseUrl: input.baseUrl,
      fields: fieldsForRow(row, deps.now),
      deps,
    });
    if (run.ok && run.entryId !== null) {
      submitted += 1;
      // A row that went in is evidence the run's picture of the record is good
      // enough, so the count of duplicates in a row starts again from here.
      duplicatesInARow = 0;
      line({ result: "submitted", entry_id: run.entryId });
      continue;
    }

    refused += 1;
    const reason = run.error ?? "unknown_error";
    line({
      result: "refused",
      reason,
      ...(run.status === null ? {} : { status: run.status }),
    });
    // A refusal the door made is about this key and this day -- the daily write
    // cap, `rate_limited` (src/keys.ts), above all -- so the run stops and says
    // what is left: nineteen more submissions would earn nineteen more copies
    // of the same 429. A refusal the submit path made for itself, before the
    // door was asked, is about this row alone and the next row is still worth
    // trying.
    //
    // `duplicate_claim` is the one door refusal that is about the row rather
    // than about the key or the day: it says this exact claim is already in the
    // log, which is true of that row and says nothing about the next one. A
    // re-run over a list whose first row was filed yesterday used to stall on
    // it forever, which made the tool unusable for the thing it is for —
    // running the same list again until the whole of it is in.
    //
    // It is stepped over and not ignored. Each one spent a write, because the
    // door charges before it checks, so `SEED_DUPLICATES_BEFORE_STOP` of them
    // in a row ends the run: that many together is the read above the loop
    // having missed something rather than one unlucky row, and carrying on
    // would spend the day's cap proving it.
    if (DUPLICATE_REFUSALS.includes(reason)) {
      duplicatesInARow += 1;
      if (duplicatesInARow >= SEED_DUPLICATES_BEFORE_STOP) {
        stopped = reason;
        index += 1;
        break;
      }
      continue;
    }
    if (run.status !== null) {
      stopped = reason;
      index += 1;
      break;
    }
  }

  const remaining = input.rows.length - index;
  if (stopped !== null) {
    deps.io.stderr(`seed: stopped at ${stopped}, ${remaining} rows remain`);
  } else if (remaining > 0) {
    deps.io.stdout(`${remaining} rows remain`);
  }

  if (skipped > 0) {
    deps.io.stdout(`${skipped} rows the record already held were not filed again`);
  }

  // A skipped row is not a failure and does not colour the exit code: a run
  // over a list the record already holds in full did everything asked of it.
  //
  // Nor is the day's write cap, once rows are in. `ok` stays false — a row the
  // run reached was refused, and that is what `ok` is about — but the exit code
  // is the run's own verdict on itself, and a run that filed what the day had
  // room for and stopped where the record told it to stop did the thing it was
  // asked to do. Its list is finished by running it again tomorrow. One
  // refusal and no other, because a quota reached after a row was refused for
  // its own reasons is still a run with a bad row in it, and that row is the
  // fact worth an alert; the rows filed are counted too, so a run that met the
  // cap having written nothing is a key with no writes left and is a failure to
  // say so.
  const quotaOnly = stopped === WRITE_QUOTA && refused === 1 && submitted > 0;
  return {
    ok: stopped === null && refused === 0,
    code: (stopped === null && refused === 0) || quotaOnly ? 0 : 1,
    submitted,
    checked,
    refused,
    skipped,
    remaining,
    stopped,
    log,
  };
}

/** One seed log line, as the file holds it: one JSON object, one line. */
export function seedLogText(lines: readonly SeedLogLine[]): string {
  return lines.map((line) => JSON.stringify(line)).join("\n") + "\n";
}

/** Where the log is written: the named directory, or beside the source list. */
export function seedLogPath(sourcesPath: string, out: string | null): string {
  return join(out ?? dirname(resolve(sourcesPath)), SEED_LOG_NAME);
}

/** One command line, read. */
export interface SeedArgs {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly sourcesPath: string;
  readonly dryRun: boolean;
  readonly out: string | null;
  readonly limit: number | null;
}

/** A count written the one way a count is written: plain decimal, no padding. */
const COUNT = /^(?:0|[1-9][0-9]*)$/;

/**
 * Read the arguments, or answer null for the usage line and exit 2.
 *
 * `--limit` is checked here rather than at the first row: a run told to seed
 * `ten` rows and quietly given all of them is a run that seeded a list nobody
 * asked for.
 */
export function parseSeedArgs(args: readonly string[]): SeedArgs | null {
  const positional: string[] = [];
  let dryRun = false;
  let out: string | null = null;
  let limit: number | null = null;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--dry-run") {
      dryRun = true;
    } else if (argument === "--out") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) return null;
      out = value;
      index += 1;
    } else if (argument === "--limit") {
      const value = args[index + 1];
      if (value === undefined || !COUNT.test(value)) return null;
      if (!Number.isSafeInteger(Number(value))) return null;
      limit = Number(value);
      index += 1;
    } else if (argument.startsWith("--")) {
      return null;
    } else {
      positional.push(argument);
    }
  }

  const [keyPath, baseUrl, sourcesPath] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    sourcesPath === undefined ||
    positional.length > 3
  ) {
    return null;
  }
  return { keyPath, baseUrl, sourcesPath, dryRun, out, limit };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const parsed = parseSeedArgs(process.argv.slice(2));
  if (parsed === null) {
    console.error(USAGE);
    process.exit(2);
  }
  const { keyPath, baseUrl, sourcesPath, dryRun, out, limit } = parsed;

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };

  let sources: unknown;
  try {
    sources = JSON.parse(await readFile(resolve(sourcesPath), "utf8"));
  } catch (error) {
    io.stderr(`${sourcesPath}: ${reasonOf(error)}`);
    process.exit(2);
  }
  const rows = checkSources(sources);
  if (!rows.ok) {
    io.stderr(`${rows.reason}: ${rows.detail}`);
    process.exit(2);
  }

  process.exit(
    await runCommand({ name: "seed", baseUrl, io }, async () => {
      const run = await runSeed({
        key: await readKeyFile(keyPath),
        baseUrl,
        rows: rows.rows,
        dryRun,
        limit,
        deps: {
          http: new WebHttpClient(),
          fetcher: new WebFetcher(),
          now: new Date(),
          io,
        },
      });
      if (run.log.length > 0) {
        const path = seedLogPath(sourcesPath, out);
        await appendFile(path, seedLogText(run.log), "utf8");
        io.stdout(`seed log ${path}`);
      }
      return run.code;
    }),
  );
}
/* c8 ignore stop */

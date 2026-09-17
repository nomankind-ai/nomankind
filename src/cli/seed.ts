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
 * to pick up. The log is one JSON line per row, appended, so two runs over the
 * same list read as one history.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives the whole batch in process against
 * handleRequest with no network at all. `main` is thin. A private key is never
 * printed. node:fs and node:path are allowed in this CLI file only.
 */

import { appendFile, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { WebFetcher } from "../adapters/fetch.js";
import { hashText, normalizeText } from "../normalize.js";
import { CORE_TEXT_MAX_CHARS } from "../policy.js";
import { runCommand } from "./main.js";
import { runSubmit, type SubmitDeps } from "./submit.js";
import {
  containsSpan,
  fetchAndHash,
  readKeyFile,
  reasonOf,
  WebHttpClient,
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

/** The name of the log, in the directory the run writes it to. */
export const SEED_LOG_NAME = "seed-log.jsonl";

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
 * The defaults say what the capture supports and nothing more. A quotation
 * entry records that the cited page carries this passage; what the page said
 * before is not something this tool captured, so the `before` says so in those
 * words rather than asserting an absence nobody checked. `effective_at` is the
 * day the capture was taken, for the same reason the checkpoint's seeded entry
 * uses its own day: it is the one date the run actually knows.
 */
export function fieldsForRow(row: SeedRow, now: Date): Record<string, unknown> {
  return {
    subject: row.subject,
    category: row.category,
    domain: row.domain,
    claim: row.span,
    before: row.before ?? "not recorded in nomankind",
    after: row.after ?? "the cited page carries this passage verbatim",
    effective_at: row.effective_at ?? now.toISOString().slice(0, 10),
    citation: row.citation,
  };
}

/** What one row came to. The log line carries exactly this, and the index. */
export type RowOutcome =
  | { readonly result: "submitted"; readonly entry_id: string }
  | { readonly result: "checked" }
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
  /** 0 when every row passed, 1 on a refusal, 2 on a file this tool cannot read. */
  readonly code: 0 | 1 | 2;
  readonly submitted: number;
  readonly checked: number;
  readonly refused: number;
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
 * daily write cap above all — and nineteen more submissions would earn nineteen
 * more copies of the same 429.
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

  const log: SeedLogLine[] = [];
  let submitted = 0;
  let checked = 0;
  let refused = 0;
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
    // cap above all -- so the run stops and says what is left. A refusal the
    // submit path made for itself, before the door was asked, is about this row
    // alone and the next row is still worth trying.
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

  return {
    ok: stopped === null && refused === 0,
    code: stopped === null && refused === 0 ? 0 : 1,
    submitted,
    checked,
    refused,
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

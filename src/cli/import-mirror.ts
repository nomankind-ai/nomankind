/**
 * import-mirror: a fork keeps going with the record.
 *
 * Whitepaper Section 11 and the Conclusion: the log goes out daily under CC0 so
 * that nomankind going away is an inconvenience rather than an ending, and "the
 * exit is not a promise, it is a copy". `npm run verify-mirror` says the copy is
 * real; this command is what makes it an exit. It replays one environment's
 * mirror directory into a local D1 database, so `npm run dev` then serves that
 * record as its own log and the sweep goes on sealing from the imported head.
 *
 * Six rules, and every one of them is about not being trusted.
 *
 * 1. Nothing is written until the directory has passed exactly the checks
 *    `npm run verify-mirror` makes — its own functions, not a second copy of
 *    them — so an import can never accept bytes the verifier would refuse.
 *    `--force` is not an escape from that; it only allows a non-empty database.
 * 2. The events go in through the repository's `appendEvents`, under the chain
 *    rule every door writes under: seq by seq onto the stored head, prev_hash
 *    against the stored hash, and the first event onto nothing.
 * 3. Nothing derived is copied. The registry rows are folded out of the events
 *    (src/import.ts) and held against `operators.json`; every entry is
 *    re-derived by the kernel over the events that were just imported, at the
 *    sealed head, and compared with the mirror's own file — a difference is a
 *    refusal before a single entry row is written. Only the seals, the anchors
 *    and the model's answers are stored as they stand, because a signature, an
 *    external timestamp and a thing a model said are not functions of the log.
 * 4. Every write is one of the repository's own atomic batches. There is no
 *    resume: a failure part way leaves a database the command names and the
 *    reader drops, which on a laptop is a directory.
 * 5. A database with any event in it is refused unless `--force`, and `--force`
 *    still refuses a stored head that is not a prefix of the mirror — same
 *    events, same hashes — and otherwise imports only what is after it, so a
 *    fork catches up from a newer export instead of starting again.
 * 6. Exit 0 with one summary line, 1 with the named refusal, 2 on usage. Never
 *    a stack trace: a mirror is a stranger's directory.
 *
 * What is rebuilt here and what the first sweep rebuilds. Here: the events, the
 * registry rows, the entries, the seals, the anchors, the attestations with
 * their scorers and answers, every ledger row that is a pure function of the log
 * (src/mirror.ts's `mirrorLedgerRows`, which is what `ledger.jsonl` is), and the
 * standing columns (`mirrorStanding`, which is what `standing.json` is) — with
 * the ledger cursor and the standing position set to the imported head, so the
 * next sweep continues rather than re-emitting. Left for the sweep: the
 * assignments, the mirror rows, the sweep steps and the read receipts, none of
 * which the mirror carries and all of which the next runs make for themselves.
 * Not rebuilt by anyone, and it is not a gap: the payout references, which
 * belong to a payment provider rather than to the log, so a fork onboards its
 * own operators before it pays any.
 *
 * `importMirror` takes a database, so the tests and the end-to-end proof drive
 * it in process with no child process; the command below is a thin wrapper that
 * opens the local database wrangler dev uses, through `getPlatformProxy` on the
 * top-level environment, and applies the migrations first.
 *
 * node:fs and node:path are allowed in this CLI file only; everything it hands
 * the work to stays Workers-safe.
 */

import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { extractCore } from "../core.js";
import { deriveEntry } from "../derive.js";
import { entryHash } from "../hash.js";
import {
  ImportRefusal,
  firstDifference,
  headRelation,
  importPlan,
  readLayout,
  type ImportPlan,
  type MirrorLayout,
  type StoredEvent,
} from "../import.js";
import {
  mirrorAttestations,
  mirrorLedgerRows,
  mirrorStanding,
  v1Sidecar,
  type MirrorFormat,
} from "../mirror.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { Entry } from "../schema.js";
import { sealsForEntries } from "../seal.js";
import type { D1Like } from "../storage/d1.js";
import { applyMigrations, migrationsInOrder } from "../storage/migrate.js";
import {
  appendEvents,
  eventsInRange,
  headSeq,
  putAnchor,
  putAgent,
  putAttestation,
  putEntry,
  putLedgerRows,
  putOperator,
  putOperatorDomain,
  putSeal,
  setLedgerCursor,
  setOperatorStanding,
} from "../storage/repository.js";
import { LEDGER_CURSOR, sealedLog } from "../worker/sweep.js";
import { verifyMirror } from "./verify-mirror.js";
import { WebHttpClient, type HttpClient, type ValidatorIo } from "./validator.js";

const USAGE =
  "usage: import-mirror <mirror-dir>/<env> [--persist-to <dir>] " +
  "[--captures <url-or-dir>] [--force]";

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** What one invocation asks for. */
export interface ImportArguments {
  readonly dir: string;
  /** Where miniflare keeps its state, or null for the default wrangler dev uses. */
  readonly persistTo: string | null;
  /** A capture archive, or null to fetch from the manifest's own base. */
  readonly captures: string | null;
  /** Whether a non-empty database may be imported into. */
  readonly force: boolean;
}

/**
 * The arguments one invocation names, or null when they are not a call.
 *
 * Refuses rather than guesses, exactly as `verify-mirror` and `sync` do: a
 * reader who mistyped a flag should be told the usage rather than handed a run
 * over a database they did not mean.
 */
export function importArguments(
  args: readonly string[],
): ImportArguments | null {
  const [dir, ...rest] = args;
  if (dir === undefined || dir.startsWith("--")) return null;

  const values = new Map<string, string>();
  let force = false;
  for (let index = 0; index < rest.length; ) {
    const flag = rest[index];
    if (flag === "--force") {
      if (force) return null;
      force = true;
      index += 1;
      continue;
    }
    if (flag !== "--persist-to" && flag !== "--captures") return null;
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(flag)) return null;
    values.set(flag, value);
    index += 2;
  }

  return {
    dir,
    persistTo: values.get("--persist-to") ?? null,
    captures: values.get("--captures") ?? null,
    force,
  };
}

/** What the summary line says, and what a caller in process gets back. */
export interface ImportSummary {
  readonly environment: string;
  /** The layout the directory claimed: `v1` or `v2`. */
  readonly format: MirrorFormat;
  /**
   * Whether the attestation rows were written with the model's answers.
   *
   * False for a v1 mirror, which carries none: the answers are the one thing in
   * the export that is not a function of the log, so an older copy has no way to
   * hand them over and the rows go in without them. Everything else about those
   * attestations is `deriveAttestation`'s fold over the imported events, which
   * is the same fold either way.
   */
  readonly answers: boolean;
  readonly events: number;
  readonly seals: number;
  readonly anchors: number;
  readonly operators: number;
  readonly entries: number;
  readonly attestations: number;
  readonly ledgerRows: number;
  readonly head: number;
  readonly sealSeq: number;
}

/** How one import is driven. Everything has a default a command would use. */
export interface ImportOptions {
  /** Whether a non-empty database may be imported into. */
  readonly force?: boolean;
  /** A capture archive for the verification, or null for the manifest's base. */
  readonly captures?: string | null;
  /** The client the verification fetches captures with. */
  readonly http?: HttpClient;
  /** Where the verification's own lines go; dropped when there is nowhere. */
  readonly io?: ValidatorIo;
}

/** Every file under a directory, by its path relative to it, as the layout keys it. */
async function filesUnder(dir: string): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  const walk = async (at: string): Promise<void> => {
    for (const item of await readdir(at, { withFileTypes: true })) {
      const path = join(at, item.name);
      if (item.isDirectory()) {
        await walk(path);
        continue;
      }
      found.set(
        relative(dir, path).split("\\").join("/"),
        await readFile(path, "utf8"),
      );
    }
  };
  await walk(dir);
  return found;
}

/** A short, one-line cause: an errno where there is one, else the first line. */
function reasonOf(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === "string") return code;
  }
  if (error instanceof Error) {
    const first = error.message.split("\n")[0];
    if (first !== undefined && first.length > 0) return first;
  }
  return "unknown error";
}

/**
 * What one error said, in one line and with no stack behind it.
 *
 * The message first and the errno second, the other way round from `reasonOf`:
 * a miniflare that will not start says why in its message, and `ENOENT` on its
 * own would tell a reader nothing about which file was missing.
 */
function messageOf(error: unknown): string {
  if (error instanceof Error) {
    const first = error.message.split("\n")[0];
    if (first !== undefined && first.length > 0) return first;
  }
  return reasonOf(error);
}

/**
 * The stored log, as much of it as it takes to say whether it is a prefix.
 *
 * Seq and hash per event and nothing else: the hash covers everything an
 * importer could write, so two logs that agree hash for hash agree about
 * everything. Paged, never one unbounded scan, for the reason the whole storage
 * layer exists.
 */
async function storedEvents(db: D1Like, head: number): Promise<StoredEvent[]> {
  const stored: StoredEvent[] = [];
  for (let from = 0; from <= head; ) {
    const to = Math.min(from + LIST_PAGE_LIMIT - 1, head);
    const page = await eventsInRange(db, from, to);
    if (page.length === 0) break;
    for (const event of page) stored.push({ seq: event.seq, hash: event.hash });
    from = to + 1;
  }
  return stored;
}

/**
 * Run the directory through `verify-mirror` itself.
 *
 * Its own functions rather than a second copy of its checks: an import that
 * checked a little less than the verifier does would be a door into the log
 * that nobody had verified.
 */
async function verify(
  dir: string,
  options: ImportOptions,
): Promise<void> {
  const failures: string[] = [];
  const code = await verifyMirror(
    options.captures === undefined || options.captures === null
      ? [dir]
      : [dir, "--captures", options.captures],
    {
      stdout: (line: string) => {
        if (line.startsWith("FAIL ")) failures.push(line);
        options.io?.stdout(line);
      },
      stderr: (line: string) => {
        failures.push(line);
        options.io?.stderr(line);
      },
    },
    options.http ?? new WebHttpClient(),
  );
  if (code === OK) return;
  throw new ImportRefusal(
    "verify_failed",
    failures.length === 0
      ? `${dir}: the verifier refused it`
      : `${dir}: ${failures[0]!}`,
  );
}

/** The registry rows: the operator, its agents, and the domains it is attested in. */
async function writeOperators(db: D1Like, plan: ImportPlan): Promise<void> {
  for (const operator of plan.operators) {
    await putOperator(db, operator.record);
    for (const agent of operator.agents) await putAgent(db, agent);
    for (const domain of operator.domains) await putOperatorDomain(db, domain);
  }
}

/**
 * Every entry, re-derived at the sealed head over the events that were just
 * imported, and compared with the mirror's own file.
 *
 * Read back out of the database rather than folded off the directory: what has
 * to be right is the log this command wrote, and a derivation over the files
 * would only prove the files agree with themselves. The clock is the newest
 * seal's `sealed_at`, which is the instant the export derived at, and the
 * inclusion proofs come from the seals in one pass because they are a fact about
 * the seals rather than about which entry is asked.
 *
 * Everything is derived and compared before anything is written: rule 3 is that
 * a disagreement is a refusal rather than a row, and a loop that wrote as it
 * went would leave half of them behind.
 */
async function writeEntries(
  db: D1Like,
  layout: MirrorLayout,
  plan: ImportPlan,
): Promise<void> {
  const events = await sealedLog(db, plan.head);
  const seals = await sealsForEntries(events, plan.seals);
  const derived: { id: string; entry: Entry; sidecar: unknown }[] = [];

  for (const id of plan.entries) {
    const record = layout.entries.get(id)!;
    let entry;
    try {
      entry = deriveEntry(events, id, { now: plan.asOf }, seals);
    } catch {
      throw new ImportRefusal("underivable_entry", `entries/${id}.json`);
    }
    // The sidecar of a v1 file is compared on the keys a v1 sidecar had: the
    // source class was derived into it after that layout was written, so the
    // file is right to carry none. What is stored is the re-derivation all the
    // same, source class and all — the row is the kernel's reading of the log
    // this command just wrote, never a copy of somebody's file.
    const expectedSidecar =
      layout.format === "v1" ? v1Sidecar(entry.sidecar) : entry.sidecar;
    const actualSidecar =
      layout.format === "v1" ? v1Sidecar(record.sidecar) : record.sidecar;
    const difference =
      firstDifference(
        entry.entry as unknown as Record<string, unknown>,
        record.entry,
        "/entry",
      ) ??
      firstDifference(
        expectedSidecar as Record<string, unknown>,
        actualSidecar,
        "/sidecar",
      );
    if (difference !== null) {
      throw new ImportRefusal(
        "entry_differs",
        `entries/${id}.json${difference.field} ${difference.reason}`,
      );
    }
    const hash = await entryHash(extractCore(entry.entry));
    if (hash !== record.entry_hash) {
      throw new ImportRefusal(
        "entry_differs",
        `entries/${id}.json/entry_hash mismatch`,
      );
    }
    derived.push({ id, entry: entry.entry as Entry, sidecar: entry.sidecar });
  }

  for (const one of derived) {
    await putEntry(
      db,
      one.entry,
      one.sidecar as Parameters<typeof putEntry>[2],
      plan.head,
    );
  }
}

/**
 * The three families the mirror recomputes rather than reads, recomputed once
 * more here — by the very functions that built the files — and stored.
 *
 * The attestations are `deriveAttestation`'s fold over the imported events, with
 * the answers the files carry beside them: Section 8 seals the score and the
 * probe hash, so the answers are the one thing a replay has to take on the
 * mirror's word, and `verify-mirror` has already held them to the hash the log
 * committed to. The ledger rows and the standing are what `ledger.jsonl` and
 * `standing.json` are, which is what the sweep's own steps write, so both
 * cursors are then set to the imported head: the fork's first sweep carries on
 * from there rather than pricing and re-deciding the whole log again.
 */
async function writeRecomputed(
  db: D1Like,
  layout: MirrorLayout,
  plan: ImportPlan,
): Promise<{ attestations: number; ledgerRows: number }> {
  const attestations = mirrorAttestations(
    layout.events,
    [...layout.answers].map(([attestation, answers]) => ({
      attestation,
      answers,
    })),
    plan.asOf,
  );
  for (const record of attestations) {
    await putAttestation(db, {
      attestation: record.attestation,
      answers: record.answers,
    });
  }

  // Recomputed rather than read, which is why a v1 mirror carrying no
  // `ledger.jsonl` is imported with the same rows a v2 one is.
  const ledger = mirrorLedgerRows(layout.events, plan.asOf);
  await putLedgerRows(db, ledger);
  await setLedgerCursor(db, LEDGER_CURSOR, plan.head);

  for (const standing of mirrorStanding(layout.events, plan.head).operators) {
    await setOperatorStanding(
      db,
      standing.operator,
      standing.standing,
      plan.head,
    );
  }

  return { attestations: attestations.length, ledgerRows: ledger.length };
}

/**
 * Replay one mirror directory into one database.
 *
 * Throws `ImportRefusal` with a named reason on every refusal and writes nothing
 * before the last of them. Takes the database rather than opening one, so the
 * tests and the end-to-end proof drive it in process.
 */
export async function importMirror(
  dir: string,
  db: D1Like,
  options: ImportOptions = {},
): Promise<ImportSummary> {
  const target = resolve(dir);

  // (1) The verifier's own checks, before anything at all is read for writing.
  await verify(target, options);

  let files: Map<string, string>;
  try {
    files = await filesUnder(target);
  } catch (error) {
    throw new ImportRefusal("unreadable", `${target}: ${reasonOf(error)}`);
  }
  const layout = readLayout(files);

  // (5) A database with any event in it, and where its head sits.
  const stored = await headSeq(db);
  if (stored !== null && options.force !== true) {
    throw new ImportRefusal(
      "database_not_empty",
      `the log already holds ${stored + 1} events; --force to import into it`,
    );
  }
  const relation = headRelation(
    layout.events,
    stored === null ? [] : await storedEvents(db, stored),
  );
  const plan = importPlan(layout, relation);

  // (2) The events, in seq order, under the chain rule.
  for (let from = 0; from < plan.events.length; from += LIST_PAGE_LIMIT) {
    await appendEvents(db, plan.events.slice(from, from + LIST_PAGE_LIMIT));
  }

  // (3) The rows. The seals go in before the entries because an entry's own
  // seal is part of the entry, and the anchors beside them.
  await writeOperators(db, plan);
  for (const seal of plan.seals) await putSeal(db, seal);
  for (const anchor of plan.anchors) await putAnchor(db, anchor);
  await writeEntries(db, layout, plan);
  const recomputed = await writeRecomputed(db, layout, plan);

  return {
    environment: layout.environment,
    format: layout.format,
    answers: layout.format !== "v1",
    events: plan.events.length,
    seals: plan.seals.length,
    anchors: plan.anchors.length,
    operators: plan.operators.length,
    entries: plan.entries.length,
    attestations: recomputed.attestations,
    ledgerRows: recomputed.ledgerRows,
    head: plan.head,
    sealSeq: layout.sealSeq,
  };
}

/**
 * The one line an import that worked prints.
 *
 * `answers none` on a v1 mirror is not a detail: the attestation rows are there
 * and their fold is the log's own, but what the model actually said is the one
 * thing that older layout never carried, and a reader who is told the
 * attestations were imported deserves to be told that much about them.
 */
export function summaryLine(summary: ImportSummary): string {
  return [
    "import",
    summary.environment,
    `format ${summary.format}`,
    `events ${summary.events}`,
    `seals ${summary.seals}`,
    `anchors ${summary.anchors}`,
    `operators ${summary.operators}`,
    `entries ${summary.entries}`,
    `attestations ${summary.attestations}`,
    `answers ${summary.answers ? "carried" : "none"}`,
    `ledger ${summary.ledgerRows}`,
    `head ${summary.head}`,
    `seal ${summary.sealSeq}`,
  ].join(" ");
}

/** The repository root, resolved from this file so the cwd does not matter. */
const ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** The local database the command writes into, and the way to close it. */
export interface ImportPlatform {
  readonly env: { readonly DB: D1Like };
  dispose(): Promise<void>;
}

/** How the command gets one. Injected, so a test can drive the refusals. */
export type PlatformOpener = (
  persistTo: string | null,
) => Promise<ImportPlatform>;

/** The migration files, in the order `applyMigrations` will run them. */
/* c8 ignore start -- reads the repository's own migrations directory. */
async function migrations(): Promise<{ name: string; sql: string }[]> {
  const directory = join(ROOT, "migrations");
  const files = await Promise.all(
    (await readdir(directory)).map(async (name) => ({
      name,
      sql: await readFile(join(directory, name), "utf8"),
    })),
  );
  return migrationsInOrder(files);
}

/**
 * Where miniflare's state actually goes for a given `--persist-to`.
 *
 * `wrangler dev --persist-to X` and `wrangler d1 ... --persist-to X` keep their
 * state under `X/v3`, while `getPlatformProxy`'s `persist.path` is that inner
 * directory itself; without the segment an import lands beside the database the
 * server then reads, and every route answers 503 on an unmigrated file. The
 * `v3` is wrangler's own persist layout, not ours.
 *
 * With no flag, the default is the one `wrangler dev` takes with no flag:
 * `.wrangler/state/v3` under this repository, which is what `npm run dev`
 * serves, so `npm run import-mirror -- ../log/production` and then `npm run dev`
 * is the whole flow.
 */
export function persistPathFor(argument: string | null): string {
  const root = argument === null ? join(ROOT, ".wrangler", "state") : argument;
  return join(resolve(root), "v3");
}

/**
 * The local database `npm run dev` serves from: miniflare's, through wrangler's
 * `getPlatformProxy` on the top-level environment.
 */
const openPlatform: PlatformOpener = async (persistTo) => {
  const { getPlatformProxy } = await import("wrangler");
  return await getPlatformProxy<{ DB: D1Like }>({
    configPath: join(ROOT, "wrangler.jsonc"),
    persist: { path: persistPathFor(persistTo) },
  });
};
/* c8 ignore stop */

/**
 * The command: open the local database wrangler dev uses, migrate it, and
 * replay the directory into it.
 *
 * The same database and the same state directory `npm run dev` serves from, so
 * an import is followed by `npm run dev` and the record is simply there.
 * `--persist-to` names another state directory, exactly as wrangler's own flag
 * does.
 *
 * Opening it is inside the refusals rather than before them. A missing
 * `wrangler.jsonc`, a state directory another process holds, a miniflare that
 * will not start: every one of those is a thing about this laptop rather than
 * about the mirror, and rule 6 is that a reader gets a named line and never a
 * stack trace. So the open is `database_unavailable` with what the failure said,
 * and the dispose only ever runs on a platform that opened.
 */
export async function run(
  args: readonly string[],
  io: ValidatorIo,
  open: PlatformOpener = openPlatform,
): Promise<number> {
  const parsed = importArguments(args);
  if (parsed === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  let platform: ImportPlatform;
  try {
    platform = await open(parsed.persistTo);
  } catch (error) {
    io.stderr(`import database_unavailable: ${messageOf(error)}`);
    return FAILED;
  }

  try {
    await applyMigrations(platform.env.DB, await migrations());
    const summary = await importMirror(parsed.dir, platform.env.DB, {
      force: parsed.force,
      captures: parsed.captures,
      io,
    });
    io.stdout(summaryLine(summary));
    return OK;
  } catch (error) {
    io.stderr(
      error instanceof ImportRefusal
        ? `import ${error.message}`
        : `import failed ${reasonOf(error)}`,
    );
    return FAILED;
  } finally {
    await platform.dispose();
  }
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(
    await run(process.argv.slice(2), {
      stdout: (line: string) => console.log(line),
      stderr: (line: string) => console.error(line),
    }),
  );
}
/* c8 ignore stop */

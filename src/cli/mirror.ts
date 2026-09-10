/**
 * mirror: the daily export, built from the outside.
 *
 * Whitepaper Section 11, "Deployment and status": the sealed log is exported
 * daily to a public repository under CC0, so that nomankind going away is an
 * inconvenience rather than an ending. The Worker builds that export from its
 * own database (src/worker/sweep.ts's mirror step); this command builds the
 * very same directory from the public API of any instance, using nothing but
 * the reads a stranger has.
 *
 * That is the whole point of it. A mirror only a Worker can produce is a
 * promise; a mirror anyone can reproduce byte for byte from the doors is a
 * check. Both paths hand the same `MirrorInput` to the same `buildMirror`, so
 * two exports of the same sealed head are the same bytes whichever side made
 * them, and a forker who does not believe the published mirror can build their
 * own and diff it.
 *
 * The sealed head is pinned once, from the seal chain, and everything else is
 * read against it: the events are trimmed to it, and every entry record is
 * taken from `GET /sync`, which derives each entry at exactly that head under
 * exactly that seal's `sealed_at` (src/worker/sync.ts). A log that sealed again
 * while this command was reading stops it with `head_moved` rather than mixing
 * two moments into one directory — which is the same refusal `buildMirror`
 * makes as `gap`, caught one read earlier and named for what happened.
 *
 * Nothing unsealed is exported and no capture is written. Section 11 keeps the
 * snapshots outside the mirror on purpose: the mirror is CC0 and holds hashes,
 * while the captures are a stranger's bytes served from the archive and may be
 * withdrawn, and withdrawing one must remove a copy and leave the proof
 * standing. `mirror.json`'s `captures_base` says where they are served from,
 * and `npm run verify-mirror` fetches them from there or from a local archive.
 *
 * The core is exported over the injected http client, so a test drives it in
 * process against `handleRequest` with no network. node:fs and node:path are
 * allowed in this CLI file only.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import type { Anchor } from "../anchor.js";
import type { Event } from "../events.js";
import {
  buildMirror,
  MirrorError,
  type MirrorAttestationAnswers,
  type MirrorEntryRecord,
  type MirrorFile,
  type MirrorInput,
  type MirrorOperator,
} from "../mirror.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { Seal } from "../seal.js";
import { readEvents, readSeals } from "./export.js";
import {
  errorOf,
  getJson,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE = "usage: mirror <base-url> <out-dir>";

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/**
 * A read the export needs did not answer, or answered something the export
 * cannot build a directory out of.
 *
 * `reason` is one snake_case word, in the same voice the sweep's mirror step
 * skips in, so a person reading a failed mirror run and a person reading the
 * status page are reading the same vocabulary.
 */
export class MirrorFailure extends Error {
  override readonly name = "MirrorFailure";
  readonly reason: string;

  constructor(reason: string, detail: string) {
    super(`${reason}: ${detail}`);
    this.reason = reason;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One read that must succeed, or the export stops and says which one. */
async function read(
  http: HttpClient,
  baseUrl: string,
  path: string,
): Promise<unknown> {
  const { status, body } = await getJson(http, baseUrl, path);
  if (status !== 200) {
    throw new MirrorFailure(
      "read_failed",
      `${path}: ${status}${errorOf(body) === null ? "" : ` ${errorOf(body)}`}`,
    );
  }
  return body;
}

/**
 * Which environment this instance is, which is the directory the export lands
 * under.
 *
 * `GET /health` and no other read: the environment name is a fact about the
 * deployment rather than about the log, and it is the one thing the layout
 * needs that no log record carries.
 */
export async function readEnvironment(
  http: HttpClient,
  baseUrl: string,
): Promise<string> {
  const body = await read(http, baseUrl, "/health");
  const environment = isRecord(body) ? body["environment"] : undefined;
  if (typeof environment !== "string" || environment.length === 0) {
    throw new MirrorFailure("no_environment", "/health names no environment");
  }
  return environment;
}

/**
 * Every anchor, in date order, paged.
 *
 * The empty string because the route reads strictly after a day and every real
 * day sorts above it, exactly as the sweep's own `allAnchors` does.
 */
export async function readAnchors(
  http: HttpClient,
  baseUrl: string,
): Promise<Anchor[]> {
  const anchors: Anchor[] = [];
  let after = "";
  for (;;) {
    const query =
      after === ""
        ? `/anchors?limit=${LIST_PAGE_LIMIT}`
        : `/anchors?after=${encodeURIComponent(after)}&limit=${LIST_PAGE_LIMIT}`;
    const body = (await read(http, baseUrl, query)) as { anchors?: unknown };
    const page = Array.isArray(body.anchors) ? (body.anchors as Anchor[]) : [];
    anchors.push(...page);
    if (page.length < LIST_PAGE_LIMIT) break;
    after = page[page.length - 1]!.date;
  }
  return anchors;
}

/**
 * Every operator, with its agents, its domains and whether it is trusted.
 *
 * The listing route serves one page of at most its own limit and offers no
 * cursor, so that is what is read — the same shape `npm run export` reads the
 * registry in, and the same GAP: an environment with more than
 * LIST_PAGE_LIMIT operators needs a cursor on `GET /operators` before this
 * command can mirror all of them.
 *
 * `trusted` is read off the operator record's own details, which is where the
 * standing step caches what the log says, so this file asks the registry the
 * same question the sweep's export asks its database.
 */
export async function readMirrorOperators(
  http: HttpClient,
  baseUrl: string,
): Promise<MirrorOperator[]> {
  const listed = (await read(
    http,
    baseUrl,
    `/operators?limit=${LIST_PAGE_LIMIT}`,
  )) as { operators?: unknown };
  const rows = Array.isArray(listed.operators) ? listed.operators : [];

  const operators: MirrorOperator[] = [];
  for (const row of rows) {
    if (!isRecord(row) || typeof row["id"] !== "string") continue;
    const id = row["id"];
    const full = await read(
      http,
      baseUrl,
      `/operators/${encodeURIComponent(id)}`,
    );
    if (!isRecord(full)) continue;
    const details = full["details"];
    const domains = full["domains"];
    const agents = full["agents"];
    operators.push({
      operator: id,
      maintainer: full["maintainer"] === true,
      provider: full["provider"] === true,
      trusted: isRecord(details) && details["trusted"] === true,
      domains: Array.isArray(domains)
        ? domains.filter((one): one is string => typeof one === "string")
        : [],
      agents: Array.isArray(agents)
        ? agents.filter((one): one is string => typeof one === "string")
        : [],
    });
  }
  return operators;
}

/**
 * Every entry at or below the sealed head, derived there, out of the delta
 * stream.
 *
 * `GET /sync` re-derives each entry it delivers at the sealed head under that
 * seal's own `sealed_at` and hands over the entry, its sidecar and its core
 * hash — which is exactly the triple the mirror's `entries/<id>.json` holds and
 * exactly the way the sweep's mirror step produces one. Taking them from the
 * stream rather than re-deriving locally is what makes the two paths agree by
 * construction rather than by luck: there is one derivation, and this command
 * reads its answer.
 *
 * One entry is touched by several events in a page and delivered with each of
 * them; the records are the same record, so the last one seen wins and the map
 * keeps one per id.
 *
 * A page that reports a different sealed head or a different `as_of` than the
 * one pinned from the seal chain stops the run: two moments in one directory
 * would be a mirror nobody could reproduce.
 */
export async function readMirrorEntries(
  http: HttpClient,
  baseUrl: string,
  head: number,
  asOf: string,
): Promise<MirrorEntryRecord[]> {
  const byId = new Map<string, MirrorEntryRecord>();
  let from = 0;
  for (;;) {
    const body = (await read(
      http,
      baseUrl,
      `/sync?from=${from}&limit=${LIST_PAGE_LIMIT}`,
    )) as Record<string, unknown>;

    const sealedHead = body["sealed_head"];
    const pageAsOf = body["as_of"];
    if (sealedHead !== head || pageAsOf !== asOf) {
      throw new MirrorFailure(
        "head_moved",
        `the log sealed again while it was read: ${String(sealedHead)} at ${String(pageAsOf)}`,
      );
    }

    const items = Array.isArray(body["events"]) ? body["events"] : [];
    for (const item of items) {
      if (!isRecord(item)) continue;
      const entry = item["entry"];
      const sidecar = item["sidecar"];
      const entryHash = item["entry_hash"];
      if (!isRecord(entry) || typeof entry["id"] !== "string") continue;
      if (!isRecord(sidecar) || typeof entryHash !== "string") continue;
      byId.set(entry["id"], {
        entry: entry as unknown as MirrorEntryRecord["entry"],
        sidecar: sidecar as unknown as MirrorEntryRecord["sidecar"],
        entry_hash: entryHash,
      });
    }

    const pageHead = body["head"];
    if (typeof pageHead !== "number" || pageHead >= head) break;
    from = pageHead + 1;
  }
  return [...byId.values()];
}

/**
 * The model's answers, per attestation the instance has opened at or below the
 * sealed head.
 *
 * `GET /attestations` paged for the ids and `GET /attestations/{id}` for each
 * one's answers, because the listing serves the derived record and the answers
 * only travel beside a single record. The attestations themselves are never
 * taken from either: the layout folds them out of the sealed events, so what
 * this reads is the one field the log does not carry.
 *
 * Keyset downward by `requested_seq`, exactly as the route pages, and trimmed to
 * the head this export was pinned at.
 */
export async function readMirrorAnswers(
  http: HttpClient,
  baseUrl: string,
  head: number,
): Promise<MirrorAttestationAnswers[]> {
  const answers: MirrorAttestationAnswers[] = [];
  let before: number | undefined;
  for (;;) {
    const query =
      before === undefined
        ? `/attestations?limit=${LIST_PAGE_LIMIT}`
        : `/attestations?before=${before}&limit=${LIST_PAGE_LIMIT}`;
    const body = (await read(http, baseUrl, query)) as { attestations?: unknown };
    const page = Array.isArray(body.attestations) ? body.attestations : [];
    if (page.length === 0) break;

    let oldest: number | null = null;
    for (const row of page) {
      if (!isRecord(row)) continue;
      const id = row["id"];
      const requestedSeq = row["requested_seq"];
      if (typeof id !== "string" || typeof requestedSeq !== "number") continue;
      if (oldest === null || requestedSeq < oldest) oldest = requestedSeq;
      if (requestedSeq > head) continue;
      const one = await read(
        http,
        baseUrl,
        `/attestations/${encodeURIComponent(id)}`,
      );
      const served = isRecord(one) ? one["answers"] : null;
      answers.push({
        attestation: id,
        answers: Array.isArray(served)
          ? (served as MirrorAttestationAnswers["answers"])
          : null,
      });
    }

    if (page.length < LIST_PAGE_LIMIT || oldest === null) break;
    before = oldest;
  }
  return answers;
}

/** What one export is: which directory it lands in, and the files in it. */
export interface MirrorBuild {
  readonly environment: string;
  readonly head: number;
  readonly sealSeq: number;
  readonly files: MirrorFile[];
}

/**
 * The newest seal of a chain, by seq rather than by position in the list.
 *
 * The same rule `buildMirror` applies, made here as well because the head has
 * to be pinned before the entries are read and the answer must not depend on
 * the order a paged read handed the chain over in.
 */
function newestSeal(seals: readonly Seal[]): Seal | null {
  let newest: Seal | null = null;
  for (const seal of seals) {
    if (newest === null || seal.seq > newest.seq) newest = seal;
  }
  return newest;
}

/**
 * Build the export from one instance's public API.
 *
 * The order is the order of what depends on what: the environment names the
 * directory, the seal chain pins the head, the log is read and trimmed to it,
 * and only then are the entries taken from the stream at that head.
 *
 * Throws MirrorFailure when a read did not answer, and MirrorError when the
 * layout refuses what was read — `no_seal` for a log with nothing sealed,
 * `gap` for events that do not cover a seal's own range.
 */
export async function buildMirrorFromApi(input: {
  readonly baseUrl: string;
  readonly http: HttpClient;
  readonly now: Date;
}): Promise<MirrorBuild> {
  const environment = await readEnvironment(input.http, input.baseUrl);
  const seals = await readSeals(input.http, input.baseUrl);
  const newest = newestSeal(seals);
  if (newest === null) {
    throw new MirrorError("no_seal", "the instance has sealed nothing yet");
  }

  const head = newest.last_seq;
  // Trimmed rather than asked for: `GET /events` pages the whole log, and the
  // mirror is the sealed record, so everything past the head is dropped here.
  const events = (await readEvents(input.http, input.baseUrl)).filter(
    (event: Event) => event.seq <= head,
  );

  const mirrorInput: MirrorInput = {
    environment,
    exported_at: input.now.toISOString(),
    seals,
    anchors: await readAnchors(input.http, input.baseUrl),
    events,
    entries: await readMirrorEntries(
      input.http,
      input.baseUrl,
      head,
      newest.sealed_at,
    ),
    operators: await readMirrorOperators(input.http, input.baseUrl),
    attestations: await readMirrorAnswers(input.http, input.baseUrl, head),
  };

  return {
    environment,
    head,
    sealSeq: newest.seq,
    files: buildMirror(mirrorInput),
  };
}

/**
 * Write one export under `outDir`, in its environment's own directory, and
 * answer that directory's path.
 *
 * The bytes are `MirrorFile.content` exactly: `buildMirror` already put the
 * trailing newline on, and a writer that added one of its own would make a
 * directory that no longer matches the published mirror.
 */
export async function writeMirror(
  outDir: string,
  build: MirrorBuild,
): Promise<string> {
  const target = join(resolve(outDir), build.environment);
  for (const file of build.files) {
    const path = join(target, file.path);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, file.content, "utf8");
  }
  return target;
}

/**
 * The command: build the layout from an instance and write it.
 *
 * Returns the process's exit code — 0 with the directory and a summary line
 * printed, 1 on a named refusal, 2 on a usage error. Never a stack trace: a
 * command pointed at a stranger's Worker is reading a stranger's answers.
 */
export async function runMirror(
  args: readonly string[],
  io: ValidatorIo,
  http: HttpClient = new WebHttpClient(),
  now: Date = new Date(),
): Promise<number> {
  const [baseUrl, outDir, ...rest] = args;
  if (baseUrl === undefined || outDir === undefined || rest.length > 0) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  let build: MirrorBuild;
  try {
    build = await buildMirrorFromApi({ baseUrl, http, now });
  } catch (error) {
    if (error instanceof MirrorFailure) {
      io.stderr(`mirror ${error.reason} ${error.message}`);
      return FAILED;
    }
    if (error instanceof MirrorError) {
      io.stderr(`mirror ${error.reason}`);
      return FAILED;
    }
    io.stderr(
      `mirror failed ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`,
    );
    return FAILED;
  }

  const target = await writeMirror(outDir, build);
  io.stdout(
    `mirror ${build.environment} head ${build.head} seal ${build.sealSeq} files ${build.files.length}`,
  );
  io.stdout(target);
  return OK;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(
    await runMirror(process.argv.slice(2), {
      stdout: (line: string) => console.log(line),
      stderr: (line: string) => console.error(line),
    }),
  );
}
/* c8 ignore stop */

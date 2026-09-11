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
 * Two views, since the release window (decision D-100). With no credential the
 * command reads the public doors as a stranger does and builds the released
 * view: the same directory the Worker builds, with the unreleased seals as hash
 * lines and no entry file for an entry whose submission has not opened yet. With
 * `--key <api key>` or `--sign <key.json>` — a paid key, or an operator's own
 * agent key — it reads the content the fork is entitled to and builds the same
 * directory with those seals and those entries written in full. Either way the
 * window is judged at the injected clock and at nothing else, so the released
 * view is the Worker's export byte for byte for the same sealed head and the
 * same instant, and the full view is that directory plus the content — the same
 * `released_head` and the same `standing_position`, with more files under them.
 *
 * A signed read is the M2 signature the disclosure gate already verifies: GET,
 * the path with no query string, a null body, and the four headers (D-014).
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
import { LIST_PAGE_LIMIT, RELEASE_WINDOW_DAYS } from "../policy.js";
import { signRequest } from "../request.js";
import type { Seal } from "../seal.js";
import { readEvents, readSeals } from "./export.js";
import {
  errorOf,
  getJson,
  readKeyFile,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE =
  "usage: mirror <base-url> <out-dir> [--key <api key>] [--sign <key.json>]";

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
 * A page that reports a different sealed head than the one pinned from the seal
 * chain stops the run: two moments in one directory would be a mirror nobody
 * could reproduce. The page's `as_of` is held to being the same on every page
 * rather than to being the sealed head's, because it is not always the sealed
 * head's: a keyless reader is served to the released head and every entry as it
 * stood there (decision D-100), and that boundary is this view's own instant.
 * The two coincide the moment the reader is entitled to the whole log.
 */
export async function readMirrorEntries(
  http: HttpClient,
  baseUrl: string,
  head: number,
  asOf: string,
  events: readonly Event[],
): Promise<MirrorEntryRecord[]> {
  const byId = new Map<string, MirrorEntryRecord>();
  let pageAsOf: unknown = null;
  let from = 0;
  for (;;) {
    const body = (await read(
      http,
      baseUrl,
      `/sync?from=${from}&limit=${LIST_PAGE_LIMIT}`,
    )) as Record<string, unknown>;

    const sealedHead = body["sealed_head"];
    if (sealedHead !== head) {
      throw new MirrorFailure(
        "head_moved",
        `the log sealed again while it was read: ${String(sealedHead)} at ${String(body["as_of"])}`,
      );
    }

    const items = Array.isArray(body["events"]) ? body["events"] : [];
    // A page with nothing on it is the end of what this reader is served: the
    // range past the released head is empty for a keyless one, and past the
    // sealed head for everybody. It carries the sealed head's own `as_of`
    // rather than the page's, so it is never what this run's instant is taken
    // from.
    if (items.length === 0) break;
    if (pageAsOf === null) pageAsOf = body["as_of"];
    if (body["as_of"] !== pageAsOf) {
      throw new MirrorFailure(
        "head_moved",
        `two instants in one export: ${String(pageAsOf)} and ${String(body["as_of"])}`,
      );
    }
    void asOf;

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

  // And the entries the stream could not hand over (decision D-100).
  //
  // A keyless reader is served `/sync` only to the released head, so an entry
  // whose submission is still inside its window never appears on a page — and
  // the export it is left out of would be a directory whose index is short two
  // rows the Worker's own export writes. The submissions are all in the hash
  // lines `GET /events` serves, which name the event's `entry_id` with a null
  // payload beside it, and the free `GET /entries/{id}` answers every one of
  // them with the proof, the sidecar, the entry hash and the release date. That
  // is exactly the triple the index row is written from, so the row the fork
  // writes is byte for byte the row the Worker wrote.
  //
  // Trimmed to the pinned head for the same reason the events are: anything
  // past it is not the sealed record this directory is of. An id the stream
  // already delivered is left alone — the stream is the derivation, and a
  // second read of the same entry would be a second moment.
  for (const event of events) {
    if (event.type !== "entry_submitted") continue;
    if (event.seq > head) continue;
    const id = event.entry_id;
    if (typeof id !== "string" || byId.has(id)) continue;
    const record = await readWithheldEntry(http, baseUrl, id);
    if (record !== null) byId.set(id, record);
  }
  return [...byId.values()];
}

/**
 * One unreleased entry, off the free entry door: its proof, its sidecar and the
 * hash of its whole core.
 *
 * Null when the door answered with the entry itself, which is what an entitled
 * reader is served — and an entitled reader was already handed that entry by
 * `GET /sync`, so there is nothing here to take from the second read. The
 * withheld envelope is told apart by the key it arrives under (`proof`, never
 * `entry`), exactly as the export command tells the two apart.
 */
async function readWithheldEntry(
  http: HttpClient,
  baseUrl: string,
  id: string,
): Promise<MirrorEntryRecord | null> {
  const body = await read(http, baseUrl, `/entries/${encodeURIComponent(id)}`);
  if (!isRecord(body)) return null;
  const proof = body["proof"];
  const sidecar = body["sidecar"];
  const entryHash = body["entry_hash"];
  if (!isRecord(proof) || !isRecord(sidecar)) return null;
  if (typeof entryHash !== "string") return null;
  return {
    entry: proof as unknown as MirrorEntryRecord["entry"],
    sidecar: sidecar as unknown as MirrorEntryRecord["sidecar"],
    entry_hash: entryHash,
  };
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

// ---------------------------------------------------------------------------
// The two views
// ---------------------------------------------------------------------------

/** What one invocation asks for. */
export interface MirrorPlan {
  readonly baseUrl: string;
  readonly outDir: string;
  /** A paid API key, or null. */
  readonly key: string | null;
  /** The path to an operator's agent key file, or null. */
  readonly signPath: string | null;
}

/**
 * The plan one invocation names, or null when the arguments are not one.
 *
 * Refuses rather than guesses, exactly as `verify-mirror` and `sync` do, and
 * refuses both credentials at once: a run that presented a key and a signature
 * would leave a reader guessing which one reached the content.
 */
export function mirrorPlan(args: readonly string[]): MirrorPlan | null {
  const [baseUrl, outDir, ...rest] = args;
  if (baseUrl === undefined || outDir === undefined) return null;
  if (baseUrl.startsWith("--") || outDir.startsWith("--")) return null;

  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; ) {
    const flag = rest[index];
    if (flag !== "--key" && flag !== "--sign") return null;
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(flag)) return null;
    values.set(flag, value);
    index += 2;
  }
  if (values.has("--key") && values.has("--sign")) return null;

  return {
    baseUrl,
    outDir,
    key: values.get("--key") ?? null,
    signPath: values.get("--sign") ?? null,
  };
}

/**
 * The same client, with a bearer key on every read.
 *
 * A wrapper rather than a parameter threaded through six readers: what a
 * credential changes is the request, not the export, and `buildMirror` decides
 * the layout from the same inputs either way.
 */
class KeyedHttp implements HttpClient {
  constructor(
    private readonly inner: HttpClient,
    private readonly key: string,
  ) {}

  fetch(request: Request): Promise<Response> {
    const headers = new Headers(request.headers);
    headers.set("authorization", `Bearer ${this.key}`);
    return this.inner.fetch(new Request(request, { headers }));
  }
}

/**
 * The same client, with the M2 signature on every read.
 *
 * Exactly the form the disclosure gate verifies and the form `readerAccess`
 * verifies: GET, the path with no query string, a null body, and a fresh nonce
 * per request — which is why the headers are built per request rather than once.
 */
class SigningHttp implements HttpClient {
  constructor(
    private readonly inner: HttpClient,
    private readonly key: ValidatorKey,
    private readonly now: Date,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const signed = await signRequest({
      method: request.method,
      path: new URL(request.url).pathname,
      body: null,
      agentId: this.key.agentId,
      privateKey: this.key.privateKey,
      timestamp: this.now.toISOString(),
    });
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(signed)) headers.set(name, value);
    return this.inner.fetch(new Request(request, { headers }));
  }
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
  /**
   * Which of the two directories to build (decision D-100).
   *
   * `released` is the published layout, judged at this run's own instant: the
   * seals inside their window as hash lines, and no file for an entry nobody
   * may read yet. `full` is the copy an entitled fork takes with `--key` or
   * `--sign`: the same layout, judged as of the day the newest seal opens, so
   * every payload this reader was served is written out and the manifest's
   * `released_head` says so rather than claiming a public head the files do not
   * match. A reader with no credential cannot build it, because the doors do
   * not hand them the payloads it is made of.
   */
  readonly view?: "released" | "full";
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

  // The instant the window is judged at is this run's own, in both views. A
  // fork that was served the whole log writes the whole log, and says so with
  // its files; it does not get to say that more of the log is public than is.
  // `released_head` and `standing_position` are therefore the same numbers the
  // Worker's export of the same head carries at the same clock, and the full
  // directory is a superset of the published one rather than a rival reading of
  // it.
  const mirrorInput: MirrorInput = {
    environment,
    exported_at: input.now.toISOString(),
    now: input.now.toISOString(),
    release_window_days: RELEASE_WINDOW_DAYS,
    view: input.view ?? "released",
    seals,
    anchors: await readAnchors(input.http, input.baseUrl),
    events,
    entries: await readMirrorEntries(
      input.http,
      input.baseUrl,
      head,
      newest.sealed_at,
      events,
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
  const plan = mirrorPlan(args);
  if (plan === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  // The released view is what a stranger gets and what the line says they got:
  // a fork that is entitled to more has to say so with a key or a signature.
  let reader = http;
  if (plan.key !== null) reader = new KeyedHttp(http, plan.key);
  if (plan.signPath !== null) {
    try {
      reader = new SigningHttp(http, await readKeyFile(plan.signPath), now);
    } catch (error) {
      io.stderr(
        `mirror bad_key_file ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`,
      );
      return FAILED;
    }
  }
  const view = plan.key === null && plan.signPath === null ? "released" : "full";

  let build: MirrorBuild;
  try {
    build = await buildMirrorFromApi({
      baseUrl: plan.baseUrl,
      http: reader,
      now,
      view,
    });
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

  const target = await writeMirror(plan.outDir, build);
  io.stdout(
    `mirror ${build.environment} head ${build.head} seal ${build.sealSeq} files ${build.files.length} view ${view}`,
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

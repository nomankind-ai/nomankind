/**
 * export: the two files the offline verifier takes.
 *
 * Whitepaper, Goals and non-goals, goal 4: "anyone can check the proof offline
 * with two files and one script". `npm run verify` is the script and this is
 * where the two files come from (decision D-038): `entry.json` as the Worker
 * serves it, and `log.json` as the LogBundle beside it — the whole log paged to
 * its head, the registry as the operator routes report it, and the captures the
 * snapshot hashes point at, base64 as the verifier reads them.
 *
 * Nothing here decides anything and nothing here is recomputed: the export is a
 * faithful copy of what the Worker says, so a verifier that disagrees with it is
 * disagreeing with the log rather than with this command. The seals are paged
 * out of `GET /seals` exactly as the events are paged out of `GET /events`, and
 * a Worker that has sealed nothing yet answers an empty list, which the verifier
 * already reads as "nothing sealed yet".
 *
 * The core is exported over the injected http client, so the checkpoint builds a
 * bundle in process without a network. node:fs and node:path are allowed in this
 * CLI file only.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { base64Encode } from "../encoding.js";
import type { Event } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { Seal } from "../seal.js";
import type { Capture, LogBundle, Registry } from "../verify.js";
import {
  errorOf,
  getJson,
  urlFor,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE = "usage: export <base-url> <entry-id> <out-dir>";

/** The two file names the verifier is handed. */
export const ENTRY_FILE = "entry.json";
export const BUNDLE_FILE = "log.json";

/** A read failed, naming what could not be read. */
export class ExportFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExportFailure";
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
    throw new ExportFailure(
      `${path}: ${status}${errorOf(body) === null ? "" : ` ${errorOf(body)}`}`,
    );
  }
  return body;
}

/**
 * The whole log, paged to its head.
 *
 * Keyset, exactly as the route serves it: the last seq seen is what the next
 * page resumes after, and the loop ends when the page's last event is the head
 * the route reported with it.
 */
export async function readEvents(
  http: HttpClient,
  baseUrl: string,
): Promise<Event[]> {
  const events: Event[] = [];
  let after: number | null = null;
  for (;;) {
    const query =
      after === null
        ? `/events?limit=${LIST_PAGE_LIMIT}`
        : `/events?after=${after}&limit=${LIST_PAGE_LIMIT}`;
    const page = (await read(http, baseUrl, query)) as {
      events: Event[];
      head: number | null;
    };
    events.push(...page.events);
    if (page.events.length === 0) break;
    const last = page.events[page.events.length - 1]!.seq;
    if (page.head === null || last >= page.head) break;
    after = last;
  }
  return events;
}

/**
 * The whole seal chain, paged to its head.
 *
 * The same keyset walk the events take, against the same shape of answer: the
 * last seal seq seen is what the next page resumes after, and the loop ends when
 * the page's last seal is the head the route reported with it. A Worker that has
 * sealed nothing answers `{seals: [], head: null}`, and the bundle carries the
 * empty list.
 */
export async function readSeals(
  http: HttpClient,
  baseUrl: string,
): Promise<Seal[]> {
  const seals: Seal[] = [];
  let after: number | null = null;
  for (;;) {
    const query =
      after === null
        ? `/seals?limit=${LIST_PAGE_LIMIT}`
        : `/seals?after=${after}&limit=${LIST_PAGE_LIMIT}`;
    const page = (await read(http, baseUrl, query)) as {
      seals: Seal[];
      head: number | null;
    };
    seals.push(...page.seals);
    if (page.seals.length === 0) break;
    const last = page.seals[page.seals.length - 1]!.seq;
    if (page.head === null || last >= page.head) break;
    after = last;
  }
  return seals;
}

/**
 * The registry as the operator routes report it: every agent's operator, and
 * every operator's maintainer and provider flags. The list route serves one page
 * of at most its own limit and offers no cursor, so that is what is read.
 */
export async function readRegistry(
  http: HttpClient,
  baseUrl: string,
): Promise<Registry> {
  const listed = (await read(
    http,
    baseUrl,
    `/operators?limit=${LIST_PAGE_LIMIT}`,
  )) as { operators?: unknown };
  const rows = Array.isArray(listed.operators) ? listed.operators : [];

  const agents: Record<string, string> = {};
  const operators: Registry["operators"] = {};
  for (const row of rows) {
    if (!isRecord(row) || typeof row["id"] !== "string") continue;
    const id = row["id"];
    const full = await read(
      http,
      baseUrl,
      `/operators/${encodeURIComponent(id)}`,
    );
    if (!isRecord(full)) continue;
    // Decision D-071: the domains the operator is attested in, exactly as
    // GET /operators/{id} lists them. The offline exclusions check reruns
    // `checkValidation` against them, so a bundle without them would rerun a
    // different rule from the one the Worker applied.
    const domains = full["domains"];
    operators[id] = {
      maintainer: full["maintainer"] === true,
      provider: full["provider"] === true,
      ...(Array.isArray(domains)
        ? { domains: domains.filter((d): d is string => typeof d === "string") }
        : {}),
    };
    const bound = full["agents"];
    if (!Array.isArray(bound)) continue;
    for (const agent of bound) {
      if (typeof agent === "string") agents[agent] = id;
    }
  }
  return { agents, operators };
}

/** Every snapshot hash the entry and its approvers name, without duplicates. */
export function captureHashes(entry: unknown): string[] {
  const hashes: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === "string" && !hashes.includes(value)) hashes.push(value);
  };
  if (!isRecord(entry)) return hashes;
  add(entry["snapshot_hash"]);
  const approvers = entry["approvers"];
  if (Array.isArray(approvers)) {
    for (const record of approvers) {
      if (isRecord(record)) add(record["snapshot_hash"]);
    }
  }
  return hashes;
}

/**
 * One archived capture, as the verifier reads it: the raw bytes base64, and the
 * content type the norm rule hashed under. The sidecar's own header is the
 * authority — it is the value the hash was taken with — and the response's
 * content type stands in when the sidecar carries none. A hash the archive does
 * not hold is skipped rather than exported as an empty capture.
 */
async function readCapture(
  http: HttpClient,
  baseUrl: string,
  hash: string,
): Promise<Capture | null> {
  const path = `/captures/${encodeURIComponent(hash)}`;
  const response = await http.fetch(new Request(urlFor(baseUrl, path)));
  if (response.status === 404) return null;
  if (response.status !== 200) {
    throw new ExportFailure(`${path}: ${response.status}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());

  let sidecarType: string | null = null;
  const sidecar = await getJson(http, baseUrl, `${path}/sidecar`);
  if (sidecar.status === 200 && isRecord(sidecar.body)) {
    const headers = sidecar.body["headers"];
    if (isRecord(headers) && typeof headers["content-type"] === "string") {
      sidecarType = headers["content-type"];
    }
  }

  return {
    content_type: sidecarType ?? response.headers.get("content-type"),
    body_base64: base64Encode(bytes),
  };
}

/** The two files, built but not written. */
export interface ExportResult {
  readonly entry: unknown;
  readonly bundle: LogBundle;
}

/**
 * Build the entry and the log bundle beside it, from the Worker alone.
 *
 * Throws ExportFailure when a read the bundle needs did not answer; a capture
 * the archive does not hold is not one of those, and is simply absent.
 */
export async function buildExport(input: {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly http: HttpClient;
  readonly now: Date;
}): Promise<ExportResult> {
  const entry = await read(
    input.http,
    input.baseUrl,
    `/entries/${encodeURIComponent(input.entryId)}`,
  );

  const captures: Record<string, Capture> = {};
  for (const hash of captureHashes(entry)) {
    const capture = await readCapture(input.http, input.baseUrl, hash);
    if (capture !== null) captures[hash] = capture;
  }

  const bundle: LogBundle = {
    as_of: input.now.toISOString(),
    events: await readEvents(input.http, input.baseUrl),
    registry: await readRegistry(input.http, input.baseUrl),
    // An empty list is not a missing field: the verifier reads it as a log
    // nothing has sealed yet.
    seals: await readSeals(input.http, input.baseUrl),
    captures,
  };
  return { entry, bundle };
}

/** Write the two files into `outDir`, and answer the two paths. */
export async function writeExport(
  outDir: string,
  result: ExportResult,
): Promise<{ entryPath: string; bundlePath: string }> {
  const target = resolve(outDir);
  await mkdir(target, { recursive: true });
  const entryPath = join(target, ENTRY_FILE);
  const bundlePath = join(target, BUNDLE_FILE);
  await writeFile(entryPath, `${JSON.stringify(result.entry, null, 2)}\n`, "utf8");
  await writeFile(
    bundlePath,
    `${JSON.stringify(result.bundle, null, 2)}\n`,
    "utf8",
  );
  return { entryPath, bundlePath };
}

/**
 * The command: build the two files and write them. Returns the process's exit
 * code — 0 with both paths printed, 1 when a read the bundle needs failed.
 */
export async function exportEntry(
  baseUrl: string,
  entryId: string,
  outDir: string,
  io: ValidatorIo,
  http: HttpClient = new WebHttpClient(),
  now: Date = new Date(),
): Promise<number> {
  let result: ExportResult;
  try {
    result = await buildExport({ baseUrl, entryId, http, now });
  } catch (error) {
    io.stderr(
      `${entryId}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  }

  const written = await writeExport(outDir, result);
  io.stdout(written.entryPath);
  io.stdout(written.bundlePath);
  return 0;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const [baseUrl, entryId, outDir] = process.argv.slice(2);
  if (baseUrl === undefined || entryId === undefined || outDir === undefined) {
    console.error(USAGE);
    process.exit(2);
  }
  process.exit(
    await exportEntry(baseUrl, entryId, outDir, {
      stdout: (line: string) => console.log(line),
      stderr: (line: string) => console.error(line),
    }),
  );
}
/* c8 ignore stop */

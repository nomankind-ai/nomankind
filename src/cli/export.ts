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
 * `--bounded` writes the same two files with a smaller second one, read as
 * narrowly as it is written (decision D-120). The whole log is what an entry's
 * checks need only because the chain is walked from seq 0 and the derived view
 * is refolded out of everything; what the entry's OWN proof needs is its own
 * events, a Merkle path from each of them to the root the seal covering it
 * committed to, those seals and the seal before each of them, and the registry
 * and captures as ever.
 *
 * Both halves are bounded, and that is the point. The bundle does not grow with
 * the log and neither does the walk that builds it: `GET /entries/{id}/events`
 * answers the entry's own events with a proof each in one call, so a bounded
 * export costs the same handful of requests on a log of a thousand entries as on
 * a log of ten.
 *
 * What it leaves out is what a bounded bundle could never hold: every other
 * entry's events, which are the inputs of the chain walk from seq 0, of the
 * exclusions replayed against who was registered at each decision, and of the
 * derived fold. The verifier names those as not run rather than passing over
 * them.
 *
 * Full is still the default, and deliberately. The paper promises two files and
 * one script, the checkpoint writes them, the published example is one of them,
 * and an `ok` over a full bundle is a wider sentence than an `ok` over a bounded
 * one. A default that quietly narrowed what `ok` means would be a default that
 * changed the promise without anyone asking for it; a reader who wants the
 * smaller file asks for it and is told, on stderr and in the verifier's report,
 * what they got.
 *
 * The core is exported over the injected http client, so the checkpoint builds a
 * bundle in process without a network. node:fs and node:path are allowed in this
 * CLI file only.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { attributionOf, type Attribution } from "../attribution.js";
import { operatorKindsAt } from "../derive.js";
import { base64Encode } from "../encoding.js";
import type { Event } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { Seal } from "../seal.js";
import type { BundleProof, Capture, LogBundle, Registry } from "../verify.js";
import {
  errorOf,
  getJson,
  keyedHttp,
  readKeyFile,
  signingHttp,
  type Clock,
  urlFor,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";
import { runCommand, unreachableLine } from "./main.js";

const USAGE =
  "usage: export <base-url> <entry-id> <out-dir> [--bounded] [--key <api key>] [--sign <key.json>]";

/** The two file names the verifier is handed. */
export const ENTRY_FILE = "entry.json";
export const BUNDLE_FILE = "log.json";

/**
 * The sidecar beside them: who the entry is owed to (decision D-130).
 *
 * A third file rather than a field, because the entry is the entry: the
 * published object is schema-validated with `additionalProperties: false`, so
 * nothing new goes inside it, and a bundle that carried the block would be
 * asking the verifier to check a field no signature covers. The sidecar is
 * folded from the bundle's own events by `attributionOf`, so a reader who
 * distrusts it can recompute it from the two files it sits beside — which is
 * the same promise every other number in the export carries.
 */
export const ATTRIBUTION_FILE = "attribution.json";

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

/**
 * Every capture a community operator's registration named, without duplicates
 * (decision D-138 item 5).
 *
 * A `profile` binding is a key published on a page, and the page is evidence
 * like a citation's snapshot: the registration names the hash its bytes are
 * archived under, and the offline verifier reads the key out of those bytes for
 * itself (src/verify.ts, `verifyProfileBinding`). A bundle that carried the
 * validation and not the page would carry a binding nobody could recheck, which
 * is exactly what this decision promised not to do.
 *
 * Read off the events by name and defensively, like every other reading of a
 * stored payload here: an event shaped otherwise is one this function says
 * nothing about.
 */
export function bindingCaptureHashes(events: readonly unknown[]): string[] {
  const hashes: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === "string" && !hashes.includes(value)) hashes.push(value);
  };
  for (const event of events) {
    if (!isRecord(event)) continue;
    const type = event["type"];
    // The registration, and the upgrade that may follow it (D-142): a binding
    // that got stronger publishes a key on a page, and a bundle carrying the
    // later validations without that page would carry a binding nobody could
    // recheck — the same hole this function was written to close.
    if (
      type !== "community_operator_registered" &&
      type !== "community_operator_bound"
    ) {
      continue;
    }
    const payload = event["payload"];
    if (!isRecord(payload)) continue;
    const binding = payload["binding"];
    if (!isRecord(binding)) continue;
    if (binding["kind"] === "profile") {
      add(binding["capture_hash"]);
      continue;
    }
    // An account binding (D-142) archives two pages rather than one: the
    // comment the line was read from, and the profile that shows whose account
    // said it. Both are what the verifier checks, so both travel.
    if (binding["kind"] === "account") {
      add(binding["comment_capture_hash"]);
      add(binding["profile_capture_hash"]);
    }
  }
  return hashes;
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
  // A capture this reader may not have is absent from this view rather than a
  // failed export: the disclosure rule withholds a redacted transcript's
  // payload from anyone but an operator (D-096), and what the bundle carries is
  // the hash, which is what it was always going to check.
  if (response.status === 403) return null;
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

/**
 * One seal by its own seq, or null when the log has none there.
 *
 * Null rather than a failure for a 404: a bounded bundle asks for the seal
 * before each covering seal, and the seal before seal 0 does not exist. Any
 * other status is a read the bundle needed and did not get, and stops the
 * export like every other one.
 */
async function readSeal(
  http: HttpClient,
  baseUrl: string,
  seq: number,
): Promise<Seal | null> {
  const path = `/seals/${seq}`;
  const { status, body } = await getJson(http, baseUrl, path);
  if (status === 404) return null;
  if (status !== 200) {
    throw new ExportFailure(
      `${path}: ${status}${errorOf(body) === null ? "" : ` ${errorOf(body)}`}`,
    );
  }
  return body as Seal;
}

/**
 * One entry's own events, in seq order, with a proof for each sealed one, out of
 * the door that answers exactly that (decision D-120).
 *
 * One request, bounded by the entry rather than by the log: the whole point of
 * `GET /entries/{id}/events` is that a reader gathering one entry's story no
 * longer has to page `GET /events` to its head to be sure they have it all. The
 * proofs are the Worker's own, recomputed nowhere here, for the same reason
 * nothing else in this command is recomputed.
 */
async function readEntryEvents(
  http: HttpClient,
  baseUrl: string,
  entryId: string,
): Promise<{
  events: Event[];
  head: number | null;
  proofs: Record<string, BundleProof>;
}> {
  const body = (await read(
    http,
    baseUrl,
    `/entries/${encodeURIComponent(entryId)}/events`,
  )) as {
    events?: Event[];
    head?: number | null;
    proofs?: unknown[];
  };

  const events = Array.isArray(body.events) ? body.events : [];
  const proofs: Record<string, BundleProof> = {};
  for (const item of Array.isArray(body.proofs) ? body.proofs : []) {
    if (!isRecord(item)) continue;
    const seal = item["seal"];
    const proof = item["inclusion_proof"];
    if (typeof item["seq"] !== "number") continue;
    if (!isRecord(seal) || typeof seal["seq"] !== "number") continue;
    if (typeof proof !== "string") continue;
    proofs[String(item["seq"])] = {
      seal_seq: seal["seq"],
      inclusion_proof: proof,
    };
  }
  return { events, head: body.head ?? null, proofs };
}

/**
 * The bundle bounded to one entry's seals (decision D-120), read as narrowly as
 * it is written.
 *
 * The reads are what the entry is and not what the log is: the entry record,
 * which the export has already read; its own events with their proofs, in one
 * call; the seals those proofs are against and the seal before each of them,
 * each by seq; and the registry and the captures, exactly as the full export
 * reads them. Nothing here pages `GET /events`, so a bounded export costs the
 * same handful of requests on a log of a thousand entries as on a log of ten.
 */
async function buildBoundedBundle(input: {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly http: HttpClient;
  readonly now: Date;
  readonly captures: Record<string, Capture>;
}): Promise<LogBundle> {
  const log = await readEntryEvents(input.http, input.baseUrl, input.entryId);

  const wanted = new Set<number>();
  for (const proof of Object.values(log.proofs)) {
    wanted.add(proof.seal_seq);
    // The seal before it, for the link. Seal 0 has none, and `readSeal` answers
    // null for a seq the chain does not hold.
    if (proof.seal_seq > 0) wanted.add(proof.seal_seq - 1);
  }

  const seals: Seal[] = [];
  for (const seq of [...wanted].sort((left, right) => left - right)) {
    const seal = await readSeal(input.http, input.baseUrl, seq);
    if (seal !== null) seals.push(seal);
  }

  return {
    as_of: input.now.toISOString(),
    events: [...log.events].sort((left, right) => left.seq - right.seq),
    registry: await readRegistry(input.http, input.baseUrl),
    seals,
    captures: input.captures,
    bounded: true,
    head: log.head,
    proofs: log.proofs,
  };
}

/** The two files, built but not written, and the attribution sidecar. */
export interface ExportResult {
  readonly entry: unknown;
  readonly bundle: LogBundle;
  /** Who the entry is owed to, folded from the bundle's own events (D-130). */
  readonly attribution: Attribution;
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
  /**
   * Write the bundle bounded to this entry's seals rather than the whole log
   * (decision D-120). Absent is the whole log, which is what every caller that
   * predates the flag asks for and gets.
   */
  readonly bounded?: boolean;
}): Promise<ExportResult> {
  const answer = await read(
    input.http,
    input.baseUrl,
    `/entries/${encodeURIComponent(input.entryId)}`,
  );
  // The record is free from the seal (D-127): the entry door answers with the
  // entry itself to every reader, so what is written is what was read.
  const entry = answer;

  const captures: Record<string, Capture> = {};
  for (const hash of captureHashes(entry)) {
    const capture = await readCapture(input.http, input.baseUrl, hash);
    if (capture !== null) captures[hash] = capture;
  }

  let bundle: LogBundle =
    input.bounded === true
      ? await buildBoundedBundle({ ...input, captures })
      : {
          as_of: input.now.toISOString(),
          events: await readEvents(input.http, input.baseUrl),
          registry: await readRegistry(input.http, input.baseUrl),
          // An empty list is not a missing field: the verifier reads it as a
          // log nothing has sealed yet.
          seals: await readSeals(input.http, input.baseUrl),
          captures,
        };

  // The pages the bundle's own registrations named (D-138 item 5). After the
  // bundle rather than before it, because which registrations are in it is a
  // fact about the bundle: a bounded export carries the entry's own events and
  // a full one carries the log's, and each gets exactly the captures its events
  // ask for. A page the archive no longer holds is absent rather than a failed
  // export, exactly as a citation's snapshot is.
  const binding: Record<string, Capture> = {};
  for (const hash of bindingCaptureHashes(bundle.events)) {
    if (bundle.captures?.[hash] !== undefined) continue;
    const capture = await readCapture(input.http, input.baseUrl, hash);
    if (capture !== null) binding[hash] = capture;
  }
  if (Object.keys(binding).length > 0) {
    bundle = { ...bundle, captures: { ...bundle.captures, ...binding } };
  }

  // Folded from the bundle that was just built and never fetched: the block is
  // a function of the entry and its events, both of which are in the two files,
  // so the sidecar cannot say anything the bundle does not already support. A
  // bounded bundle carries the entry's events without the registry's, and a
  // community validation still reads as one there because the event says so.
  const head = bundle.events.reduce(
    (highest, event) => (event.seq > highest ? event.seq : highest),
    0,
  );
  const attribution = attributionOf(
    isRecord(entry) ? entry : {},
    bundle.events,
    operatorKindsAt(bundle.events, head),
  );

  return { entry, bundle, attribution };
}

/** Write the files into `outDir`, and answer their paths. */
export async function writeExport(
  outDir: string,
  result: ExportResult,
): Promise<{
  entryPath: string;
  bundlePath: string;
  attributionPath: string;
}> {
  const target = resolve(outDir);
  await mkdir(target, { recursive: true });
  const entryPath = join(target, ENTRY_FILE);
  const bundlePath = join(target, BUNDLE_FILE);
  const attributionPath = join(target, ATTRIBUTION_FILE);
  await writeFile(entryPath, `${JSON.stringify(result.entry, null, 2)}\n`, "utf8");
  await writeFile(
    bundlePath,
    `${JSON.stringify(result.bundle, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    attributionPath,
    `${JSON.stringify(result.attribution, null, 2)}\n`,
    "utf8",
  );
  return { entryPath, bundlePath, attributionPath };
}

/** What one invocation asks for, or null when the arguments are not an export. */
export interface ExportPlan {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly outDir: string;
  /** A paid API key, presented as a bearer token. */
  readonly key: string | null;
  /** An operator's agent key file, whose signature every read carries. */
  readonly signPath: string | null;
  /** `--bounded`: the bundle bounded to this entry's seals (decision D-120). */
  readonly bounded: boolean;
}

/**
 * Read one invocation, or answer null when it is not an export.
 *
 * Three positionals and two credentials, either of which reaches inside the
 * release window (decision D-100) and neither of which is required: without one
 * the export is the released view, which is every hash, seal and position the
 * log has published and none of the content it has not. Refuses rather than
 * guesses — an unknown flag is refused for the reason src/read.ts refuses an
 * unknown query parameter — and both credentials at once is refused too, since
 * a reader presenting both has not said which one they meant to be billed as.
 */
export function exportPlan(args: readonly string[]): ExportPlan | null {
  const [baseUrl, entryId, outDir, ...rest] = args;
  if (baseUrl === undefined || baseUrl.startsWith("--")) return null;
  if (entryId === undefined || entryId.startsWith("--")) return null;
  if (outDir === undefined || outDir.startsWith("--")) return null;

  const values = new Map<string, string>();
  // `--bounded` takes no value, so the walk steps by what each flag actually
  // is rather than by pairs; a repeated flag is still refused, and so is a
  // value that looks like another flag.
  let bounded = false;
  for (let index = 0; index < rest.length; ) {
    const flag = rest[index];
    if (flag === undefined) return null;
    if (flag === "--bounded") {
      if (bounded) return null;
      bounded = true;
      index += 1;
      continue;
    }
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
    entryId,
    outDir,
    key: values.get("--key") ?? null,
    signPath: values.get("--sign") ?? null,
    bounded,
  };
}

/**
 * The command: build the two files and write them. Returns the process's exit
 * code — 0 with both paths printed, 1 when a read the bundle needs failed.
 *
 */
export async function exportEntry(
  baseUrl: string,
  entryId: string,
  outDir: string,
  io: ValidatorIo,
  http: HttpClient = new WebHttpClient(),
  now: Date = new Date(),
  bounded = false,
): Promise<number> {
  let result: ExportResult;
  try {
    result = await buildExport({ baseUrl, entryId, http, now, bounded });
  } catch (error) {
    io.stderr(
      unreachableLine(baseUrl, error) ??
        `${entryId}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  }

  // What a bounded bundle is, said where a reader will see it and not only in
  // the verifier's report: the file proves this entry's events were sealed, and
  // the three checks that are a fold over the whole log are not in it.
  if (result.bundle.bounded === true) {
    io.stderr(
      `${entryId}: bounded bundle at head ${result.bundle.head ?? "none"}; the chain, the exclusions and the derived view are not checkable from it`,
    );
  }

  const written = await writeExport(outDir, result);
  io.stdout(written.entryPath);
  io.stdout(written.bundlePath);
  // Third, and after the two the paper promises: "two files and one script"
  // still holds — the verifier takes the first two and this one is the
  // attribution a reader cites from (D-130).
  io.stdout(written.attributionPath);
  return 0;
}

/**
 * The client one invocation reads through: the caller's own, the caller's with
 * a bearer key on every request, or the caller's with an operator agent's M2
 * signature on every read (decision D-100).
 */
export async function exportClient(
  http: HttpClient,
  plan: ExportPlan,
  clock: Clock,
): Promise<HttpClient> {
  if (plan.key !== null) return keyedHttp(http, plan.key);
  if (plan.signPath !== null) {
    return signingHttp(http, await readKeyFile(plan.signPath), clock);
  }
  return http;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = exportPlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(2);
  }
  const now = new Date();
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  process.exit(
    await runCommand({ name: "export", baseUrl: plan.baseUrl, io }, async () =>
      exportEntry(
        plan.baseUrl,
        plan.entryId,
        plan.outDir,
        io,
        await exportClient(new WebHttpClient(), plan, () => new Date()),
        now,
        plan.bounded,
      ),
    ),
  );
}
/* c8 ignore stop */

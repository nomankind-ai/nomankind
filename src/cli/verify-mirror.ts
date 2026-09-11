/**
 * verify-mirror: the offline verifier, pointed at a whole mirror.
 *
 * Whitepaper Section 11, "Deployment and status", and the Conclusion: the exit
 * is not a promise, it is a copy. `npm run verify` checks one entry against the
 * two files beside it; this command checks a fresh clone of the log repository,
 * end to end, with nothing but the clone and this code — the manifest, the
 * event chain, every seal, every anchor, and every entry through the same
 * `verifyOffline` the paper's one script runs.
 *
 * The bundle is built out of the mirror itself. `operators.json` is exactly
 * what the verifier's `Registry` needs, the events files hold the whole sealed
 * log, `seals.jsonl` holds the chain, and `mirror.json`'s `as_of` is the
 * instant every entry in the directory was derived at — so the bundle a forker
 * checks against is the mirror rather than anything this command invented.
 *
 * The captures are the one thing the mirror does not hold, and that is Section
 * 11's design rather than an omission: the snapshots live outside the mirror as
 * an evidentiary archive, so that a withdrawal removes a copy and leaves the
 * proof. They are fetched from the environment's `captures_base` by default, or
 * read from a local archive with `--captures <dir>` — one file per capture,
 * named by the hex of its hash, with a `<hex>.meta.json` sidecar carrying the
 * content type the hash was taken under. A capture nobody can produce is a
 * named diff on that entry, never a crash: an archive that has withdrawn a page
 * is a fact about the archive, and the reader is told which entry it touched.
 *
 * Three layouts are accepted, and each directory is checked as the one it
 * claims. `nomankind-mirror-v3` is what the export writes now: the same files,
 * with the release window applied (D-100). `nomankind-mirror-v2` is the layout
 * before the window, checked whole. A `nomankind-mirror-v1` directory — a copy
 * somebody pulled before the attestations, the standing, the ledger and the
 * sidecar's source class joined the export — is checked as what v1 was: the
 * seven files it has, and its entry sidecars on the keys a v1 sidecar carried. A
 * copy already in a stranger's hands is their exit, and a verifier that refused
 * it for being old would be taking that exit back. Any other format string is
 * `unsupported_format`.
 *
 * What a withheld line changes. A seal whose window has not run out is exported
 * as hash lines — the payload null, `withheld: true` beside it — and the chain
 * is checked over them exactly as over full events, minus the one check nobody
 * can make: an event whose payload nobody was given cannot have its hash
 * recomputed, so the links and the seal roots are what carry it. Everything
 * derived from a payload is then out of reach as well — the entries, the
 * attestations, the standing and the ledger are functions of what happened, not
 * of the hashes — so a clone that carries a withheld line has those checks
 * counted as `withheld` rather than passed, and the day the last window runs out
 * the same clone checks whole. That is not a hole a forged mirror fits through:
 * the chain, every seal, every anchor and every index row are checked either
 * way, and those are what an edited export breaks first.
 *
 * A legacy v0.6 record is never passed off as ok, and it is never waved
 * through either. It was sealed before the domain key existed and v0.7's rules
 * cannot be applied to bytes that never claimed them — but every rule that is
 * about the log rather than about v0.7 still holds over it, and those are the
 * ones an edited clone would break. So a legacy record is checked exactly as a
 * v0.7 one is for its core, its author's signature, the derivation of its
 * stored fields, its hash, its index row, the chain and the seal; only
 * `verifyOffline` — the captures, the decision records, the v0.7 rules — is
 * left off, and the line says so in words. A failed check on a legacy record is
 * a FAIL line and exit 1 like any other.
 *
 * After the entries come the three families the export recomputes rather than
 * reads: every `attestations/<id>.json` re-derived from the clone's own events
 * and then the whole set put through `verifyAttestations` — the ids, the score
 * signatures, the scorers, the hashes, the fold — then `standing.json`
 * recomputed through `standingAt` at the sealed head, then `ledger.jsonl`
 * recomputed and diffed line by line. Nothing in those three is anybody's word
 * for anything: they are functions of the events in the same clone, so an edited
 * file is a named pointer and a clean one needs no trust at all.
 *
 * Which is the point of the whole per-entry pass: the file's `entry` and
 * `sidecar` are re-derived from the mirror's own events at `as_of` with the
 * same kernel the export derived them with, so a clean clone matches byte for
 * byte and an edited status, tier or approver list is a named field rather than
 * a document nobody read.
 *
 * Exit 0 when nothing failed, 1 on any failure or an unreadable directory, 2 on
 * usage. Never a stack trace: a mirror is a stranger's directory, and a
 * stranger's bytes are always answered with a verdict.
 *
 * node:fs and node:path are allowed in this CLI file only; the kernel it hands
 * the work to stays Workers-safe.
 */

import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { verifyAnchor, type Anchor } from "../anchor.js";
import { coreVersion, domainOf, extractCore, type Core } from "../core.js";
import { deriveEntry, type DerivedEntry } from "../derive.js";
import { base64Encode } from "../encoding.js";
import { eventHash, type Event } from "../events.js";
import { canonicalize, entryHash } from "../hash.js";
import type { LedgerRow } from "../ledger.js";
import {
  mirrorAttestations,
  mirrorFormatOf,
  mirrorLedgerRows,
  mirrorStanding,
  sealFileName,
  v1Sidecar,
  type MirrorAttestationRecord,
  type MirrorFormat,
  type MirrorStanding,
} from "../mirror.js";
import { isReleased, isWithheld, releaseDateOf } from "../release.js";
import {
  sealsForEntries,
  verifySeal,
  type EntrySeal,
  type Seal,
} from "../seal.js";
import { verifyEntrySignature } from "../sign.js";
import {
  verifyAttestations,
  verifyOffline,
  type Capture,
  type LogBundle,
  type Registry,
} from "../verify.js";
import { captureHashes } from "./export.js";
import {
  getJson,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE =
  "usage: verify-mirror <mirror-dir> [--captures <url-or-dir>] [--entry <id>]";

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** The prefix a snapshot hash carries; the rest of it names the capture file. */
const HASH_PREFIX = "sha256:";

/** What one invocation asks for. */
export interface MirrorVerifyPlan {
  readonly dir: string;
  /** A base URL or a local directory, or null for `mirror.json`'s own base. */
  readonly captures: string | null;
  /** One entry id, or null for every entry in the directory. */
  readonly entry: string | null;
}

/**
 * The plan one invocation names, or null when the arguments are not one.
 *
 * Refuses rather than guesses, exactly as `npm run sync` does: a reader who
 * mistyped `--entry` should be told the usage rather than handed a run over a
 * directory they did not mean.
 */
export function mirrorVerifyPlan(
  args: readonly string[],
): MirrorVerifyPlan | null {
  const [dir, ...rest] = args;
  if (dir === undefined || dir.startsWith("--")) return null;

  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; ) {
    const flag = rest[index];
    if (flag !== "--captures" && flag !== "--entry") return null;
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(flag)) return null;
    values.set(flag, value);
    index += 2;
  }

  return {
    dir,
    captures: values.get("--captures") ?? null,
    entry: values.get("--entry") ?? null,
  };
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

/** A file of the mirror could not be read or was not what it claims to be. */
class MirrorUnreadable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MirrorUnreadable";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One JSON document of the mirror, read and parsed. */
async function readJson(path: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new MirrorUnreadable(`${path}: cannot read: ${reasonOf(error)}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new MirrorUnreadable(`${path}: not JSON: ${reasonOf(error)}`);
  }
}

/** One `.jsonl` file: a document per line, blank lines ignored. */
async function readLines(path: string): Promise<unknown[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new MirrorUnreadable(`${path}: cannot read: ${reasonOf(error)}`);
  }
  const values: unknown[] = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (line.length === 0) continue;
    try {
      values.push(JSON.parse(line) as unknown);
    } catch (error) {
      throw new MirrorUnreadable(
        `${path}:${index + 1}: not JSON: ${reasonOf(error)}`,
      );
    }
  }
  return values;
}

// ---------------------------------------------------------------------------
// The captures
// ---------------------------------------------------------------------------

/** Where the captures an entry names are read from. */
interface CaptureSource {
  /** A base URL ending in a slash, or null when the archive is local. */
  readonly base: string | null;
  /** A local directory, or null when the archive is served. */
  readonly dir: string | null;
}

/** Whether a `--captures` value names a server or a directory on this disk. */
function captureSource(value: string): CaptureSource {
  if (value.startsWith("http://") || value.startsWith("https://")) {
    return { base: value.endsWith("/") ? value : `${value}/`, dir: null };
  }
  return { base: null, dir: resolve(value) };
}

/** The file name a capture is archived under: the hex of its hash. */
function captureFileName(hash: string): string {
  return hash.startsWith(HASH_PREFIX) ? hash.slice(HASH_PREFIX.length) : hash;
}

/**
 * One capture from a served archive, as the verifier reads it.
 *
 * The sidecar's own `content-type` is the authority — it is the header the
 * hash was taken with — and the response's own stands in when the archive
 * serves no sidecar, exactly as `npm run export` reads one.
 */
async function fetchCapture(
  http: HttpClient,
  base: string,
  hash: string,
): Promise<Capture | null> {
  const url = `${base}${encodeURIComponent(hash)}`;
  let response: Response;
  try {
    response = await http.fetch(new Request(url));
  } catch {
    return null;
  }
  if (response.status !== 200) return null;
  const bytes = new Uint8Array(await response.arrayBuffer());

  let sidecarType: string | null = null;
  const sidecar = await getJson(http, url, `${url}/sidecar`);
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
 * One capture from a local archive: the bytes under the hex of the hash, and
 * the content type from the `.meta.json` beside them.
 *
 * A capture with no sidecar is read with a null content type, which is what the
 * norm rule reads as "no header was served", rather than being refused: an
 * operator's own archive is theirs to keep, and the hash is the check.
 */
async function loadCapture(dir: string, hash: string): Promise<Capture | null> {
  const name = captureFileName(hash);
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await readFile(join(dir, name)));
  } catch {
    return null;
  }

  let contentType: string | null = null;
  try {
    const meta = JSON.parse(
      await readFile(join(dir, `${name}.meta.json`), "utf8"),
    ) as unknown;
    if (isRecord(meta) && typeof meta["content_type"] === "string") {
      contentType = meta["content_type"];
    }
  } catch {
    contentType = null;
  }

  return { content_type: contentType, body_base64: base64Encode(bytes) };
}

/** Every capture one entry needs, from wherever this run reads them. */
async function capturesFor(
  entry: unknown,
  source: CaptureSource,
  http: HttpClient,
  held: Map<string, Capture>,
): Promise<Record<string, Capture>> {
  const captures: Record<string, Capture> = {};
  for (const hash of captureHashes(entry)) {
    const memoized = held.get(hash);
    if (memoized !== undefined) {
      captures[hash] = memoized;
      continue;
    }
    const capture =
      source.dir !== null
        ? await loadCapture(source.dir, hash)
        : source.base === null
          ? null
          : await fetchCapture(http, source.base, hash);
    if (capture === null) continue;
    held.set(hash, capture);
    captures[hash] = capture;
  }
  return captures;
}

// ---------------------------------------------------------------------------
// The mirror, read
// ---------------------------------------------------------------------------

/** Everything one directory holds, read once. */
interface Mirror {
  readonly manifest: Record<string, unknown>;
  /**
   * The layout the manifest claims, or null when it claims one nobody knows.
   *
   * An unknown format is a named failure on `mirror.json` and never a different
   * run: the directory is then checked as the current layout, which is the
   * strictest reading of it there is.
   */
  readonly format: MirrorFormat | null;
  readonly seals: Seal[];
  readonly anchors: Anchor[];
  readonly events: Event[];
  /**
   * The events the directory carries in full: the log it made public.
   *
   * What every derivation reads. The hash lines are in `events` and stay there,
   * because the chain, the seal roots and the inclusion proofs are over every
   * event's hash — a withheld line is a leaf like any other — while a fold over
   * payloads can only be over the payloads there are.
   */
  readonly full: Event[];
  readonly registry: Registry;
  readonly operatorCount: number;
  readonly index: Record<string, unknown>[];
  /**
   * The seqs the directory carries as hash lines (D-100).
   *
   * Empty for every v1 and v2 clone and for a v3 one whose windows have all run
   * out, which is why a released mirror is checked exactly as it always was.
   */
  readonly withheld: ReadonlySet<number>;
}

/** The registry the verifier needs, out of the mirror's own operators file. */
function registryOf(operators: unknown): {
  registry: Registry;
  count: number;
} {
  const agents: Record<string, string> = {};
  const records: Registry["operators"] = {};
  const rows =
    isRecord(operators) && Array.isArray(operators["operators"])
      ? operators["operators"]
      : [];
  for (const row of rows) {
    if (!isRecord(row) || typeof row["operator"] !== "string") continue;
    const id = row["operator"];
    const domains = row["domains"];
    records[id] = {
      maintainer: row["maintainer"] === true,
      provider: row["provider"] === true,
      ...(Array.isArray(domains)
        ? {
            domains: domains.filter(
              (one): one is string => typeof one === "string",
            ),
          }
        : {}),
    };
    const bound = row["agents"];
    if (!Array.isArray(bound)) continue;
    for (const agent of bound) {
      if (typeof agent === "string") agents[agent] = id;
    }
  }
  return { registry: { agents, operators: records }, count: rows.length };
}

/** Read one `<env>/` directory: the manifest and every file it names. */
async function readMirror(dir: string): Promise<Mirror> {
  const manifest = await readJson(join(dir, "mirror.json"));
  if (!isRecord(manifest)) {
    throw new MirrorUnreadable(`${join(dir, "mirror.json")}: not an object`);
  }

  const seals = (await readLines(join(dir, "seals.jsonl"))) as Seal[];
  const anchors = (await readLines(join(dir, "anchors.jsonl"))) as Anchor[];
  const ordered = [...seals].sort((left, right) => left.seq - right.seq);

  const events: Event[] = [];
  for (const seal of ordered) {
    events.push(
      ...((await readLines(join(dir, sealFileName(seal.seq)))) as Event[]),
    );
  }

  const operators = await readJson(join(dir, "operators.json"));
  const { registry, count } = registryOf(operators);

  const index = await readJson(join(dir, "index.json"));
  if (!Array.isArray(index)) {
    throw new MirrorUnreadable(`${join(dir, "index.json")}: not an array`);
  }

  const withheld = new Set<number>();
  for (const event of events) {
    if (isWithheld(event)) withheld.add(event.seq);
  }
  const full = events.filter((event) => !withheld.has(event.seq));

  return {
    manifest,
    format: mirrorFormatOf(manifest["format"]),
    seals: ordered,
    anchors,
    events,
    full,
    registry,
    operatorCount: count,
    index: index.filter(isRecord),
    withheld,
  };
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/** What the run counted, which is what the summary line says. */
interface Tally {
  ok: number;
  legacy: number;
  /** Checks the window put out of reach, which the next export puts back. */
  withheld: number;
  failed: number;
}

/** One check that did not hold, in the shape every failure line takes. */
function fail(
  io: ValidatorIo,
  tally: Tally,
  id: string,
  check: string,
  field: string,
  reason: string,
): void {
  tally.failed += 1;
  io.stdout(`FAIL ${id} ${check} ${field} ${reason}`);
}

/** One check the window put out of reach, in the shape every such line takes. */
function withhold(io: ValidatorIo, tally: Tally, id: string, note: string): void {
  tally.withheld += 1;
  io.stdout(`withheld ${id} ${note}`);
}

/**
 * Whether this directory is the older layout, and so carries three files fewer.
 *
 * A format nobody knows reads as the current layout: it has already failed on
 * `/format`, and the strictest reading of a directory nobody can place is the
 * one that asks it for everything.
 */
function isV1(mirror: Mirror): boolean {
  return mirror.format === "v1";
}

/**
 * The manifest, against the directory it describes.
 *
 * The counts are the point: a mirror whose `entries` does not equal the number
 * of entry files is a directory somebody edited, and every later check would
 * pass on the part that was left.
 *
 * The three counts v1 does not carry are not asked of a v1 manifest — there is
 * no attestations directory, no `standing.json` and no `ledger.jsonl` under it
 * to count — and every count that is about the log rather than about the newer
 * files is asked of both.
 */
function checkManifest(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
  recomputed: Recomputed,
): void {
  const manifest = mirror.manifest;
  let failures = 0;
  const wrong = (field: string, reason: string): void => {
    failures += 1;
    fail(io, tally, "mirror.json", "mirror", field, reason);
  };

  if (mirror.format === null) wrong("/format", "unsupported_format");
  if (typeof manifest["environment"] !== "string") {
    wrong("/environment", "missing");
  }
  if (manifest["seals"] !== mirror.seals.length) wrong("/seals", "count");
  if (manifest["events"] !== mirror.events.length) wrong("/events", "count");
  if (manifest["operators"] !== mirror.operatorCount) {
    wrong("/operators", "count");
  }
  if (manifest["entries"] !== mirror.index.length) wrong("/entries", "count");
  // The three counts a v1 manifest does not carry. All three are recomputed from
  // the clone's own public events, withheld lines or not, so all three are asked
  // of every layout that has them.
  if (!isV1(mirror)) {
    if (manifest["attestations"] !== recomputed.attestations.length) {
      wrong("/attestations", "count");
    }
    if (manifest["ledger_rows"] !== recomputed.ledger.length) {
      wrong("/ledger_rows", "count");
    }
    if (manifest["standing_position"] !== recomputed.standing.position) {
      wrong("/standing_position", "mismatch");
    }
  }

  // The window's own two fields, on the layout that has them. `released_head`
  // is checked against the seal files themselves, so a manifest edited to claim
  // more of the log is public than the directory carries fails here.
  if (mirror.format === "v3") {
    const window = manifest["release_window_days"];
    if (typeof window !== "number" || !Number.isInteger(window) || window < 0) {
      wrong("/release_window_days", "missing");
    }
    if (manifest["released_head"] !== releasedHeadOf(mirror)) {
      wrong("/released_head", "mismatch");
    }
  }

  const newest = mirror.seals[mirror.seals.length - 1];
  if (newest === undefined) {
    wrong("/head", "no_seal");
  } else {
    if (manifest["head"] !== newest.last_seq) wrong("/head", "mismatch");
    if (manifest["seal_seq"] !== newest.seq) wrong("/seal_seq", "mismatch");
    if (manifest["as_of"] !== newest.sealed_at) wrong("/as_of", "mismatch");
  }

  if (failures === 0) io.stdout("ok mirror.json");
}

/**
 * The event chain over every events file, in seq order, hash lines included.
 *
 * `verifyChain`'s three rules, with the one exception the window makes: seq runs
 * from 0 without a gap, every prev_hash is the hash before it, and every hash
 * recomputes — except a withheld line's, which nobody was given the payload to
 * recompute. Its hash is still the leaf the seal's Merkle root is over
 * (`checkSeals`), so an edited hash line is caught one check later; and the day
 * that seal releases, the same file is checked whole.
 */
async function checkChain(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
): Promise<void> {
  for (let index = 0; index < mirror.events.length; index += 1) {
    const event = mirror.events[index]!;
    const at = `/events/${index}`;
    if (event.seq !== index) {
      fail(io, tally, "events", "chain", at, "bad_seq");
      return;
    }
    const expectedPrev = index === 0 ? null : mirror.events[index - 1]!.hash;
    if (event.prev_hash !== expectedPrev) {
      fail(io, tally, "events", "chain", at, "bad_prev_hash");
      return;
    }
    if (mirror.withheld.has(event.seq)) continue;
    const { hash, ...fields } = event;
    if ((await eventHash(fields)) !== hash) {
      fail(io, tally, "events", "chain", at, "bad_hash");
      return;
    }
  }
  io.stdout("ok events");
}

/**
 * The largest position the directory carries in full, or null when it carries
 * none: what `mirror.json`'s `released_head` has to say.
 *
 * Read off the files rather than off a clock, which is the only honest reading
 * of somebody else's directory: a manifest that claims more released than the
 * seal files actually hold is a manifest somebody edited.
 */
function releasedHeadOf(mirror: Mirror): number | null {
  let head: number | null = null;
  for (const seal of releasedSeals(mirror)) {
    if (head === null || seal.last_seq > head) head = seal.last_seq;
  }
  return head;
}

/**
 * The seals whose every event the directory carries in full.
 *
 * What the offline verifier is handed beside the public events: a seal whose
 * batch is hash lines has a root over leaves this clone still has, but a
 * verifier asked to recompute it from payloads it was not given would call the
 * seal broken. `checkSeals` checks all of them over all the lines, which is
 * where that check belongs.
 */
function releasedSeals(mirror: Mirror): Seal[] {
  return mirror.seals.filter((seal) => {
    for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
      if (mirror.withheld.has(seq)) return false;
    }
    return true;
  });
}

/**
 * A withheld event whose release date has already passed: a stale export, which
 * the next run heals on its own.
 *
 * A warning and never a failure. The directory is a snapshot of a day, the
 * window ran out after it was written, and the next export writes that seal in
 * full — a verifier that failed the clone for it would be failing it for the
 * passage of time.
 */
function warnStale(io: ValidatorIo, mirror: Mirror, now: Date): void {
  let stale = 0;
  let earliest: string | null = null;
  for (const seal of mirror.seals) {
    if (!isReleased(seal.sealed_at, now)) continue;
    for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
      if (!mirror.withheld.has(seq)) continue;
      stale += 1;
      const date = releaseDateOf(seal.sealed_at);
      if (earliest === null || date < earliest) earliest = date;
    }
  }
  if (stale === 0) return;
  io.stdout(
    `warn mirror stale ${stale} withheld events released on ${String(earliest)}; the next export writes them in full`,
  );
}

/** Every seal, against the events it covers and the seal before it. */
async function checkSeals(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
): Promise<void> {
  let previous: Seal | null = null;
  for (const seal of mirror.seals) {
    const held = await verifySeal(mirror.events, seal, previous);
    if (held) io.stdout(`ok seal/${seal.seq}`);
    else fail(io, tally, `seal/${seal.seq}`, "seal", "/seals.jsonl", "bad_seal");
    previous = seal;
  }
}

/** Every anchor, against the day's seals in the chain beside it. */
async function checkAnchors(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
): Promise<void> {
  for (const anchor of mirror.anchors) {
    const held = await verifyAnchor(anchor, mirror.seals);
    if (held) io.stdout(`ok anchor/${anchor.date}`);
    else {
      fail(
        io,
        tally,
        `anchor/${anchor.date}`,
        "anchor",
        "/anchors.jsonl",
        "bad_anchor",
      );
    }
  }
}

/** Whether one stored entry was sealed before the domain key existed. */
function isLegacy(entry: unknown): boolean {
  try {
    return coreVersion(extractCore(entry)) === "v0.6";
  } catch {
    // A record whose core cannot even be extracted is not a legacy record; it
    // is a broken one, and `verifyOffline` is the thing that should say so.
    return false;
  }
}

/** What a `withheld` line says about an entry the window has not opened. */
const UNRELEASED_NOTE =
  "(not released yet; the export carries its proof and its index row, and " +
  "writes the entry file on its release date)";

/** What a `withheld` line says about a record the clone cannot re-derive. */
const UNDERIVABLE_NOTE =
  "(the clone carries a withheld event of its own, so nothing derived from a " +
  "payload is checked; the chain, the seals, the anchors and the index are)";

/** What the `legacy` line says, so the wording lives in one place. */
const LEGACY_NOTE =
  "(v0.6 record, not decided on again; core, signature, derivation, chain, " +
  "and seal checked; captures and records not, the verifier checks v0.7 only)";

/** The canonical form of a value, or a sentinel for one that has none. */
function safeCanonical(value: unknown): string {
  try {
    return canonicalize(value);
  } catch {
    return "<uncanonical>";
  }
}

/** One named difference: the JSON pointer it is at and the word for it. */
interface Difference {
  readonly field: string;
  readonly reason: string;
}

/**
 * The first field two objects disagree on, as a JSON pointer under `prefix`.
 *
 * The first and not all of them: a reader who edited one field wants to be told
 * which, and a reader who swapped a whole record does not need thirteen lines
 * to learn that it is not the one the log proves. Keys are walked in the
 * expected object's own order, so two runs over one clone name one field.
 */
function firstDifference(
  expected: Record<string, unknown>,
  actual: unknown,
  prefix: string,
): Difference | null {
  if (!isRecord(actual)) return { field: prefix, reason: "malformed" };
  for (const key of Object.keys(expected)) {
    // A key whose derived value is `undefined` is a key JSON does not write --
    // `domain` on a legacy core is exactly that, held as an absent value rather
    // than a null one (src/core.ts) -- so the file is right to carry none, and
    // wrong to carry one.
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

/** The `entry_submitted` event one id was sealed in, or null. */
function submissionOf(events: readonly Event[], id: string): Event | null {
  for (const event of events) {
    if (event.type !== "entry_submitted") continue;
    const payload = event.payload as unknown;
    if (!isRecord(payload)) continue;
    const core = payload["core"];
    if (isRecord(core) && core["id"] === id) return event;
  }
  return null;
}

/** The core an author actually signed, off the submission event. */
function sealedCore(event: Event): Record<string, unknown> | null {
  const payload = event.payload as unknown;
  if (!isRecord(payload)) return null;
  const core = payload["core"];
  return isRecord(core) ? core : null;
}

/** The seal covering a sealed position, or null when nothing does. */
function coveringSeal(seals: readonly Seal[], position: number): Seal | null {
  for (const seal of seals) {
    if (position >= seal.first_seq && position <= seal.last_seq) return seal;
  }
  return null;
}

/**
 * The row `index.json` must carry for one entry file, rebuilt from the file and
 * the mirror's own events rather than copied off the index.
 *
 * Every value here is read from somewhere other than the row it is checked
 * against -- the entry, its sidecar, the submission event's position, the seal
 * that covers it -- which is what makes the check a check: an index somebody
 * retouched to match an edited entry still disagrees with the log.
 */
function expectedIndexRow(
  file: Record<string, unknown>,
  entry: Record<string, unknown>,
  position: number,
  sealSeq: number | null,
  releaseDate: string | null | undefined,
): Record<string, unknown> {
  const sidecar = file["sidecar"];
  return {
    id: entry["id"],
    // A legacy core names no domain and means the default one, which is what
    // `domainOf` answers and what the export wrote.
    domain: domainOf(entry),
    subject: entry["subject"],
    category: entry["category"],
    status: entry["status"],
    tier: entry["evidence_tier"],
    effective_tier: isRecord(sidecar) ? sidecar["effective_tier"] : null,
    submitted_at: entry["submitted_at"],
    position,
    seal_seq: sealSeq,
    stale: entry["stale"],
    superseded_by: entry["superseded_by"],
    entry_hash: file["entry_hash"],
    // The column the window added (D-100), computed from the covering seal
    // rather than read off the row. `undefined` on the older layouts, which is
    // how `firstDifference` says a key must not be there at all.
    release_date: releaseDate,
  };
}

/**
 * The five checks every entry file gets, legacy or not.
 *
 * `derived` is the one that carries the others: the entry and its sidecar are
 * re-derived from the mirror's own events at the manifest's `as_of` with the
 * same kernel the export derived them with, so the comparison is against what
 * the log proves rather than against anything this command invented.
 * `entry_hash`, `index`, `core` and `signature` each close a door the
 * derivation alone leaves open -- a hash nobody recomputed, an index row nobody
 * read, a core swapped for one the log never sealed, a signature that never
 * covered these bytes.
 */
async function checkRecord(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
  id: string,
  file: Record<string, unknown>,
  entrySeals: ReadonlyMap<string, EntrySeal>,
  row: Record<string, unknown> | undefined,
): Promise<void> {
  const entry = file["entry"] as Record<string, unknown>;
  const asOf = mirror.manifest["as_of"];

  // derived: the entry and the sidecar, recomputed from the events.
  let derived: DerivedEntry | null = null;
  try {
    derived = deriveEntry(
      mirror.full,
      id,
      { now: typeof asOf === "string" ? asOf : "" },
      entrySeals,
    );
  } catch {
    fail(io, tally, id, "derived", "/entry", "underivable");
  }
  if (derived !== null) {
    // A v1 sidecar is compared on the keys a v1 sidecar had: `source` was
    // derived into it after that layout was written, so a v1 file is right to
    // carry none and the re-derivation is right to have one.
    const expectedSidecar = isV1(mirror)
      ? v1Sidecar(derived.sidecar)
      : derived.sidecar;
    const actualSidecar = isV1(mirror)
      ? v1Sidecar(file["sidecar"])
      : file["sidecar"];
    const difference =
      firstDifference(
        derived.entry as unknown as Record<string, unknown>,
        entry,
        "/entry",
      ) ??
      firstDifference(
        expectedSidecar as Record<string, unknown>,
        actualSidecar,
        "/sidecar",
      );
    if (difference !== null) {
      fail(io, tally, id, "derived", difference.field, difference.reason);
    }
  }

  // entry_hash: the file's own core, hashed again.
  let hash: string | null = null;
  try {
    hash = await entryHash(entry);
  } catch {
    hash = null;
  }
  if (hash === null) {
    fail(io, tally, id, "entry_hash", "/entry_hash", "no_core");
  } else if (file["entry_hash"] !== hash) {
    fail(io, tally, id, "entry_hash", "/entry_hash", "mismatch");
  }

  // core and index, both against the submission event's own position.
  const submitted = submissionOf(mirror.full, id);
  if (submitted === null) {
    fail(io, tally, id, "core", "/entry", "unsubmitted");
  } else {
    const covering = coveringSeal(mirror.seals, submitted.seq);
    const difference = firstDifference(
      expectedIndexRow(
        file,
        entry,
        submitted.seq,
        covering === null ? null : covering.seq,
        // `undefined` on the layouts that had no such column, which is how
        // `firstDifference` says a key must not be there at all.
        mirror.format !== "v3"
          ? undefined
          : covering === null
            ? null
            : releaseDateOf(covering.sealed_at),
      ),
      row,
      "/index",
    );
    if (difference !== null) {
      fail(io, tally, id, "index", difference.field, difference.reason);
    }

    const logCore = sealedCore(submitted);
    let stored: Core | null = null;
    try {
      stored = extractCore(entry);
    } catch {
      stored = null;
    }
    if (logCore === null || stored === null) {
      fail(io, tally, id, "core", "/entry", "no_core");
    } else {
      const core = firstDifference(logCore, stored, "/entry");
      if (core !== null) fail(io, tally, id, "core", core.field, core.reason);
    }
  }

  // signature: the author's own, over the core as the file carries it.
  if (!(await verifyEntrySignature(entry))) {
    fail(io, tally, id, "signature", "/entry/signature", "bad_signature");
  }
}

/**
 * The lines the inclusion proofs are folded over.
 *
 * Every event stays in the list, hash lines included, because a proof is over
 * the hashes of a seal's whole batch and a sibling nobody may read yet is still
 * a sibling. The one thing that is stood in for is a withheld submission's own
 * payload: the fold reads a submission's `core.id` to know which entry the proof
 * it just built belongs to, and null has no `core`. The proof built under that
 * empty core belongs to no entry and is never asked for, which is right — an
 * entry whose submission is still withheld has no file in this directory.
 */
function proofLines(mirror: Mirror): Event[] {
  if (mirror.withheld.size === 0) return mirror.events;
  return mirror.events.map((event) =>
    mirror.withheld.has(event.seq) && event.type === "entry_submitted"
      ? ({ ...event, payload: { core: {} } } as unknown as Event)
      : event,
  );
}

/** Every entry the directory holds, or the one `--entry` named. */
async function checkEntries(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
  dir: string,
  plan: MirrorVerifyPlan,
  http: HttpClient,
): Promise<void> {
  const base = mirror.manifest["captures_base"];
  const source =
    plan.captures !== null
      ? captureSource(plan.captures)
      : { base: typeof base === "string" ? base : null, dir: null };

  const ids: string[] = [];
  const rows = new Map<string, Record<string, unknown>>();
  for (const row of mirror.index) {
    const id = row["id"];
    if (typeof id !== "string") continue;
    ids.push(id);
    if (!rows.has(id)) rows.set(id, row);
  }
  const wanted =
    plan.entry === null ? ids : ids.filter((id) => id === plan.entry);
  if (plan.entry !== null && wanted.length === 0) {
    fail(io, tally, plan.entry, "entry", "/index.json", "not_in_mirror");
    return;
  }

  const asOf = mirror.manifest["as_of"];
  const held = new Map<string, Capture>();
  // One pass over the whole sealed log, shared by every entry: the inclusion
  // proofs are a fact about the seals rather than about which entry is asked.
  const entrySeals = await sealsForEntries(proofLines(mirror), mirror.seals);
  // The entries some event of whose own the clone carries only as a hash line.
  const withheldEntries = new Set<string>();
  for (const event of mirror.events) {
    if (!mirror.withheld.has(event.seq)) continue;
    if (typeof event.entry_id === "string") withheldEntries.add(event.entry_id);
  }

  for (const id of wanted) {
    // An entry whose own submission is still a hash line has no file yet, and
    // one whose own later events are hash lines cannot be re-derived from the
    // clone: both are `withheld` rather than a pass or a failure, and both heal
    // on their own. An entry every one of whose events is here is checked
    // exactly as it is in a mirror with nothing withheld at all -- a lifecycle
    // is the sub-sequence of the log bearing the entry's id, and this clone
    // holds all of it.
    const position = rows.get(id)?.["position"];
    if (typeof position === "number" && mirror.withheld.has(position)) {
      withhold(io, tally, id, UNRELEASED_NOTE);
      continue;
    }
    if (withheldEntries.has(id)) {
      withhold(io, tally, id, UNDERIVABLE_NOTE);
      continue;
    }
    const file = await readJson(join(dir, "entries", `${id}.json`));
    if (!isRecord(file) || !isRecord(file["entry"])) {
      fail(io, tally, id, "entry", "/entry", "malformed");
      continue;
    }
    const entry = file["entry"];

    const before = tally.failed;
    await checkRecord(io, tally, mirror, id, file, entrySeals, rows.get(id));

    if (isLegacy(entry)) {
      // Never `ok`, and never waved through either: the checks above have
      // already run, and any FAIL line they wrote stands beside this one.
      tally.legacy += 1;
      io.stdout(`legacy ${id} ${LEGACY_NOTE}`);
      continue;
    }

    const bundle: LogBundle = {
      as_of: typeof asOf === "string" ? asOf : "",
      events: mirror.full,
      registry: mirror.registry,
      seals: releasedSeals(mirror),
      captures: await capturesFor(entry, source, http, held),
    };

    const report = await verifyOffline(entry, bundle);
    if (report.ok) {
      if (tally.failed === before) {
        tally.ok += 1;
        io.stdout(`ok ${id}`);
      }
      continue;
    }
    for (const diff of report.diffs) {
      fail(io, tally, id, diff.check, diff.field, diff.reason);
    }
  }
}

// ---------------------------------------------------------------------------
// The attestations, standing, and the ledger
// ---------------------------------------------------------------------------

/**
 * The three families the export recomputes rather than reads, recomputed again
 * here from the clone's own events. A file that does not match is a file
 * somebody edited: nothing in these three is anybody's word for anything.
 */
interface Recomputed {
  readonly attestations: MirrorAttestationRecord[];
  readonly standing: MirrorStanding;
  readonly ledger: LedgerRow[];
}

/**
 * The sealed head the clone's own seal chain ends at, and the instant every
 * derivation in it was taken at.
 *
 * Read off the newest seal rather than off the manifest, which is the thing
 * being checked: `checkManifest` holds the manifest's `head` and `as_of` against
 * these two, so a manifest edited to agree with an edited file still fails.
 */
function headOf(mirror: Mirror): { head: number; asOf: string } {
  const newest = mirror.seals[mirror.seals.length - 1];
  return newest === undefined
    ? { head: -1, asOf: "" }
    : { head: newest.last_seq, asOf: newest.sealed_at };
}

/**
 * Everything the three families come to for one clone.
 *
 * Over the events the directory carries in full and at the released head, which
 * is how the export folds them (src/mirror.ts): all three are folds over
 * payloads, so they are folds over the payloads that are public, and that is
 * what makes them checkable at all. A clone with nothing withheld in it is a
 * clone whose released head is its sealed head, and this is then exactly the
 * fold it always was.
 */
function recompute(mirror: Mirror): Recomputed {
  const head = releasedHeadOf(mirror) ?? -1;
  const public_ = releasedSeals(mirror);
  const newest = public_[public_.length - 1];
  const asOf = newest === undefined ? "" : newest.sealed_at;
  const events = mirror.full.filter((event) => event.seq <= head);
  return {
    // No answers: the model's answers are not in the log, so what is recomputed
    // is the derived attestation and never the answers beside it.
    attestations: mirrorAttestations(events, [], asOf),
    standing: mirrorStanding(events, head),
    ledger: mirrorLedgerRows(events, asOf),
  };
}

/**
 * Every attestation file, re-derived from the clone's own events and diffed,
 * and then the whole set through `verifyAttestations`.
 *
 * Two different questions. The first is whether the file says what the events
 * say — an edited status, score or scorer list is a named field. The second is
 * whether the events themselves hold up: the id over its request, each score's
 * signature, each scorer's standing to sign, the hashes, the fold. The first is
 * about the copy and the second is about the log, and a clone can fail either.
 */
async function checkAttestations(
  io: ValidatorIo,
  tally: Tally,
  mirror: Mirror,
  dir: string,
  recomputed: Recomputed,
): Promise<void> {
  for (const record of recomputed.attestations) {
    const id = record.attestation.id;
    const name = `attestation/${id}`;
    const file = await readJson(join(dir, "attestations", `${id}.json`));
    if (!isRecord(file)) {
      fail(io, tally, name, "attestation", "/attestation", "malformed");
      continue;
    }
    const difference = firstDifference(
      record.attestation as unknown as Record<string, unknown>,
      file["attestation"],
      "/attestation",
    );
    if (difference !== null) {
      fail(io, tally, name, "attestation", difference.field, difference.reason);
      continue;
    }
    // The answers are the one thing the log does not carry, so the file is only
    // held to carrying the key: what they hash to is the score records' problem,
    // and `verifyAttestations` below is what asks that question.
    if (!Object.prototype.hasOwnProperty.call(file, "answers")) {
      fail(io, tally, name, "attestation", "/answers", "missing");
      continue;
    }
    io.stdout(`ok ${name}`);
  }

  const { asOf } = headOf(mirror);
  const report = await verifyAttestations({
    as_of: asOf,
    events: mirror.full,
    registry: mirror.registry,
    seals: releasedSeals(mirror),
    // The attestation checks are about signatures, scorers and hashes; no
    // capture is named by any of them.
    captures: {},
  });
  if (report.ok) {
    io.stdout(`ok attestations ${report.attestations.length}`);
    return;
  }
  for (const one of report.attestations) {
    for (const diff of one.diffs) {
      fail(io, tally, `attestation/${one.id}`, diff.check, diff.field, diff.reason);
    }
  }
}

/** `standing.json`, recomputed through `standingAt` over the clone's events. */
async function checkStanding(
  io: ValidatorIo,
  tally: Tally,
  dir: string,
  recomputed: Recomputed,
): Promise<void> {
  const actual = await readJson(join(dir, "standing.json"));
  const expected = recomputed.standing as unknown as Record<string, unknown>;
  if (!isRecord(actual)) {
    fail(io, tally, "standing", "standing", "/standing", "malformed");
    return;
  }

  // The operators row by row before the document as a whole, so an edited
  // number names the operator it was edited on rather than the whole list.
  const rows = actual["operators"];
  if (Array.isArray(rows)) {
    for (let index = 0; index < recomputed.standing.operators.length; index += 1) {
      const one = recomputed.standing.operators[index]!;
      const difference = firstDifference(
        one as unknown as Record<string, unknown>,
        rows[index],
        `/operators/${index}`,
      );
      if (difference === null) continue;
      fail(io, tally, "standing", "standing", difference.field, difference.reason);
      return;
    }
    if (rows.length !== recomputed.standing.operators.length) {
      fail(io, tally, "standing", "standing", "/operators", "count");
      return;
    }
  }

  const difference = firstDifference(expected, actual, "");
  if (difference !== null) {
    fail(io, tally, "standing", "standing", difference.field, difference.reason);
    return;
  }
  io.stdout("ok standing");
}

/** `ledger.jsonl`, recomputed from the clone's events and diffed line by line. */
async function checkLedger(
  io: ValidatorIo,
  tally: Tally,
  dir: string,
  recomputed: Recomputed,
): Promise<void> {
  const actual = await readLines(join(dir, "ledger.jsonl"));
  for (let index = 0; index < recomputed.ledger.length; index += 1) {
    const row = recomputed.ledger[index]!;
    if (index >= actual.length) {
      fail(io, tally, "ledger", "ledger", `/${index}`, "missing");
      return;
    }
    const difference = firstDifference(
      row as unknown as Record<string, unknown>,
      actual[index],
      `/${index}`,
    );
    if (difference === null) continue;
    fail(io, tally, "ledger", "ledger", difference.field, difference.reason);
    return;
  }
  if (actual.length > recomputed.ledger.length) {
    fail(
      io,
      tally,
      "ledger",
      "ledger",
      `/${recomputed.ledger.length}`,
      "unexpected",
    );
    return;
  }
  io.stdout("ok ledger");
}

/**
 * Check one mirror directory.
 *
 * Returns the process's exit code: 0 when nothing failed, 1 on any failure or
 * an unreadable directory, 2 when the command was called wrong.
 */
export async function verifyMirror(
  args: readonly string[],
  io: ValidatorIo,
  http: HttpClient = new WebHttpClient(),
  now: Date = new Date(),
): Promise<number> {
  const plan = mirrorVerifyPlan(args);
  if (plan === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const dir = resolve(plan.dir);

  let mirror: Mirror;
  try {
    mirror = await readMirror(dir);
  } catch (error) {
    io.stderr(
      error instanceof MirrorUnreadable
        ? error.message
        : `${dir}: cannot read: ${reasonOf(error)}`,
    );
    return FAILED;
  }

  const tally: Tally = { ok: 0, legacy: 0, withheld: 0, failed: 0 };
  try {
    const recomputed = recompute(mirror);
    checkManifest(io, tally, mirror, recomputed);
    await checkChain(io, tally, mirror);
    await checkSeals(io, tally, mirror);
    await checkAnchors(io, tally, mirror);
    await checkEntries(io, tally, mirror, dir, plan, http);
    // The three families a v1 directory does not carry are not asked of one:
    // the layout it claims is the layout it is checked as.
    if (!isV1(mirror)) {
      await checkAttestations(io, tally, mirror, dir, recomputed);
      await checkStanding(io, tally, dir, recomputed);
      await checkLedger(io, tally, dir, recomputed);
    }
    warnStale(io, mirror, now);
  } catch (error) {
    io.stderr(
      error instanceof MirrorUnreadable
        ? error.message
        : `${dir}: cannot verify: ${reasonOf(error)}`,
    );
    return FAILED;
  }

  const environment = mirror.manifest["environment"];
  io.stdout(
    [
      "summary",
      typeof environment === "string" ? environment : "unknown",
      `head ${String(mirror.manifest["head"])}`,
      `seals ${mirror.seals.length}`,
      `anchors ${mirror.anchors.length}`,
      `entries ${mirror.index.length}`,
      `ok ${tally.ok}`,
      `legacy ${tally.legacy}`,
      `withheld ${tally.withheld}`,
      `failed ${tally.failed}`,
    ].join(" "),
  );
  return tally.failed === 0 ? OK : FAILED;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(
    await verifyMirror(process.argv.slice(2), {
      stdout: (line: string) => console.log(line),
      stderr: (line: string) => console.error(line),
    }),
  );
}
/* c8 ignore stop */

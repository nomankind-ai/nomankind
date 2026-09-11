/**
 * read: the reader's side of the frozen reader, and of the receipt.
 *
 * Whitepaper Section 8, "The frozen reader": a reader asks for one fact and is
 * handed one entry with "a signed read receipt naming the entry, the time, and a
 * running counter". Section 9, Money: readers keep those receipts and "can
 * compare the receipts they hold against the published counts". A receipt only
 * carries that weight if the reader checks it at the moment it is handed over,
 * which is what this command is: one read, and then every check the reader could
 * make later, made now, before the answer is believed.
 *
 * Four checks, in one fixed order, stopping at the first failure:
 *
 *   receipt_entry       the receipt names the entry that was served
 *   entry_hash          the receipt's entry_hash is the served core's own hash
 *   receipt_signature   the issuer's key signed exactly those five fields
 *   seal                the entry's submission event is in the sealed batch
 *
 * The order is the order of what each check would let through. A receipt for
 * another entry is not evidence about this one at all; a receipt naming this
 * entry but hashing a different version of it is a receipt for an answer the
 * reader was not given; a signature nobody made proves nothing about either; and
 * only once the receipt is sound is it worth asking whether the log has sealed
 * the entry it names. The seal check is the whole offline chain, walked over the
 * wire: the submission event is fetched from the public log at the position the
 * entry's seal object names, its hash is recomputed from its own fields rather
 * than trusted, and that recomputed hash is what the inclusion proof is verified
 * against the seal's Merkle root. Nothing in the answer is taken on the serving
 * side's word.
 *
 * An unsealed entry passes the seal check rather than failing it. Section 6
 * seals in batches, so an entry read between its submission and the next sweep
 * is honestly unsealed; the printed line says so, and the reader can come back.
 *
 * Reads are unauthenticated, so this command holds no key and signs nothing.
 * The core is exported over the injected http client, so a test drives it in
 * process with no network. node:path is allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { extractCore } from "../core.js";
import { eventHash, type Event } from "../events.js";
import { entryHash } from "../hash.js";
import { decodeProof, verifyInclusion } from "../merkle.js";
import { verifyReadReceipt } from "../receipt.js";
import {
  errorOf,
  getJson,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE =
  "usage: read <base-url> <entry-id> [--key <secret>] | read <base-url> --subject <subject> --category <category> [--domain <slug>] [--min-tier <tier>] [--max-age <days>] [--key <secret>]";

/** The checks, in the order they are made. The order is the contract. */
export const READ_CHECKS = [
  "receipt_entry",
  "entry_hash",
  "receipt_signature",
  "seal",
] as const;

export type ReadCheck = (typeof READ_CHECKS)[number];

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The key one invocation presents, or null when it reads on the free tier.
 *
 * Read out of the arguments and never out of the environment: a credential
 * picked up from an ambient variable is a credential nobody knows was sent.
 */
export function readKey(args: readonly string[]): string | null {
  const at = args.indexOf("--key");
  if (at === -1) return null;
  const value = args[at + 1];
  if (value === undefined || value.startsWith("--")) return null;
  return value;
}

/**
 * The client one invocation reads through: the caller's own, or the caller's
 * with the bearer header on every request it makes.
 *
 * A wrapper rather than a second fetch path, so the seal check's events read
 * goes out the same way the read did — one client, one place the header is
 * added, and nothing anywhere else in this file has to know about the key.
 */
export function withKey(http: HttpClient, key: string | null): HttpClient {
  if (key === null) return http;
  return {
    async fetch(request: Request): Promise<Response> {
      const headers = new Headers(request.headers);
      headers.set("authorization", `Bearer ${key}`);
      return http.fetch(new Request(request, { headers }));
    },
  };
}

/**
 * The path one invocation reads, or null when the arguments are not a read.
 *
 * Refuses rather than guesses: an unknown flag is refused because a reader who
 * misspelt `--min-tier` would otherwise be handed an answer that quietly
 * ignored their demand, which is the same reason src/read.ts refuses an unknown
 * query parameter. Parsing happens before any I/O, so a bad invocation never
 * touches the network.
 */
export function readPath(args: readonly string[]): string | null {
  const [baseArg, ...rest] = args;
  if (baseArg === undefined || baseArg.startsWith("--")) return null;

  const first = rest[0];
  if (first !== undefined && !first.startsWith("--")) {
    // The by-id form: one positional entry id, and at most the key beside it.
    const after = rest.slice(1);
    if (after.length !== 0 && (after.length !== 2 || after[0] !== "--key")) {
      return null;
    }
    if (after.length === 2 && after[1]!.startsWith("--")) return null;
    return `/read/${encodeURIComponent(first)}`;
  }

  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (flag === undefined || value === undefined) return null;
    if (value.startsWith("--")) return null;
    if (values.has(flag)) return null;
    values.set(flag, value);
  }

  const known = [
    "--subject",
    "--category",
    "--domain",
    "--min-tier",
    "--max-age",
    // The key is sent as a header, never as a query parameter: a credential in
    // a URL is a credential in somebody's access log.
    "--key",
  ];
  for (const flag of values.keys()) {
    if (!known.includes(flag)) return null;
  }

  const subject = values.get("--subject");
  const category = values.get("--category");
  if (subject === undefined || category === undefined) return null;

  // The query parameters src/read.ts names, in that order and no others.
  const params = new URLSearchParams();
  params.set("subject", subject);
  params.set("category", category);
  // Decision D-071: absent means the reader named no domain and every domain's
  // entries about that subject are candidates, which is what a client written
  // before v0.7 asks for.
  const domain = values.get("--domain");
  if (domain !== undefined) params.set("domain", domain);
  const minTier = values.get("--min-tier");
  if (minTier !== undefined) params.set("min_tier", minTier);
  const maxAge = values.get("--max-age");
  if (maxAge !== undefined) params.set("max_age", maxAge);
  return `/read?${params.toString()}`;
}

/**
 * The seal check: the submission event at the sealed position, rehashed, and
 * proved into the seal's root.
 *
 * Every step is done from what came back rather than from what was claimed. The
 * event's own hash field is recomputed with eventHash over its fields, so an
 * event edited in flight fails here rather than being fed to the proof as a
 * leaf; and the proof is decoded from the entry's own seal object, so a
 * malformed proof is a failed check rather than a crash.
 */
async function sealHolds(
  http: HttpClient,
  baseUrl: string,
  entrySeal: Record<string, unknown>,
  seal: unknown,
): Promise<boolean> {
  if (!isRecord(seal) || typeof seal["root"] !== "string") return false;

  const position = entrySeal["position"];
  if (!Number.isSafeInteger(position) || (position as number) < 0) return false;
  const seq = position as number;

  const proof = decodeProof(
    typeof entrySeal["inclusion_proof"] === "string"
      ? entrySeal["inclusion_proof"]
      : "",
  );
  if (proof === null) return false;

  // `after` is exclusive and seq 0 is a real position, so the first event is
  // asked for by omitting `after` rather than by writing -1.
  const query =
    seq === 0 ? "/events?limit=1" : `/events?after=${seq - 1}&limit=1`;
  const page = await getJson(http, baseUrl, query);
  if (page.status !== 200 || !isRecord(page.body)) return false;
  const events = page.body["events"];
  if (!Array.isArray(events) || events.length !== 1) return false;

  const event = events[0] as Event;
  if (!isRecord(event) || event.seq !== seq) return false;
  const recomputed = await eventHash({
    seq: event.seq,
    at: event.at,
    type: event.type,
    entry_id: event.entry_id,
    payload: event.payload,
    prev_hash: event.prev_hash,
  });
  if (recomputed !== event.hash) return false;

  return verifyInclusion(recomputed, proof, seal["root"]);
}

/**
 * Read one entry and check the receipt it came with.
 *
 * Returns the process's exit code: 2 on arguments that are not a read, 1 on a
 * refusal or a failed check, 0 when every check held.
 */
export async function runRead(
  args: readonly string[],
  http: HttpClient,
  io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  },
): Promise<number> {
  const path = readPath(args);
  if (path === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const baseUrl = args[0] as string;
  // Every request this run makes goes out on the same tier, the reader's own.
  const client = withKey(http, readKey(args));

  const answer = await getJson(client, baseUrl, path);
  if (answer.status !== 200) {
    const error = errorOf(answer.body) ?? "unknown";
    let line = `refused ${answer.status} ${error}`;
    if (answer.status === 409 && isRecord(answer.body)) {
      const status = answer.body["status"];
      const superseded = answer.body["superseded_by"];
      line += ` status ${typeof status === "string" ? status : "none"}`;
      line += ` superseded_by ${
        typeof superseded === "string" ? superseded : "none"
      }`;
    }
    io.stdout(line);
    return FAILED;
  }

  const failed = (check: ReadCheck): number => {
    io.stdout(`failed ${check}`);
    return FAILED;
  };

  const body = isRecord(answer.body) ? answer.body : {};
  const entry = isRecord(body["entry"]) ? body["entry"] : {};
  const receipt = isRecord(body["receipt"]) ? body["receipt"] : {};
  const sidecar = isRecord(body["sidecar"]) ? body["sidecar"] : {};

  const entryId = entry["id"];
  if (typeof entryId !== "string" || receipt["entry_id"] !== entryId) {
    return failed("receipt_entry");
  }

  let hash: string;
  try {
    hash = await entryHash(extractCore(entry));
  } catch {
    return failed("entry_hash");
  }
  if (receipt["entry_hash"] !== hash) return failed("entry_hash");

  if (!(await verifyReadReceipt(receipt))) return failed("receipt_signature");

  const entrySeal = entry["seal"];
  const sealed = isRecord(entrySeal);
  if (sealed && !(await sealHolds(client, baseUrl, entrySeal, body["seal"]))) {
    return failed("seal");
  }

  const status = entry["status"];
  const tier = sidecar["effective_tier"];
  io.stdout(
    [
      `ok ${entryId}`,
      `status ${typeof status === "string" ? status : "none"}`,
      `tier ${typeof tier === "string" ? tier : "none"}`,
      `counter ${String(receipt["counter"])}`,
      // The key's own counter, printed only when the receipt carries one: a
      // free read has none, and a line that said "none" would invite the reader
      // to look for a number that was never owed.
      ...(typeof receipt["key_counter"] === "number"
        ? [`key_counter ${String(receipt["key_counter"])}`]
        : []),
      `issuer ${String(receipt["issuer"])}`,
      `seal ${sealed ? "sealed" : "unsealed"}`,
    ].join(" "),
  );
  return OK;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(await runRead(process.argv.slice(2), new WebHttpClient()));
}
/* c8 ignore stop */

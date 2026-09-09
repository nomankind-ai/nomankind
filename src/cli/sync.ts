/**
 * sync: the trainer's side of the delta stream, and of the sync receipt.
 *
 * Whitepaper Section 8, "The delta stream": a training run does not re-download
 * the corpus, it asks for everything the log learned after a position it already
 * holds and is handed those events in sealed order, with the new head and one
 * signed receipt covering what was delivered. Section 9, Money: each delivered
 * verified entry counts as a read, and the receipts a trainer keeps are what it
 * later holds against the published counts.
 *
 * A page of the stream is only worth resuming from if it was checked at the
 * moment it arrived. This command is that check: one page, and then every check
 * a trainer could make later, made now, before a single event is ingested.
 *
 * Five checks, in one fixed order, stopping at the first failure:
 *
 *   chain              every delivered event rehashes, and consecutive ones link
 *   proofs             every event is proved into a seal the log still answers
 *   receipt_entries    the receipt names exactly the entries that were delivered
 *   receipt_signature  the issuer's key signed exactly those seven fields
 *   identical          a second ask of the same question answers the same page
 *
 * The order is the order of what each check would let through. Events whose
 * hashes do not recompute are not evidence about anything, so nothing is proved
 * into a root until they do; a proof against a root the log will not stand
 * behind proves nothing either; only once the page is sound is it worth asking
 * whether the receipt bills for the page that was actually served, and only once
 * the receipt says the right thing is its signature worth checking. `identical`
 * is last and optional because it costs a second request: Section 8's ordering
 * promise is that two trainers resuming from the same `from` are handed the same
 * events forever, and `--twice` is that promise tested against the one serving
 * side that could break it.
 *
 * The stream is unauthenticated, so this command holds no key and signs nothing.
 * The core is exported over the injected http client, so a test drives it in
 * process with no network. node:path is allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { extractCore } from "../core.js";
import { eventHash, type Event } from "../events.js";
import { entryHash } from "../hash.js";
import { decodeProof, verifyInclusion } from "../merkle.js";
import { verifySyncReceipt } from "../receipt.js";
import {
  getJson,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE =
  "usage: sync <base-url> [--from <n>] [--limit <n>] [--flatten] [--min-tier <tier>] [--twice]";

/** The checks, in the order they are made. The order is the contract. */
export const SYNC_CHECKS = [
  "chain",
  "proofs",
  "receipt_entries",
  "receipt_signature",
  "identical",
] as const;

export type SyncCheck = (typeof SYNC_CHECKS)[number];

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** Flags that carry a value, and flags that are their own answer. */
const VALUED_FLAGS = ["--from", "--limit", "--min-tier"];
const BARE_FLAGS = ["--flatten", "--twice"];

/** A non-negative integer in plain decimal, as src/sync.ts reads one. */
const INTEGER_PATTERN = /^(0|[1-9][0-9]*)$/;

/** What one invocation asks for: a path to fetch, and whether to ask twice. */
export interface SyncPlan {
  readonly path: string;
  readonly twice: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The page one invocation asks for, or null when the arguments are not a sync.
 *
 * Refuses rather than guesses, for the same reason src/sync.ts refuses an
 * unknown query parameter: a trainer who misspelt `--min-tier` would otherwise
 * be handed a stream that quietly ignored the demand and told itself it had
 * filtered. Parsing happens before any I/O, so a bad invocation never touches
 * the network.
 */
export function syncPlan(args: readonly string[]): SyncPlan | null {
  const [baseArg, ...rest] = args;
  if (baseArg === undefined || baseArg.startsWith("--")) return null;

  const values = new Map<string, string>();
  const switches = new Set<string>();
  for (let index = 0; index < rest.length; ) {
    const flag = rest[index];
    if (flag === undefined || !flag.startsWith("--")) return null;
    if (BARE_FLAGS.includes(flag)) {
      if (switches.has(flag)) return null;
      switches.add(flag);
      index += 1;
      continue;
    }
    if (!VALUED_FLAGS.includes(flag)) return null;
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(flag)) return null;
    values.set(flag, value);
    index += 2;
  }

  // A sealed position and a page size are integers or they are nothing: a
  // trainer who wrote `--from yesterday` gets the usage, not a page from 0.
  for (const flag of ["--from", "--limit"]) {
    const written = values.get(flag);
    if (written === undefined) continue;
    if (!INTEGER_PATTERN.test(written)) return null;
    if (!Number.isSafeInteger(Number(written))) return null;
  }

  // The query parameters src/sync.ts names, in that order and no others.
  const params = new URLSearchParams();
  const from = values.get("--from");
  if (from !== undefined) params.set("from", from);
  const limit = values.get("--limit");
  if (limit !== undefined) params.set("limit", limit);
  if (switches.has("--flatten")) params.set("flatten", "true");
  const minTier = values.get("--min-tier");
  if (minTier !== undefined) params.set("min_tier", minTier);

  const query = params.toString();
  return {
    path: query.length === 0 ? "/sync" : `/sync?${query}`,
    twice: switches.has("--twice"),
  };
}

/** The reason a refusal named. Refusals carry `reason`; `error` is the fallback. */
function reasonOf(body: unknown): string {
  if (!isRecord(body)) return "unknown";
  const reason = body["reason"] ?? body["error"];
  return typeof reason === "string" ? reason : "unknown";
}

// ---------------------------------------------------------------------------
// One delivered item, as much of it as the checks need
// ---------------------------------------------------------------------------

interface Item {
  readonly kind: "entry" | "unlearn" | "event";
  readonly event: Event;
  readonly sealSeq: number;
  readonly inclusionProof: string;
  readonly entry: unknown;
  readonly entryHash: unknown;
}

/**
 * Read one item of the page, or null when it is not one.
 *
 * A malformed item is a failed `chain` rather than a crash: the trainer is
 * being handed a page by a serving side it does not trust, and garbage in that
 * page is an answer about the page, not an exception.
 */
function readItem(value: unknown): Item | null {
  if (!isRecord(value)) return null;
  const kind = value["kind"];
  if (kind !== "entry" && kind !== "unlearn" && kind !== "event") return null;

  const event = value["event"];
  if (!isRecord(event)) return null;
  if (!Number.isSafeInteger(event["seq"])) return null;
  if (typeof event["hash"] !== "string") return null;

  const proof = value["proof"];
  if (!isRecord(proof)) return null;
  const sealSeq = proof["seal_seq"];
  if (!Number.isSafeInteger(sealSeq)) return null;
  const inclusion = proof["inclusion_proof"];
  if (typeof inclusion !== "string") return null;

  return {
    kind,
    event: event as unknown as Event,
    sealSeq: sealSeq as number,
    inclusionProof: inclusion,
    entry: value["entry"] ?? null,
    entryHash: value["entry_hash"] ?? null,
  };
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

/**
 * chain: every delivered event's hash is recomputed from its own fields, and
 * two events delivered at consecutive seqs link.
 *
 * Recomputing is the point: an event edited in flight fails here rather than
 * being fed to a Merkle proof as a leaf. The link is only asserted for
 * consecutive seqs because a filtered page legitimately has holes — Section 8's
 * `flatten` and `min_tier` drop entries the trainer did not ask for — and a
 * missing neighbour is not evidence that the chain is broken.
 */
async function chainHolds(items: readonly Item[]): Promise<boolean> {
  for (let index = 0; index < items.length; index += 1) {
    const event = items[index]!.event;
    const recomputed = await eventHash({
      seq: event.seq,
      at: event.at,
      type: event.type,
      entry_id: event.entry_id,
      payload: event.payload,
      prev_hash: event.prev_hash,
    });
    if (recomputed !== event.hash) return false;
    if (index === 0) continue;
    const earlier = items[index - 1]!.event;
    if (event.seq !== earlier.seq + 1) continue;
    if (event.prev_hash !== earlier.hash) return false;
  }
  return true;
}

/**
 * proofs: every item is proved into the root of the seal its proof names, and
 * that seal's root is what the log still answers for it.
 *
 * The second half is what stops a page being self-consistent and false. A
 * serving side could hand over a batch of invented events under an invented
 * root and prove every one of them into it; asking `/seals/{seq}` for the root
 * separately is asking the log to stand behind the same number twice. Each
 * named seal is asked for once.
 */
async function proofsHold(
  http: HttpClient,
  baseUrl: string,
  items: readonly Item[],
  seals: readonly unknown[],
): Promise<boolean> {
  const roots = new Map<number, string>();
  for (const seal of seals) {
    if (!isRecord(seal)) return false;
    const seq = seal["seq"];
    const root = seal["root"];
    if (!Number.isSafeInteger(seq) || typeof root !== "string") return false;
    if (roots.has(seq as number)) return false;
    roots.set(seq as number, root);
  }

  const confirmed = new Set<number>();
  for (const item of items) {
    const root = roots.get(item.sealSeq);
    if (root === undefined) return false;
    const proof = decodeProof(item.inclusionProof);
    if (proof === null) return false;
    if (!(await verifyInclusion(item.event.hash, proof, root))) return false;

    if (confirmed.has(item.sealSeq)) continue;
    const answered = await getJson(http, baseUrl, `/seals/${item.sealSeq}`);
    if (answered.status !== 200 || !isRecord(answered.body)) return false;
    if (answered.body["seq"] !== item.sealSeq) return false;
    if (answered.body["root"] !== root) return false;
    confirmed.add(item.sealSeq);
  }
  return true;
}

/** One entry the page delivered: which entry, which version, what status. */
interface Delivered {
  readonly entry_id: string;
  readonly entry_hash: string;
  readonly status: string;
}

/**
 * The distinct entries the page delivered, in first-delivery order, or null
 * when an item does not name one it can prove.
 *
 * Distinct, because one entry is touched by several events in a page — a
 * submission and two validations — and a receipt naming it three times would be
 * a bill for three deliveries of one entry. The hash is recomputed from the
 * served entry's own core, so the receipt names the version the trainer was
 * actually handed rather than the version the serving side said it handed over.
 */
async function deliveredEntries(
  items: readonly Item[],
): Promise<Delivered[] | null> {
  const seen = new Set<string>();
  const delivered: Delivered[] = [];
  for (const item of items) {
    if (item.kind === "event") continue;
    if (!isRecord(item.entry)) return null;
    const entryId = item.entry["id"];
    const status = item.entry["status"];
    if (typeof entryId !== "string" || typeof status !== "string") return null;
    if (item.event.entry_id !== entryId) return null;
    if (typeof item.entryHash !== "string") return null;

    let recomputed: string;
    try {
      recomputed = await entryHash(extractCore(item.entry));
    } catch {
      return null;
    }
    if (recomputed !== item.entryHash) return null;

    if (seen.has(entryId)) continue;
    seen.add(entryId);
    delivered.push({ entry_id: entryId, entry_hash: recomputed, status });
  }
  return delivered;
}

/**
 * receipt_entries: the receipt covers exactly the page that was delivered.
 *
 * A page that delivered nothing must carry no receipt: Section 9 bills for what
 * was delivered, and a signed receipt for an empty page is a counter spent on
 * nothing, which would leave a hole in the running sequence a reader is meant to
 * be able to add up.
 */
function receiptEntriesHold(
  body: Record<string, unknown>,
  items: readonly Item[],
  delivered: readonly Delivered[],
  receipt: unknown,
): boolean {
  if (items.length === 0) return receipt === null;
  if (!isRecord(receipt)) return false;

  const entries = receipt["entries"];
  if (!Array.isArray(entries) || entries.length !== delivered.length) {
    return false;
  }
  for (let index = 0; index < delivered.length; index += 1) {
    const named = entries[index];
    const expected = delivered[index]!;
    if (!isRecord(named)) return false;
    if (named["entry_id"] !== expected.entry_id) return false;
    if (named["entry_hash"] !== expected.entry_hash) return false;
    if (named["status"] !== expected.status) return false;
  }

  if (receipt["from"] !== body["from"]) return false;
  if (receipt["head"] !== body["head"]) return false;
  if (receipt["event_count"] !== items.length) return false;
  return true;
}

/** The fields a second ask of the same question must answer identically. */
const STABLE_FIELDS = ["events", "seals", "head", "sealed_head", "as_of"];

/**
 * identical: the same query, asked again, answers the same page.
 *
 * The receipt is deliberately not compared: it carries a fresh `issued_at` and
 * a fresh counter, because the second ask is a second delivery and Section 9
 * bills it. What must not move is the page itself.
 */
function samePage(first: Record<string, unknown>, second: unknown): boolean {
  if (!isRecord(second)) return false;
  for (const field of STABLE_FIELDS) {
    if (JSON.stringify(first[field]) !== JSON.stringify(second[field])) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/**
 * Fetch one page of the delta stream and check everything it claims.
 *
 * Returns the process's exit code: 2 on arguments that are not a sync, 1 on a
 * refusal or a failed check, 0 when every check held.
 */
export async function runSync(
  args: readonly string[],
  http: HttpClient,
  io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  },
): Promise<number> {
  const plan = syncPlan(args);
  if (plan === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const baseUrl = args[0] as string;

  const answer = await getJson(http, baseUrl, plan.path);
  if (answer.status !== 200) {
    io.stderr(`refused ${answer.status} ${reasonOf(answer.body)}`);
    return FAILED;
  }

  const failed = (check: SyncCheck): number => {
    io.stderr(`failed ${check}`);
    return FAILED;
  };

  const body = isRecord(answer.body) ? answer.body : {};
  const rawItems = Array.isArray(body["events"]) ? body["events"] : [];
  const seals = Array.isArray(body["seals"]) ? body["seals"] : [];
  const receipt = body["receipt"] ?? null;

  const items: Item[] = [];
  for (const raw of rawItems) {
    const item = readItem(raw);
    if (item === null) return failed("chain");
    items.push(item);
  }

  if (!(await chainHolds(items))) return failed("chain");
  if (!(await proofsHold(http, baseUrl, items, seals))) return failed("proofs");

  const delivered = await deliveredEntries(items);
  if (delivered === null) return failed("receipt_entries");
  if (!receiptEntriesHold(body, items, delivered, receipt)) {
    return failed("receipt_entries");
  }

  if (receipt !== null && !(await verifySyncReceipt(receipt))) {
    return failed("receipt_signature");
  }

  if (plan.twice) {
    const again = await getJson(http, baseUrl, plan.path);
    if (again.status !== 200) return failed("identical");
    if (!samePage(body, again.body)) return failed("identical");
  }

  const ran = plan.twice
    ? SYNC_CHECKS
    : SYNC_CHECKS.filter((check) => check !== "identical");
  io.stdout(
    [
      "ok",
      `from ${String(body["from"])}`,
      `head ${String(body["head"])}`,
      `sealed_head ${String(body["sealed_head"])}`,
      `delivered ${items.length}`,
      `entries ${delivered.length}`,
      `counter ${isRecord(receipt) ? String(receipt["counter"]) : "none"}`,
      `checks ${ran.join(",")}`,
    ].join(" "),
  );
  return OK;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(await runSync(process.argv.slice(2), new WebHttpClient()));
}
/* c8 ignore stop */

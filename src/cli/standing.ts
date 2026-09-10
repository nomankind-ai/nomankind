/**
 * standing: recompute one operator's standing from the log and check the served
 * number against it.
 *
 * Whitepaper Section 9, "Standing": "Standing is not a score nomankind assigns.
 * It is derived from the sealed public events by a published formula, so anyone
 * can recompute anyone's standing from the log and get the same number." This
 * command is the second half of that sentence, made runnable: it pages the
 * sealed log off the public endpoint, folds it with the same kernel the Worker
 * folds it with (src/standing.ts), and compares six numbers with what
 * `/operators/{id}/standing` answered. Nothing is taken on the serving side's
 * word, and a disagreement is printed field by field rather than as one word,
 * because which field disagrees is what says where to look.
 *
 * The fold stops at the sealed head and not at the log's head: an event nothing
 * has sealed yet can still be reordered by a race, so a number computed over it
 * would be a number the server is right to disagree with. Which is also why the
 * endpoint computes at exactly that position.
 *
 * Reads are unauthenticated, so this command holds no key and signs nothing.
 * Everything goes over the injected http client, so a test drives it in process
 * with no network. node:path is allowed in this CLI file only.
 */

import { resolve } from "node:path";

import type { Event } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import { standingOf, zeroStanding, type Standing } from "../standing.js";
import {
  errorOf,
  getJson,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";

const USAGE = "usage: standing <base-url> <operator>";

/** The fields compared, in the order they are printed. The order is the contract. */
export const STANDING_FIELDS = [
  "earned",
  "burned",
  "locked",
  "standing",
  "available",
  "position",
] as const;

export type StandingField = (typeof STANDING_FIELDS)[number];

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The position the sealed log ends at, or null when nothing is sealed yet.
 *
 * Two reads, because `/seals` names the newest seal by its own sequence number
 * and what the fold needs is the log position that seal covers to.
 */
async function sealedHead(
  http: HttpClient,
  baseUrl: string,
): Promise<number | null | undefined> {
  const chain = await getJson(http, baseUrl, "/seals?limit=1");
  if (chain.status !== 200 || !isRecord(chain.body)) return undefined;
  const head = chain.body["head"];
  if (head === null) return null;
  if (!Number.isSafeInteger(head)) return undefined;

  const seal = await getJson(http, baseUrl, `/seals/${String(head)}`);
  if (seal.status !== 200 || !isRecord(seal.body)) return undefined;
  const last = seal.body["last_seq"];
  return Number.isSafeInteger(last) ? (last as number) : undefined;
}

/** The sealed log, paged off the public endpoint, oldest first. */
async function sealedEvents(
  http: HttpClient,
  baseUrl: string,
  through: number,
): Promise<Event[] | null> {
  const events: Event[] = [];
  // `after` is exclusive and seq 0 is a real position, so the start of the log
  // is asked for by omitting `after` rather than by writing -1.
  let after: number | null = null;
  for (;;) {
    const query =
      after === null
        ? `/events?limit=${LIST_PAGE_LIMIT}`
        : `/events?after=${after}&limit=${LIST_PAGE_LIMIT}`;
    const page = await getJson(http, baseUrl, query);
    if (page.status !== 200 || !isRecord(page.body)) return null;
    const listed = page.body["events"];
    if (!Array.isArray(listed)) return null;
    if (listed.length === 0) break;

    for (const event of listed as Event[]) {
      if (event.seq > through) return events;
      events.push(event);
    }
    after = (listed[listed.length - 1] as Event).seq;
    if (after >= through) break;
  }
  return events;
}

/** One field of the served answer, or undefined when it is not a number. */
function served(body: Record<string, unknown>, field: StandingField): number | undefined {
  const value = body[field];
  return typeof value === "number" ? value : undefined;
}

/**
 * Recompute one operator's standing and compare it with the served answer.
 *
 * Returns the process's exit code: 2 on arguments that are not a standing
 * check, 1 on a refusal or a field that disagrees, 0 when every field matched.
 */
export async function runStanding(
  args: readonly string[],
  http: HttpClient,
  io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  },
): Promise<number> {
  const [baseUrl, operator, ...rest] = args;
  if (
    baseUrl === undefined ||
    operator === undefined ||
    baseUrl.startsWith("--") ||
    operator.startsWith("--") ||
    rest.length > 0
  ) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  const head = await sealedHead(http, baseUrl);
  if (head === undefined) {
    io.stdout("failed seals");
    return FAILED;
  }

  // Nothing sealed is a real state and not a failure: the fold is over no
  // events, and the endpoint answers a null position for the same reason.
  let local: Standing;
  if (head === null) {
    local = zeroStanding(operator, 0);
  } else {
    const events = await sealedEvents(http, baseUrl, head);
    if (events === null) {
      io.stdout("failed events");
      return FAILED;
    }
    local = standingOf(events, operator, head);
  }

  const answer = await getJson(
    http,
    baseUrl,
    `/operators/${encodeURIComponent(operator)}/standing`,
  );
  if (answer.status !== 200 || !isRecord(answer.body)) {
    io.stdout(`refused ${answer.status} ${errorOf(answer.body) ?? "unknown"}`);
    return FAILED;
  }
  const body = answer.body;

  const differences: string[] = [];
  for (const field of STANDING_FIELDS) {
    // An unsealed log has no position to compare: the endpoint says null, which
    // is the same answer as "nothing has been computed at any position yet".
    if (field === "position" && head === null) {
      if (body["position"] !== null) {
        differences.push(`position local none served ${String(body["position"])}`);
      }
      continue;
    }
    const theirs = served(body, field);
    const ours = local[field];
    if (theirs !== ours) {
      differences.push(`${field} local ${ours} served ${String(body[field])}`);
    }
  }

  if (differences.length > 0) {
    for (const line of differences) io.stdout(line);
    return FAILED;
  }

  io.stdout(
    [
      `ok ${operator}`,
      `standing ${local.standing}`,
      `available ${local.available}`,
      `position ${head === null ? "unsealed" : String(head)}`,
    ].join(" "),
  );
  return OK;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.exit(await runStanding(process.argv.slice(2), new WebHttpClient()));
}
/* c8 ignore stop */

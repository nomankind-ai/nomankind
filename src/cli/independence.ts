/**
 * independence: recompute /independence from a mirror export, offline.
 *
 * Decision D-132. The independence page published two sets, an intersection, a
 * flag and a claim, and a reader had no way to arrive at any of them except by
 * believing the page. That is the wrong shape for the one page whose whole
 * subject is not having to believe the record: a claim about independence that
 * only the record can compute is a claim about the record's word.
 *
 * So this command recomputes the page from two inputs a stranger holds. The
 * first is a mirror export — `operators.json` for the validator set, its
 * perimeters and the agent bindings, `seals.jsonl` for the newest seal's
 * countersignatures — and the second is this repository's own
 * `src/policy.ts`, where `WITNESS_PIN` lives. Both go through
 * `independenceReport`, the same function the Worker calls, so there is one
 * implementation of the rules and this is a second reader of it rather than a
 * second copy.
 *
 * With `--compare <served json>` it holds its answer against the page's JSON
 * twin — a local file, or a URL it fetches — and prints one named difference
 * per line, by path, with the mirror's value and the served one. Exit 1 on any
 * difference, so it is usable from a check.
 *
 * `seal_seq` is the one field a difference is expected on and it is reported
 * as a position line rather than a difference: a mirror is a moment and the
 * page is now, so the newest seal the export saw is older than the newest seal
 * the page reads by however long ago the export ran. Everything the newest
 * seal carries moves with it — a witness's `counted` and its `head` — so a
 * mirror taken before a countersignature landed will differ on those too, and
 * those are real differences and are printed as such.
 *
 * Exit 0 when nothing differs, 1 on a difference or an unreadable directory, 2
 * on usage. Never a stack trace: a mirror is a stranger's directory.
 *
 * node:fs and node:path are allowed in this CLI file only; the module it hands
 * the work to (src/independence.ts) is pure and Workers-safe.
 */

import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import {
  independenceReport,
  witnessAgentId,
  type IndependenceReport,
  type ValidatorEntry,
} from "../independence.js";
import { WITNESS_PIN } from "../policy.js";
import { isPerimeter } from "../registry.js";
import { runCommand } from "./main.js";
import type { ValidatorIo } from "./validator.js";

const USAGE = "usage: independence <mirror-dir> [--compare <served json>]";

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** What one invocation asks for. */
export interface IndependencePlan {
  readonly dir: string;
  /** A path or URL to the served JSON, or null for "just print mine". */
  readonly compare: string | null;
}

/**
 * The plan one invocation names, or null when the arguments are not one.
 *
 * Refuses rather than guesses, exactly as `npm run verify-mirror` does: a
 * reader who mistyped `--compare` should be told the usage rather than handed
 * a run that quietly compared against nothing.
 */
export function independencePlan(
  args: readonly string[],
): IndependencePlan | null {
  const [dir, ...rest] = args;
  if (dir === undefined || dir.startsWith("--")) return null;

  let compare: string | null = null;
  for (let index = 0; index < rest.length; ) {
    if (rest[index] !== "--compare") return null;
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (compare !== null) return null;
    compare = value;
    index += 2;
  }
  return { dir, compare };
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

async function readJsonFile(path: string): Promise<unknown> {
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

/** Every line of a JSONL file, parsed, skipping the blank tail. */
async function readJsonLines(path: string): Promise<unknown[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new MirrorUnreadable(`${path}: cannot read: ${reasonOf(error)}`);
  }
  const rows: unknown[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    try {
      rows.push(JSON.parse(line) as unknown);
    } catch (error) {
      throw new MirrorUnreadable(`${path}: not JSONL: ${reasonOf(error)}`);
    }
  }
  return rows;
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((each): each is string => typeof each === "string")
    : [];
}

/**
 * The validator set, off the mirror's `operators.json`.
 *
 * The same rows the directory serves and the same order — the export sorts by
 * operator id and so does the page's keyset read — so the two lists line up
 * item by item and a difference is a difference rather than an ordering.
 */
function validatorsOf(operators: unknown, path: string): ValidatorEntry[] {
  if (!isRecord(operators) || !Array.isArray(operators["operators"])) {
    throw new MirrorUnreadable(`${path}: no operators array`);
  }
  const rows: ValidatorEntry[] = [];
  for (const row of operators["operators"]) {
    if (!isRecord(row) || typeof row["operator"] !== "string") continue;
    const perimeter = row["perimeter"];
    rows.push({
      operator: row["operator"],
      trusted: row["trusted"] === true,
      maintainer: row["maintainer"] === true,
      provider: row["provider"] === true,
      domains: strings(row["domains"]),
      // Absent on every mirror built before D-128, which is no perimeter
      // disclosed, and ignored when it is not a perimeter word.
      perimeter: isPerimeter(perimeter) ? perimeter : null,
    });
  }
  return rows;
}

/** Which operator each agent answers for, off the mirror's own map. */
function agentsOf(operators: unknown): Map<string, string> {
  const bound = new Map<string, string>();
  if (!isRecord(operators) || !isRecord(operators["agents"])) return bound;
  for (const [agent, operator] of Object.entries(operators["agents"])) {
    if (typeof operator === "string") bound.set(agent, operator);
  }
  return bound;
}

/** The newest seal in the export, by seq, or null when it holds none. */
function newestSeal(seals: readonly unknown[]): Record<string, unknown> | null {
  let newest: Record<string, unknown> | null = null;
  for (const seal of seals) {
    if (!isRecord(seal) || typeof seal["seq"] !== "number") continue;
    if (newest === null || seal["seq"] > (newest["seq"] as number)) {
      newest = seal;
    }
  }
  return newest;
}

/** The countersignatures that seal carries, in the report's own shape. */
function countedOf(
  seal: Record<string, unknown> | null,
): { agent: string; head: { tree_size: number; root: string } | null }[] {
  if (seal === null || !Array.isArray(seal["witnesses"])) return [];
  const counted: {
    agent: string;
    head: { tree_size: number; root: string } | null;
  }[] = [];
  for (const witness of seal["witnesses"]) {
    if (!isRecord(witness) || typeof witness["agent"] !== "string") continue;
    const head = witness["head"];
    counted.push({
      agent: witness["agent"],
      head:
        isRecord(head) &&
        typeof head["tree_size"] === "number" &&
        typeof head["root"] === "string"
          ? { tree_size: head["tree_size"], root: head["root"] }
          : null,
    });
  }
  return counted;
}

/**
 * The whole report, recomputed from one mirror export and the policy module.
 *
 * Exported so a test can run it over a directory without going through the
 * process entry point, which is the same reason `verifyMirror` is.
 */
export async function reportFromMirror(
  dir: string,
): Promise<IndependenceReport> {
  const operators = await readJsonFile(join(dir, "operators.json"));
  const seals = await readJsonLines(join(dir, "seals.jsonl"));

  const validators = validatorsOf(operators, join(dir, "operators.json"));
  const bound = agentsOf(operators);
  const seal = newestSeal(seals);

  // The one comparison the log can make honestly, made off the mirror's own
  // agent map rather than off a name: a pinned witness whose key is bound as a
  // registered operator's agent is that operator.
  const boundOperators = new Map<string, string>();
  for (const pin of WITNESS_PIN) {
    const agent = witnessAgentId(pin.public_key);
    const operator = bound.get(agent);
    if (operator !== undefined) boundOperators.set(agent, operator);
  }

  return independenceReport({
    validators,
    pin: WITNESS_PIN,
    counted: countedOf(seal),
    boundOperators,
    sealSeq: seal === null ? null : (seal["seq"] as number),
  });
}

/** The served JSON, from a local file or over http. */
async function readServed(source: string): Promise<unknown> {
  if (!/^https?:\/\//.test(source)) return readJsonFile(source);
  let response: Response;
  try {
    response = await fetch(source, { headers: { accept: "application/json" } });
  } catch (error) {
    throw new MirrorUnreadable(`${source}: cannot fetch: ${reasonOf(error)}`);
  }
  if (!response.ok) {
    throw new MirrorUnreadable(`${source}: HTTP ${response.status}`);
  }
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw new MirrorUnreadable(`${source}: not JSON: ${reasonOf(error)}`);
  }
}

/** One difference, as a path and the two values that disagree there. */
export interface Difference {
  readonly path: string;
  readonly mirror: string;
  readonly served: string;
}

function show(value: unknown): string {
  return value === undefined ? "(absent)" : JSON.stringify(value);
}

/**
 * Every place the two documents disagree, by path, deepest difference first
 * reached.
 *
 * A whole subtree is one line when one side has it and the other does not:
 * printing forty lines for a missing set would bury the one fact that the set
 * is missing. Where both sides have a container, the walk goes inside, so an
 * altered `trusted` flag reads as
 * `validator_set[2].trusted` and names the operator's own row.
 */
export function differences(
  mirror: unknown,
  served: unknown,
  path = "",
): Difference[] {
  if (Array.isArray(mirror) && Array.isArray(served)) {
    const found: Difference[] = [];
    const length = Math.max(mirror.length, served.length);
    for (let index = 0; index < length; index += 1) {
      found.push(
        ...differences(mirror[index], served[index], `${path}[${index}]`),
      );
    }
    return found;
  }
  if (isRecord(mirror) && isRecord(served)) {
    const found: Difference[] = [];
    const keys = [...new Set([...Object.keys(mirror), ...Object.keys(served)])];
    for (const key of keys.sort()) {
      const here = path === "" ? key : `${path}.${key}`;
      found.push(...differences(mirror[key], served[key], here));
    }
    return found;
  }
  if (JSON.stringify(mirror ?? null) === JSON.stringify(served ?? null)) {
    return [];
  }
  return [{ path: path === "" ? "(root)" : path, mirror: show(mirror), served: show(served) }];
}

/** The one field the two are expected to disagree on, and are forgiven for. */
const EXPECTED_DIFFERENCE = "seal_seq";

/**
 * Run one invocation.
 *
 * Pure in the sense that matters: it reads two documents and writes lines, and
 * every verdict in between is `independenceReport`'s.
 */
export async function independence(
  args: readonly string[],
  io: ValidatorIo,
): Promise<number> {
  const plan = independencePlan(args);
  if (plan === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  let report: IndependenceReport;
  try {
    report = await reportFromMirror(plan.dir);
  } catch (error) {
    io.stderr(
      error instanceof MirrorUnreadable
        ? error.message
        : `${plan.dir}: cannot read: ${reasonOf(error)}`,
    );
    return FAILED;
  }

  io.stdout(JSON.stringify(report, null, 2));
  if (plan.compare === null) return OK;

  let served: unknown;
  try {
    served = await readServed(plan.compare);
  } catch (error) {
    io.stderr(
      error instanceof MirrorUnreadable
        ? error.message
        : `${plan.compare}: cannot read: ${reasonOf(error)}`,
    );
    return FAILED;
  }

  const found = differences(report, served);
  let failures = 0;
  for (const difference of found) {
    if (difference.path === EXPECTED_DIFFERENCE) {
      // Expected, and said out loud rather than hidden: the mirror is a moment
      // and the page is now.
      io.stdout(
        `position ${difference.path} mirror=${difference.mirror} served=${difference.served}`,
      );
      continue;
    }
    failures += 1;
    io.stdout(
      `differs ${difference.path} mirror=${difference.mirror} served=${difference.served}`,
    );
  }
  io.stdout(
    `summary differences ${failures} compared ${plan.compare} mirror ${plan.dir}`,
  );
  return failures === 0 ? OK : FAILED;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  const compare = independencePlan(process.argv.slice(2))?.compare ?? null;
  const baseUrl =
    compare !== null && /^https?:\/\//.test(compare) ? compare : null;
  process.exit(
    await runCommand({ name: "independence", baseUrl, io }, () =>
      independence(process.argv.slice(2), io),
    ),
  );
}
/* c8 ignore stop */

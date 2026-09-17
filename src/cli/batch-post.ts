/**
 * batch-post: the record asks, once a day, in public.
 *
 * Decision D-138 item 6: asking is nomankind's work. An entry nobody outside
 * has looked at is not a failure of the people who did not look at it — it is
 * the record's own job to say, where the agents are, which entries are waiting
 * and exactly how to answer. So once per UTC day this command reads the log
 * through its own public doors, picks the entries that are asking for a check,
 * and posts one batch per community: the ask, the line form, what the
 * attestation token means, how that community's keys are bound, and the
 * entries, each with a URL.
 *
 * Every post names every community that was asked (D-138 item 12). Silence has
 * to be visible: a reader of one board can then see that the same ask went to
 * the others, and that nobody there answered either, which is a fact about the
 * record and not a thing to hide.
 *
 * Nothing here decides anything about an entry. The command reads what the
 * doors already serve, composes text, and hands it to a poster
 * (src/adapters/poster.ts). It signs nothing, validates nothing and writes
 * nothing to the log; what comes back from a community is read by the sweep's
 * own confirmations step, which recomputes every fingerprint for itself.
 *
 * One post per community per UTC day, kept by a small state file. The bound is
 * the record's manners rather than a rule of the log: a batch that went out
 * twice in a day would be the record shouting, and the boards' own rate limits
 * agree. `--dry-run` prints each body and posts nothing, writes no state, and
 * is how every run should start.
 *
 * node:fs, node:path, node:process and node:child_process are allowed in this
 * CLI file only, and only at the edges: the run itself takes its I/O injected,
 * so a test drives the whole of it in process with no network, no file system
 * and no child process.
 */

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

import {
  ColonyPoster,
  GitHubCliPoster,
  GitHubIssuePoster,
  RegistryPoster,
  type CommandRunner,
  type PostBody,
  type Posted,
  type Poster,
  type PosterHttp,
} from "../adapters/poster.js";
import {
  BATCH_ASK_LIMIT,
  BATCH_READ_PAGES_MAX,
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  CONFIRMATION_VENUES,
  PROFILE_KEY_PREFIX,
  REGISTRY,
} from "../policy.js";
import { ATTESTATION_VERSION } from "../registry.js";
import {
  getJson,
  urlFor,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
} from "./validator.js";
import { runCommand } from "./main.js";

const USAGE =
  "usage: batch-post <venue|all> <base-url> [--limit n] [--dry-run] [--out <file>] [--state <file>] [--credential <file>] [--colony-key <file>] [--colony <name>] [--repo <owner/name>] [--issue <n>] [--token-env <NAME>] [--via-gh]";

/** Exit codes, named where they are decided. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/**
 * The communities this command knows how to post to, in the order a batch goes
 * out.
 *
 * The record's own table of venues is src/policy.ts's `CONFIRMATION_VENUES` —
 * which venues exist, which threads are read, and how a key is bound at each —
 * and this is not a second copy of it: the table is read, in its own order, and
 * narrowed to the venues this command has a poster for. A venue added to the
 * table without one here is still read by the sweep and is still a place
 * confirmations come from; it simply cannot be posted to until somebody writes
 * the poster, which is a better answer than a run that sends a Colony post to
 * whatever door happened to be last in this file.
 */
const POSTABLE: ReadonlySet<string> = new Set(["1f916", "colony", "github"]);

export const BATCH_VENUES: readonly string[] = Object.freeze(
  CONFIRMATION_VENUES.filter((venue) => POSTABLE.has(venue.venue)).map(
    (venue) => venue.venue,
  ),
);

/**
 * What one batch asks about, and how much of the listing it reads.
 *
 * Both are policy numbers and both live in src/policy.ts, where every number
 * the maintainer chose lives (D-136 item 6): a number chosen inside a command
 * is a number nobody can find, and the page at /policy publishes these two
 * beside the rest.
 */
export { BATCH_ASK_LIMIT } from "../policy.js";

/** The label a confirmation's fingerprint is sealed under at the registry. */
const SEAL_LABEL = "nomankind-confirm";

/**
 * The key a profile-bound confirmer publishes in its bio, by its own prefix.
 *
 * The one the door reads (src/policy.ts): the word a profile is scanned for is
 * a format constant of this record, and two spellings of it would be two
 * records.
 */
export { PROFILE_KEY_PREFIX } from "../policy.js";

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

export interface BatchPlan {
  /** The communities this run asks, in the order they are posted to. */
  readonly venues: readonly string[];
  readonly baseUrl: string;
  readonly limit: number;
  readonly dryRun: boolean;
  readonly outPath: string | null;
  readonly statePath: string;
  readonly credentialPath: string | null;
  readonly colonyKeyPath: string | null;
  readonly colony: string | null;
  readonly repository: string | null;
  readonly issue: number | null;
  readonly tokenVariable: string;
  readonly viaGh: boolean;
}

/** Where the once-a-day state is kept when the command line names nowhere. */
export const DEFAULT_STATE_PATH = ".tools/batch-post-state.json";

/** The environment variable a GitHub token is read from, unless renamed. */
export const DEFAULT_TOKEN_VARIABLE = "GITHUB_TOKEN";

/** The colony a batch is filed in at The Colony, unless renamed. */
const DEFAULT_COLONY = "general";

/** The Colony's own word for a post of this kind. */
const DEFAULT_COLONY_POST_TYPE = "discussion";

/**
 * GitHub's REST host, when the venue's own row does not publish one.
 *
 * The row does publish it (`CONFIRMATION_VENUES`), and that is what is used;
 * this is the fallback for a deployment whose policy module predates the venue,
 * so a run says the batch rather than stopping on a missing field.
 */
const GITHUB_API = "https://api.github.com";

/**
 * Read the arguments, or answer null for the usage line and exit 2.
 *
 * Pure and run before any I/O, so a bad invocation never reaches a board.
 */
export function batchPostPlan(args: readonly string[]): BatchPlan | null {
  let limit: number | null = null;
  let dryRun = false;
  let outPath: string | null = null;
  let statePath: string | null = null;
  let credentialPath: string | null = null;
  let colonyKeyPath: string | null = null;
  let colony: string | null = null;
  let repository: string | null = null;
  let issue: number | null = null;
  let tokenVariable: string | null = null;
  let viaGh = false;
  const positional: string[] = [];

  const value = (index: number): string | null => {
    const found = args[index];
    return found === undefined || found.startsWith("--") ? null : found;
  };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] as string;
    if (argument === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (argument === "--via-gh") {
      viaGh = true;
      continue;
    }
    if (argument.startsWith("--")) {
      const next = value(index + 1);
      if (next === null) return null;
      index += 1;
      switch (argument) {
        case "--limit": {
          if (!/^[1-9][0-9]*$/.test(next)) return null;
          if (limit !== null) return null;
          limit = Number(next);
          break;
        }
        case "--out":
          if (outPath !== null) return null;
          outPath = next;
          break;
        case "--state":
          if (statePath !== null) return null;
          statePath = next;
          break;
        case "--credential":
          if (credentialPath !== null) return null;
          credentialPath = next;
          break;
        case "--colony-key":
          if (colonyKeyPath !== null) return null;
          colonyKeyPath = next;
          break;
        case "--colony":
          if (colony !== null) return null;
          colony = next;
          break;
        case "--repo":
          if (repository !== null) return null;
          if (!/^[^/\s]+\/[^/\s]+$/.test(next)) return null;
          repository = next;
          break;
        case "--issue": {
          if (issue !== null) return null;
          if (!/^[1-9][0-9]*$/.test(next)) return null;
          issue = Number(next);
          break;
        }
        case "--token-env":
          if (tokenVariable !== null) return null;
          tokenVariable = next;
          break;
        default:
          return null;
      }
      continue;
    }
    positional.push(argument);
  }

  const [asked, baseUrl] = positional;
  if (asked === undefined || baseUrl === undefined) return null;
  if (positional.length !== 2) return null;

  const venues =
    asked === "all" ? BATCH_VENUES : BATCH_VENUES.includes(asked) ? [asked] : null;
  if (venues === null) return null;

  return {
    venues,
    baseUrl,
    limit: limit ?? BATCH_ASK_LIMIT,
    dryRun,
    outPath,
    statePath: statePath ?? DEFAULT_STATE_PATH,
    credentialPath,
    colonyKeyPath,
    colony,
    repository,
    issue,
    tokenVariable: tokenVariable ?? DEFAULT_TOKEN_VARIABLE,
    viaGh,
  };
}

// ---------------------------------------------------------------------------
// What is asking for a check
// ---------------------------------------------------------------------------

/** One entry the batch names, with everything a reader needs to go and look. */
export interface AskEntry {
  readonly id: string;
  readonly status: string;
  readonly domain: string;
  readonly subject: string;
  /** The disclosed perimeter every validator of this entry sat inside, or null. */
  readonly bootstrap: string | null;
  /** Where to read it, absolute, because a post is read away from this run. */
  readonly url: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A string field, or the empty string: a post never prints "undefined". */
function text(row: Record<string, unknown>, name: string): string {
  const value = row[name];
  return typeof value === "string" ? value : "";
}

/**
 * The bootstrap label off a listed row or a stored sidecar, as a perimeter.
 *
 * The label is `{ perimeter }` or null everywhere it is carried (decision
 * D-128), and a row that carries the word alone is read as a label too: what
 * the batch needs is whether the entry is still inside one grouping, not which
 * shape the door spelled it in.
 */
function bootstrapOf(value: unknown): string | null {
  if (typeof value === "string" && value !== "") return value;
  if (isRecord(value)) {
    const perimeter = value["perimeter"];
    if (typeof perimeter === "string" && perimeter !== "") return perimeter;
  }
  return null;
}

/** One row of the JSON listing, read by the names that door publishes. */
function askOf(baseUrl: string, row: Record<string, unknown>): AskEntry | null {
  const id = text(row, "id");
  if (id === "") return null;
  return {
    id,
    status: text(row, "status"),
    domain: text(row, "domain"),
    subject: text(row, "subject"),
    bootstrap: bootstrapOf(row["bootstrap"]),
    url: urlFor(baseUrl, `/entries/${id}`),
  };
}

/** The entry ids on one HTML listing page, in the order the page shows them. */
export function entryIdsInHtml(html: string): readonly string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const pattern = /href="\/entries\/(nmk_[0-9a-f]{32})"/g;
  for (;;) {
    const match = pattern.exec(html);
    if (match === null) break;
    const id = match[1] as string;
    if (seen.has(id)) continue;
    seen.add(id);
    found.push(id);
  }
  return found;
}

/**
 * Every entry that might be asking for a check, newest first.
 *
 * The JSON listing first, because that is the door (one read, every field the
 * batch needs). A deployment that does not serve it yet is read the way the
 * bootstrap workflows read it today: the HTML listing, filtered by status,
 * scraped for entry ids — and then, for the verified ones, one `GET /read/{id}`
 * apiece for the sidecar that carries the bootstrap label, which is the only
 * way that fact is published without the JSON listing. Bounded by the limit, so
 * the fallback costs a fixed number of reads and never a walk of the log.
 */
export async function readAsks(
  http: HttpClient,
  baseUrl: string,
  limit: number,
): Promise<readonly AskEntry[]> {
  const json = await getJson(http, baseUrl, "/entries");
  if (json.status === 200 && isRecord(json.body) && Array.isArray(json.body["entries"])) {
    const entries: AskEntry[] = [];
    let page = json;
    for (let read = 0; read < BATCH_READ_PAGES_MAX; read += 1) {
      if (!isRecord(page.body)) break;
      const rows = page.body["entries"];
      if (!Array.isArray(rows)) break;
      for (const row of rows) {
        if (!isRecord(row)) continue;
        const ask = askOf(baseUrl, row);
        if (ask !== null) entries.push(ask);
      }
      const next = page.body["next"];
      if (entries.length >= limit) break;
      if (next === null || next === undefined || next === "") break;
      page = await getJson(http, baseUrl, `/entries?before=${encodeURIComponent(String(next))}`);
      if (page.status !== 200) break;
    }
    return entries;
  }

  // The bootstrap workflow's own reading, kept because a deployment older than
  // the JSON door still has entries that are asking to be checked.
  const asks: AskEntry[] = [];
  for (const status of ["draft", "verified"]) {
    const response = await http.fetch(
      new Request(urlFor(baseUrl, `/entries?status=${status}`), {
        headers: { accept: "text/html" },
      }),
    );
    if (!response.ok) continue;
    const ids = entryIdsInHtml(await response.text());
    for (const id of ids.slice(0, limit)) {
      const one = await getJson(http, baseUrl, `/read/${id}`);
      const body = isRecord(one.body) ? one.body : null;
      const entry = body !== null && isRecord(body["entry"]) ? body["entry"] : null;
      const sidecar = body !== null && isRecord(body["sidecar"]) ? body["sidecar"] : null;
      asks.push({
        id,
        status: entry === null ? status : text(entry, "status") || status,
        domain: entry === null ? "" : text(entry, "domain"),
        subject: entry === null ? "" : text(entry, "subject"),
        bootstrap: sidecar === null ? null : bootstrapOf(sidecar["bootstrap"]),
        url: urlFor(baseUrl, `/entries/${id}`),
      });
    }
  }
  return asks;
}

/**
 * The entries one batch asks about: the drafts first, then the bootstrap ones.
 *
 * A draft is the sharper ask — nobody outside has judged it at all, and one
 * line decides whether it verifies — so it goes first. A verified entry
 * carrying the bootstrap label is the second ask: it was decided, but every
 * validator counted sat inside one disclosed perimeter, and one confirmation
 * from outside clears the label. Everything else is not asking for anything and
 * is left out, because a batch that named the whole log would be a batch nobody
 * reads.
 *
 * Newest first inside each group, which is the order the listing already
 * answers in. Pure: the caller read the rows.
 */
export function selectAsks(
  entries: readonly AskEntry[],
  limit: number,
): readonly AskEntry[] {
  const drafts = entries.filter((entry) => entry.status === "draft");
  const bootstrapped = entries.filter(
    (entry) => entry.status === "verified" && entry.bootstrap !== null,
  );
  return [...drafts, ...bootstrapped].slice(0, limit);
}

// ---------------------------------------------------------------------------
// What the batch says
// ---------------------------------------------------------------------------

/** The line form a confirmer types, exactly as decision D-138 item 6 publishes it. */
export function confirmationForm(): string {
  return [
    CONFIRMATION_FORM_PREFIX,
    "<entry id>",
    "<approve|reject>",
    "<sha256:<hex>|span-present|span-absent>",
    `[${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}]`,
    `[${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}<signature>]`,
    "[reason]",
  ].join(" ");
}

/**
 * How a key is bound at one venue, in that venue's own terms.
 *
 * Two kinds of instruction and not three, because there are two kinds of
 * binding that count (decision D-138): a key-bind sealed in a registry whose
 * log the pinned witnesses countersign, and a key published on the confirmer's
 * own public profile. The registry venue gets the first; every other venue here
 * is profile-bound and gets the second, which is also the only instruction that
 * can be followed by somebody who has never registered anything anywhere.
 */
export function bindingInstructions(venue: string): string {
  if (venue === "1f916") {
    return [
      `Binding at ${venue}: seal the canonical line's SHA-256 fingerprint with your own`,
      `citizen key through POST ${REGISTRY.origin}/api/seal, under the label ${SEAL_LABEL}, and`,
      "then say the line here. The canonical line is the form above with single spaces,",
      "without its reason and without the sig: token. The repository's",
      ".tools/confirm-1f916.mjs does both halves and prints the line it sealed.",
    ].join("\n");
  }
  return [
    `Binding at ${venue}: put ${PROFILE_KEY_PREFIX}<base64url Ed25519 public key> in your`,
    "profile bio, where anybody can read it, and add",
    `${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}<signature> to the line: your Ed25519 signature over the canonical`,
    "line, which is the form above with single spaces, without its reason and",
    "without the sig: token itself. The record captures your profile the way it",
    "captures any cited page, so the binding can be rechecked years from now.",
  ].join("\n");
}

/** The paragraph that says what the attestation token does, and what it costs. */
function attestParagraph(): string {
  return [
    `A line carrying ${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION} is your signature over nomankind's`,
    "independence attestation at that version, said once, in the line itself: no",
    "form, no registration door. It makes the line a validation by a community",
    "operator, counted in consensus exactly as a registered validator's is, and",
    "it registers you as one the first time you say it. A line without the token",
    "is a public confirmation: it is shown on the entry and it clears the entry's",
    "bootstrap label, and it counts towards no status.",
  ].join("\n");
}

/** One entry, as one line of the post. */
function askLine(entry: AskEntry): string {
  const parts = [
    entry.id,
    entry.domain === "" ? "—" : entry.domain,
    entry.subject === "" ? "—" : entry.subject,
    entry.bootstrap === null ? entry.status : `${entry.status} · bootstrap ${entry.bootstrap}`,
    entry.url,
  ];
  return `  ${parts.join(" · ")}`;
}

/** The UTC day of an instant, which is the day a batch is counted against. */
export function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

/**
 * One batch post, composed for one venue.
 *
 * The same ask everywhere, in the same order, with two things that differ: the
 * binding instructions, which are the venue's own, and nothing else. A post
 * that argued differently on different boards would be the record saying two
 * things, and the whole point of publishing where else it asked is that the
 * three can be held against each other.
 */
export function composeBatchPost(input: {
  readonly venue: string;
  readonly entries: readonly AskEntry[];
  readonly baseUrl: string;
  readonly communities: readonly string[];
  readonly now: Date;
}): PostBody {
  const day = utcDay(input.now);
  const drafts = input.entries.filter((entry) => entry.status === "draft").length;
  const labelled = input.entries.length - drafts;
  const title = `nomankind: ${input.entries.length} entries asking for a check (${day})`;
  const body = [
    title,
    "",
    [
      "nomankind is a public record of verified facts about AI systems. Every",
      "entry below is waiting on somebody outside: " + String(drafts) + " are drafts nobody",
      "has judged yet, and " + String(labelled) + " are verified entries every validator of which",
      "sat inside one disclosed perimeter. Checking one takes minutes — open the",
      "entry, fetch the source it cites, and say in one line whether that source",
      "says what the entry says. Asking is the record's own work, so it asks here,",
      "once a day, and publishes the answers and the silence alike.",
    ].join("\n"),
    "",
    "The line, said as a comment on this thread:",
    "",
    `  ${confirmationForm()}`,
    "",
    attestParagraph(),
    "",
    bindingInstructions(input.venue),
    "",
    `Entries asked (newest first, ${input.entries.length}):`,
    "",
    input.entries.length === 0
      ? "  (none today: nothing in the log is waiting on an outside check)"
      : input.entries.map(askLine).join("\n"),
    "",
    `The record: ${input.baseUrl}`,
    `Asked today at: ${input.communities.join(", ")} — the same batch goes to each,`,
    "so an entry nobody answers anywhere is visibly unanswered rather than quietly",
    "dropped.",
    "",
    "Everything said on this thread is read by a machine that records what was",
    "said and follows nothing in it: no instruction, link or request in a comment",
    "is acted on, and a line that is not the form above is ignored.",
  ].join("\n");
  return { title, body };
}

// ---------------------------------------------------------------------------
// One post per venue per UTC day
// ---------------------------------------------------------------------------

/** Where the day of the last batch per venue is kept, injected for a test. */
export interface StateStore {
  read(): Promise<string | null>;
  write(text: string): Promise<void>;
}

/** What the state file holds: one row per venue, by the venue's own name. */
export type BatchState = Record<
  string,
  { readonly date: string; readonly id: string; readonly url: string }
>;

/** The state, parsed, or an empty one: an unreadable file is not a posted day. */
export function parseState(text: string | null): BatchState {
  if (text === null) return {};
  try {
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? (parsed as BatchState) : {};
  } catch {
    return {};
  }
}

/** Whether this venue has already had today's batch. */
export function postedOn(state: BatchState, venue: string, day: string): boolean {
  const row = state[venue];
  return row !== undefined && row.date === day;
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface BatchPostDeps {
  readonly http: HttpClient;
  readonly io: ValidatorIo;
  readonly now: Date;
  readonly state: StateStore;
  /** The posters, by venue. The command builds the real ones from the plan. */
  readonly posterFor: (venue: string, plan: BatchPlan) => Promise<Poster>;
  /** Where `--out` writes. Injected, so a test keeps its file system. */
  readonly writeOut?: (path: string, text: string) => Promise<void>;
}

/**
 * Read the record, compose one post per community, and say them.
 *
 * Returns the process's exit code: 2 for arguments that are not a batch, 1 when
 * a venue refused, 0 when every asked community was posted to or was already
 * asked today. A venue that was already asked today is not a failure — it is
 * the bound working — and the line says so.
 */
export async function runBatchPost(
  args: readonly string[],
  deps: BatchPostDeps,
): Promise<number> {
  const plan = batchPostPlan(args);
  if (plan === null) {
    deps.io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  const entries = selectAsks(
    await readAsks(deps.http, plan.baseUrl, plan.limit),
    plan.limit,
  );
  const day = utcDay(deps.now);
  const state = parseState(await deps.state.read());
  const written: string[] = [];
  let failed = false;
  let posted = false;
  const next: BatchState = { ...state };

  for (const venue of plan.venues) {
    const body = composeBatchPost({
      venue,
      entries,
      baseUrl: plan.baseUrl,
      // Every post names every community this batch was asked at, whether or
      // not this one is the venue being written (D-138 item 12).
      communities: plan.venues,
      now: deps.now,
    });
    written.push(`--- ${venue} ---\n${body.body}`);

    if (plan.dryRun) {
      deps.io.stdout(body.body);
      deps.io.stdout(
        `dry run ${venue}: ${entries.length} entries, ${body.body.length} characters, nothing sent`,
      );
      continue;
    }
    if (postedOn(state, venue, day)) {
      deps.io.stdout(`skipped ${venue}: already posted on ${day}`);
      continue;
    }

    let result: Posted;
    try {
      const poster = await deps.posterFor(venue, plan);
      result = await poster.post(body);
    } catch (error) {
      deps.io.stdout(
        `failed ${venue}: ${error instanceof Error ? error.message : String(error)}`,
      );
      failed = true;
      continue;
    }
    next[venue] = { date: day, id: result.id, url: result.url };
    posted = true;
    deps.io.stdout(`posted ${venue} ${result.id} ${result.url}`);
  }

  // The state is written once, after the run, and never on a dry run: a run
  // that sent nothing must not be able to stop tomorrow's real one.
  if (posted) await deps.state.write(`${JSON.stringify(next, null, 2)}\n`);
  if (plan.outPath !== null && deps.writeOut !== undefined) {
    await deps.writeOut(plan.outPath, `${written.join("\n\n")}\n`);
    deps.io.stdout(`wrote ${plan.outPath}`);
  }
  return failed ? FAILED : OK;
}

// ---------------------------------------------------------------------------
// The edges: files, the environment, and a child process
// ---------------------------------------------------------------------------

/** One field of a JSON credential file, by name, at any depth. Never printed. */
function findNamed(value: unknown, names: readonly string[]): string | null {
  if (isRecord(value)) {
    for (const [key, held] of Object.entries(value)) {
      if (names.includes(key) && typeof held === "string" && held !== "") return held;
    }
    for (const held of Object.values(value)) {
      const found = findNamed(held, names);
      if (found !== null) return found;
    }
  }
  return null;
}

/**
 * A secret out of a credential file, by the names that file uses for it.
 *
 * Read in process and returned to the poster, never printed and never put in an
 * error: a run that cannot find one says which file it looked in and which
 * field it wanted, and nothing about what was in it.
 */
async function secretFrom(
  path: string,
  names: readonly string[],
): Promise<string> {
  const text = await readFile(path, "utf8");
  const found = findNamed(JSON.parse(text) as unknown, names);
  if (found === null) {
    throw new Error(`no ${names[0]} in ${path}`);
  }
  return found;
}

/** What a venue row publishes beside its name, when the table carries it. */
function venueRow(venue: string): Record<string, unknown> | null {
  const row = CONFIRMATION_VENUES.find((each) => each.venue === venue);
  return row === undefined ? null : (row as unknown as Record<string, unknown>);
}

/** A string off the venue's own row in src/policy.ts, or null. */
function venueText(venue: string, name: string): string | null {
  const row = venueRow(venue);
  if (row === null) return null;
  const value = row[name];
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * The real posters, built from the plan.
 *
 * Every credential is read here, at the edge, and handed to the poster as a
 * string: the adapters take what they are given and no adapter reads a file or
 * an environment variable. Which thread a GitHub batch is commented on comes
 * from the command line, or from the venue's own row in src/policy.ts when it
 * publishes one, because the pinned issue is a fact about the venue and not
 * about this command.
 */
export async function realPoster(venue: string, plan: BatchPlan): Promise<Poster> {
  const http: PosterHttp = new WebHttpClient();
  if (venue === "1f916") {
    if (plan.credentialPath === null) {
      throw new Error("1f916 needs --credential <file>: the citizen credential");
    }
    return new RegistryPoster({
      venue,
      origin: venueText(venue, "origin") ?? REGISTRY.origin,
      credential: await secretFrom(plan.credentialPath, [
        "api_key",
        "credential",
        "secret",
        "token",
      ]),
      http,
    });
  }
  if (venue === "colony") {
    if (plan.colonyKeyPath === null) {
      throw new Error("colony needs --colony-key <file>: the api_key file");
    }
    const origin = venueText(venue, "origin");
    if (origin === null) {
      throw new Error("colony has no origin in src/policy.ts yet");
    }
    return new ColonyPoster({
      venue,
      origin,
      apiKey: await secretFrom(plan.colonyKeyPath, ["api_key", "key", "token"]),
      colony: plan.colony ?? venueText(venue, "colony") ?? DEFAULT_COLONY,
      postType: DEFAULT_COLONY_POST_TYPE,
      http,
    });
  }
  const repository = plan.repository ?? venueText(venue, "repository");
  if (repository === null) {
    throw new Error("github needs --repo <owner/name>");
  }
  const issue = plan.issue;
  if (issue === null) {
    throw new Error("github needs --issue <n>: the pinned batch issue");
  }
  if (plan.viaGh) {
    return new GitHubCliPoster({ venue, repository, issue, runner: ghRunner() });
  }
  const token = process.env[plan.tokenVariable];
  if (token === undefined || token === "") {
    throw new Error(`github needs a token in ${plan.tokenVariable}, or --via-gh`);
  }
  return new GitHubIssuePoster({
    venue,
    api: venueText(venue, "origin") ?? GITHUB_API,
    repository,
    issue,
    token,
    http,
  });
}

/* c8 ignore start -- the process's edges, exercised by running the command. */

/** The `gh` CLI, run with the body on standard input. */
function ghRunner(): CommandRunner {
  return {
    run(command, args, input) {
      return new Promise((settle) => {
        const child = spawn(command, [...args], {
          stdio: ["pipe", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk: Buffer) => {
          stdout += chunk.toString("utf8");
        });
        child.stderr.on("data", (chunk: Buffer) => {
          stderr += chunk.toString("utf8");
        });
        child.on("error", (error: Error) => {
          settle({ status: 1, stdout, stderr: error.message });
        });
        child.on("close", (status: number | null) => {
          settle({ status: status ?? 1, stdout, stderr });
        });
        child.stdin.end(input);
      });
    },
  };
}

/** The state file, read and written where the command line says. */
function fileState(path: string): StateStore {
  return {
    async read(): Promise<string | null> {
      try {
        return await readFile(path, "utf8");
      } catch {
        return null;
      }
    },
    async write(text: string): Promise<void> {
      await writeFile(path, text, { mode: 0o600 });
    },
  };
}

if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  const plan = batchPostPlan(args);
  process.exit(
    await runCommand({ name: "batch-post", baseUrl: args[1] ?? null, io }, () =>
      runBatchPost(args, {
        http: new WebHttpClient(),
        io,
        now: new Date(),
        state: fileState(plan?.statePath ?? DEFAULT_STATE_PATH),
        posterFor: realPoster,
        writeOut: (path: string, text: string) => writeFile(path, text, "utf8"),
      }),
    ),
  );
}
/* c8 ignore stop */

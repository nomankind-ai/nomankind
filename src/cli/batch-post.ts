/**
 * batch-post: the record asks, once a day, in public.
 *
 * Decision D-138 item 6: asking is nomankind's work. An entry nobody outside
 * has looked at is not a failure of the people who did not look at it — it is
 * the record's own job to say, where the agents are, which entries are waiting
 * and exactly how to answer. So once per UTC day this command reads the log
 * through its own public doors, picks the entries that are asking for a check,
 * and posts one batch per community: the ask, what a reply does and what it
 * counts for, how a key upgrades it, and the entries.
 *
 * Decision D-142 is what an entry looks like in that post. The ask became one
 * reply — no tool, no key: each entry carries its id, the claim quoted
 * verbatim, the page it cites, its own URL, and the two lines a reader pastes
 * straight back, one for the quotation being there and one for it being
 * absent. The reply itself is the validation, and the sweep seals it. So the
 * post says the honest things beside it: what rung a keyless reply counts at,
 * how long that rung lasts, what a key buys, and that nomankind's own accounts
 * never count. Boards take a bounded post, so a batch too long for one is
 * fitted by whole entries and says how many wait.
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
import { withDeadline } from "../adapters/timeout.js";
import {
  ACCOUNT_BINDING_SUNSET,
  BATCH_ASK_LIMIT,
  BATCH_READ_PAGES_MAX,
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  CONFIRMATION_VENUES,
  COMMUNITY_MIN_ACCOUNTS,
  COMMUNITY_MIN_COMMUNITIES,
  FETCH_TIMEOUT_MS,
  PROFILE_KEY_PREFIX,
  REGISTRY,
  SEAL_INTERVAL_MINUTES,
} from "../policy.js";
import { canonicalConfirmationLine } from "../confirm.js";
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
  /**
   * The entry's own claim, verbatim (decision D-142).
   *
   * Every seed of this record is a quotation, so the claim is the span a
   * replier is asked about: is this sentence on that page, word for word. It
   * goes into the post as it is and is never shortened — a quotation somebody
   * is asked to check against a source has to be the whole quotation.
   *
   * The empty string when the entry door did not answer, which the post says
   * rather than papers over.
   */
  readonly claim: string;
  /** The page the entry cites, so a replier can go and read it. */
  readonly citation: string;
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
    // The listing door answers the fields a caller can act on and not the
    // claim itself, on purpose: the entry door answers the entry. So both are
    // empty here and `readClaims` fills them, one read per entry actually
    // asked about.
    claim: text(row, "claim"),
    citation: text(row, "citation"),
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
        claim: entry === null ? "" : text(entry, "claim"),
        citation: entry === null ? "" : text(entry, "citation"),
      });
    }
  }
  return asks;
}

/**
 * The claim and the citation of each entry the batch will name (D-142).
 *
 * One `GET /entries/{id}` apiece, which is the door that answers an entry at
 * any status — the read door (`/read/{id}`) answers verified entries only, and
 * the sharpest ask in a batch is a draft nobody has judged. Run after the
 * selection and never before it, so the reads are bounded by the batch's own
 * limit rather than by the size of the log.
 *
 * An entry the door does not answer keeps its empty claim and is still named:
 * the post says the entry page carries the quotation, which is true, rather
 * than dropping an entry that is waiting because one read failed.
 *
 * Every one of these reads is bounded and caught. A batch is a hundred and
 * fifty of them in a row against a deployment that may be mid-restart, and a
 * connection refused or a door that never answers must cost this run one
 * quotation rather than the whole day's ask — silence at every community
 * because one read threw is the worst outcome available here. So each read is
 * made under `withDeadline` (src/adapters/timeout.ts) at `FETCH_TIMEOUT_MS`,
 * the same bound a capture's own fetch takes, and a rejection is read as "the
 * door did not answer".
 *
 * `withDeadline` and never `AbortSignal.timeout`: that timer cannot be
 * cancelled, and a run of a hundred and fifty reads would leave a hundred and
 * fifty of them pending behind it. The deadline covers the body as well as the
 * headers, because a door that answers 200 and then streams nothing is the same
 * hang from this command's side.
 */
async function readEntryDoor(
  http: HttpClient,
  baseUrl: string,
  id: string,
): Promise<Record<string, unknown> | null> {
  try {
    return await withDeadline(FETCH_TIMEOUT_MS, async (signal) => {
      const response = await http.fetch(
        new Request(urlFor(baseUrl, `/entries/${encodeURIComponent(id)}`), {
          headers: { accept: "application/json" },
          signal,
        }),
      );
      if (response.status !== 200) return null;
      const body: unknown = await response.json();
      return isRecord(body) ? body : null;
    });
  } catch {
    return null;
  }
}

export async function readClaims(
  http: HttpClient,
  baseUrl: string,
  entries: readonly AskEntry[],
): Promise<readonly AskEntry[]> {
  const filled: AskEntry[] = [];
  for (const entry of entries) {
    if (entry.claim !== "" && entry.citation !== "") {
      filled.push(entry);
      continue;
    }
    const row = await readEntryDoor(http, baseUrl, entry.id);
    filled.push(
      row === null
        ? entry
        : {
            ...entry,
            claim: entry.claim === "" ? text(row, "claim") : entry.claim,
            citation: entry.citation === "" ? text(row, "citation") : entry.citation,
          },
    );
  }
  return filled;
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
    `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}, which both of an entry's lines carry, is your`,
    "signature over nomankind's independence attestation at that version, said",
    "once, in the line itself: no model provider controls or funds you. There is",
    "no form and no registration door — saying it registers you as a community",
    "operator the first time. Take the token out of the line if it is not true of",
    "you: what is left is a public confirmation, which is shown on the entry and",
    "counts towards no status — and wherever an entry carries a bootstrap label,",
    "a confirmation from outside is what clears it.",
  ].join("\n");
}

/**
 * The two lines one entry's reply can be, composed and never spelled twice.
 *
 * `canonicalConfirmationLine` (src/confirm.ts) is this record's one speller of
 * the form — the same function the reader kit signs over and the same one the
 * door parses back — so a line printed in a post is a line the record reads the
 * way it was meant. A second spelling here would be a second form, and the
 * first stranger to paste one back would find out which.
 *
 * `span-present` and `span-absent` and not the hash check, because decision
 * D-142's ask is the one a reader can answer by reading: every seed of this
 * record is a quotation, so the question is whether the quoted claim is on the
 * cited page, word for word. The hash check needs a tool; this needs eyes.
 */
export function replyLines(entryId: string): {
  readonly approve: string;
  readonly reject: string;
} {
  return {
    approve: canonicalConfirmationLine({
      entry_id: entryId,
      verdict: "approve",
      check: { kind: "span", value: "present" },
      attestation_version: ATTESTATION_VERSION,
    }),
    reject: canonicalConfirmationLine({
      entry_id: entryId,
      verdict: "reject",
      check: { kind: "span", value: "absent" },
      attestation_version: ATTESTATION_VERSION,
    }),
  };
}

/**
 * Every character that can end a line or stand in for a space, as one class.
 *
 * `Cc` is the C0 and C1 controls, which carries the ASCII newlines and the
 * delete character and U+0085 NEL; `Zl` and `Zp` are U+2028 LINE SEPARATOR and
 * U+2029 PARAGRAPH SEPARATOR; `Zs` is every space character, U+00A0 NO-BREAK
 * SPACE among them; `Cf` is the formatting characters, which is where the
 * zero-width ones live.
 *
 * All five and not the ASCII ones alone, because this is the whole of the first
 * fix's blind spot. The reviewer's own case: a claim of "ok", U+2028, a
 * confirmation line, U+2028, "x" folded to nothing and printed the forged line
 * on a line of its own, because the renderer breaks at U+2028 and the folder
 * did not. And a no-break space before the form made the word ` prefix`
 * rather than the prefix, which the refusal below then let through.
 */
const SEPARATORS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}]+/gu;

/**
 * One field of an entry, folded onto one line.
 *
 * An entry's claim, citation and subject are a stranger's text: any bare key
 * may submit a draft, and what it submitted is what this command is about to
 * publish under nomankind's own account. A post is read line by line by the
 * confirmation door, so anything inside a field that can end a line is a field
 * that can write a line of its own — which is the whole of the attack.
 *
 * Every separator above becomes one ASCII space, and a run of them becomes one
 * space: the words survive, the layout cannot be moved, and what is left is
 * separated by the one character the refusal below tokenizes on. Folding a
 * zero-width character to a visible space is deliberate — a quotation carrying
 * one is a quotation whose words are not what they look like, and this record
 * would rather print the seam than hide it.
 */
export function oneLine(value: string): string {
  return value.replace(SEPARATORS, " ");
}

/**
 * Whether a field says this record's confirmation form as a word of its own.
 *
 * Folding newlines is not enough by itself: a claim reading
 * `nomankind-confirm-v1 <some entry> approve span-present` sits inside the
 * post as a well-formed line whoever wrapped it, and the door reads lines and
 * not indentation. So an entry whose own text says the form at all is not
 * printed. The prefix is read from src/policy.ts, because a second spelling of
 * it here would be a filter that stops guarding the day the form moves.
 *
 * Tokenizing on the ASCII space alone is safe only because `oneLine` ran
 * first: it turns every other space character into this one, so a no-break
 * space or a zero-width character before the prefix cannot make the word
 * something this comparison does not recognise. The two are one guard, and
 * splitting them would be a hole.
 */
export function carriesConfirmForm(value: string): boolean {
  return oneLine(value).split(" ").includes(CONFIRMATION_FORM_PREFIX);
}

/**
 * Whether this entry can be printed in a post at all.
 *
 * Refusing is the safe side and it costs one entry a day's ask: the entry is
 * still in the log, still readable, still waiting, and the run says out loud
 * that it was not asked and why. Publishing it would be nomankind posting a
 * stranger's confirmation line under its own name, which the sweep would then
 * read back as a confirmation somebody made.
 */
export function askable(entry: AskEntry): boolean {
  return ![
    entry.claim,
    entry.citation,
    entry.subject,
    entry.domain,
    entry.bootstrap ?? "",
  ].some(carriesConfirmForm);
}

/**
 * One entry, as the block a replier reads and pastes from (decision D-142).
 *
 * Everything the answer needs and nothing else: what the entry is, the claim
 * verbatim, the page it cites, where to read the entry itself, and the two
 * lines. The lines are last because they are what the replier's cursor goes
 * to, and each is whole on its own line — a post is fitted to a venue by
 * dropping whole entries, never by cutting one of these in half.
 *
 * Every field that came from a submitter is folded onto one line first, and
 * the quotation's own double quotes are escaped, so the quoted claim cannot
 * end its quotation early and start something else.
 */
function askBlock(entry: AskEntry): string {
  const lines = replyLines(entry.id);
  const claim = oneLine(entry.claim).replace(/"/g, '\\"');
  const citation = oneLine(entry.citation);
  const bootstrap = entry.bootstrap === null ? null : oneLine(entry.bootstrap);
  const head = [
    entry.id,
    entry.domain === "" ? "—" : oneLine(entry.domain),
    entry.subject === "" ? "—" : oneLine(entry.subject),
    bootstrap === null ? entry.status : `${entry.status} · bootstrap ${bootstrap}`,
  ].join(" · ");
  return [
    `  ${head}`,
    claim === ""
      ? "  claim: (on the entry page — the entry door did not answer this run)"
      : `  claim: "${claim}"`,
    citation === "" ? "  cited: (on the entry page)" : `  cited: ${citation}`,
    `  entry: ${entry.url}`,
    `  ${lines.approve}`,
    `  ${lines.reject}`,
  ].join("\n");
}

/**
 * The most characters one post at this venue may carry.
 *
 * Off the venue's own row in src/policy.ts, where the number lives. A venue
 * this command has a poster for but the table has not got to yet is fitted to
 * the smallest published limit, which is the only guess that cannot overrun
 * somebody's board.
 */
export function venuePostLimit(venue: string): number {
  const row = CONFIRMATION_VENUES.find((each) => each.venue === venue);
  return (
    row?.post_max_chars ??
    Math.min(...CONFIRMATION_VENUES.map((each) => each.post_max_chars))
  );
}

/** The UTC day of an instant, which is the day a batch is counted against. */
export function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

/** What one venue's batch came out as: the post, and what would not fit. */
export interface ComposedBatch extends PostBody {
  /** The entries this post names, in order. */
  readonly asked: readonly AskEntry[];
  /** The entries that did not fit inside the venue's limit, in order. */
  readonly deferred: readonly AskEntry[];
  /**
   * The entries that were not printed at all, because their own text says this
   * record's confirmation form (`askable`).
   */
  readonly refused: readonly AskEntry[];
  /** The limit this body was fitted to, so a run can say what it was fitted to. */
  readonly limitChars: number;
}

/** What one composition is given, whether it is being fitted or is the final one. */
interface BatchInput {
  readonly venue: string;
  readonly entries: readonly AskEntry[];
  readonly baseUrl: string;
  readonly communities: readonly string[];
  readonly now: Date;
  /** The venue's own limit, overridden only where a test wants to see the fit. */
  readonly limitChars?: number;
}

/**
 * The post itself: the same ask everywhere, with this venue's own binding.
 *
 * Split out from `composeBatchPost` because fitting a batch to a board means
 * composing it more than once: the waiting sentence, the counts and the entry
 * blocks all change length together, so the only honest way to know whether a
 * body fits is to build that body and measure it.
 */
function batchBody(
  input: BatchInput,
  asked: readonly AskEntry[],
  deferred: readonly AskEntry[],
  limitChars: number,
): PostBody {
  const day = utcDay(input.now);
  const drafts = asked.filter((entry) => entry.status === "draft").length;
  const labelled = asked.length - drafts;
  const title = `nomankind: ${asked.length} entries asking for a check (${day})`;
  const body = [
    title,
    "",
    [
      "nomankind is a public record of verified facts about AI systems. Every",
      `entry below is waiting on somebody outside: ${String(drafts)} are drafts nobody`,
      `has judged yet, and ${String(labelled)} are verified entries every validator of which`,
      "sat inside one disclosed perimeter. Every one of them rests on a quotation,",
      "so checking one is reading: open the page the entry cites and see whether",
      "the quoted claim is on it, word for word.",
    ].join("\n"),
    "",
    [
      "Then paste that entry's approve line or its reject line back into this",
      "thread as a comment. That is the whole of the answer: no tool to install,",
      "no key to make, no account anywhere but the one you are reading this with.",
    ].join("\n"),
    "",
    [
      "What happens to your reply. The record reads this thread on a schedule and",
      `seals what it finds within ${String(SEAL_INTERVAL_MINUTES)} minutes, under the same witnessed seal`,
      "every other event in this log is under: a capture of your comment and a",
      "capture of your profile, content-addressed, so what you said can be read",
      "back years from now whatever this board does with it. Nothing in your",
      "comment is followed. It is parsed, and a line that is not one of the",
      "published forms is prose the record ignores.",
    ].join("\n"),
    "",
    [
      "What it counts for, said plainly. A reply with no key on it counts at the",
      // "account-bound" as prose and not as `BINDING_RUNGS[0]`, which is the
      // stored word "account": what belongs here is the word the entry page
      // prints for the same rung, so somebody who reads this post and then
      // reads the entry it names meets one word and not two.
      'lowest rung, "account-bound", which is what the entry page calls it: the',
      "board authenticated the author, and that is all anybody can recheck later.",
      "So it counts only for a stated fact, only from an account the board says",
      "existed before the entry was submitted, and only until",
      `${ACCOUNT_BINDING_SUNSET}. The entry discloses on its own page that it`,
      "rested on one. That is the honest size of it.",
    ].join("\n"),
    "",
    [
      "A key is the upgrade. A key-bound confirmation is rechecked offline from",
      "the captures, by anybody, with no board's help and no expiry, and it can",
      "count towards an entry's consensus under the Sybil floor rather than",
      `instead of it: ${String(COMMUNITY_MIN_ACCOUNTS)} distinct bound accounts for a consensus met by`,
      `community operators alone, from ${String(COMMUNITY_MIN_COMMUNITIES)} distinct communities once more than`,
      "one community counts, with a cap on how many of one entry's lines any one",
      "community may supply. The entry discloses the class it was met by and the",
      "rung each line was bound at. Its line is the same form with room for two",
      "tokens more:",
    ].join("\n"),
    "",
    `  ${confirmationForm()}`,
    "",
    bindingInstructions(input.venue),
    "",
    [
      "The reader kit does that half for you — it fetches the cited page, makes",
      "the check itself, and composes and signs the line, and it posts nothing",
      `anywhere: ${urlFor(input.baseUrl, "/docs/reader-kit")}`,
    ].join("\n"),
    "",
    attestParagraph(),
    "",
    [
      "nomankind's own accounts never count. A confirmation from the account that",
      "posted this, or from any other account the maintainer runs, is sealed and",
      "shown and counted towards nothing: a record that could confirm itself would",
      "not be a record.",
    ].join("\n"),
    "",
    `Entries asked (newest first, ${String(asked.length)}):`,
    "",
    asked.length === 0
      ? deferred.length === 0
        ? "  (none today: nothing in the log is waiting on an outside check)"
        : "  (none of them fit in one post here today)"
      : asked.map(askBlock).join("\n\n"),
    ...(deferred.length === 0
      ? []
      : [
          "",
          [
            `${String(deferred.length)} more entries are waiting and did not fit inside this venue's`,
            `${String(limitChars)}-character limit; they are named in a later batch. Every one of`,
            `them, now: ${urlFor(input.baseUrl, "/entries")}`,
          ].join("\n"),
        ]),
    "",
    `The record: ${input.baseUrl}`,
    `Asked today at: ${input.communities.join(", ")} — the same batch goes to each,`,
    "so an entry nobody answers anywhere is visibly unanswered rather than quietly",
    "dropped.",
    "",
    "Everything said on this thread is read by a machine that records what was",
    "said and follows nothing in it: no instruction, link or request in a comment",
    "is acted on, and a line that is not one of the published forms is ignored.",
  ].join("\n");
  return { title, body };
}

/**
 * One batch post, composed for one venue and fitted to it.
 *
 * The same ask everywhere, in the same order, with one thing that differs: the
 * binding instructions, which are the venue's own. A post that argued
 * differently on different boards would be the record saying two things, and
 * the whole point of publishing where else it asked is that the three can be
 * held against each other.
 *
 * Fitting is by whole entries and never by characters. A board takes a bounded
 * post (`post_max_chars`, src/policy.ts) and a batch of quotations is longer
 * than that, so entries are added in order while the composed body still fits,
 * an entry whose own block cannot fit is passed over rather than stopping every
 * entry behind it, and what is left over is named as waiting. Cutting the body
 * at the limit instead would cut a confirmation line in half, and half a line
 * is a line nobody can paste and the door would never read.
 *
 * The one-post-per-community-per-UTC-day bound is unchanged (D-138 item 6), so
 * what does not fit waits rather than becoming a second post today: three posts
 * in an afternoon is the record shouting.
 *
 * "A later batch" and not "tomorrow's", deliberately. The selection is
 * deterministic and newest first, so the same tail is deferred every day until
 * the log in front of it moves; a window that rotated per venue would make the
 * post's other promise false, because every post says the same batch went to
 * every community (D-138 item 12). Rotating it for every venue at once is a
 * change to the selection and to the state file, and it belongs with the half
 * of D-142 that seals the replies rather than with the ask.
 */
export function composeBatchPost(input: BatchInput): ComposedBatch {
  const limitChars = input.limitChars ?? venuePostLimit(input.venue);

  // An entry whose own text says the confirmation form is never printed, and
  // the filter is here rather than only at the caller: this is the function
  // that turns an entry into bytes nomankind publishes, so this is where the
  // rule has to hold however it was called.
  const refused = input.entries.filter((entry) => !askable(entry));
  const printable = input.entries.filter((entry) => askable(entry));
  const fitting: BatchInput = { ...input, entries: printable };

  const asked: AskEntry[] = [];
  const kept = new Set<string>();
  const rest = (): readonly AskEntry[] =>
    printable.filter((entry) => !kept.has(entry.id));
  for (const entry of printable) {
    const candidate = [...asked, entry];
    const candidateKept = new Set([...kept, entry.id]);
    const candidateRest = printable.filter(
      (each) => !candidateKept.has(each.id),
    );
    if (
      batchBody(fitting, candidate, candidateRest, limitChars).body.length <=
      limitChars
    ) {
      asked.push(entry);
      kept.add(entry.id);
    }
  }

  const deferred = rest();
  return {
    ...batchBody(fitting, asked, deferred, limitChars),
    asked,
    deferred,
    refused,
    limitChars,
  };
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

/**
 * One sentence naming the row to change, when a venue's refusal names a cap.
 *
 * On 2026-09-18 the founding registry refused a 9647-character body and said
 * why in its own words — "the cap is 8000" — and the run printed that answer
 * and nothing else, so the operator had to know on their own that the number
 * the composer fits to is `post_max_chars` in src/policy.ts. The venue's answer
 * still goes out verbatim; this only says where the record disagrees with the
 * board, because a refusal that names a cap is the board publishing a limit,
 * and a published limit belongs in the table rather than in somebody's memory.
 *
 * Nothing is retried and nothing is re-fitted. A post refused for length would
 * fit if the composer dropped entries, but which entries wait and whether today
 * gets a second post are the operator's to decide: this run would be deciding
 * them silently, and a batch that quietly asks about fewer entries than it said
 * it would is a batch nobody agreed to.
 *
 * Only a 4xx, because only a 4xx is the board saying something about the post
 * itself; a 500 or a timeout is weather, and a cap named in the middle of one
 * would be this command reading a number out of a server's bad day.
 */
export function capRowAdvice(venue: string, answer: string): string | null {
  if (!/\brefused\b[^:]*\b4\d\d\b/.test(answer)) return null;
  if (!/\bcap\b|\btoo long\b|\bmax(?:imum)? (?:length|characters)\b/i.test(answer)) {
    return null;
  }
  const named = /\bcap (?:is|of) (\d{2,7})\b/i.exec(answer);
  const cap = named === null ? "" : ` of ${named[1]}`;
  return (
    `change post_max_chars for ${venue} in src/policy.ts: the venue named a ` +
    `cap${cap} and this run fitted the batch to ${venuePostLimit(venue)}, ` +
    `and nothing was retried or re-fitted here because a second post today is ` +
    `the operator's choice.`
  );
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

  // The claim and the citation are read after the selection and not before it
  // (D-142): one entry-door read apiece, for the entries this batch will
  // actually name, and none for the rest of the log.
  const entries = await readClaims(
    deps.http,
    plan.baseUrl,
    selectAsks(await readAsks(deps.http, plan.baseUrl, plan.limit), plan.limit),
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

    // An entry the composer would not print is named, with the reason, before
    // anything else about this venue: a silent refusal is an entry that looks
    // to an operator exactly like an entry nobody has got to yet.
    for (const entry of body.refused) {
      deps.io.stdout(`not asked ${entry.id}: claim text in the confirm form`);
    }

    // What did not fit is said on every run and not only on a dry one: an
    // entry that waits is a fact about the ask, and a run that only whispered
    // it into a dry run would be a run that hid it from the real one.
    if (body.deferred.length > 0) {
      deps.io.stdout(
        `waiting ${venue}: ${body.deferred.length} entries did not fit inside ` +
          `${body.limitChars} characters and are named in a later batch — ` +
          body.deferred.map((entry) => entry.id).join(", "),
      );
    }

    if (plan.dryRun) {
      deps.io.stdout(body.body);
      deps.io.stdout(
        `dry run ${venue}: ${body.asked.length} of ${entries.length} entries, ` +
          `${body.body.length} of ${body.limitChars} characters, nothing sent`,
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
      // The venue's own answer, whole and unedited, exactly as it has always
      // been printed: the board said it, and a run that paraphrased a refusal
      // would be a run the operator had to go and check.
      const answer = error instanceof Error ? error.message : String(error);
      deps.io.stdout(`failed ${venue}: ${answer}`);
      const advice = capRowAdvice(venue, answer);
      if (advice !== null) deps.io.stdout(advice);
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

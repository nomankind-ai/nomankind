/**
 * validator: the fixture validator, a client of the Worker and nothing else.
 *
 * Whitepaper, Lifecycle of an entry, Validate: "A validator does not take the
 * submission's snapshot on faith. Each fetches the live source itself, checks
 * that it says what the entry says, and records its own snapshot hash in its
 * signed record." That sentence is this command. It reads the entry from the
 * Worker, fetches the citation itself under the norm rule, hashes what it got
 * with the kernel's own snapshotHash, and signs a decision that carries its own
 * hash. The Worker judges the decision; nothing here writes to the log.
 *
 * Decision D-031 puts the judgment of a proposed test with the validator, not
 * with the kernel. A fixture validator cannot judge prose, so this one judges by
 * an allowlist of predicate forms it can actually decide against the capture it
 * fetched: `contains:<text>`, `absent:<text>`, and `status:<code>`. A predicate
 * in the allowlist is accepted and rerun under the n-of-k rule; a predicate
 * outside it is not accepted, and the entry is then validated as a document,
 * which is exactly what the paper says a rejected test means. An entry in a
 * transcript category needs a model rerun, which this fixture has no way to
 * make, so its test is never accepted and it carries no reproduction. Which
 * categories those are is the entry's own domain's table and never a list here
 * (`isTranscriptCategory`), so ai-safety's observed categories take the path
 * ai-ecosystem's behavior and misbehavior take, by reading policy rather than
 * by being named again (D-096).
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so the checkpoint drives it in process against handleRequest
 * and a test drives it without a network. `main` is thin.
 *
 * Decision D-085 adds the one judgment this fixture can make without looking at
 * a page: `--duplicate-of <entry-id>` says the operator has decided this entry
 * restates a verified entry it does not supersede. That is a judgment about
 * meaning, not about bytes, so the run skips its own fetch entirely and signs a
 * rejection in the published form, `duplicate_claim:<entry-id>`. The mechanical
 * duplicate never reaches a validator: the submit door refuses it.
 *
 * Decision D-128 item 3 adds `--quote`, the rule a public validating pool runs
 * under: approve only when this validator's own fetch reproduces the entry's
 * snapshot hash AND the normalized capture carries the entry's claim verbatim,
 * and otherwise reject `quotation_not_reproduced: <hash mismatch | span
 * absent>`. Both outcomes name the run they were decided in when the runner sets
 * one, so the entry page -- which shows a decision's reason -- carries a link
 * anyone can open and watch the check happen. Without the flag nothing about a
 * run changes. The exclusions hold before any capture either way: the door's
 * own, and here the one a client can see for itself, `legacy_entry`.
 *
 * A private key is never printed. node:fs and node:path are allowed in this CLI
 * file only; everything it imports stays Workers-safe. node:process is read only
 * at the entry point, and only for the run URL the runner sets.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  SNAPSHOT_REQUEST_HEADERS,
  WebFetcher,
  type SnapshotFetcher,
} from "../adapters/fetch.js";
import { receiptArtifactHash } from "../artifact.js";
import { coreVersion, domainOf, extractCore, type Core } from "../core.js";
import {
  DUPLICATE_REASON_PREFIX,
  parseDuplicateReason,
} from "../duplicate-reason.js";
import { base64urlDecode } from "../encoding.js";
import type { ApproverRecord } from "../events.js";
import { isTranscriptCategory, proposedTest } from "../evidence.js";
import { importPrivateKeyPkcs8 } from "../identity.js";
import { normalizeText, snapshotHash } from "../normalize.js";
import { NORM_VERSION, REPRODUCTION_RUNS } from "../policy.js";
import { signRecord } from "../records.js";
import { signRequest } from "../request.js";
import { runCommand } from "./main.js";

export interface ValidatorIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

export const USAGE =
  "usage: validator <key.json> <base-url> <entry-id> [--assigned]" +
  " [--duplicate-of <entry-id>] [--quote]";

/** The reason a validator signs when the page no longer hashes to the entry's. */
export const SNAPSHOT_MISMATCH = "snapshot_mismatch";

// ---------------------------------------------------------------------------
// The quotation rule (M25e, decision D-128 item 3)
// ---------------------------------------------------------------------------

/**
 * The reason a `--quote` run signs when its own fetch reproduced the entry.
 *
 * An approval may carry a reason and nothing forces it to; this one does,
 * because the whole point of a public pool run is that the entry page says what
 * was checked and where anyone can watch it being checked.
 */
export const QUOTATION_REPRODUCED = "quotation_reproduced";

/** The reason a `--quote` run signs when it did not. The half is always named. */
export const QUOTATION_NOT_REPRODUCED = "quotation_not_reproduced";

/** Which half of the rule failed: the hash, or the passage. */
export type QuotationFailure = "hash mismatch" | "span absent";

/** The published form of a quotation rejection, built in one place. */
export function quotationReason(failure: QuotationFailure): string {
  return `${QUOTATION_NOT_REPRODUCED}: ${failure}`;
}

/**
 * The stop a `--quote` run makes on a record sealed under schema v0.6.
 *
 * The door's own word (src/worker/validate.ts): such a core carries no domain,
 * so nothing derived from it can ever validate. The draft listing already stops
 * offering it as work, and a pool that fetched the page first would be spending
 * a public run on an entry no decision can reach. It is asked before the fetch,
 * with the rest of the exclusions the door applies.
 */
export const LEGACY_ENTRY = "legacy_entry";

/**
 * Does one capture carry this passage, verbatim?
 *
 * "Verbatim" is the norm rule's word. Both sides are read in the norm rule's own
 * spelling -- the capture because `snapshotHash` extracted and normalized it,
 * the passage because it is put through the same `normalizeText` here -- so the
 * comparison is exact once whitespace has been folded the one way the rule folds
 * it, and no looser. A capture with no extracted text carries no passage at all:
 * a PDF or a binary decides nothing here, exactly as it decides no predicate.
 *
 * Exported because the seeder refuses a row on this same question before it
 * submits it (src/cli/seed.ts), and a seeder that asked it differently from the
 * validator would be a second rule for the one word.
 */
export function containsSpan(capture: CaptureFacts, span: string): boolean {
  if (capture.text === null) return false;
  const wanted = normalizeText(span);
  if (wanted.length === 0) return false;
  return capture.text.includes(wanted);
}

/**
 * The public run this decision was made in, from the environment a runner sets:
 * the composed URL when the workflow passes one, else the three parts GitHub
 * Actions sets on every job.
 *
 * Pure, and takes the environment rather than reading it, so the composition is
 * tested without a process -- node:process is the entry point's to read.
 */
export function runUrlFrom(
  env: Record<string, string | undefined>,
): string | null {
  const given = env["GITHUB_RUN_URL"];
  if (typeof given === "string" && given.length > 0) return given;
  const server = env["GITHUB_SERVER_URL"];
  const repository = env["GITHUB_REPOSITORY"];
  const runId = env["GITHUB_RUN_ID"];
  if (
    server === undefined ||
    repository === undefined ||
    runId === undefined ||
    server.length === 0 ||
    repository.length === 0 ||
    runId.length === 0
  ) {
    return null;
  }
  return `${server}/${repository}/actions/runs/${runId}`;
}

/**
 * One reason, naming the run it was signed in when there is one.
 *
 * The URL goes last and the reason ends with it, so a reader of the entry page
 * -- which shows the reason and has shown it since M21 -- finds the public run
 * at the end of the sentence whatever the sentence was.
 */
export function withRun(reason: string, runUrl: string | null): string {
  return runUrl === null ? reason : `${reason}; run: ${runUrl}`;
}

/**
 * The reason a validator signs when it judges an entry a duplicate: the
 * published form of decision D-085, built from the one place it is defined.
 */
export function duplicateReason(entryId: string): string {
  return `${DUPLICATE_REASON_PREFIX}${entryId}`;
}

/**
 * Is this an id a duplicate rejection can name?
 *
 * Asked by building the reason and reading it back, rather than by a second
 * copy of the id pattern. The form is `parseDuplicateReason`'s to define, so an
 * id this command would sign into a reason that module cannot read is an id
 * this command refuses.
 */
function namesAnEntry(entryId: string): boolean {
  return parseDuplicateReason(duplicateReason(entryId)) === entryId;
}

/** The one observation method whose receipt must carry a billing line. */
const METERED_CALL = "metered_call";

/**
 * What this fixture puts in a metered call's billing line. The receipt artifact
 * requires one for that method and this validator never spends money, so it says
 * so rather than inventing an amount.
 */
const FIXTURE_BILLING = Object.freeze({
  metered: false,
  note: "fixture validator: the predicate was decided from one HTTP GET",
});

// ---------------------------------------------------------------------------
// The way out of the process
// ---------------------------------------------------------------------------

/** Somewhere to send a request. Injected, so a test routes it to the router. */
export interface HttpClient {
  fetch(request: Request): Promise<Response>;
}

/** The client the deployed command uses: the platform's own fetch. */
export class WebHttpClient implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    return globalThis.fetch(request);
  }
}

/** A key file, read: the agent id and the private half, never printed. */
export interface ValidatorKey {
  readonly agentId: string;
  readonly privateKey: CryptoKey;
}

/**
 * A source of the current instant: a fixed one, or a function asked for it.
 *
 * A run that signs one request signs it at the instant it started and the two
 * are the same thing. A run that signs a read now and another one six minutes
 * from now is not: `REQUEST_CLOCK_SKEW_SECONDS` is 300, so the second read
 * carries a timestamp the door refuses (the QA of 2026-09-13). Hence the
 * function: a command passes `() => new Date()` and every request it makes is
 * stamped when it is made, and a test passes the fixed instant it wants.
 */
export type Clock = Date | (() => Date);

/** The instant a clock says it is, whichever of the two forms it is. */
export function instantOf(clock: Clock): Date {
  return typeof clock === "function" ? clock() : clock;
}

/** Everything a run needs besides its arguments. All of it injected. */
export interface ValidatorDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly key: ValidatorKey;
  /**
   * What the signed reads are stamped by, when it is not `now`. A command
   * passes the live clock so a long run's later reads are not stamped at the
   * instant it started; absent, the fixed `now` stands, which is what a test
   * and a one-request run both want.
   */
  readonly clock?: () => Date;
}

/** An absolute URL for a path against a base. */
export function urlFor(baseUrl: string, path: string): string {
  return new URL(path, baseUrl).toString();
}

/** One GET, with its status and whatever JSON came back. */
export async function getJson(
  http: HttpClient,
  baseUrl: string,
  path: string,
): Promise<{ status: number; body: unknown }> {
  const response = await http.fetch(new Request(urlFor(baseUrl, path)));
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

/**
 * The same client, with one agent's M2 signature on every read it makes.
 *
 * A signed read is what buys a command the operator read cap, and this is how
 * one carries it: exactly the form `readerAccess` verifies — method GET, the
 * URL's pathname with no query string, a null body, and a fresh nonce per
 * request, which is why the headers are built inside `fetch` rather than
 * once.
 *
 * The timestamp is asked of the clock inside `fetch` for the same reason. A
 * fixed instant stamped at process start is a signature that ages: a walk that
 * waits for the sweep to seal — `checkpoint --wait-seal` spends a whole
 * SEAL_INTERVAL_MINUTES budget — reads again minutes later, and a timestamp
 * more than `REQUEST_CLOCK_SKEW_SECONDS` old is 401 `clock_skew` (the QA of
 * 2026-09-13). So a command passes `() => new Date()` and every read it makes
 * carries the instant it was made; a test passes the fixed instant it wants.
 *
 * Reads only. A write carries its own signature over its own body, made by the
 * key that is entitled to make it, and a wrapper that replaced those headers
 * with a GET-shaped signature would refuse every write door there is.
 */
export function signingHttp(
  http: HttpClient,
  key: ValidatorKey,
  clock: Clock,
): HttpClient {
  return {
    async fetch(request: Request): Promise<Response> {
      if (request.method !== "GET") return http.fetch(request);
      const url = new URL(request.url);
      const signed = await signRequest({
        method: "GET",
        path: url.pathname,
        body: null,
        agentId: key.agentId,
        privateKey: key.privateKey,
        timestamp: instantOf(clock).toISOString(),
      });
      const headers = new Headers(request.headers);
      for (const [name, value] of Object.entries(signed)) {
        headers.set(name, value);
      }
      return http.fetch(new Request(request, { headers }));
    },
  };
}

/**
 * The same client, with a bearer key on every request it makes.
 *
 * The other half of the window's entitlement, and the plainer one: a paid key
 * reads inside the window at every door, and the header is added in one place
 * so nothing else in a command has to know the reader holds one.
 */
export function keyedHttp(http: HttpClient, key: string): HttpClient {
  return {
    fetch(request: Request): Promise<Response> {
      const headers = new Headers(request.headers);
      headers.set("authorization", `Bearer ${key}`);
      return http.fetch(new Request(request, { headers }));
    },
  };
}

/**
 * One signed write request, carrying the four M2 headers over the method, the
 * path and the canonical body. Exported because the checkpoint signs registry
 * and submit requests the same way, and there must be one place that does it.
 */
export async function signedPost(input: {
  readonly baseUrl: string;
  readonly path: string;
  readonly body: unknown;
  readonly key: ValidatorKey;
  readonly now: Date;
}): Promise<Request> {
  const headers = await signRequest({
    method: "POST",
    path: input.path,
    body: input.body,
    agentId: input.key.agentId,
    privateKey: input.key.privateKey,
    timestamp: input.now.toISOString(),
  });
  return new Request(urlFor(input.baseUrl, input.path), {
    method: "POST",
    body: JSON.stringify(input.body),
    headers: { ...headers, "content-type": "application/json" },
  });
}

/** An object, as a body read off a door is one. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The named error in a refusal body, or null when the body carries none. */
export function errorOf(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const error = body["error"];
  return typeof error === "string" ? error : null;
}

/** One item of the `errors` array a schema refusal carries: where, and what. */
export interface DoorError {
  /** The JSON pointer the door named, or "" when it named none. */
  readonly path: string;
  readonly message: string;
}

/**
 * The `errors` array under a refusal, or null when the body carries none.
 *
 * A 422 from the validate, reconfirm, dispute and revalidate doors carries the
 * schema's own list of what was wrong, and until the newcomer dry run of
 * 2026-09-13 every command threw it away and printed the one word
 * `schema_invalid` -- which tells an operator that something about their
 * submission did not fit and nothing whatever about what. Read defensively: the
 * items are a door's JSON and not this process's own objects.
 */
export function errorsOf(body: unknown): readonly DoorError[] | null {
  if (!isRecord(body)) return null;
  const errors = body["errors"];
  if (!Array.isArray(errors)) return null;
  return errors.map((item) => {
    if (!isRecord(item)) return { path: "", message: String(item) };
    const path = item["path"];
    const message = item["message"];
    return {
      path: typeof path === "string" ? path : "",
      message: typeof message === "string" ? message : JSON.stringify(item),
    };
  });
}

/**
 * The lines a door's answer prints: the status and the word it refused in, then
 * whatever detail it gave -- the schema's `errors` list, or the short `reason`
 * a refusal like `legacy_entry` carries instead.
 *
 * One function, because the four write commands print the same last line and a
 * detail printed by one of them and not the others is a detail nobody can rely
 * on seeing.
 */
export function refusalLines(status: number, body: unknown): readonly string[] {
  const error = errorOf(body);
  const lines = [`response ${status}${error === null ? "" : ` ${error}`}`];
  const errors = errorsOf(body);
  if (errors !== null) {
    for (const item of errors) {
      lines.push(`  ${item.path === "" ? "" : `${item.path}: `}${item.message}`);
    }
    return lines;
  }
  const reason = isRecord(body) ? body["reason"] : undefined;
  if (typeof reason === "string" && reason.length > 0) lines.push(`  ${reason}`);
  return lines;
}

// ---------------------------------------------------------------------------
// Reading the entry (decision D-124)
// ---------------------------------------------------------------------------

/**
 * The stop reason when the signing key is bound to no registered operator.
 *
 * One word for one condition, written down once and asked for by every command
 * at its own registry check.
 */
export const UNREGISTERED_OPERATOR = "unregistered_operator";

/** What that stop says about the key, in the one place the sentence lives. */
export function unregisteredOperatorDetail(agentId: string): string {
  return `agent ${agentId} is bound to no registered operator`;
}

/** The operator the registry puts behind one key, or null when it has none. */
export async function operatorFor(
  http: HttpClient,
  baseUrl: string,
  agentId: string,
): Promise<string | null> {
  const { status, body } = await getJson(
    http,
    baseUrl,
    `/agents/${encodeURIComponent(agentId)}`,
  );
  if (status !== 200) return null;
  const operator = isRecord(body) ? body["operator"] : undefined;
  if (!isRecord(operator)) return null;
  const id = operator["id"];
  return typeof id === "string" ? id : null;
}

/** Why a run stopped before it asked a door anything: the word, and a detail. */
export interface ReadStop {
  readonly reason: string;
  /** A short phrase for the printed line, or null when the word is all there is. */
  readonly detail: string | null;
}

/** The entry a signed read got, or the reason the run stops. */
export type EntryRead =
  | { readonly ok: true; readonly body: unknown }
  | { readonly ok: false; readonly stop: ReadStop };

/**
 * Read one entry with this run's own key.
 *
 * Signed with the operator key the run already holds, which buys the operator
 * read cap. The record is free from the seal (D-127), so a 200 is the entry
 * itself and there is no second shape to tell it from.
 *
 * `entry_malformed` is left for what it was always meant for: a body that
 * claims to be an entry and cannot be read as one.
 */
export async function readEntry(input: {
  readonly http: HttpClient;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly key: ValidatorKey;
  readonly clock: Clock;
}): Promise<EntryRead> {
  const read = await getJson(
    signingHttp(input.http, input.key, input.clock),
    input.baseUrl,
    `/entries/${encodeURIComponent(input.entryId)}`,
  );
  if (read.status !== 200) {
    return {
      ok: false,
      stop: {
        reason: errorOf(read.body) ?? `entry_unreadable_${read.status}`,
        detail: null,
      },
    };
  }

  return { ok: true, body: read.body };
}

/**
 * The one line a stopped run prints: the thing it was working on, the word that
 * stopped it, and the detail behind the word when there is one.
 *
 * Pure and exported so the wording is tested without a process, exactly as
 * `failureLine` in ./main.ts is.
 */
export function stopLine(
  name: string,
  run: { readonly error: string | null; readonly detail?: string | null },
): string {
  const detail = run.detail ?? null;
  return `${name}: ${run.error ?? "unknown error"}${detail === null ? "" : ` ${detail}`}`;
}

// ---------------------------------------------------------------------------
// The allowlist of predicate forms (D-031)
// ---------------------------------------------------------------------------

/** The predicate forms this fixture can decide against a capture. */
export const PREDICATE_FORMS = ["contains", "absent", "status"] as const;

export type PredicateForm = (typeof PREDICATE_FORMS)[number];

export interface Predicate {
  readonly form: PredicateForm;
  readonly value: string;
}

/** A three-digit HTTP status code, as `status:` takes it. */
const STATUS_CODE = /^[1-9][0-9]{2}$/;

/**
 * Read a proposed test as one of the allowed predicate forms, or answer null.
 *
 * Null is the whole judgment this fixture is able to make: a test it cannot
 * decide is a test it does not accept (D-031), and the entry is then validated
 * as a document rather than being rejected for the shape of its prose.
 */
export function parsePredicate(test: unknown): Predicate | null {
  if (typeof test !== "string") return null;
  const trimmed = test.trim();
  const colon = trimmed.indexOf(":");
  if (colon <= 0) return null;
  const form = trimmed.slice(0, colon);
  const value = trimmed.slice(colon + 1).trim();
  if (value.length === 0) return null;
  if (form === "contains" || form === "absent") return { form, value };
  if (form === "status") {
    return STATUS_CODE.test(value) ? { form: "status", value } : null;
  }
  return null;
}

/** One capture, as far as a predicate is concerned. */
export interface CaptureFacts {
  /** The normalized extraction the hash was taken over; null for raw bytes. */
  readonly text: string | null;
  readonly status: number;
}

/**
 * Whether a predicate held against one capture.
 *
 * A capture with no extracted text — a PDF, a binary — decides no text
 * predicate, and a predicate that cannot be decided did not hold. Saying
 * `absent` held because nothing could be read would be reading a refusal as
 * evidence.
 */
export function decidePredicate(
  predicate: Predicate,
  capture: CaptureFacts,
): boolean {
  if (predicate.form === "status") {
    return capture.status === Number(predicate.value);
  }
  if (capture.text === null) return false;
  const found = capture.text.includes(predicate.value);
  return predicate.form === "contains" ? found : !found;
}

// ---------------------------------------------------------------------------
// The validator's own fetch and hash (Section 6)
// ---------------------------------------------------------------------------

/** One capture this validator took: what it hashed to, and what it said. */
export interface Snapshot extends CaptureFacts {
  readonly hash: string;
  readonly finalUrl: string;
  readonly contentType: string | null;
}

export type SnapshotAttempt =
  | { ok: true; snapshot: Snapshot }
  | { ok: false; reason: string };

/**
 * Fetch a citation and hash it under the norm rule, exactly as the Worker does
 * at submission. The refusal comes back under the rule's own name.
 */
export async function fetchAndHash(
  fetcher: SnapshotFetcher,
  citation: string,
): Promise<SnapshotAttempt> {
  const fetched = await fetcher.fetch(citation);
  if (!fetched.ok) return { ok: false, reason: fetched.reason };
  const contentType = fetched.headers["content-type"] ?? null;
  const hashed = await snapshotHash(fetched.bytes, contentType);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };
  return {
    ok: true,
    snapshot: {
      hash: hashed.hash,
      text: hashed.extracted,
      status: fetched.status,
      finalUrl: fetched.finalUrl,
      contentType,
    },
  };
}

// ---------------------------------------------------------------------------
// The two judgments
// ---------------------------------------------------------------------------

export interface TestJudgement {
  /** null for a stated entry: there is no test to judge. */
  readonly test_accepted: boolean | null;
  /** The predicate to rerun, when one was accepted. */
  readonly predicate: Predicate | null;
}

/**
 * This validator's judgment of the entry's proposed test.
 *
 * A stated entry has none and gets null, in every domain: a governance
 * instrument and a published commitment are judged by the snapshot rule like
 * any other stated fact. An entry in one of the entry's own domain's transcript
 * categories needs a model rerun this fixture cannot make, so its test is not
 * accepted whatever it says. Everything else is accepted exactly when its test
 * is one of the allowlist's forms.
 */
export function judgeTest(core: Core): TestJudgement {
  const test = proposedTest(core);
  if (test === null) return { test_accepted: null, predicate: null };
  if (isTranscriptCategory(domainOf(core), core["category"])) {
    return { test_accepted: false, predicate: null };
  }
  const predicate = parsePredicate(test);
  return { test_accepted: predicate !== null, predicate };
}

/** Approved when this validator's own hash is the entry's, rejected otherwise. */
export function decideSnapshot(
  core: Core,
  ownHash: string,
): { decision: "approve" | "reject"; reason: string | null } {
  return ownHash === core["snapshot_hash"]
    ? { decision: "approve", reason: null }
    : { decision: "reject", reason: SNAPSHOT_MISMATCH };
}

/**
 * The quotation rule: approved only when this validator's own fetch reproduces
 * the entry's snapshot hash AND carries the entry's claim verbatim.
 *
 * Two demands and one decision, because they are one sentence of the paper: a
 * validator approves what its own fetch reproduces. The hash says the page is
 * the page that was submitted; the passage says the page says what the entry
 * says. Either half failing is a rejection that names which half, so the entry
 * page tells an author whether the source moved or the claim was never in it.
 * The hash is asked first: a page that is not the submitted page decides nothing
 * about a passage found in it.
 *
 * A claim that is not a string is a passage no capture contains, and is
 * answered as one rather than as a crash.
 */
export function decideQuotation(
  core: Core,
  snapshot: Snapshot,
  runUrl: string | null,
): { decision: "approve" | "reject"; reason: string } {
  if (snapshot.hash !== core["snapshot_hash"]) {
    return {
      decision: "reject",
      reason: withRun(quotationReason("hash mismatch"), runUrl),
    };
  }
  const claim = core["claim"];
  if (typeof claim !== "string" || !containsSpan(snapshot, claim)) {
    return {
      decision: "reject",
      reason: withRun(quotationReason("span absent"), runUrl),
    };
  }
  return {
    decision: "approve",
    reason: withRun(QUOTATION_REPRODUCED, runUrl),
  };
}

/**
 * The n-of-k rerun: REPRODUCTION_RUNS fetches of the citation, counting the runs
 * the predicate held in. A run whose fetch failed is a run the predicate did not
 * hold in, so a flapping source lowers the count rather than shortening it.
 */
export async function runPredicate(
  fetcher: SnapshotFetcher,
  citation: string,
  predicate: Predicate,
): Promise<{ runs: number; holds: number }> {
  let holds = 0;
  for (let run = 0; run < REPRODUCTION_RUNS; run += 1) {
    const attempt = await fetchAndHash(fetcher, citation);
    if (attempt.ok && decidePredicate(predicate, attempt.snapshot)) {
      holds += 1;
    }
  }
  return { runs: REPRODUCTION_RUNS, holds };
}

/**
 * The receipt artifact behind this validator's own observation: what was asked
 * for, what came back, and what it hashed to. Exactly the eight receipt keys.
 */
export function buildValidatorReceipt(input: {
  readonly method: string;
  readonly subject: unknown;
  readonly test: string;
  readonly citation: string;
  readonly snapshot: Snapshot;
  readonly observedAt: string;
  readonly observer: string;
}): Record<string, unknown> {
  return {
    method: input.method,
    subject: input.subject,
    test: input.test,
    request: {
      method: "GET",
      url: input.citation,
      headers: { ...SNAPSHOT_REQUEST_HEADERS },
    },
    response: {
      status: input.snapshot.status,
      final_url: input.snapshot.finalUrl,
      content_type: input.snapshot.contentType,
      snapshot_hash: input.snapshot.hash,
    },
    billing: input.method === METERED_CALL ? { ...FIXTURE_BILLING } : null,
    observed_at: input.observedAt,
    observer: input.observer,
  };
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface ValidatorRun {
  /** The decision is on the log, or the entry was already decided. */
  readonly ok: boolean;
  /** The validate route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /**
   * The short phrase behind the word, or null when the word is all there is
   * (decision D-124): the agent on `unregistered_operator`.
   */
  readonly detail: string | null;
  /** The `errors` array a 422 carried, or null when the answer had none. */
  readonly errors: readonly DoorError[] | null;
  readonly decision: "approve" | "reject" | null;
  readonly reason: string | null;
  readonly record: ApproverRecord | null;
}

function stopped(error: string, detail: string | null = null): ValidatorRun {
  return {
    ok: false,
    status: null,
    error,
    detail,
    errors: null,
    decision: null,
    reason: null,
    record: null,
  };
}

/**
 * Validate one entry: read it, fetch its citation, judge the test, decide on the
 * snapshot rule, sign the record and post it.
 *
 * `duplicateOf` is the one run that never fetches. The operator has already
 * judged that this entry restates the entry it names (D-085), and no capture of
 * the citation could settle that question one way or the other, so taking one
 * would be a fetch whose answer is discarded. The record carries the published
 * reason and no snapshot hash: a rejection may carry one but nothing forces it
 * to, and this validator took none.
 *
 * The exit code the CLI reports is the caller's to compute from `ok`: a 201 and
 * a 409 entry_closed are both a run that did its job, because the third of three
 * validators in a small pool finds the entry already decided.
 */
export async function runValidator(input: {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly assigned?: boolean;
  /** The entry this one duplicates, when the operator judged it one. */
  readonly duplicateOf?: string | null;
  /**
   * Decide this entry under the quotation rule (D-128 item 3): approve only
   * when this validator's own fetch reproduces the snapshot hash and carries
   * the claim verbatim. Absent, the run is exactly what it always was.
   */
  readonly quote?: boolean;
  /** The public run this decision is made in, when it is made in one. */
  readonly runUrl?: string | null;
  readonly deps: ValidatorDeps;
  readonly io: ValidatorIo;
}): Promise<ValidatorRun> {
  const { deps, io } = input;

  // Read with this run's own key: a 200 is the entry (D-127).
  const read = await readEntry({
    http: deps.http,
    baseUrl: input.baseUrl,
    entryId: input.entryId,
    key: deps.key,
    clock: deps.clock ?? deps.now,
  });
  if (!read.ok) return stopped(read.stop.reason, read.stop.detail);

  let core: Core;
  try {
    core = extractCore(read.body);
  } catch {
    return stopped("entry_malformed");
  }
  // The kernel implements exactly one norm version, so an entry signed under
  // another is refused rather than hashed under rules it never claimed.
  if (core["norm_version"] !== NORM_VERSION) {
    return stopped("unsupported_norm_version");
  }
  // The exclusions hold before any fetch, and this is the one of them a client
  // can see for itself: a v0.6 core carries no domain, so the door refuses
  // `legacy_entry` whatever the decision says. A pool run offers it to nobody.
  if (input.quote === true && coreVersion(core) === "v0.6") {
    return stopped(LEGACY_ENTRY);
  }

  const operator = await operatorFor(
    deps.http,
    input.baseUrl,
    deps.key.agentId,
  );
  // The registry is the only answer that can be right about which operator is
  // behind this key (D-124).
  if (operator === null) {
    return stopped(
      UNREGISTERED_OPERATOR,
      unregisteredOperatorDetail(deps.key.agentId),
    );
  }

  const citation = core["citation"];
  if (typeof citation !== "string") return stopped("unsupported_citation");

  const duplicateOf = input.duplicateOf ?? null;
  if (duplicateOf !== null && !namesAnEntry(duplicateOf)) {
    return stopped("bad_duplicate_of");
  }

  // The test judgment is a reading of the entry's own prose and costs no
  // request, so a duplicate rejection still states it: the schema requires one
  // on every approver record of an observed entry, whatever the decision was.
  const judged = judgeTest(core);

  let own: Snapshot | null = null;
  let decided: { decision: "approve" | "reject"; reason: string | null };
  if (duplicateOf === null) {
    const attempt = await fetchAndHash(deps.fetcher, citation);
    if (!attempt.ok) return stopped(attempt.reason);
    own = attempt.snapshot;
    decided =
      input.quote === true
        ? decideQuotation(core, own, input.runUrl ?? null)
        : decideSnapshot(core, own.hash);
  } else {
    decided = { decision: "reject", reason: duplicateReason(duplicateOf) };
  }

  // The validator's own measurement, when it accepted the test and could run it.
  let observation: Record<string, unknown> | null = null;
  if (own !== null && judged.predicate !== null && judged.test_accepted === true) {
    const entryObservation = core["observation"];
    const method =
      typeof entryObservation === "object" && entryObservation !== null
        ? (entryObservation as Record<string, unknown>)["method"]
        : undefined;
    if (typeof method !== "string") return stopped("missing_observation");

    const counts = await runPredicate(deps.fetcher, citation, judged.predicate);
    const observedAt = deps.now.toISOString().slice(0, 10);
    const receipt = buildValidatorReceipt({
      method,
      subject: core["subject"],
      test: `${judged.predicate.form}:${judged.predicate.value}`,
      citation,
      snapshot: own,
      observedAt,
      observer: deps.key.agentId,
    });
    const hashed = await receiptArtifactHash(receipt);
    if (!hashed.ok) return stopped(hashed.reason);
    observation = {
      method,
      receipt_hash: hashed.hash,
      observed_at: observedAt,
      runs: counts.runs,
      holds: counts.holds,
    };
  }

  // Every key the schema's approvers[] item names, present, null where allowed.
  const record: ApproverRecord = {
    agent: deps.key.agentId,
    operator,
    decision: decided.decision,
    reason: decided.reason,
    snapshot_hash: own === null ? null : own.hash,
    assigned_random: input.assigned === true,
    test_accepted: judged.test_accepted,
    reproduction: null,
    observation,
    signed_at: deps.now.toISOString(),
  };

  const signature = await signRecord(
    input.entryId,
    "validation",
    record,
    deps.key.privateKey,
  );
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: `/entries/${encodeURIComponent(input.entryId)}/validate`,
    body: { record, signature },
    key: deps.key,
    now: deps.now,
  });

  const response = await deps.http.fetch(request);
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  const error = response.status === 201 ? null : errorOf(body);

  io.stdout(
    `decision ${record.decision}${record.reason === null ? "" : ` ${record.reason}`}` +
      `${own === null ? "" : ` hash ${own.hash}`}`,
  );
  // The door's own detail under the word it refused in (D-124): a schema
  // refusal that printed `schema_invalid` and nothing else told an operator
  // only that something was wrong.
  for (const line of refusalLines(response.status, body)) io.stdout(line);

  // The verdict stands: the third of three in a small pool finds the entry
  // already decided, and that is the rule working rather than a failure.
  const closed = response.status === 409 && error === "entry_closed";
  return {
    ok: response.status === 201 || closed,
    status: response.status,
    error,
    detail: null,
    errors: errorsOf(body),
    decision: record.decision,
    reason: record.reason ?? null,
    record,
  };
}

// ---------------------------------------------------------------------------
// The key file
// ---------------------------------------------------------------------------

/**
 * Read a key file written by keygen. The private half is imported and never
 * printed, logged, or carried in a returned message.
 */
export async function readKeyFile(path: string): Promise<ValidatorKey> {
  const text = await readFile(resolve(path), "utf8");
  const parsed = JSON.parse(text) as Record<string, unknown>;
  const agentId = parsed["agent_id"];
  const pkcs8 = parsed["private_key_pkcs8"];
  if (typeof agentId !== "string" || typeof pkcs8 !== "string") {
    throw new Error(`${path}: not a nomankind key file`);
  }
  return {
    agentId,
    privateKey: await importPrivateKeyPkcs8(base64urlDecode(pkcs8)),
  };
}

/** A short, one-line cause: an errno where there is one, else the first line. */
export function reasonOf(error: unknown): string {
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

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/** One command line, read. */
export interface ValidatorArgs {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly assigned: boolean;
  readonly duplicateOf: string | null;
  readonly quote: boolean;
}

/**
 * Read the arguments, or answer null for the usage line and exit 2.
 *
 * `--duplicate-of` takes the id of the entry this one duplicates, and the id is
 * checked here rather than at the door: a malformed id would be signed into a
 * reason nobody can parse, and a rejection whose published form does not parse
 * is a rejection the entry page and the confidence inputs cannot read. Better
 * the usage line than a signed record that says nothing.
 */
export function parseValidatorArgs(
  args: readonly string[],
): ValidatorArgs | null {
  const positional: string[] = [];
  let assigned = false;
  let duplicateOf: string | null = null;
  let quote = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--assigned") {
      assigned = true;
    } else if (argument === "--quote") {
      quote = true;
    } else if (argument === "--duplicate-of") {
      const value = args[index + 1];
      if (value === undefined || !namesAnEntry(value)) return null;
      duplicateOf = value;
      index += 1;
    } else if (argument.startsWith("--")) {
      return null;
    } else {
      positional.push(argument);
    }
  }

  const [keyPath, baseUrl, entryId] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    entryId === undefined ||
    positional.length > 3 ||
    // Two different judgments about one entry: `--duplicate-of` says the
    // operator decided this entry restates another and takes no capture at all,
    // and `--quote` says the decision rests on nothing but a capture. A run
    // asked for both has not said which decision it is making.
    (quote && duplicateOf !== null)
  ) {
    return null;
  }
  return { keyPath, baseUrl, entryId, assigned, duplicateOf, quote };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const parsed = parseValidatorArgs(process.argv.slice(2));
  if (parsed === null) {
    console.error(USAGE);
    process.exit(2);
  }
  const { keyPath, baseUrl, entryId, assigned, duplicateOf, quote } = parsed;

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  // The one thing read from the environment here: the public run this decision
  // is being made in, which the entry page then shows in the reason.
  const runUrl = runUrlFrom(process.env);
  process.exit(
    await runCommand({ name: entryId, baseUrl, io }, async () => {
      const run = await runValidator({
        baseUrl,
        entryId,
        assigned,
        duplicateOf,
        quote,
        runUrl,
        io,
        deps: {
          http: new WebHttpClient(),
          fetcher: new WebFetcher(),
          now: new Date(),
          clock: () => new Date(),
          key: await readKeyFile(keyPath),
        },
      });
      if (!run.ok && run.status === null) {
        io.stderr(stopLine(entryId, run));
      }
      return run.ok ? 0 : 1;
    }),
  );
}
/* c8 ignore stop */

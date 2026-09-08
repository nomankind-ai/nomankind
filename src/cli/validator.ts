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
 * which is exactly what the paper says a rejected test means. A behavior or
 * misbehavior entry needs a model rerun, which this fixture has no way to make,
 * so its test is never accepted and it carries no reproduction.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so the checkpoint drives it in process against handleRequest
 * and a test drives it without a network. `main` is thin.
 *
 * A private key is never printed. node:fs and node:path are allowed in this CLI
 * file only; everything it imports stays Workers-safe.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  SNAPSHOT_REQUEST_HEADERS,
  WebFetcher,
  type SnapshotFetcher,
} from "../adapters/fetch.js";
import { receiptArtifactHash } from "../artifact.js";
import { extractCore, type Core } from "../core.js";
import { base64urlDecode } from "../encoding.js";
import type { ApproverRecord } from "../events.js";
import { isTranscriptCategory, proposedTest } from "../evidence.js";
import { importPrivateKeyPkcs8 } from "../identity.js";
import { snapshotHash } from "../normalize.js";
import { NORM_VERSION, REPRODUCTION_RUNS } from "../policy.js";
import { signRecord } from "../records.js";
import { signRequest } from "../request.js";

export interface ValidatorIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

const USAGE =
  "usage: validator <key.json> <base-url> <entry-id> [--assigned]";

/** The reason a validator signs when the page no longer hashes to the entry's. */
export const SNAPSHOT_MISMATCH = "snapshot_mismatch";

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

/** Everything a run needs besides its arguments. All of it injected. */
export interface ValidatorDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly key: ValidatorKey;
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

/** The named error in a refusal body, or null when the body carries none. */
export function errorOf(body: unknown): string | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const error = (body as Record<string, unknown>)["error"];
  return typeof error === "string" ? error : null;
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
 * A stated entry has none and gets null. A behavior or misbehavior entry needs a
 * model rerun this fixture cannot make, so its test is not accepted whatever it
 * says. Everything else is accepted exactly when its test is one of the
 * allowlist's forms.
 */
export function judgeTest(core: Core): TestJudgement {
  const test = proposedTest(core);
  if (test === null) return { test_accepted: null, predicate: null };
  if (isTranscriptCategory(core["category"])) {
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
  readonly decision: "approve" | "reject" | null;
  readonly reason: string | null;
  readonly record: ApproverRecord | null;
}

function stopped(error: string): ValidatorRun {
  return {
    ok: false,
    status: null,
    error,
    decision: null,
    reason: null,
    record: null,
  };
}

/** The operator the registry puts behind this key, or null when it has none. */
async function operatorFor(
  deps: ValidatorDeps,
  baseUrl: string,
): Promise<string | null> {
  const { status, body } = await getJson(
    deps.http,
    baseUrl,
    `/agents/${encodeURIComponent(deps.key.agentId)}`,
  );
  if (status !== 200) return null;
  const operator = (body as Record<string, unknown> | null)?.["operator"];
  if (typeof operator !== "object" || operator === null) return null;
  const id = (operator as Record<string, unknown>)["id"];
  return typeof id === "string" ? id : null;
}

/**
 * Validate one entry: read it, fetch its citation, judge the test, decide on the
 * snapshot rule, sign the record and post it.
 *
 * The exit code the CLI reports is the caller's to compute from `ok`: a 201 and
 * a 409 entry_closed are both a run that did its job, because the third of three
 * validators in a small pool finds the entry already decided.
 */
export async function runValidator(input: {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly assigned?: boolean;
  readonly deps: ValidatorDeps;
  readonly io: ValidatorIo;
}): Promise<ValidatorRun> {
  const { deps, io } = input;

  const read = await getJson(
    deps.http,
    input.baseUrl,
    `/entries/${encodeURIComponent(input.entryId)}`,
  );
  if (read.status !== 200) {
    return stopped(errorOf(read.body) ?? `entry_unreadable_${read.status}`);
  }

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

  const operator = await operatorFor(deps, input.baseUrl);
  if (operator === null) return stopped("unregistered_agent");

  const citation = core["citation"];
  if (typeof citation !== "string") return stopped("unsupported_citation");

  const own = await fetchAndHash(deps.fetcher, citation);
  if (!own.ok) return stopped(own.reason);

  const judged = judgeTest(core);
  const decided = decideSnapshot(core, own.snapshot.hash);

  // The validator's own measurement, when it accepted the test and could run it.
  let observation: Record<string, unknown> | null = null;
  if (judged.predicate !== null && judged.test_accepted === true) {
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
      snapshot: own.snapshot,
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
    snapshot_hash: own.snapshot.hash,
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
    `decision ${record.decision}${record.reason === null ? "" : ` ${record.reason}`} hash ${own.snapshot.hash}`,
  );
  io.stdout(
    `response ${response.status}${error === null ? "" : ` ${error}`}`,
  );

  // The verdict stands: the third of three in a small pool finds the entry
  // already decided, and that is the rule working rather than a failure.
  const closed = response.status === 409 && error === "entry_closed";
  return {
    ok: response.status === 201 || closed,
    status: response.status,
    error,
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

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const assigned = args.includes("--assigned");
  const positional = args.filter((argument) => !argument.startsWith("--"));
  const [keyPath, baseUrl, entryId] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    entryId === undefined ||
    positional.length > 3
  ) {
    console.error(USAGE);
    process.exit(2);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  let code = 1;
  try {
    const run = await runValidator({
      baseUrl,
      entryId,
      assigned,
      io,
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        key: await readKeyFile(keyPath),
      },
    });
    if (!run.ok && run.status === null) {
      io.stderr(`${entryId}: ${run.error ?? "unknown error"}`);
    }
    code = run.ok ? 0 : 1;
  } catch (error) {
    io.stderr(`${entryId}: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

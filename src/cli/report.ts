/**
 * report: a reader's client for POST /entries/{id}/failure-reports.
 *
 * Whitepaper Section 8, "Failure reports": "A reader that acts on a verified
 * entry and fails — a price that is wrong, a limit that is not there — files a
 * signed failure report against the entry, with its transcript frozen and hashed
 * like any artifact. A single report is a signal. A published threshold of
 * reports from distinct operators auto-opens a revalidation at nomankind's
 * expense."
 *
 * This command is the reader's half of that sentence and it is deliberately
 * thin. The artifact is the reader's own — the transcript or receipt of the
 * interaction that failed them — and this does not build it, edit it or
 * normalise it: it sends exactly the object in the file, because the hash the
 * Worker takes is over exactly those bytes and a client that reshaped them would
 * be freezing something the reader never saw.
 *
 * Any key may file. Section 5 lets anyone hold one, and Section 12 accepts the
 * flood risk explicitly, answering it at the threshold rather than at the door:
 * three bare-key reports open nothing, and three registered operators open a
 * check. So this command asks nothing about who is signing.
 *
 * The core is exported over injected io — an http client, a clock and a key — so
 * a test drives it in process against handleRequest with no network at all.
 * `main` is thin. A private key is never printed. node:fs and node:path are
 * allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  errorOf,
  readKeyFile,
  reasonOf,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE = "usage: report <key.json> <base-url> <entry-id> <report.json>";

/** The one refusal this command makes for itself, before any request. */
export const BAD_REPORT = "bad_report";

/** Exactly the keys a report file may carry. */
export const REPORT_FIELDS: readonly string[] = Object.freeze([
  "observed",
  "artifact",
  "citation",
] as const);

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** What one invocation asks for. */
export interface ReportPlan {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly reportPath: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The report one invocation asks for, or null when the arguments are not one.
 * Parsed before any I/O, so a bad invocation never touches the network.
 */
export function reportPlan(args: readonly string[]): ReportPlan | null {
  for (const argument of args) {
    if (argument.startsWith("--")) return null;
  }
  const [keyPath, baseUrl, entryId, reportPath] = args;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    entryId === undefined ||
    reportPath === undefined ||
    args.length > 4
  ) {
    return null;
  }
  return { keyPath, baseUrl, entryId, reportPath };
}

/** The report file, read: accepted as it stands, or refused with a reason. */
export type ReportVerdict =
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; reason: string; detail: string };

/**
 * Read a report file, or refuse it.
 *
 * Pure and synchronous, and run before anything is asked of the Worker. The
 * artifact is checked only for being an object: whether it is a transcript or a
 * receipt is read off its key set by src/artifact.ts, on the Worker's side,
 * where the hash is taken.
 */
export function checkReport(report: unknown): ReportVerdict {
  if (!isRecord(report)) {
    return { ok: false, reason: BAD_REPORT, detail: "not a JSON object" };
  }
  const unknown = Object.keys(report).filter(
    (key) => !REPORT_FIELDS.includes(key),
  );
  if (unknown.length > 0) {
    return {
      ok: false,
      reason: BAD_REPORT,
      detail: `not a report field: ${unknown.join(", ")}`,
    };
  }
  const observed = report["observed"];
  if (typeof observed !== "string" || observed.trim().length === 0) {
    return {
      ok: false,
      reason: BAD_REPORT,
      // The schema: `observed` is "what the reader actually saw, in plain
      // language". An empty one is a vote, not a report.
      detail: "observed: missing or empty",
    };
  }
  if (!isRecord(report["artifact"])) {
    return { ok: false, reason: BAD_REPORT, detail: "artifact: not an object" };
  }
  const citation = report["citation"];
  if (
    citation !== undefined &&
    citation !== null &&
    typeof citation !== "string"
  ) {
    return { ok: false, reason: BAD_REPORT, detail: "citation: not a string" };
  }

  const body: Record<string, unknown> = {
    observed,
    artifact: report["artifact"],
  };
  // Section 8: a citation is what makes the report eligible for upgrade, so it
  // travels when there is one and is left out entirely when there is not.
  if (typeof citation === "string") body["citation"] = citation;
  return { ok: true, body };
}

/** Everything a run needs besides its arguments. All of it injected. */
export interface ReportDeps {
  readonly http: HttpClient;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one report run did. */
export interface ReportRun {
  /** The report is on the log. */
  readonly ok: boolean;
  /** The report route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** Whether this report was the one that reached the threshold. */
  readonly openedRevalidation: boolean;
}

/** File one report against one entry. */
export async function runReport(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly report: unknown;
  readonly deps: ReportDeps;
}): Promise<ReportRun> {
  const { deps } = input;

  const checked = checkReport(input.report);
  if (!checked.ok) {
    deps.io.stderr(`${checked.reason}: ${checked.detail}`);
    return {
      ok: false,
      status: null,
      error: checked.reason,
      openedRevalidation: false,
    };
  }

  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: `/entries/${encodeURIComponent(input.entryId)}/failure-reports`,
    body: checked.body,
    key: input.key,
    now: deps.now,
  });

  const response = await deps.http.fetch(request);
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (response.status !== 201) {
    const error = errorOf(body);
    deps.io.stdout(
      `response ${response.status}${error === null ? "" : ` ${error}`}`,
    );
    return {
      ok: false,
      status: response.status,
      error,
      openedRevalidation: false,
    };
  }

  const opened =
    isRecord(body) && body["opened_revalidation"] === true;
  deps.io.stdout(`report filed on ${input.entryId}`);
  deps.io.stdout(`revalidation ${opened ? "opened" : "not opened"}`);
  return {
    ok: true,
    status: 201,
    error: null,
    openedRevalidation: opened,
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = reportPlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(BAD_ARGUMENTS);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  // A report file that cannot be read or parsed is a usage failure, not a
  // refusal: nothing was ever asked of the log.
  let report: unknown;
  try {
    report = JSON.parse(await readFile(resolve(plan.reportPath), "utf8"));
  } catch (error) {
    io.stderr(`${plan.reportPath}: ${reasonOf(error)}`);
    process.exit(BAD_ARGUMENTS);
  }

  let code: number = FAILED;
  try {
    const run = await runReport({
      key: await readKeyFile(plan.keyPath),
      baseUrl: plan.baseUrl,
      entryId: plan.entryId,
      report,
      deps: { http: new WebHttpClient(), now: new Date(), io },
    });
    if (!run.ok && run.status === null) {
      io.stderr(`report: ${run.error ?? "unknown error"}`);
    }
    code = run.ok ? OK : FAILED;
  } catch (error) {
    io.stderr(`report: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

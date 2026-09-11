/**
 * dispute: a challenger's own client for POST /entries/{id}/dispute.
 *
 * Whitepaper Section 6, "Dispute": "Verified entries stay open to challenge. A
 * challenge is itself an entry, in the correction category, and it requires a
 * citation." This command is the challenger's half of that sentence. It reads
 * the target from the log so the correction can carry the same subject, reads
 * the fields the challenger chose, builds and signs a correction core with the
 * submit command's own helper — the same fetch under the norm rule, the same
 * naming and stamping, the same `author_operator` read from the registry — and
 * posts it against the entry it challenges.
 *
 * Two of the fields are not the challenger's. `category` is always
 * `correction`, because that is what a challenge is, and `subject` defaults to
 * the target's, because a challenge is a claim about the same fact and the
 * Worker refuses one that is not (`subject_mismatch`). A fields file naming
 * either is a mistake this command reports before it touches the network rather
 * than a value it quietly overwrites.
 *
 * `--from-report` and `--from-revalidation` are the two upgrades Section 8 and
 * Section 6 name: a failure report that carries a citation, and a revalidation
 * request that turned one up. Both are positions in the log, and the Worker
 * checks that the position really is one of ours and really is still open.
 *
 * Nothing is decided here. The Worker fetches the cited page for itself, runs
 * the whole submission pipeline on the correction, and refuses the filing if any
 * of it does not hold; what this command prints is what the Worker said.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives it in process against handleRequest with no
 * network at all. `main` is thin. A private key is never printed. node:fs and
 * node:path are allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { DEFAULT_DOMAIN } from "../policy.js";
import { signCore } from "../sign.js";
import { buildAuthoredCore } from "./submit.js";
import {
  errorOf,
  getJson,
  readKeyFile,
  signingHttp,
  reasonOf,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE =
  "usage: dispute <key.json> <base-url> <target-id> <fields.json> [--from-report <n>] [--from-revalidation <n>]";

/** The one refusal this command makes for itself, before any request. */
export const BAD_FIELDS = "bad_fields";

/** The category a challenge is always in. Section 6 says so outright. */
export const CORRECTION = "correction";

/**
 * The fields a challenger chooses. `subject` is here because a challenger may
 * state it, and it defaults to the target's when they do not; `category` is not,
 * because a challenge has only one, and neither is `domain` (decision D-071),
 * because a challenge belongs to the domain of the fact it challenges and to no
 * other -- a challenger who could name it could file the correction somewhere
 * the entry's own validators are not.
 */
export const DISPUTE_FIELDS: readonly string[] = Object.freeze([
  "subject",
  "claim",
  "before",
  "after",
  "effective_at",
  "citation",
  "evidence",
] as const);

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** Flags that carry a value. There are no bare flags on this command. */
const VALUED_FLAGS = ["--from-report", "--from-revalidation"];

/** A log position in plain decimal, as every seq in the log is written. */
const POSITION_PATTERN = /^(0|[1-9][0-9]*)$/;

/** What one invocation asks for, once its arguments hold up. */
export interface DisputePlan {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly targetId: string;
  readonly fieldsPath: string;
  readonly fromReport: number | null;
  readonly fromRevalidation: number | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The filing one invocation asks for, or null when the arguments are not one.
 *
 * Refuses rather than guesses, and parses before any I/O: a challenger who
 * misspelt `--from-report` would otherwise file an ordinary dispute and be told
 * nothing about the report they meant to upgrade.
 */
export function disputePlan(args: readonly string[]): DisputePlan | null {
  const positional: string[] = [];
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; ) {
    const argument = args[index];
    if (argument === undefined) return null;
    if (!argument.startsWith("--")) {
      positional.push(argument);
      index += 1;
      continue;
    }
    if (!VALUED_FLAGS.includes(argument)) return null;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(argument)) return null;
    values.set(argument, value);
    index += 2;
  }

  const [keyPath, baseUrl, targetId, fieldsPath] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    targetId === undefined ||
    fieldsPath === undefined ||
    positional.length > 4
  ) {
    return null;
  }

  const position = (flag: string): number | null | undefined => {
    const written = values.get(flag);
    if (written === undefined) return null;
    if (!POSITION_PATTERN.test(written)) return undefined;
    const value = Number(written);
    return Number.isSafeInteger(value) ? value : undefined;
  };
  const fromReport = position("--from-report");
  const fromRevalidation = position("--from-revalidation");
  if (fromReport === undefined || fromRevalidation === undefined) return null;

  return { keyPath, baseUrl, targetId, fieldsPath, fromReport, fromRevalidation };
}

/** The fields file, read as a challenger's own: accepted, or refused. */
export type DisputeFieldsVerdict =
  | { ok: true; fields: Record<string, unknown> }
  | { ok: false; reason: string; detail: string };

/**
 * Read a fields file as a challenger's fields, or refuse it.
 *
 * Pure and synchronous, and run before anything is fetched: the subject is
 * filled in from the target, which the caller has already read, and the category
 * is the one a challenge always has.
 */
export function checkDisputeFields(
  fields: unknown,
  targetSubject: string,
  targetDomain: string = DEFAULT_DOMAIN,
): DisputeFieldsVerdict {
  if (!isRecord(fields)) {
    return { ok: false, reason: BAD_FIELDS, detail: "not a JSON object" };
  }
  const unknown = Object.keys(fields).filter(
    (key) => !DISPUTE_FIELDS.includes(key),
  );
  if (unknown.length > 0) {
    return {
      ok: false,
      reason: BAD_FIELDS,
      detail: `not the challenger's to set: ${unknown.join(", ")}`,
    };
  }
  const subject = fields["subject"];
  if (subject !== undefined && typeof subject !== "string") {
    return { ok: false, reason: BAD_FIELDS, detail: "subject: not a string" };
  }
  return {
    ok: true,
    fields: {
      ...fields,
      // A challenge is a claim about the same fact, and the Worker refuses one
      // that is not (`subject_mismatch`).
      subject: subject ?? targetSubject,
      category: CORRECTION,
      // The target's own domain (decision D-071). A legacy v0.6 target carries
      // none and reads as ai-ecosystem -- though the Worker refuses a new
      // decision on one anyway, so such a filing never gets far.
      domain: targetDomain,
    },
  };
}

/** Everything a run needs besides its arguments. All of it injected. */
export interface DisputeDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one filing run did. */
export interface DisputeRun {
  /** The challenge is on the log. */
  readonly ok: boolean;
  /** The dispute route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** The id the kernel derived from the signed correction core. */
  readonly correctionId: string | null;
  /** The target's status after the filing, on 201. */
  readonly targetStatus: string | null;
}

function stopped(error: string): DisputeRun {
  return {
    ok: false,
    status: null,
    error,
    correctionId: null,
    targetStatus: null,
  };
}

/**
 * File one dispute: read the target, build and sign the correction, and post it
 * against the entry it challenges.
 */
export async function runDispute(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly targetId: string;
  readonly fields: unknown;
  readonly fromReport?: number | null;
  readonly fromRevalidation?: number | null;
  readonly deps: DisputeDeps;
}): Promise<DisputeRun> {
  const { deps } = input;

  // The target, for its subject: a challenge is about the same fact, so the
  // correction carries the subject the entry it challenges carries.
  // Signed with the operator key this run already holds (decision D-100): an
  // entry inside the release window is served to a signed request from an agent
  // bound to a registered operator, and a validator is exactly that reader —
  // the people who have to judge an entry are the ones the window is not for.
  const read = await getJson(
    signingHttp(deps.http, input.key, deps.now),
    input.baseUrl,
    `/entries/${encodeURIComponent(input.targetId)}`,
  );
  if (read.status !== 200) {
    return stopped(errorOf(read.body) ?? `entry_unreadable_${read.status}`);
  }
  const subject = isRecord(read.body) ? read.body["subject"] : undefined;
  if (typeof subject !== "string") return stopped("entry_malformed");
  const domain = isRecord(read.body) ? read.body["domain"] : undefined;

  const checked = checkDisputeFields(
    input.fields,
    subject,
    typeof domain === "string" ? domain : DEFAULT_DOMAIN,
  );
  if (!checked.ok) {
    deps.io.stderr(`${checked.reason}: ${checked.detail}`);
    return { ...stopped(checked.reason), status: null };
  }

  const built = await buildAuthoredCore({
    key: input.key,
    baseUrl: input.baseUrl,
    fields: checked.fields,
    deps,
  });
  if (!built.ok) {
    if (built.usage) deps.io.stderr(`${built.reason}: ${built.detail ?? ""}`);
    return stopped(built.reason);
  }
  const { core } = built;
  const correctionId = core["id"] as string;

  const signature = await signCore(core, input.key.privateKey);
  const body: Record<string, unknown> = { entry: { ...core, signature } };
  if (input.fromReport !== undefined && input.fromReport !== null) {
    body["from_report_seq"] = input.fromReport;
  }
  if (input.fromRevalidation !== undefined && input.fromRevalidation !== null) {
    body["from_revalidation_seq"] = input.fromRevalidation;
  }

  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: `/entries/${encodeURIComponent(input.targetId)}/dispute`,
    body,
    key: input.key,
    now: deps.now,
  });

  const response = await deps.http.fetch(request);
  let answer: unknown = null;
  try {
    answer = await response.json();
  } catch {
    answer = null;
  }

  if (response.status !== 201) {
    const error = errorOf(answer);
    deps.io.stdout(
      `response ${response.status}${error === null ? "" : ` ${error}`}`,
    );
    return {
      ok: false,
      status: response.status,
      error,
      correctionId,
      targetStatus: null,
    };
  }

  const target = isRecord(answer) ? answer["target"] : null;
  const targetStatus =
    isRecord(target) && typeof target["status"] === "string"
      ? (target["status"] as string)
      : null;
  deps.io.stdout(`correction ${correctionId}`);
  deps.io.stdout(`target ${input.targetId} status ${targetStatus ?? "unknown"}`);

  return {
    ok: true,
    status: 201,
    error: null,
    correctionId,
    targetStatus,
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = disputePlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(BAD_ARGUMENTS);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  // A fields file that cannot be read or parsed is a usage failure, not a
  // refusal: nothing was ever asked of the log.
  let fields: unknown;
  try {
    fields = JSON.parse(await readFile(resolve(plan.fieldsPath), "utf8"));
  } catch (error) {
    io.stderr(`${plan.fieldsPath}: ${reasonOf(error)}`);
    process.exit(BAD_ARGUMENTS);
  }

  let code: number = FAILED;
  try {
    const run = await runDispute({
      key: await readKeyFile(plan.keyPath),
      baseUrl: plan.baseUrl,
      targetId: plan.targetId,
      fields,
      fromReport: plan.fromReport,
      fromRevalidation: plan.fromRevalidation,
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        io,
      },
    });
    if (!run.ok && run.status === null) {
      io.stderr(`dispute: ${run.error ?? "unknown error"}`);
    }
    code = run.ok ? OK : FAILED;
  } catch (error) {
    io.stderr(`dispute: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

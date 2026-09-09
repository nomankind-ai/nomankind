/**
 * submit: an author's own client for POST /entries.
 *
 * Whitepaper, Lifecycle of an entry, Submit: "An agent posts a signed entry ...
 * The source is snapshotted at the moment of submission and its normalized hash
 * frozen into the record." This command is the author's half of that sentence.
 * It reads the fields the author chose, fetches the citation itself under the
 * norm rule, hashes what it got with the kernel's own snapshotHash, fills in
 * `snapshot_hash`, builds the core through src/submit.ts's buildSubmittedCore —
 * which names the entry, stamps the submission time and the norm version in
 * force — signs that core with the author's key, and posts it as a signed
 * request. Nothing is decided here: the Worker fetches the same page for itself
 * and refuses the submission if the two hashes disagree.
 *
 * The author chooses ten fields and no more. `id`, `submitted_at`,
 * `norm_version`, `signature`, `snapshot_hash` and `evidence_tier` are the
 * submission's to fill in, and `author` and `author_operator` are the key's, so
 * naming any of them in the fields file is a mistake the command reports before
 * it touches the network rather than a value it quietly overwrites.
 *
 * `author_operator` is read from the registry, not from the fields file and not
 * from the key file: the kernel refuses a submission whose author_operator is
 * not the operator the registry puts behind the signing key at that moment
 * (`author_operator_mismatch`), so the registry is the only answer that can be
 * right. A bare key has none and the entry names none.
 *
 * What this command does not carry: the receipt of an observed entry and the
 * frozen transcript of a behavior or misbehavior entry. Those two snapshot
 * their evidence rather than the cited page, so their hashes are not this
 * command's to compute; a fields file naming one is submitted honestly and the
 * Worker's own refusal is printed.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives it in process against handleRequest with
 * no network at all. `main` is thin. A private key is never printed. node:fs
 * and node:path are allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { signCore } from "../sign.js";
import { buildSubmittedCore } from "../submit.js";
import {
  errorOf,
  fetchAndHash,
  getJson,
  readKeyFile,
  reasonOf,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE = "usage: submit <key.json> <base-url> <fields.json>";

/** The one refusal this command makes for itself, before any request. */
export const BAD_FIELDS = "bad_fields";

/**
 * The author's own fields of the signed core: everything the schema puts in the
 * core except the ones submission fills in and the ones the key decides.
 */
export const AUTHOR_FIELDS: readonly string[] = Object.freeze([
  "subject",
  "category",
  "claim",
  "before",
  "after",
  "effective_at",
  "citation",
  "evidence",
  "observation",
  "supersedes",
] as const);

/** The fields with no default: a core cannot be built without them. */
const REQUIRED_FIELDS: readonly string[] = Object.freeze([
  "subject",
  "category",
  "claim",
  "before",
  "after",
  "effective_at",
  "citation",
] as const);

/** Everything a run needs besides its arguments. All of it injected. */
export interface SubmitDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** The fields file, read: accepted as they stand, or refused with a reason. */
export type FieldsVerdict =
  | { ok: true; fields: Record<string, unknown> }
  | { ok: false; reason: string; detail: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Read a fields file as the author's own fields, or refuse it.
 *
 * Pure and synchronous, and run before anything is fetched or asked of the
 * Worker: a file naming a field the author does not choose is a mistake about
 * what a submission is, and answering it with a network round trip would only
 * delay the same message.
 */
export function checkFields(fields: unknown): FieldsVerdict {
  if (!isRecord(fields)) {
    return { ok: false, reason: BAD_FIELDS, detail: "not a JSON object" };
  }
  const unknown = Object.keys(fields).filter(
    (key) => !AUTHOR_FIELDS.includes(key),
  );
  if (unknown.length > 0) {
    return {
      ok: false,
      reason: BAD_FIELDS,
      detail: `not the author's to set: ${unknown.join(", ")}`,
    };
  }
  const missing = REQUIRED_FIELDS.filter(
    (key) => typeof fields[key] !== "string",
  );
  if (missing.length > 0) {
    return {
      ok: false,
      reason: BAD_FIELDS,
      detail: `missing or not a string: ${missing.join(", ")}`,
    };
  }
  const supersedes = fields["supersedes"];
  if (
    supersedes !== undefined &&
    supersedes !== null &&
    typeof supersedes !== "string"
  ) {
    return {
      ok: false,
      reason: BAD_FIELDS,
      detail: "supersedes: not an entry id or null",
    };
  }
  for (const key of ["evidence", "observation"] as const) {
    const value = fields[key];
    if (value !== undefined && value !== null && !isRecord(value)) {
      return {
        ok: false,
        reason: BAD_FIELDS,
        detail: `${key}: not an object or null`,
      };
    }
  }
  return { ok: true, fields };
}

/**
 * The operator the registry puts behind one key, or null when it has none.
 *
 * The validator asks the same question of the same route; this is the one place
 * the two client commands of M15 read it from, so a bare key answers null on
 * both doors for the same reason.
 */
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
  const operator = (body as Record<string, unknown> | null)?.["operator"];
  if (!isRecord(operator)) return null;
  const id = operator["id"];
  return typeof id === "string" ? id : null;
}

/** What one submission run did. `code` is the exit code the CLI reports. */
export interface SubmitRun {
  /** The entry is on the log. */
  readonly ok: boolean;
  /** 0 on 201, 1 on a refusal, 2 on a fields file this command will not send. */
  readonly code: 0 | 1 | 2;
  /** The submit route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** The id the kernel derived from the signed core, once one was built. */
  readonly entryId: string | null;
  /** The status the log gave the entry, which for a new entry is draft. */
  readonly entryStatus: string | null;
}

function stopped(error: string): SubmitRun {
  return {
    ok: false,
    code: 1,
    status: null,
    error,
    entryId: null,
    entryStatus: null,
  };
}

/**
 * Submit one entry: read the fields, capture the citation, build and sign the
 * core, and post it.
 */
export async function runSubmit(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly fields: Record<string, unknown>;
  readonly deps: SubmitDeps;
}): Promise<SubmitRun> {
  const { deps } = input;

  const checked = checkFields(input.fields);
  if (!checked.ok) {
    deps.io.stderr(`${checked.reason}: ${checked.detail}`);
    return {
      ok: false,
      code: 2,
      status: null,
      error: checked.reason,
      entryId: null,
      entryStatus: null,
    };
  }
  const fields = checked.fields;
  const citation = fields["citation"] as string;

  // Section 6: the source is snapshotted at the moment of submission. The
  // Worker fetches it again for itself and refuses a hash that disagrees.
  const captured = await fetchAndHash(deps.fetcher, citation);
  if (!captured.ok) return stopped(captured.reason);

  const core = await buildSubmittedCore(
    {
      subject: fields["subject"] as string,
      category: fields["category"] as string,
      claim: fields["claim"] as string,
      before: fields["before"] as string,
      after: fields["after"] as string,
      effective_at: fields["effective_at"] as string,
      evidence: fields["evidence"],
      observation: fields["observation"],
      citation,
      snapshot_hash: captured.snapshot.hash,
      supersedes: (fields["supersedes"] as string | null | undefined) ?? null,
      author: input.key.agentId,
      author_operator: await operatorFor(
        deps.http,
        input.baseUrl,
        input.key.agentId,
      ),
    },
    { now: deps.now.toISOString() },
  );
  const entryId = core["id"] as string;

  const signature = await signCore(core, input.key.privateKey);
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: "/entries",
    body: { entry: { ...core, signature } },
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

  if (response.status === 201) {
    const status = isRecord(body) ? body["status"] : null;
    const entryStatus = typeof status === "string" ? status : null;
    deps.io.stdout(`entry ${entryId} status ${entryStatus ?? "unknown"}`);
    return { ok: true, code: 0, status: 201, error: null, entryId, entryStatus };
  }

  const error = errorOf(body);
  deps.io.stdout(
    `response ${response.status}${error === null ? "" : ` ${error}`}`,
  );
  return {
    ok: false,
    code: 1,
    status: response.status,
    error,
    entryId,
    entryStatus: null,
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const [keyPath, baseUrl, fieldsPath] = process.argv.slice(2);
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    fieldsPath === undefined ||
    process.argv.length > 5
  ) {
    console.error(USAGE);
    process.exit(2);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  // A fields file that cannot be read or parsed is a usage failure, not a
  // refusal: nothing was ever asked of the log.
  let fields: unknown;
  try {
    fields = JSON.parse(await readFile(resolve(fieldsPath), "utf8"));
  } catch (error) {
    io.stderr(`${fieldsPath}: ${reasonOf(error)}`);
    process.exit(2);
  }

  let code = 1;
  try {
    const run = await runSubmit({
      key: await readKeyFile(keyPath),
      baseUrl,
      fields: fields as Record<string, unknown>,
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        io,
      },
    });
    if (!run.ok && run.status === null && run.code === 1) {
      io.stderr(`submit: ${run.error ?? "unknown error"}`);
    }
    code = run.code;
  } catch (error) {
    io.stderr(`submit: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

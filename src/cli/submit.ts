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
 * `--receipt <file.json>` carries the measurement receipt of an observed entry
 * (M22, closing the M15 gap's client half). The artifact is checked with the
 * kernel's own `checkReceiptArtifact` and hashed with `receiptArtifactHash`
 * before anything is fetched, the hash fills `observation.receipt_hash` when the
 * fields file leaves it null, and the artifact itself goes out as the body's
 * `receipt`, which is where the submit door archives it at that hash. A fields
 * file that already names a receipt_hash is left alone: the author is claiming a
 * receipt already archived, and quietly overwriting the claim would hide the
 * disagreement rather than let the Worker refuse it.
 *
 * The fields file may also carry `disclosure` (D-096), which is not a core
 * field and is never signed: an object mapping each redaction placeholder's
 * JSON pointer into the transcript artifact to the value it replaced. It goes
 * out as the body's `disclosure`, where the submit door hashes each value
 * against its placeholder and archives the object at its own content address,
 * to be published when the domain's disclosure window closes. The transcript's
 * own hash is over the artifact as submitted, placeholders included, so nothing
 * here changes what the author signed.
 *
 * `--transcript <file.json>` carries the frozen transcript artifact of a
 * behavior or misbehavior entry, which snapshots its evidence rather than the
 * cited page (the #64 gap, D-084). The artifact goes through the kernel's own
 * `transcriptArtifactHash`, which refuses a shape that is not a transcript in
 * the kernel's own words before anything is fetched; its six measured fields
 * fill the fields file's `evidence` wherever that file leaves one null, and the
 * hash it returns becomes the core's
 * `snapshot_hash`, which for these categories is the hash of the artifact and
 * not of a page. Nothing is fetched on this path at all: the door rebuilds the
 * same artifact from the same `evidence` and archives it at the same hash, so
 * there is no page to snapshot and no second copy to send. A fields file whose
 * `evidence` already names a measured field is left alone, as a receipt_hash is,
 * and one that names a transcript the file does not is refused here in one line
 * rather than posted for the door to answer `snapshot_mismatch`.
 *
 * `--disclosure <file.json>` is the same body field the fields file may carry,
 * read from a file instead: it goes out as the body's `disclosure` unchanged.
 * Naming it both ways is a usage error, because one of the two would have to be
 * dropped and neither is the obvious loser.
 *
 * A receipt and a transcript are never both: an observed entry rests on a
 * measurement receipt and a transcript entry on its transcript, and a submission
 * offering both is a mistake about which kind of entry is being made, refused
 * before anything is fetched.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives it in process against handleRequest with
 * no network at all. `main` is thin. A private key is never printed. node:fs
 * and node:path are allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import {
  checkReceiptArtifact,
  receiptArtifactHash,
  transcriptArtifactHash,
  TRANSCRIPT_ARTIFACT_KEYS,
} from "../artifact.js";
import type { Core } from "../core.js";
import { canonicalize } from "../hash.js";
import { signCore } from "../sign.js";
import { buildSubmittedCore } from "../submit.js";
import { runCommand } from "./main.js";
import {
  errorOf,
  fetchAndHash,
  getJson,
  operatorFor,
  readKeyFile,
  reasonOf,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

/**
 * Why a submission carries one artifact and not two, in the words both the
 * usage line and the refusal use: one sentence, said in one place, so a reader
 * who meets it on the command line and again on stderr meets the same rule.
 */
export const BOTH_ARTIFACTS =
  "an observed entry carries a receipt and a transcript entry a transcript, never both";

/** The usage line, and the one thing about the flags it cannot show. */
export const USAGE = [
  "usage: submit <key.json> <base-url> <fields.json> [--receipt <file.json>]",
  "                [--transcript <file.json>] [--disclosure <file.json>]",
  BOTH_ARTIFACTS,
].join("\n");

/** The flags that take the file after them. Each is dropped by its index. */
const FILE_FLAGS = ["--receipt", "--transcript", "--disclosure"] as const;

/** The one refusal this command makes for itself, before any request. */
export const BAD_FIELDS = "bad_fields";

/**
 * The fields file's keys that are not core fields but body fields (D-096).
 *
 * `disclosure` is the originals behind a redacted transcript payload: an object
 * mapping each placeholder's JSON pointer into the artifact to the value it
 * replaced. It is not signed and it is not in the core -- the transcript's hash
 * is over the artifact as submitted, placeholders included, which is the whole
 * point of the rule -- so it travels beside the entry in the body, exactly as
 * `--receipt` does, and the door decides it.
 *
 * The fields file is still where it belongs when the author writes it by hand:
 * it is their own material about their own evidence, and a transcript entry's
 * evidence is already in that file. `--disclosure` is the same body field for a
 * payload a runner wrote to its own file, which is how a seeded transcript
 * arrives. One or the other, never both: two disclosures for one entry would
 * make one of them silently lose.
 */
export const BODY_FIELDS: readonly string[] = Object.freeze(["disclosure"]);

/**
 * The author's own fields of the signed core: everything the schema puts in the
 * core except the ones submission fills in and the ones the key decides.
 */
export const AUTHOR_FIELDS: readonly string[] = Object.freeze([
  "subject",
  "category",
  // The registered domain the fact is filed in (decision D-071). The author's
  // to choose and the author's to sign: `domain` is a key of the frozen core,
  // so an entry can never be re-homed after the fact.
  "domain",
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
  // Required and with no default: the author names the domain they sign, and a
  // fields file without one is refused `bad_fields` before any I/O.
  "domain",
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
    (key) => !AUTHOR_FIELDS.includes(key) && !BODY_FIELDS.includes(key),
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
  // The shape and nothing more: which pointers a disclosure must carry, and
  // whether each value hashes to the placeholder it stands for, is the door's
  // judgment (`disclosure_missing`, `disclosure_mismatch`), and a client that
  // decided it here would be a second rule to disagree with the first.
  const disclosure = fields["disclosure"];
  if (
    disclosure !== undefined &&
    disclosure !== null &&
    !isRecord(disclosure)
  ) {
    return {
      ok: false,
      reason: BAD_FIELDS,
      detail: "disclosure: not an object or null",
    };
  }
  return { ok: true, fields };
}

/**
 * The operator the registry puts behind one key, or null when it has none.
 *
 * The validator asks the same question of the same route (decision D-124), so
 * the one implementation lives beside that read (./validator.ts) and this is
 * the name the commands of M15 have always imported it under.
 */
export { operatorFor } from "./validator.js";

/**
 * A core built and ready to sign, or the reason the run stopped before one
 * could be.
 *
 * `usage` is what tells a mistake about the fields file from a refusal: a file
 * naming a field the author does not choose was never a submission at all, and
 * the CLI exits 2 rather than 1 for it.
 */
export type CoreAttempt =
  | { ok: true; core: Core }
  | { ok: false; reason: string; detail: string | null; usage: boolean };

/**
 * Read an author's fields, capture the citation, and build the signed core.
 *
 * The whole front half of a submission, in one place, because the dispute
 * command needs exactly it: Section 6's challenge "is itself an entry, in the
 * correction category", so a challenger builds a core the same way an author
 * does — the same checked fields, the same fetch under the norm rule, the same
 * `buildSubmittedCore` naming and stamping it, the same `author_operator` read
 * from the registry rather than guessed. Two commands doing that two ways would
 * be two ways for the same core to come out different.
 *
 * Nothing is signed and nothing is sent here.
 */
export async function buildAuthoredCore(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly fields: Record<string, unknown>;
  /**
   * The snapshot hash, when the caller already holds it. A transcript entry's
   * snapshot is the frozen artifact and not the cited page, so the norm rule
   * leaves nothing to fetch there; every other entry leaves this unset and the
   * citation is captured here as it always was.
   */
  readonly snapshotHash?: string;
  readonly deps: {
    readonly http: HttpClient;
    readonly fetcher: SnapshotFetcher;
    readonly now: Date;
  };
}): Promise<CoreAttempt> {
  const { deps } = input;

  const checked = checkFields(input.fields);
  if (!checked.ok) {
    return {
      ok: false,
      reason: checked.reason,
      detail: checked.detail,
      usage: true,
    };
  }
  const fields = checked.fields;
  const citation = fields["citation"] as string;

  // Section 6: the source is snapshotted at the moment of submission. The
  // Worker fetches it again for itself and refuses a hash that disagrees. A
  // caller carrying a transcript's hash has already snapshotted what its norm
  // rule snapshots, and fetching the citation here would hash a page nobody
  // compares it to.
  let snapshotHash = input.snapshotHash;
  if (snapshotHash === undefined) {
    const captured = await fetchAndHash(deps.fetcher, citation);
    if (!captured.ok) {
      return { ok: false, reason: captured.reason, detail: null, usage: false };
    }
    snapshotHash = captured.snapshot.hash;
  }

  const core = await buildSubmittedCore(
    {
      subject: fields["subject"] as string,
      category: fields["category"] as string,
      domain: fields["domain"] as string,
      claim: fields["claim"] as string,
      before: fields["before"] as string,
      after: fields["after"] as string,
      effective_at: fields["effective_at"] as string,
      evidence: fields["evidence"],
      observation: fields["observation"],
      citation,
      snapshot_hash: snapshotHash,
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
  return { ok: true, core };
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
 * A run this command will not send: the reason and its one line on stderr.
 *
 * Every one of these is decided before anything is fetched or asked of the log,
 * so the exit code is 2 — a call that was never a submission — and not the 1
 * that means the log refused one.
 */
function notSent(io: ValidatorIo, reason: string, detail: string): SubmitRun {
  io.stderr(`${reason}: ${detail}`);
  return {
    ok: false,
    code: 2,
    status: null,
    error: reason,
    entryId: null,
    entryStatus: null,
  };
}

/**
 * The `evidence` a transcript entry signs: the author's own, with each measured
 * field the artifact carries filled in where the fields file leaves it null.
 *
 * `provider_statement` is never the artifact's — it is a citation, not a
 * measurement, and `buildTranscriptArtifact` drops it for exactly that reason —
 * so it is carried through as the author wrote it, and defaulted to null so the
 * key the schema requires is always present.
 */
function evidenceWithTranscript(
  named: unknown,
  artifact: Record<string, unknown>,
): Record<string, unknown> {
  const author = isRecord(named) ? named : {};
  return {
    ...author,
    ...artifact,
    provider_statement: author["provider_statement"] ?? null,
  };
}

/**
 * The measured fields a fields file names differently from the artifact.
 *
 * The door rebuilds the transcript from the entry's own `evidence` and hashes
 * that, so an author whose evidence says one thing and whose transcript file
 * says another has signed a snapshot_hash of neither. Compared in the kernel's
 * canonical form, because `parameters` is an object and two objects that differ
 * only in key order are the same measurement.
 */
function transcriptDisagreements(
  named: unknown,
  artifact: Record<string, unknown>,
): string[] {
  const author = isRecord(named) ? named : {};
  return TRANSCRIPT_ARTIFACT_KEYS.filter((key) => {
    const value = author[key];
    return (
      value !== undefined &&
      value !== null &&
      canonicalize(value) !== canonicalize(artifact[key])
    );
  });
}

/**
 * Submit one entry: read the fields, capture the citation, build and sign the
 * core, and post it.
 */
export async function runSubmit(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly fields: Record<string, unknown>;
  /** The measurement receipt of an observed entry, when there is one. */
  readonly receipt?: unknown;
  /** The frozen transcript artifact of a transcript entry, when there is one. */
  readonly transcript?: unknown;
  /** The originals behind a redacted transcript, read from their own file. */
  readonly disclosure?: unknown;
  readonly deps: SubmitDeps;
}): Promise<SubmitRun> {
  const { deps } = input;

  let fields = input.fields;

  // Which kind of entry this is, before anything else: an entry rests on a
  // measurement receipt or on a transcript, and one offering both names no kind
  // at all.
  if (input.receipt !== undefined && input.transcript !== undefined) {
    return notSent(deps.io, BAD_FIELDS, BOTH_ARTIFACTS);
  }
  if (input.disclosure !== undefined && fields["disclosure"] !== undefined) {
    return notSent(
      deps.io,
      BAD_FIELDS,
      "disclosure: named by the fields file and by --disclosure",
    );
  }

  // The receipt first, because its hash goes INTO the signed core: an artifact
  // the kernel refuses is a usage failure and never reaches the network, and a
  // hash computed after the core was built would be a hash of something the
  // author never signed.
  if (input.receipt !== undefined) {
    const checked = checkReceiptArtifact(input.receipt);
    if (!checked.ok) {
      return notSent(deps.io, checked.reason, checked.detail);
    }
    const hashed = await receiptArtifactHash(input.receipt);
    /* c8 ignore next 3 -- unreachable: the check above already passed. */
    if (!hashed.ok) {
      return notSent(deps.io, hashed.reason, hashed.detail);
    }
    const observation = fields["observation"];
    if (
      isRecord(observation) &&
      (observation["receipt_hash"] === null ||
        observation["receipt_hash"] === undefined)
    ) {
      fields = {
        ...fields,
        observation: { ...observation, receipt_hash: hashed.hash },
      };
    }
  }

  // The transcript next, and for the same reason: its hash is the entry's
  // snapshot_hash, so it is checked and hashed by the kernel's own rule before
  // anything is fetched, and the artifact's measured fields are the evidence the
  // author signs.
  let snapshotHash: string | undefined;
  if (input.transcript !== undefined) {
    // The hash is the check: `transcriptArtifactHash` refuses the shape itself,
    // in the kernel's own reason and detail, so asking twice would only be a
    // second place for the two answers to differ.
    const hashed = await transcriptArtifactHash(input.transcript);
    if (!hashed.ok) {
      return notSent(deps.io, hashed.reason, hashed.detail);
    }
    const artifact = input.transcript as Record<string, unknown>;
    const named = fields["evidence"];
    if (named !== undefined && named !== null && !isRecord(named)) {
      // The refusal `checkFields` makes, reached before the filling rather than
      // after it: an evidence that is not an object cannot be completed from an
      // artifact, and completing it anyway would answer the author's mistake by
      // replacing it.
      return notSent(deps.io, BAD_FIELDS, "evidence: not an object or null");
    }
    const disagreeing = transcriptDisagreements(named, artifact);
    if (disagreeing.length > 0) {
      return notSent(
        deps.io,
        BAD_FIELDS,
        `evidence names a transcript this file is not: ${disagreeing.join(", ")}`,
      );
    }
    fields = { ...fields, evidence: evidenceWithTranscript(named, artifact) };
    snapshotHash = hashed.hash;
  }

  const built = await buildAuthoredCore({
    key: input.key,
    baseUrl: input.baseUrl,
    fields,
    ...(snapshotHash === undefined ? {} : { snapshotHash }),
    deps,
  });
  if (!built.ok) {
    if (!built.usage) return stopped(built.reason);
    deps.io.stderr(`${built.reason}: ${built.detail ?? ""}`);
    return {
      ok: false,
      code: 2,
      status: null,
      error: built.reason,
      entryId: null,
      entryStatus: null,
    };
  }
  const { core } = built;
  const entryId = core["id"] as string;

  // One body field, two spellings: the flag when it was given, the fields file
  // otherwise. Naming both was refused above.
  const disclosure = input.disclosure ?? fields["disclosure"];

  const signature = await signCore(core, input.key.privateKey);
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: "/entries",
    body: {
      entry: { ...core, signature },
      // The artifact itself, untouched: the hash the Worker takes is over
      // exactly these bytes, and it archives it at that hash.
      ...(input.receipt === undefined ? {} : { receipt: input.receipt }),
      // The originals behind a redacted payload, as the fields file or the
      // `--disclosure` file carried them and untouched for the same reason: the
      // door hashes each value and refuses one that is not the placeholder's
      // (D-096). Absent when neither names one, and never sent as null, because
      // a body key present with nothing in it is a disclosure claim about
      // nothing.
      ...(isRecord(disclosure) ? { disclosure } : {}),
    },
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

/** The three paths the command needs, and the optional artifact files. */
export interface SubmitArgs {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly fieldsPath: string;
  readonly receiptPath?: string;
  readonly transcriptPath?: string;
  readonly disclosurePath?: string;
}

/**
 * The command line, parsed. `null` is "print the usage line": a pure function so
 * the argument shapes can be checked without a process.
 *
 * Each file flag takes the argument after it, and those arguments are the only
 * non-flag words that are not positional. They are dropped by index, and only
 * when the flag is actually there: without it `indexOf` returns -1, and a filter
 * that dropped index `-1 + 1` would eat the key path out of every plain call. A
 * flag whose next word is another flag, or is missing, names no file.
 *
 * A receipt and a transcript together are refused here rather than sent: they
 * are the evidence of two different kinds of entry, and the usage line says so.
 */
export function parseSubmitArgs(argv: readonly string[]): SubmitArgs | null {
  const paths: Partial<Record<(typeof FILE_FLAGS)[number], string>> = {};
  const taken = new Set<number>();
  for (const flag of FILE_FLAGS) {
    const at = argv.indexOf(flag);
    if (at === -1) continue;
    const path = argv[at + 1];
    if (path === undefined || path.startsWith("--")) return null;
    paths[flag] = path;
    taken.add(at + 1);
  }
  const positional = argv.filter(
    (argument, index) => !taken.has(index) && !argument.startsWith("--"),
  );
  const [keyPath, baseUrl, fieldsPath] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    fieldsPath === undefined ||
    positional.length > 3 ||
    (paths["--receipt"] !== undefined && paths["--transcript"] !== undefined)
  ) {
    return null;
  }
  const receiptPath = paths["--receipt"];
  const transcriptPath = paths["--transcript"];
  const disclosurePath = paths["--disclosure"];
  return {
    keyPath,
    baseUrl,
    fieldsPath,
    ...(receiptPath === undefined ? {} : { receiptPath }),
    ...(transcriptPath === undefined ? {} : { transcriptPath }),
    ...(disclosurePath === undefined ? {} : { disclosurePath }),
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const parsed = parseSubmitArgs(process.argv.slice(2));
  if (parsed === null) {
    console.error(USAGE);
    process.exit(2);
  }
  const { keyPath, baseUrl, fieldsPath } = parsed;

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  // A file that cannot be read or parsed is a usage failure, not a refusal:
  // nothing was ever asked of the log. The fields file and every artifact file
  // are read the same way and for the same reason.
  const readJson = async (path: string): Promise<unknown> => {
    try {
      return JSON.parse(await readFile(resolve(path), "utf8"));
    } catch (error) {
      io.stderr(`${path}: ${reasonOf(error)}`);
      process.exit(2);
    }
  };

  const fields = await readJson(fieldsPath);
  const receipt =
    parsed.receiptPath === undefined
      ? undefined
      : await readJson(parsed.receiptPath);
  const transcript =
    parsed.transcriptPath === undefined
      ? undefined
      : await readJson(parsed.transcriptPath);
  const disclosure =
    parsed.disclosurePath === undefined
      ? undefined
      : await readJson(parsed.disclosurePath);

  process.exit(
    await runCommand({ name: "submit", baseUrl, io }, async () => {
      const run = await runSubmit({
        key: await readKeyFile(keyPath),
        baseUrl,
        fields: fields as Record<string, unknown>,
        ...(receipt === undefined ? {} : { receipt }),
        ...(transcript === undefined ? {} : { transcript }),
        ...(disclosure === undefined ? {} : { disclosure }),
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
      return run.code;
    }),
  );
}
/* c8 ignore stop */

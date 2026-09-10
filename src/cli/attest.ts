/**
 * attest: the fixture model and the fixture scorer, clients of the Worker and
 * nothing else.
 *
 * Whitepaper Section 8, "Drift attestation": "A probe set is drawn from
 * verified, observed, fresh entries by public randomness ... The model answers
 * the probes. Three operators from the trusted pool, none under the model's
 * operator, score its answers against the log and sign the result." Three
 * subcommands, one per sentence: `request` asks for the probe set, `answer`
 * sends the model's answers, and `score` signs one operator's verdict. The
 * Worker judges all three; nothing here writes to the log and nothing here
 * decides a rule.
 *
 * A fixture model has no beliefs, so `answer` gives back the log's own answer by
 * default: each probe is answered with the cited entry's `claim`, read from the
 * Worker. That is a model in perfect agreement, which is the useful baseline —
 * and `--drift` is the other end of it, answering every probe with the word
 * `drifted`, which scores zero. A real model's answers come from a file through
 * `--answers`, and this command sends them untouched.
 *
 * A fixture scorer is the same shape of thing: it reads the attestation, reads
 * each probed entry's claim from the log, and counts a probe agreed when the
 * model's answer and the claim are equal after `normalizeText` — the norm rule's
 * own step 4, so a difference in whitespace or unicode form is not drift. Then
 * it signs the `nomankind-record-v1` record with the kind `attestation_score`
 * over the attestation id and posts it. Judging prose is not something a fixture
 * can do, and pretending otherwise would put a judgment in the log that nobody
 * made.
 *
 * The core is exported over injected io — an http client, a clock and a key — so
 * a test drives it in process against handleRequest with no network at all.
 * `main` is thin. A private key is never printed. node:fs and node:path are
 * allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import type { AttestationScoreRecord, Probe } from "../events.js";
import { normalizeText } from "../normalize.js";
import { signRecord } from "../records.js";
import { operatorFor } from "./submit.js";
import {
  WebHttpClient,
  errorOf,
  getJson,
  readKeyFile,
  reasonOf,
  signedPost,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE = [
  "usage: attest request <key.json> <base-url>",
  "       attest answer <key.json> <base-url> <id> [--answers <file.json>] [--drift]",
  "       attest score <key.json> <base-url> <id>",
].join("\n");

/** The exit codes, named where they are decided. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** What a drifted model says about everything it is asked. */
export const DRIFT_ANSWER = "drifted";

/** Everything a run needs besides its arguments. All of it injected. */
export interface AttestDeps {
  readonly http: HttpClient;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one run did. `code` is the exit code the CLI reports. */
export interface AttestRun {
  readonly ok: boolean;
  readonly code: 0 | 1 | 2;
  /** The route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** The attestation the run acted on, once one was known. */
  readonly attestation: string | null;
  /** The attestation's status as the door reported it back. */
  readonly attestationStatus: string | null;
  /** The probes agreed, for a score; null for the other two subcommands. */
  readonly agreed: number | null;
}

function stopped(error: string, attestation: string | null = null): AttestRun {
  return {
    ok: false,
    code: FAILED,
    status: null,
    error,
    attestation,
    attestationStatus: null,
    agreed: null,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The status field of whatever the door answered, or null. */
function statusOf(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const status = body["status"];
  return typeof status === "string" ? status : null;
}

/**
 * One signed write, posted and read back the same way in all three subcommands:
 * the status, the refusal it named, and the attestation it answered with.
 */
async function post(
  input: {
    readonly key: ValidatorKey;
    readonly baseUrl: string;
    readonly path: string;
    readonly body: unknown;
    readonly ok: number;
    readonly deps: AttestDeps;
  },
): Promise<{ status: number; error: string | null; body: unknown }> {
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: input.path,
    body: input.body,
    key: input.key,
    now: input.deps.now,
  });
  const response = await input.deps.http.fetch(request);
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  const error = response.status === input.ok ? null : errorOf(body);
  input.deps.io.stdout(
    `response ${response.status}${error === null ? "" : ` ${error}`}`,
  );
  return { status: response.status, error, body };
}

// ---------------------------------------------------------------------------
// attest request
// ---------------------------------------------------------------------------

/**
 * Ask for a probe set. The body is empty on purpose: the probes and the three
 * scorers are drawn by public randomness, so there is nothing for a model to ask
 * for beyond the asking.
 */
export async function runRequest(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly deps: AttestDeps;
}): Promise<AttestRun> {
  const answered = await post({
    key: input.key,
    baseUrl: input.baseUrl,
    path: "/attestations",
    body: {},
    ok: 201,
    deps: input.deps,
  });

  if (answered.status !== 201) {
    return {
      ok: false,
      code: FAILED,
      status: answered.status,
      error: answered.error,
      attestation: null,
      attestationStatus: null,
      agreed: null,
    };
  }

  const body = answered.body as Record<string, unknown>;
  const id = typeof body["id"] === "string" ? body["id"] : null;
  const probes = Array.isArray(body["probes"]) ? body["probes"].length : 0;
  const scorers = Array.isArray(body["scorers"]) ? body["scorers"].length : 0;
  input.deps.io.stdout(
    `attestation ${id ?? "unknown"} probes ${probes} scorers ${scorers} deadline ${String(body["deadline"])}`,
  );
  return {
    ok: true,
    code: OK,
    status: 201,
    error: null,
    attestation: id,
    attestationStatus: statusOf(body),
    agreed: null,
  };
}

// ---------------------------------------------------------------------------
// Reading an attestation, and the entries it probes
// ---------------------------------------------------------------------------

/** One attestation as the read route serves it: the record, plus the answers. */
interface ServedAttestation {
  readonly probes: readonly Probe[];
  readonly probe_hash: string;
  readonly answers_hash: string | null;
  readonly answers: readonly { entry_id: string; answer: string }[] | null;
}

type Served =
  | { ok: true; attestation: ServedAttestation }
  | { ok: false; error: string };

async function readAttestation(
  deps: AttestDeps,
  baseUrl: string,
  id: string,
): Promise<Served> {
  const { status, body } = await getJson(
    deps.http,
    baseUrl,
    `/attestations/${encodeURIComponent(id)}`,
  );
  if (status !== 200 || !isRecord(body)) {
    return { ok: false, error: errorOf(body) ?? `attestation_unreadable_${status}` };
  }
  if (!Array.isArray(body["probes"]) || typeof body["probe_hash"] !== "string") {
    return { ok: false, error: "attestation_malformed" };
  }
  return { ok: true, attestation: body as unknown as ServedAttestation };
}

/**
 * The claim one probed entry makes, read from the Worker.
 *
 * The log's own answer to the probe: what the record says is true about that
 * subject right now. Null when the entry cannot be read, which is a stopped run
 * rather than a wrong answer — a fixture that answered "" for an unreadable
 * entry would be scoring the network rather than the model.
 */
async function claimOf(
  deps: AttestDeps,
  baseUrl: string,
  entryId: string,
): Promise<string | null> {
  const { status, body } = await getJson(
    deps.http,
    baseUrl,
    `/entries/${encodeURIComponent(entryId)}`,
  );
  if (status !== 200 || !isRecord(body)) return null;
  const claim = body["claim"];
  return typeof claim === "string" ? claim : null;
}

// ---------------------------------------------------------------------------
// attest answer
// ---------------------------------------------------------------------------

/**
 * Answer the probes.
 *
 * `answers` is a file the caller supplies, sent untouched. Without one this
 * fixture answers each probe with the cited entry's own claim — a model in
 * perfect agreement — and `--drift` answers every probe with `drifted`, which
 * agrees with nothing.
 */
export async function runAnswer(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly attestation: string;
  readonly answers?: unknown;
  readonly drift?: boolean;
  readonly deps: AttestDeps;
}): Promise<AttestRun> {
  const { deps } = input;
  const served = await readAttestation(deps, input.baseUrl, input.attestation);
  if (!served.ok) return stopped(served.error, input.attestation);

  let answers: unknown = input.answers;
  if (answers === undefined) {
    const built: { entry_id: string; answer: string }[] = [];
    for (const probe of served.attestation.probes) {
      if (input.drift === true) {
        built.push({ entry_id: probe.entry_id, answer: DRIFT_ANSWER });
        continue;
      }
      const claim = await claimOf(deps, input.baseUrl, probe.entry_id);
      if (claim === null) return stopped("entry_unreadable", input.attestation);
      built.push({ entry_id: probe.entry_id, answer: claim });
    }
    answers = built;
  }

  const answered = await post({
    key: input.key,
    baseUrl: input.baseUrl,
    path: `/attestations/${encodeURIComponent(input.attestation)}/answers`,
    body: { answers },
    ok: 200,
    deps,
  });

  return {
    ok: answered.status === 200,
    code: answered.status === 200 ? OK : FAILED,
    status: answered.status,
    error: answered.error,
    attestation: input.attestation,
    attestationStatus: statusOf(answered.body),
    agreed: null,
  };
}

// ---------------------------------------------------------------------------
// attest score
// ---------------------------------------------------------------------------

/**
 * Score the answers.
 *
 * A probe is agreed when the model's answer and the entry's claim are equal
 * after `normalizeText`, which is the norm rule's own step 4: a difference in
 * whitespace, line endings or unicode form is not drift, and treating it as
 * drift would publish a lower score than the log supports.
 */
export async function runScore(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly attestation: string;
  readonly deps: AttestDeps;
}): Promise<AttestRun> {
  const { deps } = input;
  const served = await readAttestation(deps, input.baseUrl, input.attestation);
  if (!served.ok) return stopped(served.error, input.attestation);
  const { probes, probe_hash, answers_hash, answers } = served.attestation;

  if (answers === null || answers_hash === null) {
    return stopped("not_answered", input.attestation);
  }

  // Section 5: the operator is the unit, and the registry is the only answer
  // that can be right about which one is behind this key.
  const operator = await operatorFor(
    deps.http,
    input.baseUrl,
    input.key.agentId,
  );
  if (operator === null) return stopped("unregistered_agent", input.attestation);

  const said = new Map(answers.map((answer) => [answer.entry_id, answer.answer]));
  let agreed = 0;
  for (const probe of probes) {
    const claim = await claimOf(deps, input.baseUrl, probe.entry_id);
    if (claim === null) return stopped("entry_unreadable", input.attestation);
    const answer = said.get(probe.entry_id);
    if (answer === undefined) continue;
    if (normalizeText(answer) === normalizeText(claim)) agreed += 1;
  }

  // Exactly the six keys `AttestationScoreRecord` names. The two hashes pin
  // which questions and which answers were scored, so this verdict can never be
  // moved onto a different probe set or a different set of answers.
  const record: AttestationScoreRecord = {
    agent: input.key.agentId,
    operator,
    agreed,
    probe_hash,
    answers_hash,
    signed_at: deps.now.toISOString(),
  };
  const signature = await signRecord(
    input.attestation,
    "attestation_score",
    record,
    input.key.privateKey,
  );

  deps.io.stdout(`agreed ${agreed} of ${probes.length}`);
  const answered = await post({
    key: input.key,
    baseUrl: input.baseUrl,
    path: `/attestations/${encodeURIComponent(input.attestation)}/score`,
    body: { record, signature },
    ok: 201,
    deps,
  });

  return {
    ok: answered.status === 201,
    code: answered.status === 201 ? OK : FAILED,
    status: answered.status,
    error: answered.error,
    attestation: input.attestation,
    attestationStatus: statusOf(answered.body),
    agreed,
  };
}

// ---------------------------------------------------------------------------
// The arguments
// ---------------------------------------------------------------------------

export type AttestSubcommand = "request" | "answer" | "score";

/** One run's arguments, read: which door, whose key, and against what. */
export interface AttestPlan {
  readonly subcommand: AttestSubcommand;
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly attestation: string | null;
  readonly answersPath: string | null;
  readonly drift: boolean;
}

/**
 * Read the arguments, or answer null for anything that is not one of the three
 * subcommands. Pure and synchronous, and run before anything is asked of the
 * Worker: a mistake about which door is being knocked on is a usage failure,
 * and a network round trip would only delay the same message.
 */
export function attestPlan(argv: readonly string[]): AttestPlan | null {
  const drift = argv.includes("--drift");
  const answersAt = argv.indexOf("--answers");
  let answersPath: string | null = null;
  const positional: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] as string;
    if (argument === "--drift") continue;
    if (argument === "--answers") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) return null;
      answersPath = value;
      index += 1;
      continue;
    }
    if (argument.startsWith("--")) return null;
    positional.push(argument);
  }
  if (answersAt !== -1 && answersPath === null) return null;

  const [subcommand, keyPath, baseUrl, attestation] = positional;
  if (keyPath === undefined || baseUrl === undefined) return null;
  if (subcommand === "request") {
    if (positional.length !== 3 || answersPath !== null || drift) return null;
    return {
      subcommand,
      keyPath,
      baseUrl,
      attestation: null,
      answersPath: null,
      drift: false,
    };
  }
  if (subcommand === "answer" || subcommand === "score") {
    if (positional.length !== 4 || attestation === undefined) return null;
    if (subcommand === "score" && (answersPath !== null || drift)) return null;
    // Answers from a file and a drifted model are two different answers to the
    // same probes, and a run naming both would have to pick one silently.
    if (answersPath !== null && drift) return null;
    return { subcommand, keyPath, baseUrl, attestation, answersPath, drift };
  }
  return null;
}

/** Run whichever door the plan named. */
export async function runAttest(input: {
  readonly plan: AttestPlan;
  readonly key: ValidatorKey;
  readonly answers?: unknown;
  readonly deps: AttestDeps;
}): Promise<AttestRun> {
  const { plan } = input;
  if (plan.subcommand === "request") {
    return runRequest({
      key: input.key,
      baseUrl: plan.baseUrl,
      deps: input.deps,
    });
  }
  if (plan.subcommand === "answer") {
    return runAnswer({
      key: input.key,
      baseUrl: plan.baseUrl,
      attestation: plan.attestation as string,
      ...(input.answers === undefined ? {} : { answers: input.answers }),
      drift: plan.drift,
      deps: input.deps,
    });
  }
  return runScore({
    key: input.key,
    baseUrl: plan.baseUrl,
    attestation: plan.attestation as string,
    deps: input.deps,
  });
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = attestPlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(BAD_ARGUMENTS);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };

  // An answers file that cannot be read or parsed is a usage failure, not a
  // refusal: nothing was ever asked of the log.
  let answers: unknown;
  if (plan.answersPath !== null) {
    try {
      answers = JSON.parse(await readFile(resolve(plan.answersPath), "utf8"));
    } catch (error) {
      io.stderr(`${plan.answersPath}: ${reasonOf(error)}`);
      process.exit(BAD_ARGUMENTS);
    }
  }

  let code: number = FAILED;
  try {
    const run = await runAttest({
      plan,
      key: await readKeyFile(plan.keyPath),
      ...(answers === undefined ? {} : { answers }),
      deps: { http: new WebHttpClient(), now: new Date(), io },
    });
    if (!run.ok && run.status === null) {
      io.stderr(`attest: ${run.error ?? "unknown error"}`);
    }
    code = run.code;
  } catch (error) {
    io.stderr(`attest: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

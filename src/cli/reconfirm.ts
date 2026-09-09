/**
 * reconfirm: the fixture reconfirmer, a client of the Worker and nothing else.
 *
 * Whitepaper, Lifecycle of an entry, Revalidate: "Any trusted operator can
 * reconfirm a stale entry by taking a fresh snapshot and signing that the source
 * still says what the entry says." Section 7, Freshness and decay: past its
 * window an entry stays verified but shows as stale, and the withheld half
 * builds up as a bounty "paid to whoever makes it fresh again". This command is
 * the operator's side of both sentences: it reads the entry, fetches the
 * citation itself under the entry's norm rule, hashes what it got with the
 * kernel's own snapshotHash, signs the schema's reconfirmations[] item over that
 * hash and posts it. The Worker judges the attestation; nothing here writes to
 * the log and nothing derived is ever sent in.
 *
 * Three shapes of attestation, and this fixture can make two of them:
 *
 * A stated entry is reconfirmed by the fresh snapshot hash and nothing else, so
 * this command reconfirms one only when its own hash is the entry's. A page that
 * has moved is not something a reconfirmation may paper over — Section 7 says a
 * changed fact is a superseding entry's job, not a reconfirmation's — so it
 * stops with `snapshot_mismatch` and sends nothing.
 *
 * An observed entry outside behavior and misbehavior is reconfirmed by a fresh
 * measurement, so this command reruns the entry's own proposed test exactly as
 * the fixture validator does: the same allowlist of predicate forms (D-031), the
 * same REPRODUCTION_RUNS fetches, the same receipt artifact, and its hash in the
 * observation it signs.
 *
 * A behavior or misbehavior entry is reconfirmed by rerunning the frozen prompt,
 * which needs a model this fixture has no way to call, so it stops with
 * `cannot_reproduce` rather than attesting to a rerun it never made. The same
 * answer covers an observed entry whose proposed test is outside the allowlist:
 * the measurement the rule asks for is one this fixture cannot make.
 *
 * The read-share slots the attestation rotates are derived in the ledger and not
 * carried on the entry (the schema says so outright), so the printed line comes
 * from rederiving the entry with the kernel's own src/derive.ts over the public
 * log the Worker just served. Nothing is recomputed by hand.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives it in process against handleRequest with no
 * network at all. `main` is thin. A private key is never printed. node:path is
 * allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { receiptArtifactHash } from "../artifact.js";
import { extractCore, type Core } from "../core.js";
import { deriveEntry } from "../derive.js";
import { isTranscriptCategory, proposedTest } from "../evidence.js";
import type { ReconfirmationRecord } from "../events.js";
import { NORM_VERSION } from "../policy.js";
import { signRecord } from "../records.js";
import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { readEvents } from "./export.js";
import { operatorFor } from "./submit.js";
import {
  buildValidatorReceipt,
  errorOf,
  fetchAndHash,
  getJson,
  parsePredicate,
  readKeyFile,
  reasonOf,
  runPredicate,
  signedPost,
  SNAPSHOT_MISMATCH,
  WebHttpClient,
  type HttpClient,
  type Snapshot,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE = "usage: reconfirm <key.json> <base-url> <entry-id>";

/**
 * The reason this fixture stops when the rule asks for a measurement it has no
 * way to make: a model rerun, or a predicate outside the allowlist it can decide.
 */
export const CANNOT_REPRODUCE = "cannot_reproduce";

/** Everything a run needs besides its arguments. All of it injected. */
export interface ReconfirmDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one reconfirmation run did. */
export interface ReconfirmRun {
  /** The attestation is on the log. */
  readonly ok: boolean;
  /** The reconfirm route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** The record that was signed and sent, when one was. */
  readonly record: ReconfirmationRecord | null;
  /** The refreshed entry's derived last-confirmed date, on 201. */
  readonly lastConfirmed: string | null;
  /** The reopened window's end, on 201. */
  readonly expiresAt: string | null;
  /** The operators holding the read-share slots after this attestation. */
  readonly slots: readonly string[] | null;
}

function stopped(error: string): ReconfirmRun {
  return {
    ok: false,
    status: null,
    error,
    record: null,
    lastConfirmed: null,
    expiresAt: null,
    slots: null,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The observation this fixture measured for itself, or the reason it could not.
 *
 * The fixture validator's rerun, made again at reconfirmation time: the same
 * predicate out of the entry's own proposed test, the same n-of-k fetches, the
 * same eight-key receipt artifact, and the observation the schema's
 * reconfirmations[] item asks for.
 */
async function freshObservation(
  core: Core,
  deps: ReconfirmDeps,
  citation: string,
  snapshot: Snapshot,
  agentId: string,
): Promise<
  { ok: true; observation: Record<string, unknown> } | { ok: false; reason: string }
> {
  const predicate = parsePredicate(proposedTest(core));
  // A test this fixture cannot decide is a measurement it cannot make, and a
  // reconfirmation has no "validated as a document" fallback to fall to.
  if (predicate === null) return { ok: false, reason: CANNOT_REPRODUCE };

  const entryObservation = core["observation"];
  const method = isRecord(entryObservation)
    ? entryObservation["method"]
    : undefined;
  if (typeof method !== "string") {
    return { ok: false, reason: "missing_observation" };
  }

  const counts = await runPredicate(deps.fetcher, citation, predicate);
  const observedAt = deps.now.toISOString().slice(0, 10);
  const hashed = await receiptArtifactHash(
    buildValidatorReceipt({
      method,
      subject: core["subject"],
      test: `${predicate.form}:${predicate.value}`,
      citation,
      snapshot,
      observedAt,
      observer: agentId,
    }),
  );
  if (!hashed.ok) return { ok: false, reason: hashed.reason };

  return {
    ok: true,
    observation: {
      method,
      receipt_hash: hashed.hash,
      observed_at: observedAt,
      runs: counts.runs,
      holds: counts.holds,
    },
  };
}

/**
 * The operators holding the entry's read-share slots, rederived from the public
 * log with the kernel's own derivation.
 *
 * The schema keeps the slots out of the entry — "derived in the ledger, not
 * stored here" — so the only honest way to print them is to read the log the
 * Worker serves and run src/derive.ts over it. Null when the log could not be
 * read: the attestation is on the chain either way, and a failed read here must
 * not be reported as a failed reconfirmation.
 */
async function slotsFor(
  deps: ReconfirmDeps,
  baseUrl: string,
  entryId: string,
): Promise<readonly string[] | null> {
  try {
    const events = await readEvents(deps.http, baseUrl);
    const derived = deriveEntry(events, entryId, {
      now: deps.now.toISOString(),
    });
    return (derived.sidecar.read_share_slots ?? []).map((slot) => slot.operator);
  } catch {
    return null;
  }
}

/**
 * Reconfirm one entry: read it, fetch its citation, make the attestation its
 * shape asks for, sign it and post it.
 */
export async function runReconfirm(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly deps: ReconfirmDeps;
}): Promise<ReconfirmRun> {
  const { deps } = input;

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

  const operator = await operatorFor(
    deps.http,
    input.baseUrl,
    input.key.agentId,
  );
  if (operator === null) return stopped("unregistered_agent");

  // Section 4: reconfirming a behavior or misbehavior entry means rerunning the
  // frozen prompt. Asked before the citation is fetched, because a page this
  // fixture cannot judge is a page it has no reason to pull.
  if (isTranscriptCategory(core["category"])) {
    return stopped(CANNOT_REPRODUCE);
  }

  const citation = core["citation"];
  if (typeof citation !== "string") return stopped("unsupported_citation");

  const own = await fetchAndHash(deps.fetcher, citation);
  if (!own.ok) return stopped(own.reason);

  let observation: Record<string, unknown> | null = null;
  if (core["evidence_tier"] === "observed") {
    const measured = await freshObservation(
      core,
      deps,
      citation,
      own.snapshot,
      input.key.agentId,
    );
    if (!measured.ok) return stopped(measured.reason);
    observation = measured.observation;
  } else if (own.snapshot.hash !== core["snapshot_hash"]) {
    // Section 7: a source that has moved is superseded, never reconfirmed. The
    // attestation for a stated entry is the fresh hash and nothing else, so
    // there is nothing honest left to sign.
    return stopped(SNAPSHOT_MISMATCH);
  }

  // Every key the schema's reconfirmations[] item names, present, null where
  // the entry's shape leaves the slot unused.
  const record: ReconfirmationRecord = {
    agent: input.key.agentId,
    operator,
    snapshot_hash: own.snapshot.hash,
    reproduction: null,
    observation,
    signed_at: deps.now.toISOString(),
  };

  const signature = await signRecord(
    input.entryId,
    "reconfirmation",
    record,
    input.key.privateKey,
  );
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: `/entries/${encodeURIComponent(input.entryId)}/reconfirm`,
    body: { record, signature },
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
      record,
      lastConfirmed: null,
      expiresAt: null,
      slots: null,
    };
  }

  const entry = isRecord(body) ? body : {};
  const lastConfirmed =
    typeof entry["last_confirmed"] === "string" ? entry["last_confirmed"] : null;
  const expiresAt =
    typeof entry["expires_at"] === "string" ? entry["expires_at"] : null;
  const slots = await slotsFor(deps, input.baseUrl, input.entryId);

  deps.io.stdout(
    `last_confirmed ${lastConfirmed ?? "none"} expires_at ${expiresAt ?? "none"}`,
  );
  deps.io.stdout(
    `read_share_slots ${slots === null ? "unread" : slots.join(" ") || "none"}`,
  );

  return {
    ok: true,
    status: 201,
    error: null,
    record,
    lastConfirmed,
    expiresAt,
    slots,
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const [keyPath, baseUrl, entryId] = process.argv.slice(2);
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    entryId === undefined ||
    process.argv.length > 5
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
    const run = await runReconfirm({
      key: await readKeyFile(keyPath),
      baseUrl,
      entryId,
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        io,
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

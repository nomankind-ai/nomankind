/**
 * revalidate: an operator's client for the two revalidation doors.
 *
 * Whitepaper Section 6, "Revalidate": "Any operator can also request
 * revalidation of an entry inside its window by staking a small amount of
 * standing. No citation is needed; the request only asks for a check. It is
 * assigned at random to a trusted operator ... If the check finds the fact
 * changed, the requester gets the stake back plus a challenger-style reward. If
 * the entry holds, the requester loses the stake."
 *
 * Two invocations, one per door. Without `--resolve` this is the requester: it
 * asks for a check and nothing else, because no citation is needed and there is
 * nothing to send. With `--resolve held` or `--resolve changed` this is the
 * drawn checker: it reads the entry, fetches the citation itself under the
 * entry's norm rule and hashes what it got with the kernel's own snapshotHash,
 * exactly as `npm run reconfirm` does, and signs the schema's reconfirmations[]
 * item over that hash.
 *
 * The verdict is the checker's and this command does not make it: `held` and
 * `changed` are what the operator tells it, and the fresh hash it signs is the
 * evidence beside that word. A fixture that decided for itself by comparing
 * hashes would be answering a narrower question than Section 6 asks — a page can
 * move without the fact changing, and a fact can change without the page moving.
 *
 * Nothing derived is ever sent in, and nothing is decided here: the Worker
 * settles the stake, and the status never changes at either door.
 *
 * The core is exported over injected io — an http client, a snapshot fetcher, a
 * clock and a key — so a test drives it in process against handleRequest with no
 * network at all. `main` is thin. A private key is never printed. node:path is
 * allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { extractCore, type Core } from "../core.js";
import type { ReconfirmationRecord } from "../events.js";
import { NORM_VERSION } from "../policy.js";
import { signRecord } from "../records.js";
import { operatorFor } from "./submit.js";
import {
  errorOf,
  fetchAndHash,
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
  "usage: revalidate <key.json> <base-url> <entry-id> [--resolve held|changed]";

/** The two words a check can end in. Section 6 names both. */
export const OUTCOMES = ["held", "changed"] as const;

export type Outcome = (typeof OUTCOMES)[number];

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** What one invocation asks for: which door, and on which entry. */
export interface RevalidatePlan {
  readonly keyPath: string;
  readonly baseUrl: string;
  readonly entryId: string;
  /** null asks for a check; a word answers one. */
  readonly resolve: Outcome | null;
}

/**
 * The door one invocation asks for, or null when the arguments are not either.
 *
 * A `--resolve` carrying anything but the two words is refused rather than read
 * as one of them: a checker who wrote `--resolve true` must not have it taken as
 * "the entry held", which forfeits somebody's stake.
 */
export function revalidatePlan(args: readonly string[]): RevalidatePlan | null {
  const positional: string[] = [];
  let resolveWord: string | undefined;
  for (let index = 0; index < args.length; ) {
    const argument = args[index];
    if (argument === undefined) return null;
    if (!argument.startsWith("--")) {
      positional.push(argument);
      index += 1;
      continue;
    }
    if (argument !== "--resolve") return null;
    if (resolveWord !== undefined) return null;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    resolveWord = value;
    index += 2;
  }

  const [keyPath, baseUrl, entryId] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    entryId === undefined ||
    positional.length > 3
  ) {
    return null;
  }
  if (resolveWord !== undefined && !OUTCOMES.includes(resolveWord as Outcome)) {
    return null;
  }

  return {
    keyPath,
    baseUrl,
    entryId,
    resolve: (resolveWord as Outcome | undefined) ?? null,
  };
}

/** Everything a run needs besides its arguments. All of it injected. */
export interface RevalidateDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one run did, whichever door it went through. */
export interface RevalidateRun {
  readonly ok: boolean;
  /** The route's status, or null when the run stopped before asking. */
  readonly status: number | null;
  /** The refusal the route named, or the local failure that stopped the run. */
  readonly error: string | null;
  /** The record signed and sent, on a resolution. */
  readonly record: ReconfirmationRecord | null;
}

function stopped(error: string): RevalidateRun {
  return { ok: false, status: null, error, record: null };
}

/** The entry, as a core, or the reason it could not be read. */
async function readCore(
  deps: RevalidateDeps,
  key: ValidatorKey,
  baseUrl: string,
  entryId: string,
): Promise<{ ok: true; core: Core } | { ok: false; reason: string }> {
  // Signed with the operator key this run already holds (decision D-100): an
  // entry inside the release window is served to a signed request from an agent
  // bound to a registered operator, and a revalidator is exactly that reader.
  const read = await getJson(
    signingHttp(deps.http, key, deps.now),
    baseUrl,
    `/entries/${encodeURIComponent(entryId)}`,
  );
  if (read.status !== 200) {
    return {
      ok: false,
      reason: errorOf(read.body) ?? `entry_unreadable_${read.status}`,
    };
  }
  let core: Core;
  try {
    core = extractCore(read.body);
  } catch {
    return { ok: false, reason: "entry_malformed" };
  }
  // The kernel implements exactly one norm version, so an entry signed under
  // another is refused rather than hashed under rules it never claimed.
  if (core["norm_version"] !== NORM_VERSION) {
    return { ok: false, reason: "unsupported_norm_version" };
  }
  return { ok: true, core };
}

/**
 * Ask for a check: one signed request with an empty body.
 *
 * "No citation is needed; the request only asks for a check", so there is
 * nothing to send and the signature over the empty body is the whole ask.
 */
async function request_(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly deps: RevalidateDeps;
}): Promise<RevalidateRun> {
  const { deps } = input;
  const request = await signedPost({
    baseUrl: input.baseUrl,
    path: `/entries/${encodeURIComponent(input.entryId)}/revalidate`,
    body: {},
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

  const error = response.status === 201 ? null : errorOf(body);
  deps.io.stdout(
    `response ${response.status}${error === null ? "" : ` ${error}`}`,
  );
  return { ok: response.status === 201, status: response.status, error, record: null };
}

/**
 * Answer a check: fetch the citation, hash it under the norm rule, sign the
 * reconfirmation record over that hash, and post it with the verdict.
 */
async function resolve_(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly outcome: Outcome;
  readonly deps: RevalidateDeps;
}): Promise<RevalidateRun> {
  const { deps } = input;

  const read = await readCore(deps, input.key, input.baseUrl, input.entryId);
  if (!read.ok) return stopped(read.reason);

  const operator = await operatorFor(
    deps.http,
    input.baseUrl,
    input.key.agentId,
  );
  if (operator === null) return stopped("unregistered_agent");

  const citation = read.core["citation"];
  if (typeof citation !== "string") return stopped("unsupported_citation");

  const own = await fetchAndHash(deps.fetcher, citation);
  if (!own.ok) return stopped(own.reason);

  // Every key the schema's reconfirmations[] item names, present, null where
  // this check has nothing to put in the slot. A checker that reran a model or
  // took a measurement would fill them; this one signs the fresh hash.
  const record: ReconfirmationRecord = {
    agent: input.key.agentId,
    operator,
    snapshot_hash: own.snapshot.hash,
    reproduction: null,
    observation: null,
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
    path: `/entries/${encodeURIComponent(input.entryId)}/revalidate/resolve`,
    body: { record, signature, held: input.outcome === "held" },
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

  const error = response.status === 200 ? null : errorOf(body);
  deps.io.stdout(`check ${input.outcome} hash ${own.snapshot.hash}`);
  deps.io.stdout(
    `response ${response.status}${error === null ? "" : ` ${error}`}`,
  );
  return {
    ok: response.status === 200,
    status: response.status,
    error,
    record,
  };
}

/** Run whichever door the plan named. */
export async function runRevalidate(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly entryId: string;
  readonly resolve?: Outcome | null;
  readonly deps: RevalidateDeps;
}): Promise<RevalidateRun> {
  const outcome = input.resolve ?? null;
  return outcome === null
    ? request_({
        key: input.key,
        baseUrl: input.baseUrl,
        entryId: input.entryId,
        deps: input.deps,
      })
    : resolve_({
        key: input.key,
        baseUrl: input.baseUrl,
        entryId: input.entryId,
        outcome,
        deps: input.deps,
      });
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = revalidatePlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(BAD_ARGUMENTS);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  let code: number = FAILED;
  try {
    const run = await runRevalidate({
      key: await readKeyFile(plan.keyPath),
      baseUrl: plan.baseUrl,
      entryId: plan.entryId,
      resolve: plan.resolve,
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        io,
      },
    });
    if (!run.ok && run.status === null) {
      io.stderr(`${plan.entryId}: ${run.error ?? "unknown error"}`);
    }
    code = run.ok ? OK : FAILED;
  } catch (error) {
    io.stderr(`revalidate: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

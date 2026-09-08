/**
 * checkpoint: the paper's first falsifiable milestone, end to end.
 *
 * Whitepaper, Conclusion: "The first falsifiable milestone is small and public:
 * three verified operators, none of them the maintainer's, promoting a seeded
 * entry to verified under the rules above." This command walks exactly that
 * against a running Worker and then checks the result the way a stranger would:
 * three fixture operators join and are named to the trusted pool, the maintainer
 * submits one seeded entry with a bare key, the three validate it in turn, the
 * entry comes back verified, the two files are exported, and the offline
 * verifier answers ok on them.
 *
 * Nothing is asserted that the Worker did not say. Every step reads its own
 * result back, every refusal that means "already done" is treated as done so the
 * command can be rerun against a demo that has already joined, and a step that
 * does not hold ends the run with the reason on stderr.
 *
 * The whole run is driven over injected io — an http client, a snapshot fetcher,
 * a clock and the keys — so the M14 checkpoint test drives this same code in
 * process against handleRequest. node:fs and node:path are allowed in this CLI
 * file only.
 */

import { resolve } from "node:path";

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { signAttestation } from "../registry.js";
import { signCore } from "../sign.js";
import { buildSubmittedCore } from "../submit.js";
import { verifyOffline, type LogBundle, type VerifyReport } from "../verify.js";
import { buildExport, writeExport, type ExportResult } from "./export.js";
import {
  errorOf,
  fetchAndHash,
  getJson,
  readKeyFile,
  reasonOf,
  runValidator,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE =
  "usage: checkpoint <base-url> <maintainer-key.json> <fixture-a.json> <fixture-b.json> <fixture-c.json> <out-dir>";

/** The three fixture operators, in the order they join. */
export const CHECKPOINT_DOMAINS: readonly string[] = Object.freeze([
  "fixture-a.nomankind.ai",
  "fixture-b.nomankind.ai",
  "fixture-c.nomankind.ai",
]);

/** The onboarding reference the mock payment provider calls verified. */
export const CHECKPOINT_PAYOUT_REFERENCE = "mock-verified-checkpoint";

/** The page the seeded entry cites. */
export const CHECKPOINT_CITATION = "https://example.com/";

/** The thing the seeded entry is about. */
export const CHECKPOINT_SUBJECT = "example/demo-model";

/** Every claim string says what it is, so the seed is never mistaken for news. */
const SEED = "demo checkpoint seed";

/** One step of the walk, as it is printed. */
export interface CheckpointStep {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface CheckpointResult {
  readonly ok: boolean;
  readonly entryId: string | null;
  readonly steps: readonly CheckpointStep[];
  readonly entry: unknown;
  readonly bundle: LogBundle | null;
  readonly report: VerifyReport | null;
}

/** What the walk needs besides the keys. All of it injected. */
export interface CheckpointDeps {
  readonly http: HttpClient;
  readonly fetcher: SnapshotFetcher;
  readonly now: Date;
  readonly io: ValidatorIo;
  /** Where the two exported files go, or null to build them without writing. */
  readonly outDir?: string | null;
}

/** The four keys the walk acts with. */
export interface CheckpointKeys {
  readonly maintainer: ValidatorKey;
  readonly fixtures: readonly ValidatorKey[];
}

/** A validator's own printing, silenced: the walk prints one line per step. */
const SILENT: ValidatorIo = { stdout: () => {}, stderr: () => {} };

/** One POST, with its status and whatever JSON came back. */
async function post(
  deps: CheckpointDeps,
  baseUrl: string,
  path: string,
  body: unknown,
  key: ValidatorKey,
): Promise<{ status: number; body: unknown }> {
  const request = await signedPost({
    baseUrl,
    path,
    body,
    key,
    now: deps.now,
  });
  const response = await deps.http.fetch(request);
  let parsed: unknown = null;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed };
}

/**
 * Walk the checkpoint.
 *
 * Every step is recorded in order and the first failure ends the run, so the
 * printed trail always ends at the thing that did not hold.
 */
export async function runCheckpoint(input: {
  readonly baseUrl: string;
  readonly keys: CheckpointKeys;
  readonly deps: CheckpointDeps;
}): Promise<CheckpointResult> {
  const { baseUrl, keys, deps } = input;
  const steps: CheckpointStep[] = [];

  const step = (name: string, ok: boolean, detail: string): boolean => {
    steps.push({ name, ok, detail });
    deps.io.stdout(`${ok ? "ok  " : "FAIL"} ${name}${detail === "" ? "" : ` ${detail}`}`);
    return ok;
  };

  const stop = (): CheckpointResult => ({
    ok: false,
    entryId: null,
    steps,
    entry: null,
    bundle: null,
    report: null,
  });

  if (keys.fixtures.length !== CHECKPOINT_DOMAINS.length) {
    step("keys", false, `expected ${CHECKPOINT_DOMAINS.length} fixture keys`);
    return stop();
  }

  // The DNS record each fixture operator needs, printed before anything is
  // asked of the door, so a missing record reads as a missing record.
  for (let index = 0; index < CHECKPOINT_DOMAINS.length; index += 1) {
    const domain = CHECKPOINT_DOMAINS[index]!;
    deps.io.stdout(
      `txt _nomankind.${domain} TXT ${keys.fixtures[index]!.agentId}`,
    );
  }

  const at = deps.now.toISOString();

  // Step one: the three fixture operators join, each with its own attestation.
  for (let index = 0; index < CHECKPOINT_DOMAINS.length; index += 1) {
    const operator = CHECKPOINT_DOMAINS[index]!;
    const key = keys.fixtures[index]!;
    const attestation = await signAttestation(key.privateKey, {
      operator,
      agent: key.agentId,
      signed_at: at,
    });
    const answer = await post(
      deps,
      baseUrl,
      "/operators",
      {
        operator,
        attestation,
        payout: { reference: CHECKPOINT_PAYOUT_REFERENCE },
      },
      key,
    );
    const error = errorOf(answer.body);
    const already =
      answer.status === 409 &&
      (error === "operator_exists" || error === "agent_bound");
    if (
      !step(
        `register ${operator}`,
        answer.status === 201 || already,
        already ? `already ${error}` : `${answer.status}${error === null ? "" : ` ${error}`}`,
      )
    ) {
      return stop();
    }
  }

  // Step two: the maintainer names each of them to the trusted pool.
  for (const operator of CHECKPOINT_DOMAINS) {
    const answer = await post(
      deps,
      baseUrl,
      "/genesis",
      { operator },
      keys.maintainer,
    );
    const error = errorOf(answer.body);
    const already = answer.status === 409 && error === "already_trusted";
    if (
      !step(
        `genesis ${operator}`,
        answer.status === 200 || already,
        already ? "already trusted" : `${answer.status}${error === null ? "" : ` ${error}`}`,
      )
    ) {
      return stop();
    }
  }

  // Step three: the seeded entry, submitted with a bare maintainer key, so it
  // names no operator and all three fixtures are outside it.
  const captured = await fetchAndHash(deps.fetcher, CHECKPOINT_CITATION);
  if (!captured.ok) {
    step("capture", false, captured.reason);
    return stop();
  }
  const effectiveAt = at.slice(0, 10);
  const core = await buildSubmittedCore(
    {
      subject: CHECKPOINT_SUBJECT,
      category: "limit",
      claim: `${SEED}: ${CHECKPOINT_SUBJECT} request limit is documented at its cited page`,
      before: `${SEED}: no documented request limit`,
      after: `${SEED}: the cited page is the documented request limit`,
      effective_at: effectiveAt,
      evidence_tier: "stated",
      citation: CHECKPOINT_CITATION,
      snapshot_hash: captured.snapshot.hash,
      author: keys.maintainer.agentId,
    },
    { now: at },
  );
  const entryId = core["id"] as string;
  const signature = await signCore(core, keys.maintainer.privateKey);
  const submitted = await post(
    deps,
    baseUrl,
    "/entries",
    { entry: { ...core, signature } },
    keys.maintainer,
  );
  const submitError = errorOf(submitted.body);
  const alreadySubmitted =
    submitted.status === 409 && submitError === "duplicate_entry";
  if (
    !step(
      `submit ${entryId}`,
      submitted.status === 201 || alreadySubmitted,
      alreadySubmitted
        ? "already submitted"
        : `${submitted.status}${submitError === null ? "" : ` ${submitError}`}`,
    )
  ) {
    return stop();
  }

  // Step four: the three validate, in order. The third finds the entry already
  // decided under the small-pool rule, which is the rule working.
  for (let index = 0; index < keys.fixtures.length; index += 1) {
    const key = keys.fixtures[index]!;
    const run = await runValidator({
      baseUrl,
      entryId,
      deps: { http: deps.http, fetcher: deps.fetcher, now: deps.now, key },
      io: SILENT,
    });
    const detail =
      run.status === null
        ? (run.error ?? "stopped")
        : `${run.status}${run.error === null ? ` ${run.decision ?? ""}` : ` ${run.error}`}`;
    if (!step(`validate ${CHECKPOINT_DOMAINS[index]}`, run.ok, detail.trim())) {
      return stop();
    }
  }

  // Step five: the entry, read back, has to be verified.
  const read = await getJson(
    deps.http,
    baseUrl,
    `/entries/${encodeURIComponent(entryId)}`,
  );
  const status =
    typeof read.body === "object" && read.body !== null
      ? (read.body as Record<string, unknown>)["status"]
      : null;
  if (!step("verified", read.status === 200 && status === "verified", String(status))) {
    return stop();
  }

  // Step six: the two files. What is written is JSON of exactly these two
  // objects, so verifying them is verifying the files.
  let exported: ExportResult;
  try {
    exported = await buildExport({
      baseUrl,
      entryId,
      http: deps.http,
      now: deps.now,
    });
  } catch (error) {
    step("export", false, reasonOf(error));
    return stop();
  }
  if (deps.outDir !== null && deps.outDir !== undefined) {
    const written = await writeExport(deps.outDir, exported);
    step("export", true, `${written.entryPath} ${written.bundlePath}`);
  } else {
    step("export", true, "built");
  }

  // Step seven: the offline verifier, on those two files and nothing else.
  const report = await verifyOffline(exported.entry, exported.bundle);
  const ok = step(
    "verify",
    report.ok,
    report.ok ? "ok" : `${report.diffs.length} diff(s)`,
  );
  if (!ok) {
    for (const diff of report.diffs) {
      deps.io.stderr(`${diff.check} ${diff.field} ${diff.reason}`);
    }
  }

  deps.io.stdout(`entry ${entryId} verifier ${report.ok ? "ok" : "failed"}`);

  return {
    ok,
    entryId,
    steps,
    entry: exported.entry,
    bundle: exported.bundle,
    report,
  };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const [baseUrl, maintainerPath, aPath, bPath, cPath, outDir] = args;
  if (
    baseUrl === undefined ||
    maintainerPath === undefined ||
    aPath === undefined ||
    bPath === undefined ||
    cPath === undefined ||
    outDir === undefined
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
    const result = await runCheckpoint({
      baseUrl,
      keys: {
        maintainer: await readKeyFile(maintainerPath),
        fixtures: [
          await readKeyFile(aPath),
          await readKeyFile(bPath),
          await readKeyFile(cPath),
        ],
      },
      deps: {
        http: new WebHttpClient(),
        fetcher: new WebFetcher(),
        now: new Date(),
        io,
        outDir,
      },
    });
    code = result.ok ? 0 : 1;
  } catch (error) {
    io.stderr(`checkpoint: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */

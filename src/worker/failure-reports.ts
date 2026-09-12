/**
 * The failure-report route: the door a reader who was let down by a verified
 * entry comes in through.
 *
 * Whitepaper Section 8, "Failure reports": "A reader that acts on a verified
 * entry and fails — a price that is wrong, a limit that is not there — files a
 * signed failure report against the entry, with its transcript frozen and hashed
 * like any artifact. A single report is a signal. A published threshold of
 * reports from distinct operators auto-opens a revalidation at nomankind's
 * expense. Reports never change the core or the status by themselves."
 *
 * Section 12, "Failure reports can be flooded": "Bare keys can file them, so a
 * campaign can manufacture volume against a true entry. The threshold that
 * auto-opens revalidation counts distinct verified operators only, and
 * revalidation confirms rather than overturns, so the cost of a flood is a
 * wasted check and never a wrong record."
 *
 * Both paragraphs are this file. Any key may file, bare keys included, because
 * readers are the largest verification pool the log has; the flood is answered
 * at the threshold and not at the door. The artifact is frozen and archived at
 * its own hash exactly as a submission's receipt is, so the report's evidence is
 * checkable years later by someone who was not here.
 *
 * Order matters and is deliberate: the id, the shape, the envelope signature,
 * the entry, the artifact (src/artifact.ts), then the report rules
 * (src/dispute.ts). Only then is anything archived, and only then is anything
 * written.
 *
 * Nothing derived is set here, and the status is never touched: the
 * `failure_reports[]` array and the sidecar's view of any check the threshold
 * opened are both src/derive.ts's, recomputed from a log that already holds
 * these events.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and the
 * threshold is FAILURE_REPORT_THRESHOLD inside src/dispute.ts. The id pattern is
 * read out of the entry schema rather than copied into TypeScript.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import {
  checkReceiptArtifact,
  checkTranscriptArtifact,
  failureReportArtifactHash,
  failureReportArtifactKind,
} from "../artifact.js";
import { extractCore } from "../core.js";
import { registeredOperatorsAt, type EntryStatus } from "../derive.js";
import {
  checkFailureReport,
  failureReportThresholdReached,
  openRevalidation,
} from "../dispute.js";
import type { Event, EventInput } from "../events.js";
import { canonicalize } from "../hash.js";
import { archiveAddress } from "../normalize.js";
import { validateEntry, type ValidationError } from "../schema.js";
import {
  getEntry,
  headSeq,
  operatorForAgent,
  recordFailureReport,
  type CaptureRecord,
} from "../storage/repository.js";
import { archiveCapture, type Sidecar } from "../storage/r2.js";
import type { Env } from "./env.js";
import {
  unavailable,
  withChainRetry,
  authenticate,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { ArchiveUnreachable } from "./submit.js";
import { entryWorld, rederive } from "./world.js";

/**
 * What this route is given besides its bindings: the instant the request is
 * being served at. Injected, so a test drives the real router on a fixed clock
 * and nothing under src/ reads one of its own.
 */
export interface FailureReportDeps {
  readonly now: Date;
}

/** The schema's own id pattern. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);

const ENTRIES_PREFIX = "/entries/";

/** The suffix that makes an entry's URL the door for a report against it. */
const REPORTS_SUFFIX = "/failure-reports";

/** The media type an artifact is archived under: it is JSON, canonically. */
const ARTIFACT_MEDIA_TYPE = "application/json";

const encoder = new TextEncoder();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/** A report's body: what the reader saw, the frozen artifact, and evidence. */
interface ReportBody {
  readonly observed: string;
  readonly artifact: Record<string, unknown>;
  readonly citation: string | null;
}

/**
 * The wire shape of a report, checked before anything is read out of it.
 *
 * `citation` is optional because the schema says so: "its presence makes the
 * report eligible for upgrade to a dispute", and a reader who has evidence but
 * no citation still has a report worth filing.
 */
function parseReportBody(body: unknown): ReportBody | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (key !== "observed" && key !== "artifact" && key !== "citation") {
      return null;
    }
  }
  const observed = body["observed"];
  if (typeof observed !== "string") return null;

  const artifact = body["artifact"];
  if (!isRecord(artifact)) return null;

  let citation: string | null = null;
  if (body["citation"] !== undefined && body["citation"] !== null) {
    if (typeof body["citation"] !== "string") return null;
    citation = body["citation"];
  }

  return { observed, artifact, citation };
}

// ---------------------------------------------------------------------------
// The frozen artifact
// ---------------------------------------------------------------------------

/** One artifact, checked, hashed and ready for the archive. */
interface FrozenArtifact {
  readonly hash: string;
  readonly archiveHash: string;
  readonly kind: "transcript" | "receipt";
  readonly bytes: Uint8Array;
}

/**
 * Check and hash the artifact a report carries, or answer the refusal.
 *
 * Section 8: the failing interaction arrives "with its transcript frozen and
 * hashed like any artifact", so the artifact goes through exactly the same
 * checks a submission's does — its kind is read off its key set, and the check
 * for that kind is the one src/artifact.ts already holds. The hash is over the
 * RFC 8785 canonical form, which is what makes it the same value for anyone who
 * recomputes it.
 */
async function freeze(
  artifact: Record<string, unknown>,
): Promise<{ ok: true; frozen: FrozenArtifact } | { ok: false; reason: string }> {
  const kind = failureReportArtifactKind(artifact);
  if (kind === null) return { ok: false, reason: "unknown_artifact" };

  const check =
    kind === "transcript"
      ? checkTranscriptArtifact(artifact)
      : checkReceiptArtifact(artifact);
  if (!check.ok) return { ok: false, reason: check.reason };

  const hashed = await failureReportArtifactHash(artifact);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };

  const bytes = encoder.encode(canonicalize(artifact));
  return {
    ok: true,
    frozen: {
      hash: hashed.hash,
      archiveHash: await archiveAddress(bytes),
      kind,
      bytes,
    },
  };
}

/**
 * The sidecar of something that was never fetched.
 *
 * The same deviation the submit route documents: the norm rule writes a sidecar
 * for a fetched page, and a report's artifact is evidence the reader computed
 * rather than something we retrieved. A record saying "nobody fetched this" is
 * truer than no record.
 */
function unfetchedSidecar(at: string, fetcher: string): Sidecar {
  return {
    final_url: null,
    status: null,
    headers: {},
    fetched_at: at,
    fetcher,
  };
}

// ---------------------------------------------------------------------------
// POST /entries/{id}/failure-reports
// ---------------------------------------------------------------------------

/** The derived entry did not validate against the schema. */
class SchemaInvalid extends Error {
  readonly errors: readonly ValidationError[];

  constructor(errors: readonly ValidationError[]) {
    super("the derived entry does not validate");
    this.name = "SchemaInvalid";
    this.errors = errors;
  }
}

async function report(
  request: Request,
  env: Env,
  deps: FailureReportDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const body = parseReportBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");

  const frozen = await freeze(body.artifact);
  if (!frozen.ok) return refuse(422, frozen.reason);

  // Section 5: anyone may hold a key, and Section 8 wants readers filing, so a
  // bare key is not refused — it simply names no operator, which is exactly what
  // the threshold below counts on.
  const operator = await operatorForAgent(env.DB, auth.agent);

  const world = await entryWorld(env.DB, id);
  const priorReports = world.entryEvents.filter(
    (event) => event.type === "failure_report",
  ) as Event<"failure_report">[];

  const verdict = checkFailureReport(
    { status: (stored.entry as Record<string, unknown>)["status"] as EntryStatus },
    {
      priorReporters: priorReports.map((event) => event.payload.reporter),
      reporter: auth.agent,
      observed: body.observed,
      artifactHash: frozen.frozen.hash,
    },
  );
  if (!verdict.ok) {
    // One report per agent per entry: a second is the same reader saying the
    // same thing again, which is a conflict rather than a malformed request.
    const status = verdict.reason === "duplicate_reporter" ? 409 : 422;
    return refuse(status, verdict.reason);
  }

  // The registry as of the head, which is what the threshold counts against:
  // Section 12 counts "distinct VERIFIED OPERATORS only", judged at the position
  // the question is asked at and never against a registry that moved later.
  const head = (await headSeq(env.DB)) ?? 0;
  const registered = registeredOperatorsAt(world.registry, head).operators;
  const alreadyOpen = openRevalidation(world.entryEvents) !== null;

  // The provenance of the archived artifact names the 1F916 identity that put
  // it there, which is ours (D-016), exactly as a capture's sidecar does.
  const fetcher = env.MAINTAINER_AGENT_ID;
  if (fetcher === "") return refuse(503, "fetcher_not_configured");

  const at = deps.now.toISOString();

  // Every check has passed. The artifact goes to the archive first: it is
  // content addressed and immutable, so a batch that then fails leaves an
  // artifact nothing points at rather than a row pointing at nothing.
  try {
    await archiveCapture(env.CAPTURES, {
      archiveHash: frozen.frozen.archiveHash,
      bytes: frozen.frozen.bytes,
      mediaType: ARTIFACT_MEDIA_TYPE,
      sidecar: unfetchedSidecar(at, fetcher),
    });
  } catch (error) {
    throw new ArchiveUnreachable(error);
  }

  const normVersion = extractCore(stored.entry)["norm_version"] as string;

  let derivedEntry: Record<string, unknown> | null = null;
  let openedRevalidation = false;
  try {
    // Retried from the derivation: an event's position and hash are the head's,
    // so a write that lost the next position in the log is built again onto the
    // head that moved rather than sent again. The derived row and the opened
    // request are cleared with it, because a row derived at last attempt's
    // position would be stored at a seq the log never gave it.
    await withChainRetry(async () => {
      derivedEntry = null;
      openedRevalidation = false;
      const written = await recordFailureReport(env.DB, {
        event: {
          at,
          type: "failure_report",
          entry_id: id,
          payload: {
            reporter: auth.agent,
            operator,
            observed: body.observed,
            artifact_hash: frozen.frozen.hash,
            citation: body.citation,
          },
        },
        // Each report's artifact is its own row under its own role, so no report
        // overwrites the entry's own captures or another reader's evidence.
        capture: (event): CaptureRecord => ({
          entryId: id,
          role: `report:${event.seq}`,
          contentHash: frozen.frozen.hash,
          archiveHash: frozen.frozen.archiveHash,
          normVersion,
          kind: frozen.frozen.kind,
          mediaType: ARTIFACT_MEDIA_TYPE,
          size: frozen.frozen.bytes.byteLength,
          fetchedAt: at,
        }),
        // Section 8: "A published threshold of reports from distinct operators
        // auto-opens a revalidation at nomankind's expense." Nobody staked, so the
        // request names no requester and no operator, and src/stake.ts writes no
        // row for it.
        opens: (event): EventInput<"revalidation_requested"> | null => {
          if (alreadyOpen) return null;
          if (!failureReportThresholdReached([...priorReports, event], registered)) {
            return null;
          }
          return {
            at,
            type: "revalidation_requested",
            entry_id: id,
            payload: { requester: null, operator: null, source: "failure_reports" },
          };
        },
        stored: (event, opened) => {
          const extra = opened === null ? [event] : [event, opened];
          const derived = rederive(world, id, deps.now, extra);
          const result = validateEntry(derived.entry);
          if (!result.ok) throw new SchemaInvalid(result.errors);
          derivedEntry = derived.entry as Record<string, unknown>;
          return {
            entry: derived.entry,
            sidecar: derived.sidecar,
            derivedThroughSeq: extra[extra.length - 1]!.seq,
          };
        },
      });
      openedRevalidation = written.opened !== null;
    });
  } catch (error) {
    if (error instanceof SchemaInvalid) {
      return json({ error: "schema_invalid", errors: error.errors }, 422);
    }
    throw error;
  }

  return json(
    { entry: derivedEntry, opened_revalidation: openedRevalidation },
    201,
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/**
 * The entry id in `/entries/{id}/failure-reports`, or null when the path is not
 * that shape. An id carrying a further slash is not one entry's report door and
 * falls through rather than being trimmed into one.
 */
function reportsPathId(path: string): string | null {
  if (!path.startsWith(ENTRIES_PREFIX)) return null;
  if (!path.endsWith(REPORTS_SUFFIX)) return null;
  const raw = path.slice(
    ENTRIES_PREFIX.length,
    path.length - REPORTS_SUFFIX.length,
  );
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Route one request to the report door, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched.
 *
 * The storage and archive boundaries are the submit route's, for the same
 * reason: a database or a bucket that does not answer is our outage and says
 * which of the two it was, rather than reaching the platform as a raw 500.
 */
export async function handleFailureReports(
  request: Request,
  env: Env,
  deps: FailureReportDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  const id = reportsPathId(path);
  if (id === null) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  try {
    return await report(
      request,
      { ...env, DB: guardDatabase(env.DB) },
      deps,
      path,
      id,
    );
  } catch (error) {
    // The message only: no binding contents, no request data.
    const answer = unavailable(error, "failure-reports");
    if (answer !== null) return answer;
    if (error instanceof ArchiveUnreachable) {
      console.error(`failure-reports: archive unreachable: ${error.message}`);
      return refuse(503, "archive_unreachable");
    }
    throw error;
  }
}

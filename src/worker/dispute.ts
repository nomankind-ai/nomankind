/**
 * The dispute route: the door a challenge against a verified entry comes in
 * through.
 *
 * Whitepaper Section 6, "Dispute": "Verified entries stay open to challenge. A
 * challenge is itself an entry, in the correction category, and it requires a
 * citation. It passes through the same validation process with one extra
 * exclusion: no operator that signed the original, submitter or validator, may
 * validate the challenge against it. Filing takes a stake, so burner keys cannot
 * dispute for free. A verified operator stakes standing, a bare key stakes a
 * refundable filing fee, and the amounts are published policy."
 *
 * Two entries are in play and this door is scoped to the CHALLENGED one: the
 * path names the target, the body carries the correction, and the events that
 * come out land on both. "The same validation process" is meant literally — the
 * correction goes through `prepareSubmission`, which is the POST /entries
 * pipeline itself and not a copy of it, so a correction that would have been
 * refused as a submission is refused here for the same reason with the same
 * status.
 *
 * Order matters and is deliberate: the id, the shape, the envelope signature,
 * the target, the identity, the whole submission pipeline on the correction,
 * the filing rules (src/dispute.ts), and last the two links a filing may claim
 * to be an upgrade of. Nothing is written until every one of them has passed,
 * and the archive is written only after that: a refused filing leaves the log
 * exactly where it was.
 *
 * Nothing derived is set here. `overturned_by`, the `disputes[]` row and the
 * status are all src/derive.ts's, recomputed from a log that already holds these
 * events; the stake rows are src/stake.ts's, read out of the sealed event.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and the
 * stake amounts reach the ledger through src/stake.ts from src/policy.ts. The id
 * pattern is read out of the entry schema rather than copied into TypeScript.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import type { EntryStatus } from "../derive.js";
import {
  checkDisputeFiling,
  openDispute,
  openRevalidation,
} from "../dispute.js";
import type { Event, EventInput } from "../events.js";
import { validateEntry, type ValidationError } from "../schema.js";
import { disputeStake, revalidationOutcomeStakes } from "../stake.js";
import {
  getEntry,
  openRevalidationAssignment,
  recordDisputeFiling,
  type StoredEntryInput,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  authenticate,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import {
  ArchiveUnreachable,
  archivePrepared,
  prepareSubmission,
  type SubmitDeps,
} from "./submit.js";
import { entryWorld, rederive } from "./world.js";

/**
 * What this route is given besides its bindings: the instant the request is
 * being served at, and the way out to the network the capture needs. Both
 * injected, exactly as the submit route takes them, because this door runs the
 * submit route's own pipeline.
 */
export type DisputeDeps = SubmitDeps;

/** The schema's own id pattern. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);

/** The suffix that makes an entry's URL the door for a challenge to it. */
const DISPUTE_SUFFIX = "/dispute";

const ENTRIES_PREFIX = "/entries/";

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/**
 * A filing's body: the signed correction entry exactly as POST /entries takes
 * one, and the two positions a filing may claim to be an upgrade of.
 */
interface DisputeBody {
  readonly entry: Record<string, unknown>;
  readonly receipt: Record<string, unknown> | undefined;
  readonly fromReportSeq: number | null;
  readonly fromRevalidationSeq: number | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Exactly the four keys a filing may carry, and no others. */
const BODY_KEYS: readonly string[] = Object.freeze([
  "entry",
  "receipt",
  "from_report_seq",
  "from_revalidation_seq",
] as const);

/** A log position: a non-negative safe integer, as every seq in the log is. */
function isPosition(value: unknown): value is number {
  return (
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0
  );
}

/**
 * The wire shape of a filing, checked before anything is read out of it.
 *
 * Only the envelope is checked here: whether the entry inside it is a
 * submission at all is `prepareSubmission`'s question, asked with the submit
 * route's own parser, so the two doors can never disagree about what an entry
 * looks like on the wire.
 */
function parseDisputeBody(body: unknown): DisputeBody | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (!BODY_KEYS.includes(key)) return null;
  }

  const entry = body["entry"];
  if (!isRecord(entry)) return null;

  let receipt: Record<string, unknown> | undefined;
  if ("receipt" in body) {
    const value = body["receipt"];
    if (!isRecord(value)) return null;
    receipt = value;
  }

  let fromReportSeq: number | null = null;
  if (body["from_report_seq"] !== undefined) {
    if (!isPosition(body["from_report_seq"])) return null;
    fromReportSeq = body["from_report_seq"];
  }
  let fromRevalidationSeq: number | null = null;
  if (body["from_revalidation_seq"] !== undefined) {
    if (!isPosition(body["from_revalidation_seq"])) return null;
    fromRevalidationSeq = body["from_revalidation_seq"];
  }

  return { entry, receipt, fromReportSeq, fromRevalidationSeq };
}

// ---------------------------------------------------------------------------
// The two links a filing may claim
// ---------------------------------------------------------------------------

/**
 * Whether `seq` names a failure report on this target, filed by this agent,
 * carrying a citation, and not already upgraded.
 *
 * Section 8: "a report that carries a citation or a reproducible observation is
 * upgraded into a dispute." The citation is what makes it eligible, the reporter
 * is who may upgrade it — an upgrade puts a stake up, and nobody else's report
 * is anybody's to stake on — and one report upgrades once, because the schema's
 * `upgraded_to` is one id and a second dispute would leave the first invisible.
 */
function reportLinkHolds(
  events: readonly Event[],
  seq: number,
  agent: string,
): boolean {
  const report = events.find(
    (event) => event.seq === seq && event.type === "failure_report",
  ) as Event<"failure_report"> | undefined;
  if (report === undefined) return false;
  if (report.payload.reporter !== agent) return false;
  const citation = report.payload.citation;
  if (typeof citation !== "string" || citation.trim().length === 0) {
    return false;
  }
  return !events.some(
    (event) =>
      event.type === "dispute_filed" &&
      (event as Event<"dispute_filed">).payload.from_report_seq === seq,
  );
}

/**
 * The open revalidation request at `seq`, made by this agent, or null.
 *
 * Section 6, "Revalidate": "A request that turns up a citation can be upgraded
 * into a dispute." Only the requester may: the upgrade returns their stake and
 * takes the dispute's own out of them instead, so it is their doubt to escalate
 * and nobody else's. Only while it is open, because a request already resolved
 * has had its answer and its stake settled.
 */
function revalidationLink(
  events: readonly Event[],
  seq: number,
  agent: string,
): Event<"revalidation_requested"> | null {
  const open = openRevalidation(events);
  if (open === null || open.seq !== seq) return null;
  return open.payload.requester === agent ? open : null;
}

// ---------------------------------------------------------------------------
// POST /entries/{id}/dispute
// ---------------------------------------------------------------------------

/**
 * The derived entry did not validate against the schema.
 *
 * Thrown from inside `recordDisputeFiling`'s derivation callbacks, which run
 * before the batch is executed, so a filing the schema refuses is refused with
 * nothing written — not the correction, not the challenge, not the stake.
 */
class SchemaInvalid extends Error {
  readonly errors: readonly ValidationError[];

  constructor(errors: readonly ValidationError[]) {
    super("the derived entry does not validate");
    this.name = "SchemaInvalid";
    this.errors = errors;
  }
}

async function file(
  request: Request,
  env: Env,
  deps: DisputeDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  // The shape, before the envelope: a body that is not a filing is a 400
  // whoever signed it. The clone is what lets the body be read twice — once
  // here and once by the verifier, which signs over the canonical form of it.
  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const body = parseDisputeBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");

  // The key that signed the request is the challenger, and the challenger is
  // the correction's author: filing under someone else's correction would put
  // their stake and standing at risk on a dispute they never chose to file.
  const author = body.entry["author"];
  if (typeof author === "string" && author !== auth.agent) {
    return refuse(403, "author_mismatch");
  }

  // "It passes through the same validation process." The same pipeline, then,
  // and not a second one that could drift from it.
  const attempt = await prepareSubmission(env, deps, auth.agent, {
    ...(body.receipt === undefined
      ? { entry: body.entry }
      : { entry: body.entry, receipt: body.receipt }),
  });
  if (!attempt.ok) return attempt.response;
  const { prepared } = attempt;

  const targetWorld = await entryWorld(env.DB, id);
  const targetEvents = targetWorld.entryEvents;
  const target = stored.entry as Record<string, unknown>;

  const filing = checkDisputeFiling(
    prepared.core,
    {
      id,
      subject: target["subject"] as string,
      status: target["status"] as EntryStatus,
    },
    {
      challenger: auth.agent,
      challengerOperator:
        (prepared.core["author_operator"] as string | null) ?? null,
      openDisputes: openDispute(targetEvents) === null ? 0 : 1,
    },
  );
  if (!filing.ok) {
    // Section 6 gives an upheld challenge the power to overturn the entry, so a
    // second open one is a conflict about the same fact rather than a malformed
    // request: 409, as every other "already in flight" refusal is.
    const status = filing.reason === "dispute_open" ? 409 : 422;
    return refuse(status, filing.reason);
  }

  if (
    body.fromReportSeq !== null &&
    !reportLinkHolds(targetEvents, body.fromReportSeq, auth.agent)
  ) {
    return refuse(422, "bad_report_link");
  }

  const upgraded =
    body.fromRevalidationSeq === null
      ? null
      : revalidationLink(targetEvents, body.fromRevalidationSeq, auth.agent);
  if (body.fromRevalidationSeq !== null && upgraded === null) {
    return refuse(422, "bad_revalidation_link");
  }

  // The draw the upgrade closes, if the request had one standing. Read before
  // the write, because the batch's callbacks are synchronous.
  const openCheck =
    upgraded === null ? null : await openRevalidationAssignment(env.DB, id);

  // Every check has passed. The correction's evidence goes to the archive
  // first, exactly as POST /entries does it, then one atomic batch.
  await archivePrepared(env, prepared);

  const at = prepared.at;
  let correctionEntry: Record<string, unknown> | null = null;
  let targetEntry: Record<string, unknown> | null = null;
  try {
    await recordDisputeFiling(env.DB, {
      correction: {
        event: {
          at,
          type: "entry_submitted",
          entry_id: prepared.id,
          payload: prepared.event.payload as Event<"entry_submitted">["payload"],
        },
        // The correction derives over its own events alone: `dispute_filed` is
        // scoped to the target, so it changes nothing about the challenge, and
        // the pipeline already derived and schema-checked exactly this entry.
        stored: (submitted): StoredEntryInput => {
          correctionEntry = prepared.derived.entry as Record<string, unknown>;
          return {
            entry: prepared.derived.entry,
            sidecar: prepared.derived.sidecar,
            derivedThroughSeq: submitted.seq,
          };
        },
        captures: prepared.captureRows,
      },
      // The challenge, on the target, naming the correction the log has just
      // seen. `citation` and `snapshot_hash` are copied off the correction's own
      // core so a reader folding the target's events alone can fill the schema's
      // disputes[] item without fetching another entry.
      filed: (submitted): EventInput<"dispute_filed"> => ({
        at,
        type: "dispute_filed",
        entry_id: id,
        payload: {
          correction_entry_id: submitted.payload.core["id"] as string,
          challenger: auth.agent,
          operator:
            (prepared.core["author_operator"] as string | null) ?? null,
          citation: prepared.core["citation"] as string,
          snapshot_hash: prepared.core["snapshot_hash"] as string,
          from_report_seq: body.fromReportSeq,
          from_revalidation_seq: body.fromRevalidationSeq,
        },
      }),
      // Section 6: "A request that turns up a citation can be upgraded into a
      // dispute." The request closes as `upgraded` in the same batch, so its
      // stake comes back and the dispute's own takes over from there.
      also: (submitted): readonly EventInput[] =>
        upgraded === null
          ? []
          : [
              {
                at,
                type: "revalidation_resolved",
                entry_id: id,
                payload: {
                  request_seq: upgraded.seq,
                  outcome: "upgraded",
                  checker: null,
                  operator: null,
                  snapshot_hash: null,
                  correction_entry_id: submitted.payload.core["id"] as string,
                },
              } satisfies EventInput<"revalidation_resolved">,
            ],
      target: (_submitted, filed, also): StoredEntryInput => {
        const extra = [filed as Event, ...also];
        const derived = rederive(targetWorld, id, deps.now, extra);
        const result = validateEntry(derived.entry);
        if (!result.ok) throw new SchemaInvalid(result.errors);
        targetEntry = derived.entry as Record<string, unknown>;
        return {
          entry: derived.entry,
          sidecar: derived.sidecar,
          derivedThroughSeq: extra[extra.length - 1]!.seq,
        };
      },
      stake: (filed) => disputeStake(filed),
      ledger: (_filed, also) => {
        if (upgraded === null || also.length === 0) return [];
        return revalidationOutcomeStakes(
          upgraded,
          also[0] as Event<"revalidation_resolved">,
        );
      },
      answeredAssignmentSeq: openCheck === null ? null : openCheck.seq,
    });
  } catch (error) {
    if (error instanceof SchemaInvalid) {
      return json({ error: "schema_invalid", errors: error.errors }, 422);
    }
    throw error;
  }

  return json({ correction: correctionEntry, target: targetEntry }, 201);
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/**
 * The entry id in `/entries/{id}/dispute`, or null when the path is not that
 * shape. An id carrying a further slash is not one entry's dispute door and
 * falls through rather than being trimmed into one.
 */
function disputePathId(path: string): string | null {
  if (!path.startsWith(ENTRIES_PREFIX)) return null;
  if (!path.endsWith(DISPUTE_SUFFIX)) return null;
  const raw = path.slice(
    ENTRIES_PREFIX.length,
    path.length - DISPUTE_SUFFIX.length,
  );
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Route one request to the dispute door, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched.
 *
 * The storage and archive boundaries are the submit route's: D1 through the
 * wrapped handle and R2 through the pipeline's own marker, so a database or a
 * bucket that does not answer is a JSON 503 naming which of the two it was
 * rather than a raw 500. Nothing else is caught — a refusal is a value this
 * route returns, and a bug of ours escapes.
 */
export async function handleDispute(
  request: Request,
  env: Env,
  deps: DisputeDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  const id = disputePathId(path);
  if (id === null) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  try {
    return await file(
      request,
      { ...env, DB: guardDatabase(env.DB) },
      deps,
      path,
      id,
    );
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`dispute: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    if (error instanceof ArchiveUnreachable) {
      console.error(`dispute: archive unreachable: ${error.message}`);
      return refuse(503, "archive_unreachable");
    }
    throw error;
  }
}

/**
 * The revalidate routes: the door an operator asks for a check through, and the
 * door the drawn checker answers it through.
 *
 * Whitepaper Section 6, "Revalidate": "Any operator can also request
 * revalidation of an entry inside its window by staking a small amount of
 * standing. No citation is needed; the request only asks for a check. It is
 * assigned at random to a trusted operator, the entry keeps earning while the
 * check is pending, and requests are capped per operator per window. If the
 * check finds the fact changed, the requester gets the stake back plus a
 * challenger-style reward. If the entry holds, the requester loses the stake. A
 * request that turns up a citation can be upgraded into a dispute."
 *
 * Three of those sentences are here. The request door stakes standing and opens
 * the check; the draw between them is the sweep's (src/worker/sweep.ts); the
 * resolve door records what the checker found and settles the stake. The
 * upgrade is the dispute door's, because an upgrade is a filing.
 *
 * A request body is empty on purpose: "no citation is needed", so there is
 * nothing to send, and the signed request itself is the whole ask. A resolution
 * carries the same signed record a reconfirmation does — the schema's
 * reconfirmations[] item — because a check is a fresh snapshot signed by the
 * operator that took it, and inventing a second record shape for the same act
 * would give an offline reader two things to learn instead of one.
 *
 * The status never changes at the resolve door, whichever way the check went.
 * Section 12: "revalidation confirms rather than overturns". A fact that has
 * changed is corrected by a superseding entry or by a dispute, both of which
 * have their own doors and their own validators; a check that found a change
 * says so, refunds the stake and pays the reward, and stops there.
 *
 * Nothing derived is set here: every stored row is what src/derive.ts made of a
 * log that already holds these events, and every ledger row is src/stake.ts's,
 * read out of the sealed event.
 *
 * No policy number lives here: the bare integers are HTTP status codes, the cap
 * is REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW inside src/dispute.ts, the
 * stake amount is src/policy.ts's — src/stake.ts writes it into the ledger row
 * and the standing gate reads the same constant to say what a requester must be
 * able to cover — and the timestamp window is REQUEST_CLOCK_SKEW_SECONDS. The id
 * pattern is read out of the entry schema.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import { domainOf } from "../core.js";
import { operatorDomainsOf } from "../derive.js";
import {
  checkRevalidationRequest,
  checkStakeCover,
  lockedStanding,
  openRevalidation,
  requestsByOperatorInWindow,
} from "../dispute.js";
import type { ReconfirmationRecord } from "../events.js";
import {
  LIST_PAGE_LIMIT,
  REQUEST_CLOCK_SKEW_SECONDS,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "../policy.js";
import { verifyRecordSignature } from "../records.js";
import { validateEntry, type ValidationError } from "../schema.js";
import { revalidationOutcomeStakes, revalidationStake } from "../stake.js";
import {
  getEntry,
  headSeq,
  openRevalidationAssignment,
  openStakeRowsForOperator,
  operatorForAgent,
  operatorStanding,
  recordRevalidationRequest,
  recordRevalidationResolution,
} from "../storage/repository.js";
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
import { entryWorld, rederive } from "./world.js";

/**
 * What these routes are given besides their bindings: the instant the request is
 * being served at. Injected, so a test drives the real router on a fixed clock
 * and nothing under src/ reads one of its own.
 */
export interface RevalidateDeps {
  readonly now: Date;
}

/** The schema's own id pattern. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);

const ENTRIES_PREFIX = "/entries/";

/** The two suffixes: the request door, and the resolution door under it. */
const REVALIDATE_SUFFIX = "/revalidate";
const RESOLVE_SUFFIX = "/revalidate/resolve";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The derived entry did not validate against the schema.
 *
 * Thrown from inside the writers' derivation callbacks, which run before the
 * batch is executed, so a write the schema refuses leaves the log exactly as it
 * was — not even the event that would have carried it.
 */
class SchemaInvalid extends Error {
  readonly errors: readonly ValidationError[];

  constructor(errors: readonly ValidationError[]) {
    super("the derived entry does not validate");
    this.name = "SchemaInvalid";
    this.errors = errors;
  }
}

// ---------------------------------------------------------------------------
// POST /entries/{id}/revalidate
// ---------------------------------------------------------------------------

async function request_(
  request: Request,
  env: Env,
  deps: RevalidateDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  // "No citation is needed; the request only asks for a check." So the body is
  // empty, and a body carrying anything at all is a request about something
  // this door does not do.
  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  if (!isRecord(raw) || Object.keys(raw).length > 0) {
    return refuse(400, "bad_body");
  }

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  if ((await getEntry(env.DB, id)) === null) return refuse(404, "not_found");

  // The whole event set this entry is derived over, superseders included, so a
  // superseded entry is seen as superseded here rather than as still standing.
  const world = await entryWorld(env.DB, id);
  const before = rederive(world, id, deps.now);

  // Section 5: anyone may hold a key, and null is the truth about a bare one.
  // The kernel refuses a bare key its own way (`bare_key`); this only reports
  // what the registry says.
  const operator = await operatorForAgent(env.DB, auth.agent);

  const head = (await headSeq(env.DB)) ?? 0;
  const verdict = checkRevalidationRequest(
    {
      status: before.derived.status,
      stale: before.derived.stale,
      // The entry's own domain, off the stored entry, which carries the signed
      // core's `domain` verbatim; the derived fields hold no domain at all, so
      // reading them would hand every entry the default. A legacy v0.6 entry has
      // no `domain` in its core and reads as the default (decision D-071).
      domain: domainOf(before.entry),
    },
    {
      requesterOperator: operator,
      // The domains this operator is attested in, folded out of the registry
      // events. A bare key has no operator and is refused `bare_key` first.
      ...(operator === null
        ? {}
        : { operatorDomains: operatorDomainsOf(world.registry, operator, head) }),
      // "Requests are capped per operator per window", and the window opened at
      // the entry's own last_confirmed, which derivation already computes.
      requestsThisWindow:
        operator === null
          ? 0
          : requestsByOperatorInWindow(
              world.entryEvents,
              operator,
              before.derived.last_confirmed,
            ),
      openRequest: openRevalidation(world.entryEvents) !== null,
    },
  );
  if (!verdict.ok) {
    // A check already in flight is a conflict about the same question rather
    // than a malformed ask: 409, as every other "already open" refusal is.
    const status = verdict.reason === "request_open" ? 409 : 422;
    return refuse(status, verdict.reason);
  }

  // Section 6: the request is made "by staking a small amount of standing", and
  // Section 9 has standing gate "revalidation-request caps and dispute stakes".
  // The requester is an operator by here (`bare_key` refused the other case), so
  // it must be able to cover the stake: its standing less what its still-open
  // stakes already hold. The gate reads the standing the sweep stored, which is
  // the published formula folded to the last sealed head and so at most one
  // interval behind the log.
  // A bare key never reaches this: `bare_key` above refused it, and its own door
  // into Section 6 is the dispute's refundable fee.
  if (operator !== null) {
    const stored = await operatorStanding(env.DB, operator);
    const cover = checkStakeCover({
      standing: stored?.standing ?? 0,
      locked: lockedStanding(
        await openStakeRowsForOperator(env.DB, operator, LIST_PAGE_LIMIT),
      ),
      stake: REVALIDATION_REQUEST_STAKE_STANDING,
    });
    if (!cover.ok) return refuse(422, cover.reason);
  }

  const at = deps.now.toISOString();
  let derivedEntry: Record<string, unknown> | null = null;
  try {
    // Retried from the derivation: an event's position and hash are the head's,
    // so a write that lost the next position in the log is built again onto the
    // head that moved rather than sent again. The derived row is cleared with it,
    // because a row derived at last attempt's position would be stored at a seq
    // the log never gave it.
    await withChainRetry(async () => {
      derivedEntry = null;
      await recordRevalidationRequest(env.DB, {
        event: {
          at,
          type: "revalidation_requested",
          entry_id: id,
          payload: { requester: auth.agent, operator, source: "operator" },
        },
        stored: (event) => {
          const derived = rederive(world, id, deps.now, [event]);
          const result = validateEntry(derived.entry);
          if (!result.ok) throw new SchemaInvalid(result.errors);
          derivedEntry = derived.entry as Record<string, unknown>;
          return {
            entry: derived.entry,
            sidecar: derived.sidecar,
            derivedThroughSeq: event.seq,
          };
        },
        // Section 6: the request is made "by staking a small amount of standing".
        ledger: (event) => {
          const staked = revalidationStake(event);
          return staked === null ? [] : [staked];
        },
      });
    });
  } catch (error) {
    if (error instanceof SchemaInvalid) {
      return json({ error: "schema_invalid", errors: error.errors }, 422);
    }
    throw error;
  }

  return json(derivedEntry, 201);
}

// ---------------------------------------------------------------------------
// POST /entries/{id}/revalidate/resolve
// ---------------------------------------------------------------------------

/** A resolution's body: the record the checker signed, and what it found. */
interface ResolveBody {
  readonly record: ReconfirmationRecord;
  readonly signature: string;
  readonly held: boolean;
}

/**
 * Exactly the schema's reconfirmations[] item keys, in the schema's own order.
 * The item requires every one of them, so an unused slot is written as null and
 * never left out.
 */
const RECORD_KEYS: readonly string[] = Object.freeze([
  "agent",
  "operator",
  "snapshot_hash",
  "reproduction",
  "observation",
  "signed_at",
] as const);

/**
 * The wire shape of a resolution, checked before anything is read out of it.
 *
 * The record is the reconfirmation record and nothing else, with the signature
 * beside it and never inside it (decision D-034); `held` is the checker's own
 * verdict, and it is a boolean because a check has exactly two answers.
 */
function parseResolveBody(body: unknown): ResolveBody | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (key !== "record" && key !== "signature" && key !== "held") return null;
  }
  const signature = body["signature"];
  if (typeof signature !== "string") return null;
  const held = body["held"];
  if (typeof held !== "boolean") return null;

  const record = body["record"];
  if (!isRecord(record)) return null;
  for (const key of Object.keys(record)) {
    if (!RECORD_KEYS.includes(key)) return null;
  }
  for (const key of RECORD_KEYS) {
    if (record[key] === undefined) return null;
  }
  if (typeof record["agent"] !== "string") return null;
  if (typeof record["operator"] !== "string") return null;
  if (typeof record["snapshot_hash"] !== "string") return null;
  if (typeof record["signed_at"] !== "string") return null;
  if (record["reproduction"] !== null && !isRecord(record["reproduction"])) {
    return null;
  }
  if (record["observation"] !== null && !isRecord(record["observation"])) {
    return null;
  }

  return { record: record as unknown as ReconfirmationRecord, signature, held };
}

async function resolve(
  request: Request,
  env: Env,
  deps: RevalidateDeps,
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
  const body = parseResolveBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  if ((await getEntry(env.DB, id)) === null) return refuse(404, "not_found");

  const world = await entryWorld(env.DB, id);
  const open = openRevalidation(world.entryEvents);
  if (open === null) return refuse(422, "no_open_request");

  // Section 6: the request "is assigned at random to a trusted operator". Only
  // that operator's drawn agent answers it: a check anyone could answer would be
  // a check the requester could answer themselves.
  const assignment = await openRevalidationAssignment(env.DB, id);
  if (assignment === null || assignment.agent !== auth.agent) {
    return refuse(422, "not_assigned");
  }

  const { record } = body;
  // The key that signed the request and the key inside the record must be the
  // same one: a check is signed by its own checker, never relayed.
  if (auth.agent !== record.agent) return refuse(403, "agent_mismatch");

  const signedAt = Date.parse(record.signed_at);
  if (
    Number.isNaN(signedAt) ||
    Math.abs(signedAt - deps.now.getTime()) >
      REQUEST_CLOCK_SKEW_SECONDS * MILLISECONDS_PER_SECOND
  ) {
    return refuse(422, "bad_signed_at");
  }

  // D-034: the signature is over the entry id, the kind, and the record, so a
  // check signed for one entry can never be replayed onto another.
  if (
    !(await verifyRecordSignature(id, "reconfirmation", record, body.signature))
  ) {
    return refuse(422, "bad_record_signature");
  }

  const at = deps.now.toISOString();
  let derivedEntry: Record<string, unknown> | null = null;
  try {
    // Retried from the derivation: an event's position and hash are the head's,
    // so a write that lost the next position in the log is built again onto the
    // head that moved rather than sent again. The derived row is cleared with it,
    // because a row derived at last attempt's position would be stored at a seq
    // the log never gave it.
    await withChainRetry(async () => {
      derivedEntry = null;
      await recordRevalidationResolution(env.DB, {
        event: {
          at,
          type: "revalidation_resolved",
          entry_id: id,
          payload: {
            request_seq: open.seq,
            // "If the check finds the fact changed ... If the entry holds ..."
            outcome: body.held ? "held" : "changed",
            checker: record.agent,
            operator: record.operator,
            snapshot_hash: record.snapshot_hash,
            // An upgrade names a correction; a check does not make one.
            correction_entry_id: null,
          },
        },
        stored: (event) => {
          const derived = rederive(world, id, deps.now, [event]);
          const result = validateEntry(derived.entry);
          if (!result.ok) throw new SchemaInvalid(result.errors);
          derivedEntry = derived.entry as Record<string, unknown>;
          return {
            entry: derived.entry,
            sidecar: derived.sidecar,
            derivedThroughSeq: event.seq,
          };
        },
        ledger: (event) => revalidationOutcomeStakes(open, event),
        answeredAssignmentSeq: assignment.seq,
      });
    });
  } catch (error) {
    if (error instanceof SchemaInvalid) {
      return json({ error: "schema_invalid", errors: error.errors }, 422);
    }
    throw error;
  }

  return json(derivedEntry, 200);
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/** The entry id before `suffix`, or null when the path is not that shape. */
function pathId(path: string, suffix: string): string | null {
  if (!path.startsWith(ENTRIES_PREFIX)) return null;
  if (!path.endsWith(suffix)) return null;
  const raw = path.slice(ENTRIES_PREFIX.length, path.length - suffix.length);
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Route one request to the request door or the resolution door, or answer null
 * when the path is neither, which leaves the Worker's own not_found untouched.
 *
 * The resolution suffix is tried first, because `/revalidate/resolve` also ends
 * in nothing the request suffix would match — the id before it would carry a
 * slash — but reading it in the other order would be relying on that rather than
 * saying it.
 *
 * The storage boundary is the validate door's: D1 is reached through the wrapped
 * handle, so a database that does not answer is a JSON 503 rather than a raw
 * 500. Nothing else is caught.
 */
export async function handleRevalidate(
  request: Request,
  env: Env,
  deps: RevalidateDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  const resolveId = pathId(path, RESOLVE_SUFFIX);
  const requestId = resolveId === null ? pathId(path, REVALIDATE_SUFFIX) : null;
  if (resolveId === null && requestId === null) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  const guarded: Env = { ...env, DB: guardDatabase(env.DB) };
  try {
    return resolveId !== null
      ? await resolve(request, guarded, deps, path, resolveId)
      : await request_(request, guarded, deps, path, requestId as string);
  } catch (error) {
    // The message only: no binding contents, no request data.
    const answer = unavailable(error, "revalidate");
    if (answer !== null) return answer;
    throw error;
  }
}

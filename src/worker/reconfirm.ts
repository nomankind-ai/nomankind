/**
 * The reconfirm route: the door a trusted operator refreshes a stale entry
 * through.
 *
 * Whitepaper, Lifecycle of an entry, Revalidate: "Any trusted operator can
 * reconfirm a stale entry by taking a fresh snapshot and signing that the source
 * still says what the entry says ... A reconfirmation appends a fresh
 * attestation, advances the derived last-confirmed date and reopens the
 * freshness window." Section 7, Freshness and decay: past its window an entry
 * stays verified but shows as stale, "and the withheld half builds up on the
 * entry as a reconfirmation bounty, paid to whoever makes it fresh again".
 *
 * The fetch and the hash happen on the reconfirmer's side and this Worker does
 * not repeat them (decision D-044: receipts, not gates), exactly as it does not
 * repeat a validator's. What arrives is the record they signed, carrying the
 * hash they got, and what this file does is prove who signed it and put it
 * through the rules before it joins the log. The rules themselves are
 * src/reconfirm.ts's and are pure, so the refusal an operator gets here is one
 * an offline reader can rederive from the log.
 *
 * Order matters and is deliberate, and it is the validate door's order: the id,
 * the shape, the envelope signature, the entry, the identity, the record's
 * timestamp, the record signature, then the kernel check, then staleness, then
 * derivation and the schema. Nothing is written until every one of them has
 * passed: a refused reconfirmation leaves the log exactly where it was.
 *
 * Staleness is a gate here and nowhere else. src/reconfirm.ts deliberately does
 * not ask it — a stale entry is still verified, and the rule it enforces is
 * about who may reconfirm rather than when — so the door asks it, because
 * Section 6 gives the trusted pool the stale entries and gives a check inside
 * the window to a staked revalidation request, which is M20's.
 *
 * Nothing derived is set here. last_confirmed advancing, the window reopening,
 * the read-share slot seating or rotating and the tier staying where it was are
 * all src/derive.ts's, recomputed from a log that already holds this
 * attestation. The bounty is src/bounty.ts's, read out of the entry as it stood
 * before and out of the sealed event.
 *
 * No policy number lives here: the bare integers are HTTP status codes and the
 * timestamp window is REQUEST_CLOCK_SKEW_SECONDS from src/policy.ts. The id
 * pattern is read out of the entry schema rather than copied into TypeScript.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import { bountyAccrual } from "../bounty.js";
import { domainOf, type Core } from "../core.js";
import {
  agentOperatorsAt,
  isVersionStale,
  operatorDomainsOf,
  trustedOperatorsAt,
} from "../derive.js";
import type { Event, ReconfirmationRecord } from "../events.js";
import { authorityHostsFor, REQUEST_CLOCK_SKEW_SECONDS } from "../policy.js";
import { checkReconfirmation } from "../reconfirm.js";
import { verifyRecordSignature } from "../records.js";
import { validateEntry, type ValidationError } from "../schema.js";
import {
  getEntry,
  headSeq,
  recordReconfirmation,
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
import { entryWorld, eventsOf, rederive } from "./world.js";

/**
 * What this route is given besides its bindings: the instant the request is
 * being served at. Injected, so a test drives the real router on a fixed clock
 * and nothing under src/ reads one of its own.
 */
export interface ReconfirmDeps {
  readonly now: Date;
}

/** The schema's own id pattern. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);

/** The suffix that makes an entry's URL the door for a reconfirmation of it. */
const RECONFIRM_SUFFIX = "/reconfirm";

const ENTRIES_PREFIX = "/entries/";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/** A reconfirmation's body: the record signed, and the signature beside it. */
interface ReconfirmBody {
  readonly record: ReconfirmationRecord;
  readonly signature: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
 * The wire shape of a reconfirmation, checked before anything is read out of it.
 *
 * Only the shape is checked here. Whether the record's contents hold up is
 * src/reconfirm.ts's, and whether the whole entry then validates is the
 * schema's, asked below. The signature is beside the record and never inside it
 * (decision D-034), so a record carrying one is not this shape.
 */
function parseReconfirmBody(body: unknown): ReconfirmBody | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (key !== "record" && key !== "signature") return null;
  }
  const signature = body["signature"];
  if (typeof signature !== "string") return null;

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

  return { record: record as unknown as ReconfirmationRecord, signature };
}

/** The core the author signed, out of the entry's own submission event. */
function submissionCore(events: readonly Event[], entryId: string): Core | null {
  for (const event of events) {
    if (event.type !== "entry_submitted") continue;
    if (event.entry_id !== entryId) continue;
    return (event as Event<"entry_submitted">).payload.core;
  }
  return null;
}

/**
 * The derived entry did not validate against the schema.
 *
 * Thrown from inside `recordReconfirmation`'s derivation callback, which runs
 * before the batch is executed, so a record the schema refuses is refused with
 * nothing written — not even the event that would have carried it, and not the
 * bounty row that would have gone beside it.
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
// POST /entries/{id}/reconfirm
// ---------------------------------------------------------------------------

async function reconfirm(
  request: Request,
  env: Env,
  deps: ReconfirmDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  // The shape, before the envelope: a body that is not a reconfirmation is a
  // 400 whoever signed it. The clone is what lets the body be read twice — once
  // here and once by the verifier, which signs over the canonical form of it.
  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const body = parseReconfirmBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");

  const { record } = body;
  // The key that signed the request and the key inside the record must be the
  // same one: an attestation is signed by its own reconfirmer, never relayed.
  if (auth.agent !== record.agent) return refuse(403, "agent_mismatch");

  const signedAt = Date.parse(record.signed_at);
  if (
    Number.isNaN(signedAt) ||
    Math.abs(signedAt - deps.now.getTime()) >
      REQUEST_CLOCK_SKEW_SECONDS * MILLISECONDS_PER_SECOND
  ) {
    return refuse(422, "bad_signed_at");
  }

  // D-034: the signature is over the entry id, the kind, and the record, so an
  // attestation signed for one entry can never be replayed onto another, and a
  // validation's signature can never be replayed as a reconfirmation's.
  if (
    !(await verifyRecordSignature(id, "reconfirmation", record, body.signature))
  ) {
    return refuse(422, "bad_record_signature");
  }

  // The whole event set this entry is derived over, superseders included, so a
  // superseded entry is seen as superseded here rather than as still standing
  // (src/worker/world.ts).
  const world = await entryWorld(env.DB, id);
  const core = submissionCore(world.entryEvents, id);
  if (core === null) {
    // Unreachable: an entry row exists only where its submission event does.
    return refuse(404, "not_found");
  }

  // The entry as it stands, before this attestation. Everything the check reads
  // and everything the bounty is measured from comes out of this one derivation,
  // so the status the door judged and the window the bounty ran over cannot come
  // from two different readings of the log.
  const before = rederive(world, id, deps.now);

  const head = (await headSeq(env.DB)) ?? 0;
  const verdict = checkReconfirmation(record, core, {
    submitter: {
      agent: core["author"] as string,
      operator: (core["author_operator"] as string | null) ?? null,
    },
    agentOperators: Object.fromEntries(agentOperatorsAt(world.registry, head)),
    trustedOperators: [...trustedOperatorsAt(world.registry, head)],
    // Decision D-071: the reconfirmer's own domains, folded out of the same
    // events. The check compares them against the entry's domain, which it
    // reads off the signed core it was handed.
    operatorDomains: operatorDomainsOf(world.registry, record.operator, head),
    // Decision D-096: the hosts of the authority this entry's subject names,
    // from src/policy.ts, and whether a later version of the model has already
    // verified -- both asked of the same world the status comes from.
    authority_hosts: authorityHostsFor(domainOf(core), core["subject"]),
    versionStale: isVersionStale(eventsOf(world), id),
    status: before.derived.status,
    effectiveTier: before.sidecar.effective_tier,
  });
  if (!verdict.ok) return refuse(422, verdict.reason);

  // Section 6: "Any trusted operator can reconfirm a stale entry." An entry
  // still inside its window is refreshed by a staked revalidation request, not
  // by walking up to this door, so the door says so rather than sealing an
  // attestation that reopens a window nobody had closed.
  if (!before.derived.stale) return refuse(409, "entry_not_stale");

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
      await recordReconfirmation(env.DB, {
        event: {
          at,
          type: "reconfirmation",
          entry_id: id,
          payload: { record, signature: body.signature },
        },
        // Called with the event already sealed onto the head and before anything
        // is written, so the entry stored is derived from a log that holds this
        // attestation, and a schema refusal here leaves the log exactly as it was.
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
        // Section 7: the withheld half is paid to whoever makes the entry fresh
        // again. Measured against the entry as it stood *before* this attestation,
        // because deriving after the fact would find the window already reopened
        // and would never see a bounty at all.
        bounty: (event) =>
          bountyAccrual(
            { expires_at: before.derived.expires_at, stale: before.derived.stale },
            event,
          ),
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
// The router
// ---------------------------------------------------------------------------

/**
 * The entry id in `/entries/{id}/reconfirm`, or null when the path is not that
 * shape. An id carrying a further slash is not one entry's reconfirmation door
 * and falls through rather than being trimmed into one.
 */
function reconfirmPathId(path: string): string | null {
  if (!path.startsWith(ENTRIES_PREFIX)) return null;
  if (!path.endsWith(RECONFIRM_SUFFIX)) return null;
  const raw = path.slice(
    ENTRIES_PREFIX.length,
    path.length - RECONFIRM_SUFFIX.length,
  );
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Route one request to the reconfirm door, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched.
 *
 * The storage boundary is the validate door's: D1 is reached through the wrapped
 * handle, so a database that does not answer is a JSON 503 rather than a raw
 * 500. Nothing else is caught — a refusal is a value this route returns, and a
 * bug of ours escapes.
 */
export async function handleReconfirm(
  request: Request,
  env: Env,
  deps: ReconfirmDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  const id = reconfirmPathId(path);
  if (id === null) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  try {
    return await reconfirm(
      request,
      { ...env, DB: guardDatabase(env.DB) },
      deps,
      path,
      id,
    );
  } catch (error) {
    // The message only: no binding contents, no request data.
    const answer = unavailable(error, "reconfirm");
    if (answer !== null) return answer;
    throw error;
  }
}

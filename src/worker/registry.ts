/**
 * The registry routes: joining, genesis naming, and the reads that show both.
 *
 * Whitepaper Section 11's joining steps, less the money one (D-127): publish a
 * DNS TXT record carrying your 1F916 agent id, and sign the
 * provider-independence attestation from Section 10 with your 1F916 key — and
 * then: "The binding is then sealed into nomankind's log and you can validate."
 * This module is the door those steps knock on. It gathers the facts and writes
 * the events; it decides nothing itself. Every rule lives in src/registry.ts,
 * which is pure, so the same refusal an operator gets here is one an offline
 * reader can rederive from the log.
 *
 * Section 11 genesis: "The maintainer seeds the trusted pool once, by naming
 * its first members in public ... Genesis operators may not include the
 * maintainer's own." POST /genesis is that power and nothing else: only the
 * configured maintainer key may use it, an unconfigured maintainer refuses it
 * to everyone, and the naming is an event in the same log as everything else.
 *
 * Order matters and is deliberate. Structure, then signature, then the store,
 * then the two checks that reach outside this process. A malformed request
 * never costs a DNS lookup, and nothing is written until every check has
 * passed: a refusal leaves the log exactly where it was.
 *
 * No policy number lives here. The bare integers are HTTP status codes, the
 * page size is LIST_PAGE_LIMIT from src/policy.ts, and the DNS protocol
 * constants are src/adapters/dns.ts's.
 */

import type { DnsResolver } from "../adapters/dns.js";
import { attributionOf } from "../attribution.js";
import {
  buildCertificate,
  type CertificateSubject,
} from "../certificate.js";
import { operatorKindsAt } from "../derive.js";
import { appendEvent, type Attestation, type Event } from "../events.js";
import { publicKeyFromAgentId } from "../identity.js";
import { utcDay } from "../anchor.js";
import { quotaScopeForClient } from "../keys.js";
import { checkParameters, readLimit } from "../params.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_EARLY_ACCESS_DAYS,
  LIST_PAGE_LIMIT,
  REQUEST_CLOCK_SKEW_SECONDS,
  REQUEST_MAX_BODY_BYTES,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  WRITES_PER_CLIENT_PER_DAY,
  domainPolicy,
  isRegisteredDomain,
  type Tier,
} from "../policy.js";
import {
  perimeterOf,
  checkAgentBind,
  checkDomainJoin,
  checkGenesisNaming,
  checkRegistration,
  parseAgentBindBody,
  parseDomainJoinBody,
  parseGenesisBody,
  parseRegistrationBody,
  txtMatches,
  txtRecordName,
  type AgentBindRefusal,
  type GenesisRefusal,
  type JoinRefusal,
  type RegistrationRefusal,
} from "../registry.js";
import {
  checkKeyRotation,
  type KeyRotationRefusal,
} from "../rotation.js";
import {
  marksOf,
  standingAt,
  tierOf,
  zeroStanding,
  type RecordMarks,
  type StandingCounts,
} from "../standing.js";
import { STRICT_TRANSPORT_SECURITY } from "../ui/html.js";
import {
  HEADER_AGENT,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  verifyRequest,
} from "../request.js";
import type {
  D1Like,
  D1LikeExecResult,
  D1LikeResult,
  D1LikeStatement,
} from "../storage/d1.js";
import { addQuota, quotaOn } from "../storage/keys.js";
import { D1NonceStore } from "../storage/nonces.js";
import {
  EventAppendError,
  agentsForOperator,
  eventBySeq,
  eventsForEntry,
  getEntry,
  getOperator,
  latestSeal,
  headSeq,
  listOperators,
  operatorDomains,
  operatorForAgent,
  operatorTier,
  operatorTierForAgent,
  standingByOperator,
  standingForOperators,
  storedStandings,
  recordAgentBind,
  recordDomainJoin,
  recordKeyRotation,
  retiredAgents,
  registerOperator,
  trustOperator,
  type AgentRecord,
  type OperatorRecord,
  type OperatorStanding,
} from "../storage/repository.js";
import { maintainerAgentId } from "./config.js";
import { signerFor } from "./read.js";
import { sealedLog } from "./sweep.js";
import { registryEvents } from "./world.js";
import type { Env } from "./env.js";

/**
 * What a request handler is given besides its bindings: the instant this
 * request is being served at, and the one way out of the process. Both are
 * injected so a test drives a real router with a fake clock and a fixture
 * resolver, and so nothing under src/ reads a clock of its own.
 */
export interface RegistryDeps {
  readonly now: Date;
  readonly dns: DnsResolver;
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/** Every response this Worker writes is JSON that must not be cached. */
export function json(
  body: unknown,
  status: number,
  extraHeaders?: HeadersInit,
): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "application/json");
  headers.set("cache-control", "no-store");
  // The transport rule, beside the page's own security headers and for the same
  // reason (the QA of 2026-09-12): a JSON door is reached by a browser too.
  headers.set("strict-transport-security", STRICT_TRANSPORT_SECURITY);
  return new Response(JSON.stringify(body), { status, headers });
}

/** A refusal: the status, and the reason in the same word the kernel used. */
export function refuse(status: number, reason: string): Response {
  return json({ error: reason }, status);
}

export function methodNotAllowed(allow: string): Response {
  return json({ error: "method_not_allowed" }, 405, { allow });
}

/**
 * The methods a read door answers, and the `Allow` header that names them.
 *
 * A HEAD is a GET without the body — it is how a client asks what a read would
 * cost and whether it has changed without paying for the bytes — so every read
 * door answers it with the same status and the same headers as the GET, and the
 * body is dropped in exactly one place, src/worker/index.ts. A door that
 * refused it would be a door whose 405 said nothing was wrong.
 */
export const READ_METHODS = "GET, HEAD";

/** Whether this request is a read: the GET, or the HEAD that stands for it. */
export function isRead(request: Request): boolean {
  return request.method === "GET" || request.method === "HEAD";
}

/**
 * The status each registration refusal answers with.
 *
 * An excluded party at the door is 403: the request was understood, the identity
 * was proved, and the answer is still no (Section 10). A domain that is not a
 * domain, a record domain nobody registered, and an attestation that does not
 * verify or is for another domain are 422 — the request was well formed and its
 * contents were not. A name already taken is 409.
 */
const REGISTRATION_STATUS: Record<RegistrationRefusal, number> = {
  bad_domain: 422,
  unregistered_domain: 422,
  provider_operator: 403,
  missing_attestation: 422,
  bad_attestation: 422,
  attestation_domain_mismatch: 422,
  operator_exists: 409,
  agent_bound: 409,
};

/**
 * The status each domain-join refusal answers with, the same shape and for the
 * same reasons as a registration's: an excluded party is 403, a domain already
 * held is 409, and everything else is a well-formed request whose contents do
 * not hold up (422). An unregistered operator is 422 rather than 404 because
 * the route's own 404 is about the operator the path names, and this refusal is
 * about the log not carrying its registration.
 */
const JOIN_STATUS: Record<JoinRefusal, number> = {
  unregistered_operator: 422,
  unregistered_domain: 422,
  excluded_party: 403,
  already_joined: 409,
  missing_attestation: 422,
  bad_attestation: 422,
  attestation_domain_mismatch: 422,
};

/**
 * The status each agent-bind refusal answers with.
 *
 * An operator the registry does not hold is 404 and not 422: the path names it,
 * so this is the route's own not_found said in the kernel's word for it. A
 * request signed by somebody else's key is 403 — understood, proved, and still
 * refused — a key already bound is 409, and everything else is a well-formed
 * request whose contents do not hold up (422).
 */
const AGENT_BIND_STATUS: Record<AgentBindRefusal, number> = {
  unregistered_operator: 404,
  not_operator_agent: 403,
  agent_bound: 409,
  bad_agent: 422,
  missing_attestation: 422,
  bad_attestation: 422,
  attestation_domain_mismatch: 422,
};

/**
 * The status each rotation refusal answers with (D-095, D-097 item 3).
 *
 * `community_operator` is 409 and not 404: the operator is registered and the
 * caller is not wrong about it existing, but its key rotates by its profile
 * and not at this door (D-140 item 5), so the request is in conflict with what
 * that operator is rather than about nobody. `agent_retired` is 409 for the
 * same reason -- the key exists and its retirement is already in the log.
 */
const KEY_ROTATION_STATUS: Record<KeyRotationRefusal, number> = {
  unknown_operator: 404,
  community_operator: 409,
  unknown_agent: 403,
  author_mismatch: 403,
  agent_retired: 409,
  bad_agent: 422,
  agent_already_bound: 409,
  missing_attestation: 422,
  bad_attestation: 422,
};

/**
 * The status each genesis refusal answers with. An unconfigured maintainer is
 * 503 and not 403: the power exists and this deployment cannot exercise it,
 * which is our state rather than the caller's fault.
 */
const GENESIS_STATUS: Record<GenesisRefusal, number> = {
  maintainer_not_configured: 503,
  not_maintainer: 403,
  unregistered_operator: 422,
  maintainer_operator: 403,
  provider_operator: 403,
  already_trusted: 409,
};

// ---------------------------------------------------------------------------
// The storage boundary
// ---------------------------------------------------------------------------

/**
 * A call into D1 threw.
 *
 * The health probe already says `storage: "unreachable"` rather than falling
 * over when the database does not answer, and these routes owe a caller the
 * same answer instead of a raw 500. Distinguishing that case from a bug of ours
 * cannot be done by inspecting an error after the fact, so it is marked where
 * it happens: every call through the wrapped handle below that throws is
 * rewrapped as this, and the route boundary catches this and nothing else. A
 * TypeError from our own row reading, thrown after D1 answered, stays a
 * programming error and still reaches the platform as a 500.
 */
export class StorageUnreachable extends Error {
  constructor(reason: unknown) {
    super(reason instanceof Error ? reason.message : String(reason));
    this.name = "StorageUnreachable";
  }
}

/** Run a D1 call, marking anything it throws as a storage failure. */
async function through<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw new StorageUnreachable(error);
  }
}

/** The same, for the calls D1 makes synchronously. */
function throughSync<T>(call: () => T): T {
  try {
    return call();
  } catch (error) {
    throw new StorageUnreachable(error);
  }
}

/**
 * Each wrapped statement, back to the one D1 gave us. `batch` has to be handed
 * the driver's own statements, so a wrapper is unwrapped again on the way in.
 */
const UNDERLYING = new WeakMap<D1LikeStatement, D1LikeStatement>();

function guardStatement(statement: D1LikeStatement): D1LikeStatement {
  const guarded: D1LikeStatement = {
    bind(...values: unknown[]): D1LikeStatement {
      return guardStatement(throughSync(() => statement.bind(...values)));
    },
    first<Row = Record<string, unknown>>(): Promise<Row | null> {
      return through(() => statement.first<Row>());
    },
    all<Row = Record<string, unknown>>(): Promise<D1LikeResult<Row>> {
      return through(() => statement.all<Row>());
    },
    run<Row = Record<string, unknown>>(): Promise<D1LikeResult<Row>> {
      return through(() => statement.run<Row>());
    },
  };
  UNDERLYING.set(guarded, statement);
  return guarded;
}

/**
 * The database handle the routes actually use: the binding, with every way it
 * can fail marked as a storage failure rather than left to escape as an
 * unhandled exception. Exported because the routes M13 mounts beside these owe
 * a caller the same 503 and must not grow a weaker boundary of their own.
 */
export function guardDatabase(db: D1Like): D1Like {
  return {
    prepare(sql: string): D1LikeStatement {
      return guardStatement(throughSync(() => db.prepare(sql)));
    },
    batch<Row = Record<string, unknown>>(
      statements: D1LikeStatement[],
    ): Promise<D1LikeResult<Row>[]> {
      const unwrapped = statements.map(
        (statement) => UNDERLYING.get(statement) ?? statement,
      );
      return through(() => db.batch<Row>(unwrapped));
    },
    exec(sql: string): Promise<D1LikeExecResult> {
      return through(() => db.exec(sql));
    },
  };
}

// ---------------------------------------------------------------------------
// The chain boundary
// ---------------------------------------------------------------------------

/**
 * How many times a write door rebuilds its batch onto a head that moved under
 * it. A retry budget, not a policy number: it bounds a loop whose every
 * iteration is a real conflict, and the answer when it runs out is a refusal
 * rather than a signed request quietly dropped.
 */
const CHAIN_ATTEMPTS = 3;

/**
 * Three writes in a row lost the race for the next position in the log.
 *
 * The chain is single-file by design: an event's seq is the head's plus one and
 * its `prev_hash` is the head's hash, so two writes that land in one tick — a
 * validation while the sweep is sealing, two operators registering together —
 * cannot both be written, and the loser's whole batch is refused by the unique
 * index on events.seq. That is not a storage failure and must not be answered
 * as one: the database is healthy and the request is good, so the door rebuilds
 * onto the new head and writes again. This is what it means when even that ran
 * out, and it is its own refusal (`chain_conflict`) so a caller can tell "try
 * again in a moment" from "the database is not answering".
 */
export class ChainConflict extends Error {
  constructor(reason: unknown) {
    super(reason instanceof Error ? reason.message : String(reason));
    this.name = "ChainConflict";
  }
}

/**
 * The database refusing a second event at one position, in the words SQLite
 * uses for it. Anchored on the column, so a unique violation anywhere else in
 * the same batch — an operator name, a receipt counter — is not read as this.
 */
const SEQ_TAKEN = /UNIQUE constraint failed:[^\n]*\bevents\.seq\b/;

/**
 * Whether a failed write lost the chain rather than the database.
 *
 * Two failures and only two mean it. `EventAppendError` is the chain rule
 * refusing a run built on a head somebody has already replaced, and its two
 * reasons are the whole of that rule: a seq that is not head + 1, and a
 * prev_hash that is not the head's. The other is the unique index on
 * events.seq, which is the same race lost one layer down — both writers passed
 * the rule against the head they read, and the database refused the second
 * insert.
 *
 * Everything else is somebody else's failure and keeps its own name. In
 * particular a transient D1 error is not turned into a conflict by another
 * writer happening to move the head in the same moment: the head moving is not
 * evidence about why *this* write failed, and a database that is not answering
 * must stay `storage_unreachable` or a real outage would be reported to every
 * caller as a race they should try again.
 */
function lostTheChain(error: unknown): boolean {
  if (error instanceof EventAppendError) {
    return error.reason === "bad_seq" || error.reason === "bad_prev_hash";
  }
  if (error instanceof StorageUnreachable) return SEQ_TAKEN.test(error.message);
  return false;
}

/**
 * Run one write of the log, rebuilding it from the door's own derivation when
 * another writer takes the position first.
 *
 * `write` is the whole of a door's derivation and its batch, not the batch
 * alone: every event's seq and `prev_hash` — and so its hash, and so the hash
 * of everything chained after it — are functions of the head, so a rebuild that
 * started from the failed statements would write the same doomed bytes again.
 * Handed the closure instead, this re-reads nothing itself and simply lets the
 * door do its own work over, which is why the doors that re-check a duplicate
 * inside their closure answer 409 to a racing twin rather than retrying into
 * the same wall.
 *
 * One helper and not one per door: seven copies of a retry rule would be seven
 * chances for a door to give up sooner, or to answer a conflict as an outage.
 */
export async function withChainRetry<T>(write: () => Promise<T>): Promise<T> {
  let last: unknown = null;
  for (let attempt = 0; attempt < CHAIN_ATTEMPTS; attempt += 1) {
    try {
      return await write();
    } catch (error) {
      if (!lostTheChain(error)) throw error;
      last = error;
    }
  }
  throw new ChainConflict(last);
}

/**
 * The 503 a door owes for a write it could not make, or null when the failure
 * is not one of those and belongs to the platform.
 *
 * The two cases a caller has to be able to tell apart: the database did not
 * answer, and the log's next position kept going to somebody else. One place
 * decides which, so a door cannot grow a weaker boundary of its own, and the
 * message alone reaches the log — no binding contents, no request data.
 */
export function unavailable(error: unknown, route: string): Response | null {
  if (error instanceof ChainConflict) {
    console.error(`${route}: chain conflict: ${error.message}`);
    return refuse(503, "chain_conflict");
  }
  if (error instanceof StorageUnreachable) {
    console.error(`${route}: storage unreachable: ${error.message}`);
    return refuse(503, "storage_unreachable");
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reading and authenticating a write
// ---------------------------------------------------------------------------

export type Authenticated =
  | { ok: true; agent: string; body: unknown }
  | { ok: false; response: Response };

/** The request's headers, lowercased, as verifyRequest wants them. */
function headerMap(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  return headers;
}

/** ISO 8601 date-time with a seconds field and an explicit offset or Z. */
const ISO_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** How many milliseconds a second is. Not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_IN_A_DAY = 86_400_000;

/**
 * Everything the verifier can decide about a signed request without its body.
 *
 * The four headers' presence, the agent header naming a real key, and the
 * timestamp being a timestamp inside the skew window — exactly the checks
 * `verifyRequest` makes before it ever looks at the body, in the same order and
 * answering in the same words, so a caller is told the same thing whichever of
 * the two reached the verdict.
 *
 * It exists because the body is the expensive part. The signature covers the
 * canonical body and so cannot be checked without it, but nothing above it can:
 * an unsigned request has no business costing this Worker a twelve-megabyte read
 * and a parse before it is told it was never signed. So this runs first, on
 * headers alone, and the body is read only for a request that got this far.
 *
 * The nonce is not checked here, only that it is present: spending a nonce is a
 * write, and a request that has not been read yet has not been served.
 */
function headerVerdict(
  headers: Record<string, string>,
  now: Date,
): { ok: true; publicKey: Uint8Array } | { ok: false; reason: string } {
  const present = (name: string): string | undefined => {
    const value = headers[name];
    return value === undefined || value === "" ? undefined : value;
  };

  const agentHeader = present(HEADER_AGENT);
  const timestamp = present(HEADER_TIMESTAMP);
  if (
    agentHeader === undefined ||
    timestamp === undefined ||
    present(HEADER_NONCE) === undefined ||
    present(HEADER_SIGNATURE) === undefined
  ) {
    return { ok: false, reason: "missing_header" };
  }

  let publicKey: Uint8Array;
  try {
    publicKey = publicKeyFromAgentId(agentHeader);
  } catch {
    return { ok: false, reason: "agent_mismatch" };
  }

  if (!ISO_DATE_TIME.test(timestamp)) {
    return { ok: false, reason: "bad_timestamp" };
  }
  const signedAt = Date.parse(timestamp);
  if (Number.isNaN(signedAt)) return { ok: false, reason: "bad_timestamp" };
  const skew = Math.abs(now.getTime() - signedAt) / MILLISECONDS_PER_SECOND;
  if (skew > REQUEST_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: "clock_skew" };
  }

  return { ok: true, publicKey };
}

/**
 * The request's body, or the refusal its size earned.
 *
 * Two checks and not one. `Content-Length` above the cap is refused before a
 * byte is read, which is what makes an oversized body cost nothing at all; a
 * body that declares no length is read through its own stream and abandoned at
 * the cap plus one byte, which is what stops a chunked body from being the way
 * around the first check. Either way nothing above REQUEST_MAX_BODY_BYTES is
 * ever held in this isolate, and no JSON parse happens anywhere before this.
 *
 * One helper for every write door, because thirteen copies of a cap would be
 * thirteen chances for a door to be the one that forgot.
 */
export async function readCappedBody(
  request: Request,
): Promise<{ ok: true; text: string } | { ok: false; response: Response }> {
  const tooLarge = {
    ok: false as const,
    response: refuse(413, "body_too_large"),
  };

  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > REQUEST_MAX_BODY_BYTES) {
      return tooLarge;
    }
  }

  const stream = request.body;
  if (stream === null) return { ok: true, text: await request.text() };

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done === true) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > REQUEST_MAX_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      return tooLarge;
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(bytes) };
}

/**
 * The scope one agent's writes are counted under.
 *
 * The agent id in the clear, because it is already public: it is in every
 * signed request's headers and in every event the agent's writes produce, and a
 * counter under it records how much that key wrote and never what it wrote.
 */
export function writeScopeForAgent(agent: string): string {
  return `write:agent:${agent}`;
}

/**
 * The scope one client address's writes are counted under: the same hashed
 * client scope the read path counts a keyless reader under, under this side's
 * own prefix so a day's reads and a day's writes are never the same row.
 */
export async function writeScopeForClient(request: Request): Promise<string> {
  return `write:${await quotaScopeForClient(
    request.headers.get("cf-connecting-ip"),
  )}`;
}

/** The start of the day after this one, which is when a write cap resets. */
function writeQuotaResetsAt(day: string): string {
  const start = Date.parse(`${day}T00:00:00.000Z`);
  return new Date(start + MILLISECONDS_IN_A_DAY).toISOString();
}

/**
 * The per-day write cap one signing agent writes under (decision D-130).
 *
 * D-130 gates participation by tier as published policy, and the write cap is
 * the first gate a key meets: a probation operator "submits at a probationary
 * write cap", an established one has the full cap, and a senior one a higher
 * one. The three numbers are src/policy.ts's and the reading of them is
 * src/standing.ts's `tierOf`; nothing is decided here.
 *
 * A bare key gets the probation cap. It has no operator, so it has no standing
 * and no tier of its own, and the honest place to put a name nobody vouches for
 * is the bottom band — which is also what keeps the key factory the client
 * bucket exists to bound from buying anything by minting operators instead.
 *
 * One keyed read (`operatorTierForAgent`), on a path that already reads the
 * nonce store and writes two counters.
 */
async function agentWriteCap(db: D1Like, agent: string): Promise<number> {
  const row = await operatorTierForAgent(db, agent);
  const tier =
    row === null
      ? "probation"
      : tierOf(row.standing ?? 0, row.trusted);
  if (tier === "probation") return WRITES_PER_AGENT_PER_DAY_PROBATION;
  if (tier === "senior") return WRITES_PER_AGENT_PER_DAY_SENIOR;
  return WRITES_PER_AGENT_PER_DAY;
}

/**
 * Charge one write against the two buckets that bound the free write path, or
 * refuse when either is spent.
 *
 * Whitepaper Section 5 lets anyone submit with a bare agent key and Section 9
 * prices spam through the paid loop. Both hold here, and the second is why the
 * first can: a self-generated key is free, so the agent bucket alone would be
 * bounded by nothing at all — a caller that mints a key per request spends a
 * fresh cap every time. The client bucket is the one that counts the caller
 * rather than the name they signed under, keyed by the same hashed client scope
 * the read path counts a keyless reader under, so the two together bound both
 * the busy key and the key factory.
 *
 * Charged after the signature verifies and before any fetch, DNS lookup,
 * archive write or derivation: a write is the cheapest thing to refuse before
 * the expensive part of a door, and it is charged whether or not the door goes
 * on to refuse the request on its own merits. That is deliberate and matches
 * what the nonce already does — a request that authenticated and was then
 * refused has spent this Worker's attention, and a caller who could make a
 * hundred doomed submissions for free would have found the hole this closes.
 *
 * The same table the read quota uses, under its own scope prefix, so there is
 * one place a day's usage lives and one UPSERT that the database does the
 * arithmetic of.
 */
export async function chargeWrite(
  db: D1Like,
  request: Request,
  agent: string,
  now: Date,
): Promise<{ ok: true } | { ok: false; response: Response }> {
  const day = utcDay(now.toISOString());
  // Which cap this key writes under (decision D-130): the tier of the operator
  // behind it at the moment of the request. One keyed read, before the counters,
  // because the cap has to be known before it can be compared against — and a
  // bare key reads as probation, which is what it is: nobody's established
  // operator.
  const agentCap = await agentWriteCap(db, agent);
  const agentScope = writeScopeForAgent(agent);
  const clientScope = await writeScopeForClient(request);

  const agentUsed = await quotaOn(db, agentScope, day);
  const clientUsed = await quotaOn(db, clientScope, day);

  const spent = (
    bucket: "agent" | "client",
    limit: number,
    used: number,
  ): { ok: false; response: Response } => ({
    ok: false,
    response: json(
      {
        error: "write_quota",
        bucket,
        limit,
        used,
        resets_at: writeQuotaResetsAt(day),
      },
      429,
      {
        "x-nomankind-write-limit": String(limit),
        "x-nomankind-write-remaining": "0",
      },
    ),
  });

  if (agentUsed >= agentCap) {
    return spent("agent", agentCap, agentUsed);
  }
  if (clientUsed >= WRITES_PER_CLIENT_PER_DAY) {
    return spent("client", WRITES_PER_CLIENT_PER_DAY, clientUsed);
  }

  await addQuota(db, agentScope, day, 1);
  await addQuota(db, clientScope, day, 1);
  return { ok: true };
}

/**
 * Read the body and prove who sent it (decision D-014).
 *
 * The signature covers the method, the path and the canonical body, so a
 * capture cannot be replayed against another route, and the nonce store is D1
 * rather than isolate memory: a Worker that forgot a nonce because the replay
 * landed in a second isolate would accept it. The store is pruned at `now`
 * before the check, so retention is measured against the injected clock and
 * never against a wall clock read down here.
 *
 * The order is what a refusal costs, cheapest first, and it is the same order at
 * every write door because every write door is this function:
 *
 * 1. the four headers' presence and shape and the timestamp's skew, on headers
 *    alone (401 missing_header, agent_mismatch, bad_timestamp, clock_skew), so
 *    an unsigned body is never read at all;
 * 2. the body against REQUEST_MAX_BODY_BYTES (413 body_too_large), declared
 *    length first and the arriving bytes second;
 * 3. the parse, and the object shape a signed body must have (400 bad_body) —
 *    the first JSON.parse anywhere on the write path, and it is after the cap;
 * 4. the nonce and the signature, which need the canonical body (401 replay,
 *    bad_signature);
 * 5. one write charged against the day's two buckets (429 write_quota).
 *
 * Only then does the door get its turn, with a body it does not have to read
 * again. The genesis door is the one that charges nothing: it is the
 * maintainer's own key naming the first trusted operators once, and a cap on it
 * would be a cap on ourselves.
 */
export async function authenticate(
  request: Request,
  env: Env,
  deps: { readonly now: Date },
  path: string,
  options: { readonly charge?: boolean } = {},
): Promise<Authenticated> {
  const headers = headerMap(request);
  const precheck = headerVerdict(headers, deps.now);
  if (!precheck.ok) {
    return { ok: false, response: refuse(401, precheck.reason) };
  }

  const read = await readCappedBody(request);
  if (!read.ok) return { ok: false, response: read.response };

  let body: unknown;
  try {
    body = JSON.parse(read.text);
  } catch {
    return { ok: false, response: refuse(400, "bad_body") };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, response: refuse(400, "bad_body") };
  }

  const nonces = new D1NonceStore(env.DB);
  await nonces.prune(deps.now);
  const verdict = await verifyRequest({
    method: request.method,
    path,
    body,
    headers,
    publicKey: precheck.publicKey,
    now: deps.now,
    nonces,
  });
  if (!verdict.ok) {
    return { ok: false, response: refuse(401, verdict.reason) };
  }

  // The key is the key it claims to be — and from the seal of its rotation on,
  // it is a key that stopped answering for its operator (D-095, D-097 item 3).
  // Asked here rather than at each door, because a retired key is refused at
  // every write door and not at some of them, and one question after the
  // signature is one question: the fold is over the `key_rotated` events alone,
  // which is an indexed range over a handful of rows.
  //
  // 403 and not 401: the signature is good and the caller is who they say. What
  // is gone is the standing to write, which is exactly what a forbidden is.
  // Nothing about the past is touched — the signatures this key made before its
  // rotation stay valid, and derivation and the verifier both read positions.
  if (await isRetired(env.DB, verdict.agentId)) {
    return { ok: false, response: refuse(403, "agent_retired") };
  }

  if (options.charge !== false) {
    const charged = await chargeWrite(env.DB, request, verdict.agentId, deps.now);
    if (!charged.ok) return { ok: false, response: charged.response };
  }

  return { ok: true, agent: verdict.agentId, body };
}

/**
 * The maintainer's agent id, or null when none is configured.
 *
 * Read through `maintainerAgentId` (src/worker/config.ts), which treats an
 * unset binding and an empty one as the same absence. The `=== ""` test this
 * replaced let an unset var through as `undefined`, so a deployment that had
 * configured no maintainer at all answered the genesis door 403
 * `not_maintainer` — "you are not the maintainer", about a maintainer nobody
 * named — instead of 503 `maintainer_not_configured` (the QA of 2026-09-12).
 */
function maintainerOf(env: Env): string | null {
  return maintainerAgentId(env);
}

/**
 * Whether this key has been retired by a rotation (D-095, D-097 item 3).
 *
 * One read of the `key_rotated` events, folded by src/rotation.ts's own
 * `retiredAgentsAt` through the repository, so the doors and derivation cannot
 * come to two different answers about which keys have stopped speaking.
 *
 * A log that has never held a rotation — which is every log until the first one
 * — costs one empty indexed range per signed write.
 */
async function isRetired(db: D1Like, agent: string): Promise<boolean> {
  return (await retiredAgents(db, LIST_PAGE_LIMIT)).has(agent);
}

/** The log's last event, or nothing when the log is empty. */
async function tail(env: Env): Promise<Event[]> {
  const head = await headSeq(env.DB);
  if (head === null) return [];
  const event = await eventBySeq(env.DB, head);
  return event === null ? [] : [event];
}

/**
 * The attested fields, and only those.
 *
 * The signature is over the operator, the agent, the version, the domain when
 * the record carries one, the timestamp and that domain's fixed sentence
 * (src/registry.ts). Copying the request's object verbatim would seal whatever
 * unsigned keys it also carried into the log beside them, so the event carries
 * exactly what was signed.
 *
 * `domain` is copied only when the record actually declares one (decision
 * D-071). Absent stays absent rather than becoming the default slug: the
 * pre-v0.7 signing bytes carried no domain key at all, so adding one would make
 * a legacy attestation stop verifying against its own signature.
 */
function attestationOf(value: unknown): Attestation {
  const record = value as Record<string, unknown>;
  const domain = record["domain"];
  return {
    version: String(record["version"]),
    ...(typeof domain === "string" ? { domain } : {}),
    signed_at: String(record["signed_at"]),
    signature: String(record["signature"]),
  };
}

// ---------------------------------------------------------------------------
// POST /operators
// ---------------------------------------------------------------------------

async function register(
  request: Request,
  env: Env,
  deps: RegistryDeps,
  path: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const parsed = parseRegistrationBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { operator, domain, attestation } = parsed.value;
  const agent = auth.agent;

  const check = await checkRegistration({
    operator,
    agent,
    // The body's domain, or null when the client wrote none — which is what a
    // client written before v0.7 sends, and reads as the default domain.
    domain,
    attestation,
    maintainerAgentId: maintainerOf(env),
    operatorExists: (await getOperator(env.DB, operator)) !== null,
    agentOperator: await operatorForAgent(env.DB, agent),
    now: deps.now,
  });
  if (!check.ok) {
    return refuse(REGISTRATION_STATUS[check.reason], check.reason);
  }

  // Step one, Section 11: the TXT record on a domain the operator controls.
  const lookup = await deps.dns.txt(txtRecordName(operator));
  if (!lookup.ok) {
    return lookup.reason === "nxdomain"
      ? refuse(422, "dns_no_record")
      : refuse(503, "dns_unavailable");
  }
  if (!txtMatches(lookup.values, agent)) {
    return refuse(422, "dns_mismatch");
  }

  // Every check has passed, so now the binding is sealed into the log. The two
  // events and the two rows go down in one atomic batch (registerOperator), so
  // a registration is either fully in the log and visible or not there at all.
  //
  // The whole of it is inside the retry, derivation included: another write
  // landing in this same tick takes the next position in the log and this batch
  // is refused whole, and events rebuilt from a head that moved are different
  // events. The store reads the check rests on are inside it for the same
  // reason — a twin registering the same name is exactly the race that moves
  // the head, and on the second pass the name is taken and the honest answer is
  // the 409 it always was, not a 503.
  const seal = async (): Promise<Response> => {
    const settled = await checkRegistration({
      operator,
      agent,
      domain,
      attestation,
      maintainerAgentId: maintainerOf(env),
      operatorExists: (await getOperator(env.DB, operator)) !== null,
      agentOperator: await operatorForAgent(env.DB, agent),
      now: deps.now,
    });
    if (!settled.ok) {
      return refuse(REGISTRATION_STATUS[settled.reason], settled.reason);
    }

    const at = deps.now.toISOString();
    const previous = await tail(env);
    const withOperator = await appendEvent(previous, {
      at,
      type: "operator_registered",
      entry_id: null,
      // The domain the check settled on, written into the event rather than left
      // to the row: an offline reader folds `operatorDomainsAt` out of the log
      // alone, so the first domain has to be in the log alone (decision D-071).
      payload: { operator, maintainer: settled.maintainer, domain: settled.domain },
    });
    const withBinding = await appendEvent(withOperator, {
      at,
      type: "agent_bound",
      entry_id: null,
      payload: { operator, agent, attestation: attestationOf(attestation) },
    });
    const events = withBinding.slice(previous.length);
    const registered = events[0];
    const bound = events[1];

    const record: OperatorRecord = {
      id: operator,
      // Every operator this door registers is a domain operator (D-138): a
      // community one is registered by its own attested line and by nothing
      // else, and its id carries the colon `checkRegistration` refuses.
      kind: "domain",
      maintainer: settled.maintainer,
      // Nobody registers as a provider: checkRegistration refuses the domain, so
      // the column exists for a later decision and is false at every door today.
      provider: false,
      registeredSeq: registered.seq,
      details: {
        registered_by: agent,
        attestation: attestationOf(attestation),
        // Trust is granted by an event and never at registration, even for the
        // maintainer's own operator (Section 11).
        trusted: false,
        trusted_seq: null,
      },
    };
    const agentRecord: AgentRecord = {
      agentId: agent,
      operatorId: operator,
      registeredSeq: bound.seq,
    };
    await registerOperator(env.DB, {
      events,
      operator: record,
      agent: agentRecord,
      domain: { domain: settled.domain, attestation: attestationOf(attestation) },
    });

    return json({ ...record, agents: [agent], domains: [settled.domain] }, 201);
  };

  return await withChainRetry(seal);
}

// ---------------------------------------------------------------------------
// POST /operators/{id}/domains
// ---------------------------------------------------------------------------

/**
 * Take on a second domain.
 *
 * Decision D-071: registration binds an operator to the domain its attestation
 * was signed for, and a later domain is joined by signing that domain's own
 * attestation. The order here is the order every other write takes: the path,
 * then the body, then the request signature, then the store, then the pure
 * check — so a malformed request never costs a signature verification and
 * nothing is written until every check has passed.
 *
 * The join is the operator's own act, so the signing key has to be an agent of
 * the operator the path names. An agent registered to somebody else is 403 and
 * not 404: the operator exists, and this key is simply not it.
 */
async function joinDomain(
  request: Request,
  env: Env,
  deps: RegistryDeps,
  path: string,
  operator: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const parsed = parseDomainJoinBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { domain, attestation } = parsed.value;

  const record = await getOperator(env.DB, operator);
  if (record === null) return refuse(404, "not_found");
  if ((await operatorForAgent(env.DB, auth.agent)) !== operator) {
    return refuse(403, "agent_mismatch");
  }

  const held = await operatorDomains(env.DB, operator);
  const check = await checkDomainJoin({
    operator,
    agent: auth.agent,
    domain,
    attestation,
    registered: true,
    domains: held.map((row) => row.domain),
    now: deps.now,
  });
  if (!check.ok) return refuse(JOIN_STATUS[check.reason], check.reason);

  // The tier gate (decision D-130), after the join's own rules and before
  // anything is written: "established at trusted standing has ... domain
  // joins", so a probation operator is refused `insufficient_tier`, and a
  // domain still inside its early-access window is senior-only until it closes.
  //
  // Last of the refusals because it is the least specific: a domain nobody
  // registered and a domain this operator already holds are answers about the
  // join that was asked for, and a tier refusal in front of them would tell an
  // operator it lacks the standing for something it could not have had anyway.
  // Nothing has been written or fetched by here, so it still costs a refusal
  // nothing but the rows this door already read.
  const gate = await checkJoinTier(env.DB, operator, domain, deps.now);
  if (gate !== null) return gate;

  // The event is the record and the row is the index into it, written in one
  // batch (recordDomainJoin), so a join is either fully in the log and visible
  // to the next draw or not there at all.
  const joined = await withChainRetry(() =>
    recordDomainJoin(env.DB, {
      at: deps.now.toISOString(),
      type: "operator_joined_domain",
      entry_id: null,
      payload: {
        operator,
        agent: auth.agent,
        domain,
        attestation: attestationOf(attestation),
      },
    }),
  );

  const agents = await agentsForOperator(env.DB, operator, LIST_PAGE_LIMIT);
  return json(
    {
      ...record,
      agents: agents.map((agent) => agent.agentId),
      domains: [...held.map((row) => row.domain), joined.payload.domain],
    },
    201,
  );
}

/**
 * Whether this operator's tier lets it join this domain, or the refusal.
 *
 * Decision D-130 in its two words. `insufficient_tier` is a probation operator
 * asking for something the tiers reserve for established ones: joining a second
 * domain is taking on work in a field nobody has vouched for you in, and the
 * bar for it is the trusted pool's own. `early_access` is an established
 * operator asking for a domain that was registered less than
 * DOMAIN_EARLY_ACCESS_DAYS ago: recognition in its one practical form, the
 * senior operators that carried the record get first sight of a new domain, and
 * after the window the domain is open to every established operator for good.
 *
 * 403 for both: the request is well formed and the operator is who it says it
 * is; what it lacks is the standing, which is exactly what a 403 says.
 *
 * Null when the join may go on, so the caller reads it as a gate rather than as
 * a verdict about the join itself — `checkDomainJoin` is still the authority on
 * whether the attestation, the domain and the operator fit together.
 */
async function checkJoinTier(
  db: D1Like,
  operator: string,
  domain: string,
  now: Date,
): Promise<Response | null> {
  const row = await operatorTier(db, operator);
  const tier = tierOf(row?.standing ?? 0, row?.trusted ?? false);
  if (tier === "probation") return refuse(403, "insufficient_tier");
  if (tier === "senior") return null;
  return domainInEarlyAccess(domain, now)
    ? refuse(403, "early_access")
    : null;
}

/**
 * Whether a registered domain is still inside its early-access window.
 *
 * The window runs forward from the domain's own published `registered_at`, for
 * `DOMAIN_EARLY_ACCESS_DAYS`, and it is never reopened. A clock before that
 * date is outside it rather than deep inside it: the window is the first
 * fortnight of a registered domain's life, and a request made before the
 * registration is not in that fortnight at all.
 *
 * A domain nobody registered has no window either — `checkDomainJoin` refuses
 * it `unregistered_domain`, in its own words, a moment later.
 */
function domainInEarlyAccess(domain: string, now: Date): boolean {
  if (!isRegisteredDomain(domain)) return false;
  const registered = Date.parse(`${domainPolicy(domain).registered_at}T00:00:00.000Z`);
  if (!Number.isFinite(registered)) return false;
  const age = now.getTime() - registered;
  return age >= 0 && age < DOMAIN_EARLY_ACCESS_DAYS * MILLISECONDS_IN_A_DAY;
}

// ---------------------------------------------------------------------------
// POST /operators/{id}/agents
// ---------------------------------------------------------------------------

/**
 * Bind a second agent to an operator.
 *
 * Whitepaper Section 5: "An operator runs agents", and every agent under one
 * counts as one for validation. Registration binds the first; this binds the
 * next. The operator vouches for the new key by signing the request with a key
 * it already has, and the new key signs the independence attestation for the
 * domain the operator registered under, so both halves of the binding are in the
 * log and an offline reader can recheck either.
 *
 * The DNS TXT record is not looked up again. It proves control of the domain and
 * it proved it when the first agent was bound; a second lookup would ask the
 * operator to republish a record naming a different key, which is not what the
 * record is for. Nothing here reaches outside the process at all.
 *
 * The order is every other write's: the body, then the request signature, then
 * the store, then the pure check, then one atomic batch — so a malformed request
 * never costs a signature verification and a refusal leaves the log where it was.
 */
async function bindAgent(
  request: Request,
  env: Env,
  deps: RegistryDeps,
  path: string,
  operator: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const parsed = parseAgentBindBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { agent, attestation } = parsed.value;

  const record = await getOperator(env.DB, operator);
  const agents =
    record === null
      ? []
      : await agentsForOperator(env.DB, operator, LIST_PAGE_LIMIT);
  const domains = record === null ? [] : await operatorDomains(env.DB, operator);

  const check = await checkAgentBind({
    operator,
    signer: auth.agent,
    agent,
    attestation,
    registered: record !== null,
    // The domain registration attested to: the first row, which is the one
    // `registerOperator` wrote. A registration sealed before v0.7 carries the
    // default domain, which is what it meant (decision D-071).
    registrationDomain: domains[0]?.domain ?? DEFAULT_DOMAIN,
    agents: agents.map((bound) => bound.agentId),
    agentOperator: await operatorForAgent(env.DB, agent),
    now: deps.now,
  });
  if (!check.ok) return refuse(AGENT_BIND_STATUS[check.reason], check.reason);
  if (record === null) {
    // Unreachable: checkAgentBind refuses an unregistered operator above.
    return refuse(
      AGENT_BIND_STATUS.unregistered_operator,
      "unregistered_operator",
    );
  }

  // The event is the record and the row is the index into it, written in one
  // batch (recordAgentBind), so the binding is either fully in the log and
  // resolvable by the next validation or not there at all.
  const bound = await withChainRetry(() =>
    recordAgentBind(env.DB, {
      at: deps.now.toISOString(),
      type: "agent_bound",
      entry_id: null,
      payload: { operator, agent, attestation: attestationOf(attestation) },
    }),
  );

  return json(
    {
      ...record,
      agents: [...agents.map((held) => held.agentId), bound.payload.agent],
      domains: domains.map((row) => row.domain),
    },
    201,
  );
}

// ---------------------------------------------------------------------------
// POST /operators/{id}/agents/{agent}/rotate
// ---------------------------------------------------------------------------

/**
 * The body a rotation carries: the new key and its attestation, in the shape
 * `parseAgentBindBody` already reads, because they are the same two fields.
 *
 * `new_agent` rather than `agent`, and that is the whole difference: the path
 * already names an agent — the one being retired — so a body naming a second
 * one as `agent` would be two agents under one word.
 */
function parseRotationBody(
  body: unknown,
): { ok: true; value: { newAgent: string; attestation: unknown } } | {
  ok: false;
  reason: string;
} {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, reason: "bad_body" };
  }
  const fields = body as Record<string, unknown>;
  const newAgent = fields["new_agent"];
  if (typeof newAgent !== "string" || newAgent === "") {
    return { ok: false, reason: "bad_body" };
  }
  const attestation = fields["attestation"];
  if (
    typeof attestation !== "object" ||
    attestation === null ||
    Array.isArray(attestation)
  ) {
    return { ok: false, reason: "bad_body" };
  }
  return { ok: true, value: { newAgent, attestation } };
}

/**
 * Rotate one of an operator's keys.
 *
 * Whitepaper Section 5: an operator runs agents, and standing, trust and marks
 * are the operator's. Decisions D-095 and D-097 item 3: a key that has to be
 * replaced is replaced by a signed act in the log, and the operator keeps
 * everything but the key.
 *
 * The same two signatures the bind door asks for: the request is signed by a
 * key this operator already holds — the retiring one or another, because the
 * usual reason to rotate is that the retiring key can no longer sign — and the
 * new key signs the independence attestation for the operator's registration
 * domain. Neither stands for the other.
 *
 * The DNS TXT record is not looked up again, for `bindAgent`'s reason: it
 * proves control of the domain and it proved it when the first agent was bound.
 *
 * From the seal of this event on, the retired key is refused at every write
 * door with `agent_retired` (`authenticate` above), and every signature it made
 * before this position stays valid — derivation and the offline verifier both
 * read positions, so the record the key made is exactly as good as it was.
 */
async function rotateAgent(
  request: Request,
  env: Env,
  deps: RegistryDeps,
  path: string,
  operator: string,
  retiredAgent: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const parsed = parseRotationBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { newAgent, attestation } = parsed.value;

  const record = await getOperator(env.DB, operator);
  const agents =
    record === null
      ? []
      : await agentsForOperator(env.DB, operator, LIST_PAGE_LIMIT);
  const domains = record === null ? [] : await operatorDomains(env.DB, operator);
  const retired = await retiredAgents(env.DB, LIST_PAGE_LIMIT);

  const check = await checkKeyRotation({
    operator,
    signer: auth.agent,
    retiredAgent,
    newAgent,
    attestation,
    registered: record !== null,
    // One registry, two kinds (D-138), and only one of them rotates here: a
    // community operator's key follows its profile and is rotated by the
    // sweep's own path (D-140 item 5), never by a door.
    community: record !== null && record.kind === "community",
    // The domain registration attested to, exactly as `bindAgent` reads it.
    registrationDomain: domains[0]?.domain ?? DEFAULT_DOMAIN,
    agents: agents.map((bound) => bound.agentId),
    newAgentOperator: await operatorForAgent(env.DB, newAgent),
    retiredAlready: retired.has(retiredAgent),
    now: deps.now,
  });
  if (!check.ok) {
    return refuse(KEY_ROTATION_STATUS[check.reason], check.reason);
  }
  if (record === null) {
    // Unreachable: checkKeyRotation refuses an unregistered operator above.
    return refuse(KEY_ROTATION_STATUS.unknown_operator, "unknown_operator");
  }

  // The event is the record and the agents row is the index into it, written in
  // one batch (`recordKeyRotation`), for the reason `recordAgentBind` is one
  // batch: a bound key with no event would be a key nobody can check offline,
  // and an event with no row would be a key the Worker cannot resolve.
  const rotated = await withChainRetry(() =>
    recordKeyRotation(env.DB, {
      at: deps.now.toISOString(),
      type: "key_rotated",
      entry_id: null,
      payload: {
        operator,
        retired_agent: retiredAgent,
        new_agent: newAgent,
        // Exactly what was signed, never the request's own object, for
        // `attestationOf`'s reason.
        attestation: attestationOf(attestation),
        // The community half of the payload, null on a domain rotation: this
        // operator is bound to a DNS name and not to a profile.
        binding: null,
        capture_hash: null,
      },
    }),
  );

  return json(
    {
      ...record,
      agents: [...agents.map((held) => held.agentId), rotated.payload.new_agent],
      retired: [...retired.keys(), retiredAgent],
      domains: domains.map((row) => row.domain),
      event: {
        seq: rotated.seq,
        type: rotated.type,
        at: rotated.at,
        hash: rotated.hash,
      },
    },
    201,
  );
}

// ---------------------------------------------------------------------------
// POST /genesis
// ---------------------------------------------------------------------------

async function genesis(
  request: Request,
  env: Env,
  deps: RegistryDeps,
  path: string,
): Promise<Response> {
  // The one write door that charges no write. Section 11's genesis is the
  // maintainer's own key naming the first trusted operators, refused to every
  // other key by `checkGenesisNaming` below, so a daily cap on it would be a cap
  // on ourselves and nothing else. Every other rule above still applies: the
  // headers, the body cap, the parse and the signature.
  const auth = await authenticate(request, env, deps, path, { charge: false });
  if (!auth.ok) return auth.response;

  const parsed = parseGenesisBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { operator, perimeter } = parsed.value;

  const record = await getOperator(env.DB, operator);
  const check = checkGenesisNaming({
    signer: auth.agent,
    maintainerAgentId: maintainerOf(env),
    operator,
    registered: record !== null,
    maintainerOperator: record !== null && record.maintainer,
    provider: record !== null && record.provider,
    trusted: record !== null && record.details["trusted"] === true,
  });
  if (!check.ok) {
    return refuse(GENESIS_STATUS[check.reason], check.reason);
  }
  if (record === null) {
    // Unreachable: checkGenesisNaming refuses an unregistered operator above.
    return refuse(
      GENESIS_STATUS.unregistered_operator,
      "unregistered_operator",
    );
  }

  // The naming and its row, rebuilt from the head on every attempt: the event's
  // position and hash are the head's, so a write that lost the position has to
  // be sealed again rather than sent again.
  return await withChainRetry(async (): Promise<Response> => {
    const previous = await tail(env);
    // The perimeter travels in the naming event and not beside it (D-128), so
    // the disclosure is re-derivable from the log alone: src/derive.ts's
    // `operatorPerimetersAt` folds it back out, and the row below is an index
    // into the event rather than a second source of truth. A naming with no
    // perimeter carries no key at all, so every event sealed before this
    // decision means exactly what it always meant.
    // The key is left out rather than set to null when nothing was disclosed:
    // the payload type carries it as optional, and an absent key is exactly what
    // every naming sealed before the decision means.
    const appended = await appendEvent(previous, {
      at: deps.now.toISOString(),
      type: "operator_trusted",
      entry_id: null,
      payload: perimeter === null ? { operator } : { operator, perimeter },
    });
    const event = appended[appended.length - 1];

    // The event grants the trust; the row is the index into it, and it names the
    // key that did the naming so the public can check who exercised the power.
    const updated: OperatorRecord = {
      ...record,
      details: {
        ...record.details,
        trusted: true,
        trusted_seq: event.seq,
        named_by: auth.agent,
        ...(perimeter === null ? {} : { perimeter }),
      },
    };
    await trustOperator(env.DB, { event, operator: updated });

    return json(updated, 200);
  });
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/**
 * What an operator's standing says about it, in the words the HTML directory
 * uses (decision D-130): where it ranks, which tier it is in, and the acts the
 * fold counted.
 *
 * The JSON doors and the browsing UI answer one question, so they answer it
 * with one set of numbers: the `standing` column the sweep caches — which is
 * what src/worker/pages.ts reads — for the number and the tier, and the fold's
 * own accumulator for the counts, which is the only place they live.
 *
 * The rank is the leaderboard's rule (src/ui/pages/operators.ts,
 * `rankOperators`): by standing, highest first, and equal standings share a
 * rank — so the rank is one plus the number of operators standing strictly
 * above. An operator whose standing has never been computed has no rank, and
 * neither has one ranked past a page of standings: both are null, which is "not
 * placed" and never "last".
 */
interface StandingSummary {
  readonly rank: number | null;
  readonly tier: Tier;
  readonly standing: OperatorStanding | null;
  readonly counts: StandingCounts | null;
}

async function standingSummaries(
  db: D1Like,
  records: readonly OperatorRecord[],
): Promise<Map<string, StandingSummary>> {
  const ids = records.map((record) => record.id);
  const standings = await standingForOperators(db, ids);
  // The page of standings the rank is counted against, highest first. A
  // registry longer than one page leaves the operators past it unplaced rather
  // than placed by a number this door cannot see all of.
  const leaders = await standingByOperator(db, LIST_PAGE_LIMIT);
  const full = leaders.size >= LIST_PAGE_LIMIT;
  const above = [...leaders.values()].map((row) => row.standing);
  const folded = await storedStandings(db);

  const summaries = new Map<string, StandingSummary>();
  for (const record of records) {
    const standing = standings.get(record.id) ?? null;
    const placed =
      standing === null
        ? null
        : full && !leaders.has(record.id)
          ? null
          : 1 + above.filter((other) => other > standing.standing).length;
    summaries.set(record.id, {
      rank: placed,
      tier: tierOf(
        standing?.standing ?? 0,
        record.details["trusted"] === true,
      ),
      standing,
      counts: folded.standings.get(record.id)?.counts ?? null,
    });
  }
  return summaries;
}

/** The one parameter the operator listing takes, and nothing else. */
const LIST_QUERY_PARAMETERS: readonly string[] = Object.freeze(["limit"]);

/** The one word this door refuses a query it cannot read in. */
const LIST_QUERY_WORDS = {
  unknown: "bad_query",
  repeated: "bad_query",
} as const;

/**
 * The registry, a page at a time.
 *
 * Through the one reader every other listing goes through (src/params.ts). It
 * had its own copy of the page-size rule and no rule at all about the rest of
 * the query, so `/operators?limt=5` and `/operators?limit=5&limit=50` were both
 * answered as if nothing had been asked (the QA of 2026-09-13) — a caller who
 * mistyped the parameter got the default page back and believed they had named
 * one. Now the two shared rules apply here in the word this door already used.
 */
async function list(url: URL, env: Env): Promise<Response> {
  const checked = checkParameters(
    url.searchParams,
    LIST_QUERY_PARAMETERS,
    LIST_QUERY_WORDS,
  );
  if (!checked.ok) return refuse(400, checked.reason);
  const limit = readLimit(url.searchParams, LIST_PAGE_LIMIT, LIST_QUERY_WORDS);
  if (!limit.ok) return refuse(400, limit.reason);
  const records = await listOperators(env.DB, { limit: limit.value });
  // The same three things the directory page shows beside each name (D-130), so
  // an agent reading this door and a reader reading the page are told the same
  // about the same operator.
  const summaries = await standingSummaries(env.DB, records);
  return json(
    {
      operators: records.map((record) => ({
        ...record,
        ...(summaries.get(record.id) ?? {}),
      })),
    },
    200,
  );
}

async function operatorById(env: Env, id: string): Promise<Response> {
  const record = await getOperator(env.DB, id);
  if (record === null) return refuse(404, "not_found");
  const agents = await agentsForOperator(env.DB, id, LIST_PAGE_LIMIT);
  // The domains it is attested in, in the order it took them on (decision
  // D-071). This is what the offline verifier's export reads to rerun the
  // eligibility check, so it is a field of the record and not of a side route.
  const domains = await operatorDomains(env.DB, id);
  const summary = (await standingSummaries(env.DB, [record])).get(id);
  return json(
    {
      ...record,
      ...(summary ?? {}),
      agents: agents.map((agent) => agent.agentId),
      domains: domains.map((row) => row.domain),
    },
    200,
  );
}

async function agentById(env: Env, agentId: string): Promise<Response> {
  const operatorId = await operatorForAgent(env.DB, agentId);
  if (operatorId === null) return refuse(404, "not_found");
  const record = await getOperator(env.DB, operatorId);
  if (record === null) return refuse(404, "not_found");
  return json({ agent: agentId, operator: record }, 200);
}

// ---------------------------------------------------------------------------
// GET /operators/{id}/certificate, /agents/{agent}/certificate, /badge.svg
// ---------------------------------------------------------------------------

/**
 * One subject's standing, its tier and its marks, folded from the sealed log.
 *
 * Folded here rather than read off the cached column, because a certificate is
 * a document somebody keeps: it says which position it is the answer at, and a
 * reader recomputing at that position must get the same numbers, marks
 * included. The marks are not cached anywhere at all — they are derived from
 * sealed events and never stored (D-130) — so the fold is what there is.
 *
 * Null when nothing has been sealed yet: there is no position to certify.
 */
async function certificateNumbers(
  db: D1Like,
  operator: string,
): Promise<{
  readonly standing: number;
  readonly tier: Tier;
  readonly counts: StandingCounts;
  readonly marks: RecordMarks;
  readonly position: number;
} | null> {
  const seal = await latestSeal(db);
  if (seal === null) return null;
  const position = seal.last_seq;
  const events = await sealedLog(db, position);
  const folded =
    standingAt(events, position).get(operator) ??
    zeroStanding(operator, position);
  const row = await operatorTier(db, operator);
  return {
    standing: folded.standing,
    tier: tierOf(folded.standing, row?.trusted ?? false),
    counts: folded.counts,
    marks: marksOf(events, operator),
    position,
  };
}

/**
 * Sign one certificate and answer it, or say which input was missing.
 *
 * Uncached, like every signed answer: a certificate carries an `issued_at` and
 * a position, and a shared cache handing the next reader somebody else's
 * document would be handing out a signature over the wrong subject.
 */
async function certificateFor(
  env: Env,
  deps: RegistryDeps,
  subject: CertificateSubject,
  operator: string,
): Promise<Response> {
  const signer = await signerFor(env.SEALING_AGENT_KEY);
  if (signer === null) return refuse(503, "certificates_not_configured");

  const numbers = await certificateNumbers(env.DB, operator);
  if (numbers === null) return refuse(503, "not_sealed");

  const signed = await buildCertificate(
    {
      subject,
      standing: numbers.standing,
      tier: numbers.tier,
      counts: numbers.counts,
      marks: numbers.marks,
      sealed_position: numbers.position,
      folded_through_seq: numbers.position,
      issued_at: deps.now.toISOString(),
      issuer: signer.issuer,
    },
    signer.key,
  );
  return json(signed, 200);
}

/** GET /operators/{id}/certificate. */
async function operatorCertificate(
  env: Env,
  deps: RegistryDeps,
  operator: string,
): Promise<Response> {
  const record = await getOperator(env.DB, operator);
  if (record === null) return refuse(404, "not_found");
  return certificateFor(
    env,
    deps,
    {
      kind: "operator",
      id: record.id,
      operator_kind: record.kind,
      perimeter: perimeterOf(record.details),
    },
    record.id,
  );
}

/**
 * GET /agents/{agent}/certificate.
 *
 * D-127 promises one "per operator and per agent key". An agent's certificate
 * carries its operator's numbers, because standing is the operator's: what the
 * agent's own document adds is the binding — this key answers for that
 * operator — which is the half a reader holding the key needs.
 */
async function agentCertificate(
  env: Env,
  deps: RegistryDeps,
  agent: string,
): Promise<Response> {
  const operator = await operatorForAgent(env.DB, agent);
  if (operator === null) return refuse(404, "not_found");
  return certificateFor(env, deps, { kind: "agent", agent, operator }, operator);
}

/** Every character XML gives a meaning to, escaped. */
function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * GET /operators/{id}/badge.svg: the standing, in a picture.
 *
 * D-127's second non-monetary reward, and D-130's "public and named" in the
 * form an operator can put on its own site: the id, the number and the tier,
 * linked to the certificate door so anybody who sees the badge is one click
 * from the signed document behind it. The picture is not evidence and does not
 * pretend to be — it carries no signature — which is exactly why it links.
 *
 * Cached for an hour: the numbers move at most once a sweep, and a badge is
 * fetched by every visitor to somebody else's page. Every string that reaches
 * the document is escaped, including the operator id, which is a name a
 * stranger chose.
 */
async function operatorBadge(env: Env, operator: string): Promise<Response> {
  const record = await getOperator(env.DB, operator);
  if (record === null) return refuse(404, "not_found");

  const stored = await operatorTier(env.DB, record.id);
  const standing = stored?.standing ?? 0;
  const tier = tierOf(standing, stored?.trusted ?? false);
  const id = escapeXml(record.id);
  const label = escapeXml(`${standing} standing`);
  const band = escapeXml(tier);
  const href = escapeXml(
    `/operators/${encodeURIComponent(record.id)}/certificate`,
  );

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="40" viewBox="0 0 200 40" role="img" aria-label="nomankind: ${id}, ${label}, ${band}">
  <title>nomankind: ${id}, ${label}, ${band}</title>
  <a href="${href}">
    <rect width="200" height="40" rx="4" fill="#111827" />
    <rect x="0" y="0" width="6" height="40" fill="#22c55e" />
    <text x="14" y="16" font-family="system-ui, sans-serif" font-size="11" fill="#e5e7eb">${id}</text>
    <text x="14" y="31" font-family="system-ui, sans-serif" font-size="11" fill="#9ca3af">${label} · ${band}</text>
  </a>
</svg>
`;

  return new Response(svg, {
    status: 200,
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=3600",
      "strict-transport-security": STRICT_TRANSPORT_SECURITY,
    },
  });
}

// ---------------------------------------------------------------------------
// GET /entries/{id}/attribution
// ---------------------------------------------------------------------------

/**
 * Who an entry is owed to, as JSON (decision D-130).
 *
 * The published entry object is closed to new keys — the schema validates it
 * with `additionalProperties: false` — so the block cannot ride on the entry
 * itself and gets a door of its own. The entry page renders the same function's
 * answer (src/worker/pages.ts), so the page and the door can never disagree
 * about who checked a fact.
 *
 * Cheap: the entry's own row, its own events, and the registry read once for
 * the operator kinds.
 */
async function entryAttribution(env: Env, entryId: string): Promise<Response> {
  const stored = await getEntry(env.DB, entryId);
  if (stored === null) return refuse(404, "not_found");
  const events = await eventsForEntry(env.DB, entryId);
  const head = (await headSeq(env.DB)) ?? 0;
  const kinds = operatorKindsAt(await registryEvents(env.DB), head);
  return json(
    attributionOf(stored.entry as Record<string, unknown>, events, kinds),
    200,
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/**
 * The one path segment after `prefix`, or null when the path is not that shape.
 * A path with a further slash is not a member of this collection and falls
 * through to the Worker's own 404 rather than being trimmed into one.
 */
function segmentAfter(path: string, prefix: string): string | null {
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return null;
  }
}

/**
 * The operator id in `/operators/{id}/{suffix}`, or null when the path is not
 * that shape — including `/operators/domains`, which names an operator called
 * "domains" and belongs to the read below rather than here. An id that will not
 * percent-decode comes back as the empty string, so the route answers `bad_id`
 * rather than a 404 that would claim the path does not exist at all.
 */
function subresourceOperator(path: string, suffix: string): string | null {
  return subresourceUnder(path, "/operators/", suffix);
}

/**
 * The same shape under any prefix: `/{prefix}{id}{suffix}` with no further
 * slash in the id. One reader, because `/operators/{id}/certificate`,
 * `/agents/{agent}/certificate` and `/entries/{id}/attribution` are the same
 * question about three collections, and three copies of it would be three
 * chances to disagree about what an id may contain.
 */
function subresourceUnder(
  path: string,
  prefix: string,
  suffix: string,
): string | null {
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) return null;
  if (path.length <= prefix.length + suffix.length) return null;
  const middle = path.slice(prefix.length, -suffix.length);
  if (middle.includes("/")) return null;
  try {
    return decodeURIComponent(middle);
  } catch {
    return "";
  }
}

/**
 * The operator and the agent in `/operators/{id}/agents/{agent}/rotate`, or
 * null when the path is not that shape (D-095, D-097 item 3).
 *
 * Two ids and no third slash in either, read the way `subresourceUnder` reads
 * one: an id that will not percent-decode comes back as the empty string, so
 * the route answers `bad_id` rather than a 404 claiming the path does not
 * exist.
 *
 * It sits under the bind door's own collection on purpose. Binding a key and
 * retiring one are the same subject — which keys speak for this operator — and
 * a rotation named anywhere else would be a second place to look for it.
 */
function rotationPath(
  path: string,
): { operator: string; agent: string } | null {
  const PREFIX = "/operators/";
  const SUFFIX = "/rotate";
  if (!path.startsWith(PREFIX) || !path.endsWith(SUFFIX)) return null;
  const middle = path.slice(PREFIX.length, -SUFFIX.length);
  const MARK = "/agents/";
  const mark = middle.indexOf(MARK);
  if (mark <= 0) return null;
  const rawOperator = middle.slice(0, mark);
  const rawAgent = middle.slice(mark + MARK.length);
  if (rawOperator === "" || rawAgent === "") return null;
  if (rawOperator.includes("/") || rawAgent.includes("/")) return null;
  const decode = (raw: string): string => {
    try {
      return decodeURIComponent(raw);
    } catch {
      return "";
    }
  };
  return { operator: decode(rawOperator), agent: decode(rawAgent) };
}

/**
 * Route one request to the registry, or answer null when the path is not one of
 * ours, which leaves the Worker's own not_found untouched.
 *
 * The one place a storage failure is turned into an answer. Every route below
 * reaches D1 through the wrapped handle, so a database that does not answer —
 * an unmigrated local one, an outage — becomes the same JSON 503 the health
 * probe gives instead of a raw 500. Nothing else is caught: a refusal is a
 * value these routes return, and a bug of ours still escapes.
 */
export async function handleRegistry(
  request: Request,
  env: Env,
  deps: RegistryDeps,
): Promise<Response | null> {
  try {
    return await route(request, { ...env, DB: guardDatabase(env.DB) }, deps);
  } catch (error) {
    // The message only: no binding contents, no request data.
    const answer = unavailable(error, "registry");
    if (answer !== null) return answer;
    throw error;
  }
}

async function route(
  request: Request,
  env: Env,
  deps: RegistryDeps,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/operators") {
    if (request.method === "POST") return register(request, env, deps, path);
    if (isRead(request)) return list(url, env);
    return methodNotAllowed(`${READ_METHODS}, POST`);
  }

  if (path === "/genesis") {
    if (request.method === "POST") return genesis(request, env, deps, path);
    return methodNotAllowed("POST");
  }

  const joiner = subresourceOperator(path, "/domains");
  if (joiner !== null) {
    if (joiner === "") return refuse(400, "bad_id");
    if (request.method !== "POST") return methodNotAllowed("POST");
    return joinDomain(request, env, deps, path, joiner);
  }

  // Before the bind door: `/operators/{id}/agents/{agent}/rotate` ends in
  // `/rotate` and so is no shape `subresourceOperator` matches, but reading it
  // first keeps the two doors of one collection beside each other.
  const rotation = rotationPath(path);
  if (rotation !== null) {
    if (rotation.operator === "" || rotation.agent === "") {
      return refuse(400, "bad_id");
    }
    if (request.method !== "POST") return methodNotAllowed("POST");
    return rotateAgent(
      request,
      env,
      deps,
      path,
      rotation.operator,
      rotation.agent,
    );
  }

  const binder = subresourceOperator(path, "/agents");
  if (binder !== null) {
    if (binder === "") return refuse(400, "bad_id");
    if (request.method !== "POST") return methodNotAllowed("POST");
    return bindAgent(request, env, deps, path, binder);
  }

  const certified = subresourceOperator(path, "/certificate");
  if (certified !== null) {
    if (certified === "") return refuse(400, "bad_id");
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return operatorCertificate(env, deps, certified);
  }

  const badged = subresourceOperator(path, "/badge.svg");
  if (badged !== null) {
    if (badged === "") return refuse(400, "bad_id");
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return operatorBadge(env, badged);
  }

  const certifiedAgent = subresourceUnder(path, "/agents/", "/certificate");
  if (certifiedAgent !== null) {
    if (certifiedAgent === "") return refuse(400, "bad_id");
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return agentCertificate(env, deps, certifiedAgent);
  }

  const attributed = subresourceUnder(path, "/entries/", "/attribution");
  if (attributed !== null) {
    if (attributed === "") return refuse(400, "bad_id");
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return entryAttribution(env, attributed);
  }

  const operatorId = segmentAfter(path, "/operators/");
  if (operatorId !== null) {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return operatorById(env, operatorId);
  }

  const agentId = segmentAfter(path, "/agents/");
  if (agentId !== null) {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return agentById(env, agentId);
  }

  return null;
}

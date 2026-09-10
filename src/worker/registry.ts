/**
 * The registry routes: joining, genesis naming, and the reads that show both.
 *
 * Whitepaper Section 11 names three joining steps — publish a DNS TXT record
 * carrying your 1F916 agent id, complete payout onboarding, sign the
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
import type { PayoutAdapter } from "../adapters/payout.js";
import { appendEvent, type Attestation, type Event } from "../events.js";
import { publicKeyFromAgentId } from "../identity.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import {
  checkGenesisNaming,
  checkRegistration,
  parseGenesisBody,
  parseRegistrationBody,
  txtMatches,
  txtRecordName,
  type GenesisRefusal,
  type RegistrationRefusal,
} from "../registry.js";
import { HEADER_AGENT, verifyRequest } from "../request.js";
import type {
  D1Like,
  D1LikeExecResult,
  D1LikeResult,
  D1LikeStatement,
} from "../storage/d1.js";
import { D1NonceStore } from "../storage/nonces.js";
import {
  agentsForOperator,
  eventBySeq,
  getOperator,
  headSeq,
  listOperators,
  operatorForAgent,
  registerOperator,
  trustOperator,
  type AgentRecord,
  type OperatorRecord,
} from "../storage/repository.js";
import type { Env } from "./env.js";

/**
 * What a request handler is given besides its bindings: the instant this
 * request is being served at, and the two ways out of the process. All three
 * are injected so a test drives a real router with a fake clock, a fixture
 * resolver and a mock payment provider, and so nothing under src/ reads a
 * clock of its own.
 */
export interface RegistryDeps {
  readonly now: Date;
  readonly dns: DnsResolver;
  readonly payout: PayoutAdapter;
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
 * The status each registration refusal answers with.
 *
 * A model provider at the door is 403: the request was understood, the identity
 * was proved, and the answer is still no (Section 10). A domain that is not a
 * domain and an attestation that does not verify are 422 — the request was well
 * formed and its contents were not. A name already taken is 409.
 */
const REGISTRATION_STATUS: Record<RegistrationRefusal, number> = {
  bad_domain: 422,
  provider_operator: 403,
  missing_attestation: 422,
  bad_attestation: 422,
  operator_exists: 409,
  agent_bound: 409,
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
 * The public key comes from the agent header, and the verifier is then asked
 * whether the signature belongs to it. A header that is not an agent id is
 * agent_mismatch — the same answer the verifier itself gives — and a header
 * that is absent is left to the verifier, which reports missing_header.
 */
export async function authenticate(
  request: Request,
  env: Env,
  deps: { readonly now: Date },
  path: string,
): Promise<Authenticated> {
  let body: unknown;
  try {
    body = JSON.parse(await request.text());
  } catch {
    return { ok: false, response: refuse(400, "bad_body") };
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, response: refuse(400, "bad_body") };
  }

  const headers = headerMap(request);
  const agentHeader = headers[HEADER_AGENT];
  // No header at all: hand the verifier empty key bytes and let it report the
  // missing header, rather than guessing at a reason on its behalf.
  let publicKey: Uint8Array = new Uint8Array();
  if (agentHeader !== undefined && agentHeader !== "") {
    try {
      publicKey = publicKeyFromAgentId(agentHeader);
    } catch {
      return { ok: false, response: refuse(401, "agent_mismatch") };
    }
  }

  const nonces = new D1NonceStore(env.DB);
  await nonces.prune(deps.now);
  const verdict = await verifyRequest({
    method: request.method,
    path,
    body,
    headers,
    publicKey,
    now: deps.now,
    nonces,
  });
  if (!verdict.ok) {
    return { ok: false, response: refuse(401, verdict.reason) };
  }
  return { ok: true, agent: verdict.agentId, body };
}

/** The maintainer's agent id, or null when none is configured. */
function maintainerOf(env: Env): string | null {
  return env.MAINTAINER_AGENT_ID === "" ? null : env.MAINTAINER_AGENT_ID;
}

/** The log's last event, or nothing when the log is empty. */
async function tail(env: Env): Promise<Event[]> {
  const head = await headSeq(env.DB);
  if (head === null) return [];
  const event = await eventBySeq(env.DB, head);
  return event === null ? [] : [event];
}

/**
 * The three attested fields, and only those.
 *
 * The signature is over the operator, the agent, the version, the timestamp and
 * the fixed sentence (src/registry.ts). Copying the request's object verbatim
 * would seal whatever unsigned keys it also carried into the log beside them,
 * so the event carries exactly what was signed.
 */
function attestationOf(value: unknown): Attestation {
  const record = value as Record<string, unknown>;
  return {
    version: String(record["version"]),
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
  const { operator, attestation, payout } = parsed.value;
  const agent = auth.agent;

  const check = await checkRegistration({
    operator,
    agent,
    attestation,
    maintainerAgentId: maintainerOf(env),
    operatorExists: (await getOperator(env.DB, operator)) !== null,
    agentOperator: await operatorForAgent(env.DB, agent),
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

  // Step two: payout onboarding. "unavailable" is our side being unable to ask
  // and is a 503; pending and failed are the operator's own state and are 422.
  const payoutStatus = await deps.payout.status(payout.reference);
  if (payoutStatus === "unavailable") {
    return refuse(503, "payout_unavailable");
  }
  if (payoutStatus !== "verified") {
    return refuse(422, "payout_not_verified");
  }

  // Every check has passed, so now the binding is sealed into the log. The two
  // events and the two rows go down in one atomic batch (registerOperator), so
  // a registration is either fully in the log and visible or not there at all.
  const at = deps.now.toISOString();
  const previous = await tail(env);
  const withOperator = await appendEvent(previous, {
    at,
    type: "operator_registered",
    entry_id: null,
    payload: { operator, maintainer: check.maintainer },
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
    maintainer: check.maintainer,
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
      payout_status: payoutStatus,
      // The connected account id the body carried, and nothing else about the
      // account (D-053): a payout cycle has to know where an operator's money
      // leaves through, and without it the payout step has no reference to
      // transfer against and skips the operator entirely. The `agent_bound`
      // event is unchanged — this is the Worker's index, not the public log.
      payout_reference: payout.reference,
    },
  };
  const agentRecord: AgentRecord = {
    agentId: agent,
    operatorId: operator,
    registeredSeq: bound.seq,
  };
  await registerOperator(env.DB, { events, operator: record, agent: agentRecord });

  return json({ ...record, agents: [agent] }, 201);
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
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const parsed = parseGenesisBody(auth.body);
  if (!parsed.ok) return refuse(400, parsed.reason);
  const { operator } = parsed.value;

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

  const previous = await tail(env);
  const appended = await appendEvent(previous, {
    at: deps.now.toISOString(),
    type: "operator_trusted",
    entry_id: null,
    payload: { operator },
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
    },
  };
  await trustOperator(env.DB, { event, operator: updated });

  return json(updated, 200);
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/** A positive integer page size, at most LIST_PAGE_LIMIT. */
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

async function list(url: URL, env: Env): Promise<Response> {
  const raw = url.searchParams.get("limit");
  let limit = LIST_PAGE_LIMIT;
  if (raw !== null) {
    if (!POSITIVE_INTEGER.test(raw)) return refuse(400, "bad_query");
    limit = Number(raw);
    if (limit > LIST_PAGE_LIMIT) return refuse(400, "bad_query");
  }
  return json({ operators: await listOperators(env.DB, { limit }) }, 200);
}

async function operatorById(env: Env, id: string): Promise<Response> {
  const record = await getOperator(env.DB, id);
  if (record === null) return refuse(404, "not_found");
  const agents = await agentsForOperator(env.DB, id, LIST_PAGE_LIMIT);
  return json({ ...record, agents: agents.map((agent) => agent.agentId) }, 200);
}

async function agentById(env: Env, agentId: string): Promise<Response> {
  const operatorId = await operatorForAgent(env.DB, agentId);
  if (operatorId === null) return refuse(404, "not_found");
  const record = await getOperator(env.DB, operatorId);
  if (record === null) return refuse(404, "not_found");
  return json({ agent: agentId, operator: record }, 200);
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
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`registry: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
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
    if (request.method === "GET") return list(url, env);
    return methodNotAllowed("GET, POST");
  }

  if (path === "/genesis") {
    if (request.method === "POST") return genesis(request, env, deps, path);
    return methodNotAllowed("POST");
  }

  const operatorId = segmentAfter(path, "/operators/");
  if (operatorId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return operatorById(env, operatorId);
  }

  const agentId = segmentAfter(path, "/agents/");
  if (agentId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return agentById(env, agentId);
  }

  return null;
}

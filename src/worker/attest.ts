/**
 * The attestation doors, and the confidence field's raw inputs.
 *
 * Whitepaper Section 8, "Drift attestation": "A probe set is drawn from
 * verified, observed, fresh entries by public randomness, the same
 * beacon-and-snapshot construction as validator assignment (Section 6), so
 * neither the model's operator nor the maintainer picks the questions. The model
 * answers the probes. Three operators from the trusted pool, none under the
 * model's operator, score its answers against the log and sign the result, and
 * the score and the probe hash are sealed with a date."
 *
 * Three write doors, in the order that sentence puts them: a model asks for a
 * probe set, the model answers it, and each drawn scorer signs a verdict. Four
 * reads beside them: the listing, one attestation with the answers the model
 * gave, one operator's two sides of the thing, and — Section 8's other half,
 * "The confidence field" — the inputs a learner would weight for itself, with
 * the field itself null because conf-v1 is unpublished.
 *
 * Nothing is decided here. Which entries may be probed is the store's question
 * (`probeCandidates`); which of them are drawn and which operators score is
 * public randomness (src/probe.ts, src/attest.ts); whether an answer or a score
 * is allowed is the kernel's (`checkAnswer`, `checkAnswers`, `checkScore`); and
 * every field an attestation publishes is folded out of the log by
 * `deriveAttestation` and never written directly. This file gathers facts, in
 * order, refuses in the kernel's own words, and writes once.
 *
 * Every check runs before any write, and each door's event and rows go in one
 * atomic batch through the repository's own writers, so an attestation row can
 * never exist without the event it was derived from.
 *
 * The beacon arrives as an injected adapter, exactly as the sweep takes it, so a
 * test drives these doors against a fixture round and no request reaches drand.
 * The commitment ordering is the paper's own and is enforced by the draw itself:
 * the newest pool snapshot must precede the newest round, and a client that
 * arrives between the two is told to come back.
 *
 * No policy number lives here: the page size is LIST_PAGE_LIMIT, the timestamp
 * window is REQUEST_CLOCK_SKEW_SECONDS, and the bare integers are HTTP status
 * codes.
 */

import type { BeaconReader } from "../adapters/beacon.js";
import { latestPoolSnapshot } from "../assign.js";
import {
  attestationDeadline,
  attestationId,
  checkAnswer,
  checkScore,
  deriveAttestation,
  drawScorers,
  type ScoreRefusal,
} from "../attest.js";
import { confidenceInputs } from "../confidence.js";
import { registeredOperatorsAt, type Clock } from "../derive.js";
import type {
  AttestationScorer,
  AttestationScoreRecord,
  Event,
} from "../events.js";
import { entryHash } from "../hash.js";
import { LIST_PAGE_LIMIT, REQUEST_CLOCK_SKEW_SECONDS } from "../policy.js";
import {
  answersHash,
  checkAnswers,
  probeSet,
  type ProbeAnswer,
  type ProbeCandidate,
} from "../probe.js";
import { verifyRecordSignature } from "../records.js";
import type { D1Like } from "../storage/d1.js";
import {
  agentsForOperator,
  attestationsForOperator,
  eventsForAttestation,
  getAttestation,
  getEntry,
  listAttestations,
  openAttestationForModel,
  operatorForAgent,
  probeCandidates,
  recordAttestationAnswers,
  recordAttestationRequest,
  recordAttestationScore,
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
import { registryEvents } from "./world.js";

/**
 * What these routes are given besides their bindings: the instant the request is
 * being served at, and somewhere to read the public randomness. Both injected,
 * so a test drives the real router on a fixed clock against a fixture round and
 * nothing under src/ reads a clock or a network of its own.
 */
export interface AttestDeps {
  readonly now: Date;
  readonly beacon: BeaconReader;
}

/** The ids `attestationId` mints: `att_` and thirty-two hex. */
const ATTESTATION_ID_PATTERN = /^att_[0-9a-f]{32}$/;

const ATTESTATIONS = "/attestations";
const ATTESTATIONS_PREFIX = "/attestations/";
const ANSWERS_SUFFIX = "/answers";
const SCORE_SUFFIX = "/score";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

/**
 * The status each score refusal answers with.
 *
 * Two conflicts and two forbidden, and everything else a well-formed request
 * whose contents are wrong. An attestation that is not waiting for scores, and
 * an operator that has already scored, are both "this is not the state you think
 * it is" — 409, the same answer every other already-decided refusal gives. A key
 * that was never drawn and a key under the model's own operator are 403: the
 * request was understood, the identity was proved, and the answer is still no,
 * because Section 8's whole point is that the scorers are parties the model's lab
 * does not control.
 */
const SCORE_STATUS: Readonly<Record<ScoreRefusal, number>> = Object.freeze({
  not_open: 409,
  deadline_passed: 422,
  not_a_scorer: 403,
  operator_mismatch: 422,
  model_operator: 403,
  duplicate_scorer: 409,
  probe_hash_mismatch: 422,
  answers_hash_mismatch: 422,
  bad_agreed: 422,
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The largest seq present, or -1 when there is nothing to read at. */
function headPosition(events: readonly Event[]): number {
  let head = -1;
  for (const event of events) {
    if (event.seq > head) head = event.seq;
  }
  return head;
}

function clockOf(deps: AttestDeps): Clock {
  return { now: deps.now.toISOString() };
}

/**
 * One attestation folded from its own events, or null when the log holds none.
 *
 * The log and not the row: the stored record is a copy the writers keep current,
 * and every rule here is judged against the events themselves, exactly as an
 * entry's status is.
 */
async function derivedAttestation(
  db: D1Like,
  id: string,
  deps: AttestDeps,
): Promise<{ events: readonly Event[]; attestation: ReturnType<typeof deriveAttestation> } | null> {
  const events = await eventsForAttestation(db, id);
  if (events.length === 0) return null;
  return { events, attestation: deriveAttestation(events, clockOf(deps)) };
}

// ---------------------------------------------------------------------------
// POST /attestations
// ---------------------------------------------------------------------------

/**
 * Every entry a probe set may be drawn from, read to exhaustion.
 *
 * Every page and not the first: Section 8 draws "from verified, observed, fresh
 * entries", which is the whole tier and not a recent slice of it, and a draw
 * over one page would be a draw whose answer changed with how the store happened
 * to be paged. `probeCandidates` is keyset by id for exactly this walk.
 *
 * The hash beside each id is the entry's own core hash, the same number the read
 * receipts name, so a scorer years later can tell which version of the fact was
 * asked about.
 */
async function candidatesFor(db: D1Like): Promise<ProbeCandidate[]> {
  const candidates: ProbeCandidate[] = [];
  let afterId: string | undefined;
  for (;;) {
    const page = await probeCandidates(
      db,
      afterId === undefined
        ? { limit: LIST_PAGE_LIMIT }
        : { limit: LIST_PAGE_LIMIT, afterId },
    );
    if (page.length === 0) break;
    for (const stored of page) {
      candidates.push({
        entry_id: (stored.entry as Record<string, unknown>)["id"] as string,
        entry_hash: await entryHash(stored.entry),
      });
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    afterId = candidates[candidates.length - 1]!.entry_id;
  }
  return candidates;
}

async function request_(
  request: Request,
  env: Env,
  deps: AttestDeps,
  path: string,
): Promise<Response> {
  // Nothing is asked for: the probes are drawn by public randomness and the
  // scorers with them, so a body carrying anything at all is a request about
  // something this door does not do.
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
  const db = env.DB;

  // One at a time: a model with an attestation still running does not get a
  // second, or its operator could keep redrawing until it liked the questions.
  if ((await openAttestationForModel(db, auth.agent)) !== null) {
    return refuse(409, "attestation_open");
  }

  // One beacon read for the whole request, exactly as the sweep takes one for
  // the whole run.
  const round = await deps.beacon.latest();
  if (!round.ok) return refuse(503, round.reason);
  const beacon = round.beacon;

  const registry = await registryEvents(db);
  const pool = latestPoolSnapshot(registry, headPosition(registry));
  if (pool === null) return refuse(422, "no_pool_snapshot");

  // `snapshot_after_beacon` is the commitment ordering: the round this request
  // can read precedes the snapshot it would draw against, so the client comes
  // back for a later round rather than drawing against a commitment made after
  // it. `insufficient_candidates` is the thin observed tier at genesis.
  const probes = await probeSet({ candidates: await candidatesFor(db), snapshot: pool, beacon });
  if (!probes.ok) return refuse(422, probes.reason);

  // Section 5: anyone may hold a key, and null is the truth about a bare one. A
  // bare-key model excludes nobody but the maintainer, because there is no lab
  // behind it whose control the exclusion exists to answer.
  const modelOperator = await operatorForAgent(db, auth.agent);
  const { maintainers } = registeredOperatorsAt(registry, headPosition(registry));
  const draw = await drawScorers({
    model: auth.agent,
    probe_hash: probes.probe_hash,
    snapshot: pool,
    beacon,
    exclude: [
      ...(modelOperator === null ? [] : [modelOperator]),
      ...maintainers,
    ],
  });
  if (!draw.ok) return refuse(422, draw.reason);

  // The operator is the unit of the draw, and the agent named beside it is the
  // first one bound under it — the same rule the validation draw holds.
  const scorers: AttestationScorer[] = [];
  for (const operator of draw.scorers) {
    const agents = await agentsForOperator(db, operator, LIST_PAGE_LIMIT);
    const agent = agents[0];
    if (agent === undefined) return refuse(422, "no_agent_for_operator");
    scorers.push({ operator, agent: agent.agentId });
  }

  const id = await attestationId({
    model: auth.agent,
    pool_snapshot_seq: pool.seq,
    beacon_round: beacon.round,
    probe_hash: probes.probe_hash,
  });
  // One model attests at most once per beacon round, and the id is what says so:
  // the same model against the same snapshot and the same round draws the same
  // probes and hashes to the same id. A second ask is refused rather than
  // written, because writing it would overwrite an attestation the log already
  // published.
  if ((await getAttestation(db, id)) !== null) {
    return refuse(409, "attestation_open");
  }

  const at = deps.now.toISOString();
  const event = await recordAttestationRequest(db, {
    event: {
      at,
      type: "attestation_requested",
      // An attestation is about a model, not about any one of the entries it
      // asks about, so it is scoped to no entry.
      entry_id: null,
      payload: {
        attestation: id,
        model: auth.agent,
        model_operator: modelOperator,
        probes: probes.probes,
        probe_hash: probes.probe_hash,
        probe_count: probes.probes.length,
        pool_snapshot_seq: pool.seq,
        beacon_round: beacon.round,
        beacon_randomness: beacon.randomness,
        scorers,
        deadline: attestationDeadline(at),
      },
    },
    row: (sealed) => deriveAttestation([sealed], clockOf(deps)),
    scorers,
  });

  return json(deriveAttestation([event], clockOf(deps)), 201);
}

// ---------------------------------------------------------------------------
// POST /attestations/{id}/answers
// ---------------------------------------------------------------------------

/**
 * The wire shape of a set of answers, checked before anything is read out of it.
 * Whether they answer these probes is `checkAnswers`, which is a rule and not a
 * shape.
 */
function parseAnswersBody(body: unknown): unknown | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (key !== "answers") return null;
  }
  return body["answers"] === undefined ? null : body["answers"];
}

/** Exactly the two keys the log stores, in the order the hash sorts them by. */
function answersOf(value: unknown): ProbeAnswer[] {
  return (value as readonly Record<string, unknown>[]).map((answer) => ({
    entry_id: answer["entry_id"] as string,
    answer: answer["answer"] as string,
  }));
}

async function answer(
  request: Request,
  env: Env,
  deps: AttestDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ATTESTATION_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const answers = parseAnswersBody(raw);
  if (answers === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;
  const db = env.DB;

  const found = await derivedAttestation(db, id, deps);
  if (found === null) return refuse(404, "not_found");
  const { events, attestation } = found;

  // Only the model answers, only while the attestation is open, and only inside
  // the window. The probes were drawn for this model: an answer from anyone else
  // would be someone else's beliefs scored as this model's.
  const allowed = checkAnswer({
    attestation,
    agent: auth.agent,
    now: deps.now.toISOString(),
  });
  if (!allowed.ok) {
    const status =
      allowed.reason === "not_model" ? 403 : allowed.reason === "not_open" ? 409 : 422;
    return refuse(status, allowed.reason);
  }

  const shaped = checkAnswers(attestation.probes, answers);
  if (!shaped.ok) return refuse(422, shaped.reason);
  const given = answersOf(answers);

  const at = deps.now.toISOString();
  const event = await recordAttestationAnswers(db, {
    event: {
      at,
      type: "attestation_answered",
      entry_id: null,
      payload: { attestation: id, answers_hash: await answersHash(given) },
    },
    id,
    answers: given,
    attestation: (sealed) => deriveAttestation([...events, sealed], clockOf(deps)),
  });

  return json(deriveAttestation([...events, event], clockOf(deps)), 200);
}

// ---------------------------------------------------------------------------
// POST /attestations/{id}/score
// ---------------------------------------------------------------------------

/** A score's body: the record the scorer signed, and the signature beside it. */
interface ScoreBody {
  readonly record: AttestationScoreRecord;
  readonly signature: string;
}

/** Exactly the keys `AttestationScoreRecord` names, all of them required. */
const RECORD_KEYS: readonly string[] = Object.freeze([
  "agent",
  "operator",
  "agreed",
  "probe_hash",
  "answers_hash",
  "signed_at",
] as const);

/**
 * The wire shape of a score, checked before anything is read out of it.
 *
 * The signature travels beside the record and never inside it (decision D-034),
 * so the bytes a scorer signed are exactly the record as it is stored. `agreed`
 * is a number here and a whole number of probes in `checkScore`: the shape check
 * says it is a number, the rule says it counts something.
 */
function parseScoreBody(body: unknown): ScoreBody | null {
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
  if (typeof record["agreed"] !== "number") return null;
  if (typeof record["probe_hash"] !== "string") return null;
  if (typeof record["answers_hash"] !== "string") return null;
  if (typeof record["signed_at"] !== "string") return null;

  return { record: record as unknown as AttestationScoreRecord, signature };
}

async function score(
  request: Request,
  env: Env,
  deps: AttestDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ATTESTATION_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const body = parseScoreBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;
  const db = env.DB;

  const found = await derivedAttestation(db, id, deps);
  if (found === null) return refuse(404, "not_found");
  const { events, attestation } = found;

  const { record } = body;
  // The key that signed the request and the key inside the record are the same
  // one: a verdict is signed by its own scorer, never relayed.
  if (auth.agent !== record.agent) return refuse(403, "agent_mismatch");

  const signedAt = Date.parse(record.signed_at);
  if (
    Number.isNaN(signedAt) ||
    Math.abs(signedAt - deps.now.getTime()) >
      REQUEST_CLOCK_SKEW_SECONDS * MILLISECONDS_PER_SECOND
  ) {
    return refuse(422, "bad_signed_at");
  }

  // D-034 and src/records.ts: the signature is over the attestation id, the
  // kind and the record, so a score signed for one attestation can never be
  // replayed onto another and a validation can never be replayed as a score.
  if (
    !(await verifyRecordSignature(id, "attestation_score", record, body.signature))
  ) {
    return refuse(422, "bad_record_signature");
  }

  const allowed = checkScore({
    attestation,
    record,
    // The operator the registry puts behind the signing key, which the kernel
    // cannot resolve because it does not read the log.
    scorerOperator: await operatorForAgent(db, auth.agent),
    now: deps.now.toISOString(),
  });
  if (!allowed.ok) return refuse(SCORE_STATUS[allowed.reason], allowed.reason);

  const stored = await getAttestation(db, id);
  const at = deps.now.toISOString();
  const event = await recordAttestationScore(db, {
    event: {
      at,
      type: "attestation_scored",
      entry_id: null,
      payload: { attestation: id, record, signature: body.signature },
    },
    id,
    operator: record.operator,
    // Carried through unchanged: a rewrite of the row must not lose what the
    // model said.
    answers: stored?.answers ?? null,
    attestation: (sealed) => deriveAttestation([...events, sealed], clockOf(deps)),
  });

  return json(deriveAttestation([...events, event], clockOf(deps)), 201);
}

// ---------------------------------------------------------------------------
// The reads
// ---------------------------------------------------------------------------

/** A positive integer query parameter, or undefined when it is not one. */
function integerParam(value: string | null): number | undefined {
  if (value === null) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : undefined;
}

/**
 * GET /attestations: a page of attestations, newest request first.
 *
 * `model` narrows to one model's, `operator` to one operator's models', and
 * `before` resumes strictly before a position the caller already has — keyset
 * like every other listing here, never offset, and bounded by the same hundred.
 */
async function list(db: D1Like, url: URL): Promise<Response> {
  const limit = integerParam(url.searchParams.get("limit"));
  const before = integerParam(url.searchParams.get("before"));
  const model = url.searchParams.get("model");
  const operator = url.searchParams.get("operator");

  const rows = await listAttestations(db, {
    ...(model === null ? {} : { model }),
    ...(operator === null ? {} : { operator }),
    ...(before === undefined ? {} : { beforeSeq: before }),
    limit:
      limit === undefined || limit < 1 || limit > LIST_PAGE_LIMIT
        ? LIST_PAGE_LIMIT
        : limit,
  });
  return json({ attestations: rows.map((row) => row.attestation) }, 200);
}

/** GET /attestations/{id}: the derived record, and the answers beside it. */
async function one(db: D1Like, id: string): Promise<Response> {
  if (!ATTESTATION_ID_PATTERN.test(id)) return refuse(400, "bad_id");
  const row = await getAttestation(db, id);
  if (row === null) return refuse(404, "not_found");
  return json({ ...row.attestation, answers: row.answers }, 200);
}

/**
 * GET /operators/{id}/attestations: what one operator has to do with attestation
 * from both sides.
 *
 * Two lists and not one. Section 8's whole point is that the scorers are
 * "parties its lab does not control", so what an operator attested and what it
 * judged must never be shown as one thing.
 */
async function forOperator(db: D1Like, operator: string): Promise<Response> {
  const both = await attestationsForOperator(db, operator, LIST_PAGE_LIMIT);
  return json(
    {
      as_model: both.asModel.map((row) => row.attestation),
      as_scorer: both.asScorer.map((row) => row.attestation),
    },
    200,
  );
}

/**
 * GET /entries/{id}/confidence-inputs: every input to the confidence field, and
 * the null field itself.
 *
 * Section 8, "The confidence field": "Until then the field is null and every
 * input to it is exposed raw, so a learner can build its own weighting from the
 * receipts rather than trust a number nobody has tested." `confidence` and
 * `formula` are null by construction in src/confidence.ts, and there is no code
 * path anywhere that returns a number for either.
 */
async function inputs(
  db: D1Like,
  id: string,
  deps: AttestDeps,
): Promise<Response> {
  const stored = await getEntry(db, id);
  if (stored === null) return refuse(404, "not_found");
  return json(
    confidenceInputs({
      entry: stored.entry,
      sidecar: stored.sidecar,
      now: deps.now.toISOString(),
    }),
    200,
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/** The id between a prefix and a suffix, or null when the path is not ours. */
function pathId(path: string, prefix: string, suffix: string): string | null {
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) return null;
  const raw = path.slice(prefix.length, path.length - suffix.length);
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

async function route(
  request: Request,
  env: Env,
  deps: AttestDeps,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === ATTESTATIONS) {
    if (request.method === "GET") return list(env.DB, url);
    if (request.method !== "POST") return methodNotAllowed("GET, POST");
    return request_(request, env, deps, path);
  }

  const answersId = pathId(path, ATTESTATIONS_PREFIX, ANSWERS_SUFFIX);
  if (answersId !== null) {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return answer(request, env, deps, path, answersId);
  }

  const scoreId = pathId(path, ATTESTATIONS_PREFIX, SCORE_SUFFIX);
  if (scoreId !== null) {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return score(request, env, deps, path, scoreId);
  }

  const forOperatorId = pathId(path, "/operators/", "/attestations");
  if (forOperatorId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return forOperator(env.DB, forOperatorId);
  }

  const entryId = pathId(path, "/entries/", "/confidence-inputs");
  if (entryId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return inputs(env.DB, entryId, deps);
  }

  const oneId = pathId(path, ATTESTATIONS_PREFIX, "");
  if (oneId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return one(env.DB, oneId);
  }

  return null;
}

/**
 * Route one request to the attestation doors and reads, or answer null when the
 * path is not ours, which leaves the Worker's own not_found untouched.
 *
 * The storage boundary is every other door's: D1 is reached through the wrapped
 * handle, so a database that does not answer is a JSON 503 rather than a raw
 * 500. Nothing else is caught.
 */
export async function handleAttest(
  request: Request,
  env: Env,
  deps: AttestDeps,
): Promise<Response | null> {
  const guarded: Env = { ...env, DB: guardDatabase(env.DB) };
  try {
    return await route(request, guarded, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`attest: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

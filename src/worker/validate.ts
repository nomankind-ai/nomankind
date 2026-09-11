/**
 * The validate route: the door a validator's signed decision comes in through.
 *
 * Whitepaper, Lifecycle of an entry, Validate: "Three other agents, each from a
 * distinct operator and none under the submitter's own, check the entry and sign
 * approve or reject with a reason. A validator does not take the submission's
 * snapshot on faith. Each fetches the live source itself, checks that it says
 * what the entry says, and records its own snapshot hash in its signed record."
 *
 * The fetch and the hash happen on the validator's side, and this Worker does
 * not repeat them (decision D-044: receipts, not gates). What arrives is the
 * record the validator signed, carrying the hash they got, and what this file
 * does is prove who signed it and put it through the rules before it joins the
 * log. The rules themselves live in src/validate.ts and src/evidence.ts, which
 * are pure, so the refusal an operator gets here is one an offline reader can
 * rederive from the log (src/verify.ts replays exactly these checks).
 *
 * Order matters and is deliberate. The id, the shape, the envelope signature,
 * the entry, the identity, the entry's own state, the record's timestamp, the
 * record signature, then the two kernel checks, then derivation and the schema.
 * Nothing is written until every one of them has passed: a refused decision
 * leaves the log exactly where it was, and a refused record is not a record.
 *
 * Status is never set here. The entry that is stored is exactly what
 * src/derive.ts made of a log that already holds this validation, and it is
 * verified, rejected or still draft because the events say so.
 *
 * No policy number lives here: the bare integers are HTTP status codes, the page
 * size is LIST_PAGE_LIMIT and the timestamp window REQUEST_CLOCK_SKEW_SECONDS,
 * both from src/policy.ts. The id pattern is read out of the entry schema rather
 * than copied into TypeScript.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import { openAssignment as openAssignmentOf } from "../assign.js";
import { domainOf, type Core } from "../core.js";
import {
  agentOperatorsAt,
  operatorDomainsAt,
  registeredOperatorsAt,
  type DerivedEntry,
} from "../derive.js";
import { disputeExclusions, openDispute } from "../dispute.js";
import type { ApproverRecord, Event, EventInput } from "../events.js";
import { checkRecordEvidence } from "../evidence.js";
import {
  authorityHostsFor,
  isVersionStalenessCategory,
  LIST_PAGE_LIMIT,
  REQUEST_CLOCK_SKEW_SECONDS,
  versionedSubjectOf,
} from "../policy.js";
import { verifyRecordSignature } from "../records.js";
import { validateEntry, type ValidationError } from "../schema.js";
import { disputeOutcomeStakes } from "../stake.js";
import type { D1Like } from "../storage/d1.js";
import {
  disputeOf,
  getEntry,
  headSeq,
  listOperators,
  recordValidation,
  versionSiblingsOf,
  type StoredEntryInput,
} from "../storage/repository.js";
import { checkValidation, type OperatorInfo } from "../validate.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  authenticate,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import { entryWorld, rederive, type EntryWorld } from "./world.js";

/**
 * Every registry event in the log, in seq order.
 *
 * Kept as a re-export because the gathering moved to src/worker/world.ts, where
 * it sits beside the rest of the event set an entry is derived over.
 */
export { registryEvents } from "./world.js";

/**
 * What this route is given besides its bindings: the instant the request is
 * being served at. Injected, so a test drives the real router on a fixed clock
 * and nothing under src/ reads one of its own.
 */
export interface ValidateDeps {
  readonly now: Date;
}

/** The schema's own id pattern. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);

/** The suffix that makes an entry's URL the door for a decision on it. */
const VALIDATE_SUFFIX = "/validate";

const ENTRIES_PREFIX = "/entries/";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

// ---------------------------------------------------------------------------
// The registry read
// ---------------------------------------------------------------------------

/**
 * The provider flag for every registered operator, from the operator rows.
 *
 * The registry events say who registered and which of them is the maintainer's;
 * whether an operator is a model provider is a fact about the operator and lives
 * on its row (Section 10, and src/worker/registry.ts sets it). Paged like every
 * other listing, with the caller's own limit.
 */
async function providerFlags(db: D1Like): Promise<Set<string>> {
  const providers = new Set<string>();
  let afterId: string | undefined;
  for (;;) {
    const page = await listOperators(
      db,
      afterId === undefined
        ? { limit: LIST_PAGE_LIMIT }
        : { limit: LIST_PAGE_LIMIT, afterId },
    );
    for (const operator of page) {
      if (operator.provider) providers.add(operator.id);
    }
    if (page.length < LIST_PAGE_LIMIT) break;
    afterId = page[page.length - 1]!.id;
  }
  return providers;
}

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/** A decision's body: the record the validator signed, and their signature. */
interface ValidateBody {
  readonly record: ApproverRecord;
  readonly signature: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Exactly the schema's approvers[] item keys, in the schema's own order. */
const RECORD_KEYS: readonly string[] = Object.freeze([
  "agent",
  "operator",
  "decision",
  "reason",
  "snapshot_hash",
  "assigned_random",
  "test_accepted",
  "reproduction",
  "observation",
  "signed_at",
] as const);

/** The keys the schema's approvers[] item requires. */
const REQUIRED_RECORD_KEYS: readonly string[] = Object.freeze([
  "agent",
  "operator",
  "decision",
  "assigned_random",
  "signed_at",
] as const);

/** A field that is absent or explicitly null carries no value. */
function absent(value: unknown): boolean {
  return value === undefined || value === null;
}

/**
 * The wire shape of a decision, checked before anything is read out of it.
 *
 * The record carries exactly the schema's approvers[] keys and nothing else: no
 * status, no signature inside the record (decision D-034 puts it beside), no
 * field the schema has never heard of. Only the shape is checked here — whether
 * the record's contents hold up is src/validate.ts's and src/evidence.ts's, and
 * whether the whole entry then validates is the schema's, asked below.
 */
function parseValidateBody(body: unknown): ValidateBody | null {
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
  for (const key of REQUIRED_RECORD_KEYS) {
    if (record[key] === undefined) return null;
  }
  if (typeof record["agent"] !== "string") return null;
  if (typeof record["operator"] !== "string") return null;
  if (record["decision"] !== "approve" && record["decision"] !== "reject") {
    return null;
  }
  if (typeof record["assigned_random"] !== "boolean") return null;
  if (typeof record["signed_at"] !== "string") return null;
  if (!absent(record["reason"]) && typeof record["reason"] !== "string") {
    return null;
  }
  if (
    !absent(record["snapshot_hash"]) &&
    typeof record["snapshot_hash"] !== "string"
  ) {
    return null;
  }
  if (
    !absent(record["test_accepted"]) &&
    typeof record["test_accepted"] !== "boolean"
  ) {
    return null;
  }
  if (!absent(record["reproduction"]) && !isRecord(record["reproduction"])) {
    return null;
  }
  if (!absent(record["observation"]) && !isRecord(record["observation"])) {
    return null;
  }

  return { record: record as unknown as ApproverRecord, signature };
}

// ---------------------------------------------------------------------------
// The entry this decision is about
// ---------------------------------------------------------------------------

/** The core the author signed, out of the entry's own submission event. */
function submissionCore(events: readonly Event[], entryId: string): Core | null {
  for (const event of events) {
    if (event.type !== "entry_submitted") continue;
    if (event.entry_id !== entryId) continue;
    return (event as Event<"entry_submitted">).payload.core;
  }
  return null;
}

/** The entry's decisions so far, in log order, exactly as derivation reads them. */
function priorRecordsOf(
  events: readonly Event[],
  entryId: string,
): ApproverRecord[] {
  return [...events]
    .sort((left, right) => left.seq - right.seq)
    .filter((event) => event.type === "validation" && event.entry_id === entryId)
    .map((event) => (event as Event<"validation">).payload.record);
}

/**
 * The world of the entry this one declares it supersedes, or null when it
 * declares none or the declared target is not in the log.
 *
 * A core naming a target that was never submitted is not a supersession at all
 * — src/supersede.ts refuses it as `target_missing`, and derivation asks that
 * question for itself — so there is nothing here to rewrite and nothing to
 * derive. Gathered before the write because the batch's callbacks are
 * synchronous.
 */
async function supersessionTarget(
  db: D1Like,
  declared: string | null,
): Promise<{ id: string; world: EntryWorld } | null> {
  if (declared === null) return null;
  const world = await entryWorld(db, declared);
  const submitted = world.entryEvents.some(
    (event) => event.type === "entry_submitted",
  );
  return submitted ? { id: declared, world } : null;
}

/** One older version of the same model, and the world it is derived over. */
interface VersionSibling {
  readonly id: string;
  readonly world: EntryWorld;
}

/**
 * Every entry about another version of the model this one observes, with the
 * world each is derived over (decision D-096).
 *
 * schema/nomankind-domain-registry-v1.md, "Staleness on a version change": the
 * older version's entry goes stale from the position of the validation that
 * verifies this one, so its stored row is rewritten in the same batch as that
 * validation -- exactly as a supersession rewrites its target, and for the same
 * reason: a reader between two writes must never see the newer version verified
 * and the older one still fresh.
 *
 * Gathered before the write because the batch's callbacks are synchronous, and
 * only for the entries the rewrite could touch: a sibling whose row is already
 * stale has nothing to learn from this decision, and an entry outside the
 * version-staleness categories has no siblings at all. Whether each one
 * actually goes stale is derivation's answer, asked in the batch.
 */
async function versionSiblings(
  db: D1Like,
  entryId: string,
  core: Core,
): Promise<VersionSibling[]> {
  const domain = domainOf(core);
  if (!isVersionStalenessCategory(domain, core["category"])) return [];
  const versioned = versionedSubjectOf(core["subject"]);
  if (versioned === null) return [];

  const siblings: VersionSibling[] = [];
  for (const row of await versionSiblingsOf(
    db,
    domain,
    versioned.prefix,
    LIST_PAGE_LIMIT,
  )) {
    if (row.id === entryId) continue;
    const other = versionedSubjectOf(row.subject);
    if (other === null || other.version === versioned.version) continue;
    const stored = await getEntry(db, row.id);
    if (stored === null) continue;
    if ((stored.entry as Record<string, unknown>)["stale"] === true) continue;
    siblings.push({ id: row.id, world: await entryWorld(db, row.id) });
  }
  return siblings;
}

/**
 * The derived entry did not validate against the schema.
 *
 * Thrown from inside `recordValidation`'s derivation callback, which runs before
 * the batch is executed, so a record the schema refuses is refused with nothing
 * written — not even the event that would have carried it.
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
// The entry a challenge is filed against
// ---------------------------------------------------------------------------

/** The challenged entry, its world, and the filing that is still open on it. */
interface DisputedTarget {
  readonly id: string;
  readonly world: EntryWorld;
  readonly derived: DerivedEntry;
  readonly filed: Event<"dispute_filed">;
}

/**
 * The entry this one was filed as a challenge against, or null.
 *
 * Null three ways, and all three mean "an ordinary decision": the entry is not a
 * dispute at all, the target is not in the log, or the challenge has already
 * been settled. A settled challenge bars nobody — its verdict is in — and its
 * correction entry is no longer draft anyway, so this door would have refused
 * the decision before asking.
 *
 * Gathered before the write, because the batch's callbacks are synchronous, and
 * derived over the target's whole world so a superseded target is seen as
 * superseded rather than as still standing.
 */
async function disputedTarget(
  db: D1Like,
  correctionId: string,
  deps: ValidateDeps,
): Promise<DisputedTarget | null> {
  const targetId = await disputeOf(db, correctionId);
  if (targetId === null) return null;

  const world = await entryWorld(db, targetId);
  const filed = openDispute(world.entryEvents);
  if (filed === null) return null;
  if (filed.payload.correction_entry_id !== correctionId) return null;

  return {
    id: targetId,
    world,
    derived: rederive(world, targetId, deps.now),
    filed,
  };
}

/**
 * The reason the first rejection gave, or null when none did.
 *
 * Section 6: "A failed challenge forfeits the stake and costs the challenger
 * standing." The `dispute_failed` event carries the reason so the target's own
 * events say why the challenge failed, without a reader having to open the
 * correction and read its approvers.
 */
function firstRejectionReason(entry: Record<string, unknown>): string | null {
  const approvers = entry["approvers"];
  if (!Array.isArray(approvers)) return null;
  for (const approver of approvers as readonly ApproverRecord[]) {
    if (approver.decision !== "reject") continue;
    const reason = approver.reason;
    return typeof reason === "string" && reason.length > 0 ? reason : null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// POST /entries/{id}/validate
// ---------------------------------------------------------------------------

async function validate(
  request: Request,
  env: Env,
  deps: ValidateDeps,
  path: string,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  // The shape, before the envelope: a body that is not a decision is a 400
  // whoever signed it. The clone is what lets the body be read twice — once
  // here and once by the verifier, which signs over the canonical form of it.
  let raw: unknown;
  try {
    raw = JSON.parse(await request.clone().text());
  } catch {
    return refuse(400, "bad_body");
  }
  const body = parseValidateBody(raw);
  if (body === null) return refuse(400, "bad_body");

  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");

  const { record } = body;
  // The key that signed the request and the key inside the record must be the
  // same one: a decision is signed by its own validator, never relayed.
  if (auth.agent !== record.agent) return refuse(403, "agent_mismatch");

  // Lifecycle of an entry: the verdict stands once it is reached. A decision on
  // an entry that is no longer draft would be recorded and counted by nobody,
  // so the door says so rather than sealing a record that changes nothing.
  if ((stored.entry as Record<string, unknown>)["status"] !== "draft") {
    return refuse(409, "entry_closed");
  }

  const signedAt = Date.parse(record.signed_at);
  if (
    Number.isNaN(signedAt) ||
    Math.abs(signedAt - deps.now.getTime()) >
      REQUEST_CLOCK_SKEW_SECONDS * MILLISECONDS_PER_SECOND
  ) {
    return refuse(422, "bad_signed_at");
  }

  // D-034: the signature is over the entry id, the kind, and the record, so a
  // decision signed for one entry can never be replayed onto another.
  if (!(await verifyRecordSignature(id, "validation", record, body.signature))) {
    return refuse(422, "bad_record_signature");
  }

  // The whole event set this entry is derived over, superseders included, so a
  // partial read can never drop a `superseded_by` the log already says is there
  // (src/worker/world.ts).
  const world = await entryWorld(env.DB, id);
  const { registry, entryEvents } = world;
  const core = submissionCore(entryEvents, id);
  if (core === null) {
    // Unreachable: an entry row exists only where its submission event does.
    return refuse(404, "not_found");
  }

  // The context, gathered at the head of the log. Everything in it is read out
  // of the events; nothing is decided here.
  const head = (await headSeq(env.DB)) ?? 0;
  const registered = registeredOperatorsAt(registry, head);
  const providers = await providerFlags(env.DB);
  // Decision D-071: eligibility is per domain, so each operator carries the
  // domains it is attested in, folded out of the same events the rest of the
  // context is. An operator the fold does not know reads as the default domain,
  // which is what its registration meant before v0.7.
  const attested = operatorDomainsAt(registry, head);
  const operators: Record<string, OperatorInfo> = {};
  for (const operator of registered.operators) {
    operators[operator] = {
      maintainer: registered.maintainers.has(operator),
      provider: providers.has(operator),
      ...(attested.has(operator) ? { domains: attested.get(operator)! } : {}),
    };
  }
  const open = openAssignmentOf(entryEvents, id);

  // Section 6, "Dispute": a challenge "passes through the same validation
  // process with one extra exclusion: no operator that signed the original,
  // submitter or validator, may validate the challenge against it." The
  // `dispute_of` column says whether this entry is such a challenge, and the
  // challenged entry, derived over its own world, says who signed it. An
  // ordinary entry answers null here and the list is empty, which is why every
  // other decision behaves exactly as it always has.
  const challenged = await disputedTarget(env.DB, id, deps);
  const excludedOperators =
    challenged === null
      ? []
      : disputeExclusions(
          challenged.derived.entry as unknown as {
            author_operator: string | null;
            approvers: readonly ApproverRecord[];
          },
        );

  const verdict = checkValidation(record, {
    submitter: {
      agent: core["author"] as string,
      operator: (core["author_operator"] as string | null) ?? null,
    },
    agentOperators: Object.fromEntries(agentOperatorsAt(registry, head)),
    operators,
    // The entry's own domain, off its signed core: a legacy v0.6 core carries
    // none and reads as the default domain.
    domain: domainOf(core),
    // Decision D-096: the official hosts of the authority this entry's subject
    // names, from src/policy.ts and nowhere else. Empty for ai-ecosystem, for
    // a subject with no authority row, and for the fixture row -- which is why
    // every decision outside the two new domains is unchanged.
    authority_hosts: authorityHostsFor(domainOf(core), core["subject"]),
    priorRecords: priorRecordsOf(entryEvents, id),
    openAssignment: open === null ? null : { operator: open.operator },
    excludedOperators,
  });
  if (!verdict.ok) return refuse(422, verdict.reason);

  const evidence = checkRecordEvidence(record, core);
  if (!evidence.ok) return refuse(422, evidence.reason);

  // Identity and operators: the operator is the unit, so any agent under the
  // assigned operator answers the assignment.
  const answeredAssignmentSeq =
    open !== null && open.operator === record.operator ? open.seq : null;

  // Freshness and decay: the superseding entry "names the superseded entry
  // inside the new entry's frozen, signed core ... and the old entry's
  // superseded-by pointer is derived from it". The approvals are the check, so
  // the target's pointer appears at exactly the decision that verifies this
  // entry and never earlier. Its world is gathered now, before the write, so the
  // sync callback below has it in hand; whether it is used at all is decided
  // there, from what derivation made of this decision.
  const declared = core["supersedes"];
  const supersession = await supersessionTarget(
    env.DB,
    typeof declared === "string" ? declared : null,
  );

  // The older versions of the same model, gathered here for the same reason and
  // rewritten in the same batch (decision D-096).
  const siblings = await versionSiblings(env.DB, id, core);

  const at = deps.now.toISOString();
  let derivedEntry: Record<string, unknown> | null = null;
  let verifiedByThisDecision = false;

  /**
   * This entry as this decision leaves it, derived once and reused.
   *
   * `alsoEvents` runs before `stored` — the extra events have to be sealed onto
   * the same run — so the verdict is needed before the stored row is built, and
   * deriving twice would be asking the same log the same question twice.
   */
  let decided: DerivedEntry | null = null;
  const decide = (event: Event<"validation">): DerivedEntry => {
    if (decided === null) decided = rederive(world, id, deps.now, [event]);
    return decided;
  };

  try {
    await recordValidation(env.DB, {
      event: {
        at,
        type: "validation",
        entry_id: id,
        payload: { record, signature: body.signature },
      },
      // Section 6, "Dispute": "An upheld challenge returns the stake, pays the
      // challenger, overturns the entry", and a failed one "forfeits the stake".
      // Both land on the CHALLENGED entry, and both land in this batch: the
      // decision that decides the correction is the moment the target is
      // overturned or the challenge is done, and a reader between two writes
      // must never see a correction verified and its target still standing.
      alsoEvents: (event): readonly EventInput[] => {
        if (challenged === null) return [];
        const status = decide(event).derived.status;
        const correctionId = challenged.filed.payload.correction_entry_id;
        if (status === "verified") {
          return [
            {
              at,
              type: "dispute_upheld",
              entry_id: challenged.id,
              payload: { correction_entry_id: correctionId },
            },
          ];
        }
        if (status === "rejected") {
          return [
            {
              at,
              type: "dispute_failed",
              entry_id: challenged.id,
              payload: {
                correction_entry_id: correctionId,
                reason: firstRejectionReason(
                  decide(event).entry as Record<string, unknown>,
                ),
              },
            },
          ];
        }
        // Still draft: the challenge has neither stood nor failed yet.
        return [];
      },
      // Called with the event already sealed onto the head and before anything
      // is written, so the entry stored is derived from a log that holds this
      // decision, and a schema refusal here leaves the log exactly as it was.
      stored: (event) => {
        const derived = decide(event);
        const result = validateEntry(derived.entry);
        if (!result.ok) throw new SchemaInvalid(result.errors);
        derivedEntry = derived.entry as Record<string, unknown>;
        verifiedByThisDecision = derived.derived.status === "verified";
        return {
          entry: derived.entry,
          sidecar: derived.sidecar,
          derivedThroughSeq: event.seq,
        };
      },
      // The other entries this decision changed, rewritten in the same batch.
      // Nothing is decided here: each is rederived over its own world with this
      // decision and whatever it sealed folded in, and derivation is what says
      // what changed.
      also: (event, extra): readonly StoredEntryInput[] => {
        const rows: StoredEntryInput[] = [];

        // Freshness and decay: the superseding entry "names the superseded entry
        // inside the new entry's frozen, signed core ... and the old entry's
        // superseded-by pointer is derived from it". The approvals are the
        // check, so the pointer appears at exactly the decision that verifies
        // this entry and never earlier. A decision that does not verify it
        // leaves the target's row untouched, which is why this is asked after
        // `stored` has run rather than before.
        if (supersession !== null && verifiedByThisDecision) {
          const merged: EntryWorld = {
            registry: supersession.world.registry,
            entryEvents: supersession.world.entryEvents,
            superseders: [...supersession.world.superseders, ...entryEvents],
            versionSiblings: supersession.world.versionSiblings,
            // The target's own seal, carried through: rewriting its row must not
            // erase a seal it really has.
            seal: supersession.world.seal,
          };
          const target = rederive(merged, supersession.id, deps.now, [event]);
          const result = validateEntry(target.entry);
          if (!result.ok) throw new SchemaInvalid(result.errors);
          rows.push({
            entry: target.entry,
            sidecar: target.sidecar,
            derivedThroughSeq: event.seq,
          });
        }

        // The older versions of the same model, rewritten from the same log
        // position: this is where their `stale` appears. Each is rederived over
        // its own world -- which already carries this entry's events, because
        // this entry is one of its version siblings -- with this decision folded
        // in, and derivation is what says whether it went stale. A sibling that
        // comes back fresh is a newer version, or one this decision did not
        // retire, and its row is left alone.
        if (verifiedByThisDecision) {
          for (const sibling of siblings) {
            const target = rederive(sibling.world, sibling.id, deps.now, [event]);
            if (!target.derived.stale) continue;
            const result = validateEntry(target.entry);
            if (!result.ok) throw new SchemaInvalid(result.errors);
            rows.push({
              entry: target.entry,
              sidecar: target.sidecar,
              derivedThroughSeq: event.seq,
            });
          }
        }

        // The challenged entry, rewritten from the same log position: this is
        // where `overturned_by` and the disputes[] outcome appear.
        if (challenged !== null && extra.length > 0) {
          const target = rederive(
            challenged.world,
            challenged.id,
            deps.now,
            extra,
          );
          const result = validateEntry(target.entry);
          if (!result.ok) throw new SchemaInvalid(result.errors);
          rows.push({
            entry: target.entry,
            sidecar: target.sidecar,
            derivedThroughSeq: extra[extra.length - 1]!.seq,
          });
        }

        return rows;
      },
      // Section 6: the outcome returns, pays or forfeits what the challenger put
      // up. The rows are src/stake.ts's, read out of the filing and the outcome
      // event, and they land in the batch that sealed the outcome.
      ledger: (_event, extra) => {
        if (challenged === null || extra.length === 0) return [];
        const outcome = extra[0] as
          | Event<"dispute_upheld">
          | Event<"dispute_failed">;
        return disputeOutcomeStakes(challenged.filed, outcome);
      },
      answeredAssignmentSeq,
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
 * The entry id in `/entries/{id}/validate`, or null when the path is not that
 * shape. An id carrying a further slash is not one entry's decision door and
 * falls through rather than being trimmed into one.
 */
function validatePathId(path: string): string | null {
  if (!path.startsWith(ENTRIES_PREFIX)) return null;
  if (!path.endsWith(VALIDATE_SUFFIX)) return null;
  const raw = path.slice(
    ENTRIES_PREFIX.length,
    path.length - VALIDATE_SUFFIX.length,
  );
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Route one request to the validate door, or answer null when the path is not
 * ours, which leaves the Worker's own not_found untouched.
 *
 * The one place a storage failure becomes an answer, exactly as the registry and
 * submit routes do it: D1 is reached through the wrapped handle, so a database
 * that does not answer is a JSON 503 rather than a raw 500. Nothing else is
 * caught — a refusal is a value this route returns, and a bug of ours escapes.
 */
export async function handleValidate(
  request: Request,
  env: Env,
  deps: ValidateDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  const id = validatePathId(path);
  if (id === null) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  try {
    return await validate(
      request,
      { ...env, DB: guardDatabase(env.DB) },
      deps,
      path,
      id,
    );
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`validate: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

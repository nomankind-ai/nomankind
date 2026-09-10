/**
 * A whole small world, in memory, for the offline verifier.
 *
 * One maintainer, one submitter, three outside operators, an HTML capture that
 * really hashes to the entry's snapshot_hash, a stated pricing entry signed by
 * its author and approved by two outside operators under the small-pool rule, a
 * seal over everything up to those decisions, and a second entry submitted
 * after the seal so it stays an unsealed draft.
 *
 * Nothing here is a placeholder: every signature is a real Ed25519 signature
 * over the bytes the kernel defines, every hash is recomputed, and both entries
 * come out of `deriveEntry`, so no derived field is ever written by hand. Keys
 * are fresh on every call, and the clock is injected — nothing reads a wall
 * clock.
 *
 * Used by the verifier's own tests and by the fixture generator that writes the
 * static two files the paper promises.
 */

import {
  APPROVALS_TO_VERIFY_SMALL_POOL,
  DEFAULT_DOMAIN,
  NORM_VERSION,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  agentIdFromPublicKey,
  answersHash,
  appendEvent,
  attestationDeadline,
  attestationId,
  base64Encode,
  buildSeal,
  deriveEntry,
  entryHash,
  exportPublicKeyRaw,
  generateKeypair,
  probeSetHash,
  sealsForEntries,
  signCore,
  snapshotHash,
  type ApproverRecord,
  type AttestationScoreRecord,
  type AttestationScorer,
  type Core,
  type Entry,
  type Event,
  type Probe,
  type ReconfirmationRecord,
  type Seal,
} from "../../src/index.js";
import { signRecord } from "../../src/records.js";
import type { LogBundle, Registry } from "../../src/verify.js";

/**
 * Every operator in this world is attested in the entry's domain: the world is
 * about the exclusions and the seals, not about domains, and an operator that
 * was attested nowhere would be refused for a reason no test here is asking
 * about (decision D-071).
 */
const DOMAINS: readonly string[] = Object.freeze([DEFAULT_DOMAIN]);

/** The maintainer's own operator: registered, never an outside validator. */
export const MAINTAINER_OPERATOR = "nomankind";

/** The operator the entries are submitted under. */
export const SUBMITTER_OPERATOR = "op_lattice";

/**
 * A model provider, registered as an operator: the one party the door refuses
 * outright (Section 5, "no model provider may register as an operator"). Only
 * present when `withProvider` is asked for, so the committed fixtures never
 * carry it.
 */
export const PROVIDER_OPERATOR = "op_provider";

/**
 * The operator that files a challenge against the verified entry. Its own, so
 * the correction's submitter is never one of the target's signers and the
 * exclusion the tests are about is the only rule in play.
 */
export const CHALLENGER_OPERATOR = "op_challenger";

/** The operator the attested model answers for. */
export const MODEL_OPERATOR = "op_model";

/**
 * The outside operators the preconditions ask for: verification needs
 * VERIFICATION_MIN_OUTSIDE_OPERATORS operators outside the submitter's own, and
 * they are all trusted, which keeps the pool under the switch so
 * APPROVALS_TO_VERIFY_SMALL_POOL approvals verify.
 */
export const OUTSIDE_OPERATORS: readonly string[] = Array.from(
  { length: VERIFICATION_MIN_OUTSIDE_OPERATORS },
  (_, index) => `op_outside${index + 1}`,
);

/** The captured page: a title, a nav the extractor strips, and a price line in main. */
export const CAPTURE_HTML = [
  "<!doctype html>",
  "<html>",
  "  <head><title>gpt-5 pricing</title></head>",
  "  <body>",
  '    <nav><a href="/docs">Docs</a> <a href="/pricing">Pricing</a></nav>',
  "    <main>",
  "      <h1>Pricing</h1>",
  "      <p>gpt-5 input: $2.50 per million tokens</p>",
  "    </main>",
  "  </body>",
  "</html>",
].join("\n");

export const CAPTURE_CONTENT_TYPE = "text/html; charset=utf-8";

/** norm-v1.2 is in force from 2026-09-08, so the world starts there. */
const EPOCH = "2026-09-08T00:00:00Z";

/** The derivation clock: two days on, well inside the pricing window. */
const DEFAULT_NOW = "2026-09-10T00:00:00Z";

const MILLISECONDS_PER_MINUTE = 60_000;

/** One minute per event, from the same fake clock. */
function at(seq: number): string {
  return new Date(
    Date.parse(EPOCH) + seq * MILLISECONDS_PER_MINUTE,
  ).toISOString();
}

/** One party: an agent id, the operator behind it, and the keypair. */
interface Party {
  agent: string;
  operator: string;
  keys: CryptoKeyPair;
}

async function makeParty(operator: string): Promise<Party> {
  const keys = await generateKeypair();
  const agent = agentIdFromPublicKey(await exportPublicKeyRaw(keys.publicKey));
  return { agent, operator, keys };
}

/** The attestation the world carries, when it was asked for one. */
export interface WorldAttestation {
  id: string;
  /** The model's agent id. */
  model: string;
  /** The operator the model answers for. */
  modelOperator: string;
  /** The scorers the request drew, in draw order. */
  scorers: readonly AttestationScorer[];
}

/** The world the verifier is handed: the entries, the bundle, and the keys. */
export interface VerifyWorld {
  entryId: string;
  draftEntryId: string;
  entry: Entry;
  draftEntry: Entry;
  bundle: LogBundle;
  /** The provider's agent id, or null when the world was built without one. */
  providerAgent: string | null;
  /** The challenge, when the world was built with one. */
  correctionEntryId: string | null;
  correctionEntry: Entry | null;
  /** The attestation, when the world was built with one. */
  attestation: WorldAttestation | null;
  /** Keyed by agent id, so a test can forge a signature from the wrong key. */
  keys: Record<string, CryptoKeyPair>;
  /** The raw capture bytes, so a test can edit the archived page. */
  captureBytes: Uint8Array;
}

export const VERIFIED_ENTRY_ID = "nmk_01M9VERIFIED";
export const DRAFT_ENTRY_ID = "nmk_01M9DRAFT";
export const CORRECTION_ENTRY_ID = "nmk_01M9CORRECTION";

function append(
  events: readonly Event[],
  type: Parameters<typeof appendEvent>[1]["type"],
  entryId: string | null,
  payload: Parameters<typeof appendEvent>[1]["payload"],
): Promise<Event[]> {
  return appendEvent(events, {
    at: at(events.length),
    type,
    entry_id: entryId,
    payload,
  });
}

/** The eighteen core keys, in the schema's own names. */
function makeCore(
  overrides: Record<string, unknown>,
  submitter: Party,
  snapshot: string,
  submittedAt: string,
): Core {
  return {
    id: VERIFIED_ENTRY_ID,
    subject: "openai/gpt-5",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00 per million input tokens",
    after: "$2.50 per million input tokens",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://platform.openai.com/docs/pricing",
    snapshot_hash: snapshot,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: submitter.agent,
    author_operator: submitter.operator,
    submitted_at: submittedAt,
    ...overrides,
  } as Core;
}

/**
 * The schema's reconfirmation record for a stated entry: a fresh snapshot hash
 * and nothing else, as `checkReconfirmation` requires of a stated entry.
 */
function reconfirmation(
  party: Party,
  snapshot: string,
  signedAt: string,
): ReconfirmationRecord {
  return {
    agent: party.agent,
    operator: party.operator,
    snapshot_hash: snapshot,
    reproduction: null,
    observation: null,
    signed_at: signedAt,
  };
}

function approval(
  party: Party,
  snapshot: string,
  signedAt: string,
): ApproverRecord {
  return {
    agent: party.agent,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: snapshot,
    // The pool is under the switch, so no validator is drawn at random.
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: signedAt,
  };
}

/** buildSeal, unwrapped: a refusal here means the world is built wrong. */
async function seal(events: readonly Event[], now: string): Promise<Seal> {
  const result = await buildSeal(events, null, { now });
  if (!result.ok) throw new Error(`buildVerifyWorld: buildSeal ${result.reason}`);
  return result.seal;
}

/**
 * Build the world. Fresh keys every call, so a test that tampers with one
 * cannot leak into another.
 */
export async function buildVerifyWorld(options?: {
  now?: string;
  /** Register a provider-flagged operator, with an agent of its own. */
  withProvider?: boolean;
  /** Append a reconfirmation by a trusted outside operator after the seal. */
  withReconfirmation?: boolean;
  /**
   * File a correction entry as a challenge against the verified entry, and
   * approve it — either by one of the target's own signers, which Section 6
   * bars, or by an operator that signed nothing of the target's.
   */
  withDispute?: "signer" | "outsider";
  /**
   * Draw, answer and score an attestation over the verified entry. `model`
   * seats the model's own operator as the first scorer, which no live draw can
   * produce and Section 8 forbids.
   */
  withAttestation?: true | "model";
}): Promise<VerifyWorld> {
  const now = options?.now ?? DEFAULT_NOW;
  const withProvider = options?.withProvider === true;
  const withReconfirmation = options?.withReconfirmation === true;
  const withDispute = options?.withDispute;
  const withAttestation = options?.withAttestation;

  const captureBytes = new TextEncoder().encode(CAPTURE_HTML);
  const captured = await snapshotHash(captureBytes, CAPTURE_CONTENT_TYPE);
  if (!captured.ok) {
    throw new Error(`buildVerifyWorld: snapshotHash ${captured.reason}`);
  }
  const snapshot = captured.hash;

  const submitter = await makeParty(SUBMITTER_OPERATOR);
  const provider = withProvider ? await makeParty(PROVIDER_OPERATOR) : null;
  const challenger =
    withDispute === undefined ? null : await makeParty(CHALLENGER_OPERATOR);
  const model =
    withAttestation === undefined ? null : await makeParty(MODEL_OPERATOR);
  const outside: Party[] = [];
  for (const operator of OUTSIDE_OPERATORS) {
    outside.push(await makeParty(operator));
  }

  // The registry: the maintainer, the submitter's operator, and the outside
  // operators, of which every one is trusted.
  const empty: Event[] = [];
  let events: Event[] = await append(empty, "operator_registered", null, {
    operator: MAINTAINER_OPERATOR,
    maintainer: true,
  });
  events = await append(events, "operator_registered", null, {
    operator: SUBMITTER_OPERATOR,
    maintainer: false,
  });
  for (const operator of OUTSIDE_OPERATORS) {
    events = await append(events, "operator_registered", null, {
      operator,
      maintainer: false,
    });
  }
  if (provider !== null) {
    events = await append(events, "operator_registered", null, {
      operator: PROVIDER_OPERATOR,
      maintainer: false,
    });
  }
  if (challenger !== null) {
    events = await append(events, "operator_registered", null, {
      operator: CHALLENGER_OPERATOR,
      maintainer: false,
    });
  }
  if (model !== null) {
    events = await append(events, "operator_registered", null, {
      operator: MODEL_OPERATOR,
      maintainer: false,
    });
  }
  for (const operator of OUTSIDE_OPERATORS) {
    events = await append(events, "operator_trusted", null, { operator });
  }
  events = await append(events, "pool_snapshot", null, {
    operators: [...OUTSIDE_OPERATORS],
  });
  const poolSnapshotSeq = events[events.length - 1]!.seq;

  // The entry the pool decides on.
  const submittedAt = at(events.length);
  const core = makeCore({}, submitter, snapshot, submittedAt);
  const signature = await signCore(core, submitter.keys.privateKey);
  events = await append(events, "entry_submitted", VERIFIED_ENTRY_ID, {
    core,
    signature,
  });

  for (let index = 0; index < APPROVALS_TO_VERIFY_SMALL_POOL; index += 1) {
    const party = outside[index]!;
    const record = approval(party, snapshot, at(events.length));
    events = await append(events, "validation", VERIFIED_ENTRY_ID, {
      record,
      signature: await signRecord(
        VERIFIED_ENTRY_ID,
        "validation",
        record,
        party.keys.privateKey,
      ),
    });
  }

  // The seal closes here, so the draft submitted next is not covered by it.
  const seals = [await seal(events, at(events.length))];

  const draftSubmittedAt = at(events.length);
  const draftCore = makeCore(
    {
      id: DRAFT_ENTRY_ID,
      subject: "anthropic/claude-4",
      claim: "claude-4 input price is $3.00 per million tokens",
      before: "$4.00 per million input tokens",
      after: "$3.00 per million input tokens",
    },
    submitter,
    snapshot,
    draftSubmittedAt,
  );
  events = await append(events, "entry_submitted", DRAFT_ENTRY_ID, {
    core: draftCore,
    signature: await signCore(draftCore, submitter.keys.privateKey),
  });

  // Section 6: a trusted operator outside the submitter's own reconfirms the
  // verified entry. It comes after the seal, so the seal stays what it was.
  if (withReconfirmation) {
    const party = outside[outside.length - 1]!;
    const record = reconfirmation(party, snapshot, at(events.length));
    events = await append(events, "reconfirmation", VERIFIED_ENTRY_ID, {
      record,
      signature: await signRecord(
        VERIFIED_ENTRY_ID,
        "reconfirmation",
        record,
        party.keys.privateKey,
      ),
    });
  }

  // Section 6, "Dispute": the challenge is itself an entry, in the correction
  // category, with a citation and the same subject, and the target's own
  // `dispute_filed` names it. Its one decision is the whole point: the door
  // bars every operator that signed the original from taking it.
  if (challenger !== null && withDispute !== undefined) {
    const correctionSubmittedAt = at(events.length);
    const correctionCore = makeCore(
      {
        id: CORRECTION_ENTRY_ID,
        category: "correction",
        claim: "gpt-5 input price is $2.75 per million tokens",
        before: "$2.50 per million input tokens",
        after: "$2.75 per million input tokens",
        author: challenger.agent,
        author_operator: challenger.operator,
      },
      challenger,
      snapshot,
      correctionSubmittedAt,
    );
    events = await append(events, "entry_submitted", CORRECTION_ENTRY_ID, {
      core: correctionCore,
      signature: await signCore(correctionCore, challenger.keys.privateKey),
    });
    // Scoped to the DISPUTED entry and naming the correction, exactly as the
    // door files it: the correction's own events say nothing about the filing.
    events = await append(events, "dispute_filed", VERIFIED_ENTRY_ID, {
      correction_entry_id: CORRECTION_ENTRY_ID,
      challenger: challenger.agent,
      operator: challenger.operator,
      citation: correctionCore["citation"] as string,
      snapshot_hash: snapshot,
      from_report_seq: null,
      from_revalidation_seq: null,
    });

    // The signer approved the target; the outsider signed nothing of its.
    const party = withDispute === "signer" ? outside[0]! : outside[2]!;
    const record = approval(party, snapshot, at(events.length));
    events = await append(events, "validation", CORRECTION_ENTRY_ID, {
      record,
      signature: await signRecord(
        CORRECTION_ENTRY_ID,
        "validation",
        record,
        party.keys.privateKey,
      ),
    });
  }

  // Section 8, "Drift attestation": the probes are drawn from the verified
  // entry, the model answers them, and the drawn scorers sign what they scored.
  let attestation: WorldAttestation | null = null;
  if (model !== null && withAttestation !== undefined) {
    const probes: readonly Probe[] = [
      { entry_id: VERIFIED_ENTRY_ID, entry_hash: await entryHash(core) },
    ];
    const probeHash = await probeSetHash(probes);
    const beaconRound = 4_242;
    const id = await attestationId({
      model: model.agent,
      pool_snapshot_seq: poolSnapshotSeq,
      beacon_round: beaconRound,
      probe_hash: probeHash,
    });
    // The draw excludes the model's own operator, so `model` seats one anyway:
    // the state the rule is about, which no honest draw can produce.
    const scorerParties =
      withAttestation === "model"
        ? [model, outside[1]!, outside[2]!]
        : [outside[0]!, outside[1]!, outside[2]!];
    const scorers: readonly AttestationScorer[] = scorerParties.map((party) => ({
      operator: party.operator,
      agent: party.agent,
    }));

    const requestedAt = at(events.length);
    events = await append(events, "attestation_requested", null, {
      attestation: id,
      domain: DEFAULT_DOMAIN,
      model: model.agent,
      model_operator: model.operator,
      probes,
      probe_hash: probeHash,
      probe_count: probes.length,
      pool_snapshot_seq: poolSnapshotSeq,
      beacon_round: beaconRound,
      beacon_randomness: "ab".repeat(32),
      scorers,
      deadline: attestationDeadline(requestedAt),
    });

    const answers = [
      { entry_id: VERIFIED_ENTRY_ID, answer: core["claim"] as string },
    ];
    const answered = await answersHash(answers);
    events = await append(events, "attestation_answered", null, {
      attestation: id,
      answers_hash: answered,
    });

    for (const party of scorerParties) {
      const record: AttestationScoreRecord = {
        agent: party.agent,
        operator: party.operator,
        agreed: probes.length,
        probe_hash: probeHash,
        answers_hash: answered,
        signed_at: at(events.length),
      };
      events = await append(events, "attestation_scored", null, {
        attestation: id,
        record,
        signature: await signRecord(
          id,
          "attestation_score",
          record,
          party.keys.privateKey,
        ),
      });
    }

    attestation = {
      id,
      model: model.agent,
      modelOperator: model.operator,
      scorers,
    };
  }

  const entrySeals = await sealsForEntries(events, seals);
  const entry = deriveEntry(events, VERIFIED_ENTRY_ID, { now }, entrySeals).entry;
  const correctionEntry =
    withDispute === undefined
      ? null
      : deriveEntry(events, CORRECTION_ENTRY_ID, { now }, entrySeals).entry;
  const draftEntry = deriveEntry(events, DRAFT_ENTRY_ID, { now }, entrySeals)
    .entry;

  /** Every party the registry knows, in one list: agents and keys read off it. */
  const parties: Party[] = [
    submitter,
    ...outside,
    ...(provider === null ? [] : [provider]),
    ...(challenger === null ? [] : [challenger]),
    ...(model === null ? [] : [model]),
  ];

  const registry: Registry = {
    agents: Object.fromEntries(
      parties.map((party) => [party.agent, party.operator]),
    ),
    operators: {
      [MAINTAINER_OPERATOR]: { maintainer: true, provider: false, domains: DOMAINS },
      [SUBMITTER_OPERATOR]: { maintainer: false, provider: false, domains: DOMAINS },
      ...Object.fromEntries(
        OUTSIDE_OPERATORS.map((operator) => [
          operator,
          { maintainer: false, provider: false, domains: DOMAINS },
        ]),
      ),
      ...(provider === null
        ? {}
        : {
            [PROVIDER_OPERATOR]: {
              maintainer: false,
              provider: true,
              domains: DOMAINS,
            },
          }),
      ...(challenger === null
        ? {}
        : {
            [CHALLENGER_OPERATOR]: {
              maintainer: false,
              provider: false,
              domains: DOMAINS,
            },
          }),
      ...(model === null
        ? {}
        : {
            [MODEL_OPERATOR]: {
              maintainer: false,
              provider: false,
              domains: DOMAINS,
            },
          }),
    },
  };

  const bundle: LogBundle = {
    as_of: now,
    events,
    registry,
    seals,
    captures: {
      [snapshot]: {
        content_type: CAPTURE_CONTENT_TYPE,
        body_base64: base64Encode(captureBytes),
      },
    },
  };

  const keys: Record<string, CryptoKeyPair> = Object.fromEntries(
    parties.map((party) => [party.agent, party.keys]),
  );

  return {
    entryId: VERIFIED_ENTRY_ID,
    draftEntryId: DRAFT_ENTRY_ID,
    entry,
    draftEntry,
    bundle,
    providerAgent: provider === null ? null : provider.agent,
    correctionEntryId: withDispute === undefined ? null : CORRECTION_ENTRY_ID,
    correctionEntry,
    attestation,
    keys,
    captureBytes,
  };
}

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
  NORM_VERSION,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  agentIdFromPublicKey,
  appendEvent,
  base64Encode,
  buildSeal,
  deriveEntry,
  exportPublicKeyRaw,
  generateKeypair,
  sealsForEntries,
  signCore,
  snapshotHash,
  type ApproverRecord,
  type Core,
  type Entry,
  type Event,
  type ReconfirmationRecord,
  type Seal,
} from "../../src/index.js";
import { signRecord } from "../../src/records.js";
import type { LogBundle, Registry } from "../../src/verify.js";

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

/** The world the verifier is handed: the two entries, the bundle, and the keys. */
export interface VerifyWorld {
  entryId: string;
  draftEntryId: string;
  entry: Entry;
  draftEntry: Entry;
  bundle: LogBundle;
  /** The provider's agent id, or null when the world was built without one. */
  providerAgent: string | null;
  /** Keyed by agent id, so a test can forge a signature from the wrong key. */
  keys: Record<string, CryptoKeyPair>;
  /** The raw capture bytes, so a test can edit the archived page. */
  captureBytes: Uint8Array;
}

export const VERIFIED_ENTRY_ID = "nmk_01M9VERIFIED";
export const DRAFT_ENTRY_ID = "nmk_01M9DRAFT";

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

/** The seventeen core keys, in the schema's own names. */
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
}): Promise<VerifyWorld> {
  const now = options?.now ?? DEFAULT_NOW;
  const withProvider = options?.withProvider === true;
  const withReconfirmation = options?.withReconfirmation === true;

  const captureBytes = new TextEncoder().encode(CAPTURE_HTML);
  const captured = await snapshotHash(captureBytes, CAPTURE_CONTENT_TYPE);
  if (!captured.ok) {
    throw new Error(`buildVerifyWorld: snapshotHash ${captured.reason}`);
  }
  const snapshot = captured.hash;

  const submitter = await makeParty(SUBMITTER_OPERATOR);
  const provider = withProvider ? await makeParty(PROVIDER_OPERATOR) : null;
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
  for (const operator of OUTSIDE_OPERATORS) {
    events = await append(events, "operator_trusted", null, { operator });
  }
  events = await append(events, "pool_snapshot", null, {
    operators: [...OUTSIDE_OPERATORS],
  });

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

  const entrySeals = await sealsForEntries(events, seals);
  const entry = deriveEntry(events, VERIFIED_ENTRY_ID, { now }, entrySeals).entry;
  const draftEntry = deriveEntry(events, DRAFT_ENTRY_ID, { now }, entrySeals)
    .entry;

  const registry: Registry = {
    agents: Object.fromEntries(
      [submitter, ...outside, ...(provider === null ? [] : [provider])].map(
        (party) => [party.agent, party.operator],
      ),
    ),
    operators: {
      [MAINTAINER_OPERATOR]: { maintainer: true, provider: false },
      [SUBMITTER_OPERATOR]: { maintainer: false, provider: false },
      ...Object.fromEntries(
        OUTSIDE_OPERATORS.map((operator) => [
          operator,
          { maintainer: false, provider: false },
        ]),
      ),
      ...(provider === null
        ? {}
        : { [PROVIDER_OPERATOR]: { maintainer: false, provider: true } }),
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
    [submitter, ...outside, ...(provider === null ? [] : [provider])].map(
      (party) => [party.agent, party.keys],
    ),
  );

  return {
    entryId: VERIFIED_ENTRY_ID,
    draftEntryId: DRAFT_ENTRY_ID,
    entry,
    draftEntry,
    bundle,
    providerAgent: provider === null ? null : provider.agent,
    keys,
    captureBytes,
  };
}

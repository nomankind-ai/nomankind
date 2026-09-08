/**
 * The operator registry: joining, and the two doors that refuse.
 *
 * Whitepaper Section 5, Identity and operators: "To register, an operator
 * proves control of a domain through a DNS record, completes payout onboarding
 * through the payment provider ... and binds both to a 1F916 identity so the
 * attestation travels with them." Section 11 names the same three joining
 * steps: publish a DNS TXT record carrying your 1F916 agent id, complete payout
 * onboarding, and sign the provider-independence attestation from Section 10.
 *
 * This module is pure: no I/O, no clock, no network. It builds and checks the
 * attestation, says what a TXT record and an operator domain have to look like,
 * and decides a registration or a genesis naming from facts the caller has
 * already gathered. The DNS lookup and the payout call are the Worker's, and
 * the time a signature was made is the caller's to supply.
 *
 * Ed25519 and SHA-256 run through globalThis.crypto.subtle only, never
 * node:crypto, so this runs unchanged on Cloudflare Workers.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import type { Attestation } from "./events.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import { MODEL_PROVIDER_DOMAINS } from "./policy.js";

const encoder = new TextEncoder();

/** ISO 8601 date-time with a seconds field and an explicit offset or Z. */
const ISO_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

// ---------------------------------------------------------------------------
// The independence attestation
// ---------------------------------------------------------------------------

/**
 * The version of the attestation an operator signs. A format constant, not a
 * policy number: it names the shape of what was signed. Exactly one version
 * exists, so any other version is unknown rather than older.
 */
export const ATTESTATION_VERSION = "nomankind-independence-v1";

/**
 * The attestation itself, Section 10: "registration requires a signed
 * attestation that no model provider holds control or a beneficial stake". One
 * fixed sentence, signed verbatim, so what an operator put their key to is the
 * same string every reader can recheck years later.
 */
export const ATTESTATION_TEXT =
  "No model provider holds control of, or a beneficial stake in, this operator.";

/**
 * Domain-separation tag for the attestation signature. A format constant: it
 * keeps an attestation signature from ever being replayed as a request
 * signature or an entry signature.
 */
export const HASH_TAG_ATTESTATION = "nomankind-attestation-v1";

/** What an attestation is made over: who attests, for what, and when. */
export interface AttestationSubject {
  readonly operator: string;
  readonly agent: string;
  readonly version: string;
  readonly signed_at: string;
}

/**
 * The bytes an attestation signs: the tag, a newline, and the JCS canonical
 * form of the attested facts. The text travels inside the signed object rather
 * than beside it, so a signature is over the sentence itself and not over a
 * version number that could later be pointed at different words.
 */
export function attestationSigningBytes(
  subject: AttestationSubject,
): Uint8Array {
  const canonical = canonicalize({
    agent: subject.agent,
    operator: subject.operator,
    signed_at: subject.signed_at,
    text: ATTESTATION_TEXT,
    version: subject.version,
  });
  return encoder.encode(`${HASH_TAG_ATTESTATION}\n${canonical}`);
}

/**
 * Sign the independence attestation with the agent's own key. The timestamp
 * comes from the caller's clock; nothing here reads Date.now().
 */
export async function signAttestation(
  privateKey: CryptoKey,
  input: { operator: string; agent: string; signed_at: string },
): Promise<Attestation> {
  const bytes = attestationSigningBytes({
    operator: input.operator,
    agent: input.agent,
    version: ATTESTATION_VERSION,
    signed_at: input.signed_at,
  });
  const signature = await signBytes(privateKey, bytes);
  return {
    version: ATTESTATION_VERSION,
    signed_at: input.signed_at,
    signature: base64urlEncode(signature),
  };
}

/**
 * Whether this attestation was signed by the key inside `agent`, for this
 * operator and this agent.
 *
 * Answers false and never throws: a caller checking an attestation is asking a
 * question, and a malformed object, an unknown version, a timestamp that is not
 * ISO 8601, a signature that is not base64url, and a signature over other bytes
 * are all answers of "no".
 */
export async function verifyAttestation(
  operator: string,
  agent: string,
  attestation: unknown,
): Promise<boolean> {
  if (
    typeof attestation !== "object" ||
    attestation === null ||
    Array.isArray(attestation)
  ) {
    return false;
  }
  const record = attestation as Record<string, unknown>;
  if (record["version"] !== ATTESTATION_VERSION) return false;
  const signedAt = record["signed_at"];
  if (typeof signedAt !== "string" || !ISO_DATE_TIME.test(signedAt)) {
    return false;
  }
  const signature = record["signature"];
  if (typeof signature !== "string" || signature.length === 0) return false;
  if (typeof operator !== "string" || typeof agent !== "string") return false;

  try {
    const publicKey = publicKeyFromAgentId(agent);
    const bytes = attestationSigningBytes({
      operator,
      agent,
      version: ATTESTATION_VERSION,
      signed_at: signedAt,
    });
    return await verifyBytes(publicKey, bytes, base64urlDecode(signature));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Domain control
// ---------------------------------------------------------------------------

/** The label a domain-control TXT record is published under. */
export const TXT_RECORD_PREFIX = "_nomankind";

/** Where an operator publishes the record that proves it controls the domain. */
export function txtRecordName(operator: string): string {
  return `${TXT_RECORD_PREFIX}.${operator}`;
}

/**
 * Whether the TXT records found at that name prove control by this agent.
 *
 * Section 11: the record carries the 1F916 agent id. Any one of the values may
 * be it — a domain carries records for other purposes too — and a value counts
 * only when it is exactly the id once surrounding whitespace is dropped. No
 * prefix and no substring: a record that merely mentions the id is not it.
 */
export function txtMatches(
  values: readonly string[],
  agent: string,
): boolean {
  if (typeof agent !== "string" || agent.length === 0) return false;
  return values.some((value) => typeof value === "string" && value.trim() === agent);
}

/**
 * RFC 1035 section 2.3.4: a label is at most 63 octets. A protocol limit, not
 * policy: it is what the DNS itself permits, so it does not live in
 * src/policy.ts and it does not move by decision.
 */
export const DNS_LABEL_MAX_LENGTH = 63;

/**
 * RFC 1035 section 2.3.4: a name is at most 255 octets on the wire, which is
 * 253 characters written out. A protocol limit, not policy, for the same
 * reason as the label limit above.
 */
export const DNS_NAME_MAX_LENGTH = 253;

const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Whether a value is a domain an operator can register under, which is also
 * the operator's id: Section 5 makes the domain the thing proved, so the
 * registry has no separate handle to collide over.
 *
 * Lowercase ASCII only, at least two labels, no trailing dot. Case is not
 * folded here: the operator id is a key in the log and two spellings of one
 * domain must never be two operators, so the one accepted spelling is the
 * lowercase one and anything else is refused rather than repaired.
 */
export function isOperatorDomain(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > DNS_NAME_MAX_LENGTH) return false;
  if (value.endsWith(".")) return false;
  const labels = value.split(".");
  if (labels.length < 2) return false;
  return labels.every(
    (label) => label.length <= DNS_LABEL_MAX_LENGTH && LABEL.test(label),
  );
}

/**
 * Whether a domain belongs to a model provider, itself or as a subdomain.
 *
 * Section 10: "No lab or model provider may be a maintainer, funder, or trusted
 * operator." The list is published policy (src/policy.ts) and is passed in so a
 * fork can run its own; the suffix test is what makes a subdomain no cheaper a
 * door than the domain.
 */
export function isProviderDomain(
  domain: string,
  providers: readonly string[] = MODEL_PROVIDER_DOMAINS,
): boolean {
  if (typeof domain !== "string") return false;
  return providers.some(
    (provider) => domain === provider || domain.endsWith(`.${provider}`),
  );
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/** What a registration request carries, once it has been recognised as one. */
export interface RegistrationBody {
  readonly operator: string;
  readonly attestation: unknown;
  readonly payout: { readonly reference: string };
}

/** What a genesis naming carries. */
export interface GenesisBody {
  readonly operator: string;
}

/** A parse either produced a body or refused it; there is no partial result. */
export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: "bad_body" };

function asObject(body: unknown): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  return body as Record<string, unknown>;
}

/**
 * Whether the object carries every required key and nothing beyond those and
 * the optional ones. An unexpected key is still refused; an optional key that
 * is simply absent is not a malformed body but a fact for a later check to
 * name.
 */
function hasKeys(
  object: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const actual = Object.keys(object);
  return (
    required.every((key) => actual.includes(key)) &&
    actual.every((key) => required.includes(key) || optional.includes(key))
  );
}

/**
 * Read a registration body.
 *
 * The attestation stays `unknown`: verifying it is verifyAttestation's job, and
 * a parser that pretended to have checked it would be the more dangerous of the
 * two mistakes. An unexpected top-level key is refused rather than ignored, so
 * a caller can never believe it sent something this endpoint honoured.
 *
 * An absent or null attestation is not a parse failure. It parses as null so
 * that checkRegistration can refuse it by name, missing_attestation, which is
 * the refusal Section 10's requirement deserves and the one REGISTRATION_REFUSALS
 * lists. An attestation that is present but is not an object is still bad_body:
 * that is a malformed request rather than a missing one.
 */
export function parseRegistrationBody(
  body: unknown,
): ParseResult<RegistrationBody> {
  const refused = { ok: false, reason: "bad_body" } as const;
  const object = asObject(body);
  if (object === null) return refused;
  if (!hasKeys(object, ["operator", "payout"], ["attestation"])) {
    return refused;
  }
  const operator = object["operator"];
  if (typeof operator !== "string") return refused;
  const supplied = object["attestation"];
  let attestation: unknown = null;
  if (supplied !== undefined && supplied !== null) {
    attestation = asObject(supplied);
    if (attestation === null) return refused;
  }
  const payout = asObject(object["payout"]);
  if (payout === null) return refused;
  const reference = payout["reference"];
  if (typeof reference !== "string" || reference.length === 0) return refused;
  return {
    ok: true,
    value: { operator, attestation, payout: { reference } },
  };
}

/** Read a genesis naming body: an operator, and nothing else. */
export function parseGenesisBody(body: unknown): ParseResult<GenesisBody> {
  const refused = { ok: false, reason: "bad_body" } as const;
  const object = asObject(body);
  if (object === null) return refused;
  if (!hasKeys(object, ["operator"])) return refused;
  const operator = object["operator"];
  if (typeof operator !== "string") return refused;
  return { ok: true, value: { operator } };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Why a registration was refused, in the order the checks run. Cheap and
 * structural first, cryptography next, and the two facts that need the store
 * last, so a malformed request never costs a signature verification.
 */
export const REGISTRATION_REFUSALS = [
  "bad_domain",
  "provider_operator",
  "missing_attestation",
  "bad_attestation",
  "operator_exists",
  "agent_bound",
] as const;

export type RegistrationRefusal = (typeof REGISTRATION_REFUSALS)[number];

/** What deciding a registration needs, all of it already gathered. */
export interface RegistrationInput {
  readonly operator: string;
  readonly agent: string;
  readonly attestation: unknown;
  /** The maintainer's own agent, or null when none is configured. */
  readonly maintainerAgentId: string | null;
  readonly operatorExists: boolean;
  /** The operator this agent is already bound to, or null when it is free. */
  readonly agentOperator: string | null;
  readonly providers?: readonly string[];
}

export type RegistrationCheck =
  | { ok: true; maintainer: boolean }
  | { ok: false; reason: RegistrationRefusal };

/**
 * Decide a registration from facts alone.
 *
 * Section 5 and Section 11 name three joining steps. Two of them reach outside
 * this process — the DNS TXT lookup and payout onboarding — and the Worker
 * checks those after this passes; nothing here does I/O, so nothing here can
 * check them. What is decided here is the rest: the operator id is a domain,
 * it is not a model provider's (Section 10), the independence attestation is
 * present and really signed by this agent's key, the operator is new, and the
 * agent is not already answering for someone else.
 *
 * `maintainer` marks nomankind's own registration. It is the acting agent being
 * the configured maintainer agent and nothing else: no request can claim it,
 * because the field is not read from one.
 */
export async function checkRegistration(
  input: RegistrationInput,
): Promise<RegistrationCheck> {
  if (!isOperatorDomain(input.operator)) {
    return { ok: false, reason: "bad_domain" };
  }
  if (isProviderDomain(input.operator, input.providers)) {
    return { ok: false, reason: "provider_operator" };
  }
  if (input.attestation === null || input.attestation === undefined) {
    return { ok: false, reason: "missing_attestation" };
  }
  const signed = await verifyAttestation(
    input.operator,
    input.agent,
    input.attestation,
  );
  if (!signed) {
    return { ok: false, reason: "bad_attestation" };
  }
  if (input.operatorExists) {
    return { ok: false, reason: "operator_exists" };
  }
  if (input.agentOperator !== null) {
    return { ok: false, reason: "agent_bound" };
  }
  return {
    ok: true,
    maintainer:
      input.maintainerAgentId !== null && input.agent === input.maintainerAgentId,
  };
}

// ---------------------------------------------------------------------------
// Genesis naming
// ---------------------------------------------------------------------------

/** Why a genesis naming was refused, in the order the checks run. */
export const GENESIS_REFUSALS = [
  "maintainer_not_configured",
  "not_maintainer",
  "unregistered_operator",
  "maintainer_operator",
  "provider_operator",
  "already_trusted",
] as const;

export type GenesisRefusal = (typeof GENESIS_REFUSALS)[number];

/** What deciding a genesis naming needs, all of it already gathered. */
export interface GenesisInput {
  /** The agent that signed the request. */
  readonly signer: string;
  readonly maintainerAgentId: string | null;
  readonly operator: string;
  readonly registered: boolean;
  /** Whether that operator is the maintainer's own. */
  readonly maintainerOperator: boolean;
  readonly provider: boolean;
  readonly trusted: boolean;
}

export type GenesisCheck =
  | { ok: true }
  | { ok: false; reason: GenesisRefusal };

/**
 * Decide whether the maintainer may name this operator to the trusted pool.
 *
 * Section 11: "The maintainer seeds the trusted pool once, by naming its first
 * members in public. That is a bootstrap exception to the earned-record rule,
 * stated as such, and the only time trusted status is granted rather than
 * earned. Genesis operators may not include the maintainer's own." Section 10
 * bars a model provider from being a trusted operator, and bars the maintainer
 * from judging at all, which is the same rule read from the other side: the
 * maintainer's operator cannot be trusted because no agent under it may
 * validate anything.
 *
 * Only the maintainer may name, so an unconfigured maintainer refuses the whole
 * power rather than granting it to whoever asks first.
 */
export function checkGenesisNaming(input: GenesisInput): GenesisCheck {
  if (input.maintainerAgentId === null) {
    return { ok: false, reason: "maintainer_not_configured" };
  }
  if (input.signer !== input.maintainerAgentId) {
    return { ok: false, reason: "not_maintainer" };
  }
  if (!input.registered) {
    return { ok: false, reason: "unregistered_operator" };
  }
  if (input.maintainerOperator) {
    return { ok: false, reason: "maintainer_operator" };
  }
  if (input.provider) {
    return { ok: false, reason: "provider_operator" };
  }
  if (input.trusted) {
    return { ok: false, reason: "already_trusted" };
  }
  return { ok: true };
}

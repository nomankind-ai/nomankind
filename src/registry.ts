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
import {
  isAgentId,
  publicKeyFromAgentId,
  signBytes,
  verifyBytes,
} from "./identity.js";
import {
  attestationFor,
  DEFAULT_DOMAIN,
  excludedPartyDomains,
  isRegisteredDomain,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "./policy.js";

const encoder = new TextEncoder();

/** Seconds to milliseconds. A unit conversion, not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

/** ISO 8601 date-time with a seconds field and an explicit offset or Z. */
const ISO_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

// ---------------------------------------------------------------------------
// The independence attestation
// ---------------------------------------------------------------------------

/**
 * The version and the sentence of the default domain's attestation.
 *
 * Decision D-071: the attestation is per domain now
 * (schema/nomankind-domain-registry-v1.md, and `DOMAINS` in src/policy.ts).
 * These two constants are the ai-ecosystem domain's, kept under their old names
 * because that is exactly what every attestation sealed before v0.7 was signed
 * under: a record carrying no domain is the ai-ecosystem attestation, verified
 * against these bytes, and stays valid forever.
 */
export const ATTESTATION_VERSION = attestationFor(DEFAULT_DOMAIN).version;

/**
 * Section 10: "registration requires a signed attestation that no model
 * provider holds control or a beneficial stake". One fixed sentence per domain,
 * signed verbatim, so what an operator put their key to is the same string every
 * reader can recheck years later.
 */
export const ATTESTATION_TEXT = attestationFor(DEFAULT_DOMAIN).text;

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
  /**
   * The domain the attestation is for. Absent means the ai-ecosystem
   * attestation as it was signed before v0.7: the signed object then held no
   * domain key at all, so an old signature stays verifiable byte for byte.
   */
  readonly domain?: string;
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
  const domain = subject.domain;
  const text = attestationFor(domain ?? DEFAULT_DOMAIN).text;
  const canonical = canonicalize({
    agent: subject.agent,
    ...(domain === undefined ? {} : { domain }),
    operator: subject.operator,
    signed_at: subject.signed_at,
    text,
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
  input: {
    operator: string;
    agent: string;
    signed_at: string;
    /** The domain whose attestation is signed; the default domain when absent. */
    domain?: string;
  },
): Promise<Attestation> {
  const domain = input.domain ?? DEFAULT_DOMAIN;
  const { version } = attestationFor(domain);
  const bytes = attestationSigningBytes({
    operator: input.operator,
    agent: input.agent,
    version,
    signed_at: input.signed_at,
    domain,
  });
  const signature = await signBytes(privateKey, bytes);
  return {
    version,
    domain,
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
  expectedDomain?: string,
): Promise<boolean> {
  if (
    typeof attestation !== "object" ||
    attestation === null ||
    Array.isArray(attestation)
  ) {
    return false;
  }
  const record = attestation as Record<string, unknown>;

  // The domain the record says it is for. Absent is ai-ecosystem, because that
  // is what a pre-v0.7 record was signed as; a domain nobody registered is not
  // an attestation at all.
  const declared = record["domain"];
  if (declared !== undefined && !isRegisteredDomain(declared)) return false;
  const domain = declared === undefined ? DEFAULT_DOMAIN : (declared as string);
  if (expectedDomain !== undefined && domain !== expectedDomain) return false;

  if (record["version"] !== attestationFor(domain).version) return false;
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
      version: attestationFor(domain).version,
      signed_at: signedAt,
      // Absent stays absent: the pre-v0.7 signing bytes carried no domain key,
      // so re-adding one here would fail every attestation ever signed.
      ...(declared === undefined ? {} : { domain }),
    });
    return await verifyBytes(publicKey, bytes, base64urlDecode(signature));
  } catch {
    return false;
  }
}

/**
 * The domain an attestation record is for: what it declares, or ai-ecosystem
 * when it declares nothing. Says nothing about whether the record verifies.
 */
export function attestationDomain(attestation: unknown): string {
  if (
    typeof attestation !== "object" ||
    attestation === null ||
    Array.isArray(attestation)
  ) {
    return DEFAULT_DOMAIN;
  }
  const declared = (attestation as Record<string, unknown>)["domain"];
  return typeof declared === "string" ? declared : DEFAULT_DOMAIN;
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
 * Whether an operator domain belongs to a party excluded from a record's
 * domain, itself or as a subdomain.
 *
 * Section 10, in its neutral form (decision D-071): no party whose products or
 * conduct the record checks may control, fund, or validate it in that domain.
 * Which parties those are is the record domain's own published list
 * (schema/nomankind-domain-registry-v1.md, `DOMAINS` in src/policy.ts) and is
 * passed in so a fork can run its own; the suffix test is what makes a
 * subdomain no cheaper a door than the domain. An operator excluded in one
 * domain stays eligible in another, which is the whole point of keying it.
 */
export function isExcludedParty(
  recordDomain: string,
  operator: string,
  parties: readonly string[] = excludedPartyDomains(recordDomain),
): boolean {
  if (typeof operator !== "string") return false;
  return parties.some(
    (party) => operator === party || operator.endsWith(`.${party}`),
  );
}

/**
 * The same question asked of the default domain, under the name every caller
 * before v0.7 knew it by: whether an operator domain is a model provider's.
 */
export function isProviderDomain(
  operator: string,
  parties: readonly string[] = excludedPartyDomains(DEFAULT_DOMAIN),
): boolean {
  return isExcludedParty(DEFAULT_DOMAIN, operator, parties);
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/** What a registration request carries, once it has been recognised as one. */
export interface RegistrationBody {
  readonly operator: string;
  /**
   * The domain the operator registers into: its first, the one its attestation
   * is signed for (decision D-071). Null when the body names none, which is
   * what a client written before v0.7 sends and reads as the default domain --
   * the only domain there was.
   */
  readonly domain: string | null;
  readonly attestation: unknown;
  readonly payout: { readonly reference: string };
}

/** What a domain join carries: the domain, and the attestation signed for it. */
export interface DomainJoinBody {
  readonly domain: string;
  readonly attestation: unknown;
}

/**
 * What binding a second agent carries: the new agent's id, and the attestation
 * that agent signed for the operator's registration domain.
 *
 * The request is signed by an agent the operator already has, so the operator
 * this is about is the path's and never the body's: a body that could name an
 * operator would be a body that could ask for someone else's.
 */
export interface AgentBindBody {
  readonly agent: string;
  readonly attestation: unknown;
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
  if (!hasKeys(object, ["operator", "payout"], ["attestation", "domain"])) {
    return refused;
  }
  const operator = object["operator"];
  if (typeof operator !== "string") return refused;
  const suppliedDomain = object["domain"];
  if (suppliedDomain !== undefined && typeof suppliedDomain !== "string") {
    return refused;
  }
  const domain = suppliedDomain === undefined ? null : suppliedDomain;
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
    value: { operator, domain, attestation, payout: { reference } },
  };
}

/**
 * Read a domain-join body: the domain, and the attestation signed for it.
 *
 * The attestation stays `unknown` for the reason a registration's does: an
 * absent or null one parses as null so `checkDomainJoin` can refuse it by name.
 */
export function parseDomainJoinBody(body: unknown): ParseResult<DomainJoinBody> {
  const refused = { ok: false, reason: "bad_body" } as const;
  const object = asObject(body);
  if (object === null) return refused;
  if (!hasKeys(object, ["domain"], ["attestation"])) return refused;
  const domain = object["domain"];
  if (typeof domain !== "string") return refused;
  const supplied = object["attestation"];
  let attestation: unknown = null;
  if (supplied !== undefined && supplied !== null) {
    attestation = asObject(supplied);
    if (attestation === null) return refused;
  }
  return { ok: true, value: { domain, attestation } };
}

/**
 * Read an agent-bind body: the new agent, and the attestation it signed.
 *
 * The attestation stays `unknown` for the reason a registration's does, and an
 * absent or null one parses as null so `checkAgentBind` can refuse it by name.
 * The agent id is read as a string and judged no further here: whether it spells
 * a key is `bad_agent`, one step later, and not a malformed body.
 */
export function parseAgentBindBody(body: unknown): ParseResult<AgentBindBody> {
  const refused = { ok: false, reason: "bad_body" } as const;
  const object = asObject(body);
  if (object === null) return refused;
  if (!hasKeys(object, ["agent"], ["attestation"])) return refused;
  const agent = object["agent"];
  if (typeof agent !== "string") return refused;
  const supplied = object["attestation"];
  let attestation: unknown = null;
  if (supplied !== undefined && supplied !== null) {
    attestation = asObject(supplied);
    if (attestation === null) return refused;
  }
  return { ok: true, value: { agent, attestation } };
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
  "unregistered_domain",
  "provider_operator",
  "missing_attestation",
  "bad_attestation",
  "attestation_domain_mismatch",
  "operator_exists",
  "agent_bound",
] as const;

export type RegistrationRefusal = (typeof REGISTRATION_REFUSALS)[number];

/** What deciding a registration needs, all of it already gathered. */
export interface RegistrationInput {
  readonly operator: string;
  readonly agent: string;
  /**
   * The registered domain this operator joins first. Null or absent reads as
   * the default domain: that is what a registration sealed before v0.7 meant.
   */
  readonly domain?: string | null;
  readonly attestation: unknown;
  /** The maintainer's own agent, or null when none is configured. */
  readonly maintainerAgentId: string | null;
  readonly operatorExists: boolean;
  /** The operator this agent is already bound to, or null when it is free. */
  readonly agentOperator: string | null;
  readonly providers?: readonly string[];
}

export type RegistrationCheck =
  | { ok: true; maintainer: boolean; domain: string }
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
  const domain = input.domain ?? DEFAULT_DOMAIN;
  if (!isRegisteredDomain(domain)) {
    return { ok: false, reason: "unregistered_domain" };
  }
  if (isExcludedParty(domain, input.operator, input.providers)) {
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
  if (attestationDomain(input.attestation) !== domain) {
    return { ok: false, reason: "attestation_domain_mismatch" };
  }
  if (input.operatorExists) {
    return { ok: false, reason: "operator_exists" };
  }
  if (input.agentOperator !== null) {
    return { ok: false, reason: "agent_bound" };
  }
  return {
    ok: true,
    domain,
    maintainer:
      input.maintainerAgentId !== null && input.agent === input.maintainerAgentId,
  };
}

// ---------------------------------------------------------------------------
// Joining a second domain
// ---------------------------------------------------------------------------

/**
 * Why a domain join was refused, in the order the checks run. The same shape as
 * a registration's, minus everything registration already settled and plus the
 * one thing a join is: an attestation for a domain this operator is not in yet.
 */
export const JOIN_REFUSALS = [
  "unregistered_operator",
  "unregistered_domain",
  "excluded_party",
  "already_joined",
  "missing_attestation",
  "bad_attestation",
  "attestation_domain_mismatch",
] as const;

export type JoinRefusal = (typeof JOIN_REFUSALS)[number];

/** What deciding a join needs, all of it already gathered. */
export interface DomainJoinInput {
  readonly operator: string;
  readonly agent: string;
  readonly domain: string;
  readonly attestation: unknown;
  /** Whether the operator is registered at all. */
  readonly registered: boolean;
  /** The domains it is already attested in (src/derive.ts, operatorDomainsAt). */
  readonly domains: readonly string[];
  readonly providers?: readonly string[];
}

export type DomainJoinCheck = { ok: true } | { ok: false; reason: JoinRefusal };

/**
 * Decide whether this operator may take on this domain.
 *
 * Decision D-071: registration binds an operator to its first domain's
 * attestation, and a later domain is joined by signing that domain's
 * attestation. Every rule here is one of registration's, read for the second
 * domain rather than the first: the operator exists, the domain is registered,
 * the operator is not an excluded party *of that domain*, it is not already in,
 * and the attestation is present, really signed by this agent's key, and for
 * this domain rather than another.
 *
 * The exclusion is keyed by the domain being joined and by nothing else, which
 * is what makes an operator excluded in one domain eligible in another.
 */
export async function checkDomainJoin(
  input: DomainJoinInput,
): Promise<DomainJoinCheck> {
  if (!input.registered) {
    return { ok: false, reason: "unregistered_operator" };
  }
  if (!isRegisteredDomain(input.domain)) {
    return { ok: false, reason: "unregistered_domain" };
  }
  if (isExcludedParty(input.domain, input.operator, input.providers)) {
    return { ok: false, reason: "excluded_party" };
  }
  if (input.domains.includes(input.domain)) {
    return { ok: false, reason: "already_joined" };
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
  if (attestationDomain(input.attestation) !== input.domain) {
    return { ok: false, reason: "attestation_domain_mismatch" };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Binding a second agent
// ---------------------------------------------------------------------------

/**
 * Why binding a second agent was refused, in the order the checks run. The
 * facts the store already holds come first, then the shape of the new id, then
 * the cryptography, so a request from a stranger never costs a signature
 * verification.
 */
export const AGENT_BIND_REFUSALS = [
  "unregistered_operator",
  "not_operator_agent",
  "agent_bound",
  "bad_agent",
  "missing_attestation",
  "bad_attestation",
  "attestation_domain_mismatch",
] as const;

export type AgentBindRefusal = (typeof AGENT_BIND_REFUSALS)[number];

/** What deciding a bind needs, all of it already gathered. */
export interface AgentBindInput {
  readonly operator: string;
  /** The agent that signed the request: one the operator already has. */
  readonly signer: string;
  /** The new agent being bound. */
  readonly agent: string;
  readonly attestation: unknown;
  /** Whether the operator is registered at all. */
  readonly registered: boolean;
  /**
   * The domain the operator registered under, whose sentence the new agent
   * signs (decision D-071). The first of the operator's domains: registration
   * took it, and a join only ever adds to the list.
   */
  readonly registrationDomain: string;
  /** The agents already bound to this operator (src/derive.ts, agentOperatorsAt). */
  readonly agents: readonly string[];
  /** The operator the new agent is already bound to, or null when it is free. */
  readonly agentOperator: string | null;
  /** The instant the request is served at. Injected; nothing here reads a clock. */
  readonly now: Date;
}

export type AgentBindCheck =
  | { ok: true }
  | { ok: false; reason: AgentBindRefusal };

/**
 * Decide whether this operator may bind a second agent.
 *
 * Whitepaper Section 5: "An operator runs agents", and "every agent under an
 * operator counts as one for validation" — so an operator with more than one
 * key is the ordinary case, and the second key has to arrive the way the first
 * did: by a signed act in the log that an offline reader can recheck.
 *
 * Registration's own three steps are not rerun. The DNS TXT record proves
 * control of the domain and was checked when the operator's first agent was
 * bound; payout onboarding is the operator's and was checked then too. What is
 * new here is the key, and the operator vouches for it by signing the request
 * with a key it already has while the new key signs the independence
 * attestation for the domain the operator registered under. Both signatures are
 * required and neither stands for the other: the request proves the operator
 * asked, and the attestation proves the new key exists and made Section 10's
 * statement itself.
 *
 * The attestation's own timestamp is held to REQUEST_CLOCK_SKEW_SECONDS of the
 * request clock. The request signature carries its own window, but it is made by
 * the *old* key: without this, an attestation signed long ago by a key that has
 * since changed hands would still bind it today.
 */
export async function checkAgentBind(
  input: AgentBindInput,
): Promise<AgentBindCheck> {
  if (!input.registered) {
    return { ok: false, reason: "unregistered_operator" };
  }
  if (!input.agents.includes(input.signer)) {
    return { ok: false, reason: "not_operator_agent" };
  }
  // Bound anywhere at all, this operator included: an agent answers for one
  // operator (Section 5), so rebinding one is not a thing this door does.
  if (input.agentOperator !== null) {
    return { ok: false, reason: "agent_bound" };
  }
  if (!isAgentId(input.agent)) {
    return { ok: false, reason: "bad_agent" };
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
  if (!withinSkew(input.attestation, input.now)) {
    return { ok: false, reason: "bad_attestation" };
  }
  if (attestationDomain(input.attestation) !== input.registrationDomain) {
    return { ok: false, reason: "attestation_domain_mismatch" };
  }
  return { ok: true };
}

/**
 * Whether an attestation's `signed_at` is inside the request window.
 *
 * The record has already verified by the time this is asked, so the timestamp is
 * an ISO 8601 string that the signature covers; anything else is a "no" rather
 * than an exception.
 */
function withinSkew(attestation: unknown, now: Date): boolean {
  const signedAt = (attestation as Record<string, unknown>)["signed_at"];
  if (typeof signedAt !== "string") return false;
  const at = Date.parse(signedAt);
  if (Number.isNaN(at)) return false;
  return (
    Math.abs(now.getTime() - at) / MILLISECONDS_PER_SECOND <=
    REQUEST_CLOCK_SKEW_SECONDS
  );
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

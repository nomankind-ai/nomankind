/**
 * Key rotation, as a kernel rule.
 *
 * Whitepaper Section 5, Identity and operators: "Every agent belongs to an
 * operator, the human or company that runs it", and standing, trust and marks
 * are the operator's. A key is how an operator speaks and is not what it is —
 * so a key that expires, leaks or is simply replaced on a schedule must cost
 * the operator nothing but the key. Decisions D-095 and D-097 item 3 name the
 * `key_rotated` event and the door that seals it; D-140 item 5 names the
 * community half, where a key follows its profile.
 *
 * What a rotation is, in one sentence: the operator says, with a key it holds,
 * that one of its keys stops answering for it here and another starts. Both
 * halves are in the log — the retiring is what makes the old key refused at
 * every write door from this position on, and the new key's own attestation is
 * what makes it a key that exists and made Section 10's statement itself.
 *
 * What a rotation is not: a rewrite. Every signature the retired key made
 * before this position stays valid and every decision it took before it stays
 * counted. Derivation and the offline verifier both read positions
 * (`retiredAgentsAt`), so the record a lost key made is exactly as good as it
 * was, and losing a key is not a way to unmake what it signed.
 *
 * Pure, except for the one WebCrypto call inside `verifyAttestation`. No
 * storage, no clock, no network: the door gathers the facts and this decides.
 * No policy number lives here.
 */

import type { Event } from "./events.js";
import { isAgentId } from "./identity.js";
import {
  attestationDomain,
  verifyAttestation,
} from "./registry.js";
import { REQUEST_CLOCK_SKEW_SECONDS } from "./policy.js";

/** How many milliseconds a second is. Not a policy number. */
const MILLISECONDS_PER_SECOND = 1000;

/**
 * Why a rotation was refused, in the order the checks run.
 *
 * The facts the store already holds come first, then the shape of the new id,
 * then the cryptography, so a request from a stranger never costs a signature
 * verification — the order `AGENT_BIND_REFUSALS` runs in, for the same reason.
 *
 * `community_operator` is last of the store's own: a community operator's key
 * follows its profile (D-140 item 5) and rotates in the sweep's own path, not
 * at a door, so this door refuses it by name rather than by silence. A refusal
 * that said `unknown_operator` about an operator the registry plainly holds
 * would send its holder looking for the wrong thing.
 */
export const KEY_ROTATION_REFUSALS = [
  "unknown_operator",
  "community_operator",
  "unknown_agent",
  "author_mismatch",
  "agent_retired",
  "bad_agent",
  "agent_already_bound",
  "missing_attestation",
  "bad_attestation",
] as const;

export type KeyRotationRefusal = (typeof KEY_ROTATION_REFUSALS)[number];

/** What deciding a rotation needs, all of it already gathered. */
export interface KeyRotationInput {
  readonly operator: string;
  /**
   * The agent that signed the request: one of the operator's own, the retiring
   * key or another.
   *
   * Section 5 again: an operator's keys all speak for it, so a rotation signed
   * by a sibling key is as good as one signed by the key being retired — which
   * is the whole point, because the reason to rotate is usually that the
   * retiring key can no longer sign anything.
   */
  readonly signer: string;
  /** The key being retired. */
  readonly retiredAgent: string;
  /** The key taking its place. */
  readonly newAgent: string;
  /** The new key's independence attestation, as the body carried it. */
  readonly attestation: unknown;
  /** Whether the log has registered this operator at all. */
  readonly registered: boolean;
  /** Whether it is a community operator (D-138), whose keys rotate elsewhere. */
  readonly community: boolean;
  /**
   * The domain the operator registered under, whose sentence the new key signs
   * (D-071). The first of the operator's domains, exactly as `checkAgentBind`
   * reads it: registration took it and a join only ever adds.
   */
  readonly registrationDomain: string;
  /** The agents bound to this operator (src/derive.ts, `agentOperatorsAt`). */
  readonly agents: readonly string[];
  /** The operator the new key is already bound to, or null when it is free. */
  readonly newAgentOperator: string | null;
  /** Whether the key being retired has already been retired by an earlier rotation. */
  readonly retiredAlready: boolean;
  /** The instant the request is served at. Injected; nothing here reads a clock. */
  readonly now: Date;
}

export type KeyRotationCheck =
  | { ok: true }
  | { ok: false; reason: KeyRotationRefusal };

/**
 * Decide whether this operator may rotate this key.
 *
 * The same two signatures `checkAgentBind` asks for and neither stands for the
 * other: the request proves the operator asked, and the attestation proves the
 * new key exists and made Section 10's statement itself. What is different is
 * the retiring, which is why `author_mismatch` is here — the key being retired
 * has to be one of this operator's, or a rotation would be a way to retire
 * somebody else's key by asking about it under your own operator's id.
 *
 * The attestation's own timestamp is held to REQUEST_CLOCK_SKEW_SECONDS of the
 * request clock, for `checkAgentBind`'s reason: the request signature carries
 * its own window but is made by an OLD key, and without this an attestation
 * signed long ago by a key that has since changed hands would still bind it
 * today.
 *
 * A key that is already retired cannot be retired again (`agent_retired`): the
 * second rotation would move the position the first one fixed, and every
 * decision the key took between the two would change from counted to
 * uncounted. The log is append-only and so is this.
 */
export async function checkKeyRotation(
  input: KeyRotationInput,
): Promise<KeyRotationCheck> {
  if (!input.registered) {
    return { ok: false, reason: "unknown_operator" };
  }
  if (input.community) {
    return { ok: false, reason: "community_operator" };
  }
  // Who asked: a key this operator holds, and nobody else's.
  if (!input.agents.includes(input.signer)) {
    return { ok: false, reason: "unknown_agent" };
  }
  // What is being retired: this operator's own key. `author_mismatch` and not
  // `unknown_agent`, because the key may well exist — under somebody else.
  if (!input.agents.includes(input.retiredAgent)) {
    return { ok: false, reason: "author_mismatch" };
  }
  if (input.retiredAlready) {
    return { ok: false, reason: "agent_retired" };
  }
  if (!isAgentId(input.newAgent)) {
    return { ok: false, reason: "bad_agent" };
  }
  // Bound anywhere at all, this operator included: an agent answers for one
  // operator (Section 5), and a rotation onto a key that already speaks is a
  // second binding rather than a new one.
  if (input.newAgentOperator !== null) {
    return { ok: false, reason: "agent_already_bound" };
  }
  if (input.newAgent === input.retiredAgent) {
    // Unreachable through the check above only when the retired key is somehow
    // unbound; named here so a rotation onto itself can never be a no-op event
    // that retires the operator's only key.
    return { ok: false, reason: "agent_already_bound" };
  }
  if (input.attestation === null || input.attestation === undefined) {
    return { ok: false, reason: "missing_attestation" };
  }
  const signed = await verifyAttestation(
    input.operator,
    input.newAgent,
    input.attestation,
  );
  if (!signed) {
    return { ok: false, reason: "bad_attestation" };
  }
  if (!withinSkew(input.attestation, input.now)) {
    return { ok: false, reason: "bad_attestation" };
  }
  if (attestationDomain(input.attestation) !== input.registrationDomain) {
    return { ok: false, reason: "bad_attestation" };
  }
  return { ok: true };
}

/** Whether an attestation's `signed_at` is inside the request window. */
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

/**
 * Which keys had been retired as of `position`, and where.
 *
 * The map's value is the seq of the `key_rotated` that retired the key, which
 * is what makes retirement a fact about a position rather than about now: a
 * decision, a signature or a write at a seq at or after it is by a key that had
 * stopped answering for its operator, and everything before it is by a key that
 * had not. Every rule that consults this reads it at the position it is judging
 * (src/derive.ts), so a validation counted in 2026 is still counted in 2028
 * whatever became of the key that signed it.
 *
 * Only events with seq <= position are folded, exactly as every fold in
 * src/derive.ts, so a rotation sealed later can never change what a past
 * decision saw (retrospective M8).
 *
 * The first retirement of a key wins and a later one does not move it: the
 * door refuses a second rotation of the same key (`agent_retired` above), and a
 * log that holds one anyway is read as retiring the key where it first said so
 * rather than as un-retiring it in between.
 *
 * Here and not in src/derive.ts because it is this module's own fact and
 * derivation is its caller: rotation.ts holds no import of derive.ts, so the
 * rule and the fold stay on the same side of the dependency.
 */
export function retiredAgentsAt(
  events: readonly Event[],
  position: number,
): Map<string, number> {
  const retired = new Map<string, number>();
  const ordered = [...events].sort((left, right) => left.seq - right.seq);
  for (const event of ordered) {
    if (event.seq > position) break;
    if (event.type !== "key_rotated") continue;
    const payload = event.payload as Record<string, unknown>;
    const agent = payload["retired_agent"];
    // Read by name and ignored when it is not a string: an event sealed by a
    // build this one does not know is skipped rather than half-read, which is
    // the rule every fold in this system keeps.
    if (typeof agent !== "string" || agent === "") continue;
    if (retired.has(agent)) continue;
    retired.set(agent, event.seq);
  }
  return retired;
}

/**
 * Whether one key had been retired by `position`.
 *
 * At the retiring position itself the key is already retired: the rotation is
 * the operator saying this key stops here, and a decision sealed at the very
 * same seq as the retirement is not a decision the operator was still speaking
 * through. Retirement is inclusive of its own seq, everywhere it is asked.
 */
export function isAgentRetiredAt(
  events: readonly Event[],
  agent: string,
  position: number,
): boolean {
  return retiredAgentsAt(events, position).has(agent);
}

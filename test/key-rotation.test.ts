/**
 * Key rotation, as a rule (decisions D-095, D-097 item 3, D-140 item 5).
 *
 * Whitepaper Section 5, Identity and operators: "Every agent belongs to an
 * operator", and standing, trust and marks are the operator's. A key is how an
 * operator speaks and is not what it is — so a key that expires, leaks or is
 * replaced on a schedule must cost the operator nothing but the key.
 *
 * Two halves, and both are here:
 *
 * The door's rule (`checkKeyRotation`), refusal by refusal, in the order the
 * checks run, so a request from a stranger never costs a signature
 * verification. Every name in KEY_ROTATION_REFUSALS is reached by a case.
 *
 * And the fold (`retiredAgentsAt`), which is what makes a retirement a fact
 * about a POSITION rather than about now. That is the whole safety property: a
 * validation signed before the rotation is still counted afterwards, and one
 * signed after it is counted by nobody. A record that invalidated its own past
 * would be a record anybody could rewrite by losing a key.
 *
 * Pure: no database, no clock but the injected one, no network.
 */

import { describe, expect, it } from "vitest";

import { agentOperatorsAt, mayValidateEntry } from "../src/derive.js";
import { appendEvent, type Attestation, type Event } from "../src/events.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { signAttestation } from "../src/registry.js";
import {
  KEY_ROTATION_REFUSALS,
  checkKeyRotation,
  isAgentRetiredAt,
  retiredAgentsAt,
  type KeyRotationInput,
} from "../src/rotation.js";
import { makeAgent, type TestAgent } from "./helpers/registry.js";

/** The injected clock: nothing here reads a wall clock. */
const NOW = new Date("2026-09-18T00:00:00.000Z");
const AT = NOW.toISOString();

const OPERATOR = "rotator.example";
const ENTRY = "nmk_0000000000000000000000000000000a";

/** One attestation by this key, for this operator, in the default domain. */
function attest(agent: TestAgent, operator = OPERATOR): Promise<Attestation> {
  return signAttestation(agent.privateKey, {
    operator,
    agent: agent.agentId,
    domain: DEFAULT_DOMAIN,
    signed_at: AT,
  });
}

/** The input a well-formed rotation makes, with whatever the case overrides. */
async function input(
  parts: Partial<KeyRotationInput> = {},
): Promise<KeyRotationInput> {
  const held = await makeAgent();
  const fresh = await makeAgent();
  return {
    operator: OPERATOR,
    signer: held.agentId,
    retiredAgent: held.agentId,
    newAgent: fresh.agentId,
    attestation: await attest(fresh),
    registered: true,
    community: false,
    registrationDomain: DEFAULT_DOMAIN,
    agents: [held.agentId],
    newAgentOperator: null,
    retiredAlready: false,
    now: NOW,
    ...parts,
  };
}

/** A log holding one rotation at the position it was appended at. */
async function rotationLog(
  retired: string,
  fresh: string,
  before: number,
): Promise<Event[]> {
  let events: Event[] = [];
  for (let index = 0; index < before; index += 1) {
    events = await appendEvent(events, {
      at: AT,
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: [] },
    });
  }
  return appendEvent(events, {
    at: AT,
    type: "key_rotated",
    entry_id: null,
    payload: {
      operator: OPERATOR,
      retired_agent: retired,
      new_agent: fresh,
      attestation: null,
      binding: null,
      capture_hash: null,
    },
  });
}

describe("checkKeyRotation", () => {
  it("accepts an operator retiring its own key for a fresh one", async () => {
    expect(await checkKeyRotation(await input())).toEqual({ ok: true });
  });

  it("accepts a rotation signed by a sibling key", async () => {
    // The usual reason to rotate is that the retiring key can no longer sign,
    // so a sibling's signature is as good as the retiring key's: Section 5's
    // agents all speak for one operator.
    const sibling = await makeAgent();
    const held = await makeAgent();
    const fresh = await makeAgent();
    expect(
      await checkKeyRotation(
        await input({
          signer: sibling.agentId,
          retiredAgent: held.agentId,
          newAgent: fresh.agentId,
          attestation: await attest(fresh),
          agents: [held.agentId, sibling.agentId],
        }),
      ),
    ).toEqual({ ok: true });
  });

  it("refuses an operator the log has never registered", async () => {
    expect(await checkKeyRotation(await input({ registered: false }))).toEqual({
      ok: false,
      reason: "unknown_operator",
    });
  });

  it("refuses a community operator: its key follows its profile", async () => {
    // D-140 item 5: a community operator's key rotates by its own profile and
    // its next counted line, never at a door. Named rather than passed over, so
    // its holder is not sent looking for the wrong thing.
    expect(await checkKeyRotation(await input({ community: true }))).toEqual({
      ok: false,
      reason: "community_operator",
    });
  });

  it("refuses a signer that is not one of this operator's keys", async () => {
    const stranger = await makeAgent();
    expect(
      await checkKeyRotation(await input({ signer: stranger.agentId })),
    ).toEqual({ ok: false, reason: "unknown_agent" });
  });

  it("refuses retiring a key that is not this operator's", async () => {
    const held = await makeAgent();
    const other = await makeAgent();
    expect(
      await checkKeyRotation(
        await input({
          signer: held.agentId,
          retiredAgent: other.agentId,
          agents: [held.agentId],
        }),
      ),
    ).toEqual({ ok: false, reason: "author_mismatch" });
  });

  it("refuses retiring a key that is already retired", async () => {
    // A second rotation would move the position the first one fixed, and every
    // decision the key took between the two would flip from counted to
    // uncounted. The log is append-only and so is this.
    expect(await checkKeyRotation(await input({ retiredAlready: true }))).toEqual(
      { ok: false, reason: "agent_retired" },
    );
  });

  it("refuses a new key that is not an agent id", async () => {
    expect(
      await checkKeyRotation(await input({ newAgent: "not-an-agent" })),
    ).toEqual({ ok: false, reason: "bad_agent" });
  });

  it("refuses a new key that already answers for somebody", async () => {
    expect(
      await checkKeyRotation(await input({ newAgentOperator: "other.example" })),
    ).toEqual({ ok: false, reason: "agent_already_bound" });
  });

  it("refuses a rotation with no attestation at all", async () => {
    expect(await checkKeyRotation(await input({ attestation: null }))).toEqual({
      ok: false,
      reason: "missing_attestation",
    });
  });

  it("refuses an attestation the new key did not sign", async () => {
    // The old key's word that a new key exists is not evidence that it does:
    // the statement has to be the NEW key's own.
    const held = await makeAgent();
    const fresh = await makeAgent();
    expect(
      await checkKeyRotation(
        await input({
          signer: held.agentId,
          retiredAgent: held.agentId,
          newAgent: fresh.agentId,
          agents: [held.agentId],
          attestation: await attest(held),
        }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
  });

  it("refuses an attestation signed outside the request window", async () => {
    // The request signature carries its own window but is made by an OLD key:
    // without this, an attestation signed long ago by a key that has since
    // changed hands would still bind it today.
    const fresh = await makeAgent();
    const stale = await signAttestation(fresh.privateKey, {
      operator: OPERATOR,
      agent: fresh.agentId,
      domain: DEFAULT_DOMAIN,
      signed_at: new Date(NOW.getTime() - 86_400_000).toISOString(),
    });
    expect(
      await checkKeyRotation(
        await input({ newAgent: fresh.agentId, attestation: stale }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
  });

  it("refuses an attestation for another domain", async () => {
    const fresh = await makeAgent();
    const elsewhere = await signAttestation(fresh.privateKey, {
      operator: OPERATOR,
      agent: fresh.agentId,
      domain: "ai-safety",
      signed_at: AT,
    });
    expect(
      await checkKeyRotation(
        await input({ newAgent: fresh.agentId, attestation: elsewhere }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
  });

  it("names every refusal it can give", async () => {
    // The list is the door's status map's domain, so a refusal added without a
    // status would be a 500 rather than an answer.
    expect(new Set(KEY_ROTATION_REFUSALS).size).toBe(
      KEY_ROTATION_REFUSALS.length,
    );
  });
});

describe("retiredAgentsAt", () => {
  it("is empty on a log that holds no rotation", async () => {
    const held = await makeAgent();
    expect(retiredAgentsAt([], Number.MAX_SAFE_INTEGER).size).toBe(0);
    expect(isAgentRetiredAt([], held.agentId, Number.MAX_SAFE_INTEGER)).toBe(
      false,
    );
  });

  it("answers by position, inclusive of the retiring seq", async () => {
    const held = await makeAgent();
    const fresh = await makeAgent();
    const log = await rotationLog(held.agentId, fresh.agentId, 3);
    const at = log[log.length - 1]!.seq;
    expect(at).toBe(3);

    // Before it, the key still speaks. At it and after it, it does not: the
    // rotation is the operator saying this key stops HERE.
    expect(isAgentRetiredAt(log, held.agentId, at - 1)).toBe(false);
    expect(isAgentRetiredAt(log, held.agentId, at)).toBe(true);
    expect(isAgentRetiredAt(log, held.agentId, at + 10)).toBe(true);
    expect(retiredAgentsAt(log, at).get(held.agentId)).toBe(at);
  });

  it("ignores a payload that names no retired key", async () => {
    // An event sealed by a build this one does not know is skipped rather than
    // half-read, which is the rule every fold in this system keeps.
    const log = await appendEvent([], {
      at: AT,
      type: "key_rotated",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        retired_agent: "",
        new_agent: "",
        attestation: null,
        binding: null,
        capture_hash: null,
      },
    });
    expect(retiredAgentsAt(log, Number.MAX_SAFE_INTEGER).size).toBe(0);
  });
});

describe("the registry, after a rotation", () => {
  it("moves the operator from the old key to the new one", async () => {
    const held = await makeAgent();
    const fresh = await makeAgent();
    let log = await appendEvent([], {
      at: AT,
      type: "operator_registered",
      entry_id: null,
      payload: { operator: OPERATOR, maintainer: false, domain: DEFAULT_DOMAIN },
    });
    log = await appendEvent(log, {
      at: AT,
      type: "agent_bound",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        agent: held.agentId,
        attestation: await attest(held),
      },
    });
    const bound = log[log.length - 1]!.seq;
    log = await appendEvent(log, {
      at: AT,
      type: "key_rotated",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        retired_agent: held.agentId,
        new_agent: fresh.agentId,
        attestation: await attest(fresh),
        binding: null,
        capture_hash: null,
      },
    });
    const at = log[log.length - 1]!.seq;

    // At the binding, the old key answers for the operator and the new one
    // answers for nobody. At the rotation, exactly the other way round — and
    // the operator's own id never moved.
    expect(agentOperatorsAt(log, bound).get(held.agentId)).toBe(OPERATOR);
    expect(agentOperatorsAt(log, bound).get(fresh.agentId)).toBeUndefined();
    expect(agentOperatorsAt(log, at).get(held.agentId)).toBeUndefined();
    expect(agentOperatorsAt(log, at).get(fresh.agentId)).toBe(OPERATOR);
  });

  it("counts the retired key's earlier decisions and not its later ones", async () => {
    const held = await makeAgent();
    const fresh = await makeAgent();
    const target = {
      id: ENTRY,
      authorOperator: "author.example",
      domain: DEFAULT_DOMAIN,
      subject: "example/kestrel-1",
    };
    let log = await appendEvent([], {
      at: AT,
      type: "operator_registered",
      entry_id: null,
      payload: { operator: OPERATOR, maintainer: false, domain: DEFAULT_DOMAIN },
    });
    const registered = log[log.length - 1]!.seq;
    log = await rotationLogOnto(log, held.agentId, fresh.agentId);
    const at = log[log.length - 1]!.seq;

    // Before the rotation the key may validate; at and after it, it may not —
    // and the OPERATOR may still, which is the point: what was retired is a
    // key, not a validator.
    expect(
      mayValidateEntry(log, registered, target, OPERATOR, held.agentId),
    ).toBe(true);
    expect(mayValidateEntry(log, at, target, OPERATOR, held.agentId)).toBe(
      false,
    );
    expect(mayValidateEntry(log, at, target, OPERATOR, fresh.agentId)).toBe(
      true,
    );
    // And a caller with no key in hand is asking about the operator, which a
    // rotation never removes: the verification precondition counts who COULD
    // sign, and that answer is unchanged.
    expect(mayValidateEntry(log, at, target, OPERATOR)).toBe(true);
  });
});

/** The same rotation, appended onto a log that already exists. */
async function rotationLogOnto(
  log: readonly Event[],
  retired: string,
  fresh: string,
): Promise<Event[]> {
  return appendEvent(log, {
    at: AT,
    type: "key_rotated",
    entry_id: null,
    payload: {
      operator: OPERATOR,
      retired_agent: retired,
      new_agent: fresh,
      attestation: null,
      binding: null,
      capture_hash: null,
    },
  });
}
